use std::{
    collections::HashSet,
    fs::{self, File},
    io::{self, Write},
    path::Path,
};

use argon2::{Algorithm, Argon2, Params, Version};
use atomicwrites::{AtomicFile, OverwriteBehavior};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::{
    error::{VaultError, VaultResult},
    models::{VaultData, MAX_VAULT_ENTRIES, MAX_VAULT_TOMBSTONES},
};

pub const FORMAT_NAME: &str = "CipherNest";
pub const FORMAT_VERSION: u32 = 1;
pub const MAX_VAULT_BYTES: u64 = 16 * 1024 * 1024;
const KEY_BYTES: usize = 32;
pub const DEVICE_KEY_BYTES: usize = KEY_BYTES;
pub const MAX_DEVICE_SLOTS: usize = 8;
const DEVICE_SLOTS_FORMAT: &str = "CipherNestDeviceSlots";
const DEVICE_SLOTS_VERSION: u32 = 1;
const MAX_DEVICE_SLOTS_BYTES: u64 = 64 * 1024;
const SALT_BYTES: usize = 16;
const NONCE_BYTES: usize = 24;
const DEFAULT_MEMORY_KIB: u32 = 64 * 1024;
const DEFAULT_ITERATIONS: u32 = 3;
const DEFAULT_PARALLELISM: u32 = 4;
const MIN_MEMORY_KIB: u32 = 19 * 1024;
const MAX_MEMORY_KIB: u32 = 256 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KdfHeader {
    pub algorithm: String,
    pub version: u32,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub salt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CipherBlock {
    pub algorithm: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultEnvelope {
    pub format: String,
    pub version: u32,
    pub vault_id: String,
    pub generation: u64,
    pub kdf: KdfHeader,
    pub wrapped_key: CipherBlock,
    pub payload: CipherBlock,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceKeyProvider {
    WindowsHello,
    MacosKeychain,
    LinuxSecretService,
}

impl DeviceKeyProvider {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WindowsHello => "windows_hello",
            Self::MacosKeychain => "macos_keychain",
            Self::LinuxSecretService => "linux_secret_service",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeviceKeySlot {
    pub device_id: String,
    pub label: String,
    pub provider: DeviceKeyProvider,
    pub created_at: u64,
    pub wrapped_root_key: CipherBlock,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeviceSlotsEnvelope {
    pub format: String,
    pub version: u32,
    pub vault_id: String,
    pub slots: Vec<DeviceKeySlot>,
}

impl DeviceSlotsEnvelope {
    pub fn empty(vault_id: &str) -> Self {
        Self {
            format: DEVICE_SLOTS_FORMAT.into(),
            version: DEVICE_SLOTS_VERSION,
            vault_id: vault_id.into(),
            slots: Vec::new(),
        }
    }
}

pub fn create_envelope(
    master_password: &str,
    data: &VaultData,
) -> VaultResult<(VaultEnvelope, Zeroizing<[u8; KEY_BYTES]>)> {
    validate_new_master_password(master_password)?;

    let mut salt = [0_u8; SALT_BYTES];
    fill_random(&mut salt)?;
    let kdf = KdfHeader {
        algorithm: "argon2id".into(),
        version: 19,
        memory_kib: DEFAULT_MEMORY_KIB,
        iterations: DEFAULT_ITERATIONS,
        parallelism: DEFAULT_PARALLELISM,
        salt: STANDARD_NO_PAD.encode(salt),
    };

    let kek = derive_kek(master_password, &kdf)?;
    let mut root_key = Zeroizing::new([0_u8; KEY_BYTES]);
    fill_random(root_key.as_mut())?;
    let wrapped_key = encrypt_bytes(root_key.as_ref(), &kek, &key_wrap_aad(&data.vault_id, &kdf))?;

    let payload = encrypt_vault_data(data, &root_key)?;
    Ok((
        VaultEnvelope {
            format: FORMAT_NAME.into(),
            version: FORMAT_VERSION,
            vault_id: data.vault_id.clone(),
            generation: data.generation,
            kdf,
            wrapped_key,
            payload,
        },
        root_key,
    ))
}

pub fn decrypt_envelope(
    master_password: &str,
    envelope: &VaultEnvelope,
) -> VaultResult<(Zeroizing<[u8; KEY_BYTES]>, VaultData)> {
    validate_envelope_header(envelope)?;
    if master_password.len() > 1024 {
        return Err(VaultError::UnlockFailed);
    }

    let kek = derive_kek(master_password, &envelope.kdf).map_err(|_| VaultError::UnlockFailed)?;
    let wrapped = decrypt_bytes(
        &envelope.wrapped_key,
        &kek,
        &key_wrap_aad(&envelope.vault_id, &envelope.kdf),
    )
    .map_err(|_| VaultError::UnlockFailed)?;
    if wrapped.len() != KEY_BYTES {
        return Err(VaultError::UnlockFailed);
    }
    let mut root_key = Zeroizing::new([0_u8; KEY_BYTES]);
    root_key.copy_from_slice(&wrapped);
    let data = decrypt_envelope_with_root_key(envelope, &root_key)?;
    Ok((root_key, data))
}

pub fn decrypt_envelope_with_root_key(
    envelope: &VaultEnvelope,
    root_key: &[u8; KEY_BYTES],
) -> VaultResult<VaultData> {
    validate_envelope_header(envelope)?;
    let payload_key = derive_payload_key(root_key, &envelope.vault_id)?;
    let plaintext = decrypt_bytes(
        &envelope.payload,
        &payload_key,
        &payload_aad(&envelope.vault_id, envelope.generation),
    )
    .map_err(|_| VaultError::UnlockFailed)?;
    let data: VaultData =
        serde_json::from_slice(&plaintext).map_err(|_| VaultError::UnlockFailed)?;
    validate_decrypted_data(&data, envelope).map_err(|_| VaultError::UnlockFailed)?;
    Ok(data)
}

pub fn update_payload(
    envelope: &VaultEnvelope,
    root_key: &[u8; KEY_BYTES],
    data: &VaultData,
) -> VaultResult<VaultEnvelope> {
    let mut next = envelope.clone();
    next.generation = data.generation;
    next.payload = encrypt_vault_data(data, root_key)?;
    Ok(next)
}

pub fn generate_device_key() -> VaultResult<Zeroizing<[u8; DEVICE_KEY_BYTES]>> {
    let mut device_key = Zeroizing::new([0_u8; DEVICE_KEY_BYTES]);
    fill_random(device_key.as_mut())?;
    Ok(device_key)
}

pub fn create_device_key_slot(
    root_key: &[u8; KEY_BYTES],
    device_key: &[u8; DEVICE_KEY_BYTES],
    vault_id: &str,
    device_id: &str,
    label: &str,
    provider: DeviceKeyProvider,
    created_at: u64,
) -> VaultResult<DeviceKeySlot> {
    validate_device_slot_metadata(device_id, label, created_at)?;
    let wrap_key = derive_device_wrap_key(device_key, vault_id, device_id)?;
    let mut slot = DeviceKeySlot {
        device_id: device_id.into(),
        label: label.into(),
        provider,
        created_at,
        wrapped_root_key: CipherBlock {
            algorithm: "xchacha20poly1305".into(),
            nonce: String::new(),
            ciphertext: String::new(),
        },
    };
    slot.wrapped_root_key = encrypt_bytes(root_key, &wrap_key, &device_wrap_aad(vault_id, &slot))?;
    Ok(slot)
}

pub fn unwrap_device_root_key(
    slot: &DeviceKeySlot,
    device_key: &[u8; DEVICE_KEY_BYTES],
    vault_id: &str,
) -> VaultResult<Zeroizing<[u8; KEY_BYTES]>> {
    validate_device_slot(slot)?;
    let wrap_key = derive_device_wrap_key(device_key, vault_id, &slot.device_id)?;
    let plaintext = decrypt_bytes(
        &slot.wrapped_root_key,
        &wrap_key,
        &device_wrap_aad(vault_id, slot),
    )
    .map_err(|_| VaultError::UnlockFailed)?;
    if plaintext.len() != KEY_BYTES {
        return Err(VaultError::UnlockFailed);
    }
    let mut root_key = Zeroizing::new([0_u8; KEY_BYTES]);
    root_key.copy_from_slice(&plaintext);
    Ok(root_key)
}

pub fn read_device_slots(path: &Path, expected_vault_id: &str) -> VaultResult<DeviceSlotsEnvelope> {
    let metadata = fs::metadata(path).map_err(|_| VaultError::NotFound)?;
    if metadata.len() == 0 || metadata.len() > MAX_DEVICE_SLOTS_BYTES {
        return Err(VaultError::InvalidVault);
    }
    let bytes = fs::read(path).map_err(|_| VaultError::InvalidVault)?;
    let slots: DeviceSlotsEnvelope =
        serde_json::from_slice(&bytes).map_err(|_| VaultError::InvalidVault)?;
    validate_device_slots(&slots, expected_vault_id)?;
    Ok(slots)
}

pub fn write_device_slots_atomic(path: &Path, slots: &DeviceSlotsEnvelope) -> VaultResult<()> {
    validate_device_slots(slots, &slots.vault_id)?;
    let bytes = serde_json::to_vec(slots).map_err(|_| VaultError::SaveFailed)?;
    if bytes.len() as u64 > MAX_DEVICE_SLOTS_BYTES {
        return Err(VaultError::SaveFailed);
    }
    write_private_atomic(path, &bytes)
}

pub fn read_envelope(path: &Path) -> VaultResult<VaultEnvelope> {
    let metadata = fs::metadata(path).map_err(|_| VaultError::NotFound)?;
    if metadata.len() == 0 || metadata.len() > MAX_VAULT_BYTES {
        return Err(VaultError::InvalidVault);
    }
    let bytes = fs::read(path).map_err(|_| VaultError::InvalidVault)?;
    let envelope: VaultEnvelope =
        serde_json::from_slice(&bytes).map_err(|_| VaultError::InvalidVault)?;
    validate_envelope_header(&envelope)?;
    Ok(envelope)
}

pub fn parse_envelope_bytes(bytes: &[u8]) -> VaultResult<VaultEnvelope> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_VAULT_BYTES {
        return Err(VaultError::InvalidVault);
    }
    let envelope: VaultEnvelope =
        serde_json::from_slice(bytes).map_err(|_| VaultError::InvalidVault)?;
    validate_envelope_header(&envelope)?;
    Ok(envelope)
}

pub fn write_envelope_atomic(path: &Path, envelope: &VaultEnvelope) -> VaultResult<()> {
    let bytes = serde_json::to_vec(envelope).map_err(|_| VaultError::SaveFailed)?;
    if bytes.len() as u64 > MAX_VAULT_BYTES {
        return Err(VaultError::SaveFailed);
    }
    write_private_atomic(path, &bytes)
}

fn write_private_atomic(path: &Path, bytes: &[u8]) -> VaultResult<()> {
    let parent = path.parent().ok_or(VaultError::SaveFailed)?;
    ensure_private_directory(parent)?;
    let atomic = AtomicFile::new(path, OverwriteBehavior::AllowOverwrite);
    atomic
        .write(|file| -> io::Result<()> {
            set_private_file_permissions(file)?;
            file.write_all(bytes)?;
            file.sync_all()
        })
        .map_err(|_| VaultError::SaveFailed)?;

    #[cfg(unix)]
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| VaultError::SaveFailed)?;

    Ok(())
}

pub fn validate_new_master_password(password: &str) -> VaultResult<()> {
    if password.len() > 1024 {
        return Err(VaultError::MasterPasswordTooLong);
    }
    if password.chars().count() < 12 {
        return Err(VaultError::MasterPasswordTooShort);
    }
    Ok(())
}

fn encrypt_vault_data(data: &VaultData, root_key: &[u8; KEY_BYTES]) -> VaultResult<CipherBlock> {
    let plaintext = Zeroizing::new(serde_json::to_vec(data).map_err(|_| VaultError::SaveFailed)?);
    let payload_key = derive_payload_key(root_key, &data.vault_id)?;
    encrypt_bytes(
        plaintext.as_slice(),
        &payload_key,
        &payload_aad(&data.vault_id, data.generation),
    )
}

fn derive_payload_key(
    root_key: &[u8; KEY_BYTES],
    vault_id: &str,
) -> VaultResult<Zeroizing<[u8; KEY_BYTES]>> {
    let hkdf = Hkdf::<Sha256>::new(Some(vault_id.as_bytes()), root_key);
    let mut payload_key = Zeroizing::new([0_u8; KEY_BYTES]);
    hkdf.expand(b"CipherNest vault-payload-v1", payload_key.as_mut())
        .map_err(|_| VaultError::InvalidVault)?;
    Ok(payload_key)
}

fn derive_device_wrap_key(
    device_key: &[u8; DEVICE_KEY_BYTES],
    vault_id: &str,
    device_id: &str,
) -> VaultResult<Zeroizing<[u8; KEY_BYTES]>> {
    let hkdf = Hkdf::<Sha256>::new(Some(vault_id.as_bytes()), device_key);
    let mut info = b"CipherNest device-root-wrap-key-v1".to_vec();
    append_aad_field(&mut info, device_id.as_bytes());
    let mut wrap_key = Zeroizing::new([0_u8; KEY_BYTES]);
    hkdf.expand(&info, wrap_key.as_mut())
        .map_err(|_| VaultError::InvalidVault)?;
    Ok(wrap_key)
}

fn encrypt_bytes(plaintext: &[u8], key: &[u8; KEY_BYTES], aad: &[u8]) -> VaultResult<CipherBlock> {
    let mut nonce = [0_u8; NONCE_BYTES];
    fill_random(&mut nonce)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| VaultError::SaveFailed)?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| VaultError::SaveFailed)?;
    Ok(CipherBlock {
        algorithm: "xchacha20poly1305".into(),
        nonce: STANDARD_NO_PAD.encode(nonce),
        ciphertext: STANDARD_NO_PAD.encode(ciphertext),
    })
}

fn decrypt_bytes(
    block: &CipherBlock,
    key: &[u8; KEY_BYTES],
    aad: &[u8],
) -> VaultResult<Zeroizing<Vec<u8>>> {
    if block.algorithm != "xchacha20poly1305" {
        return Err(VaultError::InvalidVault);
    }
    let nonce = decode_exact::<NONCE_BYTES>(&block.nonce)?;
    let ciphertext = STANDARD_NO_PAD
        .decode(&block.ciphertext)
        .map_err(|_| VaultError::InvalidVault)?;
    if ciphertext.len() < 16 || ciphertext.len() as u64 > MAX_VAULT_BYTES {
        return Err(VaultError::InvalidVault);
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| VaultError::InvalidVault)?;
    cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| VaultError::UnlockFailed)
}

fn derive_kek(password: &str, kdf: &KdfHeader) -> VaultResult<Zeroizing<[u8; KEY_BYTES]>> {
    validate_kdf(kdf)?;
    let salt = decode_exact::<SALT_BYTES>(&kdf.salt)?;
    let params = Params::new(
        kdf.memory_kib,
        kdf.iterations,
        kdf.parallelism,
        Some(KEY_BYTES),
    )
    .map_err(|_| VaultError::InvalidVault)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let normalized = Zeroizing::new(password.nfc().collect::<String>());
    let mut output = Zeroizing::new([0_u8; KEY_BYTES]);
    argon2
        .hash_password_into(normalized.as_bytes(), &salt, output.as_mut())
        .map_err(|_| VaultError::UnlockFailed)?;
    Ok(output)
}

fn validate_envelope_header(envelope: &VaultEnvelope) -> VaultResult<()> {
    if envelope.format != FORMAT_NAME
        || envelope.version != FORMAT_VERSION
        || envelope.vault_id.len() != 36
        || envelope.generation == 0
        || envelope.wrapped_key.algorithm != "xchacha20poly1305"
        || envelope.payload.algorithm != "xchacha20poly1305"
    {
        return Err(VaultError::InvalidVault);
    }
    validate_kdf(&envelope.kdf)?;
    let _ = decode_exact::<NONCE_BYTES>(&envelope.wrapped_key.nonce)?;
    let _ = decode_exact::<NONCE_BYTES>(&envelope.payload.nonce)?;
    let wrapped = STANDARD_NO_PAD
        .decode(&envelope.wrapped_key.ciphertext)
        .map_err(|_| VaultError::InvalidVault)?;
    if wrapped.len() != KEY_BYTES + 16 {
        return Err(VaultError::InvalidVault);
    }
    if envelope.payload.ciphertext.len() as u64 > MAX_VAULT_BYTES * 2 {
        return Err(VaultError::InvalidVault);
    }
    Ok(())
}

fn validate_kdf(kdf: &KdfHeader) -> VaultResult<()> {
    if kdf.algorithm != "argon2id"
        || kdf.version != 19
        || !(MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&kdf.memory_kib)
        || !(1..=10).contains(&kdf.iterations)
        || !(1..=8).contains(&kdf.parallelism)
    {
        return Err(VaultError::InvalidVault);
    }
    let _ = decode_exact::<SALT_BYTES>(&kdf.salt)?;
    Ok(())
}

fn validate_device_slots(slots: &DeviceSlotsEnvelope, expected_vault_id: &str) -> VaultResult<()> {
    if slots.format != DEVICE_SLOTS_FORMAT
        || slots.version != DEVICE_SLOTS_VERSION
        || slots.vault_id != expected_vault_id
        || slots.vault_id.len() != 36
        || uuid::Uuid::parse_str(&slots.vault_id).is_err()
        || slots.slots.len() > MAX_DEVICE_SLOTS
    {
        return Err(VaultError::InvalidVault);
    }
    let mut ids = HashSet::with_capacity(slots.slots.len());
    for slot in &slots.slots {
        validate_device_slot(slot).map_err(|_| VaultError::InvalidVault)?;
        if !ids.insert(slot.device_id.as_str()) {
            return Err(VaultError::InvalidVault);
        }
    }
    Ok(())
}

fn validate_device_slot(slot: &DeviceKeySlot) -> VaultResult<()> {
    validate_device_slot_metadata(&slot.device_id, &slot.label, slot.created_at)?;
    if slot.wrapped_root_key.algorithm != "xchacha20poly1305" {
        return Err(VaultError::InvalidVault);
    }
    let _ = decode_exact::<NONCE_BYTES>(&slot.wrapped_root_key.nonce)?;
    let wrapped = STANDARD_NO_PAD
        .decode(&slot.wrapped_root_key.ciphertext)
        .map_err(|_| VaultError::InvalidVault)?;
    if wrapped.len() != KEY_BYTES + 16 {
        return Err(VaultError::InvalidVault);
    }
    Ok(())
}

fn validate_device_slot_metadata(device_id: &str, label: &str, created_at: u64) -> VaultResult<()> {
    let valid_label = label == label.trim()
        && (1..=80).contains(&label.chars().count())
        && !label.chars().any(char::is_control);
    if uuid::Uuid::parse_str(device_id).is_err() || !valid_label || created_at == 0 {
        return Err(VaultError::InvalidInput("设备解锁信息无效".into()));
    }
    Ok(())
}

fn validate_decrypted_data(data: &VaultData, envelope: &VaultEnvelope) -> VaultResult<()> {
    if data.schema_version != 1
        || data.vault_id != envelope.vault_id
        || data.generation != envelope.generation
        || data.entries.len() > MAX_VAULT_ENTRIES
        || data.tombstones.len() > MAX_VAULT_TOMBSTONES
    {
        return Err(VaultError::InvalidVault);
    }
    Ok(())
}

fn key_wrap_aad(vault_id: &str, kdf: &KdfHeader) -> Vec<u8> {
    format!(
        "{FORMAT_NAME}\0{FORMAT_VERSION}\0KEY_WRAP\0{vault_id}\0{}\0{}\0{}\0{}\0{}\0{}",
        kdf.algorithm, kdf.version, kdf.memory_kib, kdf.iterations, kdf.parallelism, kdf.salt
    )
    .into_bytes()
}

fn payload_aad(vault_id: &str, generation: u64) -> Vec<u8> {
    format!("{FORMAT_NAME}\0{FORMAT_VERSION}\0PAYLOAD\0{vault_id}\0{generation}").into_bytes()
}

fn device_wrap_aad(vault_id: &str, slot: &DeviceKeySlot) -> Vec<u8> {
    let mut aad = b"CipherNest\0DEVICE_ROOT_WRAP\0v1".to_vec();
    append_aad_field(&mut aad, vault_id.as_bytes());
    append_aad_field(&mut aad, slot.device_id.as_bytes());
    append_aad_field(&mut aad, slot.label.as_bytes());
    append_aad_field(&mut aad, slot.provider.as_str().as_bytes());
    aad.extend_from_slice(&slot.created_at.to_be_bytes());
    aad
}

fn append_aad_field(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}

fn decode_exact<const N: usize>(encoded: &str) -> VaultResult<[u8; N]> {
    let decoded = STANDARD_NO_PAD
        .decode(encoded)
        .map_err(|_| VaultError::InvalidVault)?;
    decoded.try_into().map_err(|_| VaultError::InvalidVault)
}

fn fill_random(bytes: &mut [u8]) -> VaultResult<()> {
    getrandom::fill(bytes).map_err(|_| VaultError::SaveFailed)
}

fn ensure_private_directory(path: &Path) -> VaultResult<()> {
    #[cfg(unix)]
    let existed = path.exists();
    fs::create_dir_all(path).map_err(|_| VaultError::SaveFailed)?;
    #[cfg(unix)]
    if !existed {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|_| VaultError::SaveFailed)?;
    }
    Ok(())
}

#[cfg(unix)]
fn set_private_file_permissions(file: &File) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_private_file_permissions(_file: &File) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{VaultData, VaultSettings};

    fn data() -> VaultData {
        VaultData {
            schema_version: 1,
            vault_id: uuid::Uuid::new_v4().to_string(),
            generation: 1,
            created_at: 1,
            updated_at: 1,
            last_backup_at: None,
            settings: VaultSettings::default(),
            entries: vec![],
            tombstones: vec![],
        }
    }

    #[test]
    fn round_trip_and_wrong_password() {
        let data = data();
        let (envelope, _) =
            create_envelope("a sufficiently long master passphrase", &data).unwrap();
        let (_, decrypted) =
            decrypt_envelope("a sufficiently long master passphrase", &envelope).unwrap();
        assert_eq!(decrypted.vault_id, data.vault_id);
        assert!(decrypt_envelope("definitely the wrong password", &envelope).is_err());
    }

    #[test]
    fn tampering_is_rejected() {
        let data = data();
        let (mut envelope, _) =
            create_envelope("a sufficiently long master passphrase", &data).unwrap();
        let mut ciphertext = STANDARD_NO_PAD
            .decode(&envelope.payload.ciphertext)
            .unwrap();
        ciphertext[0] ^= 0x80;
        envelope.payload.ciphertext = STANDARD_NO_PAD.encode(ciphertext);
        assert!(decrypt_envelope("a sufficiently long master passphrase", &envelope).is_err());
    }

    #[test]
    fn atomic_file_round_trip() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.cnvault");
        let data = data();
        let (envelope, _) =
            create_envelope("a sufficiently long master passphrase", &data).unwrap();
        write_envelope_atomic(&path, &envelope).unwrap();
        let loaded = read_envelope(&path).unwrap();
        assert_eq!(loaded.vault_id, envelope.vault_id);
    }

    #[test]
    fn device_key_slot_wraps_root_key_and_authenticates_metadata() {
        let data = data();
        let (envelope, root_key) =
            create_envelope("a sufficiently long master passphrase", &data).unwrap();
        let device_key = generate_device_key().unwrap();
        let device_id = uuid::Uuid::new_v4().to_string();
        let slot = create_device_key_slot(
            &root_key,
            &device_key,
            &data.vault_id,
            &device_id,
            "This Mac",
            DeviceKeyProvider::MacosKeychain,
            1,
        )
        .unwrap();

        let unwrapped = unwrap_device_root_key(&slot, &device_key, &data.vault_id).unwrap();
        assert!(unwrapped.as_ref() == root_key.as_ref());
        assert_eq!(
            decrypt_envelope_with_root_key(&envelope, &unwrapped)
                .unwrap()
                .vault_id,
            data.vault_id
        );

        let wrong_device_key = [0xA5; DEVICE_KEY_BYTES];
        assert!(unwrap_device_root_key(&slot, &wrong_device_key, &data.vault_id).is_err());
        assert!(
            unwrap_device_root_key(&slot, &device_key, &uuid::Uuid::new_v4().to_string()).is_err()
        );
        let mut tampered = slot.clone();
        tampered.label = "Another Mac".into();
        assert!(unwrap_device_root_key(&tampered, &device_key, &data.vault_id).is_err());
        let mut tampered = slot;
        let mut ciphertext = STANDARD_NO_PAD
            .decode(&tampered.wrapped_root_key.ciphertext)
            .unwrap();
        ciphertext[0] ^= 0x80;
        tampered.wrapped_root_key.ciphertext = STANDARD_NO_PAD.encode(ciphertext);
        assert!(unwrap_device_root_key(&tampered, &device_key, &data.vault_id).is_err());
    }

    #[test]
    fn device_slots_file_contains_no_device_secret() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.cnvault.devices");
        let data = data();
        let (_, root_key) =
            create_envelope("a sufficiently long master passphrase", &data).unwrap();
        let device_key = generate_device_key().unwrap();
        let slot = create_device_key_slot(
            &root_key,
            &device_key,
            &data.vault_id,
            &uuid::Uuid::new_v4().to_string(),
            "Windows PC",
            DeviceKeyProvider::WindowsHello,
            1,
        )
        .unwrap();
        let mut slots = DeviceSlotsEnvelope::empty(&data.vault_id);
        slots.slots.push(slot);

        write_device_slots_atomic(&path, &slots).unwrap();
        let bytes = fs::read(&path).unwrap();
        let encoded_device_key = STANDARD_NO_PAD.encode(device_key.as_ref());
        assert!(!bytes
            .windows(encoded_device_key.len())
            .any(|window| window == encoded_device_key.as_bytes()));
        let loaded = read_device_slots(&path, &data.vault_id).unwrap();
        assert_eq!(loaded.slots.len(), 1);
        assert!(read_device_slots(&path, &uuid::Uuid::new_v4().to_string()).is_err());
    }
}
