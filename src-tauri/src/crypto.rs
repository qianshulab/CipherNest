use std::{
    fs::{self, File},
    io::{self, Read, Write},
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
const SALT_BYTES: usize = 16;
const NONCE_BYTES: usize = 24;
const DEFAULT_MEMORY_KIB: u32 = 64 * 1024;
const DEFAULT_ITERATIONS: u32 = 3;
const DEFAULT_PARALLELISM: u32 = 4;
const MIN_MEMORY_KIB: u32 = 19 * 1024;
const MAX_MEMORY_KIB: u32 = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KdfHeader {
    pub algorithm: String,
    pub version: u32,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub salt: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CipherBlock {
    pub algorithm: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

pub fn create_envelope(
    master_password: &str,
    data: &VaultData,
) -> VaultResult<(VaultEnvelope, Zeroizing<[u8; KEY_BYTES]>)> {
    validate_new_master_password(master_password)?;
    create_envelope_with_verified_password(master_password, data)
}

/// Re-encrypt a vault whose existing password has already been authenticated.
/// Historical passwords may predate today's creation policy; rejecting them
/// here would make an otherwise valid vault or backup impossible to migrate.
pub fn create_envelope_with_verified_password(
    master_password: &str,
    data: &VaultData,
) -> VaultResult<(VaultEnvelope, Zeroizing<[u8; KEY_BYTES]>)> {
    if master_password.len() > 1024 {
        return Err(VaultError::MasterPasswordTooLong);
    }

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

/// Refresh only a verified password slot that uses parameters below today's
/// defaults. The payload, generation, vault root key, and any keys derived
/// from the root key remain unchanged, so local encrypted sidecars stay valid.
pub fn upgrade_weak_kdf(
    master_password: &str,
    envelope: &VaultEnvelope,
    root_key: &[u8; KEY_BYTES],
) -> VaultResult<Option<VaultEnvelope>> {
    validate_envelope_header(envelope)?;
    if master_password.len() > 1024 {
        return Err(VaultError::MasterPasswordTooLong);
    }
    if envelope.kdf.memory_kib >= DEFAULT_MEMORY_KIB
        && envelope.kdf.iterations >= DEFAULT_ITERATIONS
        && envelope.kdf.parallelism >= DEFAULT_PARALLELISM
    {
        return Ok(None);
    }

    // This is a rare migration path. Recheck both the old password slot and
    // payload before replacing its only active password slot on disk.
    let (verified_root, _) = decrypt_envelope(master_password, envelope)?;
    if verified_root.as_ref() != root_key {
        return Err(VaultError::InvalidVault);
    }

    let mut salt = [0_u8; SALT_BYTES];
    fill_random(&mut salt)?;
    let kdf = KdfHeader {
        algorithm: "argon2id".into(),
        version: 19,
        memory_kib: envelope.kdf.memory_kib.max(DEFAULT_MEMORY_KIB),
        iterations: envelope.kdf.iterations.max(DEFAULT_ITERATIONS),
        parallelism: envelope.kdf.parallelism.max(DEFAULT_PARALLELISM),
        salt: STANDARD_NO_PAD.encode(salt),
    };
    let kek = derive_kek(master_password, &kdf)?;
    let wrapped_key = encrypt_bytes(root_key, &kek, &key_wrap_aad(&envelope.vault_id, &kdf))?;
    let mut upgraded = envelope.clone();
    upgraded.kdf = kdf;
    upgraded.wrapped_key = wrapped_key;
    Ok(Some(upgraded))
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

pub fn read_envelope(path: &Path) -> VaultResult<VaultEnvelope> {
    let file = File::open(path).map_err(|_| VaultError::NotFound)?;
    let metadata = file.metadata().map_err(|_| VaultError::InvalidVault)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_VAULT_BYTES {
        return Err(VaultError::InvalidVault);
    }
    // Read through the same handle used for metadata and cap the bytes even
    // if the file grows between the size check and the read.
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_VAULT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| VaultError::InvalidVault)?;
    parse_envelope_bytes(&bytes)
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
    let normalized = Zeroizing::new(password.nfc().collect::<String>());
    if normalized.chars().count() < 12 {
        return Err(VaultError::MasterPasswordTooShort);
    }
    if has_obvious_master_password_pattern(&normalized) {
        return Err(VaultError::MasterPasswordTooWeak);
    }
    Ok(())
}

fn has_obvious_master_password_pattern(password: &str) -> bool {
    let lower = Zeroizing::new(password.to_ascii_lowercase());
    let compact = Zeroizing::new(
        lower
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>(),
    );
    const COMMON_BASES: &[&str] = &[
        "password", "qwerty", "letmein", "admin", "iloveyou", "123456", "abcdef",
    ];
    if compact.as_str() == "correcthorsebatterystaple"
        || COMMON_BASES.iter().any(|base| {
            compact.strip_prefix(base).is_some_and(|tail| {
                tail.len() <= 16
                    && tail
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || byte.is_ascii_punctuation())
            })
        })
    {
        return true;
    }

    let chars = Zeroizing::new(compact.chars().collect::<Vec<char>>());
    if chars.is_empty() {
        return true;
    }
    let mut longest_run = 1_usize;
    let mut current_run = 1_usize;
    for pair in chars.windows(2) {
        current_run = if pair[0] == pair[1] {
            current_run + 1
        } else {
            1
        };
        longest_run = longest_run.max(current_run);
    }
    if longest_run >= 8 && longest_run >= chars.len().div_ceil(2) {
        return true;
    }
    for period in 1..=4.min(chars.len() / 3) {
        let mismatches = chars
            .iter()
            .enumerate()
            .filter(|(index, ch)| **ch != chars[*index % period])
            .count();
        if mismatches <= (chars.len() / 4).max(3) {
            return true;
        }
    }

    let bytes = compact.as_bytes();
    let all_digits = bytes.iter().all(u8::is_ascii_digit);
    let all_letters = bytes.iter().all(u8::is_ascii_lowercase);
    (all_digits || all_letters)
        && bytes.windows(2).all(|pair| {
            if all_digits {
                (pair[0] - b'0' + 1) % 10 == pair[1] - b'0'
                    || (pair[0] - b'0' + 9) % 10 == pair[1] - b'0'
            } else {
                pair[0].checked_add(1) == Some(pair[1]) || pair[0].checked_sub(1) == Some(pair[1])
            }
        })
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

fn decode_exact<const N: usize>(encoded: &str) -> VaultResult<[u8; N]> {
    let decoded = STANDARD_NO_PAD
        .decode(encoded)
        .map_err(|_| VaultError::InvalidVault)?;
    decoded.try_into().map_err(|_| VaultError::InvalidVault)
}

fn fill_random(bytes: &mut [u8]) -> VaultResult<()> {
    getrandom::fill(bytes).map_err(|_| VaultError::SaveFailed)
}

#[cfg(test)]
pub(crate) fn rewrap_with_test_kdf(
    password: &str,
    envelope: &VaultEnvelope,
    root_key: &[u8; KEY_BYTES],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> VaultResult<VaultEnvelope> {
    let mut salt = [0_u8; SALT_BYTES];
    fill_random(&mut salt)?;
    let kdf = KdfHeader {
        algorithm: "argon2id".into(),
        version: 19,
        memory_kib,
        iterations,
        parallelism,
        salt: STANDARD_NO_PAD.encode(salt),
    };
    let kek = derive_kek(password, &kdf)?;
    let wrapped_key = encrypt_bytes(root_key, &kek, &key_wrap_aad(&envelope.vault_id, &kdf))?;
    let mut weaker = envelope.clone();
    weaker.kdf = kdf;
    weaker.wrapped_key = wrapped_key;
    Ok(weaker)
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
            password_only_unlock: true,
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
    fn weak_password_slot_is_upgraded_without_changing_payload_or_root_key() {
        let password = "an existing vault password";
        let data = data();
        let (envelope, root_key) = create_envelope(password, &data).unwrap();
        let weak = rewrap_with_test_kdf(password, &envelope, &root_key, 19 * 1024, 1, 1).unwrap();
        let upgraded = upgrade_weak_kdf(password, &weak, &root_key)
            .unwrap()
            .expect("historical parameters need an upgrade");
        assert_eq!(upgraded.kdf.memory_kib, DEFAULT_MEMORY_KIB);
        assert_eq!(upgraded.kdf.iterations, DEFAULT_ITERATIONS);
        assert_eq!(upgraded.kdf.parallelism, DEFAULT_PARALLELISM);
        assert_ne!(upgraded.kdf.salt, weak.kdf.salt);
        assert_eq!(upgraded.payload, weak.payload);
        assert_eq!(upgraded.generation, weak.generation);
        let (unwrapped, decrypted) = decrypt_envelope(password, &upgraded).unwrap();
        assert_eq!(unwrapped.as_ref(), root_key.as_ref());
        assert_eq!(decrypted.vault_id, data.vault_id);
        assert!(decrypt_envelope("definitely the wrong password", &upgraded).is_err());
        assert!(upgrade_weak_kdf(password, &upgraded, &root_key)
            .unwrap()
            .is_none());
    }

    #[test]
    fn historical_short_password_can_be_reencrypted_after_authentication() {
        let password = "oldpass";
        assert!(matches!(
            create_envelope(password, &data()),
            Err(VaultError::MasterPasswordTooShort)
        ));
        let (envelope, root_key) =
            create_envelope_with_verified_password(password, &data()).unwrap();
        let (verified_root, _) = decrypt_envelope(password, &envelope).unwrap();
        assert_eq!(verified_root.as_ref(), root_key.as_ref());
    }

    #[test]
    fn new_password_policy_rejects_obvious_patterns_but_accepts_long_passphrases() {
        for weak in [
            "password1234!",
            "QWERTY123456",
            "123456789012",
            "abcdefghijkl",
            "aaaaaaaaaaaa",
            "aaaaaaaaaaaaX",
            "aaaaaaaaaaaaaaaaaaaaaaaX",
            "abababababab",
            "abcabcabcabc!1",
            "abcabcabcabc!@#",
            "pa\u{0085}ssword1234!",
            "correct horse battery staple",
        ] {
            assert!(matches!(
                validate_new_master_password(weak),
                Err(VaultError::MasterPasswordTooWeak)
            ));
        }
        for acceptable in [
            "five violet cedar lantern river words",
            "A long independent master passphrase",
            "passwordless-7M%q!f9p2Rz",
            "pa\u{feff}ssword1234!",
        ] {
            assert!(validate_new_master_password(acceptable).is_ok());
        }
    }

    #[test]
    fn legacy_vault_data_defaults_to_pending_password_only_migration() {
        let mut value = serde_json::to_value(data()).unwrap();
        value.as_object_mut().unwrap().remove("passwordOnlyUnlock");
        let legacy: VaultData = serde_json::from_value(value).unwrap();
        assert!(!legacy.password_only_unlock);
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
    fn read_envelope_enforces_the_file_size_limit() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.cnvault");
        let (envelope, _) =
            create_envelope("a sufficiently long master passphrase", &data()).unwrap();
        let mut bytes = serde_json::to_vec(&envelope).unwrap();
        bytes.resize(MAX_VAULT_BYTES as usize, b' ');
        fs::write(&path, &bytes).unwrap();
        assert_eq!(read_envelope(&path).unwrap(), envelope);

        bytes.push(b' ');
        fs::write(&path, &bytes).unwrap();
        assert!(matches!(
            read_envelope(&path),
            Err(VaultError::InvalidVault)
        ));

        fs::write(&path, b"").unwrap();
        assert!(matches!(
            read_envelope(&path),
            Err(VaultError::InvalidVault)
        ));
    }
}
