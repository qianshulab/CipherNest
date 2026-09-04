use std::path::Path;

use serde::Serialize;
use tauri::{Runtime, WebviewWindow};
use zeroize::Zeroizing;

use crate::{
    crypto::{DeviceKeyProvider, DEVICE_KEY_BYTES},
    error::VaultResult,
};

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlatformQuickUnlock {
    pub available: bool,
    pub method: &'static str,
    pub label: &'static str,
    pub reason: Option<String>,
}

pub fn availability() -> PlatformQuickUnlock {
    platform::availability()
}

pub fn provider() -> Option<DeviceKeyProvider> {
    platform::provider()
}

pub fn store_device_key<R: Runtime>(
    window: &WebviewWindow<R>,
    metadata_path: &Path,
    vault_id: &str,
    device_id: &str,
    device_key: &[u8; DEVICE_KEY_BYTES],
) -> VaultResult<()> {
    platform::store_device_key(window, metadata_path, vault_id, device_id, device_key)
}

pub fn load_device_key<R: Runtime>(
    window: &WebviewWindow<R>,
    metadata_path: &Path,
    vault_id: &str,
    device_id: &str,
) -> VaultResult<Zeroizing<[u8; DEVICE_KEY_BYTES]>> {
    platform::load_device_key(window, metadata_path, vault_id, device_id)
}

pub fn remove_device_key(metadata_path: &Path, vault_id: &str, device_id: &str) -> VaultResult<()> {
    platform::remove_device_key(metadata_path, vault_id, device_id)
}

#[cfg(target_os = "macos")]
mod platform {
    use super::*;
    use objc2_local_authentication::{LABiometryType, LAContext, LAPolicy};
    use security_framework::{
        access_control::{ProtectionMode, SecAccessControl},
        passwords::{
            delete_generic_password_options, generic_password, set_generic_password_options,
            AccessControlOptions, PasswordOptions,
        },
    };
    use security_framework_sys::base::errSecItemNotFound;

    use crate::error::VaultError;

    const KEYCHAIN_SERVICE: &str = "com.ciphernest.vault.quick-unlock";

    pub fn availability() -> PlatformQuickUnlock {
        let context = unsafe { LAContext::new() };
        let can_evaluate = unsafe {
            context.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics)
        };
        if can_evaluate.is_err() {
            return PlatformQuickUnlock {
                available: false,
                method: "touchId",
                label: "Touch ID",
                reason: Some("请先在系统设置中配置 Touch ID。".into()),
            };
        }

        let biometry_type = unsafe { context.biometryType() };
        if biometry_type != LABiometryType::TouchID {
            return PlatformQuickUnlock {
                available: false,
                method: "touchId",
                label: "Touch ID",
                reason: Some("这台 Mac 没有可用的 Touch ID。".into()),
            };
        }

        PlatformQuickUnlock {
            available: true,
            method: "touchId",
            label: "Touch ID",
            reason: None,
        }
    }

    pub fn provider() -> Option<DeviceKeyProvider> {
        Some(DeviceKeyProvider::MacosKeychain)
    }

    pub fn store_device_key<R: Runtime>(
        _window: &WebviewWindow<R>,
        metadata_path: &Path,
        vault_id: &str,
        device_id: &str,
        device_key: &[u8; DEVICE_KEY_BYTES],
    ) -> VaultResult<()> {
        if !availability().available {
            return Err(VaultError::QuickUnlockUnavailable);
        }

        let access_control = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenPasscodeSetThisDeviceOnly),
            AccessControlOptions::BIOMETRY_CURRENT_SET.bits(),
        )
        .map_err(|_| VaultError::DeviceKeyStore)?;

        let account = account_name(vault_id, device_id);
        let mut options = PasswordOptions::new_generic_password(KEYCHAIN_SERVICE, &account);
        options.set_access_control(access_control);
        options.set_access_synchronized(Some(false));
        options.set_label("CipherNest Touch ID 快速解锁");
        options.set_description("仅在本机 Touch ID 验证后释放的保险库设备密钥");
        options.use_protected_keychain();
        set_generic_password_options(device_key, options)
            .map_err(|_| VaultError::DeviceKeyStore)?;

        // Verify the protected item immediately. This makes enrollment prove that Touch ID can
        // actually release the bytes instead of merely trusting a policy preflight result.
        let mut verify_options = PasswordOptions::new_generic_password(KEYCHAIN_SERVICE, &account);
        verify_options.set_access_synchronized(Some(false));
        verify_options.use_protected_keychain();
        let verified = Zeroizing::new(match generic_password(verify_options) {
            Ok(value) => value,
            Err(_) => {
                let _ = remove_device_key(metadata_path, vault_id, device_id);
                return Err(VaultError::DeviceAuthenticationFailed);
            }
        });
        if verified.as_slice() != device_key {
            let _ = remove_device_key(metadata_path, vault_id, device_id);
            return Err(VaultError::DeviceKeyStore);
        }
        Ok(())
    }

    pub fn load_device_key<R: Runtime>(
        _window: &WebviewWindow<R>,
        _metadata_path: &Path,
        vault_id: &str,
        device_id: &str,
    ) -> VaultResult<Zeroizing<[u8; DEVICE_KEY_BYTES]>> {
        let account = account_name(vault_id, device_id);
        let mut options = PasswordOptions::new_generic_password(KEYCHAIN_SERVICE, &account);
        options.set_access_synchronized(Some(false));
        options.use_protected_keychain();
        let stored = Zeroizing::new(
            generic_password(options).map_err(|_| VaultError::DeviceAuthenticationFailed)?,
        );
        if stored.len() != DEVICE_KEY_BYTES {
            return Err(VaultError::QuickUnlockNotConfigured);
        }
        let mut device_key = Zeroizing::new([0_u8; DEVICE_KEY_BYTES]);
        device_key.copy_from_slice(stored.as_slice());
        Ok(device_key)
    }

    pub fn remove_device_key(
        _metadata_path: &Path,
        vault_id: &str,
        device_id: &str,
    ) -> VaultResult<()> {
        let account = account_name(vault_id, device_id);
        let mut options = PasswordOptions::new_generic_password(KEYCHAIN_SERVICE, &account);
        options.set_access_synchronized(Some(false));
        options.use_protected_keychain();
        match delete_generic_password_options(options) {
            Ok(()) => Ok(()),
            Err(error) if error.code() == errSecItemNotFound => Ok(()),
            Err(_) => Err(VaultError::DeviceKeyStore),
        }
    }

    fn account_name(vault_id: &str, device_id: &str) -> String {
        format!("{vault_id}:{device_id}")
    }
}

#[cfg(target_os = "windows")]
mod platform {
    use std::{
        fs,
        io::{self, Write},
        os::windows::ffi::OsStrExt,
        ptr,
    };

    use atomicwrites::{AtomicFile, OverwriteBehavior};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use chacha20poly1305::{
        aead::{Aead, KeyInit, Payload},
        XChaCha20Poly1305, XNonce,
    };
    use hkdf::Hkdf;
    use serde::{Deserialize, Serialize};
    use sha2::Sha256;
    use windows::{
        core::{BOOL, PCWSTR},
        Win32::{
            Foundation::HWND,
            Networking::WindowsWebServices::{
                WebAuthNAuthenticatorGetAssertion, WebAuthNAuthenticatorMakeCredential,
                WebAuthNDeletePlatformCredential, WebAuthNFreeAssertion,
                WebAuthNFreeCredentialAttestation, WebAuthNFreePlatformCredentialList,
                WebAuthNGetApiVersionNumber, WebAuthNGetPlatformCredentialList,
                WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable, WEBAUTHN_ASSERTION,
                WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
                WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM,
                WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS,
                WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_6,
                WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS,
                WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_6, WEBAUTHN_CLIENT_DATA,
                WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
                WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256,
                WEBAUTHN_COSE_ALGORITHM_RSASSA_PKCS1_V1_5_WITH_SHA256,
                WEBAUTHN_COSE_CREDENTIAL_PARAMETER, WEBAUTHN_COSE_CREDENTIAL_PARAMETERS,
                WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
                WEBAUTHN_CREDENTIAL_ATTESTATION, WEBAUTHN_CREDENTIAL_DETAILS_LIST,
                WEBAUTHN_CREDENTIAL_EX, WEBAUTHN_CREDENTIAL_EX_CURRENT_VERSION,
                WEBAUTHN_CREDENTIAL_LIST, WEBAUTHN_GET_CREDENTIALS_OPTIONS,
                WEBAUTHN_GET_CREDENTIALS_OPTIONS_VERSION_1, WEBAUTHN_HMAC_SECRET_SALT,
                WEBAUTHN_HMAC_SECRET_SALT_VALUES, WEBAUTHN_RP_ENTITY_INFORMATION,
                WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION, WEBAUTHN_USER_ENTITY_INFORMATION,
                WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
                WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
            },
        },
    };
    use zeroize::{Zeroize, Zeroizing};

    use super::*;
    use crate::error::VaultError;

    const WINDOWS_RECORD_VERSION: u32 = 1;
    const WINDOWS_RECORD_MAX_BYTES: u64 = 64 * 1024;
    const PRF_BYTES: usize = 32;
    const NONCE_BYTES: usize = 24;
    const WEBAUTHN_TIMEOUT_MS: u32 = 60_000;
    const RELYING_PARTY_ID: &str = "com.ciphernest.vault";
    const RELYING_PARTY_NAME: &str = "CipherNest";
    const ORIGIN: &str = "https://com.ciphernest.vault";

    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct WindowsHelloRecord {
        version: u32,
        vault_id: String,
        device_id: String,
        credential_id: String,
        salt: String,
        nonce: String,
        ciphertext: String,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct RecordAad<'a> {
        version: u32,
        vault_id: &'a str,
        device_id: &'a str,
        credential_id: &'a str,
        salt: &'a str,
    }

    struct WideString(Vec<u16>);

    impl WideString {
        fn new(value: &str) -> Self {
            Self(
                std::ffi::OsStr::new(value)
                    .encode_wide()
                    .chain(std::iter::once(0))
                    .collect(),
            )
        }

        fn as_pcwstr(&self) -> PCWSTR {
            PCWSTR(self.0.as_ptr())
        }
    }

    struct AttestationGuard(*mut WEBAUTHN_CREDENTIAL_ATTESTATION);

    impl Drop for AttestationGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { WebAuthNFreeCredentialAttestation(Some(self.0)) };
            }
        }
    }

    struct AssertionGuard(*mut WEBAUTHN_ASSERTION);

    impl Drop for AssertionGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { WebAuthNFreeAssertion(self.0) };
            }
        }
    }

    struct CredentialListGuard(*mut WEBAUTHN_CREDENTIAL_DETAILS_LIST);

    impl Drop for CredentialListGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { WebAuthNFreePlatformCredentialList(self.0) };
            }
        }
    }

    pub fn availability() -> PlatformQuickUnlock {
        let api_version = unsafe { WebAuthNGetApiVersionNumber() };
        if api_version < 6 {
            return PlatformQuickUnlock {
                available: false,
                method: "windowsHello",
                label: "Windows Hello",
                reason: Some("系统的 WebAuthn 版本过旧，无法安全保护设备密钥。".into()),
            };
        }
        let available = unsafe { WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable() }
            .is_ok_and(|value| value.as_bool());
        PlatformQuickUnlock {
            available,
            method: "windowsHello",
            label: "Windows Hello",
            reason: (!available).then(|| "请先在 Windows 设置中配置 Windows Hello。".into()),
        }
    }

    pub fn provider() -> Option<DeviceKeyProvider> {
        Some(DeviceKeyProvider::WindowsHello)
    }

    pub fn store_device_key<R: Runtime>(
        window: &WebviewWindow<R>,
        metadata_path: &Path,
        vault_id: &str,
        device_id: &str,
        device_key: &[u8; DEVICE_KEY_BYTES],
    ) -> VaultResult<()> {
        if !availability().available {
            return Err(VaultError::QuickUnlockUnavailable);
        }
        let hwnd = window.hwnd().map_err(|_| VaultError::DeviceKeyStore)?;
        let credential_id = make_platform_credential(hwnd, device_id)?;

        let result = (|| {
            let mut salt = [0_u8; PRF_BYTES];
            getrandom::fill(&mut salt).map_err(|_| VaultError::DeviceKeyStore)?;
            let prf = get_assertion_prf(hwnd, &credential_id, &salt)?;
            let record = seal_record(vault_id, device_id, &credential_id, &salt, &prf, device_key)?;
            write_record_atomic(metadata_path, &record)
        })();

        if result.is_err() {
            let _ = unsafe { WebAuthNDeletePlatformCredential(&credential_id) };
        }
        result
    }

    pub fn load_device_key<R: Runtime>(
        window: &WebviewWindow<R>,
        metadata_path: &Path,
        vault_id: &str,
        device_id: &str,
    ) -> VaultResult<Zeroizing<[u8; DEVICE_KEY_BYTES]>> {
        let record = read_record(metadata_path, vault_id, device_id)?;
        let credential_id = decode_bounded(&record.credential_id, 4096)?;
        if !credential_is_device_bound(&credential_id)? {
            return Err(VaultError::QuickUnlockUnavailable);
        }
        let salt_vec = decode_bounded(&record.salt, PRF_BYTES)?;
        let salt: [u8; PRF_BYTES] = salt_vec
            .try_into()
            .map_err(|_| VaultError::QuickUnlockNotConfigured)?;
        let hwnd = window
            .hwnd()
            .map_err(|_| VaultError::DeviceAuthenticationFailed)?;
        let prf = get_assertion_prf(hwnd, &credential_id, &salt)?;
        // Re-check after the interactive assertion so a credential that became backed up or
        // disappeared during the prompt never releases the wrapped device key to the caller.
        if !credential_is_device_bound(&credential_id)? {
            return Err(VaultError::QuickUnlockUnavailable);
        }
        open_record(&record, &prf)
    }

    pub fn remove_device_key(
        metadata_path: &Path,
        vault_id: &str,
        device_id: &str,
    ) -> VaultResult<()> {
        if let Ok(bytes) = fs::read(metadata_path) {
            if bytes.len() as u64 <= WINDOWS_RECORD_MAX_BYTES {
                if let Ok(record) = serde_json::from_slice::<WindowsHelloRecord>(&bytes) {
                    if record.vault_id == vault_id && record.device_id == device_id {
                        if let Ok(credential_id) = decode_bounded(&record.credential_id, 4096) {
                            // Never feed an unauthenticated file's arbitrary ID directly into the
                            // delete API. Enumeration proves the credential belongs to our RP.
                            if credential_is_device_bound(&credential_id).unwrap_or(false) {
                                let _ = unsafe { WebAuthNDeletePlatformCredential(&credential_id) };
                            }
                        }
                    }
                }
            }
        }
        match fs::remove_file(metadata_path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(VaultError::DeviceKeyStore),
        }
    }

    fn make_platform_credential(hwnd: HWND, device_id: &str) -> VaultResult<Vec<u8>> {
        let rp_id = WideString::new(RELYING_PARTY_ID);
        let rp_name = WideString::new(RELYING_PARTY_NAME);
        let rp = WEBAUTHN_RP_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION,
            pwszId: rp_id.as_pcwstr(),
            pwszName: rp_name.as_pcwstr(),
            pwszIcon: PCWSTR::null(),
        };

        let mut user_id = [0_u8; 32];
        getrandom::fill(&mut user_id).map_err(|_| VaultError::DeviceKeyStore)?;
        let user_name = WideString::new(device_id);
        let user_display_name = WideString::new("CipherNest 快速解锁");
        let user = WEBAUTHN_USER_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
            cbId: checked_u32(user_id.len())?,
            pbId: user_id.as_mut_ptr(),
            pwszName: user_name.as_pcwstr(),
            pwszIcon: PCWSTR::null(),
            pwszDisplayName: user_display_name.as_pcwstr(),
        };

        let mut client_data_json = make_client_data("webauthn.create")?;
        let hash_algorithm = WideString::new("SHA-256");
        let client_data = WEBAUTHN_CLIENT_DATA {
            dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
            cbClientDataJSON: checked_u32(client_data_json.len())?,
            pbClientDataJSON: client_data_json.as_mut_ptr(),
            pwszHashAlgId: hash_algorithm.as_pcwstr(),
        };

        let credential_type = WideString::new("public-key");
        let mut parameters = [
            WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
                dwVersion: WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
                pwszCredentialType: credential_type.as_pcwstr(),
                lAlg: WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256,
            },
            WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
                dwVersion: WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
                pwszCredentialType: credential_type.as_pcwstr(),
                lAlg: WEBAUTHN_COSE_ALGORITHM_RSASSA_PKCS1_V1_5_WITH_SHA256,
            },
        ];
        let credential_parameters = WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
            cCredentialParameters: checked_u32(parameters.len())?,
            pCredentialParameters: parameters.as_mut_ptr(),
        };

        let mut options = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS::default();
        options.dwVersion = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_6;
        options.dwTimeoutMilliseconds = WEBAUTHN_TIMEOUT_MS;
        options.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM;
        options.bRequireResidentKey = BOOL(0);
        options.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED;
        options.dwAttestationConveyancePreference = WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE;
        options.bEnablePrf = BOOL(1);

        let attestation = AttestationGuard(
            unsafe {
                WebAuthNAuthenticatorMakeCredential(
                    hwnd,
                    &rp,
                    &user,
                    &credential_parameters,
                    &client_data,
                    Some(&options),
                )
            }
            .map_err(|_| VaultError::DeviceAuthenticationFailed)?,
        );
        if attestation.0.is_null() {
            return Err(VaultError::DeviceAuthenticationFailed);
        }
        let value = unsafe { &*attestation.0 };
        if value.dwVersion < 5 || !value.bPrfEnabled.as_bool() {
            return Err(VaultError::QuickUnlockUnavailable);
        }
        if value.pbCredentialId.is_null() || value.cbCredentialId == 0 {
            return Err(VaultError::DeviceAuthenticationFailed);
        }
        let credential_id = unsafe {
            std::slice::from_raw_parts(value.pbCredentialId, value.cbCredentialId as usize).to_vec()
        };
        if credential_id.len() > 4096 {
            return Err(VaultError::DeviceAuthenticationFailed);
        }
        if !credential_is_device_bound(&credential_id)? {
            let _ = unsafe { WebAuthNDeletePlatformCredential(&credential_id) };
            return Err(VaultError::QuickUnlockUnavailable);
        }
        Ok(credential_id)
    }

    fn credential_is_device_bound(credential_id: &[u8]) -> VaultResult<bool> {
        let rp_id = WideString::new(RELYING_PARTY_ID);
        let options = WEBAUTHN_GET_CREDENTIALS_OPTIONS {
            dwVersion: WEBAUTHN_GET_CREDENTIALS_OPTIONS_VERSION_1,
            pwszRpId: rp_id.as_pcwstr(),
            bBrowserInPrivateMode: BOOL(0),
        };
        let list = CredentialListGuard(
            unsafe { WebAuthNGetPlatformCredentialList(&options) }
                .map_err(|_| VaultError::QuickUnlockUnavailable)?,
        );
        if list.0.is_null() {
            return Err(VaultError::QuickUnlockUnavailable);
        }
        let list_value = unsafe { &*list.0 };
        if list_value.cCredentialDetails > 4096 || list_value.ppCredentialDetails.is_null() {
            return Err(VaultError::QuickUnlockUnavailable);
        }
        for index in 0..list_value.cCredentialDetails as usize {
            let detail_ptr = unsafe { *list_value.ppCredentialDetails.add(index) };
            if detail_ptr.is_null() {
                continue;
            }
            let detail = unsafe { &*detail_ptr };
            if detail.pbCredentialID.is_null() || detail.cbCredentialID == 0 {
                continue;
            }
            let candidate = unsafe {
                std::slice::from_raw_parts(detail.pbCredentialID, detail.cbCredentialID as usize)
            };
            if candidate == credential_id {
                return Ok(detail.dwVersion >= 2 && !detail.bBackedUp.as_bool());
            }
        }
        Err(VaultError::QuickUnlockUnavailable)
    }

    fn get_assertion_prf(
        hwnd: HWND,
        credential_id: &[u8],
        salt: &[u8; PRF_BYTES],
    ) -> VaultResult<Zeroizing<[u8; PRF_BYTES]>> {
        let rp_id = WideString::new(RELYING_PARTY_ID);
        let mut client_data_json = make_client_data("webauthn.get")?;
        let hash_algorithm = WideString::new("SHA-256");
        let client_data = WEBAUTHN_CLIENT_DATA {
            dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
            cbClientDataJSON: checked_u32(client_data_json.len())?,
            pbClientDataJSON: client_data_json.as_mut_ptr(),
            pwszHashAlgId: hash_algorithm.as_pcwstr(),
        };

        let credential_type = WideString::new("public-key");
        let mut credential_bytes = credential_id.to_vec();
        let mut credential = WEBAUTHN_CREDENTIAL_EX {
            dwVersion: WEBAUTHN_CREDENTIAL_EX_CURRENT_VERSION,
            cbId: checked_u32(credential_bytes.len())?,
            pbId: credential_bytes.as_mut_ptr(),
            pwszCredentialType: credential_type.as_pcwstr(),
            dwTransports: 0,
        };
        let mut credential_ptr: *mut WEBAUTHN_CREDENTIAL_EX = &mut credential;
        let mut allow_list = WEBAUTHN_CREDENTIAL_LIST {
            cCredentials: 1,
            ppCredentials: &mut credential_ptr,
        };

        let mut salt_bytes = *salt;
        let mut global_salt = WEBAUTHN_HMAC_SECRET_SALT {
            cbFirst: checked_u32(salt_bytes.len())?,
            pbFirst: salt_bytes.as_mut_ptr(),
            cbSecond: 0,
            pbSecond: ptr::null_mut(),
        };
        let mut salt_values = WEBAUTHN_HMAC_SECRET_SALT_VALUES {
            pGlobalHmacSalt: &mut global_salt,
            cCredWithHmacSecretSaltList: 0,
            pCredWithHmacSecretSaltList: ptr::null_mut(),
        };

        let mut options = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS::default();
        options.dwVersion = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_6;
        options.dwTimeoutMilliseconds = WEBAUTHN_TIMEOUT_MS;
        options.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM;
        options.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED;
        options.pAllowCredentialList = &mut allow_list;
        options.pHmacSecretSaltValues = &mut salt_values;

        let assertion = AssertionGuard(
            unsafe {
                WebAuthNAuthenticatorGetAssertion(
                    hwnd,
                    rp_id.as_pcwstr(),
                    &client_data,
                    Some(&options),
                )
            }
            .map_err(|_| VaultError::DeviceAuthenticationFailed)?,
        );
        salt_bytes.zeroize();
        if assertion.0.is_null() {
            return Err(VaultError::DeviceAuthenticationFailed);
        }
        let value = unsafe { &*assertion.0 };
        if value.pHmacSecret.is_null() {
            return Err(VaultError::DeviceAuthenticationFailed);
        }
        let secret = unsafe { &*value.pHmacSecret };
        if secret.pbFirst.is_null() || secret.cbFirst as usize != PRF_BYTES {
            return Err(VaultError::DeviceAuthenticationFailed);
        }
        let mut prf = Zeroizing::new([0_u8; PRF_BYTES]);
        unsafe {
            ptr::copy_nonoverlapping(secret.pbFirst, prf.as_mut_ptr(), PRF_BYTES);
        }
        Ok(prf)
    }

    fn make_client_data(kind: &str) -> VaultResult<Vec<u8>> {
        let mut challenge = [0_u8; 32];
        getrandom::fill(&mut challenge).map_err(|_| VaultError::DeviceKeyStore)?;
        let json = serde_json::json!({
            "type": kind,
            "challenge": URL_SAFE_NO_PAD.encode(challenge),
            "origin": ORIGIN,
        });
        challenge.zeroize();
        serde_json::to_vec(&json).map_err(|_| VaultError::DeviceKeyStore)
    }

    fn seal_record(
        vault_id: &str,
        device_id: &str,
        credential_id: &[u8],
        salt: &[u8; PRF_BYTES],
        prf: &[u8; PRF_BYTES],
        device_key: &[u8; DEVICE_KEY_BYTES],
    ) -> VaultResult<WindowsHelloRecord> {
        let credential_id = URL_SAFE_NO_PAD.encode(credential_id);
        let salt = URL_SAFE_NO_PAD.encode(salt);
        let aad = record_aad(vault_id, device_id, &credential_id, &salt)?;
        let wrapping_key = derive_wrapping_key(vault_id, device_id, prf)?;
        let mut nonce = [0_u8; NONCE_BYTES];
        getrandom::fill(&mut nonce).map_err(|_| VaultError::DeviceKeyStore)?;
        let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key.as_ref())
            .map_err(|_| VaultError::DeviceKeyStore)?;
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: device_key,
                    aad: &aad,
                },
            )
            .map_err(|_| VaultError::DeviceKeyStore)?;
        Ok(WindowsHelloRecord {
            version: WINDOWS_RECORD_VERSION,
            vault_id: vault_id.into(),
            device_id: device_id.into(),
            credential_id,
            salt,
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
        })
    }

    fn open_record(
        record: &WindowsHelloRecord,
        prf: &[u8; PRF_BYTES],
    ) -> VaultResult<Zeroizing<[u8; DEVICE_KEY_BYTES]>> {
        if record.version != WINDOWS_RECORD_VERSION {
            return Err(VaultError::QuickUnlockNotConfigured);
        }
        let nonce = decode_bounded(&record.nonce, NONCE_BYTES)?;
        let nonce: [u8; NONCE_BYTES] = nonce
            .try_into()
            .map_err(|_| VaultError::QuickUnlockNotConfigured)?;
        let ciphertext = decode_bounded(&record.ciphertext, DEVICE_KEY_BYTES + 16)?;
        let aad = record_aad(
            &record.vault_id,
            &record.device_id,
            &record.credential_id,
            &record.salt,
        )?;
        let wrapping_key = derive_wrapping_key(&record.vault_id, &record.device_id, prf)?;
        let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key.as_ref())
            .map_err(|_| VaultError::DeviceAuthenticationFailed)?;
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: &ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| VaultError::DeviceAuthenticationFailed)?,
        );
        if plaintext.len() != DEVICE_KEY_BYTES {
            return Err(VaultError::DeviceAuthenticationFailed);
        }
        let mut device_key = Zeroizing::new([0_u8; DEVICE_KEY_BYTES]);
        device_key.copy_from_slice(plaintext.as_slice());
        Ok(device_key)
    }

    fn derive_wrapping_key(
        vault_id: &str,
        device_id: &str,
        prf: &[u8; PRF_BYTES],
    ) -> VaultResult<Zeroizing<[u8; 32]>> {
        let hkdf = Hkdf::<Sha256>::new(Some(vault_id.as_bytes()), prf);
        let mut wrapping_key = Zeroizing::new([0_u8; 32]);
        let info = format!("CipherNest Windows Hello device-key-v1\0{device_id}");
        hkdf.expand(info.as_bytes(), wrapping_key.as_mut())
            .map_err(|_| VaultError::DeviceKeyStore)?;
        Ok(wrapping_key)
    }

    fn record_aad(
        vault_id: &str,
        device_id: &str,
        credential_id: &str,
        salt: &str,
    ) -> VaultResult<Vec<u8>> {
        serde_json::to_vec(&RecordAad {
            version: WINDOWS_RECORD_VERSION,
            vault_id,
            device_id,
            credential_id,
            salt,
        })
        .map_err(|_| VaultError::DeviceKeyStore)
    }

    fn decode_bounded(value: &str, expected_max: usize) -> VaultResult<Vec<u8>> {
        let decoded = URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| VaultError::QuickUnlockNotConfigured)?;
        if decoded.is_empty() || decoded.len() > expected_max {
            return Err(VaultError::QuickUnlockNotConfigured);
        }
        Ok(decoded)
    }

    fn read_record(
        path: &Path,
        vault_id: &str,
        device_id: &str,
    ) -> VaultResult<WindowsHelloRecord> {
        let metadata = fs::metadata(path).map_err(|_| VaultError::QuickUnlockNotConfigured)?;
        if metadata.len() == 0 || metadata.len() > WINDOWS_RECORD_MAX_BYTES {
            return Err(VaultError::QuickUnlockNotConfigured);
        }
        let bytes = fs::read(path).map_err(|_| VaultError::QuickUnlockNotConfigured)?;
        let record: WindowsHelloRecord =
            serde_json::from_slice(&bytes).map_err(|_| VaultError::QuickUnlockNotConfigured)?;
        if record.version != WINDOWS_RECORD_VERSION
            || record.vault_id != vault_id
            || record.device_id != device_id
        {
            return Err(VaultError::QuickUnlockNotConfigured);
        }
        Ok(record)
    }

    fn write_record_atomic(path: &Path, record: &WindowsHelloRecord) -> VaultResult<()> {
        let parent = path.parent().ok_or(VaultError::DeviceKeyStore)?;
        fs::create_dir_all(parent).map_err(|_| VaultError::DeviceKeyStore)?;
        let bytes = serde_json::to_vec(record).map_err(|_| VaultError::DeviceKeyStore)?;
        if bytes.is_empty() || bytes.len() as u64 > WINDOWS_RECORD_MAX_BYTES {
            return Err(VaultError::DeviceKeyStore);
        }
        AtomicFile::new(path, OverwriteBehavior::AllowOverwrite)
            .write(|file| -> io::Result<()> {
                file.write_all(&bytes)?;
                file.sync_all()
            })
            .map_err(|_| VaultError::DeviceKeyStore)
    }

    fn checked_u32(value: usize) -> VaultResult<u32> {
        u32::try_from(value).map_err(|_| VaultError::DeviceKeyStore)
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
mod platform {
    use super::*;
    use crate::error::VaultError;

    pub fn availability() -> PlatformQuickUnlock {
        PlatformQuickUnlock {
            available: false,
            method: "unsupported",
            label: "系统快速解锁",
            reason: Some("Linux 版本暂不保存可绕过主密码的设备密钥。请使用主密码解锁。".into()),
        }
    }

    pub fn provider() -> Option<DeviceKeyProvider> {
        None
    }

    pub fn store_device_key<R: Runtime>(
        _window: &WebviewWindow<R>,
        _metadata_path: &Path,
        _vault_id: &str,
        _device_id: &str,
        _device_key: &[u8; DEVICE_KEY_BYTES],
    ) -> VaultResult<()> {
        Err(VaultError::QuickUnlockUnavailable)
    }

    pub fn load_device_key<R: Runtime>(
        _window: &WebviewWindow<R>,
        _metadata_path: &Path,
        _vault_id: &str,
        _device_id: &str,
    ) -> VaultResult<Zeroizing<[u8; DEVICE_KEY_BYTES]>> {
        Err(VaultError::QuickUnlockUnavailable)
    }

    pub fn remove_device_key(
        _metadata_path: &Path,
        _vault_id: &str,
        _device_id: &str,
    ) -> VaultResult<()> {
        Ok(())
    }
}
