//! Append-only encrypted synchronization for WebDAV collections that support
//! ordinary PROPFIND, PUT, and GET but do not implement conditional writes.
//!
//! Every writer creates a distinct content-addressed object. No request
//! overwrites a shared remote pointer. This provides eventual convergence on
//! an honest WebDAV server; it cannot prove that a server listed an unseen
//! object's existence or that a first join received the latest history.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fs::{self, File},
    io::{self, Read, Write},
    path::Path,
    time::Duration,
};

use atomicwrites::{AtomicFile, OverwriteBehavior};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use quick_xml::{events::Event as XmlEvent, name::ResolveResult, NsReader};
use reqwest::{
    header::{ACCEPT, ACCEPT_ENCODING, CACHE_CONTROL, CONTENT_TYPE},
    tls::Version as TlsVersion,
    Method, StatusCode, Url,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    models::{Tombstone, VaultEntry, MAX_VAULT_ENTRIES, MAX_VAULT_TOMBSTONES},
    sync::{self, SyncContent, SyncError, SyncResult},
};

const EVENT_FORMAT: &str = "CipherNestSyncEvent";
const STATE_FORMAT: &str = "CipherNestLocalSyncV2State";
const VERSION: u32 = 2;
const MAX_EVENT_BYTES: usize = 32 * 1024 * 1024;
const MAX_TOTAL_REMOTE_BYTES: usize = 256 * 1024 * 1024;
const MAX_STATE_BYTES: usize = 96 * 1024 * 1024;
const MAX_LIST_BYTES: usize = 16 * 1024 * 1024;
const MAX_EVENTS: usize = 40_000;
const MAX_TOTAL_OPERATIONS: usize = 200_000;
const MAX_DEVICES: usize = 64;
const MAX_REMOTE_NAME: usize = 128;
const MAX_XML_FIELD: usize = 4096;
const MAX_EVENT_OPERATIONS: usize = MAX_VAULT_ENTRIES + MAX_VAULT_TOMBSTONES;
// A matching directory listing only proves that the names have not changed.
// Re-fetch the authenticated objects regularly to detect in-place tampering.
const MAX_FAST_POLL_AGE_MS: u64 = 60 * 60 * 1000;

const LIST_BODY: &[u8] = br#"<?xml version="1.0" encoding="utf-8"?>
<d:propfind xmlns:d="DAV:"><d:prop><d:getcontentlength/></d:prop></d:propfind>"#;

#[derive(Clone)]
pub struct RecoveryMaterial {
    space_id: String,
    key: Zeroizing<[u8; 32]>,
}

impl RecoveryMaterial {
    pub fn generate() -> SyncResult<Self> {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key).map_err(|_| SyncError::InvalidData)?;
        Ok(Self {
            space_id: Uuid::new_v4().to_string(),
            key: Zeroizing::new(key),
        })
    }

    pub fn parse(code: &str) -> SyncResult<Self> {
        let mut parts = code.split('.');
        if parts.next() != Some("CN2") {
            return Err(SyncError::InvalidRecoveryCode);
        }
        let space_id = parts.next().ok_or(SyncError::InvalidRecoveryCode)?;
        let encoded = parts.next().ok_or(SyncError::InvalidRecoveryCode)?;
        if parts.next().is_some() || !valid_uuid(space_id) {
            return Err(SyncError::InvalidRecoveryCode);
        }
        let bytes = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(encoded)
                .map_err(|_| SyncError::InvalidRecoveryCode)?,
        );
        let key: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| SyncError::InvalidRecoveryCode)?;
        if key == [0; 32] {
            return Err(SyncError::InvalidRecoveryCode);
        }
        let material = Self {
            space_id: space_id.to_owned(),
            key: Zeroizing::new(key),
        };
        if material.code().as_str() != code {
            return Err(SyncError::InvalidRecoveryCode);
        }
        Ok(material)
    }

    pub fn code(&self) -> Zeroizing<String> {
        Zeroizing::new(format!(
            "CN2.{}.{}",
            self.space_id,
            URL_SAFE_NO_PAD.encode(self.key.as_ref())
        ))
    }

    pub fn space_id(&self) -> &str {
        &self.space_id
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeviceCheckpoint {
    pub counter: u64,
    pub hash: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendingEvent {
    pub name: String,
    #[serde(with = "base64_bytes")]
    pub bytes: Vec<u8>,
    pub source_generation: u64,
    pub source_content: SyncContent,
}

mod base64_bytes {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        if encoded.len() > MAX_EVENT_BYTES.saturating_mul(4) / 3 + 8 {
            return Err(serde::de::Error::custom("pending event too large"));
        }
        URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(serde::de::Error::custom)
    }
}

impl Drop for PendingEvent {
    fn drop(&mut self) {
        self.bytes.zeroize();
        self.name.zeroize();
    }
}

impl PendingEvent {
    pub fn event_hash(&self) -> &str {
        event_hash_from_name(&self.name).unwrap_or("")
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalState {
    state_version: u32,
    pub endpoint: String,
    pub username: String,
    pub app_password: String,
    pub space_id: String,
    pub root_key: [u8; 32],
    pub device_id: String,
    pub device_counter: u64,
    pub seen: BTreeMap<String, DeviceCheckpoint>,
    pub base_content: SyncContent,
    pub record_heads: BTreeMap<String, Vec<String>>,
    pub last_local_generation: u64,
    pub last_sync_at: Option<u64>,
    /// Fingerprint of the complete event-name listing from the last view
    /// whose objects were downloaded, authenticated, and accepted locally.
    #[serde(default)]
    pub verified_listing_hash: Option<String>,
    #[serde(default)]
    pub automatic: bool,
    #[serde(default)]
    pub auto_paused: bool,
    #[serde(default)]
    pub auto_warning: Option<String>,
    #[serde(default)]
    pub pending: Option<PendingEvent>,
}

impl Drop for LocalState {
    fn drop(&mut self) {
        self.app_password.zeroize();
        self.root_key.zeroize();
    }
}

impl LocalState {
    pub fn recovery_material(&self) -> SyncResult<RecoveryMaterial> {
        self.validate()?;
        Ok(RecoveryMaterial {
            space_id: self.space_id.clone(),
            key: Zeroizing::new(self.root_key),
        })
    }

    pub fn recovery_code(&self) -> SyncResult<Zeroizing<String>> {
        Ok(self.recovery_material()?.code())
    }

    pub fn validate(&self) -> SyncResult<()> {
        if self.state_version != VERSION
            || !valid_uuid(&self.space_id)
            || !valid_uuid(&self.device_id)
            || self.root_key == [0; 32]
            || self.last_local_generation == 0
            || self.seen.len() > MAX_DEVICES
            || self.record_heads.len() > MAX_EVENT_OPERATIONS
            || self.endpoint.len() > 2048
            || self.username.chars().count() > 512
            || self.username.is_empty()
            || self.app_password.is_empty()
            || self.app_password.len() > 4096
            || self
                .verified_listing_hash
                .as_ref()
                .is_some_and(|hash| !valid_hash(hash))
            || (self.verified_listing_hash.is_some()
                && (self.last_sync_at.is_none() || self.pending.is_some()))
        {
            return Err(SyncError::InvalidLocalState);
        }
        sync::validate_webdav_endpoint(&self.endpoint).map_err(|_| SyncError::InvalidLocalState)?;
        validate_content(&self.base_content).map_err(|_| SyncError::InvalidLocalState)?;
        let base_ids: HashSet<_> = self
            .base_content
            .entries
            .iter()
            .map(|entry| entry.id.as_str())
            .chain(
                self.base_content
                    .tombstones
                    .iter()
                    .map(|item| item.id.as_str()),
            )
            .collect();
        if self.record_heads.len() != base_ids.len()
            || self.record_heads.iter().any(|(id, heads)| {
                !base_ids.contains(id.as_str())
                    || heads.is_empty()
                    || heads.len() > MAX_DEVICES * 2
                    || heads.windows(2).any(|pair| pair[0] >= pair[1])
                    || heads.iter().any(|head| !valid_operation_ref(head))
            })
        {
            return Err(SyncError::InvalidLocalState);
        }
        for (id, checkpoint) in &self.seen {
            if !valid_uuid(id) || checkpoint.counter == 0 || !valid_hash(&checkpoint.hash) {
                return Err(SyncError::InvalidLocalState);
            }
        }
        if let Some(pending) = &self.pending {
            if pending.source_generation == 0
                || pending.source_generation < self.last_local_generation
                || !valid_event_name(&pending.name, &self.space_id)
                || sha256_hex(&pending.bytes) != pending.event_hash()
            {
                return Err(SyncError::InvalidLocalState);
            }
            validate_content(&pending.source_content).map_err(|_| SyncError::InvalidLocalState)?;
            let payload = verify_pending(pending, &self.recovery_material_unchecked())
                .map_err(|_| SyncError::InvalidLocalState)?
                .payload;
            if payload.device_id != self.device_id
                || payload.counter != self.device_counter.saturating_add(1)
                || payload.prev_event_hash
                    != self
                        .seen
                        .get(&self.device_id)
                        .map(|checkpoint| checkpoint.hash.clone())
            {
                return Err(SyncError::InvalidLocalState);
            }
        }
        Ok(())
    }

    fn recovery_material_unchecked(&self) -> RecoveryMaterial {
        RecoveryMaterial {
            space_id: self.space_id.clone(),
            key: Zeroizing::new(self.root_key),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
enum RecordValue {
    Entry(VaultEntry),
    Deleted(Tombstone),
}

impl RecordValue {
    fn id(&self) -> &str {
        match self {
            Self::Entry(value) => &value.id,
            Self::Deleted(value) => &value.id,
        }
    }

    fn is_deleted(&self) -> bool {
        matches!(self, Self::Deleted(_))
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Mutation {
    parents: Vec<String>,
    value: RecordValue,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EventPayload {
    protocol_version: u32,
    space_id: String,
    genesis: bool,
    device_id: String,
    counter: u64,
    prev_event_hash: Option<String>,
    observed_heads: BTreeMap<String, String>,
    created_at: u64,
    mutations: Vec<Mutation>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EncryptedEvent {
    format: String,
    version: u32,
    nonce: String,
    ciphertext: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LocalEnvelope {
    format: String,
    version: u32,
    vault_id: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Clone)]
struct VerifiedEvent {
    hash: String,
    payload: EventPayload,
}

pub struct RemoteView {
    pub content: SyncContent,
    pub seen: BTreeMap<String, DeviceCheckpoint>,
    pub record_heads: BTreeMap<String, Vec<String>>,
    pub event_count: usize,
    pub latest_at: u64,
    total_bytes: usize,
    events: Vec<VerifiedEvent>,
}

impl RemoteView {
    pub fn is_empty(&self) -> bool {
        self.event_count == 0
    }
}

pub struct WebDavV2Client {
    client: reqwest::Client,
    endpoint: Url,
    username: String,
    app_password: Zeroizing<String>,
}

impl WebDavV2Client {
    pub fn new(endpoint: &str, username: String, app_password: String) -> SyncResult<Self> {
        let app_password = Zeroizing::new(app_password);
        let endpoint = sync::validate_webdav_endpoint(endpoint)?;
        if username.is_empty()
            || username.chars().count() > 512
            || app_password.is_empty()
            || app_password.len() > 4096
        {
            return Err(SyncError::InvalidCredentials);
        }
        let builder = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .min_tls_version(TlsVersion::TLS_1_2)
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(45))
            .no_proxy()
            .user_agent("CipherNest-WebDAV/2");
        #[cfg(target_os = "windows")]
        let builder = builder.use_native_tls();
        Ok(Self {
            client: builder.build().map_err(|_| SyncError::Transport)?,
            endpoint,
            username,
            app_password,
        })
    }

    pub fn from_state(state: &LocalState) -> SyncResult<Self> {
        state.validate()?;
        Self::new(
            &state.endpoint,
            state.username.clone(),
            state.app_password.clone(),
        )
    }

    pub fn endpoint(&self) -> &str {
        self.endpoint.as_str()
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub async fn ensure_existing_collection(&self) -> SyncResult<()> {
        let method = Method::from_bytes(b"PROPFIND").map_err(|_| SyncError::Transport)?;
        let response = self
            .request(method, self.endpoint.clone())
            .header("Depth", "0")
            .header(CONTENT_TYPE, "application/xml; charset=utf-8")
            .header(ACCEPT, "application/xml, text/xml")
            .body(sync::PROPFIND_BODY)
            .send()
            .await
            .map_err(sync::classify_transport_error)?;
        if response.status() == StatusCode::NOT_FOUND {
            return Err(SyncError::NotACollection);
        }
        if response.status() != StatusCode::MULTI_STATUS {
            return Err(SyncError::UnexpectedStatus(response.status().as_u16()));
        }
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if !content_type.starts_with("application/xml") && !content_type.starts_with("text/xml") {
            return Err(SyncError::NotACollection);
        }
        let body = read_limited(response, sync::MAX_PROPFIND_BYTES).await?;
        if !sync::propfind_reports_collection(&body, &self.endpoint)? {
            return Err(SyncError::NotACollection);
        }
        Ok(())
    }

    fn request(&self, method: Method, url: Url) -> reqwest::RequestBuilder {
        self.client
            .request(method, url)
            .basic_auth(&self.username, Some(self.app_password.as_str()))
            .header(CACHE_CONTROL, "no-cache, no-store")
            .header(ACCEPT_ENCODING, "identity")
    }

    fn object_url(&self, name: &str) -> SyncResult<Url> {
        if name.is_empty()
            || name.len() > MAX_REMOTE_NAME
            || !name
                .bytes()
                .all(|value| value.is_ascii_alphanumeric() || matches!(value, b'-' | b'.'))
        {
            return Err(SyncError::InvalidData);
        }
        self.endpoint
            .join(name)
            .map_err(|_| SyncError::InvalidEndpoint)
    }

    async fn get_exact(&self, name: &str) -> SyncResult<Option<Vec<u8>>> {
        let response = self
            .request(Method::GET, self.object_url(name)?)
            .header(ACCEPT, "application/octet-stream")
            .send()
            .await
            .map_err(map_network_error)?;
        match response.status() {
            StatusCode::NOT_FOUND => Ok(None),
            StatusCode::OK => read_limited(response, MAX_EVENT_BYTES).await.map(Some),
            other => Err(SyncError::UnexpectedStatus(other.as_u16())),
        }
    }

    pub async fn upload(&self, pending: &PendingEvent) -> SyncResult<()> {
        let hash = event_hash_from_name(&pending.name).ok_or(SyncError::InvalidData)?;
        if pending.bytes.is_empty()
            || pending.bytes.len() > MAX_EVENT_BYTES
            || sha256_hex(&pending.bytes) != hash
        {
            return Err(SyncError::InvalidData);
        }
        // An interrupted PUT may already have completed. Never overwrite an
        // existing object, even if this server ignores conditional headers.
        if let Some(existing) = self.get_exact(&pending.name).await? {
            return if existing == pending.bytes {
                Ok(())
            } else {
                Err(SyncError::HashMismatch)
            };
        }
        let response = self
            .request(Method::PUT, self.object_url(&pending.name)?)
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(pending.bytes.clone())
            .send()
            .await
            .map_err(map_network_error)?;
        if !matches!(
            response.status(),
            StatusCode::OK | StatusCode::CREATED | StatusCode::NO_CONTENT
        ) {
            return Err(SyncError::UnexpectedStatus(response.status().as_u16()));
        }
        let fetched = self.get_exact(&pending.name).await?;
        if fetched.as_deref() != Some(pending.bytes.as_slice()) {
            return Err(SyncError::HashMismatch);
        }
        Ok(())
    }

    pub async fn fetch(
        &self,
        material: &RecoveryMaterial,
        checkpoint: Option<&LocalState>,
    ) -> SyncResult<RemoteView> {
        self.ensure_existing_collection().await?;
        if let Some(state) = checkpoint {
            state.validate()?;
            if state.space_id != material.space_id
                || state.root_key != *material.key
                || state.endpoint != self.endpoint.as_str()
                || state.username != self.username
            {
                return Err(SyncError::InvalidLocalState);
            }
        }
        let names = self.list_event_names(&material.space_id).await?;
        let mut events = Vec::with_capacity(names.len());
        let mut total_bytes = 0usize;
        for name in names {
            let hash = event_hash_from_name(&name).ok_or(SyncError::InvalidRemoteObject)?;
            let bytes = self
                .get_exact(&name)
                .await?
                .ok_or(SyncError::RollbackOrFork)?;
            total_bytes = total_bytes.saturating_add(bytes.len());
            if total_bytes > MAX_TOTAL_REMOTE_BYTES {
                return Err(SyncError::TooLarge);
            }
            if sha256_hex(&bytes) != hash {
                return Err(SyncError::HashMismatch);
            }
            let payload = decrypt_event(&bytes, material)?;
            events.push(VerifiedEvent {
                hash: hash.to_owned(),
                payload,
            });
        }
        let mut view = replay(&material.space_id, events)?;
        view.total_bytes = total_bytes;
        if let Some(state) = checkpoint {
            validate_remote_checkpoint(state, &view)?;
        }
        Ok(view)
    }

    /// Cheap background check for a previously authenticated, durable view.
    /// `true` means there is nothing to apply; the caller must not advance a
    /// checkpoint or overwrite local state. A changed listing, a local edit,
    /// or an expired full verification requires the normal `fetch` path.
    /// Manual synchronization should always call `fetch` directly.
    pub async fn poll_unchanged(
        &self,
        state: &LocalState,
        current: &SyncContent,
        current_generation: u64,
        now: u64,
    ) -> SyncResult<bool> {
        state.validate()?;
        if state.endpoint != self.endpoint.as_str() || state.username != self.username {
            return Err(SyncError::InvalidLocalState);
        }
        validate_content(current)?;
        if !fast_poll_allowed(state, current, current_generation, now) {
            return Ok(false);
        }
        let names = self.list_event_names(&state.space_id).await?;
        Ok(state.verified_listing_hash.as_deref()
            == Some(listing_fingerprint(&names, &state.space_id)?.as_str()))
    }

    async fn list_event_names(&self, space_id: &str) -> SyncResult<Vec<String>> {
        let method = Method::from_bytes(b"PROPFIND").map_err(|_| SyncError::Transport)?;
        let response = self
            .request(method, self.endpoint.clone())
            .header("Depth", "1")
            .header(CONTENT_TYPE, "application/xml; charset=utf-8")
            .header(ACCEPT, "application/xml, text/xml")
            .body(LIST_BODY)
            .send()
            .await
            .map_err(map_network_error)?;
        if response.status() != StatusCode::MULTI_STATUS {
            return Err(SyncError::UnexpectedStatus(response.status().as_u16()));
        }
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if !content_type.starts_with("application/xml") && !content_type.starts_with("text/xml") {
            return Err(SyncError::InvalidRemoteObject);
        }
        let bytes = read_limited(response, MAX_LIST_BYTES).await?;
        parse_listing(&bytes, &self.endpoint, space_id)
    }
}

fn validate_remote_checkpoint(state: &LocalState, view: &RemoteView) -> SyncResult<()> {
    for (device_id, previous) in &state.seen {
        let Some(current) = view.seen.get(device_id) else {
            return Err(SyncError::RollbackOrFork);
        };
        if current.counter < previous.counter
            || !view.events.iter().any(|event| {
                event.payload.device_id == *device_id
                    && event.payload.counter == previous.counter
                    && event.hash == previous.hash
            })
        {
            return Err(SyncError::RollbackOrFork);
        }
    }
    if let Some(current_self) = view.seen.get(&state.device_id) {
        let expected = state.device_counter;
        let current_is_exact_pending = state.pending.as_ref().is_some_and(|pending| {
            current_self.counter == expected.saturating_add(1)
                && current_self.hash == pending.event_hash()
        });
        if current_self.counter > expected && !current_is_exact_pending {
            // A cloned device ID or rolled-back sidecar could create a
            // second writer for this stream. Never silently adopt it.
            return Err(SyncError::RollbackOrFork);
        }
    }
    Ok(())
}

impl LocalState {
    /// Creates an uncommitted new space. The caller must atomically write this
    /// state with its pending event before attempting the remote upload.
    pub fn prepare_initial(
        client: &WebDavV2Client,
        material: &RecoveryMaterial,
        device_id: &str,
        content: &SyncContent,
        generation: u64,
        now: u64,
    ) -> SyncResult<Self> {
        if !valid_uuid(device_id) || generation == 0 || now == 0 {
            return Err(SyncError::InvalidData);
        }
        validate_content(content)?;
        let mutations = content_records(content)
            .into_values()
            .map(|value| Mutation {
                parents: Vec::new(),
                value,
            })
            .collect();
        let event = EventPayload {
            protocol_version: VERSION,
            space_id: material.space_id.clone(),
            genesis: true,
            device_id: device_id.to_owned(),
            counter: 1,
            prev_event_hash: None,
            observed_heads: BTreeMap::new(),
            created_at: now,
            mutations,
        };
        let pending = make_pending(&event, material, generation, content)?;
        let state = Self {
            state_version: VERSION,
            endpoint: client.endpoint().to_owned(),
            username: client.username().to_owned(),
            app_password: client.app_password.as_str().to_owned(),
            space_id: material.space_id.clone(),
            root_key: *material.key,
            device_id: device_id.to_owned(),
            device_counter: 0,
            seen: BTreeMap::new(),
            base_content: SyncContent {
                entries: Vec::new(),
                tombstones: Vec::new(),
            },
            record_heads: BTreeMap::new(),
            last_local_generation: generation,
            last_sync_at: None,
            verified_listing_hash: None,
            automatic: true,
            auto_paused: false,
            auto_warning: None,
            pending: Some(pending),
        };
        state.validate()?;
        Ok(state)
    }

    /// Makes a joined device state anchored to the exact previewed event set.
    /// Caller should re-fetch and compare `RemoteView::fingerprint` at confirm.
    pub fn prepare_join(
        client: &WebDavV2Client,
        material: &RecoveryMaterial,
        device_id: &str,
        remote: &RemoteView,
        local_content: &SyncContent,
        generation: u64,
        now: u64,
    ) -> SyncResult<(Self, SyncContent)> {
        if remote.is_empty() || !valid_uuid(device_id) || generation == 0 || now == 0 {
            return Err(SyncError::RemoteNotInitialized);
        }
        if remote.seen.len() >= MAX_DEVICES {
            return Err(SyncError::TooLarge);
        }
        validate_content(local_content)?;
        let mut state = Self {
            state_version: VERSION,
            endpoint: client.endpoint().to_owned(),
            username: client.username().to_owned(),
            app_password: client.app_password.as_str().to_owned(),
            space_id: material.space_id.clone(),
            root_key: *material.key,
            device_id: device_id.to_owned(),
            device_counter: 0,
            seen: remote.seen.clone(),
            base_content: remote.content.clone(),
            record_heads: remote.record_heads.clone(),
            last_local_generation: generation,
            last_sync_at: Some(now),
            verified_listing_hash: None,
            automatic: true,
            auto_paused: false,
            auto_warning: None,
            pending: None,
        };
        if state.seen.contains_key(device_id) {
            return Err(SyncError::InvalidLocalState);
        }
        let remote_records = content_records(&remote.content);
        let local_records = content_records(local_content);
        let mut mutations = Vec::new();
        for (id, value) in local_records {
            if remote_records
                .get(&id)
                .is_some_and(|remote| record_equal(remote, &value))
            {
                continue;
            }
            // First join has no common ancestry for differing records. An
            // empty parent set makes a same-ID collision a visible conflict.
            mutations.push(Mutation {
                parents: Vec::new(),
                value,
            });
        }
        if !mutations.is_empty() {
            let event = make_event(&state, mutations, now)?;
            state.pending = Some(make_pending(&event, material, generation, local_content)?);
        } else {
            state.verified_listing_hash = Some(remote.fingerprint());
        }
        state.validate()?;
        let content = if let Some(pending) = &state.pending {
            let event = verify_pending(pending, material)?;
            let mut events = remote.events.clone();
            events.push(event);
            replay(&material.space_id, events)?.content
        } else {
            remote.content.clone()
        };
        Ok((state, content))
    }

    /// Stages local mutations against the last accepted base, not against a
    /// newly fetched remote view. This preserves true concurrency semantics.
    pub fn prepare_local_changes(
        &mut self,
        current: &SyncContent,
        generation: u64,
        now: u64,
    ) -> SyncResult<bool> {
        self.validate()?;
        validate_content(current)?;
        if self.pending.is_some() {
            return Err(SyncError::InvalidLocalState);
        }
        if generation < self.last_local_generation {
            return Err(SyncError::LocalRollback);
        }
        if generation == self.last_local_generation && !contents_equal(current, &self.base_content)
        {
            return Err(SyncError::LocalRollback);
        }
        let before = content_records(&self.base_content);
        let after = content_records(current);
        let mut mutations = Vec::new();
        for (id, old_value) in &before {
            if !after.contains_key(id) {
                // Absence is never interpreted as deletion. Vault mutations
                // must persist a tombstone explicitly.
                let _ = old_value;
                return Err(SyncError::InvalidData);
            }
        }
        for (id, value) in &after {
            if before.get(id).is_some_and(|old| record_equal(old, value)) {
                continue;
            }
            let parents = self.record_heads.get(id).cloned().unwrap_or_default();
            mutations.push(Mutation {
                parents,
                value: value.clone(),
            });
        }
        if mutations.is_empty() {
            return Ok(false);
        }
        let event = make_event(self, mutations, now)?;
        let material = self.recovery_material()?;
        self.pending = Some(make_pending(&event, &material, generation, current)?);
        self.verified_listing_hash = None;
        self.validate()?;
        Ok(true)
    }

    /// Call only after `WebDavV2Client::upload` has read back the exact pending
    /// object. This advances the causal baseline to that upload, then stages
    /// local edits made while the upload was pending. Persist the resulting
    /// state atomically before sending another event.
    pub fn stage_followup_after_verified_upload(
        &mut self,
        current: &SyncContent,
        current_generation: u64,
        now: u64,
    ) -> SyncResult<bool> {
        self.validate()?;
        validate_content(current)?;
        let pending = self.pending.as_ref().ok_or(SyncError::InvalidLocalState)?;
        if current_generation < pending.source_generation
            || (current_generation == pending.source_generation
                && !contents_equal(current, &pending.source_content))
        {
            return Err(SyncError::LocalRollback);
        }
        let event = verify_pending(pending, &self.recovery_material_unchecked())?;
        let source_content = pending.source_content.clone();
        let source_generation = pending.source_generation;
        let source_ids: HashSet<String> = content_records(&source_content).into_keys().collect();
        self.record_heads.retain(|id, _| source_ids.contains(id));
        for (index, mutation) in event.payload.mutations.iter().enumerate() {
            self.record_heads.insert(
                mutation.value.id().to_owned(),
                vec![format!("{}:{index}", event.hash)],
            );
        }
        self.seen.insert(
            self.device_id.clone(),
            DeviceCheckpoint {
                counter: event.payload.counter,
                hash: event.hash,
            },
        );
        self.device_counter = event.payload.counter;
        self.base_content = source_content;
        self.last_local_generation = source_generation;
        self.pending = None;
        self.verified_listing_hash = None;
        let staged_newer_edits = self.prepare_local_changes(current, current_generation, now)?;
        self.validate()?;
        Ok(staged_newer_edits)
    }

    /// Advances an authenticated local checkpoint after the caller has made
    /// `view.content` durable in the vault. Pending events must already have
    /// been acknowledged; accepting remote content with a pending event could
    /// discard newer local edits that were made after that event was staged.
    pub fn accept_view(
        &mut self,
        view: &RemoteView,
        persisted_generation: u64,
        now: u64,
    ) -> SyncResult<()> {
        self.validate()?;
        if persisted_generation < self.last_local_generation || now == 0 {
            return Err(SyncError::LocalRollback);
        }
        if self.pending.is_some() {
            return Err(SyncError::InvalidLocalState);
        }
        for (device_id, previous) in &self.seen {
            let current = view.seen.get(device_id).ok_or(SyncError::RollbackOrFork)?;
            if current.counter < previous.counter
                || !view.events.iter().any(|event| {
                    event.payload.device_id == *device_id
                        && event.payload.counter == previous.counter
                        && event.hash == previous.hash
                })
            {
                return Err(SyncError::RollbackOrFork);
            }
        }
        self.device_counter = view
            .seen
            .get(&self.device_id)
            .map_or(self.device_counter, |checkpoint| checkpoint.counter);
        self.seen = view.seen.clone();
        self.base_content = view.content.clone();
        self.record_heads = view.record_heads.clone();
        self.last_local_generation = persisted_generation;
        self.last_sync_at = Some(now);
        self.verified_listing_hash = Some(view.fingerprint());
        self.auto_paused = false;
        self.auto_warning = None;
        self.validate()
    }
}

impl RemoteView {
    /// Check the prospective authenticated history before writing an event.
    /// A concurrent writer can still publish after this check; no ordinary
    /// WebDAV operation can make a global capacity check atomic.
    pub fn ensure_publishable(
        &self,
        pending: &PendingEvent,
        material: &RecoveryMaterial,
    ) -> SyncResult<()> {
        let event = verify_pending(pending, material)?;
        if self.events.iter().any(|known| known.hash == event.hash) {
            return Ok(());
        }
        if self.event_count >= MAX_EVENTS
            || self.total_bytes.saturating_add(pending.bytes.len()) > MAX_TOTAL_REMOTE_BYTES
        {
            return Err(SyncError::TooLarge);
        }
        let mut prospective = self.events.clone();
        prospective.push(event);
        replay(material.space_id(), prospective)?;
        Ok(())
    }

    /// Exact fingerprint of the listed authenticated event set for preview
    /// tokens. A new event requires a new preview before joining.
    pub fn fingerprint(&self) -> String {
        hash_event_set(self.events.iter().map(|event| event.hash.as_str()))
    }
}

fn hash_event_set<'a>(hashes: impl IntoIterator<Item = &'a str>) -> String {
    let mut hasher = Sha256::new();
    for hash in hashes {
        hasher.update(hash.as_bytes());
        hasher.update(b"\n");
    }
    format!("{:x}", hasher.finalize())
}

fn listing_fingerprint(names: &[String], space_id: &str) -> SyncResult<String> {
    if names.len() > MAX_EVENTS || !valid_uuid(space_id) {
        return Err(SyncError::TooLarge);
    }
    let mut hashes = Vec::with_capacity(names.len());
    let mut previous: Option<&str> = None;
    for name in names {
        if !valid_event_name(name, space_id) || previous.is_some_and(|last| last >= name.as_str()) {
            return Err(SyncError::InvalidRemoteObject);
        }
        previous = Some(name);
        hashes.push(event_hash_from_name(name).ok_or(SyncError::InvalidRemoteObject)?);
    }
    Ok(hash_event_set(hashes))
}

fn fast_poll_allowed(
    state: &LocalState,
    current: &SyncContent,
    current_generation: u64,
    now: u64,
) -> bool {
    state.pending.is_none()
        && state.verified_listing_hash.is_some()
        && state
            .last_sync_at
            .is_some_and(|last| now >= last && now - last < MAX_FAST_POLL_AGE_MS)
        && current_generation == state.last_local_generation
        && contents_equal(current, &state.base_content)
}

fn make_event(state: &LocalState, mutations: Vec<Mutation>, now: u64) -> SyncResult<EventPayload> {
    if now == 0 || mutations.is_empty() || mutations.len() > MAX_EVENT_OPERATIONS {
        return Err(SyncError::InvalidData);
    }
    let counter = state
        .device_counter
        .checked_add(1)
        .ok_or(SyncError::InvalidData)?;
    let prev_event_hash = state
        .seen
        .get(&state.device_id)
        .map(|value| value.hash.clone());
    if (counter == 1) != prev_event_hash.is_none() {
        return Err(SyncError::InvalidLocalState);
    }
    let observed_heads = state
        .seen
        .iter()
        .map(|(id, value)| (id.clone(), value.hash.clone()))
        .collect();
    Ok(EventPayload {
        protocol_version: VERSION,
        space_id: state.space_id.clone(),
        genesis: false,
        device_id: state.device_id.clone(),
        counter,
        prev_event_hash,
        observed_heads,
        created_at: now,
        mutations,
    })
}

fn make_pending(
    payload: &EventPayload,
    material: &RecoveryMaterial,
    generation: u64,
    source_content: &SyncContent,
) -> SyncResult<PendingEvent> {
    if generation == 0 {
        return Err(SyncError::InvalidData);
    }
    let bytes = encrypt_event(payload, material)?;
    let hash = sha256_hex(&bytes);
    Ok(PendingEvent {
        name: event_name(&material.space_id, &hash)?,
        bytes,
        source_generation: generation,
        source_content: source_content.clone(),
    })
}

fn verify_pending(
    pending: &PendingEvent,
    material: &RecoveryMaterial,
) -> SyncResult<VerifiedEvent> {
    if !valid_event_name(&pending.name, &material.space_id) {
        return Err(SyncError::InvalidLocalState);
    }
    let hash = sha256_hex(&pending.bytes);
    if event_hash_from_name(&pending.name) != Some(hash.as_str()) {
        return Err(SyncError::HashMismatch);
    }
    Ok(VerifiedEvent {
        hash,
        payload: decrypt_event(&pending.bytes, material)?,
    })
}

fn content_records(content: &SyncContent) -> BTreeMap<String, RecordValue> {
    let mut records = BTreeMap::new();
    for entry in &content.entries {
        records.insert(entry.id.clone(), RecordValue::Entry(entry.clone()));
    }
    for tombstone in &content.tombstones {
        records.insert(
            tombstone.id.clone(),
            RecordValue::Deleted(tombstone.clone()),
        );
    }
    records
}

fn record_equal(left: &RecordValue, right: &RecordValue) -> bool {
    match (left, right) {
        (RecordValue::Entry(a), RecordValue::Entry(b)) => a == b,
        (RecordValue::Deleted(a), RecordValue::Deleted(b)) => a == b,
        _ => false,
    }
}

fn contents_equal(left: &SyncContent, right: &SyncContent) -> bool {
    let left = content_records(left);
    let right = content_records(right);
    left.len() == right.len()
        && left.iter().all(|(id, value)| {
            right
                .get(id)
                .is_some_and(|other| record_equal(value, other))
        })
}

#[derive(Clone)]
struct VersionedRecord {
    op_id: String,
    value: RecordValue,
    parents: Vec<String>,
}

fn replay(space_id: &str, mut events: Vec<VerifiedEvent>) -> SyncResult<RemoteView> {
    if events.len() > MAX_EVENTS || !valid_uuid(space_id) {
        return Err(SyncError::TooLarge);
    }
    events.sort_by(|a, b| a.hash.cmp(&b.hash));
    let mut event_by_hash = HashMap::new();
    let mut device_streams: BTreeMap<String, Vec<&VerifiedEvent>> = BTreeMap::new();
    let mut genesis_count = 0usize;
    let mut latest_at = 0u64;
    let mut total_operations = 0usize;
    for event in &events {
        validate_event(&event.payload, space_id)?;
        total_operations = total_operations.saturating_add(event.payload.mutations.len());
        if total_operations > MAX_TOTAL_OPERATIONS {
            return Err(SyncError::TooLarge);
        }
        if event_by_hash.insert(event.hash.as_str(), event).is_some() {
            return Err(SyncError::InvalidRemoteObject);
        }
        genesis_count += usize::from(event.payload.genesis);
        latest_at = latest_at.max(event.payload.created_at);
        device_streams
            .entry(event.payload.device_id.clone())
            .or_default()
            .push(event);
    }
    if (!events.is_empty() && genesis_count != 1) || device_streams.len() > MAX_DEVICES {
        return Err(SyncError::InvalidRemoteObject);
    }
    let mut seen = BTreeMap::new();
    for (device_id, stream) in &mut device_streams {
        stream.sort_by_key(|event| event.payload.counter);
        let mut previous: Option<&str> = None;
        for (index, event) in stream.iter().enumerate() {
            if event.payload.counter != index as u64 + 1
                || event.payload.prev_event_hash.as_deref() != previous
                || event
                    .payload
                    .observed_heads
                    .get(device_id)
                    .map(String::as_str)
                    != previous
            {
                return Err(SyncError::RollbackOrFork);
            }
            previous = Some(&event.hash);
        }
        if let Some(last) = stream.last() {
            seen.insert(
                device_id.clone(),
                DeviceCheckpoint {
                    counter: last.payload.counter,
                    hash: last.hash.clone(),
                },
            );
        }
    }
    // Every observed remote object must be present. A missing dependency is
    // evidence of a partial listing, deletion, or a server-hidden branch.
    for event in &events {
        if event.payload.genesis {
            if event.payload.counter != 1
                || event.payload.prev_event_hash.is_some()
                || !event.payload.observed_heads.is_empty()
            {
                return Err(SyncError::InvalidRemoteObject);
            }
        } else if event.payload.observed_heads.is_empty() {
            return Err(SyncError::InvalidRemoteObject);
        }
        for (device_id, hash) in &event.payload.observed_heads {
            let dep = event_by_hash
                .get(hash.as_str())
                .ok_or(SyncError::RollbackOrFork)?;
            if dep.payload.device_id != *device_id || dep.hash == event.hash {
                return Err(SyncError::InvalidRemoteObject);
            }
        }
    }
    let causal_events = validate_event_dag(&events, &event_by_hash)?;

    let mut ops: BTreeMap<String, Vec<VersionedRecord>> = BTreeMap::new();
    let mut op_index: HashMap<String, (String, RecordValue)> = HashMap::new();
    for event in &events {
        for (index, mutation) in event.payload.mutations.iter().enumerate() {
            let op_id = format!("{}:{index}", event.hash);
            let id = mutation.value.id().to_owned();
            if op_index
                .insert(op_id.clone(), (id.clone(), mutation.value.clone()))
                .is_some()
            {
                return Err(SyncError::InvalidRemoteObject);
            }
            ops.entry(id).or_default().push(VersionedRecord {
                op_id,
                value: mutation.value.clone(),
                parents: mutation.parents.clone(),
            });
        }
    }

    for event in &events {
        for mutation in &event.payload.mutations {
            for parent in &mutation.parents {
                let source = parent.strip_prefix("i:").unwrap_or(parent);
                let source_hash = source
                    .split_once(':')
                    .map(|(hash, _)| hash)
                    .ok_or(SyncError::InvalidRemoteObject)?;
                let source_event = event_by_hash
                    .get(source_hash)
                    .ok_or(SyncError::RollbackOrFork)?;
                let observed_hash = event
                    .payload
                    .observed_heads
                    .get(&source_event.payload.device_id)
                    .ok_or(SyncError::RollbackOrFork)?;
                let observed_event = event_by_hash
                    .get(observed_hash.as_str())
                    .ok_or(SyncError::RollbackOrFork)?;
                if observed_event.payload.counter < source_event.payload.counter {
                    return Err(SyncError::RollbackOrFork);
                }
            }
        }
    }

    // Explicit edits to a previously generated conflict copy retain its
    // implicit origin even when newer original versions supersede the old one.
    for versions in ops.values() {
        for version in versions {
            for parent in &version.parents {
                if let Some(source_id) = parent.strip_prefix("i:") {
                    let (origin_id, origin_value) =
                        op_index.get(source_id).ok_or(SyncError::RollbackOrFork)?;
                    let expected_copy_id = conflict_copy_id(space_id, source_id);
                    if version.value.id() != expected_copy_id || origin_id == &expected_copy_id {
                        return Err(SyncError::InvalidRemoteObject);
                    }
                    if !matches!(origin_value, RecordValue::Entry(_)) {
                        return Err(SyncError::InvalidRemoteObject);
                    }
                } else {
                    let (parent_id, _) = op_index.get(parent).ok_or(SyncError::RollbackOrFork)?;
                    if parent_id != version.value.id() {
                        return Err(SyncError::InvalidRemoteObject);
                    }
                }
            }
        }
    }
    let mut implicit = BTreeSet::new();
    for versions in ops.values() {
        for version in versions {
            for parent in &version.parents {
                if let Some(source) = parent.strip_prefix("i:") {
                    implicit.insert(source.to_owned());
                }
            }
        }
    }
    // Keep every conflict copy that a causal prefix of this history could
    // display. A later edit to the original may supersede both competing
    // heads; it must not silently remove an untouched review copy.
    let mut historical_heads: BTreeMap<String, Vec<VersionedRecord>> = BTreeMap::new();
    for event in causal_events {
        for (index, mutation) in event.payload.mutations.iter().enumerate() {
            let heads = historical_heads
                .entry(mutation.value.id().to_owned())
                .or_default();
            heads.retain(|head| !mutation.parents.contains(&head.op_id));
            heads.push(VersionedRecord {
                op_id: format!("{}:{index}", event.hash),
                value: mutation.value.clone(),
                parents: mutation.parents.clone(),
            });
            if heads.len() > MAX_DEVICES * 2 {
                return Err(SyncError::TooLarge);
            }
            let maximal: Vec<_> = heads.iter().collect();
            let winner = pick_winner(&maximal)?;
            for loser in maximal {
                if loser.op_id != winner.op_id
                    && matches!(loser.value, RecordValue::Entry(_))
                    && !record_equal(&loser.value, &winner.value)
                {
                    implicit.insert(loser.op_id.clone());
                }
            }
            if implicit.len() > MAX_VAULT_ENTRIES {
                return Err(SyncError::TooLarge);
            }
        }
    }
    add_implicit_versions(space_id, &implicit, &op_index, &mut ops)?;

    loop {
        let mut additional = Vec::new();
        for versions in ops.values() {
            let maximal = maximal_versions(versions)?;
            let winner = pick_winner(&maximal)?;
            for loser in maximal {
                if loser.op_id != winner.op_id
                    && matches!(loser.value, RecordValue::Entry(_))
                    && !record_equal(&loser.value, &winner.value)
                    && !loser.op_id.starts_with("i:")
                    && !implicit.contains(&loser.op_id)
                {
                    additional.push(loser.op_id.clone());
                }
            }
        }
        if additional.is_empty() {
            break;
        }
        for source in additional {
            implicit.insert(source.clone());
        }
        if implicit.len() > MAX_VAULT_ENTRIES {
            return Err(SyncError::TooLarge);
        }
        add_implicit_versions(space_id, &implicit, &op_index, &mut ops)?;
    }
    // Explicitly referenced implicit parents may not be current conflict
    // losers. Add them after the closure above as well.
    add_implicit_versions(space_id, &implicit, &op_index, &mut ops)?;

    let mut entries = Vec::new();
    let mut tombstones = Vec::new();
    let mut record_heads = BTreeMap::new();
    for (id, versions) in &ops {
        let maximal = maximal_versions(versions)?;
        let winner = pick_winner(&maximal)?;
        let mut heads: Vec<_> = maximal
            .iter()
            .map(|version| version.op_id.clone())
            .collect();
        heads.sort();
        record_heads.insert(id.clone(), heads);
        match &winner.value {
            RecordValue::Entry(entry) => entries.push(entry.clone()),
            RecordValue::Deleted(tombstone) => tombstones.push(tombstone.clone()),
        }
    }
    entries.sort_by(|a, b| a.id.cmp(&b.id));
    tombstones.sort_by(|a, b| a.id.cmp(&b.id));
    let content = SyncContent {
        entries,
        tombstones,
    };
    validate_content(&content)?;
    Ok(RemoteView {
        content,
        seen,
        record_heads,
        event_count: events.len(),
        latest_at,
        total_bytes: 0,
        events,
    })
}

fn add_implicit_versions(
    space_id: &str,
    sources: &BTreeSet<String>,
    op_index: &HashMap<String, (String, RecordValue)>,
    ops: &mut BTreeMap<String, Vec<VersionedRecord>>,
) -> SyncResult<()> {
    for source in sources {
        let (_, value) = op_index.get(source).ok_or(SyncError::RollbackOrFork)?;
        let RecordValue::Entry(entry) = value else {
            return Err(SyncError::InvalidRemoteObject);
        };
        let copy_id = conflict_copy_id(space_id, source);
        let implicit_id = format!("i:{source}");
        let versions = ops.entry(copy_id.clone()).or_default();
        if versions.iter().any(|version| version.op_id == implicit_id) {
            continue;
        }
        let mut copy = entry.clone();
        copy.id = copy_id;
        let suffix = "（同步冲突）";
        let keep = 200usize.saturating_sub(suffix.chars().count());
        copy.title = format!(
            "{}{}",
            copy.title.chars().take(keep).collect::<String>(),
            suffix
        );
        if copy.tags.len() < 20 && !copy.tags.iter().any(|tag| tag == sync::CONFLICT_TAG) {
            copy.tags.push(sync::CONFLICT_TAG.to_owned());
        }
        versions.push(VersionedRecord {
            op_id: implicit_id,
            value: RecordValue::Entry(copy),
            parents: Vec::new(),
        });
    }
    Ok(())
}

fn maximal_versions(versions: &[VersionedRecord]) -> SyncResult<Vec<&VersionedRecord>> {
    let present: HashSet<&str> = versions
        .iter()
        .map(|version| version.op_id.as_str())
        .collect();
    let mut superseded = HashSet::new();
    for version in versions {
        for parent in &version.parents {
            if !present.contains(parent.as_str()) {
                return Err(SyncError::RollbackOrFork);
            }
            superseded.insert(parent.as_str());
        }
    }
    let maximal: Vec<_> = versions
        .iter()
        .filter(|version| !superseded.contains(version.op_id.as_str()))
        .collect();
    if maximal.is_empty() {
        return Err(SyncError::InvalidRemoteObject);
    }
    Ok(maximal)
}

fn pick_winner<'a>(versions: &[&'a VersionedRecord]) -> SyncResult<&'a VersionedRecord> {
    versions
        .iter()
        .copied()
        .max_by(|a, b| {
            a.value
                .is_deleted()
                .cmp(&b.value.is_deleted())
                .then_with(|| a.op_id.cmp(&b.op_id))
        })
        .ok_or(SyncError::InvalidRemoteObject)
}

fn conflict_copy_id(space_id: &str, op_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"CipherNest CN2 conflict copy\0");
    hasher.update(space_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(op_id.as_bytes());
    let hash = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hash[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes).to_string()
}

fn validate_event(event: &EventPayload, space_id: &str) -> SyncResult<()> {
    if event.protocol_version != VERSION
        || event.space_id != space_id
        || !valid_uuid(&event.device_id)
        || event.counter == 0
        || event.created_at == 0
        || event.observed_heads.len() > MAX_DEVICES
        || event.mutations.len() > MAX_EVENT_OPERATIONS
        || (!event.genesis && event.mutations.is_empty())
    {
        return Err(SyncError::InvalidRemoteObject);
    }
    let mut ids = HashSet::new();
    for mutation in &event.mutations {
        if !valid_uuid(mutation.value.id())
            || !ids.insert(mutation.value.id())
            || mutation.parents.len() > MAX_DEVICES * 2
        {
            return Err(SyncError::InvalidRemoteObject);
        }
        let one = match &mutation.value {
            RecordValue::Entry(entry) => SyncContent {
                entries: vec![entry.clone()],
                tombstones: vec![],
            },
            RecordValue::Deleted(tombstone) => SyncContent {
                entries: vec![],
                tombstones: vec![tombstone.clone()],
            },
        };
        validate_content(&one).map_err(|_| SyncError::InvalidRemoteObject)?;
        let mut parents = HashSet::new();
        if mutation
            .parents
            .iter()
            .any(|parent| !parents.insert(parent))
        {
            return Err(SyncError::InvalidRemoteObject);
        }
    }
    for (device_id, hash) in &event.observed_heads {
        if !valid_uuid(device_id) || !valid_hash(hash) {
            return Err(SyncError::InvalidRemoteObject);
        }
    }
    Ok(())
}

fn validate_event_dag<'a>(
    events: &'a [VerifiedEvent],
    by_hash: &HashMap<&str, &'a VerifiedEvent>,
) -> SyncResult<Vec<&'a VerifiedEvent>> {
    // Kahn's algorithm bounds cycle checking to O(events + dependencies).
    let mut indegree: HashMap<&str, usize> = HashMap::with_capacity(events.len());
    let mut children: HashMap<&str, Vec<&str>> = HashMap::new();
    for event in events {
        indegree.insert(event.hash.as_str(), event.payload.observed_heads.len());
        for parent in event.payload.observed_heads.values() {
            let parent_hash = by_hash
                .get(parent.as_str())
                .ok_or(SyncError::RollbackOrFork)?
                .hash
                .as_str();
            children
                .entry(parent_hash)
                .or_default()
                .push(event.hash.as_str());
        }
    }
    let mut ready: BTreeSet<&str> = indegree
        .iter()
        .filter_map(|(hash, degree)| (*degree == 0).then_some(*hash))
        .collect();
    let mut ordered = Vec::with_capacity(events.len());
    while let Some(hash) = ready.pop_first() {
        ordered.push(*by_hash.get(hash).ok_or(SyncError::InvalidRemoteObject)?);
        if let Some(next) = children.get(hash) {
            for child in next {
                let degree = indegree
                    .get_mut(child)
                    .ok_or(SyncError::InvalidRemoteObject)?;
                *degree = degree
                    .checked_sub(1)
                    .ok_or(SyncError::InvalidRemoteObject)?;
                if *degree == 0 {
                    ready.insert(child);
                }
            }
        }
    }
    if ordered.len() == events.len() {
        Ok(ordered)
    } else {
        Err(SyncError::RollbackOrFork)
    }
}

fn valid_uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|parsed| parsed.to_string() == value)
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_operation_ref(value: &str) -> bool {
    let value = value.strip_prefix("i:").unwrap_or(value);
    let Some((hash, index)) = value.split_once(':') else {
        return false;
    };
    valid_hash(hash)
        && !index.is_empty()
        && index.bytes().all(|byte| byte.is_ascii_digit())
        && index
            .parse::<usize>()
            .is_ok_and(|value| value < MAX_EVENT_OPERATIONS)
}

fn event_name(space_id: &str, hash: &str) -> SyncResult<String> {
    if !valid_uuid(space_id) || !valid_hash(hash) {
        return Err(SyncError::InvalidData);
    }
    Ok(format!("ciphernest-{space_id}-event-{hash}.cnevt"))
}

fn event_hash_from_name(name: &str) -> Option<&str> {
    let hash = name.strip_suffix(".cnevt")?.rsplit_once("-event-")?.1;
    valid_hash(hash).then_some(hash)
}

fn valid_event_name(name: &str, space_id: &str) -> bool {
    event_hash_from_name(name).is_some_and(|hash| {
        event_name(space_id, hash)
            .as_ref()
            .is_ok_and(|expected| expected == name)
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn validate_content(content: &SyncContent) -> SyncResult<()> {
    if content.entries.len() > MAX_VAULT_ENTRIES || content.tombstones.len() > MAX_VAULT_TOMBSTONES
    {
        return Err(SyncError::TooLarge);
    }
    let mut ids = HashSet::new();
    for entry in &content.entries {
        if !valid_uuid(&entry.id)
            || !ids.insert(entry.id.as_str())
            || !(1..=200).contains(&entry.title.chars().count())
            || entry.username.chars().count() > 500
            || !(1..=4096).contains(&entry.password.len())
            || entry.url.chars().count() > 2048
            || entry.purpose.chars().count() > 500
            || entry.notes.chars().count() > 20_000
            || entry.tags.len() > 20
            || entry.tags.iter().any(|tag| tag.chars().count() > 50)
            || entry.created_at == 0
            || entry.updated_at == 0
            || entry.password_updated_at == 0
            || entry.revision == 0
        {
            return Err(SyncError::InvalidData);
        }
    }
    for tombstone in &content.tombstones {
        if !valid_uuid(&tombstone.id)
            || !ids.insert(tombstone.id.as_str())
            || tombstone.revision == 0
            || tombstone.deleted_at == 0
        {
            return Err(SyncError::InvalidData);
        }
    }
    Ok(())
}

fn derive_key(root: &[u8; 32], id: &str, purpose: &[u8]) -> SyncResult<Zeroizing<[u8; 32]>> {
    if !valid_uuid(id) || root == &[0; 32] {
        return Err(SyncError::InvalidData);
    }
    let hkdf = Hkdf::<Sha256>::new(Some(id.as_bytes()), root);
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf.expand(purpose, key.as_mut())
        .map_err(|_| SyncError::InvalidData)?;
    Ok(key)
}

fn encrypt_block(plaintext: &[u8], key: &[u8; 32], aad: &[u8]) -> SyncResult<(String, String)> {
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce).map_err(|_| SyncError::InvalidData)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| SyncError::InvalidData)?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| SyncError::InvalidData)?;
    Ok((
        URL_SAFE_NO_PAD.encode(nonce),
        URL_SAFE_NO_PAD.encode(ciphertext),
    ))
}

fn decrypt_block(
    encoded_nonce: &str,
    encoded_ciphertext: &str,
    key: &[u8; 32],
    aad: &[u8],
    max_plaintext: usize,
) -> SyncResult<Zeroizing<Vec<u8>>> {
    let nonce: [u8; 24] = URL_SAFE_NO_PAD
        .decode(encoded_nonce)
        .map_err(|_| SyncError::InvalidRemoteObject)?
        .try_into()
        .map_err(|_| SyncError::InvalidRemoteObject)?;
    let ciphertext = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(encoded_ciphertext)
            .map_err(|_| SyncError::InvalidRemoteObject)?,
    );
    if ciphertext.len() < 16 || ciphertext.len() > max_plaintext.saturating_add(16) {
        return Err(SyncError::TooLarge);
    }
    let cipher =
        XChaCha20Poly1305::new_from_slice(key).map_err(|_| SyncError::InvalidRemoteObject)?;
    cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| SyncError::InvalidRemoteObject)
}

fn event_aad(space_id: &str) -> Vec<u8> {
    let mut aad = b"CipherNest\0SYNC_EVENT\0v2\0".to_vec();
    aad.extend_from_slice(space_id.as_bytes());
    aad
}

fn local_aad(vault_id: &str) -> Vec<u8> {
    let mut aad = b"CipherNest\0LOCAL_SYNC_STATE\0v2\0".to_vec();
    aad.extend_from_slice(vault_id.as_bytes());
    aad
}

fn encrypt_event(event: &EventPayload, material: &RecoveryMaterial) -> SyncResult<Vec<u8>> {
    validate_event(event, &material.space_id)?;
    let plaintext = Zeroizing::new(serde_json::to_vec(event).map_err(|_| SyncError::InvalidData)?);
    if plaintext.len() > MAX_EVENT_BYTES {
        return Err(SyncError::TooLarge);
    }
    let key = derive_key(
        &material.key,
        &material.space_id,
        b"CipherNest sync-v2 event",
    )?;
    let (nonce, ciphertext) = encrypt_block(&plaintext, &key, &event_aad(&material.space_id))?;
    let envelope = EncryptedEvent {
        format: EVENT_FORMAT.to_owned(),
        version: VERSION,
        nonce,
        ciphertext,
    };
    let bytes = serde_json::to_vec(&envelope).map_err(|_| SyncError::InvalidData)?;
    if bytes.len() > MAX_EVENT_BYTES {
        return Err(SyncError::TooLarge);
    }
    Ok(bytes)
}

fn decrypt_event(bytes: &[u8], material: &RecoveryMaterial) -> SyncResult<EventPayload> {
    if bytes.is_empty() || bytes.len() > MAX_EVENT_BYTES {
        return Err(SyncError::TooLarge);
    }
    let envelope: EncryptedEvent =
        serde_json::from_slice(bytes).map_err(|_| SyncError::InvalidRemoteObject)?;
    if envelope.format != EVENT_FORMAT || envelope.version != VERSION {
        return Err(SyncError::InvalidRemoteObject);
    }
    let key = derive_key(
        &material.key,
        &material.space_id,
        b"CipherNest sync-v2 event",
    )?;
    let plaintext = decrypt_block(
        &envelope.nonce,
        &envelope.ciphertext,
        &key,
        &event_aad(&material.space_id),
        MAX_EVENT_BYTES,
    )?;
    let event: EventPayload =
        serde_json::from_slice(&plaintext).map_err(|_| SyncError::InvalidRemoteObject)?;
    validate_event(&event, &material.space_id).map_err(|_| SyncError::InvalidRemoteObject)?;
    Ok(event)
}

pub fn write_local_state(
    path: &Path,
    vault_id: &str,
    vault_root_key: &[u8; 32],
    state: &LocalState,
) -> SyncResult<()> {
    if !valid_uuid(vault_id) {
        return Err(SyncError::InvalidLocalState);
    }
    state.validate()?;
    let plaintext = Zeroizing::new(serde_json::to_vec(state).map_err(|_| SyncError::LocalStateIo)?);
    if plaintext.len() > MAX_STATE_BYTES {
        return Err(SyncError::TooLarge);
    }
    let key = derive_key(vault_root_key, vault_id, b"CipherNest local-sync-state-v2")?;
    let (nonce, ciphertext) = encrypt_block(&plaintext, &key, &local_aad(vault_id))?;
    let envelope = LocalEnvelope {
        format: STATE_FORMAT.to_owned(),
        version: VERSION,
        vault_id: vault_id.to_owned(),
        nonce,
        ciphertext,
    };
    let bytes = serde_json::to_vec(&envelope).map_err(|_| SyncError::LocalStateIo)?;
    if bytes.len() > MAX_STATE_BYTES {
        return Err(SyncError::TooLarge);
    }
    write_private_atomic(path, &bytes)
}

pub fn read_local_state(
    path: &Path,
    vault_id: &str,
    vault_root_key: &[u8; 32],
) -> SyncResult<LocalState> {
    if !valid_uuid(vault_id) {
        return Err(SyncError::InvalidLocalState);
    }
    let file = File::open(path).map_err(|_| SyncError::InvalidLocalState)?;
    let metadata = file.metadata().map_err(|_| SyncError::InvalidLocalState)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_STATE_BYTES as u64 {
        return Err(SyncError::InvalidLocalState);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_STATE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| SyncError::InvalidLocalState)?;
    if bytes.len() > MAX_STATE_BYTES {
        return Err(SyncError::InvalidLocalState);
    }
    let envelope: LocalEnvelope =
        serde_json::from_slice(&bytes).map_err(|_| SyncError::InvalidLocalState)?;
    if envelope.format != STATE_FORMAT
        || envelope.version != VERSION
        || envelope.vault_id != vault_id
    {
        return Err(SyncError::InvalidLocalState);
    }
    let key = derive_key(vault_root_key, vault_id, b"CipherNest local-sync-state-v2")
        .map_err(|_| SyncError::InvalidLocalState)?;
    let plaintext = decrypt_block(
        &envelope.nonce,
        &envelope.ciphertext,
        &key,
        &local_aad(vault_id),
        MAX_STATE_BYTES,
    )
    .map_err(|_| SyncError::InvalidLocalState)?;
    let state: LocalState =
        serde_json::from_slice(&plaintext).map_err(|_| SyncError::InvalidLocalState)?;
    state.validate().map_err(|_| SyncError::InvalidLocalState)?;
    Ok(state)
}

#[cfg(test)]
pub fn rewrap_local_state(
    path: &Path,
    vault_id: &str,
    old_root_key: &[u8; 32],
    new_root_key: &[u8; 32],
) -> SyncResult<()> {
    let state = read_local_state(path, vault_id, old_root_key)?;
    write_local_state(path, vault_id, new_root_key, &state)
}

pub fn remove_local_state(path: &Path) -> SyncResult<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(SyncError::LocalStateIo),
    }
}

fn write_private_atomic(path: &Path, bytes: &[u8]) -> SyncResult<()> {
    let parent = path.parent().ok_or(SyncError::LocalStateIo)?;
    fs::create_dir_all(parent).map_err(|_| SyncError::LocalStateIo)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
            .map_err(|_| SyncError::LocalStateIo)?;
    }
    AtomicFile::new(path, OverwriteBehavior::AllowOverwrite)
        .write(|file| -> io::Result<()> {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                file.set_permissions(fs::Permissions::from_mode(0o600))?;
            }
            file.write_all(bytes)?;
            file.sync_all()
        })
        .map_err(|_| SyncError::LocalStateIo)?;
    #[cfg(unix)]
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| SyncError::LocalStateIo)?;
    Ok(())
}

fn map_network_error(error: reqwest::Error) -> SyncError {
    if error.is_timeout() {
        SyncError::Timeout
    } else if error.is_connect() {
        SyncError::SecureConnection
    } else {
        SyncError::Transport
    }
}

async fn read_limited(mut response: reqwest::Response, limit: usize) -> SyncResult<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(SyncError::TooLarge);
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(map_network_error)? {
        if bytes.len().saturating_add(chunk.len()) > limit {
            return Err(SyncError::TooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn parse_listing(body: &[u8], endpoint: &Url, space_id: &str) -> SyncResult<Vec<String>> {
    #[derive(Clone, Copy)]
    enum Capture {
        Href,
        Length,
    }
    let mut reader = NsReader::from_reader(body);
    reader.config_mut().trim_text(true);
    let mut buffer = Vec::new();
    let mut in_response = false;
    let mut in_propstat = false;
    let mut capture = None;
    let mut href = String::new();
    let mut length = String::new();
    let mut names = BTreeSet::new();
    loop {
        let (namespace, event) = reader
            .read_resolved_event_into(&mut buffer)
            .map_err(|_| SyncError::InvalidRemoteObject)?;
        if matches!(namespace, ResolveResult::Unknown(_)) {
            return Err(SyncError::InvalidRemoteObject);
        }
        let is_dav =
            matches!(namespace, ResolveResult::Bound(ref value) if value.as_ref() == b"DAV:");
        match event {
            XmlEvent::Start(element) if is_dav => match element.local_name().as_ref() {
                b"response" => {
                    if in_response {
                        return Err(SyncError::InvalidRemoteObject);
                    }
                    in_response = true;
                    href.clear();
                }
                b"propstat" if in_response => {
                    if in_propstat {
                        return Err(SyncError::InvalidRemoteObject);
                    }
                    in_propstat = true;
                    length.clear();
                }
                b"href" if in_response && !in_propstat => capture = Some(Capture::Href),
                b"getcontentlength" if in_propstat => capture = Some(Capture::Length),
                _ => {}
            },
            XmlEvent::Text(text) => {
                if let Some(target) = capture {
                    let value = text
                        .xml10_content()
                        .map_err(|_| SyncError::InvalidRemoteObject)?;
                    let destination = match target {
                        Capture::Href => &mut href,
                        Capture::Length => &mut length,
                    };
                    if destination.len().saturating_add(value.len()) > MAX_XML_FIELD {
                        return Err(SyncError::TooLarge);
                    }
                    destination.push_str(&value);
                }
            }
            XmlEvent::End(element) if is_dav => match element.local_name().as_ref() {
                b"href" | b"getcontentlength" => capture = None,
                b"propstat" if in_propstat => {
                    in_propstat = false;
                    capture = None;
                }
                b"response" if in_response => {
                    // Some WebDAV servers return 404 for this optional
                    // property while the object itself remains readable.
                    // GET still has a strict body limit and must succeed.
                    if let Some(name) = listed_event_name(&href, endpoint, space_id) {
                        if length
                            .parse::<u64>()
                            .is_ok_and(|size| size > MAX_EVENT_BYTES as u64)
                        {
                            return Err(SyncError::TooLarge);
                        }
                        if !names.insert(name) {
                            return Err(SyncError::InvalidRemoteObject);
                        }
                        if names.len() > MAX_EVENTS {
                            return Err(SyncError::TooLarge);
                        }
                    }
                    in_response = false;
                    in_propstat = false;
                    capture = None;
                }
                _ => {}
            },
            XmlEvent::DocType(_) | XmlEvent::GeneralRef(_) => {
                return Err(SyncError::InvalidRemoteObject);
            }
            XmlEvent::Eof => {
                if in_response || in_propstat || capture.is_some() {
                    return Err(SyncError::InvalidRemoteObject);
                }
                break;
            }
            _ => {}
        }
        buffer.clear();
        if reader.buffer_position() as usize > MAX_LIST_BYTES {
            return Err(SyncError::TooLarge);
        }
    }
    Ok(names.into_iter().collect())
}

fn listed_event_name(href: &str, endpoint: &Url, space_id: &str) -> Option<String> {
    if href.is_empty() || href.trim() != href || href.chars().any(char::is_control) {
        return None;
    }
    let url = endpoint.join(href).ok()?;
    if url.scheme() != endpoint.scheme()
        || url.host_str() != endpoint.host_str()
        || url.port_or_known_default() != endpoint.port_or_known_default()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    let name = url.path().strip_prefix(endpoint.path())?;
    if name.contains('/') || name.contains('%') || !valid_event_name(name, space_id) {
        return None;
    }
    Some(name.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn content(entries: Vec<VaultEntry>, tombstones: Vec<Tombstone>) -> SyncContent {
        SyncContent {
            entries,
            tombstones,
        }
    }

    fn entry(id: &str, title: &str, revision: u64) -> VaultEntry {
        VaultEntry {
            id: id.to_owned(),
            title: title.to_owned(),
            username: "user".to_owned(),
            password: format!("password-{title}"),
            url: String::new(),
            purpose: String::new(),
            notes: String::new(),
            tags: vec![],
            favorite: false,
            created_at: 1,
            updated_at: revision,
            password_updated_at: revision,
            revision,
        }
    }

    fn client() -> WebDavV2Client {
        WebDavV2Client::new(
            "https://example.invalid/dav/",
            "webdav".to_owned(),
            "password".to_owned(),
        )
        .unwrap()
    }

    fn first_event(
        material: &RecoveryMaterial,
        first_content: &SyncContent,
    ) -> (LocalState, VerifiedEvent, RemoteView) {
        let device = Uuid::new_v4().to_string();
        let mut state =
            LocalState::prepare_initial(&client(), material, &device, first_content, 1, 1).unwrap();
        let event = verify_pending(state.pending.as_ref().unwrap(), material).unwrap();
        let view = replay(material.space_id(), vec![event.clone()]).unwrap();
        assert!(!state
            .stage_followup_after_verified_upload(first_content, 1, 2)
            .unwrap());
        state.accept_view(&view, 1, 2).unwrap();
        (state, event, view)
    }

    #[test]
    fn recovery_code_and_sidecar_round_trip_without_plaintext() {
        let material = RecoveryMaterial::generate().unwrap();
        let code = material.code();
        assert_eq!(
            RecoveryMaterial::parse(&code).unwrap().code().as_str(),
            code.as_str()
        );
        assert!(RecoveryMaterial::parse(&code.to_ascii_lowercase()).is_err());
        let id = Uuid::new_v4().to_string();
        let original = content(vec![entry(&id, "secret-title", 1)], vec![]);
        let state = LocalState::prepare_initial(
            &client(),
            &material,
            &Uuid::new_v4().to_string(),
            &original,
            1,
            1,
        )
        .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.cnvault.sync-v2");
        let vault_id = Uuid::new_v4().to_string();
        let vault_key = [17u8; 32];
        write_local_state(&path, &vault_id, &vault_key, &state).unwrap();
        let bytes = fs::read(&path).unwrap();
        assert!(!bytes
            .windows(b"secret-title".len())
            .any(|part| part == b"secret-title"));
        let restored = read_local_state(&path, &vault_id, &vault_key).unwrap();
        assert_eq!(
            restored.pending.as_ref().unwrap().bytes,
            state.pending.as_ref().unwrap().bytes
        );
        assert!(read_local_state(&path, &vault_id, &[0u8; 32]).is_err());
        rewrap_local_state(&path, &vault_id, &vault_key, &[19u8; 32]).unwrap();
        assert!(read_local_state(&path, &vault_id, &vault_key).is_err());
        assert!(read_local_state(&path, &vault_id, &[19u8; 32]).is_ok());
    }

    #[test]
    fn concurrent_changes_converge_and_keep_both_passwords() {
        let material = RecoveryMaterial::generate().unwrap();
        let id = Uuid::new_v4().to_string();
        let base = content(vec![entry(&id, "base", 1)], vec![]);
        let (mut a, genesis, view) = first_event(&material, &base);
        let (mut b, _) = LocalState::prepare_join(
            &client(),
            &material,
            &Uuid::new_v4().to_string(),
            &view,
            &base,
            1,
            3,
        )
        .unwrap();
        assert!(b.pending.is_none());
        let a_content = content(vec![entry(&id, "A", 2)], vec![]);
        let b_content = content(vec![entry(&id, "B", 2)], vec![]);
        assert!(a.prepare_local_changes(&a_content, 2, 4).unwrap());
        assert!(b.prepare_local_changes(&b_content, 2, 4).unwrap());
        let a_event = verify_pending(a.pending.as_ref().unwrap(), &material).unwrap();
        let b_event = verify_pending(b.pending.as_ref().unwrap(), &material).unwrap();
        let joined = replay(
            material.space_id(),
            vec![genesis.clone(), a_event.clone(), b_event.clone()],
        )
        .unwrap();
        let reversed = replay(material.space_id(), vec![b_event, genesis, a_event]).unwrap();
        assert_eq!(joined.content.entries.len(), 2);
        assert_eq!(
            joined
                .content
                .entries
                .iter()
                .map(|item| item.password.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["password-A", "password-B"])
        );
        assert_eq!(
            joined
                .content
                .entries
                .iter()
                .map(|item| item.id.as_str())
                .collect::<BTreeSet<_>>(),
            reversed
                .content
                .entries
                .iter()
                .map(|item| item.id.as_str())
                .collect::<BTreeSet<_>>()
        );
        assert_eq!(joined.fingerprint(), reversed.fingerprint());
    }

    #[test]
    fn joining_with_same_id_different_secret_preserves_both() {
        let material = RecoveryMaterial::generate().unwrap();
        let id = Uuid::new_v4().to_string();
        let remote_content = content(vec![entry(&id, "remote", 1)], vec![]);
        let (_, genesis, view) = first_event(&material, &remote_content);
        let local_content = content(vec![entry(&id, "local", 1)], vec![]);
        let (join_state, preview_merge) = LocalState::prepare_join(
            &client(),
            &material,
            &Uuid::new_v4().to_string(),
            &view,
            &local_content,
            1,
            3,
        )
        .unwrap();
        assert!(join_state.pending.is_some());
        assert_eq!(preview_merge.entries.len(), 2);
        let joining_event =
            verify_pending(join_state.pending.as_ref().unwrap(), &material).unwrap();
        let merged = replay(material.space_id(), vec![genesis, joining_event]).unwrap();
        assert_eq!(merged.content.entries.len(), 2);
        assert_eq!(
            merged
                .content
                .entries
                .iter()
                .map(|item| item.password.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["password-local", "password-remote"])
        );
    }

    #[test]
    fn failed_upload_followup_preserves_newer_offline_edit_and_remote_branch() {
        let material = RecoveryMaterial::generate().unwrap();
        let id = Uuid::new_v4().to_string();
        let base = content(vec![entry(&id, "base", 1)], vec![]);
        let (mut a, genesis, view) = first_event(&material, &base);
        let (mut b, _) = LocalState::prepare_join(
            &client(),
            &material,
            &Uuid::new_v4().to_string(),
            &view,
            &base,
            1,
            3,
        )
        .unwrap();

        let staged = content(vec![entry(&id, "A-old", 2)], vec![]);
        a.prepare_local_changes(&staged, 2, 4).unwrap();
        let first_pending = a.pending.as_ref().unwrap().clone();
        let first_hash = first_pending.event_hash().to_owned();
        let first_update = verify_pending(&first_pending, &material).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let sidecar = directory.path().join("vault.cnvault.sync-v2");
        let vault_id = Uuid::new_v4().to_string();
        let vault_key = [42u8; 32];
        write_local_state(&sidecar, &vault_id, &vault_key, &a).unwrap();
        a = read_local_state(&sidecar, &vault_id, &vault_key).unwrap();
        assert_eq!(a.pending.as_ref().unwrap().event_hash(), first_hash);
        // The local vault remained editable after a failed attempt. The exact
        // first event is later confirmed, then a causal follow-up is staged.
        let newer_local = content(vec![entry(&id, "A-new", 3)], vec![]);
        assert!(a
            .stage_followup_after_verified_upload(&newer_local, 3, 6)
            .unwrap());
        let followup = verify_pending(a.pending.as_ref().unwrap(), &material).unwrap();
        assert_eq!(
            followup.payload.prev_event_hash.as_deref(),
            Some(first_hash.as_str())
        );
        assert_eq!(
            followup.payload.mutations[0].parents,
            vec![format!("{first_hash}:0")]
        );

        // The other device edited the same entry without seeing either A
        // event. Its branch remains a conflict copy, and A-old is superseded.
        b.prepare_local_changes(&content(vec![entry(&id, "B", 2)], vec![]), 2, 5)
            .unwrap();
        let remote_branch = verify_pending(b.pending.as_ref().unwrap(), &material).unwrap();
        let merged = replay(
            material.space_id(),
            vec![genesis, first_update, remote_branch, followup],
        )
        .unwrap();
        assert_eq!(merged.content.entries.len(), 2);
        assert_eq!(
            merged
                .content
                .entries
                .iter()
                .map(|value| value.password.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["password-A-new", "password-B"])
        );
    }

    #[test]
    fn delete_edit_conflict_keeps_tombstone_and_copy() {
        let material = RecoveryMaterial::generate().unwrap();
        let id = Uuid::new_v4().to_string();
        let base = content(vec![entry(&id, "base", 1)], vec![]);
        let (mut a, genesis, view) = first_event(&material, &base);
        let (mut b, _) = LocalState::prepare_join(
            &client(),
            &material,
            &Uuid::new_v4().to_string(),
            &view,
            &base,
            1,
            3,
        )
        .unwrap();
        a.prepare_local_changes(
            &content(
                vec![],
                vec![Tombstone {
                    id: id.clone(),
                    revision: 2,
                    deleted_at: 4,
                }],
            ),
            2,
            4,
        )
        .unwrap();
        b.prepare_local_changes(&content(vec![entry(&id, "edited", 2)], vec![]), 2, 4)
            .unwrap();
        let a_event = verify_pending(a.pending.as_ref().unwrap(), &material).unwrap();
        let b_event = verify_pending(b.pending.as_ref().unwrap(), &material).unwrap();
        let merged = replay(material.space_id(), vec![genesis, a_event, b_event]).unwrap();
        assert_eq!(merged.content.tombstones.len(), 1);
        assert_eq!(merged.content.tombstones[0].id, id);
        assert_eq!(merged.content.entries.len(), 1);
        assert_eq!(merged.content.entries[0].password, "password-edited");
        assert_ne!(merged.content.entries[0].id, id);
    }

    #[test]
    fn deleting_a_conflict_copy_does_not_resurrect_it() {
        let material = RecoveryMaterial::generate().unwrap();
        let id = Uuid::new_v4().to_string();
        let base = content(vec![entry(&id, "base", 1)], vec![]);
        let (mut a, genesis, view) = first_event(&material, &base);
        let (mut b, _) = LocalState::prepare_join(
            &client(),
            &material,
            &Uuid::new_v4().to_string(),
            &view,
            &base,
            1,
            3,
        )
        .unwrap();
        a.prepare_local_changes(&content(vec![entry(&id, "A", 2)], vec![]), 2, 4)
            .unwrap();
        b.prepare_local_changes(&content(vec![entry(&id, "B", 2)], vec![]), 2, 4)
            .unwrap();
        let a_event = verify_pending(a.pending.as_ref().unwrap(), &material).unwrap();
        let b_event = verify_pending(b.pending.as_ref().unwrap(), &material).unwrap();
        let merged = replay(
            material.space_id(),
            vec![genesis.clone(), a_event.clone(), b_event.clone()],
        )
        .unwrap();
        let copy = merged
            .content
            .entries
            .iter()
            .find(|value| value.id != id)
            .unwrap();
        let copy_id = copy.id.clone();
        let survivor = merged
            .content
            .entries
            .iter()
            .find(|value| value.id == id)
            .unwrap()
            .clone();
        let (mut c, _) = LocalState::prepare_join(
            &client(),
            &material,
            &Uuid::new_v4().to_string(),
            &merged,
            &merged.content,
            1,
            5,
        )
        .unwrap();
        c.prepare_local_changes(
            &content(
                vec![survivor],
                vec![Tombstone {
                    id: copy_id.clone(),
                    revision: copy.revision + 1,
                    deleted_at: 6,
                }],
            ),
            2,
            6,
        )
        .unwrap();
        let delete_event = verify_pending(c.pending.as_ref().unwrap(), &material).unwrap();
        assert!(delete_event.payload.mutations[0].parents[0].starts_with("i:"));
        let after = replay(
            material.space_id(),
            vec![genesis, a_event, b_event, delete_event],
        )
        .unwrap();
        assert_eq!(after.content.entries.len(), 1);
        assert_eq!(after.content.tombstones.len(), 1);
        assert_eq!(after.content.tombstones[0].id, copy_id);
    }

    #[test]
    fn editing_after_conflict_resolution_supersedes_every_original_branch() {
        let material = RecoveryMaterial::generate().unwrap();
        let id = Uuid::new_v4().to_string();
        let first_device = Uuid::new_v4().to_string();
        let second_device = Uuid::new_v4().to_string();
        let third_device = Uuid::new_v4().to_string();
        let genesis_hash = "1".repeat(64);
        let a_hash = "a".repeat(64);
        let b_hash = "b".repeat(64);
        let genesis = VerifiedEvent {
            hash: genesis_hash.clone(),
            payload: EventPayload {
                protocol_version: VERSION,
                space_id: material.space_id().to_owned(),
                genesis: true,
                device_id: first_device.clone(),
                counter: 1,
                prev_event_hash: None,
                observed_heads: BTreeMap::new(),
                created_at: 1,
                mutations: vec![Mutation {
                    parents: vec![],
                    value: RecordValue::Entry(entry(&id, "base", 1)),
                }],
            },
        };
        let a = VerifiedEvent {
            hash: a_hash.clone(),
            payload: EventPayload {
                protocol_version: VERSION,
                space_id: material.space_id().to_owned(),
                genesis: false,
                device_id: first_device.clone(),
                counter: 2,
                prev_event_hash: Some(genesis_hash.clone()),
                observed_heads: BTreeMap::from([(first_device.clone(), genesis_hash.clone())]),
                created_at: 2,
                mutations: vec![Mutation {
                    parents: vec![format!("{genesis_hash}:0")],
                    value: RecordValue::Entry(entry(&id, "A", 2)),
                }],
            },
        };
        let b = VerifiedEvent {
            hash: b_hash.clone(),
            payload: EventPayload {
                protocol_version: VERSION,
                space_id: material.space_id().to_owned(),
                genesis: false,
                device_id: second_device.clone(),
                counter: 1,
                prev_event_hash: None,
                observed_heads: BTreeMap::from([(first_device.clone(), genesis_hash)]),
                created_at: 2,
                mutations: vec![Mutation {
                    parents: vec![format!("{}:0", genesis.hash)],
                    value: RecordValue::Entry(entry(&id, "B", 2)),
                }],
            },
        };
        let conflict_id = conflict_copy_id(material.space_id(), &format!("{a_hash}:0"));
        let deleted_copy = VerifiedEvent {
            hash: "d".repeat(64),
            payload: EventPayload {
                protocol_version: VERSION,
                space_id: material.space_id().to_owned(),
                genesis: false,
                device_id: third_device.clone(),
                counter: 1,
                prev_event_hash: None,
                observed_heads: BTreeMap::from([
                    (first_device, a_hash.clone()),
                    (second_device, b_hash.clone()),
                ]),
                created_at: 3,
                mutations: vec![Mutation {
                    parents: vec![format!("i:{a_hash}:0")],
                    value: RecordValue::Deleted(Tombstone {
                        id: conflict_id.clone(),
                        revision: 3,
                        deleted_at: 3,
                    }),
                }],
            },
        };
        let events = vec![genesis, a, b, deleted_copy];
        let before = replay(material.space_id(), events.clone()).unwrap();
        assert_eq!(
            before.record_heads.get(&id).unwrap(),
            &vec![format!("{a_hash}:0"), format!("{b_hash}:0")]
        );
        let (mut joined, _) = LocalState::prepare_join(
            &client(),
            &material,
            &Uuid::new_v4().to_string(),
            &before,
            &before.content,
            1,
            4,
        )
        .unwrap();
        let resolved = content(
            vec![entry(&id, "resolved", 3)],
            before.content.tombstones.clone(),
        );
        assert!(joined.prepare_local_changes(&resolved, 2, 5).unwrap());
        let mut final_edit = verify_pending(joined.pending.as_ref().unwrap(), &material).unwrap();
        assert_eq!(
            final_edit.payload.mutations[0].parents,
            vec![format!("{a_hash}:0"), format!("{b_hash}:0")]
        );
        // A lower hash would let the stale A branch win if only B were a parent.
        final_edit.hash = "0".repeat(64);
        let after = replay(
            material.space_id(),
            events.into_iter().chain([final_edit]).collect(),
        )
        .unwrap();
        assert_eq!(after.content.entries.len(), 1);
        assert_eq!(after.content.entries[0].id, id);
        assert_eq!(after.content.entries[0].password, "password-resolved");
        assert_eq!(after.content.tombstones.len(), 1);
        assert_eq!(after.content.tombstones[0].id, conflict_id);
    }

    #[test]
    fn editing_original_does_not_remove_an_untouched_conflict_copy() {
        let material = RecoveryMaterial::generate().unwrap();
        let id = Uuid::new_v4().to_string();
        let base = content(vec![entry(&id, "base", 1)], vec![]);
        let (mut a, genesis, view) = first_event(&material, &base);
        let (mut b, _) = LocalState::prepare_join(
            &client(),
            &material,
            &Uuid::new_v4().to_string(),
            &view,
            &base,
            1,
            3,
        )
        .unwrap();
        a.prepare_local_changes(&content(vec![entry(&id, "A", 2)], vec![]), 2, 4)
            .unwrap();
        b.prepare_local_changes(&content(vec![entry(&id, "B", 2)], vec![]), 2, 4)
            .unwrap();
        let a_event = verify_pending(a.pending.as_ref().unwrap(), &material).unwrap();
        let b_event = verify_pending(b.pending.as_ref().unwrap(), &material).unwrap();
        let merged = replay(
            material.space_id(),
            vec![genesis.clone(), a_event.clone(), b_event.clone()],
        )
        .unwrap();
        let copy = merged
            .content
            .entries
            .iter()
            .find(|entry| entry.id != id)
            .unwrap()
            .clone();
        let (mut editor, _) = LocalState::prepare_join(
            &client(),
            &material,
            &Uuid::new_v4().to_string(),
            &merged,
            &merged.content,
            1,
            5,
        )
        .unwrap();
        let changed = content(vec![entry(&id, "resolved", 3), copy.clone()], vec![]);
        editor.prepare_local_changes(&changed, 2, 6).unwrap();
        let edit = verify_pending(editor.pending.as_ref().unwrap(), &material).unwrap();
        let after = replay(material.space_id(), vec![genesis, a_event, b_event, edit]).unwrap();
        assert_eq!(after.content.entries.len(), 2);
        assert!(after
            .content
            .entries
            .iter()
            .any(|entry| entry.id == id && entry.password == "password-resolved"));
        assert!(after
            .content
            .entries
            .iter()
            .any(|entry| entry.id == copy.id && entry.password == copy.password));
    }

    #[test]
    fn missing_known_event_or_dependency_fails_closed() {
        let material = RecoveryMaterial::generate().unwrap();
        let first = content(vec![], vec![]);
        let (mut state, genesis, _) = first_event(&material, &first);
        let id = Uuid::new_v4().to_string();
        state
            .prepare_local_changes(&content(vec![entry(&id, "new", 1)], vec![]), 2, 3)
            .unwrap();
        let update = verify_pending(state.pending.as_ref().unwrap(), &material).unwrap();
        assert!(matches!(
            replay(material.space_id(), vec![update.clone()]),
            Err(SyncError::InvalidRemoteObject | SyncError::RollbackOrFork)
        ));
        let mut bad = update;
        bad.payload
            .observed_heads
            .insert(Uuid::new_v4().to_string(), "a".repeat(64));
        assert!(matches!(
            replay(material.space_id(), vec![genesis, bad]),
            Err(SyncError::RollbackOrFork)
        ));
    }

    #[test]
    fn unknown_same_device_publication_is_not_silently_adopted() {
        let material = RecoveryMaterial::generate().unwrap();
        let (state, genesis, _) = first_event(&material, &content(vec![], vec![]));
        let mut cloned_writer = state.clone();
        let id = Uuid::new_v4().to_string();
        cloned_writer
            .prepare_local_changes(&content(vec![entry(&id, "clone", 1)], vec![]), 2, 3)
            .unwrap();
        let published = verify_pending(cloned_writer.pending.as_ref().unwrap(), &material).unwrap();
        let view = replay(material.space_id(), vec![genesis, published]).unwrap();
        assert!(matches!(
            validate_remote_checkpoint(&state, &view),
            Err(SyncError::RollbackOrFork)
        ));
        assert!(validate_remote_checkpoint(&cloned_writer, &view).is_ok());
    }

    #[test]
    fn listing_accepts_only_exact_space_and_collection_children() {
        let material = RecoveryMaterial::generate().unwrap();
        let hash = "a".repeat(64);
        let name = event_name(material.space_id(), &hash).unwrap();
        let body = format!(
            "<d:multistatus xmlns:d=\"DAV:\"><d:response><d:href>/dav/{name}</d:href><d:propstat><d:prop><d:getcontentlength>200</d:getcontentlength></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response><d:response><d:href>/elsewhere/{name}</d:href><d:propstat><d:prop/><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"
        );
        let names = parse_listing(
            body.as_bytes(),
            &Url::parse("https://example.invalid/dav/").unwrap(),
            material.space_id(),
        )
        .unwrap();
        assert_eq!(names, vec![name]);
    }

    #[test]
    fn listing_keeps_readable_child_when_optional_length_property_is_missing() {
        let material = RecoveryMaterial::generate().unwrap();
        let name = event_name(material.space_id(), &"a".repeat(64)).unwrap();
        let body = format!(
            "<d:multistatus xmlns:d=\"DAV:\"><d:response><d:href>/dav/{name}</d:href><d:propstat><d:prop/><d:status>HTTP/1.1 404 Not Found</d:status></d:propstat></d:response></d:multistatus>"
        );
        assert_eq!(
            parse_listing(
                body.as_bytes(),
                &Url::parse("https://example.invalid/dav/").unwrap(),
                material.space_id(),
            )
            .unwrap(),
            vec![name]
        );
    }

    #[test]
    fn publication_checks_event_and_byte_limits_before_put() {
        let material = RecoveryMaterial::generate().unwrap();
        let (mut state, _genesis, mut view) = first_event(&material, &content(vec![], vec![]));
        let id = Uuid::new_v4().to_string();
        state
            .prepare_local_changes(&content(vec![entry(&id, "added", 1)], vec![]), 2, 3)
            .unwrap();
        let pending = state.pending.as_ref().unwrap();
        view.event_count = MAX_EVENTS;
        assert!(matches!(
            view.ensure_publishable(pending, &material),
            Err(SyncError::TooLarge)
        ));
        view.event_count = 1;
        view.total_bytes = MAX_TOTAL_REMOTE_BYTES;
        assert!(matches!(
            view.ensure_publishable(pending, &material),
            Err(SyncError::TooLarge)
        ));
    }

    #[test]
    fn joining_rejects_a_sixty_fifth_writer() {
        let material = RecoveryMaterial::generate().unwrap();
        let (_, _, mut view) = first_event(&material, &content(vec![], vec![]));
        while view.seen.len() < MAX_DEVICES {
            view.seen.insert(
                Uuid::new_v4().to_string(),
                DeviceCheckpoint {
                    counter: 1,
                    hash: "a".repeat(64),
                },
            );
        }
        assert!(matches!(
            LocalState::prepare_join(
                &client(),
                &material,
                &Uuid::new_v4().to_string(),
                &view,
                &view.content,
                1,
                3,
            ),
            Err(SyncError::TooLarge)
        ));
    }

    #[test]
    fn verified_listing_fast_path_requires_exact_names_and_recent_full_check() {
        let material = RecoveryMaterial::generate().unwrap();
        let original = content(vec![], vec![]);
        let (state, genesis, view) = first_event(&material, &original);
        let names = vec![event_name(material.space_id(), &genesis.hash).unwrap()];
        assert_eq!(
            state.verified_listing_hash.as_deref(),
            Some(
                listing_fingerprint(&names, material.space_id())
                    .unwrap()
                    .as_str()
            )
        );
        assert_eq!(
            view.fingerprint(),
            listing_fingerprint(&names, material.space_id()).unwrap()
        );
        assert!(fast_poll_allowed(&state, &original, 1, 3));
        assert!(!fast_poll_allowed(&state, &original, 1, 1));
        assert!(!fast_poll_allowed(
            &state,
            &original,
            1,
            2 + MAX_FAST_POLL_AGE_MS
        ));

        let mut added = names.clone();
        added.push(event_name(material.space_id(), &"f".repeat(64)).unwrap());
        assert_ne!(
            state.verified_listing_hash.as_deref(),
            Some(
                listing_fingerprint(&added, material.space_id())
                    .unwrap()
                    .as_str()
            )
        );
        assert_ne!(
            state.verified_listing_hash.as_deref(),
            Some(
                listing_fingerprint(&[], material.space_id())
                    .unwrap()
                    .as_str()
            )
        );
        assert!(
            listing_fingerprint(&[added[1].clone(), added[0].clone()], material.space_id())
                .is_err()
        );
        assert!(
            listing_fingerprint(&[names[0].clone(), names[0].clone()], material.space_id())
                .is_err()
        );
    }

    #[test]
    fn fast_poll_falls_back_for_local_edits_pending_upload_and_old_sidecars() {
        let material = RecoveryMaterial::generate().unwrap();
        let original = content(vec![], vec![]);
        let (mut state, _, _) = first_event(&material, &original);
        let id = Uuid::new_v4().to_string();
        let changed = content(vec![entry(&id, "changed", 1)], vec![]);
        assert!(!fast_poll_allowed(&state, &changed, 2, 3));
        assert!(!fast_poll_allowed(&state, &original, 2, 3));
        assert!(state.prepare_local_changes(&changed, 2, 3).unwrap());
        assert!(state.pending.is_some());
        assert!(state.verified_listing_hash.is_none());
        assert!(!fast_poll_allowed(&state, &changed, 2, 4));

        let (state, _, _) = first_event(&material, &original);
        let mut old_json = serde_json::to_value(&state).unwrap();
        old_json
            .as_object_mut()
            .unwrap()
            .remove("verifiedListingHash");
        let old_state: LocalState = serde_json::from_value(old_json).unwrap();
        assert!(old_state.validate().is_ok());
        assert!(!fast_poll_allowed(&old_state, &original, 1, 3));
    }
}

#[cfg(test)]
#[path = "sync_v2_transport_tests.rs"]
mod transport_tests;
