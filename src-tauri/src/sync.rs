//! Conservative, personal WebDAV synchronization primitives.
//!
//! WebDAV is treated as an untrusted byte store.  The module deliberately
//! keeps the synchronization key, WebDAV credential, local vault key-wrap,
//! settings, and retired device-authentication records out of remote objects.

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    fs::{self, File},
    io::{self, Read, Write},
    path::Path,
    time::{Duration, Instant},
};

use atomicwrites::{AtomicFile, OverwriteBehavior};
use base64::{
    engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD},
    Engine as _,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use quick_xml::{events::Event, name::ResolveResult, NsReader};
use reqwest::{
    header::{
        HeaderValue, ACCEPT, ACCEPT_ENCODING, CACHE_CONTROL, CONTENT_TYPE, ETAG, IF_MATCH,
        IF_NONE_MATCH,
    },
    tls::Version as TlsVersion,
    Method, StatusCode, Url,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::models::{Tombstone, VaultEntry, MAX_VAULT_ENTRIES, MAX_VAULT_TOMBSTONES};

const REMOTE_SNAPSHOT_FORMAT: &str = "CipherNestSyncSnapshot";
const REMOTE_HEAD_FORMAT: &str = "CipherNestSyncHead";
const LOCAL_STATE_FORMAT: &str = "CipherNestLocalSyncState";
const SYNC_VERSION: u32 = 1;
const KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 24;
const TAG_BYTES: usize = 16;
const MAX_REMOTE_OBJECT_BYTES: usize = 32 * 1024 * 1024;
const MAX_HEAD_BYTES: usize = 64 * 1024;
const MAX_PROPFIND_BYTES: usize = 1024 * 1024;
const MAX_LOCAL_STATE_BYTES: usize = 40 * 1024 * 1024;
const MAX_CHAIN_DEPTH: usize = 256;
const MAX_CHAIN_WALL_TIME: Duration = Duration::from_secs(90);
const MAX_ENDPOINT_BYTES: usize = 2048;
const MAX_USERNAME_CHARS: usize = 512;
const MAX_PASSWORD_BYTES: usize = 4096;
const CONFLICT_TAG: &str = "同步冲突";
const CONFLICT_SUFFIX: &str = "（同步冲突）";
const PROPFIND_BODY: &[u8] = br#"<?xml version="1.0" encoding="utf-8" ?>
<d:propfind xmlns:d="DAV:"><d:prop><d:resourcetype/></d:prop></d:propfind>"#;

#[derive(Debug, Error)]
pub enum SyncError {
    #[error("WebDAV 地址无效或不符合安全要求。")]
    InvalidEndpoint,
    #[error("WebDAV 凭据无效。")]
    InvalidCredentials,
    #[error("同步恢复码无效。")]
    InvalidRecoveryCode,
    #[error("本地同步状态无效或已损坏。")]
    InvalidLocalState,
    #[error("本地保险库版本早于上次同步版本，已拒绝覆盖远端数据。")]
    LocalRollback,
    #[error("远端同步对象无效或认证失败。")]
    InvalidRemoteObject,
    #[error("远端对象的内容哈希不匹配。")]
    HashMismatch,
    #[error("远端尚未初始化此 CipherNest 同步空间。")]
    RemoteNotInitialized,
    #[error("远端已存在此 CipherNest 同步空间。")]
    RemoteAlreadyInitialized,
    #[error("远端已被另一台设备更新，请重新拉取并合并。")]
    ConcurrentUpdate,
    #[error("检测到远端回滚、分叉或缺失的父快照。")]
    RollbackOrFork,
    #[error("远端快照链超过安全检查上限。")]
    ChainTooLong,
    #[error("WebDAV 服务器不支持安全同步所需的条件请求或强 ETag。")]
    UnsafeServer,
    #[error("WebDAV 地址不是现有集合。")]
    NotACollection,
    #[error("WebDAV 服务器返回了不支持的状态码 {0}。")]
    UnexpectedStatus(u16),
    #[error("WebDAV 网络操作失败。")]
    Transport,
    #[error("WebDAV 网络请求超时。请检查网络及服务器端口。")]
    Timeout,
    #[error("无法建立 WebDAV HTTPS 连接。请检查服务器是否可达、端口是否启用 HTTPS，以及证书是否可信且与域名匹配。")]
    SecureConnection,
    #[error("同步对象超过大小限制。")]
    TooLarge,
    #[error("同步数据包含无效字段。")]
    InvalidData,
    #[error("本地同步状态无法安全保存。")]
    LocalStateIo,
}

pub type SyncResult<T> = Result<T, SyncError>;

#[derive(Clone)]
pub struct RecoveryMaterial {
    sync_id: String,
    key: Zeroizing<[u8; KEY_BYTES]>,
}

impl RecoveryMaterial {
    pub fn sync_id(&self) -> &str {
        &self.sync_id
    }
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SyncContent {
    pub entries: Vec<VaultEntry>,
    pub tombstones: Vec<Tombstone>,
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SyncSnapshot {
    protocol_version: u32,
    sync_id: String,
    sequence: u64,
    parent_hash: Option<String>,
    device_id: String,
    device_counter: u64,
    created_at: u64,
    entries: Vec<VaultEntry>,
    tombstones: Vec<Tombstone>,
}

impl SyncSnapshot {
    pub fn content(&self) -> SyncContent {
        SyncContent {
            entries: self.entries.clone(),
            tombstones: self.tombstones.clone(),
        }
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn created_at(&self) -> u64 {
        self.created_at
    }
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalSyncState {
    state_version: u32,
    endpoint: String,
    username: String,
    app_password: String,
    sync_id: String,
    sync_root_key: [u8; KEY_BYTES],
    device_id: String,
    device_counter: u64,
    checkpoint_hash: Option<String>,
    base_snapshot: Option<SyncSnapshot>,
    last_local_generation: u64,
    last_sync_at: Option<u64>,
}

impl LocalSyncState {
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn sync_id(&self) -> &str {
        &self.sync_id
    }

    pub fn base_snapshot(&self) -> Option<&SyncSnapshot> {
        self.base_snapshot.as_ref()
    }

    pub fn last_local_generation(&self) -> u64 {
        self.last_local_generation
    }

    pub fn last_sync_at(&self) -> Option<u64> {
        self.last_sync_at
    }

    /// Returns the high-value recovery secret in an auto-zeroizing buffer.
    /// Callers must still require a fresh master-password check and avoid logs,
    /// clipboard persistence, screenshots, and long-lived UI state.
    pub fn recovery_code(&self) -> SyncResult<Zeroizing<String>> {
        validate_local_state(self)?;
        format_recovery_parts(&self.sync_id, &self.sync_root_key)
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RemoteCursor {
    snapshot_hash: String,
    head_etag: String,
    snapshot: SyncSnapshot,
    /// The exact locally trusted checkpoint this cursor was proven to descend
    /// from.  Keeping the value (rather than only a bool) prevents accidentally
    /// using a cursor fetched for another local state.
    proven_checkpoint: Option<String>,
}

impl RemoteCursor {
    pub fn snapshot_hash(&self) -> &str {
        &self.snapshot_hash
    }

    pub fn snapshot(&self) -> &SyncSnapshot {
        &self.snapshot
    }

    pub fn checkpoint_proven(&self) -> bool {
        self.proven_checkpoint.is_some()
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MergeConflict {
    pub original_id: String,
    pub preserved_copy_id: String,
    pub kind: MergeConflictKind,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum MergeConflictKind {
    BothModified,
    DeleteVsModify,
    JoinCollision,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MergeResult {
    pub content: SyncContent,
    #[zeroize(skip)]
    pub conflicts: Vec<MergeConflict>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EncryptedObject {
    format: String,
    version: u32,
    nonce: String,
    ciphertext: String,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HeadPayload {
    protocol_version: u32,
    sync_id: String,
    sequence: u64,
    snapshot_hash: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LocalStateEnvelope {
    format: String,
    version: u32,
    vault_id: String,
    nonce: String,
    ciphertext: String,
}

struct RemoteResource {
    bytes: Vec<u8>,
    etag: Option<String>,
}

pub struct WebDavClient {
    client: reqwest::Client,
    endpoint: Url,
    username: String,
    app_password: Zeroizing<String>,
}

impl WebDavClient {
    pub fn new(endpoint: &str, username: String, app_password: String) -> SyncResult<Self> {
        let app_password = Zeroizing::new(app_password);
        let endpoint = validate_webdav_endpoint(endpoint)?;
        validate_credentials(&username, &app_password)?;
        let client = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .min_tls_version(TlsVersion::TLS_1_2)
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(45))
            .no_proxy()
            .user_agent("CipherNest-WebDAV/1")
            .build()
            .map_err(|_| SyncError::Transport)?;
        Ok(Self {
            client,
            endpoint,
            username,
            app_password,
        })
    }

    /// Rebuilds a client from an already authenticated local sidecar.  Command
    /// code should prefer this over manually copying credential fields.
    pub fn from_local_state(state: &LocalSyncState) -> SyncResult<Self> {
        validate_local_state(state)?;
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

    /// Confirms that the configured URL is an existing WebDAV collection.
    pub async fn ensure_existing_collection(&self) -> SyncResult<()> {
        let method = Method::from_bytes(b"PROPFIND").map_err(|_| SyncError::Transport)?;
        let response = self
            .request(method, self.endpoint.clone())
            .header("Depth", "0")
            .header(CONTENT_TYPE, "application/xml; charset=utf-8")
            .header(ACCEPT, "application/xml, text/xml")
            .body(PROPFIND_BODY)
            .send()
            .await
            .map_err(classify_transport_error)?;
        if response.status() != StatusCode::MULTI_STATUS {
            return Err(status_error(response.status()));
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
        let body = read_limited(response, MAX_PROPFIND_BYTES).await?;
        if !propfind_reports_collection(&body, &self.endpoint)? {
            return Err(SyncError::NotACollection);
        }
        Ok(())
    }

    /// Performs harmless create/update/delete probes in the exact configured
    /// collection.  A server that ignores either condition or emits only weak
    /// ETags is rejected.
    pub async fn verify_safe_conditions(&self) -> SyncResult<()> {
        self.ensure_existing_collection().await?;
        let probe_name = format!("ciphernest-condition-probe-{}.tmp", Uuid::new_v4());
        let first = random_probe_bytes()?;
        let second = random_probe_bytes()?;

        let create = self
            .put_resource(&probe_name, &first, Some((IF_NONE_MATCH, "*")))
            .await;
        let status = match create {
            Ok(status) if is_write_success(status) => status,
            Ok(status) => return Err(status_error(status)),
            Err(error) => return Err(error),
        };
        let _ = status;

        let result = async {
            let fetched = self
                .get_resource(&probe_name, MAX_HEAD_BYTES)
                .await?
                .ok_or(SyncError::UnsafeServer)?;
            if fetched.bytes != first {
                return Err(SyncError::UnsafeServer);
            }
            let first_etag = require_strong_etag(fetched.etag.as_deref())?;

            let duplicate = self
                .put_resource(&probe_name, &first, Some((IF_NONE_MATCH, "*")))
                .await?;
            if duplicate != StatusCode::PRECONDITION_FAILED {
                return Err(SyncError::UnsafeServer);
            }

            let wrong_match = self
                .put_resource(
                    &probe_name,
                    &second,
                    Some((IF_MATCH, "\"ciphernest-deliberately-invalid-etag\"")),
                )
                .await?;
            if wrong_match != StatusCode::PRECONDITION_FAILED {
                return Err(SyncError::UnsafeServer);
            }

            // A broken intermediary may report 412 while still forwarding a
            // write to the origin.  Do not trust the status alone: the exact
            // object and its compare-and-swap token must still be unchanged.
            let unchanged = self.get_resource(&probe_name, MAX_HEAD_BYTES).await?;
            verify_rejected_probe_writes(unchanged.as_ref(), &first, &first_etag)?;

            let update = self
                .put_resource(&probe_name, &second, Some((IF_MATCH, first_etag.as_str())))
                .await?;
            if !is_write_success(update) {
                return Err(status_error(update));
            }
            let fetched = self
                .get_resource(&probe_name, MAX_HEAD_BYTES)
                .await?
                .ok_or(SyncError::UnsafeServer)?;
            if fetched.bytes != second {
                return Err(SyncError::UnsafeServer);
            }
            let second_etag = require_strong_etag(fetched.etag.as_deref())?;
            if second_etag == first_etag {
                // A strong entity tag is unusable for compare-and-swap if it
                // remains stable after the representation changes.
                return Err(SyncError::UnsafeServer);
            }
            let deleted = self
                .delete_resource(&probe_name, Some(second_etag.as_str()))
                .await?;
            if !is_write_success(deleted) {
                return Err(status_error(deleted));
            }
            Ok(())
        }
        .await;

        if result.is_err() {
            let _ = self.delete_resource(&probe_name, None).await;
        }
        result
    }

    pub async fn create_remote(
        &self,
        material: &RecoveryMaterial,
        device_id: &str,
        content: &SyncContent,
        created_at: u64,
    ) -> SyncResult<RemoteCursor> {
        validate_recovery_material(material)?;
        validate_uuid(device_id)?;
        validate_content(content)?;
        if created_at == 0 {
            return Err(SyncError::InvalidData);
        }
        self.verify_safe_conditions().await?;
        let head_name = remote_head_name(&material.sync_id)?;
        if self
            .get_resource(&head_name, MAX_HEAD_BYTES)
            .await?
            .is_some()
        {
            return Err(SyncError::RemoteAlreadyInitialized);
        }

        let snapshot = SyncSnapshot {
            protocol_version: SYNC_VERSION,
            sync_id: material.sync_id.clone(),
            sequence: 1,
            parent_hash: None,
            device_id: device_id.to_owned(),
            device_counter: 1,
            created_at,
            entries: content.entries.clone(),
            tombstones: content.tombstones.clone(),
        };
        let (snapshot_bytes, snapshot_hash) = encode_snapshot(&snapshot, &material.key)?;
        self.put_immutable_snapshot(&material.sync_id, &snapshot_hash, &snapshot_bytes)
            .await?;

        let head = HeadPayload {
            protocol_version: SYNC_VERSION,
            sync_id: material.sync_id.clone(),
            sequence: snapshot.sequence,
            snapshot_hash: snapshot_hash.clone(),
        };
        let head_bytes = encode_head(&head, &material.key)?;
        let head_etag = self.put_head_create(&head_name, &head_bytes).await?;
        Ok(RemoteCursor {
            snapshot_hash,
            head_etag,
            snapshot,
            proven_checkpoint: None,
        })
    }

    /// Constructs the first device's authenticated local sidecar state after
    /// `create_remote` succeeds.  Keeping this constructor here prevents UI or
    /// command code from guessing protocol counters or checkpoint fields.
    pub fn state_for_created_remote(
        &self,
        material: &RecoveryMaterial,
        device_id: &str,
        last_local_generation: u64,
        now: u64,
        cursor: &RemoteCursor,
    ) -> SyncResult<LocalSyncState> {
        validate_recovery_material(material)?;
        validate_uuid(device_id)?;
        if last_local_generation == 0
            || now == 0
            || cursor.snapshot.sync_id != material.sync_id
            || cursor.snapshot.device_id != device_id
            || cursor.snapshot.sequence != 1
            || cursor.snapshot.parent_hash.is_some()
            || cursor.snapshot.device_counter != 1
        {
            return Err(SyncError::InvalidData);
        }
        self.local_state_from_cursor(
            material,
            device_id,
            cursor.snapshot.device_counter,
            last_local_generation,
            now,
            cursor,
        )
    }

    /// Fetches and authenticates the remote head and its snapshot.  When a
    /// checkpoint is supplied, the parent chain must reach it within 256
    /// links; otherwise the operation fails as rollback/fork.
    pub async fn inspect_remote(
        &self,
        material: &RecoveryMaterial,
        known_checkpoint: Option<&str>,
    ) -> SyncResult<RemoteCursor> {
        validate_recovery_material(material)?;
        if let Some(checkpoint) = known_checkpoint {
            validate_hash(checkpoint)?;
        }
        self.ensure_existing_collection().await?;
        let head_name = remote_head_name(&material.sync_id)?;
        let head_resource = self
            .get_resource(&head_name, MAX_HEAD_BYTES)
            .await?
            .ok_or(SyncError::RemoteNotInitialized)?;
        let head_etag = require_strong_etag(head_resource.etag.as_deref())?;
        let head = decode_head(&head_resource.bytes, &material.sync_id, &material.key)?;
        let first = self
            .fetch_snapshot(&material.sync_id, &head.snapshot_hash, &material.key)
            .await?;
        if first.snapshot.sequence != head.sequence {
            return Err(SyncError::InvalidRemoteObject);
        }

        let proven_checkpoint = if let Some(checkpoint) = known_checkpoint {
            self.prove_checkpoint(material, &first, checkpoint).await?;
            Some(checkpoint.to_owned())
        } else {
            None
        };

        Ok(RemoteCursor {
            snapshot_hash: first.hash,
            head_etag,
            snapshot: first.snapshot,
            proven_checkpoint,
        })
    }

    async fn commit_remote(
        &self,
        material: &RecoveryMaterial,
        cursor: &RemoteCursor,
        device_id: &str,
        device_counter: u64,
        content: &SyncContent,
        created_at: u64,
    ) -> SyncResult<RemoteCursor> {
        validate_recovery_material(material)?;
        validate_uuid(device_id)?;
        validate_content(content)?;
        validate_snapshot(&cursor.snapshot)?;
        validate_hash(&cursor.snapshot_hash)?;
        let head_etag = require_strong_etag(Some(&cursor.head_etag))?;
        if cursor.snapshot.sync_id != material.sync_id || created_at == 0 || device_counter == 0 {
            return Err(SyncError::InvalidData);
        }
        // Do not rely on a capability result cached from setup: WebDAV server
        // behaviour or an intervening proxy can change between sync sessions.
        self.verify_safe_conditions().await?;
        let sequence = cursor
            .snapshot
            .sequence
            .checked_add(1)
            .ok_or(SyncError::InvalidData)?;
        let snapshot = SyncSnapshot {
            protocol_version: SYNC_VERSION,
            sync_id: material.sync_id.clone(),
            sequence,
            parent_hash: Some(cursor.snapshot_hash.clone()),
            device_id: device_id.to_owned(),
            device_counter,
            created_at,
            entries: content.entries.clone(),
            tombstones: content.tombstones.clone(),
        };
        let (snapshot_bytes, snapshot_hash) = encode_snapshot(&snapshot, &material.key)?;
        self.put_immutable_snapshot(&material.sync_id, &snapshot_hash, &snapshot_bytes)
            .await?;

        let head = HeadPayload {
            protocol_version: SYNC_VERSION,
            sync_id: material.sync_id.clone(),
            sequence,
            snapshot_hash: snapshot_hash.clone(),
        };
        let head_bytes = encode_head(&head, &material.key)?;
        let head_name = remote_head_name(&material.sync_id)?;
        let next_etag = self
            .put_head_update(&head_name, &head_bytes, &head_etag)
            .await?;
        Ok(RemoteCursor {
            snapshot_hash,
            head_etag: next_etag,
            snapshot,
            proven_checkpoint: cursor.proven_checkpoint.clone(),
        })
    }

    pub async fn join_remote(
        &self,
        recovery_code: &str,
        device_id: &str,
        last_local_generation: u64,
        now: u64,
    ) -> SyncResult<(LocalSyncState, RemoteCursor)> {
        let material = parse_recovery_code(recovery_code)?;
        validate_uuid(device_id)?;
        if last_local_generation == 0 || now == 0 {
            return Err(SyncError::InvalidData);
        }
        self.verify_safe_conditions().await?;
        let mut cursor = self.inspect_remote(&material, None).await?;
        let state = self.local_state_from_cursor(
            &material,
            device_id,
            0,
            last_local_generation,
            now,
            &cursor,
        )?;
        // Joining is an explicit trust-on-first-use decision.  From this point
        // onward the authenticated head becomes this device's checkpoint.
        cursor.proven_checkpoint = state.checkpoint_hash.clone();
        Ok((state, cursor))
    }

    pub async fn fetch_for_sync(&self, state: &LocalSyncState) -> SyncResult<RemoteCursor> {
        validate_local_state(state)?;
        self.require_matching_state(state)?;
        let material = RecoveryMaterial {
            sync_id: state.sync_id.clone(),
            key: Zeroizing::new(state.sync_root_key),
        };
        self.inspect_remote(&material, state.checkpoint_hash.as_deref())
            .await
    }

    pub async fn commit_for_sync(
        &self,
        state: &mut LocalSyncState,
        cursor: &RemoteCursor,
        content: &SyncContent,
        local_generation: u64,
        now: u64,
    ) -> SyncResult<RemoteCursor> {
        validate_local_state(state)?;
        self.require_matching_state(state)?;
        if local_generation == 0 || now == 0 {
            return Err(SyncError::InvalidData);
        }
        validate_local_generation(state, local_generation)?;
        let checkpoint = state
            .checkpoint_hash
            .as_deref()
            .ok_or(SyncError::InvalidLocalState)?;
        let base = state
            .base_snapshot
            .as_ref()
            .ok_or(SyncError::InvalidLocalState)?;
        if cursor.proven_checkpoint.as_deref() != Some(checkpoint)
            || cursor.snapshot.sync_id != state.sync_id
            || cursor.snapshot.sequence < base.sequence
        {
            return Err(SyncError::RollbackOrFork);
        }
        if cursor.snapshot_hash == checkpoint
            && (cursor.snapshot.sequence != base.sequence
                || !contents_equal_snapshot(&base.content(), &cursor.snapshot)?)
        {
            return Err(SyncError::InvalidLocalState);
        }
        // An unchanged vault generation means the caller may only publish the
        // authenticated remote content.  Any other payload indicates that
        // local bytes changed without the vault's generation advancing (for
        // example, an old backup restored over the live vault).
        if local_generation == state.last_local_generation
            && !contents_equal_snapshot(content, &cursor.snapshot)?
        {
            return Err(SyncError::LocalRollback);
        }
        let next_counter = state
            .device_counter
            .checked_add(1)
            .ok_or(SyncError::InvalidData)?;
        let material = RecoveryMaterial {
            sync_id: state.sync_id.clone(),
            key: Zeroizing::new(state.sync_root_key),
        };
        let next = self
            .commit_remote(
                &material,
                cursor,
                &state.device_id,
                next_counter,
                content,
                now,
            )
            .await?;
        state.device_counter = next_counter;
        state.checkpoint_hash = Some(next.snapshot_hash.clone());
        state.base_snapshot = Some(next.snapshot.clone());
        state.last_local_generation = local_generation;
        state.last_sync_at = Some(now);
        validate_local_state(state)?;
        Ok(next)
    }

    /// Advances local checkpoint state after the caller has durably applied a
    /// fetched snapshot (or confirmed the local vault is already identical).
    /// It performs no network write and accepts only a cursor proven against
    /// this exact state's previous checkpoint.
    pub fn accept_fetched_for_sync(
        &self,
        state: &mut LocalSyncState,
        cursor: &RemoteCursor,
        local_generation: u64,
        now: u64,
    ) -> SyncResult<()> {
        validate_local_state(state)?;
        self.require_matching_state(state)?;
        if local_generation == 0 || now == 0 {
            return Err(SyncError::InvalidData);
        }
        validate_local_generation(state, local_generation)?;
        let checkpoint = state
            .checkpoint_hash
            .as_deref()
            .ok_or(SyncError::InvalidLocalState)?;
        let base = state
            .base_snapshot
            .as_ref()
            .ok_or(SyncError::InvalidLocalState)?;
        if cursor.proven_checkpoint.as_deref() != Some(checkpoint)
            || cursor.snapshot.sync_id != state.sync_id
            || cursor.snapshot.sequence < base.sequence
        {
            return Err(SyncError::RollbackOrFork);
        }
        if cursor.snapshot_hash == checkpoint
            && (cursor.snapshot.sequence != base.sequence
                || !contents_equal_snapshot(&base.content(), &cursor.snapshot)?)
        {
            return Err(SyncError::InvalidLocalState);
        }
        state.checkpoint_hash = Some(cursor.snapshot_hash.clone());
        state.base_snapshot = Some(cursor.snapshot.clone());
        state.last_local_generation = local_generation;
        state.last_sync_at = Some(now);
        validate_local_state(state)
    }

    fn local_state_from_cursor(
        &self,
        material: &RecoveryMaterial,
        device_id: &str,
        device_counter: u64,
        last_local_generation: u64,
        now: u64,
        cursor: &RemoteCursor,
    ) -> SyncResult<LocalSyncState> {
        let state = LocalSyncState {
            state_version: SYNC_VERSION,
            endpoint: self.endpoint.to_string(),
            username: self.username.clone(),
            app_password: self.app_password.as_str().to_owned(),
            sync_id: material.sync_id.clone(),
            sync_root_key: *material.key,
            device_id: device_id.to_owned(),
            device_counter,
            checkpoint_hash: Some(cursor.snapshot_hash.clone()),
            base_snapshot: Some(cursor.snapshot.clone()),
            last_local_generation,
            last_sync_at: Some(now),
        };
        validate_local_state(&state)?;
        Ok(state)
    }

    fn require_matching_state(&self, state: &LocalSyncState) -> SyncResult<()> {
        if self.endpoint.as_str() != state.endpoint || self.username != state.username {
            return Err(SyncError::InvalidLocalState);
        }
        Ok(())
    }

    async fn prove_checkpoint(
        &self,
        material: &RecoveryMaterial,
        first: &FetchedSnapshot,
        checkpoint: &str,
    ) -> SyncResult<()> {
        let started_at = Instant::now();
        let mut verifier = CheckpointVerifier::new(first, checkpoint)?;
        while !verifier.is_complete() {
            if started_at.elapsed() >= MAX_CHAIN_WALL_TIME {
                return Err(SyncError::ChainTooLong);
            }
            let parent_hash = verifier.required_parent_hash()?;
            let parent = self
                .fetch_snapshot(&material.sync_id, &parent_hash, &material.key)
                .await
                .map_err(|error| match error {
                    SyncError::RemoteNotInitialized => SyncError::RollbackOrFork,
                    other => other,
                })?;
            if started_at.elapsed() >= MAX_CHAIN_WALL_TIME {
                return Err(SyncError::ChainTooLong);
            }
            verifier.accept_parent(&parent)?;
            // `CheckpointVerifier` retains only hashes, IDs and counters. Drop
            // each decrypted ancestor immediately so a long chain cannot
            // multiply a full-vault snapshot into gigabytes of live memory.
            drop(parent);
        }
        Ok(())
    }

    async fn fetch_snapshot(
        &self,
        sync_id: &str,
        hash: &str,
        key: &[u8; KEY_BYTES],
    ) -> SyncResult<FetchedSnapshot> {
        let name = remote_snapshot_name(sync_id, hash)?;
        let resource = self
            .get_resource(&name, MAX_REMOTE_OBJECT_BYTES)
            .await?
            .ok_or(SyncError::RemoteNotInitialized)?;
        let snapshot = decode_snapshot(&resource.bytes, sync_id, key, hash)?;
        Ok(FetchedSnapshot {
            hash: hash.to_owned(),
            snapshot,
        })
    }

    async fn put_immutable_snapshot(
        &self,
        sync_id: &str,
        hash: &str,
        bytes: &[u8],
    ) -> SyncResult<()> {
        let name = remote_snapshot_name(sync_id, hash)?;
        let status = self
            .put_resource(&name, bytes, Some((IF_NONE_MATCH, "*")))
            .await?;
        if !is_write_success(status) && status != StatusCode::PRECONDITION_FAILED {
            return Err(status_error(status));
        }
        let fetched = self
            .get_resource(&name, MAX_REMOTE_OBJECT_BYTES)
            .await?
            .ok_or(SyncError::InvalidRemoteObject)?;
        if fetched.bytes != bytes || sha256_hex(&fetched.bytes) != hash {
            return Err(SyncError::HashMismatch);
        }
        Ok(())
    }

    async fn put_head_create(&self, name: &str, bytes: &[u8]) -> SyncResult<String> {
        let status = self
            .put_resource(name, bytes, Some((IF_NONE_MATCH, "*")))
            .await?;
        if status == StatusCode::PRECONDITION_FAILED {
            return Err(SyncError::RemoteAlreadyInitialized);
        }
        if !is_write_success(status) {
            return Err(status_error(status));
        }
        self.verify_head_after_put(name, bytes, None).await
    }

    async fn put_head_update(
        &self,
        name: &str,
        bytes: &[u8],
        current_etag: &str,
    ) -> SyncResult<String> {
        let status = self
            .put_resource(name, bytes, Some((IF_MATCH, current_etag)))
            .await?;
        if status == StatusCode::PRECONDITION_FAILED {
            return Err(SyncError::ConcurrentUpdate);
        }
        if !is_write_success(status) {
            return Err(status_error(status));
        }
        self.verify_head_after_put(name, bytes, Some(current_etag))
            .await
    }

    async fn verify_head_after_put(
        &self,
        name: &str,
        expected: &[u8],
        previous_etag: Option<&str>,
    ) -> SyncResult<String> {
        let fetched = self
            .get_resource(name, MAX_HEAD_BYTES)
            .await?
            .ok_or(SyncError::InvalidRemoteObject)?;
        if fetched.bytes != expected {
            return Err(SyncError::ConcurrentUpdate);
        }
        let etag = require_strong_etag(fetched.etag.as_deref())?;
        if previous_etag == Some(etag.as_str()) {
            return Err(SyncError::UnsafeServer);
        }
        Ok(etag)
    }

    fn request(&self, method: Method, url: Url) -> reqwest::RequestBuilder {
        self.client
            .request(method, url)
            .basic_auth(&self.username, Some(self.app_password.as_str()))
            // A cached head can make a download look up to date. Force caches
            // to revalidate reads as well as avoid storing vault traffic.
            .header(CACHE_CONTROL, "no-cache, no-store")
            .header(ACCEPT_ENCODING, "identity")
    }

    fn resource_url(&self, name: &str) -> SyncResult<Url> {
        validate_remote_name(name)?;
        self.endpoint
            .join(name)
            .map_err(|_| SyncError::InvalidEndpoint)
    }

    async fn get_resource(
        &self,
        name: &str,
        max_bytes: usize,
    ) -> SyncResult<Option<RemoteResource>> {
        let response = self
            .request(Method::GET, self.resource_url(name)?)
            .header(ACCEPT, "application/octet-stream")
            .send()
            .await
            .map_err(classify_transport_error)?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if response.status() != StatusCode::OK {
            return Err(status_error(response.status()));
        }
        let etag = response
            .headers()
            .get(ETAG)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let bytes = read_limited(response, max_bytes).await?;
        Ok(Some(RemoteResource { bytes, etag }))
    }

    async fn put_resource(
        &self,
        name: &str,
        body: &[u8],
        condition: Option<(reqwest::header::HeaderName, &str)>,
    ) -> SyncResult<StatusCode> {
        if body.len() > MAX_REMOTE_OBJECT_BYTES {
            return Err(SyncError::TooLarge);
        }
        let mut request = self
            .request(Method::PUT, self.resource_url(name)?)
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(body.to_vec());
        if let Some((name, value)) = condition {
            let value = HeaderValue::from_str(value).map_err(|_| SyncError::InvalidData)?;
            request = request.header(name, value);
        }
        request
            .send()
            .await
            .map(|response| response.status())
            .map_err(classify_transport_error)
    }

    async fn delete_resource(&self, name: &str, etag: Option<&str>) -> SyncResult<StatusCode> {
        let mut request = self.request(Method::DELETE, self.resource_url(name)?);
        if let Some(etag) = etag {
            let value = HeaderValue::from_str(etag).map_err(|_| SyncError::InvalidData)?;
            request = request.header(IF_MATCH, value);
        }
        request
            .send()
            .await
            .map(|response| response.status())
            .map_err(classify_transport_error)
    }
}

struct FetchedSnapshot {
    hash: String,
    snapshot: SyncSnapshot,
}

fn verify_rejected_probe_writes(
    fetched: Option<&RemoteResource>,
    expected_bytes: &[u8],
    expected_etag: &str,
) -> SyncResult<()> {
    let fetched = fetched.ok_or(SyncError::UnsafeServer)?;
    if fetched.bytes.as_slice() != expected_bytes
        || require_strong_etag(fetched.etag.as_deref())? != expected_etag
    {
        return Err(SyncError::UnsafeServer);
    }
    Ok(())
}

struct CheckpointLink {
    hash: String,
    sync_id: String,
    sequence: u64,
    parent_hash: Option<String>,
}

impl CheckpointLink {
    fn from_fetched(item: &FetchedSnapshot) -> SyncResult<Self> {
        validate_hash(&item.hash)?;
        validate_snapshot(&item.snapshot)?;
        Ok(Self {
            hash: item.hash.clone(),
            sync_id: item.snapshot.sync_id.clone(),
            sequence: item.snapshot.sequence,
            parent_hash: item.snapshot.parent_hash.clone(),
        })
    }
}

struct CheckpointVerifier {
    checkpoint: String,
    current: CheckpointLink,
    traversed: usize,
    seen: HashSet<String>,
}

impl CheckpointVerifier {
    fn new(first: &FetchedSnapshot, checkpoint: &str) -> SyncResult<Self> {
        validate_hash(checkpoint)?;
        let current = CheckpointLink::from_fetched(first)?;
        let mut seen = HashSet::with_capacity(MAX_CHAIN_DEPTH);
        seen.insert(current.hash.clone());
        Ok(Self {
            checkpoint: checkpoint.to_owned(),
            current,
            traversed: 1,
            seen,
        })
    }

    fn is_complete(&self) -> bool {
        self.current.hash == self.checkpoint
    }

    fn required_parent_hash(&self) -> SyncResult<String> {
        if self.is_complete() {
            return Err(SyncError::InvalidData);
        }
        if self.traversed >= MAX_CHAIN_DEPTH {
            return Err(SyncError::ChainTooLong);
        }
        self.current
            .parent_hash
            .clone()
            .ok_or(SyncError::RollbackOrFork)
    }

    fn accept_parent(&mut self, parent: &FetchedSnapshot) -> SyncResult<()> {
        if self.is_complete() {
            return Err(SyncError::InvalidData);
        }
        if self.traversed >= MAX_CHAIN_DEPTH {
            return Err(SyncError::ChainTooLong);
        }
        let parent = CheckpointLink::from_fetched(parent)?;
        if self.current.parent_hash.as_deref() != Some(parent.hash.as_str())
            || parent.sequence.checked_add(1) != Some(self.current.sequence)
            || self.current.sync_id != parent.sync_id
            || !self.seen.insert(parent.hash.clone())
        {
            return Err(SyncError::RollbackOrFork);
        }
        self.current = parent;
        self.traversed += 1;
        Ok(())
    }
}

pub fn generate_recovery_material() -> SyncResult<(RecoveryMaterial, Zeroizing<String>)> {
    let sync_id = Uuid::new_v4().to_string();
    let mut key = Zeroizing::new([0_u8; KEY_BYTES]);
    getrandom::fill(key.as_mut()).map_err(|_| SyncError::InvalidRecoveryCode)?;
    let material = RecoveryMaterial { sync_id, key };
    let code = format_recovery_code(&material)?;
    Ok((material, code))
}

pub fn format_recovery_code(material: &RecoveryMaterial) -> SyncResult<Zeroizing<String>> {
    validate_recovery_material(material)?;
    format_recovery_parts(&material.sync_id, &material.key)
}

fn format_recovery_parts(sync_id: &str, key: &[u8; KEY_BYTES]) -> SyncResult<Zeroizing<String>> {
    validate_uuid(sync_id).map_err(|_| SyncError::InvalidRecoveryCode)?;
    validate_root_key(key).map_err(|_| SyncError::InvalidRecoveryCode)?;
    let encoded_key = Zeroizing::new(URL_SAFE_NO_PAD.encode(key));
    Ok(Zeroizing::new(format!(
        "CN1.{}.{}",
        sync_id,
        encoded_key.as_str()
    )))
}

pub fn parse_recovery_code(code: &str) -> SyncResult<RecoveryMaterial> {
    if code.len() > 128 || code.trim() != code {
        return Err(SyncError::InvalidRecoveryCode);
    }
    let mut parts = code.split('.');
    if parts.next() != Some("CN1") {
        return Err(SyncError::InvalidRecoveryCode);
    }
    let sync_id = parts.next().ok_or(SyncError::InvalidRecoveryCode)?;
    let encoded_key = parts.next().ok_or(SyncError::InvalidRecoveryCode)?;
    if parts.next().is_some() {
        return Err(SyncError::InvalidRecoveryCode);
    }
    validate_uuid(sync_id).map_err(|_| SyncError::InvalidRecoveryCode)?;
    let decoded = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(encoded_key)
            .map_err(|_| SyncError::InvalidRecoveryCode)?,
    );
    if decoded.len() != KEY_BYTES {
        return Err(SyncError::InvalidRecoveryCode);
    }
    let mut key = Zeroizing::new([0_u8; KEY_BYTES]);
    key.copy_from_slice(&decoded);
    let material = RecoveryMaterial {
        sync_id: sync_id.to_owned(),
        key,
    };
    validate_recovery_material(&material).map_err(|_| SyncError::InvalidRecoveryCode)?;
    if format_recovery_code(&material)?.as_str() != code {
        return Err(SyncError::InvalidRecoveryCode);
    }
    Ok(material)
}

pub fn validate_webdav_endpoint(endpoint: &str) -> SyncResult<Url> {
    if endpoint.is_empty()
        || endpoint.len() > MAX_ENDPOINT_BYTES
        || endpoint.trim() != endpoint
        || endpoint.chars().any(char::is_control)
    {
        return Err(SyncError::InvalidEndpoint);
    }
    let url = Url::parse(endpoint).map_err(|_| SyncError::InvalidEndpoint)?;
    let lower_path = url.path().to_ascii_lowercase();
    if url.scheme() != "https"
        || url.cannot_be_a_base()
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.path().ends_with('/')
        || lower_path.contains("%2f")
        || lower_path.contains("%5c")
        || url.path().contains('\\')
    {
        return Err(SyncError::InvalidEndpoint);
    }
    Ok(url)
}

/// Rejects restoring an older local vault over a state that has already
/// synchronized a newer generation.  Call this immediately after opening the
/// vault, before presenting sync as available.
pub fn validate_local_generation(
    state: &LocalSyncState,
    current_generation: u64,
) -> SyncResult<()> {
    validate_local_state(state)?;
    if current_generation == 0 {
        return Err(SyncError::InvalidData);
    }
    if current_generation < state.last_local_generation {
        return Err(SyncError::LocalRollback);
    }
    Ok(())
}

pub fn write_local_sync_state(
    path: &Path,
    vault_id: &str,
    vault_root_key: &[u8; KEY_BYTES],
    state: &LocalSyncState,
) -> SyncResult<()> {
    validate_uuid(vault_id)?;
    validate_local_state(state)?;
    let plaintext = Zeroizing::new(serde_json::to_vec(state).map_err(|_| SyncError::InvalidData)?);
    if plaintext.len() > MAX_LOCAL_STATE_BYTES {
        return Err(SyncError::TooLarge);
    }
    let key = derive_local_state_key(vault_root_key, vault_id)?;
    let encrypted = encrypt_block(
        &plaintext,
        &key,
        &local_state_aad(vault_id),
        SyncError::LocalStateIo,
    )?;
    let envelope = LocalStateEnvelope {
        format: LOCAL_STATE_FORMAT.to_owned(),
        version: SYNC_VERSION,
        vault_id: vault_id.to_owned(),
        nonce: encrypted.0,
        ciphertext: encrypted.1,
    };
    let bytes = serde_json::to_vec(&envelope).map_err(|_| SyncError::LocalStateIo)?;
    if bytes.len() > MAX_LOCAL_STATE_BYTES {
        return Err(SyncError::TooLarge);
    }
    write_private_atomic(path, &bytes)
}

pub fn read_local_sync_state(
    path: &Path,
    vault_id: &str,
    vault_root_key: &[u8; KEY_BYTES],
) -> SyncResult<LocalSyncState> {
    validate_uuid(vault_id).map_err(|_| SyncError::InvalidLocalState)?;
    let file = File::open(path).map_err(|_| SyncError::InvalidLocalState)?;
    let metadata = file.metadata().map_err(|_| SyncError::InvalidLocalState)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_LOCAL_STATE_BYTES as u64 {
        return Err(SyncError::InvalidLocalState);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_LOCAL_STATE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| SyncError::InvalidLocalState)?;
    if bytes.is_empty() || bytes.len() > MAX_LOCAL_STATE_BYTES {
        return Err(SyncError::InvalidLocalState);
    }
    let envelope: LocalStateEnvelope =
        serde_json::from_slice(&bytes).map_err(|_| SyncError::InvalidLocalState)?;
    if envelope.format != LOCAL_STATE_FORMAT
        || envelope.version != SYNC_VERSION
        || envelope.vault_id != vault_id
    {
        return Err(SyncError::InvalidLocalState);
    }
    let key = derive_local_state_key(vault_root_key, vault_id)
        .map_err(|_| SyncError::InvalidLocalState)?;
    let plaintext = decrypt_block(
        &envelope.nonce,
        &envelope.ciphertext,
        &key,
        &local_state_aad(vault_id),
        MAX_LOCAL_STATE_BYTES,
    )
    .map_err(|_| SyncError::InvalidLocalState)?;
    let state: LocalSyncState =
        serde_json::from_slice(&plaintext).map_err(|_| SyncError::InvalidLocalState)?;
    validate_local_state(&state).map_err(|_| SyncError::InvalidLocalState)?;
    Ok(state)
}

pub fn rewrap_local_sync_state(
    path: &Path,
    vault_id: &str,
    old_vault_root_key: &[u8; KEY_BYTES],
    new_vault_root_key: &[u8; KEY_BYTES],
) -> SyncResult<()> {
    let state = read_local_sync_state(path, vault_id, old_vault_root_key)?;
    write_local_sync_state(path, vault_id, new_vault_root_key, &state)
}

pub fn remove_local_sync_state(path: &Path) -> SyncResult<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(SyncError::LocalStateIo),
    }
}

pub fn merge_three_way(
    base: &SyncSnapshot,
    local: &SyncContent,
    remote: &SyncSnapshot,
    now: u64,
) -> SyncResult<MergeResult> {
    validate_snapshot(base)?;
    validate_content(local)?;
    validate_snapshot(remote)?;
    if base.sync_id != remote.sync_id || now == 0 {
        return Err(SyncError::InvalidData);
    }

    let base_map = record_map(&base.entries, &base.tombstones)?;
    let local_map = record_map(&local.entries, &local.tombstones)?;
    let remote_map = record_map(&remote.entries, &remote.tombstones)?;
    // Deletion is represented exclusively by a tombstone.  Treating a record
    // that simply vanished as a deletion would silently discard credentials
    // after a malformed import or an old/partial local restore.
    if base_map
        .keys()
        .any(|id| !local_map.contains_key(id) || !remote_map.contains_key(id))
    {
        return Err(SyncError::InvalidData);
    }
    let mut ids = BTreeSet::new();
    ids.extend(base_map.keys().cloned());
    ids.extend(local_map.keys().cloned());
    ids.extend(remote_map.keys().cloned());

    let mut entries = Vec::new();
    let mut tombstones = Vec::new();
    let mut conflicts = Vec::new();
    let mut occupied_ids = ids.clone();

    for id in ids {
        let base_record = base_map.get(&id);
        let local_record = local_map.get(&id);
        let remote_record = remote_map.get(&id);

        if records_equal(local_record, remote_record) {
            emit_record(local_record, &mut entries, &mut tombstones);
        } else if records_equal(local_record, base_record) {
            emit_record(remote_record, &mut entries, &mut tombstones);
        } else if records_equal(remote_record, base_record) {
            emit_record(local_record, &mut entries, &mut tombstones);
        } else {
            match (local_record, remote_record) {
                (Some(Record::Entry(local_entry)), Some(Record::Entry(remote_entry))) => {
                    entries.push(local_entry.clone());
                    let copy = conflict_copy(remote_entry, now, &mut occupied_ids)?;
                    conflicts.push(MergeConflict {
                        original_id: id,
                        preserved_copy_id: copy.id.clone(),
                        kind: MergeConflictKind::BothModified,
                    });
                    entries.push(copy);
                }
                (Some(Record::Entry(modified)), Some(Record::Deleted(deleted)))
                | (Some(Record::Deleted(deleted)), Some(Record::Entry(modified))) => {
                    tombstones.push(deleted.clone());
                    let copy = conflict_copy(modified, now, &mut occupied_ids)?;
                    conflicts.push(MergeConflict {
                        original_id: id,
                        preserved_copy_id: copy.id.clone(),
                        kind: MergeConflictKind::DeleteVsModify,
                    });
                    entries.push(copy);
                }
                (Some(Record::Deleted(left)), Some(Record::Deleted(right))) => {
                    tombstones.push(prefer_tombstone(left, right));
                }
                _ => return Err(SyncError::InvalidData),
            }
        }
    }

    entries.sort_by(|left, right| left.id.cmp(&right.id));
    tombstones.sort_by(|left, right| left.id.cmp(&right.id));
    let content = SyncContent {
        entries,
        tombstones,
    };
    validate_content(&content)?;
    Ok(MergeResult { content, conflicts })
}

/// Safely combines a non-empty local vault with a remote space during first
/// join, where no common ancestor exists.  It is deliberately separate from
/// three-way merge: disjoint IDs are unioned, equal records are deduplicated,
/// and every same-ID disagreement preserves both credential values.
pub fn merge_for_join(
    local: &SyncContent,
    remote: &SyncSnapshot,
    now: u64,
) -> SyncResult<MergeResult> {
    validate_content(local)?;
    validate_snapshot(remote)?;
    if now == 0 {
        return Err(SyncError::InvalidData);
    }
    let local_map = record_map(&local.entries, &local.tombstones)?;
    let remote_map = record_map(&remote.entries, &remote.tombstones)?;
    let mut ids = BTreeSet::new();
    ids.extend(local_map.keys().cloned());
    ids.extend(remote_map.keys().cloned());
    let mut occupied_ids = ids.clone();
    let mut entries = Vec::new();
    let mut tombstones = Vec::new();
    let mut conflicts = Vec::new();

    for id in ids {
        let local_record = local_map.get(&id);
        let remote_record = remote_map.get(&id);
        if records_equal(local_record, remote_record) {
            emit_record(local_record, &mut entries, &mut tombstones);
            continue;
        }
        match (local_record, remote_record) {
            (Some(record), None) | (None, Some(record)) => {
                emit_record(Some(record), &mut entries, &mut tombstones);
            }
            (Some(Record::Entry(local_entry)), Some(Record::Entry(remote_entry))) => {
                entries.push(local_entry.clone());
                let copy = conflict_copy(remote_entry, now, &mut occupied_ids)?;
                conflicts.push(MergeConflict {
                    original_id: id,
                    preserved_copy_id: copy.id.clone(),
                    kind: MergeConflictKind::JoinCollision,
                });
                entries.push(copy);
            }
            (Some(Record::Entry(modified)), Some(Record::Deleted(deleted)))
            | (Some(Record::Deleted(deleted)), Some(Record::Entry(modified))) => {
                tombstones.push(deleted.clone());
                let copy = conflict_copy(modified, now, &mut occupied_ids)?;
                conflicts.push(MergeConflict {
                    original_id: id,
                    preserved_copy_id: copy.id.clone(),
                    kind: MergeConflictKind::DeleteVsModify,
                });
                entries.push(copy);
            }
            (Some(Record::Deleted(left)), Some(Record::Deleted(right))) => {
                tombstones.push(prefer_tombstone(left, right));
            }
            (None, None) => unreachable!("union contains only present record IDs"),
        }
    }

    entries.sort_by(|left, right| left.id.cmp(&right.id));
    tombstones.sort_by(|left, right| left.id.cmp(&right.id));
    let content = SyncContent {
        entries,
        tombstones,
    };
    validate_content(&content)?;
    Ok(MergeResult { content, conflicts })
}

fn encode_snapshot(
    snapshot: &SyncSnapshot,
    key: &[u8; KEY_BYTES],
) -> SyncResult<(Vec<u8>, String)> {
    validate_snapshot(snapshot)?;
    let bytes = encode_remote_object(
        REMOTE_SNAPSHOT_FORMAT,
        &snapshot.sync_id,
        key,
        b"snapshot",
        snapshot,
        MAX_REMOTE_OBJECT_BYTES,
    )?;
    let hash = sha256_hex(&bytes);
    Ok((bytes, hash))
}

fn decode_snapshot(
    bytes: &[u8],
    sync_id: &str,
    key: &[u8; KEY_BYTES],
    expected_hash: &str,
) -> SyncResult<SyncSnapshot> {
    validate_hash(expected_hash)?;
    if sha256_hex(bytes) != expected_hash {
        return Err(SyncError::HashMismatch);
    }
    let snapshot: SyncSnapshot = decode_remote_object(
        REMOTE_SNAPSHOT_FORMAT,
        sync_id,
        key,
        b"snapshot",
        bytes,
        MAX_REMOTE_OBJECT_BYTES,
    )?;
    validate_snapshot(&snapshot)?;
    if snapshot.sync_id != sync_id {
        return Err(SyncError::InvalidRemoteObject);
    }
    Ok(snapshot)
}

fn encode_head(head: &HeadPayload, key: &[u8; KEY_BYTES]) -> SyncResult<Vec<u8>> {
    validate_head(head)?;
    encode_remote_object(
        REMOTE_HEAD_FORMAT,
        &head.sync_id,
        key,
        b"head",
        head,
        MAX_HEAD_BYTES,
    )
}

fn decode_head(bytes: &[u8], sync_id: &str, key: &[u8; KEY_BYTES]) -> SyncResult<HeadPayload> {
    let head: HeadPayload = decode_remote_object(
        REMOTE_HEAD_FORMAT,
        sync_id,
        key,
        b"head",
        bytes,
        MAX_HEAD_BYTES,
    )?;
    validate_head(&head)?;
    if head.sync_id != sync_id {
        return Err(SyncError::InvalidRemoteObject);
    }
    Ok(head)
}

fn encode_remote_object<T: Serialize>(
    format: &str,
    sync_id: &str,
    root_key: &[u8; KEY_BYTES],
    purpose: &[u8],
    value: &T,
    max_bytes: usize,
) -> SyncResult<Vec<u8>> {
    validate_uuid(sync_id)?;
    validate_root_key(root_key)?;
    let plaintext = Zeroizing::new(serde_json::to_vec(value).map_err(|_| SyncError::InvalidData)?);
    if plaintext.len() > max_bytes {
        return Err(SyncError::TooLarge);
    }
    let key = derive_sync_key(root_key, sync_id, purpose)?;
    let encrypted = encrypt_block(
        &plaintext,
        &key,
        &remote_aad(format, sync_id),
        SyncError::InvalidData,
    )?;
    let envelope = EncryptedObject {
        format: format.to_owned(),
        version: SYNC_VERSION,
        nonce: encrypted.0,
        ciphertext: encrypted.1,
    };
    let bytes = serde_json::to_vec(&envelope).map_err(|_| SyncError::InvalidData)?;
    if bytes.len() > max_bytes {
        return Err(SyncError::TooLarge);
    }
    Ok(bytes)
}

fn decode_remote_object<T: DeserializeOwned>(
    expected_format: &str,
    sync_id: &str,
    root_key: &[u8; KEY_BYTES],
    purpose: &[u8],
    bytes: &[u8],
    max_bytes: usize,
) -> SyncResult<T> {
    validate_uuid(sync_id).map_err(|_| SyncError::InvalidRemoteObject)?;
    validate_root_key(root_key).map_err(|_| SyncError::InvalidRemoteObject)?;
    if bytes.is_empty() || bytes.len() > max_bytes {
        return Err(SyncError::TooLarge);
    }
    let envelope: EncryptedObject =
        serde_json::from_slice(bytes).map_err(|_| SyncError::InvalidRemoteObject)?;
    if envelope.format != expected_format || envelope.version != SYNC_VERSION {
        return Err(SyncError::InvalidRemoteObject);
    }
    let key =
        derive_sync_key(root_key, sync_id, purpose).map_err(|_| SyncError::InvalidRemoteObject)?;
    let plaintext = decrypt_block(
        &envelope.nonce,
        &envelope.ciphertext,
        &key,
        &remote_aad(expected_format, sync_id),
        max_bytes,
    )?;
    serde_json::from_slice(&plaintext).map_err(|_| SyncError::InvalidRemoteObject)
}

fn encrypt_block(
    plaintext: &[u8],
    key: &[u8; KEY_BYTES],
    aad: &[u8],
    error: SyncError,
) -> SyncResult<(String, String)> {
    let mut nonce = [0_u8; NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(|_| error)?;
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
        STANDARD_NO_PAD.encode(nonce),
        STANDARD_NO_PAD.encode(ciphertext),
    ))
}

fn decrypt_block(
    encoded_nonce: &str,
    encoded_ciphertext: &str,
    key: &[u8; KEY_BYTES],
    aad: &[u8],
    max_plaintext: usize,
) -> SyncResult<Zeroizing<Vec<u8>>> {
    let nonce = decode_exact::<NONCE_BYTES>(encoded_nonce)?;
    let ciphertext = Zeroizing::new(
        STANDARD_NO_PAD
            .decode(encoded_ciphertext)
            .map_err(|_| SyncError::InvalidRemoteObject)?,
    );
    if ciphertext.len() < TAG_BYTES || ciphertext.len() > max_plaintext.saturating_add(TAG_BYTES) {
        return Err(SyncError::InvalidRemoteObject);
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

fn derive_sync_key(
    root_key: &[u8; KEY_BYTES],
    sync_id: &str,
    purpose: &[u8],
) -> SyncResult<Zeroizing<[u8; KEY_BYTES]>> {
    let hkdf = Hkdf::<Sha256>::new(Some(sync_id.as_bytes()), root_key);
    let mut info = b"CipherNest sync-v1".to_vec();
    append_field(&mut info, purpose);
    let mut key = Zeroizing::new([0_u8; KEY_BYTES]);
    hkdf.expand(&info, key.as_mut())
        .map_err(|_| SyncError::InvalidData)?;
    Ok(key)
}

fn derive_local_state_key(
    vault_root_key: &[u8; KEY_BYTES],
    vault_id: &str,
) -> SyncResult<Zeroizing<[u8; KEY_BYTES]>> {
    let hkdf = Hkdf::<Sha256>::new(Some(vault_id.as_bytes()), vault_root_key);
    let mut key = Zeroizing::new([0_u8; KEY_BYTES]);
    hkdf.expand(b"CipherNest local-sync-state-v1", key.as_mut())
        .map_err(|_| SyncError::LocalStateIo)?;
    Ok(key)
}

fn remote_aad(format: &str, sync_id: &str) -> Vec<u8> {
    let mut aad = b"CipherNest\0REMOTE_SYNC\0v1".to_vec();
    append_field(&mut aad, format.as_bytes());
    append_field(&mut aad, sync_id.as_bytes());
    aad
}

fn local_state_aad(vault_id: &str) -> Vec<u8> {
    let mut aad = b"CipherNest\0LOCAL_SYNC_STATE\0v1".to_vec();
    append_field(&mut aad, vault_id.as_bytes());
    aad
}

fn append_field(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}

fn validate_recovery_material(material: &RecoveryMaterial) -> SyncResult<()> {
    validate_uuid(&material.sync_id).map_err(|_| SyncError::InvalidRecoveryCode)?;
    validate_root_key(&material.key).map_err(|_| SyncError::InvalidRecoveryCode)
}

fn validate_root_key(key: &[u8; KEY_BYTES]) -> SyncResult<()> {
    if key.iter().all(|byte| *byte == 0) {
        Err(SyncError::InvalidData)
    } else {
        Ok(())
    }
}

fn validate_credentials(username: &str, app_password: &str) -> SyncResult<()> {
    if username.is_empty()
        || username.chars().count() > MAX_USERNAME_CHARS
        || username.chars().any(char::is_control)
        || username.contains(':')
        || app_password.is_empty()
        || app_password.len() > MAX_PASSWORD_BYTES
        || app_password.chars().any(|character| character == '\0')
    {
        Err(SyncError::InvalidCredentials)
    } else {
        Ok(())
    }
}

fn validate_local_state(state: &LocalSyncState) -> SyncResult<()> {
    if state.state_version != SYNC_VERSION
        || state.last_local_generation == 0
        || state.last_sync_at == Some(0)
    {
        return Err(SyncError::InvalidLocalState);
    }
    let endpoint =
        validate_webdav_endpoint(&state.endpoint).map_err(|_| SyncError::InvalidLocalState)?;
    if endpoint.as_str() != state.endpoint {
        return Err(SyncError::InvalidLocalState);
    }
    validate_credentials(&state.username, &state.app_password)
        .map_err(|_| SyncError::InvalidLocalState)?;
    validate_uuid(&state.sync_id).map_err(|_| SyncError::InvalidLocalState)?;
    validate_uuid(&state.device_id).map_err(|_| SyncError::InvalidLocalState)?;
    validate_root_key(&state.sync_root_key).map_err(|_| SyncError::InvalidLocalState)?;
    match (&state.checkpoint_hash, &state.base_snapshot) {
        (None, None) => {}
        (Some(hash), Some(snapshot)) => {
            validate_hash(hash).map_err(|_| SyncError::InvalidLocalState)?;
            validate_snapshot(snapshot).map_err(|_| SyncError::InvalidLocalState)?;
            if snapshot.sync_id != state.sync_id {
                return Err(SyncError::InvalidLocalState);
            }
        }
        _ => return Err(SyncError::InvalidLocalState),
    }
    Ok(())
}

fn validate_head(head: &HeadPayload) -> SyncResult<()> {
    if head.protocol_version != SYNC_VERSION || head.sequence == 0 {
        return Err(SyncError::InvalidRemoteObject);
    }
    validate_uuid(&head.sync_id).map_err(|_| SyncError::InvalidRemoteObject)?;
    validate_hash(&head.snapshot_hash).map_err(|_| SyncError::InvalidRemoteObject)
}

fn validate_snapshot(snapshot: &SyncSnapshot) -> SyncResult<()> {
    if snapshot.protocol_version != SYNC_VERSION
        || snapshot.sequence == 0
        || snapshot.device_counter == 0
        || snapshot.created_at == 0
    {
        return Err(SyncError::InvalidData);
    }
    validate_uuid(&snapshot.sync_id)?;
    validate_uuid(&snapshot.device_id)?;
    match (snapshot.sequence, snapshot.parent_hash.as_deref()) {
        (1, None) => {}
        (1, Some(_)) | (_, None) => return Err(SyncError::InvalidData),
        (_, Some(hash)) => validate_hash(hash)?,
    }
    validate_content_parts(&snapshot.entries, &snapshot.tombstones)
}

fn validate_content(content: &SyncContent) -> SyncResult<()> {
    validate_content_parts(&content.entries, &content.tombstones)
}

fn validate_content_parts(entries: &[VaultEntry], tombstones: &[Tombstone]) -> SyncResult<()> {
    if entries.len() > MAX_VAULT_ENTRIES || tombstones.len() > MAX_VAULT_TOMBSTONES {
        return Err(SyncError::TooLarge);
    }
    let mut ids = HashSet::with_capacity(entries.len() + tombstones.len());
    for entry in entries {
        validate_entry(entry)?;
        if !ids.insert(entry.id.as_str()) {
            return Err(SyncError::InvalidData);
        }
    }
    for tombstone in tombstones {
        validate_uuid(&tombstone.id)?;
        if tombstone.revision == 0
            || tombstone.deleted_at == 0
            || !ids.insert(tombstone.id.as_str())
        {
            return Err(SyncError::InvalidData);
        }
    }
    Ok(())
}

fn validate_entry(entry: &VaultEntry) -> SyncResult<()> {
    validate_uuid(&entry.id)?;
    if !(1..=200).contains(&entry.title.chars().count())
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
    Ok(())
}

fn validate_uuid(value: &str) -> SyncResult<()> {
    let parsed = Uuid::parse_str(value).map_err(|_| SyncError::InvalidData)?;
    if parsed.to_string() != value {
        return Err(SyncError::InvalidData);
    }
    Ok(())
}

fn validate_hash(value: &str) -> SyncResult<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SyncError::InvalidData);
    }
    Ok(())
}

fn validate_remote_name(name: &str) -> SyncResult<()> {
    if name.is_empty()
        || name.len() > 200
        || !name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.')
        })
        || name.starts_with('.')
        || name.contains("..")
    {
        return Err(SyncError::InvalidData);
    }
    Ok(())
}

fn remote_snapshot_name(sync_id: &str, hash: &str) -> SyncResult<String> {
    validate_uuid(sync_id)?;
    validate_hash(hash)?;
    let name = format!("ciphernest-{sync_id}-snapshot-{hash}.cnsnap");
    validate_remote_name(&name)?;
    Ok(name)
}

fn remote_head_name(sync_id: &str) -> SyncResult<String> {
    validate_uuid(sync_id)?;
    let name = format!("ciphernest-{sync_id}-head.cnhead");
    validate_remote_name(&name)?;
    Ok(name)
}

fn require_strong_etag(value: Option<&str>) -> SyncResult<String> {
    let value = value.ok_or(SyncError::UnsafeServer)?;
    let bytes = value.as_bytes();
    if value.len() > 512
        || value.starts_with("W/")
        || value.starts_with("w/")
        || bytes.len() < 2
        || bytes.first() != Some(&b'"')
        || bytes.last() != Some(&b'"')
        || !bytes[1..bytes.len() - 1]
            .iter()
            .all(|byte| (0x21..=0x7e).contains(byte) && *byte != b'"')
    {
        return Err(SyncError::UnsafeServer);
    }
    Ok(value.to_owned())
}

fn propfind_reports_collection(body: &[u8], endpoint: &Url) -> SyncResult<bool> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Capture {
        Href,
        Status,
    }

    let mut reader = NsReader::from_reader(body);
    reader.config_mut().trim_text(true);
    let mut buffer = Vec::new();
    let mut in_response = false;
    let mut in_propstat = false;
    let mut in_resource_type = false;
    let mut capture = None;
    let mut href = String::new();
    let mut status = String::new();
    let mut propstat_collection = false;
    let mut response_collection = false;
    let mut exact_collection_found = false;

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
            Event::Start(element) if is_dav => match element.local_name().as_ref() {
                b"response" => {
                    if in_response {
                        return Err(SyncError::InvalidRemoteObject);
                    }
                    in_response = true;
                    href.clear();
                    response_collection = false;
                }
                b"href" if in_response && !in_propstat => {
                    href.clear();
                    capture = Some(Capture::Href);
                }
                b"propstat" if in_response => {
                    if in_propstat {
                        return Err(SyncError::InvalidRemoteObject);
                    }
                    in_propstat = true;
                    status.clear();
                    propstat_collection = false;
                }
                b"status" if in_propstat => {
                    status.clear();
                    capture = Some(Capture::Status);
                }
                b"resourcetype" if in_propstat => in_resource_type = true,
                b"collection" if in_propstat && in_resource_type => {
                    propstat_collection = true;
                }
                _ => {}
            },
            Event::Empty(element) if is_dav => {
                if element.local_name().as_ref() == b"collection" && in_propstat && in_resource_type
                {
                    propstat_collection = true;
                }
            }
            Event::Text(text) => {
                if let Some(target) = capture {
                    let decoded = text
                        .xml10_content()
                        .map_err(|_| SyncError::InvalidRemoteObject)?;
                    let destination = match target {
                        Capture::Href => &mut href,
                        Capture::Status => &mut status,
                    };
                    if destination.len().saturating_add(decoded.len()) > MAX_ENDPOINT_BYTES {
                        return Err(SyncError::InvalidRemoteObject);
                    }
                    destination.push_str(&decoded);
                }
            }
            Event::End(element) if is_dav => match element.local_name().as_ref() {
                b"href" => capture = None,
                b"status" => capture = None,
                b"resourcetype" => in_resource_type = false,
                b"propstat" if in_propstat => {
                    if propstat_collection && dav_status_is_success(&status) {
                        response_collection = true;
                    }
                    in_propstat = false;
                    in_resource_type = false;
                    capture = None;
                }
                b"response" if in_response => {
                    if response_collection && dav_href_matches_endpoint(&href, endpoint) {
                        exact_collection_found = true;
                    }
                    in_response = false;
                    in_propstat = false;
                    in_resource_type = false;
                    capture = None;
                }
                _ => {}
            },
            Event::DocType(_) | Event::GeneralRef(_) => {
                return Err(SyncError::InvalidRemoteObject);
            }
            Event::Eof => {
                if in_response || in_propstat || in_resource_type || capture.is_some() {
                    return Err(SyncError::InvalidRemoteObject);
                }
                return Ok(exact_collection_found);
            }
            _ => {}
        }
        buffer.clear();
        if reader.buffer_position() as usize > MAX_PROPFIND_BYTES {
            return Err(SyncError::TooLarge);
        }
    }
}

fn dav_status_is_success(status: &str) -> bool {
    let mut fields = status.split_ascii_whitespace();
    let Some(version) = fields.next() else {
        return false;
    };
    let Some(code) = fields.next().and_then(|value| value.parse::<u16>().ok()) else {
        return false;
    };
    version.starts_with("HTTP/") && (200..300).contains(&code)
}

fn dav_href_matches_endpoint(href: &str, endpoint: &Url) -> bool {
    if href.is_empty() || href.trim() != href || href.chars().any(char::is_control) {
        return false;
    }
    let Ok(candidate) = endpoint.join(href) else {
        return false;
    };
    candidate.scheme() == endpoint.scheme()
        && candidate.host_str() == endpoint.host_str()
        && candidate.port_or_known_default() == endpoint.port_or_known_default()
        && candidate.username() == endpoint.username()
        && candidate.password() == endpoint.password()
        && candidate.path() == endpoint.path()
        && candidate.query().is_none()
        && candidate.fragment().is_none()
}

fn classify_transport_error(error: reqwest::Error) -> SyncError {
    // Reqwest errors can contain the requested URL. Only expose fixed,
    // credential-free categories to the UI; never forward the error text.
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
    while let Some(chunk) = response.chunk().await.map_err(classify_transport_error)? {
        if bytes.len().saturating_add(chunk.len()) > limit {
            return Err(SyncError::TooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn random_probe_bytes() -> SyncResult<[u8; 32]> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| SyncError::Transport)?;
    Ok(bytes)
}

fn is_write_success(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::OK | StatusCode::CREATED | StatusCode::NO_CONTENT
    )
}

fn status_error(status: StatusCode) -> SyncError {
    match status {
        StatusCode::NOT_FOUND => SyncError::RemoteNotInitialized,
        StatusCode::PRECONDITION_FAILED => SyncError::ConcurrentUpdate,
        _ => SyncError::UnexpectedStatus(status.as_u16()),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn decode_exact<const N: usize>(encoded: &str) -> SyncResult<[u8; N]> {
    let decoded = Zeroizing::new(
        STANDARD_NO_PAD
            .decode(encoded)
            .map_err(|_| SyncError::InvalidRemoteObject)?,
    );
    decoded
        .as_slice()
        .try_into()
        .map_err(|_| SyncError::InvalidRemoteObject)
}

#[derive(Clone)]
enum Record {
    Entry(VaultEntry),
    Deleted(Tombstone),
}

fn record_map(
    entries: &[VaultEntry],
    tombstones: &[Tombstone],
) -> SyncResult<HashMap<String, Record>> {
    validate_content_parts(entries, tombstones)?;
    let mut records = HashMap::with_capacity(entries.len() + tombstones.len());
    for entry in entries {
        records.insert(entry.id.clone(), Record::Entry(entry.clone()));
    }
    for tombstone in tombstones {
        records.insert(tombstone.id.clone(), Record::Deleted(tombstone.clone()));
    }
    Ok(records)
}

fn records_equal(left: Option<&Record>, right: Option<&Record>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(Record::Entry(left)), Some(Record::Entry(right))) => entries_equal(left, right),
        (Some(Record::Deleted(left)), Some(Record::Deleted(right))) => {
            left.id == right.id
                && left.revision == right.revision
                && left.deleted_at == right.deleted_at
        }
        _ => false,
    }
}

fn contents_equal_snapshot(content: &SyncContent, snapshot: &SyncSnapshot) -> SyncResult<bool> {
    let content_records = record_map(&content.entries, &content.tombstones)?;
    let snapshot_records = record_map(&snapshot.entries, &snapshot.tombstones)?;
    if content_records.len() != snapshot_records.len() {
        return Ok(false);
    }
    Ok(content_records
        .iter()
        .all(|(id, record)| records_equal(Some(record), snapshot_records.get(id))))
}

fn entries_equal(left: &VaultEntry, right: &VaultEntry) -> bool {
    left.id == right.id
        && left.title == right.title
        && left.username == right.username
        && left.password == right.password
        && left.url == right.url
        && left.purpose == right.purpose
        && left.notes == right.notes
        && left.tags == right.tags
        && left.favorite == right.favorite
        && left.created_at == right.created_at
        && left.updated_at == right.updated_at
        && left.password_updated_at == right.password_updated_at
        && left.revision == right.revision
}

fn emit_record(
    record: Option<&Record>,
    entries: &mut Vec<VaultEntry>,
    tombstones: &mut Vec<Tombstone>,
) {
    match record {
        Some(Record::Entry(entry)) => entries.push(entry.clone()),
        Some(Record::Deleted(tombstone)) => tombstones.push(tombstone.clone()),
        None => {}
    }
}

fn prefer_tombstone(left: &Tombstone, right: &Tombstone) -> Tombstone {
    if (left.revision, left.deleted_at) >= (right.revision, right.deleted_at) {
        left.clone()
    } else {
        right.clone()
    }
}

fn conflict_copy(
    source: &VaultEntry,
    now: u64,
    occupied_ids: &mut BTreeSet<String>,
) -> SyncResult<VaultEntry> {
    let id = loop {
        let candidate = Uuid::new_v4().to_string();
        if occupied_ids.insert(candidate.clone()) {
            break candidate;
        }
    };
    let suffix_chars = CONFLICT_SUFFIX.chars().count();
    let keep = 200_usize.saturating_sub(suffix_chars);
    let mut title: String = source.title.chars().take(keep).collect();
    title.push_str(CONFLICT_SUFFIX);
    let mut tags = source.tags.clone();
    if tags.len() < 20 && !tags.iter().any(|tag| tag == CONFLICT_TAG) {
        tags.push(CONFLICT_TAG.to_owned());
    }
    Ok(VaultEntry {
        id,
        title,
        username: source.username.clone(),
        password: source.password.clone(),
        url: source.url.clone(),
        purpose: source.purpose.clone(),
        notes: source.notes.clone(),
        tags,
        favorite: source.favorite,
        created_at: now,
        updated_at: now,
        password_updated_at: source.password_updated_at,
        revision: 1,
    })
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
    let atomic = AtomicFile::new(path, OverwriteBehavior::AllowOverwrite);
    atomic
        .write(|file| -> io::Result<()> {
            set_private_file_permissions(file)?;
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

    fn entry(id: &str, title: &str, password: &str, revision: u64) -> VaultEntry {
        VaultEntry {
            id: id.to_owned(),
            title: title.to_owned(),
            username: "alice".into(),
            password: password.into(),
            url: "https://example.com".into(),
            purpose: "test".into(),
            notes: String::new(),
            tags: vec!["test".into()],
            favorite: false,
            created_at: 1,
            updated_at: revision,
            password_updated_at: revision,
            revision,
        }
    }

    fn snapshot(
        sync_id: &str,
        sequence: u64,
        parent_hash: Option<String>,
        entries: Vec<VaultEntry>,
        tombstones: Vec<Tombstone>,
    ) -> SyncSnapshot {
        SyncSnapshot {
            protocol_version: SYNC_VERSION,
            sync_id: sync_id.to_owned(),
            sequence,
            parent_hash,
            device_id: Uuid::new_v4().to_string(),
            device_counter: sequence,
            created_at: sequence,
            entries,
            tombstones,
        }
    }

    #[test]
    fn recovery_code_round_trip_is_canonical() {
        let (material, code) = generate_recovery_material().unwrap();
        let parsed = parse_recovery_code(&code).unwrap();
        assert_eq!(parsed.sync_id, material.sync_id);
        assert_eq!(parsed.key.as_ref(), material.key.as_ref());
        assert_eq!(format_recovery_code(&parsed).unwrap(), code);
        assert!(parse_recovery_code(&format!(" {}", code.as_str())).is_err());
        assert!(parse_recovery_code("CN1.not-a-uuid.not-a-key").is_err());
    }

    #[test]
    fn endpoint_validation_is_https_and_credential_free() {
        assert!(validate_webdav_endpoint("https://dav.example.test/ciphernest/").is_ok());
        assert!(validate_webdav_endpoint("http://dav.example.test/ciphernest/").is_err());
        assert!(validate_webdav_endpoint("https://user:pass@dav.example.test/c/").is_err());
        assert!(validate_webdav_endpoint("https://dav.example.test/c/?token=x").is_err());
        assert!(validate_webdav_endpoint("https://dav.example.test/c/#fragment").is_err());
        assert!(validate_webdav_endpoint("https://dav.example.test/c").is_err());
        assert!(validate_webdav_endpoint("https://dav.example.test/a%2Fb/").is_err());
        assert!(WebDavClient::new(
            "https://dav.example.test/c/",
            "bad:name".into(),
            "password".into()
        )
        .is_err());
    }

    #[test]
    fn rejected_conditional_writes_must_leave_probe_and_etag_unchanged() {
        let expected = [7_u8; 32];
        let original = RemoteResource {
            bytes: expected.to_vec(),
            etag: Some("\"probe-v1\"".into()),
        };
        assert!(verify_rejected_probe_writes(Some(&original), &expected, "\"probe-v1\"").is_ok());
        assert!(matches!(
            verify_rejected_probe_writes(None, &expected, "\"probe-v1\""),
            Err(SyncError::UnsafeServer)
        ));

        let changed_body = RemoteResource {
            bytes: vec![8_u8; 32],
            etag: Some("\"probe-v1\"".into()),
        };
        assert!(matches!(
            verify_rejected_probe_writes(Some(&changed_body), &expected, "\"probe-v1\""),
            Err(SyncError::UnsafeServer)
        ));
        let changed_etag = RemoteResource {
            bytes: expected.to_vec(),
            etag: Some("\"probe-v2\"".into()),
        };
        assert!(matches!(
            verify_rejected_probe_writes(Some(&changed_etag), &expected, "\"probe-v1\""),
            Err(SyncError::UnsafeServer)
        ));
        let weak_etag = RemoteResource {
            bytes: expected.to_vec(),
            etag: Some("W/\"probe-v1\"".into()),
        };
        assert!(matches!(
            verify_rejected_probe_writes(Some(&weak_etag), &expected, "\"probe-v1\""),
            Err(SyncError::UnsafeServer)
        ));
    }

    #[test]
    fn synced_entry_address_is_plain_text_with_a_length_limit() {
        let id = Uuid::new_v4().to_string();
        for address in [
            "3389",
            "10.0.0.8:3389",
            "internal-host",
            "RDP 跳板机（仅限公司网络）",
            "https://example.com",
            "javascript:alert(1)",
        ] {
            let mut candidate = entry(&id, "Remote host", "secret", 1);
            candidate.url = address.into();
            assert!(
                validate_entry(&candidate).is_ok(),
                "address should remain valid after sync: {address}"
            );
        }

        let mut candidate = entry(&id, "Remote host", "secret", 1);
        candidate.url = "a".repeat(2049);
        assert!(matches!(
            validate_entry(&candidate),
            Err(SyncError::InvalidData)
        ));
    }

    #[test]
    fn propfind_requires_exact_dav_collection_and_success_status() {
        let endpoint = Url::parse("https://dav.example.test/vault/").unwrap();
        let valid = br#"<d:multistatus xmlns:d="DAV:"><d:response><d:href>/vault/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#;
        assert!(propfind_reports_collection(valid, &endpoint).unwrap());
        let wrong_href = valid
            .windows(b"/vault/".len())
            .position(|part| part == b"/vault/")
            .map(|position| {
                let mut bytes = valid.to_vec();
                bytes.splice(
                    position..position + b"/vault/".len(),
                    b"/other/".iter().copied(),
                );
                bytes
            })
            .unwrap();
        assert!(!propfind_reports_collection(&wrong_href, &endpoint).unwrap());
        let wrong_namespace = br#"<d:multistatus xmlns:d="urn:not-dav"><d:response><d:href>/vault/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#;
        assert!(!propfind_reports_collection(wrong_namespace, &endpoint).unwrap());
    }

    #[test]
    fn snapshot_tamper_and_wrong_hash_are_rejected() {
        let sync_id = Uuid::new_v4().to_string();
        let key = [7_u8; KEY_BYTES];
        let snapshot = snapshot(&sync_id, 1, None, vec![], vec![]);
        let (bytes, hash) = encode_snapshot(&snapshot, &key).unwrap();
        assert_eq!(
            decode_snapshot(&bytes, &sync_id, &key, &hash)
                .unwrap()
                .sequence,
            1
        );
        assert!(matches!(
            decode_snapshot(&bytes, &sync_id, &key, &"0".repeat(64)),
            Err(SyncError::HashMismatch)
        ));

        let mut envelope: EncryptedObject = serde_json::from_slice(&bytes).unwrap();
        let mut ciphertext = STANDARD_NO_PAD.decode(&envelope.ciphertext).unwrap();
        ciphertext[0] ^= 0x80;
        envelope.ciphertext = STANDARD_NO_PAD.encode(ciphertext);
        let tampered = serde_json::to_vec(&envelope).unwrap();
        let tampered_hash = sha256_hex(&tampered);
        assert!(matches!(
            decode_snapshot(&tampered, &sync_id, &key, &tampered_hash),
            Err(SyncError::InvalidRemoteObject)
        ));
    }

    #[test]
    fn local_state_sidecar_is_bound_to_vault_and_root_key() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.cnvault.sync");
        let vault_id = Uuid::new_v4().to_string();
        let sync_id = Uuid::new_v4().to_string();
        let device_id = Uuid::new_v4().to_string();
        let state = LocalSyncState {
            state_version: SYNC_VERSION,
            endpoint: "https://dav.example.test/ciphernest/".into(),
            username: "alice".into(),
            app_password: "app-specific-password".into(),
            sync_id,
            sync_root_key: [3_u8; KEY_BYTES],
            device_id,
            device_counter: 0,
            checkpoint_hash: None,
            base_snapshot: None,
            last_local_generation: 1,
            last_sync_at: None,
        };
        let root = [9_u8; KEY_BYTES];
        write_local_sync_state(&path, &vault_id, &root, &state).unwrap();
        let raw = fs::read(&path).unwrap();
        assert!(!raw
            .windows(state.app_password.len())
            .any(|window| { window == state.app_password.as_bytes() }));
        let mut loaded = read_local_sync_state(&path, &vault_id, &root).unwrap();
        assert_eq!(loaded.app_password, state.app_password);
        assert!(validate_local_generation(&loaded, 1).is_ok());
        loaded.last_local_generation = 2;
        assert!(matches!(
            validate_local_generation(&loaded, 1),
            Err(SyncError::LocalRollback)
        ));
        assert!(read_local_sync_state(&path, &Uuid::new_v4().to_string(), &root).is_err());
        assert!(read_local_sync_state(&path, &vault_id, &[8_u8; KEY_BYTES]).is_err());
    }

    #[test]
    fn merge_combines_changes_to_different_entries() {
        let sync_id = Uuid::new_v4().to_string();
        let first_id = Uuid::new_v4().to_string();
        let second_id = Uuid::new_v4().to_string();
        let first = entry(&first_id, "First", "old-one", 1);
        let second = entry(&second_id, "Second", "old-two", 1);
        let base = snapshot(
            &sync_id,
            1,
            None,
            vec![first.clone(), second.clone()],
            vec![],
        );
        let mut local_first = first;
        local_first.password = "local-one".into();
        local_first.revision = 2;
        local_first.updated_at = 2;
        let local = SyncContent {
            entries: vec![local_first, second.clone()],
            tombstones: vec![],
        };
        let mut remote_second = second;
        remote_second.password = "remote-two".into();
        remote_second.revision = 2;
        remote_second.updated_at = 2;
        let remote = snapshot(
            &sync_id,
            2,
            Some("1".repeat(64)),
            vec![base.entries[0].clone(), remote_second],
            vec![],
        );
        let merged = merge_three_way(&base, &local, &remote, 10).unwrap();
        assert!(merged.conflicts.is_empty());
        assert_eq!(merged.content.entries.len(), 2);
        assert!(merged
            .content
            .entries
            .iter()
            .any(|item| item.id == first_id && item.password == "local-one"));
        assert!(merged
            .content
            .entries
            .iter()
            .any(|item| item.id == second_id && item.password == "remote-two"));
    }

    #[test]
    fn merge_preserves_both_concurrent_password_edits() {
        let sync_id = Uuid::new_v4().to_string();
        let id = Uuid::new_v4().to_string();
        let original = entry(&id, "Account", "old-password", 1);
        let base = snapshot(&sync_id, 1, None, vec![original.clone()], vec![]);
        let mut local_entry = original.clone();
        local_entry.password = "local-password".into();
        local_entry.revision = 2;
        local_entry.updated_at = 2;
        let local = SyncContent {
            entries: vec![local_entry],
            tombstones: vec![],
        };
        let mut remote_entry = original;
        remote_entry.password = "remote-password".into();
        remote_entry.revision = 2;
        remote_entry.updated_at = 2;
        let remote = snapshot(
            &sync_id,
            2,
            Some("1".repeat(64)),
            vec![remote_entry],
            vec![],
        );
        let merged = merge_three_way(&base, &local, &remote, 10).unwrap();
        assert_eq!(merged.conflicts.len(), 1);
        assert_eq!(merged.content.entries.len(), 2);
        assert!(merged
            .content
            .entries
            .iter()
            .any(|item| item.id == id && item.password == "local-password"));
        assert!(merged.content.entries.iter().any(|item| {
            item.id != id
                && item.password == "remote-password"
                && item.title.ends_with(CONFLICT_SUFFIX)
                && item.tags.iter().any(|tag| tag == CONFLICT_TAG)
        }));
    }

    #[test]
    fn merge_rejects_missing_record_without_tombstone() {
        let sync_id = Uuid::new_v4().to_string();
        let id = Uuid::new_v4().to_string();
        let original = entry(&id, "Account", "must-not-disappear", 1);
        let base = snapshot(&sync_id, 1, None, vec![original.clone()], vec![]);
        let local = SyncContent {
            entries: vec![],
            tombstones: vec![],
        };
        let remote = snapshot(&sync_id, 2, Some("1".repeat(64)), vec![original], vec![]);
        assert!(matches!(
            merge_three_way(&base, &local, &remote, 10),
            Err(SyncError::InvalidData)
        ));
    }

    #[test]
    fn first_join_collision_preserves_both_passwords() {
        let sync_id = Uuid::new_v4().to_string();
        let id = Uuid::new_v4().to_string();
        let local = SyncContent {
            entries: vec![entry(&id, "Local", "local-password", 1)],
            tombstones: vec![],
        };
        let remote = snapshot(
            &sync_id,
            1,
            None,
            vec![entry(&id, "Remote", "remote-password", 1)],
            vec![],
        );
        let merged = merge_for_join(&local, &remote, 10).unwrap();
        assert_eq!(merged.content.entries.len(), 2);
        assert!(merged
            .content
            .entries
            .iter()
            .any(|item| item.password == "local-password"));
        assert!(merged
            .content
            .entries
            .iter()
            .any(|item| item.password == "remote-password"));
    }

    #[test]
    fn delete_vs_modify_keeps_tombstone_and_password_copy() {
        let sync_id = Uuid::new_v4().to_string();
        let id = Uuid::new_v4().to_string();
        let original = entry(&id, "Account", "old-password", 1);
        let base = snapshot(&sync_id, 1, None, vec![original.clone()], vec![]);
        let local = SyncContent {
            entries: vec![],
            tombstones: vec![Tombstone {
                id: id.clone(),
                revision: 2,
                deleted_at: 2,
            }],
        };
        let mut remote_entry = original;
        remote_entry.password = "remote-new-password".into();
        remote_entry.revision = 2;
        remote_entry.updated_at = 2;
        let remote = snapshot(
            &sync_id,
            2,
            Some("1".repeat(64)),
            vec![remote_entry],
            vec![],
        );
        let merged = merge_three_way(&base, &local, &remote, 10).unwrap();
        assert_eq!(merged.conflicts.len(), 1);
        assert_eq!(merged.content.tombstones.len(), 1);
        assert_eq!(merged.content.tombstones[0].id, id);
        assert_eq!(merged.content.entries.len(), 1);
        assert_ne!(merged.content.entries[0].id, id);
        assert_eq!(merged.content.entries[0].password, "remote-new-password");
    }

    #[test]
    fn checkpoint_chain_rejects_rollback_or_fork() {
        let sync_id = Uuid::new_v4().to_string();
        let genesis_hash = "a".repeat(64);
        let middle_hash = "b".repeat(64);
        let head_hash = "c".repeat(64);
        let genesis = FetchedSnapshot {
            hash: genesis_hash.clone(),
            snapshot: snapshot(&sync_id, 1, None, vec![], vec![]),
        };
        let middle = FetchedSnapshot {
            hash: middle_hash.clone(),
            snapshot: snapshot(&sync_id, 2, Some(genesis_hash.clone()), vec![], vec![]),
        };
        let head = FetchedSnapshot {
            hash: head_hash,
            snapshot: snapshot(&sync_id, 3, Some(middle_hash.clone()), vec![], vec![]),
        };
        let mut verifier = CheckpointVerifier::new(&head, &genesis_hash).unwrap();
        assert_eq!(verifier.required_parent_hash().unwrap(), middle_hash);
        verifier.accept_parent(&middle).unwrap();
        assert_eq!(verifier.required_parent_hash().unwrap(), genesis_hash);
        verifier.accept_parent(&genesis).unwrap();
        assert!(verifier.is_complete());

        let mut forked = FetchedSnapshot {
            hash: "c".repeat(64),
            snapshot: snapshot(&sync_id, 3, Some(middle_hash), vec![], vec![]),
        };
        forked.snapshot.parent_hash = Some("d".repeat(64));
        let mut verifier = CheckpointVerifier::new(&forked, &genesis_hash).unwrap();
        assert!(matches!(
            verifier.accept_parent(&middle),
            Err(SyncError::RollbackOrFork)
        ));
    }

    #[test]
    fn checkpoint_chain_accepts_exact_depth_limit() {
        let sync_id = Uuid::new_v4().to_string();
        let checkpoint = checkpoint_test_hash(1);
        let head = FetchedSnapshot {
            hash: checkpoint_test_hash(MAX_CHAIN_DEPTH),
            snapshot: snapshot(
                &sync_id,
                MAX_CHAIN_DEPTH as u64,
                Some(checkpoint_test_hash(MAX_CHAIN_DEPTH - 1)),
                vec![],
                vec![],
            ),
        };
        let mut verifier = CheckpointVerifier::new(&head, &checkpoint).unwrap();

        for sequence in (1..MAX_CHAIN_DEPTH).rev() {
            let hash = checkpoint_test_hash(sequence);
            assert_eq!(verifier.required_parent_hash().unwrap(), hash);
            let parent_hash = (sequence > 1).then(|| checkpoint_test_hash(sequence - 1));
            let parent = FetchedSnapshot {
                hash,
                snapshot: snapshot(&sync_id, sequence as u64, parent_hash, vec![], vec![]),
            };
            verifier.accept_parent(&parent).unwrap();
        }

        assert!(verifier.is_complete());
    }

    #[test]
    fn checkpoint_chain_rejects_one_past_depth_limit_before_fetch() {
        let sync_id = Uuid::new_v4().to_string();
        let checkpoint = checkpoint_test_hash(1);
        let head_sequence = MAX_CHAIN_DEPTH + 1;
        let head = FetchedSnapshot {
            hash: checkpoint_test_hash(head_sequence),
            snapshot: snapshot(
                &sync_id,
                head_sequence as u64,
                Some(checkpoint_test_hash(head_sequence - 1)),
                vec![],
                vec![],
            ),
        };
        let mut verifier = CheckpointVerifier::new(&head, &checkpoint).unwrap();

        for sequence in (2..head_sequence).rev() {
            let hash = checkpoint_test_hash(sequence);
            assert_eq!(verifier.required_parent_hash().unwrap(), hash);
            let parent = FetchedSnapshot {
                hash,
                snapshot: snapshot(
                    &sync_id,
                    sequence as u64,
                    Some(checkpoint_test_hash(sequence - 1)),
                    vec![],
                    vec![],
                ),
            };
            verifier.accept_parent(&parent).unwrap();
        }

        assert!(!verifier.is_complete());
        assert!(matches!(
            verifier.required_parent_hash(),
            Err(SyncError::ChainTooLong)
        ));
    }

    fn checkpoint_test_hash(value: usize) -> String {
        format!("{value:064x}")
    }
}
