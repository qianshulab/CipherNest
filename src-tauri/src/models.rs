use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const MAX_VAULT_ENTRIES: usize = 10_000;
pub const MAX_VAULT_TOMBSTONES: usize = 20_000;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct VaultEntry {
    pub id: String,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub purpose: String,
    pub notes: String,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub created_at: u64,
    pub updated_at: u64,
    pub password_updated_at: u64,
    pub revision: u64,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct EntryInput {
    pub id: Option<String>,
    pub expected_revision: Option<u64>,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub purpose: String,
    pub notes: String,
    pub tags: Vec<String>,
    pub favorite: bool,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntrySummary {
    pub id: String,
    pub revision: u64,
    pub title: String,
    pub favorite: bool,
    pub created_at: u64,
    pub updated_at: u64,
    pub password_updated_at: u64,
    pub security_flags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
#[serde(rename_all = "camelCase")]
pub struct VaultSettings {
    pub auto_lock_minutes: u32,
    pub clipboard_clear_seconds: u32,
    pub password_reveal_seconds: u32,
    pub lock_on_blur: bool,
}

impl Default for VaultSettings {
    fn default() -> Self {
        Self {
            auto_lock_minutes: 5,
            clipboard_clear_seconds: 20,
            password_reveal_seconds: 10,
            lock_on_blur: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
#[serde(rename_all = "camelCase")]
pub struct Tombstone {
    pub id: String,
    pub revision: u64,
    pub deleted_at: u64,
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VaultData {
    pub schema_version: u32,
    pub vault_id: String,
    pub generation: u64,
    pub created_at: u64,
    pub updated_at: u64,
    pub last_backup_at: Option<u64>,
    /// Missing on vaults created before password-only unlock became mandatory.
    /// The first successful master-password unlock rotates the vault root key
    /// before this flag is persisted, revoking any copied legacy device slot.
    #[serde(default)]
    pub password_only_unlock: bool,
    pub settings: VaultSettings,
    pub entries: Vec<VaultEntry>,
    pub tombstones: Vec<Tombstone>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultStatus {
    pub exists: bool,
    pub unlocked: bool,
    pub item_count: usize,
    pub auto_lock_minutes: u32,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultOverview {
    pub total_entries: usize,
    pub favorite_count: usize,
    pub security_issue_count: usize,
    pub sync_conflict_count: usize,
    pub last_backup_at: Option<u64>,
    pub auto_backup: AutoBackupStatus,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AutoBackupStatus {
    pub count: usize,
    pub latest_at: Option<u64>,
    pub current_covered: bool,
    pub inspection_failed: bool,
    pub warning: Option<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoreSelection {
    pub token: String,
    pub file_name: String,
    pub file_size: u64,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RestorePreview {
    pub file_name: String,
    pub item_count: usize,
    pub updated_at: u64,
    pub generation: u64,
    pub vault_id_short: String,
}

/// Public synchronization state. Credentials, the sync root key, device IDs,
/// and rollback checkpoints intentionally never cross the IPC boundary.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WebDavSyncStatus {
    pub configured: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sync_id_short: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_sync_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_sequence: Option<u64>,
    pub pending_local_changes: bool,
}

impl WebDavSyncStatus {
    pub fn not_configured() -> Self {
        Self {
            configured: false,
            endpoint_host: None,
            username: None,
            sync_id_short: None,
            last_sync_at: None,
            remote_sequence: None,
            pending_local_changes: false,
        }
    }
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WebDavCredentialsInput {
    pub endpoint: String,
    pub username: String,
    pub app_password: String,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WebDavInspectInput {
    pub credentials: WebDavCredentialsInput,
    pub recovery_code: String,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum WebDavJoinMode {
    Remote,
    Merge,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WebDavJoinInput {
    pub credentials: WebDavCredentialsInput,
    pub recovery_code: String,
    pub preview_token: String,
    #[zeroize(skip)]
    pub mode: WebDavJoinMode,
    #[serde(default)]
    pub confirm_replace: bool,
}

#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct WebDavCreateResult {
    #[zeroize(skip)]
    pub status: WebDavSyncStatus,
    pub recovery_code: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WebDavRemotePreview {
    pub preview_token: String,
    pub local_has_history: bool,
    pub item_count: usize,
    pub updated_at: u64,
    pub sequence: u64,
    pub sync_id_short: String,
    /// A new device has no previously trusted checkpoint from which it can
    /// prove freshness. This remains false during the join preview.
    pub checkpoint_trusted: bool,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum WebDavSyncOutcomeKind {
    UpToDate,
    Uploaded,
    Downloaded,
    Merged,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WebDavSyncOutcome {
    pub kind: WebDavSyncOutcomeKind,
    pub conflicts: usize,
    pub sequence: u64,
    pub status: WebDavSyncStatus,
}

#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct WebDavRecoveryCode {
    pub recovery_code: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MasterPasswordChangeResult {
    pub sync_config_preserved: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeneratorOptions {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub exclude_ambiguous: bool,
    pub require_each: bool,
}

#[derive(Clone, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct GeneratedPassword {
    pub password: String,
    pub entropy_bits: f64,
    pub pool_size: usize,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityIssue {
    pub entry_id: String,
    pub title: String,
    pub kind: String,
    pub message: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityReport {
    pub issues: Vec<SecurityIssue>,
    pub total_entries: usize,
    pub weak_count: usize,
    pub reused_count: usize,
    pub stale_count: usize,
}
