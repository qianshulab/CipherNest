use std::{
    cmp::Reverse,
    collections::{HashMap, HashSet},
    ffi::OsString,
    fs::{self, File},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use atomicwrites::{AtomicFile, DisallowOverwrite};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    crypto::{
        create_envelope, decrypt_envelope, parse_envelope_bytes, read_envelope, update_payload,
        write_envelope_atomic, VaultEnvelope, MAX_VAULT_BYTES,
    },
    error::{VaultError, VaultResult},
    models::{
        AutoBackupStatus, EntryInput, EntrySummary, MasterPasswordChangeResult, SecurityIssue,
        SecurityReport, Tombstone, VaultData, VaultEntry, VaultOverview, VaultSettings,
        VaultStatus, WebDavSyncStatus, MAX_VAULT_ENTRIES, MAX_VAULT_TOMBSTONES,
    },
    sync::{self, LocalSyncState, SyncContent, SyncError},
};

const AUTO_BACKUP_LIMIT: usize = 10;
const RESTORE_FINGERPRINT_MAX_BYTES: u64 = 1024 * 1024 * 1024;
const STALE_PASSWORD_MS: u64 = 365 * 24 * 60 * 60 * 1000;

struct UnlockedVault {
    root_key: Zeroizing<[u8; 32]>,
    data: VaultData,
    envelope: VaultEnvelope,
    session_id: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RestoreIntent {
    version: u8,
    source_digest: Option<[u8; 32]>,
    target_digest: [u8; 32],
    quarantine_id: String,
}

struct BackupInspection {
    len: u64,
    modified: SystemTime,
    digest: [u8; 32],
    vault_id: Option<String>,
}

pub(crate) struct NewSyncContext {
    pub vault_id: String,
    pub session_id: String,
    pub generation: u64,
    pub content: SyncContent,
}

pub(crate) struct ExistingSyncContext {
    pub vault_id: String,
    pub session_id: String,
    pub generation: u64,
    pub content: SyncContent,
    pub state: LocalSyncState,
    pub state_digest: [u8; 32],
}

pub struct VaultStore {
    vault_path: PathBuf,
    legacy_device_slots_path: PathBuf,
    legacy_device_auth_path: PathBuf,
    sync_state_path: PathBuf,
    sync_transition_path: PathBuf,
    sync_restore_hold_path: PathBuf,
    sync_restore_next_hold_path: PathBuf,
    restore_intent_path: PathBuf,
    unlocked: Option<UnlockedVault>,
    last_activity: Instant,
    failed_unlocks: u32,
    retry_after: Option<Instant>,
    auto_backup_warning: Option<String>,
    export_warning: Option<String>,
    backup_inspections: HashMap<PathBuf, BackupInspection>,
}

impl VaultStore {
    pub fn new(vault_path: PathBuf) -> Self {
        let legacy_device_slots_path = sidecar_path_for(&vault_path, ".devices");
        let legacy_device_auth_path = sidecar_path_for(&vault_path, ".device-auth");
        let sync_state_path = sidecar_path_for(&vault_path, ".sync");
        let sync_transition_path = sidecar_path_for(&vault_path, ".sync.next");
        let sync_restore_hold_path = sidecar_path_for(&vault_path, ".sync.restore-hold");
        let sync_restore_next_hold_path = sidecar_path_for(&vault_path, ".sync.next.restore-hold");
        let restore_intent_path = sidecar_path_for(&vault_path, ".restore-intent");
        Self {
            vault_path,
            legacy_device_slots_path,
            legacy_device_auth_path,
            sync_state_path,
            sync_transition_path,
            sync_restore_hold_path,
            sync_restore_next_hold_path,
            restore_intent_path,
            unlocked: None,
            last_activity: Instant::now(),
            failed_unlocks: 0,
            retry_after: None,
            auto_backup_warning: None,
            export_warning: None,
            backup_inspections: HashMap::new(),
        }
    }

    pub fn status(&mut self) -> (VaultStatus, bool) {
        let _ = self.recover_interrupted_restore();
        let just_locked = self.enforce_auto_lock();
        let (item_count, auto_lock_minutes) = self
            .unlocked
            .as_ref()
            .map(|vault| {
                (
                    vault.data.entries.len(),
                    vault.data.settings.auto_lock_minutes,
                )
            })
            .unwrap_or((0, VaultSettings::default().auto_lock_minutes));
        (
            VaultStatus {
                exists: self.vault_path.is_file()
                    || self.restore_intent_path.exists()
                    || self.sync_restore_hold_path.exists()
                    || self.sync_restore_next_hold_path.exists(),
                unlocked: self.unlocked.is_some(),
                item_count,
                auto_lock_minutes,
            },
            just_locked,
        )
    }

    pub fn create(&mut self, master_password: &str) -> VaultResult<VaultStatus> {
        self.recover_interrupted_restore()?;
        if self.vault_path.exists() || self.restore_intent_path.exists() {
            return Err(VaultError::AlreadyExists);
        }
        let now = now_ms();
        let data = VaultData {
            schema_version: 1,
            vault_id: Uuid::new_v4().to_string(),
            generation: 1,
            created_at: now,
            updated_at: now,
            last_backup_at: None,
            password_only_unlock: true,
            settings: VaultSettings::default(),
            entries: vec![],
            tombstones: vec![],
        };
        let (envelope, root_key) = create_envelope(master_password, &data)?;
        self.invalidate_legacy_device_slots()?;
        self.cleanup_legacy_device_auth_record();
        // A stale optional sync artifact must not prevent creating the local
        // vault. Make it inactive when possible; the fresh random root key also
        // makes any undeletable old sidecar cryptographically unusable.
        self.deactivate_sync_sidecars_best_effort();
        write_envelope_atomic(&self.vault_path, &envelope)?;
        self.unlocked = Some(UnlockedVault {
            root_key,
            data,
            envelope,
            session_id: Uuid::new_v4().to_string(),
        });
        self.failed_unlocks = 0;
        self.retry_after = None;
        self.last_activity = Instant::now();
        self.complete_current_auto_backup(None);
        Ok(self.status().0)
    }

    pub fn unlock(&mut self, master_password: &str) -> VaultResult<VaultStatus> {
        // A legacy interrupted restore can leave a hold without the newer
        // transaction marker. Keep the hold inactive, but still allow access
        // to an intact local vault so its data can be exported.
        if self.restore_intent_path.exists() {
            self.recover_interrupted_restore()?;
        }
        if !self.vault_path.is_file() {
            return Err(VaultError::NotFound);
        }
        self.wait_for_unlock_retry();

        let attempt = read_envelope(&self.vault_path)
            .map_err(|_| VaultError::UnlockFailed)
            .and_then(|envelope| {
                let (root_key, data) = decrypt_envelope(master_password, &envelope)?;
                validate_loaded_data(&data).map_err(|_| VaultError::UnlockFailed)?;
                Ok(UnlockedVault {
                    root_key,
                    data,
                    envelope,
                    session_id: Uuid::new_v4().to_string(),
                })
            });
        self.finish_unlock_attempt(attempt)?;

        let needs_password_only_migration = self
            .unlocked
            .as_ref()
            .is_some_and(|vault| !vault.data.password_only_unlock);
        if needs_password_only_migration
            && self
                .rotate_root_key(master_password, master_password)
                .is_err()
        {
            self.lock();
            return Err(VaultError::PasswordOnlyMigrationFailed);
        }
        self.cleanup_legacy_device_artifacts();
        // Reconcile a staged checkpoint before a later local edit can make
        // the crash boundary ambiguous. A damaged sync state does not prevent
        // unlocking the local vault for export or repair.
        let _ = self.load_sync_state();
        self.complete_current_auto_backup(None);
        Ok(self.status().0)
    }

    pub fn lock(&mut self) -> bool {
        self.retry_after = None;
        self.unlocked.take().is_some()
    }

    pub fn touch(&mut self) {
        if self.unlocked.is_some() {
            self.last_activity = Instant::now();
        }
    }

    pub fn handle_focus_change(&mut self, focused: bool) -> bool {
        if focused {
            if self.enforce_auto_lock() {
                return true;
            }
            self.touch();
            return false;
        }
        let should_lock = self
            .unlocked
            .as_ref()
            .is_some_and(|vault| vault.data.settings.lock_on_blur);
        if should_lock {
            self.lock()
        } else {
            false
        }
    }

    pub fn list_entries(
        &mut self,
        query: Option<&str>,
        filter: Option<&str>,
        sort: Option<&str>,
    ) -> VaultResult<Vec<EntrySummary>> {
        self.require_unlocked()?;
        self.touch();
        let vault = self.unlocked.as_ref().ok_or(VaultError::Locked)?;
        let password_counts = password_counts(&vault.data.entries);
        let normalized_query = query.unwrap_or_default().trim().to_lowercase();
        let filter = filter.unwrap_or("all");
        if !matches!(filter, "all" | "favorites") {
            return Err(VaultError::InvalidInput("筛选条件无效".into()));
        }

        let mut entries: Vec<EntrySummary> = vault
            .data
            .entries
            .iter()
            .filter(|entry| filter != "favorites" || entry.favorite)
            .filter(|entry| {
                normalized_query.is_empty() || searchable_text(entry).contains(&normalized_query)
            })
            .map(|entry| entry_summary(entry, &password_counts))
            .collect();

        match sort.unwrap_or("updated_desc") {
            "updated_desc" => entries.sort_by_key(|entry| Reverse(entry.updated_at)),
            "title_asc" => entries.sort_by(|a, b| {
                a.title
                    .to_lowercase()
                    .cmp(&b.title.to_lowercase())
                    .then_with(|| a.id.cmp(&b.id))
            }),
            "created_desc" => entries.sort_by_key(|entry| Reverse(entry.created_at)),
            _ => return Err(VaultError::InvalidInput("排序方式无效".into())),
        }
        Ok(entries)
    }

    pub fn overview(&mut self) -> VaultResult<VaultOverview> {
        self.require_unlocked()?;
        self.touch();
        let auto_backup = self.auto_backup_status();
        let vault = self.unlocked.as_ref().ok_or(VaultError::Locked)?;
        let password_counts = password_counts(&vault.data.entries);
        let security_issue_count = vault
            .data
            .entries
            .iter()
            .map(|entry| entry_summary(entry, &password_counts).security_flags.len())
            .sum();
        Ok(VaultOverview {
            total_entries: vault.data.entries.len(),
            favorite_count: vault
                .data
                .entries
                .iter()
                .filter(|entry| entry.favorite)
                .count(),
            security_issue_count,
            last_backup_at: vault.data.last_backup_at,
            auto_backup,
        })
    }

    pub fn get_entry(&mut self, id: &str) -> VaultResult<VaultEntry> {
        validate_id(id)?;
        self.require_unlocked()?;
        self.touch();
        self.unlocked
            .as_ref()
            .and_then(|vault| vault.data.entries.iter().find(|entry| entry.id == id))
            .cloned()
            .ok_or(VaultError::EntryNotFound)
    }

    pub fn save_entry(&mut self, mut input: EntryInput) -> VaultResult<EntrySummary> {
        validate_entry_input(&input)?;
        self.require_unlocked()?;
        let now = now_ms();
        let requested_id = input.id.take().map(|id| canonical_id(&id)).transpose()?;
        let expected_revision = input.expected_revision.take();
        let mut next_data = self
            .unlocked
            .as_ref()
            .ok_or(VaultError::Locked)?
            .data
            .clone();

        let saved_id = if let Some(expected_revision) = expected_revision {
            let id = requested_id
                .ok_or_else(|| VaultError::InvalidInput("更新条目时必须提供条目标识".into()))?;
            let entry = next_data
                .entries
                .iter_mut()
                .find(|entry| ids_refer_to_same_uuid(&entry.id, &id))
                .ok_or(VaultError::EntryNotFound)?;
            if entry.revision != expected_revision {
                return Err(VaultError::RevisionConflict);
            }
            let password = std::mem::take(&mut input.password);
            if entry.password != password {
                entry.password_updated_at = now;
            }
            entry.title = std::mem::take(&mut input.title);
            entry.username = std::mem::take(&mut input.username);
            entry.password = password;
            entry.url = std::mem::take(&mut input.url);
            entry.purpose = std::mem::take(&mut input.purpose);
            entry.notes = std::mem::take(&mut input.notes);
            entry.tags = normalize_tags(std::mem::take(&mut input.tags));
            entry.favorite = input.favorite;
            entry.updated_at = now;
            entry.revision = entry.revision.saturating_add(1);
            entry.id.clone()
        } else {
            if next_data.entries.len() >= MAX_VAULT_ENTRIES {
                return Err(VaultError::InvalidInput(format!(
                    "保险库最多可保存 {MAX_VAULT_ENTRIES} 个条目"
                )));
            }
            let id = requested_id.unwrap_or_else(|| Uuid::new_v4().to_string());
            if next_data
                .entries
                .iter()
                .any(|entry| ids_refer_to_same_uuid(&entry.id, &id))
                || next_data
                    .tombstones
                    .iter()
                    .any(|item| ids_refer_to_same_uuid(&item.id, &id))
            {
                return Err(VaultError::EntryAlreadyExists);
            }
            next_data.entries.push(VaultEntry {
                id: id.clone(),
                title: std::mem::take(&mut input.title),
                username: std::mem::take(&mut input.username),
                password: std::mem::take(&mut input.password),
                url: std::mem::take(&mut input.url),
                purpose: std::mem::take(&mut input.purpose),
                notes: std::mem::take(&mut input.notes),
                tags: normalize_tags(std::mem::take(&mut input.tags)),
                favorite: input.favorite,
                created_at: now,
                updated_at: now,
                password_updated_at: now,
                revision: 1,
            });
            id
        };

        bump_generation(&mut next_data, now);
        self.persist(next_data)?;
        self.touch();
        let vault = self.unlocked.as_ref().ok_or(VaultError::Locked)?;
        let counts = password_counts(&vault.data.entries);
        vault
            .data
            .entries
            .iter()
            .find(|entry| entry.id == saved_id)
            .map(|entry| entry_summary(entry, &counts))
            .ok_or(VaultError::EntryNotFound)
    }

    pub fn delete_entry(&mut self, id: &str, expected_revision: u64) -> VaultResult<()> {
        validate_id(id)?;
        self.require_unlocked()?;
        let mut next_data = self
            .unlocked
            .as_ref()
            .ok_or(VaultError::Locked)?
            .data
            .clone();
        let position = next_data
            .entries
            .iter()
            .position(|entry| entry.id == id)
            .ok_or(VaultError::EntryNotFound)?;
        if next_data.entries[position].revision != expected_revision {
            return Err(VaultError::RevisionConflict);
        }
        let removed = next_data.entries.remove(position);
        let now = now_ms();
        next_data.tombstones.retain(|item| item.id != id);
        if next_data.tombstones.len() >= MAX_VAULT_TOMBSTONES {
            return Err(VaultError::InvalidInput(format!(
                "保险库删除记录已达到 {MAX_VAULT_TOMBSTONES} 个上限；请先导出备份并迁移到新保险库"
            )));
        }
        next_data.tombstones.push(Tombstone {
            id: removed.id.clone(),
            revision: removed.revision.saturating_add(1),
            deleted_at: now,
        });
        drop(removed);
        bump_generation(&mut next_data, now);
        self.persist(next_data)?;
        self.touch();
        Ok(())
    }

    pub fn set_favorite(
        &mut self,
        id: &str,
        favorite: bool,
        expected_revision: u64,
    ) -> VaultResult<u64> {
        validate_id(id)?;
        self.require_unlocked()?;
        let mut next_data = self
            .unlocked
            .as_ref()
            .ok_or(VaultError::Locked)?
            .data
            .clone();
        let now = now_ms();
        let revision = {
            let entry = next_data
                .entries
                .iter_mut()
                .find(|entry| entry.id == id)
                .ok_or(VaultError::EntryNotFound)?;
            if entry.revision != expected_revision {
                return Err(VaultError::RevisionConflict);
            }
            entry.favorite = favorite;
            entry.updated_at = now;
            entry.revision = entry.revision.saturating_add(1);
            entry.revision
        };
        bump_generation(&mut next_data, now);
        self.persist(next_data)?;
        self.touch();
        Ok(revision)
    }

    pub fn settings(&mut self) -> VaultResult<VaultSettings> {
        self.require_unlocked()?;
        self.touch();
        self.unlocked
            .as_ref()
            .map(|vault| vault.data.settings.clone())
            .ok_or(VaultError::Locked)
    }

    pub fn update_settings(&mut self, settings: VaultSettings) -> VaultResult<()> {
        validate_settings(&settings)?;
        self.require_unlocked()?;
        let mut next_data = self
            .unlocked
            .as_ref()
            .ok_or(VaultError::Locked)?
            .data
            .clone();
        next_data.settings = settings;
        bump_generation(&mut next_data, now_ms());
        self.persist(next_data)?;
        self.touch();
        Ok(())
    }

    pub fn webdav_sync_status(&mut self) -> VaultResult<WebDavSyncStatus> {
        self.require_unlocked()?;
        let Some(state) = self.load_sync_state()? else {
            self.touch();
            return Ok(WebDavSyncStatus::not_configured());
        };
        let vault = self.unlocked.as_ref().ok_or(VaultError::Locked)?;
        validate_sync_generation_and_content(&state, &vault.data)?;
        let status = sync_status_for(&state, &vault.data)?;
        self.touch();
        Ok(status)
    }

    pub(crate) fn prepare_new_sync(&mut self) -> VaultResult<NewSyncContext> {
        self.require_unlocked()?;
        if self.load_sync_state()?.is_some() {
            return Err(VaultError::InvalidInput(
                "此设备已经配置 WebDAV 同步，请先停用现有配置。".into(),
            ));
        }
        let vault = self.unlocked.as_ref().ok_or(VaultError::Locked)?;
        let context = NewSyncContext {
            vault_id: vault.data.vault_id.clone(),
            session_id: vault.session_id.clone(),
            generation: vault.data.generation,
            content: sync_content_from(&vault.data),
        };
        self.touch();
        Ok(context)
    }

    pub(crate) fn prepare_existing_sync(&mut self) -> VaultResult<ExistingSyncContext> {
        self.require_unlocked()?;
        let state = self
            .load_sync_state()?
            .ok_or(VaultError::SyncNotConfigured)?;
        let vault = self.unlocked.as_ref().ok_or(VaultError::Locked)?;
        validate_sync_generation_and_content(&state, &vault.data)?;
        let context = ExistingSyncContext {
            vault_id: vault.data.vault_id.clone(),
            session_id: vault.session_id.clone(),
            generation: vault.data.generation,
            content: sync_content_from(&vault.data),
            state_digest: sync_state_digest(&state)?,
            state,
        };
        self.touch();
        Ok(context)
    }

    /// Installs a new configuration after remote creation. Local edits that
    /// happened during the network request are retained and become pending;
    /// an older/restored local generation is never accepted.
    pub(crate) fn install_new_sync_state(
        &mut self,
        expected_vault_id: &str,
        expected_session_id: &str,
        captured_generation: u64,
        state: &LocalSyncState,
    ) -> VaultResult<WebDavSyncStatus> {
        self.require_unlocked()?;
        if self.load_sync_state()?.is_some() {
            return Err(VaultError::SyncLocalChanged);
        }
        let vault = self.unlocked.as_ref().ok_or(VaultError::Locked)?;
        if vault.data.vault_id != expected_vault_id
            || vault.session_id != expected_session_id
            || vault.data.generation < captured_generation
        {
            return Err(VaultError::SyncLocalChanged);
        }
        if state.last_local_generation() != captured_generation {
            return Err(SyncError::InvalidLocalState.into());
        }
        sync::write_local_sync_state(
            &self.sync_state_path,
            &vault.data.vault_id,
            &vault.root_key,
            state,
        )?;
        let status = sync_status_for(state, &vault.data)?;
        self.touch();
        Ok(status)
    }

    pub(crate) fn install_joined_sync_state(
        &mut self,
        expected_vault_id: &str,
        expected_session_id: &str,
        expected_generation: u64,
        state: &LocalSyncState,
        content: SyncContent,
    ) -> VaultResult<WebDavSyncStatus> {
        self.require_unlocked()?;
        if self.load_sync_state()?.is_some() {
            return Err(VaultError::SyncLocalChanged);
        }
        let vault = self.unlocked.as_ref().ok_or(VaultError::Locked)?;
        if vault.data.vault_id != expected_vault_id
            || vault.session_id != expected_session_id
            || vault.data.generation != expected_generation
        {
            return Err(VaultError::SyncLocalChanged);
        }
        let target_generation = expected_generation
            .checked_add(1)
            .ok_or_else(|| VaultError::Sync("保险库版本已达到上限。".into()))?;
        if state.last_local_generation() != target_generation {
            return Err(SyncError::InvalidLocalState.into());
        }

        sync::write_local_sync_state(
            &self.sync_transition_path,
            &vault.data.vault_id,
            &vault.root_key,
            state,
        )?;
        let mut next_data = vault.data.clone();
        next_data.entries = content.entries.clone();
        next_data.tombstones = content.tombstones.clone();
        bump_generation(&mut next_data, now_ms());
        validate_loaded_data(&next_data)?;
        if let Err(error) = self.persist(next_data) {
            // The vault replacement may have reached disk even when its final
            // durability step reported an error. Keep the staged checkpoint
            // and force a fresh unlock to inspect the actual disk generation.
            self.lock();
            return Err(error);
        }
        let vault = self.unlocked.as_ref().ok_or(VaultError::Locked)?;
        sync::write_local_sync_state(
            &self.sync_state_path,
            &vault.data.vault_id,
            &vault.root_key,
            state,
        )?;
        let _ = sync::remove_local_sync_state(&self.sync_transition_path);
        let status = sync_status_for(state, &vault.data)?;
        self.touch();
        Ok(status)
    }

    /// Commits a network result only if neither the vault nor the encrypted
    /// sidecar changed since the operation began. Applying remote/merged
    /// content preserves all local-only settings and vault identity.
    pub(crate) fn commit_sync_result(
        &mut self,
        expected_vault_id: &str,
        expected_session_id: &str,
        expected_generation: u64,
        expected_state_digest: &[u8; 32],
        state: &LocalSyncState,
        content_to_apply: Option<SyncContent>,
    ) -> VaultResult<WebDavSyncStatus> {
        self.require_unlocked()?;
        let current_state = self
            .load_sync_state()?
            .ok_or(VaultError::SyncLocalChanged)?;
        if sync_state_digest(&current_state)? != *expected_state_digest {
            return Err(VaultError::SyncLocalChanged);
        }

        let vault = self.unlocked.as_ref().ok_or(VaultError::Locked)?;
        if vault.data.vault_id != expected_vault_id
            || vault.session_id != expected_session_id
            || vault.data.generation != expected_generation
        {
            return Err(VaultError::SyncLocalChanged);
        }

        let target_generation = if content_to_apply.is_some() {
            expected_generation
                .checked_add(1)
                .ok_or_else(|| VaultError::Sync("保险库版本已达到上限。".into()))?
        } else {
            expected_generation
        };
        if state.last_local_generation() != target_generation {
            return Err(SyncError::InvalidLocalState.into());
        }

        if let Some(content) = content_to_apply {
            // Stage the next sidecar before the vault write. It is not active
            // while the current sidecar decrypts; after a crash it is only used
            // as a recovery candidate when the active sidecar cannot decrypt.
            sync::write_local_sync_state(
                &self.sync_transition_path,
                &vault.data.vault_id,
                &vault.root_key,
                state,
            )?;
            let mut next_data = vault.data.clone();
            next_data.entries = content.entries.clone();
            next_data.tombstones = content.tombstones.clone();
            bump_generation(&mut next_data, now_ms());
            validate_loaded_data(&next_data)?;
            if let Err(error) = self.persist(next_data) {
                self.lock();
                return Err(error);
            }
        }

        let vault = self.unlocked.as_ref().ok_or(VaultError::Locked)?;
        sync::write_local_sync_state(
            &self.sync_state_path,
            &vault.data.vault_id,
            &vault.root_key,
            state,
        )?;
        let _ = sync::remove_local_sync_state(&self.sync_transition_path);
        let status = sync_status_for(state, &vault.data)?;
        self.touch();
        Ok(status)
    }

    pub fn webdav_recovery_code(
        &mut self,
        current_password: &str,
    ) -> VaultResult<Zeroizing<String>> {
        self.require_master_password(current_password)?;
        let state = self
            .load_sync_state()?
            .ok_or(VaultError::SyncNotConfigured)?;
        self.touch();
        state.recovery_code().map_err(Into::into)
    }

    pub fn disable_webdav_sync(&mut self, current_password: &str) -> VaultResult<()> {
        self.require_master_password(current_password)?;
        self.remove_all_sync_sidecars()?;
        self.touch();
        Ok(())
    }

    pub fn security_report(&mut self) -> VaultResult<SecurityReport> {
        self.require_unlocked()?;
        self.touch();
        let vault = self.unlocked.as_ref().ok_or(VaultError::Locked)?;
        let counts = password_counts(&vault.data.entries);
        let mut issues = Vec::new();
        let mut weak_count = 0;
        let mut reused_count = 0;
        let mut stale_count = 0;
        for entry in &vault.data.entries {
            if is_weak_password(&entry.password) {
                weak_count += 1;
                issues.push(SecurityIssue {
                    entry_id: entry.id.clone(),
                    title: entry.title.clone(),
                    kind: "weak".into(),
                    message: "密码长度或复杂度偏低，建议换成随机长密码。".into(),
                });
            }
            if password_use_count(&counts, &entry.password) > 1 {
                reused_count += 1;
                issues.push(SecurityIssue {
                    entry_id: entry.id.clone(),
                    title: entry.title.clone(),
                    kind: "reused".into(),
                    message: "该密码也用于其他条目。".into(),
                });
            }
            if now_ms().saturating_sub(entry.password_updated_at) > STALE_PASSWORD_MS {
                stale_count += 1;
                issues.push(SecurityIssue {
                    entry_id: entry.id.clone(),
                    title: entry.title.clone(),
                    kind: "stale".into(),
                    message: "该密码已超过一年未更新，请确认是否仍在使用。".into(),
                });
            }
        }
        Ok(SecurityReport {
            issues,
            total_entries: vault.data.entries.len(),
            weak_count,
            reused_count,
            stale_count,
        })
    }

    pub fn change_master_password(
        &mut self,
        current_password: &str,
        new_password: &str,
    ) -> VaultResult<MasterPasswordChangeResult> {
        self.rotate_root_key(current_password, new_password)
    }

    pub fn mark_manual_backup(&mut self) -> VaultResult<()> {
        self.require_unlocked()?;
        let mut next_data = self
            .unlocked
            .as_ref()
            .ok_or(VaultError::Locked)?
            .data
            .clone();
        let now = now_ms();
        next_data.last_backup_at = Some(now);
        bump_generation(&mut next_data, now);
        self.persist(next_data)
    }

    pub fn replace_with_verified_backup(
        &mut self,
        envelope: VaultEnvelope,
        root_key: Zeroizing<[u8; 32]>,
        data: VaultData,
    ) -> VaultResult<()> {
        validate_loaded_data(&data)?;
        if !data.password_only_unlock {
            return Err(VaultError::InvalidVault);
        }
        self.recover_interrupted_restore()?;
        let intent = self.begin_restore_intent(&envelope)?;
        // Move synchronization state out of its active names first. A failed
        // vault replacement restores it; a successful replacement leaves it
        // disabled, even if the process stops before cleanup.
        if let Err(error) = self.hold_sync_sidecars_for_restore() {
            let _ = self.recover_interrupted_restore();
            return Err(error);
        }
        let (quarantined, previous_backup) =
            match self.preserve_current_before_restore(&intent.quarantine_id) {
                Ok(preserved) => preserved,
                Err(error) => {
                    let _ = self.recover_interrupted_restore();
                    return Err(error);
                }
            };
        if let Err(error) = self.invalidate_legacy_device_slots() {
            self.rollback_quarantine(quarantined.as_deref());
            let _ = self.recover_interrupted_restore();
            return Err(error);
        }
        if let Err(error) = write_envelope_atomic(&self.vault_path, &envelope) {
            self.rollback_quarantine(quarantined.as_deref());
            self.lock();
            let _ = self.recover_interrupted_restore();
            return Err(error);
        }
        self.unlocked = Some(UnlockedVault {
            root_key,
            data,
            envelope,
            session_id: Uuid::new_v4().to_string(),
        });
        self.cleanup_legacy_device_auth_record();
        self.last_activity = Instant::now();
        self.failed_unlocks = 0;
        self.retry_after = None;
        let _ = self.recover_interrupted_restore();
        self.complete_current_auto_backup(previous_backup.as_deref());
        Ok(())
    }

    pub fn prepare_sensitive_action(&mut self) -> VaultResult<u32> {
        self.require_unlocked()?;
        self.touch();
        self.unlocked
            .as_ref()
            .map(|vault| vault.data.settings.clipboard_clear_seconds)
            .ok_or(VaultError::Locked)
    }

    pub fn export_to(&mut self, target: &Path) -> VaultResult<()> {
        self.require_unlocked()?;
        if paths_refer_to_same_file(&self.vault_path, target) {
            return Err(VaultError::InvalidInput(
                "备份位置不能覆盖当前保险库".into(),
            ));
        }
        let backup_directory = self
            .vault_path
            .parent()
            .ok_or(VaultError::SaveFailed)?
            .join("backups");
        if target
            .parent()
            .and_then(|parent| parent.canonicalize().ok())
            == backup_directory.canonicalize().ok()
            && backup_directory.is_dir()
        {
            return Err(VaultError::InvalidInput(
                "请将导出文件保存到自动备份目录以外的位置".into(),
            ));
        }
        let envelope = self.current_envelope()?;
        let bytes = serde_json::to_vec(&envelope).map_err(|_| VaultError::SaveFailed)?;
        write_private_exclusive(target, &bytes).map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                VaultError::InvalidInput("目标备份文件已存在，请选择其他文件名".into())
            } else {
                VaultError::SaveFailed
            }
        })?;
        self.export_warning = if self.mark_manual_backup().is_err() {
            Some("加密备份已导出，但上次导出时间未能记录。".into())
        } else {
            None
        };
        self.touch();
        Ok(())
    }

    fn require_unlocked(&mut self) -> VaultResult<()> {
        self.enforce_auto_lock();
        if self.unlocked.is_none() {
            Err(VaultError::Locked)
        } else {
            Ok(())
        }
    }

    fn require_master_password(&mut self, current_password: &str) -> VaultResult<()> {
        self.require_unlocked()?;
        let vault = self.unlocked.as_ref().ok_or(VaultError::Locked)?;
        decrypt_envelope(current_password, &vault.envelope)
            .map(|_| ())
            .map_err(|_| VaultError::UnlockFailed)
    }

    fn rotate_root_key(
        &mut self,
        current_password: &str,
        new_password: &str,
    ) -> VaultResult<MasterPasswordChangeResult> {
        self.require_unlocked()?;
        let mut next_data = {
            let vault = self.unlocked.as_ref().ok_or(VaultError::Locked)?;
            decrypt_envelope(current_password, &vault.envelope)
                .map_err(|_| VaultError::UnlockFailed)?;
            vault.data.clone()
        };

        // Once the master password has been proven, retire the only legacy file that can
        // connect a platform-held device key to this vault before attempting any fallible
        // migration I/O. A failed sync rewrap or backup must never leave that shortcut active.
        self.invalidate_legacy_device_slots()?;
        self.cleanup_legacy_device_auth_record();

        let (sync_state, invalid_sync_state) = match self.load_sync_state() {
            Ok(state) => (state, false),
            Err(VaultError::Sync(_)) if self.sync_artifacts_present() => (None, true),
            Err(error) => return Err(error),
        };
        next_data.password_only_unlock = true;
        bump_generation(&mut next_data, now_ms());
        let (next_envelope, next_root_key) = create_envelope(new_password, &next_data)?;
        let current_root_key = {
            let vault = self.unlocked.as_ref().ok_or(VaultError::Locked)?;
            Zeroizing::new(*vault.root_key)
        };

        // Prepare a new-key-encrypted recovery candidate before changing the
        // vault. The active sidecar remains untouched until the vault update is
        // durable. On a crash, load_sync_state selects whichever copy decrypts
        // under the root key of the actual vault on disk.
        if let Some(state) = sync_state.as_ref() {
            sync::write_local_sync_state(
                &self.sync_transition_path,
                &next_data.vault_id,
                &current_root_key,
                state,
            )?;
            sync::rewrap_local_sync_state(
                &self.sync_transition_path,
                &next_data.vault_id,
                &current_root_key,
                &next_root_key,
            )?;
        } else {
            let _ = sync::remove_local_sync_state(&self.sync_transition_path);
        }
        let previous_backup = self.backup_current()?;

        // Any reported write failure makes the unlock caller discard its in-memory session.
        // The next master-password unlock validates the actual disk state and retries when the
        // password-only marker is still absent. The legacy device slot was removed above.
        write_envelope_atomic(&self.vault_path, &next_envelope)?;
        let vault = self.unlocked.as_mut().ok_or(VaultError::Locked)?;
        vault.root_key = next_root_key;
        vault.data = next_data;
        vault.envelope = next_envelope;
        vault.session_id = Uuid::new_v4().to_string();

        let (sync_config_preserved, warning) = if invalid_sync_state {
            let deactivated = self.deactivate_sync_sidecars_best_effort();
            let warning = if deactivated {
                "主密码已经更改；检测到损坏的同步配置并已将其停用。请使用同步恢复码重新配置。"
            } else {
                "主密码已经更改；同步配置已损坏且部分旧文件无法清理。本机不会使用这些不可读配置，请检查应用数据目录后重新配置同步。"
            };
            (false, Some(warning.into()))
        } else if let Some(state) = sync_state.as_ref() {
            match sync::write_local_sync_state(
                &self.sync_state_path,
                &vault.data.vault_id,
                &vault.root_key,
                state,
            ) {
                Ok(()) => {
                    let _ = sync::remove_local_sync_state(&self.sync_transition_path);
                    (true, None)
                }
                Err(_) => (
                    true,
                    Some(
                        "主密码已经更改；同步配置保存在加密恢复副本中，将在下次读取时自动恢复。"
                            .into(),
                    ),
                ),
            }
        } else {
            (true, None)
        };
        self.complete_current_auto_backup(Some(&previous_backup));
        let warning = match (warning, self.auto_backup_warning.as_ref()) {
            (Some(sync_warning), Some(backup_warning)) => {
                Some(format!("{sync_warning} {backup_warning}"))
            }
            (None, Some(backup_warning)) => Some(backup_warning.clone()),
            (sync_warning, None) => sync_warning,
        };
        self.cleanup_legacy_device_auth_record();
        self.touch();
        Ok(MasterPasswordChangeResult {
            sync_config_preserved,
            warning,
        })
    }

    fn wait_for_unlock_retry(&self) {
        if let Some(retry_after) = self.retry_after {
            let now = Instant::now();
            if retry_after > now {
                std::thread::sleep(retry_after.duration_since(now));
            }
        }
    }

    fn finish_unlock_attempt(
        &mut self,
        attempt: VaultResult<UnlockedVault>,
    ) -> VaultResult<VaultStatus> {
        match attempt {
            Ok(unlocked) => {
                self.unlocked = Some(unlocked);
                self.failed_unlocks = 0;
                self.retry_after = None;
                self.last_activity = Instant::now();
                Ok(self.status().0)
            }
            Err(_) => {
                self.failed_unlocks = self.failed_unlocks.saturating_add(1);
                let delay = if self.failed_unlocks < 3 {
                    0
                } else {
                    2_u64
                        .saturating_pow((self.failed_unlocks - 3).min(5))
                        .min(30)
                };
                self.retry_after = Some(Instant::now() + Duration::from_secs(delay));
                Err(VaultError::UnlockFailed)
            }
        }
    }

    fn invalidate_legacy_device_slots(&self) -> VaultResult<()> {
        match fs::remove_file(&self.legacy_device_slots_path) {
            Ok(()) => {
                #[cfg(unix)]
                {
                    let parent = self
                        .legacy_device_slots_path
                        .parent()
                        .ok_or(VaultError::SaveFailed)?;
                    File::open(parent)
                        .and_then(|directory| directory.sync_all())
                        .map_err(|_| VaultError::SaveFailed)?;
                }
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(VaultError::SaveFailed),
        }
    }

    fn cleanup_legacy_device_auth_record(&self) {
        match fs::remove_file(&self.legacy_device_auth_path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {}
        }
    }

    fn cleanup_legacy_device_artifacts(&self) {
        let _ = self.invalidate_legacy_device_slots();
        self.cleanup_legacy_device_auth_record();
    }

    fn load_sync_state(&self) -> VaultResult<Option<LocalSyncState>> {
        self.recover_interrupted_restore()?;
        let vault = self.unlocked.as_ref().ok_or(VaultError::Locked)?;
        let vault_id = vault.data.vault_id.clone();
        let root_key = Zeroizing::new(*vault.root_key);
        let active = self
            .sync_state_path
            .exists()
            .then(|| sync::read_local_sync_state(&self.sync_state_path, &vault_id, &root_key));
        let staged = self
            .sync_transition_path
            .exists()
            .then(|| sync::read_local_sync_state(&self.sync_transition_path, &vault_id, &root_key));

        let promote = |state: LocalSyncState| -> VaultResult<Option<LocalSyncState>> {
            validate_sync_generation_and_content(&state, &vault.data)?;
            sync::write_local_sync_state(&self.sync_state_path, &vault_id, &root_key, &state)?;
            let _ = sync::remove_local_sync_state(&self.sync_transition_path);
            Ok(Some(state))
        };

        match (active, staged) {
            (None, None) => Ok(None),
            (Some(Ok(state)), None) => {
                validate_sync_generation_and_content(&state, &vault.data)?;
                Ok(Some(state))
            }
            (Some(Err(error)), None) => Err(error.into()),
            (None, Some(Ok(state))) | (Some(Err(_)), Some(Ok(state))) => promote(state),
            (None, Some(Err(error))) | (Some(Err(error)), Some(Err(_))) => Err(error.into()),
            (Some(Ok(active)), Some(Err(_))) => {
                validate_sync_generation_and_content(&active, &vault.data)?;
                Ok(Some(active))
            }
            (Some(Ok(active)), Some(Ok(staged))) => {
                let active_valid = validate_sync_generation_and_content(&active, &vault.data);
                let staged_valid = validate_sync_generation_and_content(&staged, &vault.data);
                if active_valid.is_ok()
                    && staged_valid.is_ok()
                    && (active.sync_id() != staged.sync_id()
                        || active.endpoint() != staged.endpoint()
                        || active.username() != staged.username())
                {
                    return Err(SyncError::InvalidLocalState.into());
                }
                if staged_valid.is_ok()
                    && staged.last_local_generation() == vault.data.generation
                    && active.last_local_generation() < staged.last_local_generation()
                {
                    return promote(staged);
                }
                active_valid?;
                if staged.last_local_generation() > active.last_local_generation()
                    && staged.last_local_generation() < vault.data.generation
                {
                    // A later local edit makes it impossible to prove whether
                    // the staged remote content was ever installed.
                    return Err(SyncError::InvalidLocalState.into());
                }
                if staged.last_local_generation() == active.last_local_generation()
                    && staged_valid.is_ok()
                    && sync_state_digest(&staged)? != sync_state_digest(&active)?
                {
                    return Err(SyncError::InvalidLocalState.into());
                }
                if staged.last_local_generation() <= active.last_local_generation()
                    || staged.last_local_generation() > vault.data.generation
                {
                    let _ = sync::remove_local_sync_state(&self.sync_transition_path);
                }
                Ok(Some(active))
            }
        }
    }

    fn remove_all_sync_sidecars(&self) -> VaultResult<()> {
        let mut failed = false;
        for path in [
            &self.sync_state_path,
            &self.sync_transition_path,
            &self.sync_restore_hold_path,
            &self.sync_restore_next_hold_path,
        ] {
            if sync::remove_local_sync_state(path).is_err() {
                failed = true;
            }
        }
        if failed {
            Err(SyncError::LocalStateIo.into())
        } else {
            Ok(())
        }
    }

    fn sync_artifacts_present(&self) -> bool {
        [
            &self.sync_state_path,
            &self.sync_transition_path,
            &self.sync_restore_hold_path,
            &self.sync_restore_next_hold_path,
        ]
        .into_iter()
        .any(|path| path.exists())
    }

    /// Makes every known synchronization artifact inactive without ever
    /// reporting the already-completed root-key rotation as a failure.
    fn deactivate_sync_sidecars_best_effort(&self) -> bool {
        let mut all_inactive = true;
        for path in [
            &self.sync_state_path,
            &self.sync_transition_path,
            &self.sync_restore_hold_path,
            &self.sync_restore_next_hold_path,
        ] {
            if !path.exists() || sync::remove_local_sync_state(path).is_ok() {
                continue;
            }
            let mut inactive_name = OsString::from(path.as_os_str());
            inactive_name.push(format!(".disabled-{}", Uuid::new_v4()));
            if fs::rename(path, PathBuf::from(inactive_name)).is_err() {
                all_inactive = false;
            }
        }
        all_inactive
    }

    fn hold_sync_sidecars_for_restore(&self) -> VaultResult<()> {
        if self.sync_restore_hold_path.exists() || self.sync_restore_next_hold_path.exists() {
            return Err(SyncError::LocalStateIo.into());
        }

        if self.sync_state_path.exists() {
            fs::rename(&self.sync_state_path, &self.sync_restore_hold_path)
                .map_err(|_| VaultError::SaveFailed)?;
        }
        if self.sync_transition_path.exists()
            && fs::rename(
                &self.sync_transition_path,
                &self.sync_restore_next_hold_path,
            )
            .is_err()
        {
            self.rollback_held_sync_sidecars();
            return Err(VaultError::SaveFailed);
        }
        Ok(())
    }

    fn rollback_held_sync_sidecars(&self) {
        if !self.sync_state_path.exists() && self.sync_restore_hold_path.exists() {
            let _ = fs::rename(&self.sync_restore_hold_path, &self.sync_state_path);
        }
        if !self.sync_transition_path.exists() && self.sync_restore_next_hold_path.exists() {
            let _ = fs::rename(
                &self.sync_restore_next_hold_path,
                &self.sync_transition_path,
            );
        }
    }

    fn begin_restore_intent(&self, envelope: &VaultEnvelope) -> VaultResult<RestoreIntent> {
        if self.restore_intent_path.exists() {
            return Err(VaultError::SaveFailed);
        }
        let source_digest = self.restore_target_fingerprint()?;
        let target_bytes = serde_json::to_vec(envelope).map_err(|_| VaultError::SaveFailed)?;
        let target_digest = Sha256::digest(&target_bytes).into();
        if source_digest == Some(target_digest) {
            return Err(VaultError::InvalidInput(
                "所选备份与当前保险库相同，无需恢复".into(),
            ));
        }
        let intent = RestoreIntent {
            version: 1,
            source_digest,
            target_digest,
            quarantine_id: Uuid::new_v4().to_string(),
        };
        let bytes = serde_json::to_vec(&intent).map_err(|_| VaultError::SaveFailed)?;
        write_private_exclusive(&self.restore_intent_path, &bytes)
            .map_err(|_| VaultError::SaveFailed)?;
        Ok(intent)
    }

    fn restore_quarantine_path(&self, quarantine_id: &str) -> VaultResult<PathBuf> {
        let id = Uuid::parse_str(quarantine_id).map_err(|_| VaultError::SaveFailed)?;
        if id.to_string() != quarantine_id {
            return Err(VaultError::SaveFailed);
        }
        let parent = self.vault_path.parent().ok_or(VaultError::SaveFailed)?;
        Ok(parent
            .join("quarantine")
            .join(format!("invalid-{quarantine_id}.cnvault")))
    }

    fn recover_interrupted_restore(&self) -> VaultResult<()> {
        self.try_recover_interrupted_restore()
            .map_err(|_| VaultError::RestoreRecoveryFailed)
    }

    fn try_recover_interrupted_restore(&self) -> VaultResult<()> {
        if !self.restore_intent_path.exists() {
            if self.sync_restore_hold_path.exists() || self.sync_restore_next_hold_path.exists() {
                return Err(SyncError::LocalStateIo.into());
            }
            return Ok(());
        }
        let mut bytes = Vec::new();
        File::open(&self.restore_intent_path)
            .and_then(|file| file.take(4097).read_to_end(&mut bytes))
            .map_err(|_| VaultError::SaveFailed)?;
        if bytes.is_empty() || bytes.len() > 4096 {
            return Err(VaultError::SaveFailed);
        }
        let intent: RestoreIntent =
            serde_json::from_slice(&bytes).map_err(|_| VaultError::SaveFailed)?;
        if intent.version != 1 || intent.source_digest == Some(intent.target_digest) {
            return Err(VaultError::SaveFailed);
        }
        let quarantine_path = self.restore_quarantine_path(&intent.quarantine_id)?;
        let current_digest = self.restore_target_fingerprint()?;
        if current_digest == Some(intent.target_digest) {
            if self.sync_state_path.exists() || self.sync_transition_path.exists() {
                return Err(SyncError::LocalStateIo.into());
            }
            sync::remove_local_sync_state(&self.sync_restore_hold_path)?;
            sync::remove_local_sync_state(&self.sync_restore_next_hold_path)?;
        } else if current_digest == intent.source_digest {
            if (self.sync_state_path.exists() && self.sync_restore_hold_path.exists())
                || (self.sync_transition_path.exists() && self.sync_restore_next_hold_path.exists())
            {
                return Err(SyncError::LocalStateIo.into());
            }
            self.rollback_held_sync_sidecars();
            if self.sync_restore_hold_path.exists() || self.sync_restore_next_hold_path.exists() {
                return Err(SyncError::LocalStateIo.into());
            }
        } else if current_digest.is_none() && intent.source_digest.is_some() {
            if fingerprint_file(&quarantine_path)? != intent.source_digest {
                return Err(VaultError::SaveFailed);
            }
            fs::rename(&quarantine_path, &self.vault_path).map_err(|_| VaultError::SaveFailed)?;
            self.rollback_held_sync_sidecars();
            if self.sync_restore_hold_path.exists() || self.sync_restore_next_hold_path.exists() {
                return Err(SyncError::LocalStateIo.into());
            }
        } else {
            return Err(VaultError::SaveFailed);
        }
        sync::remove_local_sync_state(&self.restore_intent_path)?;
        Ok(())
    }

    fn enforce_auto_lock(&mut self) -> bool {
        let should_lock = self.unlocked.as_ref().is_some_and(|vault| {
            self.last_activity.elapsed()
                >= Duration::from_secs(vault.data.settings.auto_lock_minutes as u64 * 60)
        });
        if should_lock {
            self.lock();
            true
        } else {
            false
        }
    }

    fn persist(&mut self, data: VaultData) -> VaultResult<()> {
        validate_loaded_data(&data)?;
        let next_envelope = {
            let unlocked = self.unlocked.as_ref().ok_or(VaultError::Locked)?;
            update_payload(&unlocked.envelope, &unlocked.root_key, &data)?
        };
        let previous_backup = self.backup_current()?;
        write_envelope_atomic(&self.vault_path, &next_envelope)?;
        let unlocked = self.unlocked.as_mut().ok_or(VaultError::Locked)?;
        unlocked.data = data;
        unlocked.envelope = next_envelope;
        // The active vault is already committed. A failure to write the extra
        // snapshot must be reported separately, never as a failed user edit.
        self.complete_current_auto_backup(Some(&previous_backup));
        Ok(())
    }

    fn complete_current_auto_backup(&mut self, previous_backup: Option<&Path>) {
        self.auto_backup_warning = self
            .current_envelope()
            .and_then(|envelope| self.backup_envelope_with_protection(&envelope, previous_backup))
            .err()
            .map(|_| {
                "保险库数据已保存，但当前版本的自动备份未完成。请检查磁盘空间和备份目录权限。"
                    .into()
            });
    }

    fn auto_backup_status(&mut self) -> AutoBackupStatus {
        let mut status = AutoBackupStatus {
            count: 0,
            latest_at: None,
            current_covered: false,
            inspection_failed: false,
            warning: None,
        };
        let Some(vault) = self.unlocked.as_ref() else {
            return status;
        };
        let mut warnings = Vec::new();
        if let Some(warning) = self.auto_backup_warning.as_ref() {
            warnings.push(warning.clone());
        }
        if let Some(warning) = self.export_warning.as_ref() {
            warnings.push(warning.clone());
        }
        let disk_matches_session = self.current_envelope().is_ok();
        if !disk_matches_session {
            status.inspection_failed = true;
            warnings.push("当前保险库文件已变化，无法确认自动备份是否覆盖当前版本。".into());
        }
        let vault_id = vault.data.vault_id.clone();
        let expected_bytes = match serde_json::to_vec(&vault.envelope) {
            Ok(bytes) => bytes,
            Err(_) => {
                status.inspection_failed = true;
                warnings.push("无法检查自动备份状态。".into());
                status.warning = Some(warnings.join(" "));
                return status;
            }
        };
        let Some(parent) = self.vault_path.parent() else {
            status.inspection_failed = true;
            warnings.push("无法检查自动备份目录。".into());
            status.warning = Some(warnings.join(" "));
            return status;
        };
        let directory = parent.join("backups");
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                warnings.push("当前版本尚无自动备份。".into());
                status.warning = Some(warnings.join(" "));
                return status;
            }
            Err(_) => {
                status.inspection_failed = true;
                warnings.push("无法检查自动备份目录。".into());
                status.warning = Some(warnings.join(" "));
                return status;
            }
        };
        let expected_digest: [u8; 32] = Sha256::digest(&expected_bytes).into();
        let prefix = format!("auto-{vault_id}-");
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => {
                    status.inspection_failed = true;
                    continue;
                }
            };
            let file_name = entry.file_name();
            let Some(name) = file_name.to_str() else {
                continue;
            };
            if !name.starts_with(&prefix) || !name.ends_with(".cnvault") {
                continue;
            }
            let metadata = match fs::symlink_metadata(entry.path()) {
                Ok(metadata)
                    if metadata.file_type().is_file() && metadata.len() <= MAX_VAULT_BYTES =>
                {
                    metadata
                }
                _ => {
                    status.inspection_failed = true;
                    continue;
                }
            };
            let modified = match metadata.modified() {
                Ok(modified) => modified,
                Err(_) => {
                    status.inspection_failed = true;
                    continue;
                }
            };
            let path = entry.path();
            let inspection = self
                .backup_inspections
                .get(&path)
                .filter(|cached| cached.len == metadata.len() && cached.modified == modified);
            let (digest, recorded_vault_id) = if let Some(cached) = inspection {
                (cached.digest, cached.vault_id.clone())
            } else {
                let mut bytes = Vec::with_capacity(metadata.len() as usize);
                let read = File::open(&path)
                    .and_then(|file| file.take(MAX_VAULT_BYTES + 1).read_to_end(&mut bytes));
                if read.is_err() || bytes.is_empty() || bytes.len() as u64 > MAX_VAULT_BYTES {
                    status.inspection_failed = true;
                    continue;
                }
                let digest = Sha256::digest(&bytes).into();
                let recorded_vault_id = parse_envelope_bytes(&bytes)
                    .ok()
                    .map(|envelope| envelope.vault_id);
                if self.backup_inspections.len() >= 256 {
                    self.backup_inspections.clear();
                }
                self.backup_inspections.insert(
                    path,
                    BackupInspection {
                        len: metadata.len(),
                        modified,
                        digest,
                        vault_id: recorded_vault_id.clone(),
                    },
                );
                (digest, recorded_vault_id)
            };
            if recorded_vault_id.as_deref() != Some(vault_id.as_str()) {
                status.inspection_failed = true;
                continue;
            }
            status.count += 1;
            if let Ok(duration) = modified.duration_since(UNIX_EPOCH) {
                let timestamp = duration.as_millis().try_into().unwrap_or(u64::MAX);
                status.latest_at = Some(status.latest_at.unwrap_or(0).max(timestamp));
            } else {
                status.inspection_failed = true;
            }
            if disk_matches_session
                && digest == expected_digest
                && metadata.len() == expected_bytes.len() as u64
            {
                status.current_covered = true;
            }
        }
        if status.inspection_failed {
            warnings.push("部分自动备份无法检查，备份状态可能不完整。".into());
        }
        if !status.current_covered && !status.inspection_failed {
            warnings.push("当前版本尚无自动备份。".into());
        }
        if !warnings.is_empty() {
            status.warning = Some(warnings.join(" "));
        }
        status
    }

    fn backup_current(&self) -> VaultResult<PathBuf> {
        let current = self.current_envelope()?;
        self.backup_envelope(&current)
    }

    /// A live session must never overwrite a vault that another process or a
    /// manual file restore changed after unlock. The encrypted envelope is
    /// compared in full so even a rewrite at the same generation is caught.
    fn current_envelope(&self) -> VaultResult<VaultEnvelope> {
        let unlocked = self.unlocked.as_ref().ok_or(VaultError::Locked)?;
        let current =
            read_envelope(&self.vault_path).map_err(|_| VaultError::VaultChangedOnDisk)?;
        if current != unlocked.envelope {
            return Err(VaultError::VaultChangedOnDisk);
        }
        Ok(current)
    }

    pub(crate) fn restore_target_fingerprint(&self) -> VaultResult<Option<[u8; 32]>> {
        fingerprint_file(&self.vault_path)
    }

    fn backup_envelope(&self, current: &VaultEnvelope) -> VaultResult<PathBuf> {
        self.backup_envelope_with_protection(current, None)
    }

    fn backup_envelope_with_protection(
        &self,
        current: &VaultEnvelope,
        previous_backup: Option<&Path>,
    ) -> VaultResult<PathBuf> {
        let parent = self.vault_path.parent().ok_or(VaultError::SaveFailed)?;
        let backup_directory = parent.join("backups");
        fs::create_dir_all(&backup_directory).map_err(|_| VaultError::SaveFailed)?;
        set_private_directory_permissions(&backup_directory)?;
        let canonical_bytes = serde_json::to_vec(current).map_err(|_| VaultError::SaveFailed)?;
        if canonical_bytes.is_empty() || canonical_bytes.len() as u64 > MAX_VAULT_BYTES {
            return Err(VaultError::SaveFailed);
        }

        let primary_path = backup_directory.join(automatic_backup_name(current)?);
        let content_hash = hex_sha256(&canonical_bytes);
        for attempt in 0..32 {
            let backup_path = if attempt == 0 {
                primary_path.clone()
            } else {
                backup_directory.join(automatic_backup_collision_name(
                    current,
                    &content_hash,
                    (attempt > 1).then(|| Uuid::new_v4().to_string()).as_deref(),
                )?)
            };
            if backup_path.exists() {
                if backup_file_matches(&backup_path, &canonical_bytes)? {
                    rotate_backups(
                        &backup_directory,
                        &current.vault_id,
                        &backup_path,
                        previous_backup,
                    )?;
                    return Ok(backup_path);
                }
                continue;
            }
            match write_private_exclusive(&backup_path, &canonical_bytes) {
                Ok(()) => {
                    rotate_backups(
                        &backup_directory,
                        &current.vault_id,
                        &backup_path,
                        previous_backup,
                    )?;
                    return Ok(backup_path);
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    if backup_file_matches(&backup_path, &canonical_bytes)? {
                        rotate_backups(
                            &backup_directory,
                            &current.vault_id,
                            &backup_path,
                            previous_backup,
                        )?;
                        return Ok(backup_path);
                    }
                }
                Err(_) => return Err(VaultError::SaveFailed),
            }
        }
        Err(VaultError::SaveFailed)
    }

    fn preserve_current_before_restore(
        &self,
        quarantine_id: &str,
    ) -> VaultResult<(Option<PathBuf>, Option<PathBuf>)> {
        if !self.vault_path.exists() {
            return Ok((None, None));
        }
        if !self.vault_path.is_file() {
            return Err(VaultError::SaveFailed);
        }

        match read_envelope(&self.vault_path) {
            Ok(current) if Uuid::parse_str(&current.vault_id).is_ok() => {
                let backup_path = self.backup_envelope(&current)?;
                Ok((None, Some(backup_path)))
            }
            Ok(_) | Err(_) => self
                .quarantine_invalid_current(quarantine_id)
                .map(|path| (Some(path), None)),
        }
    }

    fn quarantine_invalid_current(&self, quarantine_id: &str) -> VaultResult<PathBuf> {
        let quarantine_path = self.restore_quarantine_path(quarantine_id)?;
        let quarantine_directory = quarantine_path.parent().ok_or(VaultError::SaveFailed)?;
        let parent = self.vault_path.parent().ok_or(VaultError::SaveFailed)?;
        fs::create_dir_all(quarantine_directory).map_err(|_| VaultError::SaveFailed)?;
        set_private_directory_permissions(quarantine_directory)?;
        if quarantine_path.exists() {
            return Err(VaultError::SaveFailed);
        }
        fs::rename(&self.vault_path, &quarantine_path).map_err(|_| VaultError::SaveFailed)?;
        if let Err(error) = secure_quarantined_file(&quarantine_path, parent, quarantine_directory)
        {
            let _ = fs::rename(&quarantine_path, &self.vault_path);
            return Err(error);
        }
        Ok(quarantine_path)
    }

    fn rollback_quarantine(&self, quarantined: Option<&Path>) {
        let Some(quarantined) = quarantined else {
            return;
        };
        if !self.vault_path.exists() {
            let _ = fs::rename(quarantined, &self.vault_path);
        }
    }
}

fn fingerprint_file(path: &Path) -> VaultResult<Option<[u8; 32]>> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(VaultError::SaveFailed),
    };
    let metadata = file.metadata().map_err(|_| VaultError::SaveFailed)?;
    if !metadata.is_file() || metadata.len() > RESTORE_FINGERPRINT_MAX_BYTES {
        return Err(VaultError::InvalidInput(
            "当前保险库文件过大或类型无效，无法安全核对恢复目标".into(),
        ));
    }
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let read = file.read(&mut buffer).map_err(|_| VaultError::SaveFailed)?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        if total > RESTORE_FINGERPRINT_MAX_BYTES {
            return Err(VaultError::InvalidInput(
                "当前保险库文件过大，无法安全核对恢复目标".into(),
            ));
        }
        digest.update(&buffer[..read]);
    }
    Ok(Some(digest.finalize().into()))
}

fn bump_generation(data: &mut VaultData, now: u64) {
    data.generation = data.generation.saturating_add(1);
    data.updated_at = now;
}

fn rotate_backups(
    directory: &Path,
    vault_id: &str,
    current_backup: &Path,
    previous_backup: Option<&Path>,
) -> VaultResult<()> {
    let prefix = format!("auto-{vault_id}-");
    let mut backups: Vec<(SystemTime, PathBuf)> = Vec::new();
    for entry in fs::read_dir(directory).map_err(|_| VaultError::SaveFailed)? {
        let entry = entry.map_err(|_| VaultError::SaveFailed)?;
        let path = entry.path();
        let belongs_to_vault = path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with(&prefix) && name.ends_with(".cnvault"));
        if !belongs_to_vault {
            continue;
        }
        let metadata = fs::symlink_metadata(&path).map_err(|_| VaultError::SaveFailed)?;
        if metadata.file_type().is_file() {
            backups.push((metadata.modified().unwrap_or(UNIX_EPOCH), path));
        }
    }
    backups.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    let remove_count = backups.len().saturating_sub(AUTO_BACKUP_LIMIT);
    // Protect both the committed version and the immediate rollback version,
    // even when their timestamps are older than unrelated snapshots.
    for (_, path) in backups
        .into_iter()
        .filter(|(_, path)| path != current_backup && previous_backup != Some(path.as_path()))
        .take(remove_count)
    {
        fs::remove_file(path).map_err(|_| VaultError::SaveFailed)?;
    }
    Ok(())
}

fn automatic_backup_name(envelope: &VaultEnvelope) -> VaultResult<String> {
    let vault_id = Uuid::parse_str(&envelope.vault_id)
        .map_err(|_| VaultError::InvalidVault)?
        .to_string();
    Ok(format!(
        "auto-{vault_id}-{:020}.cnvault",
        envelope.generation
    ))
}

fn automatic_backup_collision_name(
    envelope: &VaultEnvelope,
    content_hash: &str,
    unique_suffix: Option<&str>,
) -> VaultResult<String> {
    let vault_id = Uuid::parse_str(&envelope.vault_id)
        .map_err(|_| VaultError::InvalidVault)?
        .to_string();
    if content_hash.len() != 64 || !content_hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(VaultError::SaveFailed);
    }
    let suffix = unique_suffix
        .map(|value| format!("-{value}"))
        .unwrap_or_default();
    Ok(format!(
        "auto-{vault_id}-{:020}-{content_hash}{suffix}.cnvault",
        envelope.generation
    ))
}

fn backup_file_matches(path: &Path, expected: &[u8]) -> VaultResult<bool> {
    let metadata = fs::symlink_metadata(path).map_err(|_| VaultError::SaveFailed)?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_VAULT_BYTES {
        return Ok(false);
    }
    let file = File::open(path).map_err(|_| VaultError::SaveFailed)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_VAULT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| VaultError::SaveFailed)?;
    if bytes.len() as u64 > MAX_VAULT_BYTES {
        return Ok(false);
    }
    Ok(bytes == expected)
}

fn hex_sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn write_private_exclusive(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_VAULT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid encrypted vault size",
        ));
    }
    AtomicFile::new(path, DisallowOverwrite)
        .write(|file| -> io::Result<()> {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                file.set_permissions(fs::Permissions::from_mode(0o600))?;
            }
            file.write_all(bytes)?;
            file.sync_all()
        })
        .map_err(Into::into)
}

fn set_private_directory_permissions(path: &Path) -> VaultResult<()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| VaultError::SaveFailed)?;
    if !metadata.file_type().is_dir() {
        return Err(VaultError::SaveFailed);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|_| VaultError::SaveFailed)?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn secure_quarantined_file(path: &Path, parent: &Path, directory: &Path) -> VaultResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{FileTypeExt, PermissionsExt};

        let metadata = fs::symlink_metadata(path).map_err(|_| VaultError::SaveFailed)?;
        if metadata.file_type().is_file() && !metadata.file_type().is_symlink() {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .map_err(|_| VaultError::SaveFailed)?;
        } else if metadata.file_type().is_fifo()
            || metadata.file_type().is_socket()
            || metadata.file_type().is_block_device()
            || metadata.file_type().is_char_device()
        {
            return Err(VaultError::SaveFailed);
        }

        File::open(directory)
            .and_then(|file| file.sync_all())
            .and_then(|_| File::open(parent))
            .and_then(|file| file.sync_all())
            .map_err(|_| VaultError::SaveFailed)?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, parent, directory);
    }
    Ok(())
}

fn validate_loaded_data(data: &VaultData) -> VaultResult<()> {
    if data.schema_version != 1
        || data.generation == 0
        || data.created_at == 0
        || data.updated_at == 0
        || data.entries.len() > MAX_VAULT_ENTRIES
        || data.tombstones.len() > MAX_VAULT_TOMBSTONES
        || Uuid::parse_str(&data.vault_id)
            .map(|id| id.to_string() != data.vault_id)
            .unwrap_or(true)
    {
        return Err(VaultError::InvalidVault);
    }
    validate_settings(&data.settings).map_err(|_| VaultError::InvalidVault)?;
    let mut ids = HashSet::with_capacity(data.entries.len() + data.tombstones.len());
    for entry in &data.entries {
        if Uuid::parse_str(&entry.id)
            .map(|id| id.to_string() != entry.id)
            .unwrap_or(true)
            || entry.revision == 0
            || entry.created_at == 0
            || entry.updated_at == 0
            || entry.password_updated_at == 0
            || !ids.insert(entry.id.as_str())
        {
            return Err(VaultError::InvalidVault);
        }
        validate_entry_fields(
            &entry.title,
            &entry.username,
            &entry.password,
            &entry.url,
            &entry.purpose,
            &entry.notes,
            &entry.tags,
        )
        .map_err(|_| VaultError::InvalidVault)?;
    }
    for tombstone in &data.tombstones {
        if Uuid::parse_str(&tombstone.id)
            .map(|id| id.to_string() != tombstone.id)
            .unwrap_or(true)
            || tombstone.revision == 0
            || tombstone.deleted_at == 0
            || !ids.insert(tombstone.id.as_str())
        {
            return Err(VaultError::InvalidVault);
        }
    }
    Ok(())
}

fn validate_entry_input(input: &EntryInput) -> VaultResult<()> {
    validate_entry_fields(
        &input.title,
        &input.username,
        &input.password,
        &input.url,
        &input.purpose,
        &input.notes,
        &input.tags,
    )
}

fn validate_entry_fields(
    title: &str,
    username: &str,
    password: &str,
    url: &str,
    purpose: &str,
    notes: &str,
    tags: &[String],
) -> VaultResult<()> {
    validate_text(title, 1, 200, "应用名称")?;
    validate_text(username, 0, 500, "用户名")?;
    validate_bytes(password, 1, 4096, "密码")?;
    validate_text(purpose, 0, 500, "用途")?;
    validate_text(notes, 0, 20_000, "备注")?;
    validate_text(url, 0, 2048, "地址")?;
    if tags.len() > 20 || tags.iter().any(|tag| tag.chars().count() > 50) {
        return Err(VaultError::InvalidInput("标签数量或长度超出限制".into()));
    }
    Ok(())
}

fn validate_settings(settings: &VaultSettings) -> VaultResult<()> {
    if !(1..=120).contains(&settings.auto_lock_minutes)
        || !matches!(settings.clipboard_clear_seconds, 10 | 20 | 30 | 60)
        || !(5..=60).contains(&settings.password_reveal_seconds)
    {
        return Err(VaultError::InvalidInput("安全设置超出允许范围".into()));
    }
    Ok(())
}

fn validate_text(value: &str, min: usize, max: usize, field: &str) -> VaultResult<()> {
    let count = value.chars().count();
    if count < min || count > max {
        return Err(VaultError::InvalidInput(format!("{field}长度无效")));
    }
    Ok(())
}

fn validate_bytes(value: &str, min: usize, max: usize, field: &str) -> VaultResult<()> {
    if value.len() < min || value.len() > max {
        return Err(VaultError::InvalidInput(format!("{field}长度无效")));
    }
    Ok(())
}

fn validate_id(id: &str) -> VaultResult<()> {
    Uuid::parse_str(id)
        .map(|_| ())
        .map_err(|_| VaultError::InvalidInput("条目 ID 无效".into()))
}

fn canonical_id(id: &str) -> VaultResult<String> {
    Uuid::parse_str(id)
        .map(|value| value.to_string())
        .map_err(|_| VaultError::InvalidInput("条目 ID 无效".into()))
}

fn ids_refer_to_same_uuid(left: &str, right: &str) -> bool {
    match (Uuid::parse_str(left), Uuid::parse_str(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

fn normalize_tags(tags: Vec<String>) -> Vec<String> {
    let mut normalized = Vec::new();
    for tag in tags {
        let trimmed = tag.trim();
        if !trimmed.is_empty() && !normalized.iter().any(|existing| existing == trimmed) {
            normalized.push(trimmed.to_string());
        }
    }
    normalized
}

fn searchable_text(entry: &VaultEntry) -> String {
    format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        entry.title,
        entry.username,
        entry.url,
        entry.purpose,
        entry.notes,
        entry.tags.join("\n")
    )
    .to_lowercase()
}

fn entry_summary(entry: &VaultEntry, counts: &PasswordCounts) -> EntrySummary {
    let mut security_flags = Vec::new();
    if is_weak_password(&entry.password) {
        security_flags.push("weak".into());
    }
    if password_use_count(counts, &entry.password) > 1 {
        security_flags.push("reused".into());
    }
    if now_ms().saturating_sub(entry.password_updated_at) > STALE_PASSWORD_MS {
        security_flags.push("stale".into());
    }
    EntrySummary {
        id: entry.id.clone(),
        revision: entry.revision,
        title: entry.title.clone(),
        favorite: entry.favorite,
        created_at: entry.created_at,
        updated_at: entry.updated_at,
        password_updated_at: entry.password_updated_at,
        security_flags,
    }
}

struct PasswordCounts(HashMap<[u8; 32], usize>);

impl Drop for PasswordCounts {
    fn drop(&mut self) {
        for (mut digest, _) in self.0.drain() {
            digest.zeroize();
        }
    }
}

fn password_counts(entries: &[VaultEntry]) -> PasswordCounts {
    let mut counts = HashMap::new();
    for entry in entries {
        *counts.entry(password_digest(&entry.password)).or_insert(0) += 1;
    }
    PasswordCounts(counts)
}

fn password_use_count(counts: &PasswordCounts, password: &str) -> usize {
    let mut digest = password_digest(password);
    let count = counts.0.get(&digest).copied().unwrap_or(0);
    digest.zeroize();
    count
}

fn password_digest(password: &str) -> [u8; 32] {
    Sha256::digest(password.as_bytes()).into()
}

fn is_weak_password(password: &str) -> bool {
    const COMMON: &[&str] = &[
        "password",
        "password123",
        "12345678",
        "123456789",
        "qwerty123",
        "letmein",
        "admin123",
    ];
    if COMMON
        .iter()
        .any(|common| password.eq_ignore_ascii_case(common))
    {
        return true;
    }
    let length = password.chars().count();
    let mut pool: f64 = 0.0;
    if password
        .chars()
        .any(|character| character.is_ascii_lowercase())
    {
        pool += 26.0;
    }
    if password
        .chars()
        .any(|character| character.is_ascii_uppercase())
    {
        pool += 26.0;
    }
    if password.chars().any(|character| character.is_ascii_digit()) {
        pool += 10.0;
    }
    if password
        .chars()
        .any(|character| !character.is_ascii_alphanumeric())
    {
        pool += 32.0;
    }
    if !password.is_ascii() {
        pool += 64.0;
    }
    length < 12 || pool <= 1.0 || length as f64 * pool.log2() < 60.0
}

fn sync_content_from(data: &VaultData) -> SyncContent {
    SyncContent {
        entries: data.entries.clone(),
        tombstones: data.tombstones.clone(),
    }
}

pub(crate) fn sync_contents_equal(left: &SyncContent, right: &SyncContent) -> bool {
    if left.entries.len() != right.entries.len() || left.tombstones.len() != right.tombstones.len()
    {
        return false;
    }
    let right_entries: HashMap<&str, &VaultEntry> = right
        .entries
        .iter()
        .map(|entry| (entry.id.as_str(), entry))
        .collect();
    let right_tombstones: HashMap<&str, &Tombstone> = right
        .tombstones
        .iter()
        .map(|item| (item.id.as_str(), item))
        .collect();
    right_entries.len() == right.entries.len()
        && right_tombstones.len() == right.tombstones.len()
        && left.entries.iter().all(|entry| {
            right_entries
                .get(entry.id.as_str())
                .is_some_and(|other| **other == *entry)
        })
        && left.tombstones.iter().all(|item| {
            right_tombstones
                .get(item.id.as_str())
                .is_some_and(|other| **other == *item)
        })
}

fn validate_sync_generation_and_content(
    state: &LocalSyncState,
    data: &VaultData,
) -> VaultResult<()> {
    sync::validate_local_generation(state, data.generation)?;
    let base = state.base_snapshot().ok_or(SyncError::InvalidLocalState)?;
    if data.generation == state.last_local_generation()
        && !sync_contents_equal(&sync_content_from(data), &base.content())
    {
        return Err(SyncError::LocalRollback.into());
    }
    Ok(())
}

fn sync_status_for(state: &LocalSyncState, data: &VaultData) -> VaultResult<WebDavSyncStatus> {
    validate_sync_generation_and_content(state, data)?;
    let endpoint = Url::parse(state.endpoint()).map_err(|_| SyncError::InvalidLocalState)?;
    let endpoint_host = endpoint
        .host_str()
        .map(str::to_owned)
        .ok_or(SyncError::InvalidLocalState)?;
    let base = state.base_snapshot().ok_or(SyncError::InvalidLocalState)?;
    Ok(WebDavSyncStatus {
        configured: true,
        endpoint_host: Some(endpoint_host),
        username: Some(state.username().to_owned()),
        sync_id_short: Some(state.sync_id().chars().take(8).collect()),
        last_sync_at: state.last_sync_at(),
        remote_sequence: Some(base.sequence()),
        pending_local_changes: !sync_contents_equal(&sync_content_from(data), &base.content()),
    })
}

fn sync_state_digest(state: &LocalSyncState) -> VaultResult<[u8; 32]> {
    let encoded =
        Zeroizing::new(serde_json::to_vec(state).map_err(|_| SyncError::InvalidLocalState)?);
    Ok(Sha256::digest(encoded.as_slice()).into())
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn paths_refer_to_same_file(left: &Path, right: &Path) -> bool {
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => left == right,
    }
}

fn sidecar_path_for(vault_path: &Path, suffix: &str) -> PathBuf {
    let mut path = OsString::from(vault_path.as_os_str());
    path.push(suffix);
    PathBuf::from(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry_input(
        id: Option<String>,
        expected_revision: Option<u64>,
        title: &str,
    ) -> EntryInput {
        EntryInput {
            id,
            expected_revision,
            title: title.into(),
            username: "local-user".into(),
            password: "Z6!qL8@vN4#rT2$xP9".into(),
            url: "https://example.com".into(),
            purpose: "regression test".into(),
            notes: "encrypted note".into(),
            tags: vec!["test".into()],
            favorite: false,
        }
    }

    fn test_sync_state(data: &VaultData, last_local_generation: u64) -> LocalSyncState {
        let sync_id = Uuid::new_v4().to_string();
        let device_id = Uuid::new_v4().to_string();
        serde_json::from_value(serde_json::json!({
            "stateVersion": 1,
            "endpoint": "https://webdav.example.test/ciphernest/",
            "username": "sync-user",
            "appPassword": "application-password-for-tests",
            "syncId": sync_id,
            "syncRootKey": vec![7_u8; 32],
            "deviceId": device_id,
            "deviceCounter": 1,
            "checkpointHash": "a".repeat(64),
            "baseSnapshot": {
                "protocolVersion": 1,
                "syncId": sync_id,
                "sequence": 1,
                "parentHash": null,
                "deviceId": device_id,
                "deviceCounter": 1,
                "createdAt": 1,
                "entries": data.entries,
                "tombstones": data.tombstones,
            },
            "lastLocalGeneration": last_local_generation,
            "lastSyncAt": 1,
        }))
        .unwrap()
    }

    #[test]
    fn weak_password_detection_is_conservative() {
        assert!(is_weak_password("password123"));
        assert!(is_weak_password("tiny"));
        assert!(!is_weak_password("Tb@7.Bx9-vQ2!mZ4#rLp"));
    }

    #[test]
    fn address_field_accepts_plain_text_and_limits_length() {
        for address in [
            "3389",
            "10.0.0.8:3389",
            "internal-host",
            "RDP 跳板机（仅限公司网络）",
            "https://example.com",
            "javascript:alert(1)",
        ] {
            assert!(
                validate_entry_fields("x", "", "secret", address, "", "", &[]).is_ok(),
                "address should be stored as plain text: {address}"
            );
        }

        let too_long = "a".repeat(2049);
        assert!(validate_entry_fields("x", "", "secret", &too_long, "", "", &[]).is_err());
    }

    #[test]
    fn store_persists_entries_across_lock_and_unlock() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.cnvault");
        let mut store = VaultStore::new(path);
        let master_password = "test master passphrase with enough length";
        store.create(master_password).unwrap();
        let summary = store
            .save_entry(EntryInput {
                id: None,
                expected_revision: None,
                title: "Example".into(),
                username: "local-user".into(),
                password: "Z6!qL8@vN4#rT2$xP9".into(),
                url: "10.0.0.8:3389".into(),
                purpose: "integration test".into(),
                notes: "encrypted note".into(),
                tags: vec!["test".into()],
                favorite: true,
            })
            .unwrap();
        let summary_json = serde_json::to_value(&summary).unwrap();
        for sensitive_key in ["username", "url", "purpose", "notes", "tags", "password"] {
            assert!(
                summary_json.get(sensitive_key).is_none(),
                "entry summaries must not expose {sensitive_key}"
            );
        }
        let favorite_revision = store
            .set_favorite(&summary.id, false, summary.revision)
            .unwrap();
        assert_eq!(favorite_revision, 2);
        store
            .save_entry(EntryInput {
                id: Some(summary.id.clone()),
                expected_revision: Some(favorite_revision),
                title: "Example".into(),
                username: "local-user".into(),
                password: "Z6!qL8@vN4#rT2$xP9".into(),
                url: "10.0.0.8:3389".into(),
                purpose: "updated after favorite".into(),
                notes: "encrypted note".into(),
                tags: vec!["test".into()],
                favorite: false,
            })
            .unwrap();
        assert!(store.lock());
        assert!(matches!(
            store.get_entry(&summary.id),
            Err(VaultError::Locked)
        ));

        store.unlock(master_password).unwrap();
        let entry = store.get_entry(&summary.id).unwrap();
        assert_eq!(entry.title, "Example");
        assert_eq!(entry.password, "Z6!qL8@vN4#rT2$xP9");
        assert_eq!(entry.url, "10.0.0.8:3389");
        assert_eq!(entry.purpose, "updated after favorite");
        assert!(!entry.favorite);
        assert_eq!(entry.revision, 3);
        assert_eq!(store.list_entries(None, None, None).unwrap().len(), 1);

        store.delete_entry(&summary.id, 3).unwrap();
        assert!(store.list_entries(None, None, None).unwrap().is_empty());
    }

    #[test]
    fn reopening_the_same_data_directory_keeps_vault_backups_and_sync_settings() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.cnvault");
        let password = "upgrade preservation passphrase long enough";
        let mut before = VaultStore::new(path.clone());
        before.create(password).unwrap();
        let entry = before
            .save_entry(sample_entry_input(None, None, "Stored before upgrade"))
            .unwrap();
        let vault = before.unlocked.as_ref().unwrap();
        let sync_state = test_sync_state(&vault.data, vault.data.generation);
        sync::write_local_sync_state(
            &before.sync_state_path,
            &vault.data.vault_id,
            &vault.root_key,
            &sync_state,
        )
        .unwrap();
        let backup_count = fs::read_dir(directory.path().join("backups"))
            .unwrap()
            .count();
        drop(before);

        // A replacement executable starts with fresh process state but the
        // same app-data path. It must never create a blank vault over it.
        let mut after = VaultStore::new(path);
        assert!(after.status().0.exists);
        assert!(matches!(
            after.create(password),
            Err(VaultError::AlreadyExists)
        ));
        after.unlock(password).unwrap();
        assert_eq!(
            after.get_entry(&entry.id).unwrap().title,
            "Stored before upgrade"
        );
        assert!(after.webdav_sync_status().unwrap().configured);
        assert_eq!(
            fs::read_dir(directory.path().join("backups"))
                .unwrap()
                .count(),
            backup_count
        );
    }

    #[test]
    fn stale_session_does_not_overwrite_a_newer_vault_on_disk() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.cnvault");
        let password = "concurrent writer passphrase long enough";
        let mut stale = VaultStore::new(path.clone());
        stale.create(password).unwrap();
        stale
            .save_entry(sample_entry_input(None, None, "Original"))
            .unwrap();

        let mut newer = VaultStore::new(path.clone());
        newer.unlock(password).unwrap();
        let added = newer
            .save_entry(sample_entry_input(None, None, "Newer entry"))
            .unwrap();
        let newer_bytes = fs::read(&path).unwrap();
        assert!(matches!(
            stale.save_entry(sample_entry_input(None, None, "Stale entry")),
            Err(VaultError::VaultChangedOnDisk)
        ));
        assert_eq!(fs::read(&path).unwrap(), newer_bytes);

        stale.lock();
        stale.unlock(password).unwrap();
        assert_eq!(stale.get_entry(&added.id).unwrap().title, "Newer entry");
        assert_eq!(stale.list_entries(None, None, None).unwrap().len(), 2);
    }

    #[test]
    fn same_generation_replacement_is_not_overwritten() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.cnvault");
        let password = "same generation passphrase long enough";
        let mut store = VaultStore::new(path.clone());
        store.create(password).unwrap();
        let entry = store
            .save_entry(sample_entry_input(None, None, "Original"))
            .unwrap();
        let replacement = {
            let unlocked = store.unlocked.as_ref().unwrap();
            let mut data = unlocked.data.clone();
            data.entries[0].title = "Restored elsewhere".into();
            update_payload(&unlocked.envelope, &unlocked.root_key, &data).unwrap()
        };
        assert_eq!(
            replacement.generation,
            store.unlocked.as_ref().unwrap().envelope.generation
        );
        write_envelope_atomic(&path, &replacement).unwrap();
        let replacement_bytes = fs::read(&path).unwrap();

        assert!(matches!(
            store.save_entry(sample_entry_input(None, None, "Stale")),
            Err(VaultError::VaultChangedOnDisk)
        ));
        assert_eq!(fs::read(&path).unwrap(), replacement_bytes);
        store.lock();
        store.unlock(password).unwrap();
        assert_eq!(
            store.get_entry(&entry.id).unwrap().title,
            "Restored elsewhere"
        );
    }

    #[test]
    fn client_ids_are_idempotent_and_updates_require_the_expected_revision() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.cnvault");
        let mut store = VaultStore::new(path);
        let master_password = "test master passphrase with enough length";
        store.create(master_password).unwrap();

        let client_id = Uuid::new_v4().to_string();
        let created = store
            .save_entry(sample_entry_input(
                Some(client_id.clone()),
                None,
                "Client-created ID",
            ))
            .unwrap();
        assert_eq!(created.id, client_id);

        assert!(matches!(
            store.save_entry(sample_entry_input(
                Some(client_id.clone()),
                None,
                "Duplicate create",
            )),
            Err(VaultError::EntryAlreadyExists)
        ));

        store
            .save_entry(sample_entry_input(
                Some(client_id.clone()),
                Some(1),
                "Updated once",
            ))
            .unwrap();
        let updated = store.get_entry(&client_id).unwrap();
        assert_eq!(updated.title, "Updated once");
        assert_eq!(updated.revision, 2);

        assert!(matches!(
            store.save_entry(sample_entry_input(
                Some(client_id.clone()),
                Some(1),
                "Stale overwrite",
            )),
            Err(VaultError::RevisionConflict)
        ));
        let after_conflict = store.get_entry(&client_id).unwrap();
        assert_eq!(after_conflict.title, "Updated once");
        assert_eq!(after_conflict.revision, 2);

        store.delete_entry(&client_id, 2).unwrap();
        assert!(matches!(
            store.save_entry(sample_entry_input(
                Some(client_id),
                None,
                "Deleted ID reuse",
            )),
            Err(VaultError::EntryAlreadyExists)
        ));
    }

    #[test]
    fn favorite_and_delete_reject_stale_revisions_without_changing_the_vault() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.cnvault");
        let mut store = VaultStore::new(path.clone());
        store
            .create("revision checks passphrase long enough")
            .unwrap();
        let entry = store
            .save_entry(sample_entry_input(None, None, "Keep this entry"))
            .unwrap();
        let next_revision = store.set_favorite(&entry.id, true, entry.revision).unwrap();
        let committed = fs::read(&path).unwrap();
        assert!(matches!(
            store.set_favorite(&entry.id, false, entry.revision),
            Err(VaultError::RevisionConflict)
        ));
        assert!(matches!(
            store.delete_entry(&entry.id, entry.revision),
            Err(VaultError::RevisionConflict)
        ));
        assert_eq!(fs::read(&path).unwrap(), committed);
        assert!(store.get_entry(&entry.id).unwrap().favorite);
        store.delete_entry(&entry.id, next_revision).unwrap();
    }

    #[test]
    fn entry_limit_rejects_the_next_save_without_changing_the_vault_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.cnvault");
        let mut store = VaultStore::new(path.clone());
        let master_password = "entry limit test passphrase long enough";
        store.create(master_password).unwrap();
        let saved = store
            .save_entry(sample_entry_input(None, None, "template"))
            .unwrap();
        let template = store.get_entry(&saved.id).unwrap();
        let entries = (0..MAX_VAULT_ENTRIES)
            .map(|_| {
                let mut entry = template.clone();
                entry.id = Uuid::new_v4().to_string();
                entry
            })
            .collect();
        store.unlocked.as_mut().unwrap().data.entries = entries;
        let before = fs::read(&path).unwrap();

        assert!(matches!(
            store.save_entry(sample_entry_input(None, None, "one too many")),
            Err(VaultError::InvalidInput(_))
        ));
        assert_eq!(fs::read(&path).unwrap(), before);

        store.lock();
        assert!(store.unlock(master_password).unwrap().unlocked);
    }

    #[test]
    fn tombstone_limit_rejects_delete_without_changing_the_vault_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.cnvault");
        let mut store = VaultStore::new(path.clone());
        let master_password = "tombstone limit test passphrase long enough";
        store.create(master_password).unwrap();
        let saved = store
            .save_entry(sample_entry_input(None, None, "keep on failed delete"))
            .unwrap();
        store.unlocked.as_mut().unwrap().data.tombstones = (0..MAX_VAULT_TOMBSTONES)
            .map(|index| Tombstone {
                id: Uuid::new_v4().to_string(),
                revision: 1,
                deleted_at: index as u64 + 1,
            })
            .collect();
        let before = fs::read(&path).unwrap();

        assert!(matches!(
            store.delete_entry(&saved.id, saved.revision),
            Err(VaultError::InvalidInput(_))
        ));
        assert_eq!(fs::read(&path).unwrap(), before);

        store.lock();
        assert!(store.unlock(master_password).unwrap().unlocked);
        assert!(store.get_entry(&saved.id).is_ok());
    }

    #[test]
    fn focusing_after_the_idle_deadline_locks_before_recording_activity() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.cnvault");
        let mut store = VaultStore::new(path);
        let master_password = "test master passphrase with enough length";
        store.create(master_password).unwrap();

        let mut settings = store.settings().unwrap();
        settings.auto_lock_minutes = 1;
        store.update_settings(settings).unwrap();
        store.last_activity = Instant::now() - Duration::from_secs(61);

        assert!(store.handle_focus_change(true));
        assert!(!store.status().0.unlocked);
    }

    #[test]
    fn automatic_backup_names_do_not_collide_across_vaults() {
        let directory = tempfile::tempdir().unwrap();
        let mut first = VaultStore::new(directory.path().join("first.cnvault"));
        let mut second = VaultStore::new(directory.path().join("second.cnvault"));
        let master_password = "test master passphrase with enough length";
        first.create(master_password).unwrap();
        second.create(master_password).unwrap();

        let first_envelope = read_envelope(&first.vault_path).unwrap();
        let second_envelope = read_envelope(&second.vault_path).unwrap();
        assert_eq!(first_envelope.generation, second_envelope.generation);
        assert_ne!(first_envelope.vault_id, second_envelope.vault_id);

        first.backup_current().unwrap();
        second.backup_current().unwrap();

        let backup_directory = directory.path().join("backups");
        let names: Vec<String> = fs::read_dir(backup_directory)
            .unwrap()
            .map(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .into_string()
                    .expect("test backup names are UTF-8")
            })
            .collect();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&automatic_backup_name(&first_envelope).unwrap()));
        assert!(names.contains(&automatic_backup_name(&second_envelope).unwrap()));
    }

    #[test]
    fn current_version_is_snapshotted_after_create_save_and_unlock_without_duplicates() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.cnvault");
        let password = "automatic backup passphrase long enough";
        let mut store = VaultStore::new(path.clone());
        store.create(password).unwrap();
        let initial = store.overview().unwrap().auto_backup;
        assert_eq!(initial.count, 1);
        assert!(initial.current_covered);
        assert!(!initial.inspection_failed);

        store
            .save_entry(sample_entry_input(None, None, "Latest entry"))
            .unwrap();
        let after_save = store.overview().unwrap().auto_backup;
        assert_eq!(after_save.count, 2);
        assert!(after_save.current_covered);
        assert!(after_save.warning.is_none());

        store.lock();
        store.unlock(password).unwrap();
        let after_unlock = store.overview().unwrap().auto_backup;
        assert_eq!(after_unlock.count, 2);
        assert!(after_unlock.current_covered);
        let current = fs::read(&path).unwrap();
        assert!(fs::read_dir(directory.path().join("backups"))
            .unwrap()
            .any(|entry| fs::read(entry.unwrap().path()).unwrap() == current));
    }

    #[test]
    fn automatic_backup_status_flags_a_corrupt_snapshot_instead_of_claiming_health() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.cnvault");
        let mut store = VaultStore::new(path.clone());
        store
            .create("backup status passphrase long enough")
            .unwrap();
        let envelope = read_envelope(&path).unwrap();
        let backup_path = directory
            .path()
            .join("backups")
            .join(automatic_backup_name(&envelope).unwrap());
        assert!(store.overview().unwrap().auto_backup.current_covered);
        fs::write(&backup_path, b"corrupt encrypted snapshot").unwrap();
        let status = store.overview().unwrap().auto_backup;
        assert_eq!(status.count, 0);
        assert!(!status.current_covered);
        assert!(status.inspection_failed);
        assert!(status.warning.is_some());
    }

    #[test]
    fn rotation_keeps_current_and_immediate_previous_even_when_both_are_oldest() {
        let directory = tempfile::tempdir().unwrap();
        let backup_directory = directory.path().join("backups");
        fs::create_dir(&backup_directory).unwrap();
        let vault_id = Uuid::new_v4().to_string();
        let previous = backup_directory.join(format!("auto-{vault_id}-000000.cnvault"));
        let current = backup_directory.join(format!("auto-{vault_id}-000001.cnvault"));
        fs::write(&previous, b"previous vault backup").unwrap();
        fs::write(&current, b"current vault backup").unwrap();
        for index in 2..=AUTO_BACKUP_LIMIT + 1 {
            fs::write(
                backup_directory.join(format!("auto-{vault_id}-{index:06}.cnvault")),
                b"older history",
            )
            .unwrap();
        }
        rotate_backups(&backup_directory, &vault_id, &current, Some(&previous)).unwrap();
        assert!(current.is_file());
        assert!(previous.is_file());
        assert_eq!(
            fs::read_dir(&backup_directory).unwrap().count(),
            AUTO_BACKUP_LIMIT
        );
    }

    #[test]
    fn rotation_keeps_the_current_vault_backup_even_when_it_is_oldest() {
        let directory = tempfile::tempdir().unwrap();
        let backup_directory = directory.path().join("backups");
        fs::create_dir(&backup_directory).unwrap();
        let vault_id = Uuid::new_v4().to_string();
        let current_backup = backup_directory.join(format!("auto-{vault_id}-000000.cnvault"));
        fs::write(&current_backup, b"current vault backup").unwrap();
        for index in 1..=AUTO_BACKUP_LIMIT {
            fs::write(
                backup_directory.join(format!("auto-{vault_id}-{index:06}.cnvault")),
                b"another backup",
            )
            .unwrap();
        }

        rotate_backups(&backup_directory, &vault_id, &current_backup, None).unwrap();
        assert!(current_backup.is_file());
        assert_eq!(
            fs::read_dir(&backup_directory).unwrap().count(),
            AUTO_BACKUP_LIMIT
        );
    }

    #[test]
    fn rotation_preserves_other_vaults_snapshots() {
        let directory = tempfile::tempdir().unwrap();
        let backup_directory = directory.path().join("backups");
        fs::create_dir(&backup_directory).unwrap();
        let current_id = Uuid::new_v4().to_string();
        let old_id = Uuid::new_v4().to_string();
        let old_snapshot = backup_directory.join(format!("auto-{old_id}-000001.cnvault"));
        fs::write(&old_snapshot, b"previous vault history").unwrap();
        let mut current = PathBuf::new();
        for index in 0..=AUTO_BACKUP_LIMIT {
            current = backup_directory.join(format!("auto-{current_id}-{index:06}.cnvault"));
            fs::write(&current, b"current vault history").unwrap();
        }
        rotate_backups(&backup_directory, &current_id, &current, None).unwrap();
        assert!(old_snapshot.is_file());
        assert_eq!(
            fs::read_dir(&backup_directory).unwrap().count(),
            AUTO_BACKUP_LIMIT + 1
        );
    }

    #[test]
    fn automatic_backup_preserves_distinct_envelopes_with_same_vault_generation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.cnvault");
        let mut store = VaultStore::new(path.clone());
        let master_password = "backup collision passphrase long enough";
        store.create(master_password).unwrap();

        let first_envelope = read_envelope(&path).unwrap();
        let (_, mut alternate_data) = decrypt_envelope(master_password, &first_envelope).unwrap();
        alternate_data.settings.clipboard_clear_seconds = 17;
        let (alternate_envelope, _) = create_envelope(master_password, &alternate_data).unwrap();
        assert_eq!(alternate_envelope.vault_id, first_envelope.vault_id);
        assert_eq!(alternate_envelope.generation, first_envelope.generation);
        assert_ne!(
            serde_json::to_vec(&alternate_envelope).unwrap(),
            serde_json::to_vec(&first_envelope).unwrap()
        );

        store.backup_envelope(&first_envelope).unwrap();
        store.backup_envelope(&alternate_envelope).unwrap();
        store.backup_envelope(&alternate_envelope).unwrap();

        let backup_directory = directory.path().join("backups");
        let mut files: Vec<PathBuf> = fs::read_dir(&backup_directory)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        files.sort();
        assert_eq!(files.len(), 2);
        assert!(backup_directory
            .join(automatic_backup_name(&first_envelope).unwrap())
            .is_file());
        let alternate_bytes = serde_json::to_vec(&alternate_envelope).unwrap();
        let alternate_name = automatic_backup_collision_name(
            &alternate_envelope,
            &hex_sha256(&alternate_bytes),
            None,
        )
        .unwrap();
        assert_eq!(
            fs::read(backup_directory.join(alternate_name)).unwrap(),
            alternate_bytes
        );
    }

    #[test]
    fn a_corrupt_current_vault_is_quarantined_before_verified_restore() {
        let directory = tempfile::tempdir().unwrap();
        let source_directory = directory.path().join("source");
        fs::create_dir(&source_directory).unwrap();
        let source_path = source_directory.join("vault.cnvault");
        let target_path = directory.path().join("vault.cnvault");
        let master_password = "test master passphrase with enough length";

        let mut source = VaultStore::new(source_path.clone());
        source.create(master_password).unwrap();
        let created = source
            .save_entry(sample_entry_input(None, None, "Recovered entry"))
            .unwrap();
        let backup = read_envelope(&source_path).unwrap();
        let (root_key, data) = decrypt_envelope(master_password, &backup).unwrap();

        let corrupt_bytes = b"{this is not a CipherNest vault";
        fs::write(&target_path, corrupt_bytes).unwrap();
        let mut target = VaultStore::new(target_path.clone());
        target
            .replace_with_verified_backup(backup, root_key, data)
            .unwrap();

        let restored = read_envelope(&target_path).unwrap();
        let (_, restored_data) = decrypt_envelope(master_password, &restored).unwrap();
        assert_eq!(restored_data.entries.len(), 1);
        assert_eq!(restored_data.entries[0].id, created.id);

        let quarantine_directory = directory.path().join("quarantine");
        let quarantined: Vec<PathBuf> = fs::read_dir(quarantine_directory)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(quarantined.len(), 1);
        assert_eq!(fs::read(&quarantined[0]).unwrap(), corrupt_bytes);
    }

    #[test]
    fn first_password_unlock_retires_legacy_device_access_once() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.cnvault");
        let mut store = VaultStore::new(path.clone());
        let master_password = "test master passphrase with enough length";
        store.create(master_password).unwrap();
        let summary = store
            .save_entry(EntryInput {
                id: None,
                expected_revision: None,
                title: "Password-only migration".into(),
                username: "local-user".into(),
                password: "K7!migration-secret".into(),
                url: "https://example.com".into(),
                purpose: "legacy retirement regression".into(),
                notes: String::new(),
                tags: vec![],
                favorite: false,
            })
            .unwrap();

        let mut legacy_data = store.unlocked.as_ref().unwrap().data.clone();
        legacy_data.password_only_unlock = false;
        bump_generation(&mut legacy_data, now_ms());
        store.persist(legacy_data).unwrap();
        let before = read_envelope(&path).unwrap();
        let (before_root_key, before_data) = decrypt_envelope(master_password, &before).unwrap();
        assert!(!before_data.password_only_unlock);

        fs::write(&store.legacy_device_slots_path, b"legacy-slot-record").unwrap();
        fs::write(&store.legacy_device_auth_path, b"legacy-device-record").unwrap();
        assert!(store.lock());
        store.unlock(master_password).unwrap();

        let migrated = read_envelope(&path).unwrap();
        let (migrated_root_key, migrated_data) =
            decrypt_envelope(master_password, &migrated).unwrap();
        assert!(migrated_data.password_only_unlock);
        assert_eq!(migrated.generation, before.generation + 1);
        assert_ne!(before_root_key.as_ref(), migrated_root_key.as_ref());
        assert!(!store.legacy_device_slots_path.exists());
        assert!(!store.legacy_device_auth_path.exists());
        assert_eq!(
            store.get_entry(&summary.id).unwrap().password,
            "K7!migration-secret"
        );

        assert!(store.lock());
        store.unlock(master_password).unwrap();
        assert_eq!(
            read_envelope(&path).unwrap().generation,
            migrated.generation
        );
    }

    #[test]
    fn failed_password_only_migration_still_retires_legacy_device_slot() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.cnvault");
        let mut store = VaultStore::new(path.clone());
        let master_password = "migration failure passphrase long enough";
        store.create(master_password).unwrap();

        let legacy_envelope = {
            let vault = store.unlocked.as_ref().unwrap();
            let mut legacy_data = vault.data.clone();
            legacy_data.password_only_unlock = false;
            bump_generation(&mut legacy_data, now_ms());
            update_payload(&vault.envelope, &vault.root_key, &legacy_data).unwrap()
        };
        write_envelope_atomic(&path, &legacy_envelope).unwrap();
        fs::write(&store.legacy_device_slots_path, b"legacy-slot-record").unwrap();
        fs::write(&store.legacy_device_auth_path, b"legacy-device-record").unwrap();
        assert!(store.lock());

        // A regular file at the backup directory path forces backup_current() to fail after
        // password verification. The legacy slot must already be absent at that point.
        let backup_directory = directory.path().join("backups");
        for backup in fs::read_dir(&backup_directory).unwrap() {
            fs::remove_file(backup.unwrap().path()).unwrap();
        }
        fs::remove_dir(&backup_directory).unwrap();
        fs::write(&backup_directory, b"not-a-directory").unwrap();
        assert!(matches!(
            store.unlock(master_password),
            Err(VaultError::PasswordOnlyMigrationFailed)
        ));
        assert!(!store.status().0.unlocked);
        assert!(!store.legacy_device_slots_path.exists());
        assert!(!store.legacy_device_auth_path.exists());

        let unchanged = read_envelope(&path).unwrap();
        let (_, unchanged_data) = decrypt_envelope(master_password, &unchanged).unwrap();
        assert!(!unchanged_data.password_only_unlock);
        assert_eq!(unchanged.generation, legacy_envelope.generation);
    }

    #[test]
    fn manual_export_never_overwrites_an_existing_file_or_enters_managed_backups() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.cnvault");
        let mut store = VaultStore::new(path);
        store
            .create("exclusive export passphrase long enough")
            .unwrap();
        let target = directory.path().join("manual.cnvault");
        fs::write(&target, b"existing backup bytes").unwrap();
        assert!(matches!(
            store.export_to(&target),
            Err(VaultError::InvalidInput(_))
        ));
        assert_eq!(fs::read(&target).unwrap(), b"existing backup bytes");

        let managed_target = directory.path().join("backups").join("my-backup.cnvault");
        assert!(matches!(
            store.export_to(&managed_target),
            Err(VaultError::InvalidInput(_))
        ));
        assert!(!managed_target.exists());
    }

    #[test]
    fn successful_manual_export_is_not_reported_failed_when_timestamp_update_fails() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.cnvault");
        let password = "export timestamp passphrase long enough";
        let mut store = VaultStore::new(path);
        store.create(password).unwrap();
        let backup_directory = directory.path().join("backups");
        for backup in fs::read_dir(&backup_directory).unwrap() {
            fs::remove_file(backup.unwrap().path()).unwrap();
        }
        fs::remove_dir(&backup_directory).unwrap();
        fs::write(&backup_directory, b"directory unavailable").unwrap();

        let target = directory.path().join("manual.cnvault");
        store.export_to(&target).unwrap();
        let (_, restored) = decrypt_envelope(password, &read_envelope(&target).unwrap()).unwrap();
        assert!(restored.last_backup_at.is_none());
        assert!(store
            .overview()
            .unwrap()
            .auto_backup
            .warning
            .unwrap()
            .contains("已导出"));
    }

    #[test]
    fn exported_backup_never_copies_retired_auth_sidecars() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.cnvault");
        let backup_path = directory.path().join("portable-backup.cnvault");
        let mut store = VaultStore::new(path.clone());
        let master_password = "test master passphrase with enough length";
        store.create(master_password).unwrap();
        fs::write(&store.legacy_device_slots_path, b"retired-slot-record").unwrap();
        fs::write(&store.legacy_device_auth_path, b"retired-device-record").unwrap();

        store.export_to(&backup_path).unwrap();

        let backup = read_envelope(&backup_path).unwrap();
        let (backup_root_key, backup_data) = decrypt_envelope(master_password, &backup).unwrap();
        assert!(!sidecar_path_for(&backup_path, ".devices").exists());
        assert!(!sidecar_path_for(&backup_path, ".device-auth").exists());
        assert!(path.is_file());

        store
            .replace_with_verified_backup(backup, backup_root_key, backup_data)
            .unwrap();
        assert!(!store.legacy_device_slots_path.exists());
        assert!(!store.legacy_device_auth_path.exists());
        assert!(store.lock());
        store.unlock(master_password).unwrap();
    }

    #[test]
    fn changing_master_password_rotates_root_key_and_reencrypts_payload() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.cnvault");
        let mut store = VaultStore::new(path.clone());
        let old_password = "old master passphrase with enough length";
        let new_password = "new master passphrase with enough length";

        store.create(old_password).unwrap();
        let summary = store
            .save_entry(EntryInput {
                id: None,
                expected_revision: None,
                title: "Rekey test".into(),
                username: "local-user".into(),
                password: "B4!fresh-secret@Q8".into(),
                url: "https://example.com".into(),
                purpose: "verify root-key rotation".into(),
                notes: "must survive re-encryption".into(),
                tags: vec!["security".into()],
                favorite: false,
            })
            .unwrap();
        fs::write(&store.legacy_device_slots_path, b"retired-slot-record").unwrap();
        fs::write(&store.legacy_device_auth_path, b"retired-device-record").unwrap();
        let before_change = read_envelope(&path).unwrap();

        store
            .change_master_password(old_password, new_password)
            .unwrap();

        let backup_path = directory
            .path()
            .join("backups")
            .join(automatic_backup_name(&before_change).unwrap());
        let old_backup = read_envelope(&backup_path).unwrap();
        let current = read_envelope(&path).unwrap();
        let (old_root_key, _) = decrypt_envelope(old_password, &old_backup).unwrap();
        let (new_root_key, decrypted) = decrypt_envelope(new_password, &current).unwrap();

        assert_eq!(old_backup.vault_id, before_change.vault_id);
        assert_eq!(current.vault_id, before_change.vault_id);
        assert_eq!(old_backup.generation, before_change.generation);
        assert_eq!(current.generation, before_change.generation + 1);
        assert!(old_root_key.as_ref() != new_root_key.as_ref());
        assert_eq!(decrypted.entries.len(), 1);
        assert_eq!(decrypted.entries[0].id, summary.id);
        assert!(decrypted.password_only_unlock);
        assert!(decrypt_envelope(old_password, &current).is_err());
        assert!(decrypt_envelope(new_password, &old_backup).is_err());
        assert!(!store.legacy_device_slots_path.exists());
        assert!(!store.legacy_device_auth_path.exists());

        // Combine the old backup's valid key wrap with the current payload. If the old root key
        // had been reused, this hybrid envelope would decrypt with the old master password.
        let mut old_key_with_current_payload = old_backup;
        old_key_with_current_payload.generation = current.generation;
        old_key_with_current_payload.payload = current.payload;
        assert!(decrypt_envelope(old_password, &old_key_with_current_payload).is_err());

        // A subsequent save must use the new in-memory root key, not the key that was rotated out.
        let mut settings = store.settings().unwrap();
        settings.auto_lock_minutes = 10;
        store.update_settings(settings).unwrap();
        assert!(store.lock());
        assert!(store.unlock(old_password).is_err());
        store.unlock(new_password).unwrap();
        assert_eq!(
            store.get_entry(&summary.id).unwrap().password,
            "B4!fresh-secret@Q8"
        );
    }

    #[test]
    fn sync_sidecar_is_encrypted_and_survives_root_key_rotation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.cnvault");
        let mut store = VaultStore::new(path);
        let old_password = "old sync master passphrase long enough";
        let new_password = "new sync master passphrase long enough";
        store.create(old_password).unwrap();
        store
            .save_entry(sample_entry_input(None, None, "Encrypted sync entry"))
            .unwrap();

        let (sync_state, vault_id, root_key, entry_password) = {
            let vault = store.unlocked.as_ref().unwrap();
            (
                test_sync_state(&vault.data, vault.data.generation),
                vault.data.vault_id.clone(),
                Zeroizing::new(*vault.root_key),
                vault.data.entries[0].password.clone(),
            )
        };
        sync::write_local_sync_state(&store.sync_state_path, &vault_id, &root_key, &sync_state)
            .unwrap();
        let raw = fs::read(&store.sync_state_path).unwrap();
        assert!(!raw
            .windows(b"application-password-for-tests".len())
            .any(|window| window == b"application-password-for-tests"));
        assert!(!raw
            .windows(entry_password.len())
            .any(|window| window == entry_password.as_bytes()));
        assert!(store.webdav_sync_status().unwrap().configured);

        let result = store
            .change_master_password(old_password, new_password)
            .unwrap();
        assert!(result.sync_config_preserved);
        assert!(result.warning.is_none());
        assert!(!store.sync_transition_path.exists());
        store.lock();
        store.unlock(new_password).unwrap();
        assert!(store.webdav_sync_status().unwrap().configured);
    }

    #[test]
    fn verified_restore_disables_the_previous_sync_configuration() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.cnvault");
        let mut store = VaultStore::new(path.clone());
        let password = "restore sync master passphrase long enough";
        store.create(password).unwrap();
        let envelope = read_envelope(&path).unwrap();
        let (backup_root_key, backup_data) = decrypt_envelope(password, &envelope).unwrap();
        let sync_state = test_sync_state(&backup_data, backup_data.generation);
        sync::write_local_sync_state(
            &store.sync_state_path,
            &backup_data.vault_id,
            &backup_root_key,
            &sync_state,
        )
        .unwrap();

        store
            .save_entry(sample_entry_input(None, None, "newer than restore point"))
            .unwrap();

        store
            .replace_with_verified_backup(envelope, backup_root_key, backup_data)
            .unwrap();
        assert!(!store.sync_state_path.exists());
        assert!(!store.sync_transition_path.exists());
        assert!(!store.sync_restore_hold_path.exists());
        assert!(!store.sync_restore_next_hold_path.exists());
        assert!(!store.webdav_sync_status().unwrap().configured);
    }

    #[test]
    fn staged_sync_checkpoint_is_promoted_only_after_vault_write() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.cnvault");
        let password = "checkpoint crash recovery passphrase";
        let mut store = VaultStore::new(path.clone());
        store.create(password).unwrap();
        let vault = store.unlocked.as_ref().unwrap();
        let old_data = vault.data.clone();
        let vault_id = old_data.vault_id.clone();
        let root_key = Zeroizing::new(*vault.root_key);
        let old_state = test_sync_state(&old_data, old_data.generation);
        sync::write_local_sync_state(&store.sync_state_path, &vault_id, &root_key, &old_state)
            .unwrap();

        let mut next_data = old_data.clone();
        let entry = store
            .save_entry(sample_entry_input(None, None, "staged remote record"))
            .unwrap();
        // Return the encrypted vault to the original generation while keeping
        // the staged candidate; this is the interrupted pre-write phase.
        let old_envelope =
            update_payload(&read_envelope(&path).unwrap(), &root_key, &old_data).unwrap();
        write_envelope_atomic(&path, &old_envelope).unwrap();
        next_data.entries = vec![store.get_entry(&entry.id).unwrap()];
        next_data.generation = old_data.generation + 1;
        let mut next_state_value = serde_json::to_value(&old_state).unwrap();
        next_state_value["lastLocalGeneration"] = serde_json::json!(next_data.generation);
        next_state_value["baseSnapshot"]["entries"] =
            serde_json::to_value(&next_data.entries).unwrap();
        next_state_value["checkpointHash"] = serde_json::json!("b".repeat(64));
        let next_state: LocalSyncState = serde_json::from_value(next_state_value).unwrap();
        sync::write_local_sync_state(
            &store.sync_transition_path,
            &vault_id,
            &root_key,
            &next_state,
        )
        .unwrap();
        drop(store);

        let mut reopened = VaultStore::new(path.clone());
        reopened.unlock(password).unwrap();
        assert_eq!(
            reopened
                .load_sync_state()
                .unwrap()
                .unwrap()
                .last_local_generation(),
            old_data.generation
        );
        assert!(!reopened.sync_transition_path.exists());

        // The vault write completed, but the active sidecar did not. Reopen
        // must retain the newer checkpoint instead of discarding `.sync.next`.
        let next_envelope = update_payload(&old_envelope, &root_key, &next_data).unwrap();
        sync::write_local_sync_state(
            &reopened.sync_transition_path,
            &vault_id,
            &root_key,
            &next_state,
        )
        .unwrap();
        write_envelope_atomic(&path, &next_envelope).unwrap();
        drop(reopened);
        let mut after_commit = VaultStore::new(path);
        after_commit.unlock(password).unwrap();
        assert_eq!(
            after_commit
                .load_sync_state()
                .unwrap()
                .unwrap()
                .last_local_generation(),
            next_data.generation
        );
        assert!(!after_commit.sync_transition_path.exists());
    }

    #[test]
    fn interrupted_restore_recovers_held_sync_state_before_vault_write() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.cnvault");
        let password = "restore hold recovery passphrase";
        let mut store = VaultStore::new(path.clone());
        store.create(password).unwrap();
        let vault = store.unlocked.as_ref().unwrap();
        let old_data = vault.data.clone();
        let root_key = Zeroizing::new(*vault.root_key);
        let state = test_sync_state(&old_data, old_data.generation);
        sync::write_local_sync_state(
            &store.sync_state_path,
            &old_data.vault_id,
            &root_key,
            &state,
        )
        .unwrap();
        let mut restored_data = old_data.clone();
        bump_generation(&mut restored_data, now_ms());
        let target = update_payload(&vault.envelope, &root_key, &restored_data).unwrap();
        store.begin_restore_intent(&target).unwrap();
        store.hold_sync_sidecars_for_restore().unwrap();
        drop(store);

        let mut reopened = VaultStore::new(path.clone());
        assert!(reopened.status().0.exists);
        reopened.unlock(password).unwrap();
        assert!(reopened.webdav_sync_status().unwrap().configured);
        assert!(!reopened.restore_intent_path.exists());
        assert!(!reopened.sync_restore_hold_path.exists());

        reopened.begin_restore_intent(&target).unwrap();
        reopened.hold_sync_sidecars_for_restore().unwrap();
        write_envelope_atomic(&path, &target).unwrap();
        drop(reopened);
        let mut after_commit = VaultStore::new(path);
        after_commit.unlock(password).unwrap();
        assert!(!after_commit.webdav_sync_status().unwrap().configured);
        assert!(!after_commit.restore_intent_path.exists());
        assert!(!after_commit.sync_restore_hold_path.exists());
    }

    #[test]
    fn restoring_the_identical_vault_keeps_existing_sync_configuration() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.cnvault");
        let password = "identical restore passphrase";
        let mut store = VaultStore::new(path.clone());
        store.create(password).unwrap();
        let envelope = read_envelope(&path).unwrap();
        let (root_key, data) = decrypt_envelope(password, &envelope).unwrap();
        let state = test_sync_state(&data, data.generation);
        sync::write_local_sync_state(&store.sync_state_path, &data.vault_id, &root_key, &state)
            .unwrap();
        assert!(store
            .replace_with_verified_backup(envelope, root_key, data)
            .is_err());
        assert!(store.sync_state_path.exists());
        assert!(!store.restore_intent_path.exists());
        assert!(store.webdav_sync_status().unwrap().configured);
    }

    #[test]
    fn interrupted_restore_returns_quarantined_vault_before_create_gate() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.cnvault");
        let password = "quarantine interruption passphrase";
        let mut store = VaultStore::new(path.clone());
        store.create(password).unwrap();
        let target = read_envelope(&path).unwrap();
        let corrupt_bytes = b"corrupt existing encrypted vault";
        fs::write(&path, corrupt_bytes).unwrap();
        let intent = store.begin_restore_intent(&target).unwrap();
        store.hold_sync_sidecars_for_restore().unwrap();
        store
            .quarantine_invalid_current(&intent.quarantine_id)
            .unwrap();
        assert!(!path.exists());
        drop(store);

        let mut reopened = VaultStore::new(path.clone());
        assert!(reopened.status().0.exists);
        assert_eq!(fs::read(&path).unwrap(), corrupt_bytes);
        assert!(!reopened.restore_intent_path.exists());
        assert!(reopened.create(password).is_err());
    }

    #[test]
    fn malformed_restore_intent_blocks_unlock_with_recovery_guidance() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.cnvault");
        let password = "malformed restore intent passphrase";
        let mut store = VaultStore::new(path.clone());
        store.create(password).unwrap();
        fs::write(&store.restore_intent_path, b"not a restore transaction").unwrap();
        let mut reopened = VaultStore::new(path);
        assert!(reopened.status().0.exists);
        assert!(matches!(
            reopened.unlock(password),
            Err(VaultError::RestoreRecoveryFailed)
        ));
    }

    #[test]
    fn legacy_orphaned_sync_hold_does_not_block_local_vault_access() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.cnvault");
        let password = "legacy hold access passphrase";
        let mut store = VaultStore::new(path.clone());
        store.create(password).unwrap();
        let entry = store
            .save_entry(sample_entry_input(None, None, "recoverable local entry"))
            .unwrap();
        let vault = store.unlocked.as_ref().unwrap();
        let state = test_sync_state(&vault.data, vault.data.generation);
        sync::write_local_sync_state(
            &store.sync_state_path,
            &vault.data.vault_id,
            &vault.root_key,
            &state,
        )
        .unwrap();
        fs::rename(&store.sync_state_path, &store.sync_restore_hold_path).unwrap();
        drop(store);

        let mut reopened = VaultStore::new(path);
        assert!(reopened.status().0.exists);
        reopened.unlock(password).unwrap();
        assert_eq!(
            reopened.get_entry(&entry.id).unwrap().title,
            "recoverable local entry"
        );
        assert!(reopened.webdav_sync_status().is_err());
        assert!(reopened.sync_restore_hold_path.exists());
    }

    #[test]
    fn joined_remote_content_preserves_local_settings_and_vault_identity() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.cnvault");
        let mut store = VaultStore::new(path);
        store
            .create("join sync master passphrase long enough")
            .unwrap();
        let mut settings = store.settings().unwrap();
        settings.auto_lock_minutes = 30;
        settings.lock_on_blur = true;
        store.update_settings(settings.clone()).unwrap();
        let context = store.prepare_new_sync().unwrap();

        let now = now_ms();
        let remote_entry = VaultEntry {
            id: Uuid::new_v4().to_string(),
            title: "Remote credential".into(),
            username: "remote-user".into(),
            password: "Y9!remote-test-password#L2".into(),
            url: "https://example.com".into(),
            purpose: "sync integration test".into(),
            notes: String::new(),
            tags: vec!["remote".into()],
            favorite: false,
            created_at: now,
            updated_at: now,
            password_updated_at: now,
            revision: 1,
        };
        let mut remote_data = store.unlocked.as_ref().unwrap().data.clone();
        remote_data.entries = vec![remote_entry.clone()];
        let next_generation = context.generation + 1;
        let joined_state = test_sync_state(&remote_data, next_generation);
        let original_vault_id = context.vault_id.clone();

        let status = store
            .install_joined_sync_state(
                &context.vault_id,
                &context.session_id,
                context.generation,
                &joined_state,
                sync_content_from(&remote_data),
            )
            .unwrap();
        assert!(status.configured);
        let vault = store.unlocked.as_ref().unwrap();
        assert_eq!(vault.data.vault_id, original_vault_id);
        assert_eq!(vault.data.settings, settings);
        assert!(vault.data.entries == vec![remote_entry]);
        assert_eq!(vault.data.generation, next_generation);
        assert!(directory.path().join("backups").is_dir());
    }

    #[test]
    fn sync_result_from_a_previous_unlock_session_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.cnvault");
        let mut store = VaultStore::new(path);
        let password = "session binding passphrase long enough";
        store.create(password).unwrap();
        let context = store.prepare_new_sync().unwrap();
        let state = test_sync_state(&store.unlocked.as_ref().unwrap().data, context.generation);

        store.lock();
        store.unlock(password).unwrap();
        assert_ne!(
            store.unlocked.as_ref().unwrap().session_id,
            context.session_id
        );
        assert!(matches!(
            store.install_new_sync_state(
                &context.vault_id,
                &context.session_id,
                context.generation,
                &state,
            ),
            Err(VaultError::SyncLocalChanged)
        ));
        assert!(!store.sync_state_path.exists());
    }

    #[test]
    fn sync_refuses_a_local_generation_rollback_before_network_use() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.cnvault");
        let mut store = VaultStore::new(path);
        store
            .create("rollback sync master passphrase long enough")
            .unwrap();
        let (sync_state, vault_id, root_key) = {
            let vault = store.unlocked.as_ref().unwrap();
            (
                test_sync_state(&vault.data, vault.data.generation + 1),
                vault.data.vault_id.clone(),
                Zeroizing::new(*vault.root_key),
            )
        };
        sync::write_local_sync_state(&store.sync_state_path, &vault_id, &root_key, &sync_state)
            .unwrap();
        assert!(matches!(
            store.prepare_existing_sync(),
            Err(VaultError::Sync(message)) if message.contains("早于上次同步版本")
        ));
    }

    #[test]
    fn loaded_vault_validation_rejects_invalid_metadata_and_duplicate_record_ids() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.cnvault");
        let mut store = VaultStore::new(path);
        store
            .create("validation master passphrase long enough")
            .unwrap();
        store
            .save_entry(sample_entry_input(None, None, "Validation entry"))
            .unwrap();
        let valid = store.unlocked.as_ref().unwrap().data.clone();

        let mut invalid_schema = valid.clone();
        invalid_schema.schema_version = 0;
        assert!(matches!(
            validate_loaded_data(&invalid_schema),
            Err(VaultError::InvalidVault)
        ));

        let mut invalid_generation = valid.clone();
        invalid_generation.generation = 0;
        assert!(matches!(
            validate_loaded_data(&invalid_generation),
            Err(VaultError::InvalidVault)
        ));

        let mut noncanonical_vault_id = valid.clone();
        noncanonical_vault_id.vault_id = format!("{{{}}}", valid.vault_id);
        assert!(matches!(
            validate_loaded_data(&noncanonical_vault_id),
            Err(VaultError::InvalidVault)
        ));

        let mut duplicate_id = valid.clone();
        duplicate_id.tombstones.push(Tombstone {
            id: duplicate_id.entries[0].id.clone(),
            revision: 2,
            deleted_at: now_ms(),
        });
        assert!(matches!(
            validate_loaded_data(&duplicate_id),
            Err(VaultError::InvalidVault)
        ));

        let mut zero_revision = valid;
        zero_revision.entries[0].revision = 0;
        assert!(matches!(
            validate_loaded_data(&zero_revision),
            Err(VaultError::InvalidVault)
        ));

        let mut zero_timestamp = zero_revision;
        zero_timestamp.entries[0].revision = 1;
        zero_timestamp.entries[0].updated_at = 0;
        assert!(matches!(
            validate_loaded_data(&zero_timestamp),
            Err(VaultError::InvalidVault)
        ));
    }

    #[test]
    fn corrupt_optional_sync_state_does_not_block_root_key_rotation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.cnvault");
        let mut store = VaultStore::new(path.clone());
        let old_password = "old corrupt-sync passphrase long enough";
        let new_password = "new corrupt-sync passphrase long enough";
        store.create(old_password).unwrap();
        fs::write(&store.sync_state_path, b"not an encrypted sync sidecar").unwrap();

        let result = store
            .change_master_password(old_password, new_password)
            .unwrap();
        assert!(!result.sync_config_preserved);
        assert!(result.warning.is_some());
        assert!(!store.sync_state_path.exists());
        assert!(!store.sync_transition_path.exists());

        store.lock();
        assert!(store.unlock(old_password).is_err());
        store.unlock(new_password).unwrap();
        assert!(!store.webdav_sync_status().unwrap().configured);
    }
}
