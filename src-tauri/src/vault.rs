use std::{
    cmp::Reverse,
    collections::{HashMap, HashSet},
    ffi::OsString,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use sha2::{Digest, Sha256};
use url::Url;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    crypto::{
        create_envelope, decrypt_envelope, read_envelope, update_payload, write_envelope_atomic,
        VaultEnvelope, MAX_VAULT_BYTES,
    },
    error::{VaultError, VaultResult},
    models::{
        EntryInput, EntrySummary, MasterPasswordChangeResult, SecurityIssue, SecurityReport,
        Tombstone, VaultData, VaultEntry, VaultOverview, VaultSettings, VaultStatus,
        WebDavSyncStatus, MAX_VAULT_ENTRIES, MAX_VAULT_TOMBSTONES,
    },
    sync::{self, LocalSyncState, SyncContent, SyncError},
};

const AUTO_BACKUP_LIMIT: usize = 10;
const STALE_PASSWORD_MS: u64 = 365 * 24 * 60 * 60 * 1000;

struct UnlockedVault {
    root_key: Zeroizing<[u8; 32]>,
    data: VaultData,
    envelope: VaultEnvelope,
    session_id: String,
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
    unlocked: Option<UnlockedVault>,
    last_activity: Instant,
    failed_unlocks: u32,
    retry_after: Option<Instant>,
}

impl VaultStore {
    pub fn new(vault_path: PathBuf) -> Self {
        let legacy_device_slots_path = sidecar_path_for(&vault_path, ".devices");
        let legacy_device_auth_path = sidecar_path_for(&vault_path, ".device-auth");
        let sync_state_path = sidecar_path_for(&vault_path, ".sync");
        let sync_transition_path = sidecar_path_for(&vault_path, ".sync.next");
        let sync_restore_hold_path = sidecar_path_for(&vault_path, ".sync.restore-hold");
        let sync_restore_next_hold_path = sidecar_path_for(&vault_path, ".sync.next.restore-hold");
        Self {
            vault_path,
            legacy_device_slots_path,
            legacy_device_auth_path,
            sync_state_path,
            sync_transition_path,
            sync_restore_hold_path,
            sync_restore_next_hold_path,
            unlocked: None,
            last_activity: Instant::now(),
            failed_unlocks: 0,
            retry_after: None,
        }
    }

    pub fn status(&mut self) -> (VaultStatus, bool) {
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
                exists: self.vault_path.is_file(),
                unlocked: self.unlocked.is_some(),
                item_count,
                auto_lock_minutes,
            },
            just_locked,
        )
    }

    pub fn create(&mut self, master_password: &str) -> VaultResult<VaultStatus> {
        if self.vault_path.exists() {
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
        Ok(self.status().0)
    }

    pub fn unlock(&mut self, master_password: &str) -> VaultResult<VaultStatus> {
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

    pub fn delete_entry(&mut self, id: &str) -> VaultResult<()> {
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

    pub fn set_favorite(&mut self, id: &str, favorite: bool) -> VaultResult<u64> {
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
            let _ = sync::remove_local_sync_state(&self.sync_transition_path);
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
                let _ = sync::remove_local_sync_state(&self.sync_transition_path);
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
        // Move synchronization state out of its active names first. A failed
        // vault replacement restores it; a successful replacement leaves it
        // disabled, even if the process stops before cleanup.
        self.hold_sync_sidecars_for_restore()?;
        let quarantined = match self.preserve_current_before_restore() {
            Ok(quarantined) => quarantined,
            Err(error) => {
                self.rollback_held_sync_sidecars();
                return Err(error);
            }
        };
        if let Err(error) = self.invalidate_legacy_device_slots() {
            self.rollback_quarantine(quarantined.as_deref());
            self.rollback_held_sync_sidecars();
            return Err(error);
        }
        if let Err(error) = write_envelope_atomic(&self.vault_path, &envelope) {
            self.rollback_quarantine(quarantined.as_deref());
            self.rollback_held_sync_sidecars();
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
        let _ = sync::remove_local_sync_state(&self.sync_restore_hold_path);
        let _ = sync::remove_local_sync_state(&self.sync_restore_next_hold_path);
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
        let envelope = read_envelope(&self.vault_path)?;
        write_envelope_atomic(target, &envelope)?;
        self.mark_manual_backup()?;
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
        self.backup_current()?;

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
        let vault = self.unlocked.as_ref().ok_or(VaultError::Locked)?;
        let vault_id = vault.data.vault_id.clone();
        let root_key = Zeroizing::new(*vault.root_key);

        // Restore holds are never auto-reactivated. A completed restore must
        // disable the previous vault's sync configuration even when both
        // vaults happen to use the same root key; an interrupted process may
        // therefore fail closed by requiring sync setup again.
        let _ = sync::remove_local_sync_state(&self.sync_restore_hold_path);
        let _ = sync::remove_local_sync_state(&self.sync_restore_next_hold_path);

        if self.sync_state_path.exists() {
            match sync::read_local_sync_state(&self.sync_state_path, &vault_id, &root_key) {
                Ok(state) => {
                    // An active state that decrypts under the current vault is
                    // authoritative; any `.next` file belongs to an aborted
                    // pre-write transaction.
                    let _ = sync::remove_local_sync_state(&self.sync_transition_path);
                    let _ = sync::remove_local_sync_state(&self.sync_restore_hold_path);
                    let _ = sync::remove_local_sync_state(&self.sync_restore_next_hold_path);
                    return Ok(Some(state));
                }
                Err(active_error) => {
                    if !self.sync_transition_path.exists() {
                        return Err(active_error.into());
                    }
                    match sync::read_local_sync_state(
                        &self.sync_transition_path,
                        &vault_id,
                        &root_key,
                    ) {
                        Ok(state) => {
                            // Best-effort promotion. Even if the filesystem is
                            // temporarily read-only, the valid recovery copy is
                            // retained and may be promoted on the next attempt.
                            if sync::write_local_sync_state(
                                &self.sync_state_path,
                                &vault_id,
                                &root_key,
                                &state,
                            )
                            .is_ok()
                            {
                                let _ = sync::remove_local_sync_state(&self.sync_transition_path);
                            }
                            return Ok(Some(state));
                        }
                        Err(_) => return Err(active_error.into()),
                    }
                }
            }
        }

        if self.sync_transition_path.exists() {
            let state =
                sync::read_local_sync_state(&self.sync_transition_path, &vault_id, &root_key)?;
            if sync::write_local_sync_state(&self.sync_state_path, &vault_id, &root_key, &state)
                .is_ok()
            {
                let _ = sync::remove_local_sync_state(&self.sync_transition_path);
            }
            return Ok(Some(state));
        }

        Ok(None)
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
        sync::remove_local_sync_state(&self.sync_restore_hold_path)?;
        sync::remove_local_sync_state(&self.sync_restore_next_hold_path)?;

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
        self.backup_current()?;
        write_envelope_atomic(&self.vault_path, &next_envelope)?;
        let unlocked = self.unlocked.as_mut().ok_or(VaultError::Locked)?;
        unlocked.data = data;
        unlocked.envelope = next_envelope;
        Ok(())
    }

    fn backup_current(&self) -> VaultResult<()> {
        if !self.vault_path.is_file() {
            return Ok(());
        }
        let current = read_envelope(&self.vault_path)?;
        self.backup_envelope(&current)
    }

    fn backup_envelope(&self, current: &VaultEnvelope) -> VaultResult<()> {
        let parent = self.vault_path.parent().ok_or(VaultError::SaveFailed)?;
        let backup_directory = parent.join("backups");
        let canonical_bytes = serde_json::to_vec(current).map_err(|_| VaultError::SaveFailed)?;
        if canonical_bytes.is_empty() || canonical_bytes.len() as u64 > MAX_VAULT_BYTES {
            return Err(VaultError::SaveFailed);
        }

        let primary_path = backup_directory.join(automatic_backup_name(current)?);
        let backup_path = if !primary_path.exists() {
            primary_path
        } else if backup_file_matches(&primary_path, &canonical_bytes)? {
            rotate_backups(&backup_directory)?;
            return Ok(());
        } else {
            let content_hash = hex_sha256(&canonical_bytes);
            let hashed_path = backup_directory.join(automatic_backup_collision_name(
                current,
                &content_hash,
                None,
            )?);
            if !hashed_path.exists() {
                hashed_path
            } else if backup_file_matches(&hashed_path, &canonical_bytes)? {
                rotate_backups(&backup_directory)?;
                return Ok(());
            } else {
                backup_directory.join(automatic_backup_collision_name(
                    current,
                    &content_hash,
                    Some(&Uuid::new_v4().to_string()),
                )?)
            }
        };

        if backup_path.exists() {
            return Err(VaultError::SaveFailed);
        }
        write_envelope_atomic(&backup_path, current)?;
        rotate_backups(&backup_directory)
    }

    fn preserve_current_before_restore(&self) -> VaultResult<Option<PathBuf>> {
        if !self.vault_path.exists() {
            return Ok(None);
        }
        if !self.vault_path.is_file() {
            return Err(VaultError::SaveFailed);
        }

        match read_envelope(&self.vault_path) {
            Ok(current) if Uuid::parse_str(&current.vault_id).is_ok() => {
                self.backup_envelope(&current)?;
                Ok(None)
            }
            Ok(_) | Err(_) => self.quarantine_invalid_current().map(Some),
        }
    }

    fn quarantine_invalid_current(&self) -> VaultResult<PathBuf> {
        let parent = self.vault_path.parent().ok_or(VaultError::SaveFailed)?;
        let quarantine_directory = parent.join("quarantine");
        fs::create_dir_all(&quarantine_directory).map_err(|_| VaultError::SaveFailed)?;
        set_private_directory_permissions(&quarantine_directory)?;

        let quarantine_path = quarantine_directory.join(format!(
            "invalid-{:020}-{}.cnvault",
            now_ms(),
            Uuid::new_v4()
        ));

        // Rename within the same application-data filesystem. This preserves the exact raw file
        // without parsing or allocating based on an attacker-controlled malformed length.
        fs::rename(&self.vault_path, &quarantine_path).map_err(|_| VaultError::SaveFailed)?;
        if let Err(error) = secure_quarantined_file(&quarantine_path, parent, &quarantine_directory)
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

fn bump_generation(data: &mut VaultData, now: u64) {
    data.generation = data.generation.saturating_add(1);
    data.updated_at = now;
}

fn rotate_backups(directory: &Path) -> VaultResult<()> {
    let mut backups: Vec<(SystemTime, PathBuf)> = fs::read_dir(directory)
        .map_err(|_| VaultError::SaveFailed)?
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let path = entry.path();
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("auto-") && name.ends_with(".cnvault"))
                .then(|| {
                    let modified = entry
                        .metadata()
                        .and_then(|metadata| metadata.modified())
                        .unwrap_or(UNIX_EPOCH);
                    (modified, path)
                })
        })
        .collect();
    backups.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    let remove_count = backups.len().saturating_sub(AUTO_BACKUP_LIMIT);
    for (_, path) in backups.into_iter().take(remove_count) {
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

fn set_private_directory_permissions(path: &Path) -> VaultResult<()> {
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
        let favorite_revision = store.set_favorite(&summary.id, false).unwrap();
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

        store.delete_entry(&summary.id).unwrap();
        assert!(store.list_entries(None, None, None).unwrap().is_empty());
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

        store.delete_entry(&client_id).unwrap();
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
            store.delete_entry(&saved.id),
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
        fs::write(directory.path().join("backups"), b"not-a-directory").unwrap();
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
            .replace_with_verified_backup(envelope, backup_root_key, backup_data)
            .unwrap();
        assert!(!store.sync_state_path.exists());
        assert!(!store.sync_transition_path.exists());
        assert!(!store.sync_restore_hold_path.exists());
        assert!(!store.sync_restore_next_hold_path.exists());
        assert!(!store.webdav_sync_status().unwrap().configured);
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
