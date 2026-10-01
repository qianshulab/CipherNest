use std::{
    fs::File,
    future::Future,
    io::Read,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

#[cfg(test)]
use crate::crypto::create_envelope;
#[cfg(test)]
use std::fs;

use sha2::{Digest, Sha256};
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_clipboard_manager::ClipboardExt;
use tauri_plugin_dialog::DialogExt;
use tokio::sync::watch;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    crypto::{
        create_envelope_with_verified_password, decrypt_envelope, parse_envelope_bytes,
        upgrade_weak_kdf, VaultEnvelope, MAX_VAULT_BYTES,
    },
    error::{VaultError, VaultResult},
    generator,
    models::{
        EntryInput, EntrySummary, GeneratedPassword, GeneratorOptions, MasterPasswordChangeResult,
        RestorePreview, RestoreSelection, SecurityReport, VaultData, VaultEntry, VaultOverview,
        VaultSettings, VaultStatus, WebDavCreateResult, WebDavCredentialsInput, WebDavInspectInput,
        WebDavJoinInput, WebDavJoinMode, WebDavRecoveryCode, WebDavRemotePreview,
        WebDavSyncOutcome, WebDavSyncOutcomeKind, WebDavSyncStatus,
    },
    sync::{self, SyncContent, SyncError, WebDavClient},
    vault::{now_ms, sync_contents_equal, ExistingSyncContext, VaultStore},
    webdav_backup::{self, BackupConfig, WebDavBackupClient, WebDavBackupItem, WebDavBackupStatus},
};

#[derive(Clone)]
struct ClipboardLease {
    token: String,
    digest: [u8; 32],
}

const PENDING_RESTORE_TTL: Duration = Duration::from_secs(5 * 60);
const PENDING_SYNC_PREVIEW_TTL: Duration = Duration::from_secs(5 * 60);
const MAX_SYNC_COMMIT_ATTEMPTS: usize = 3;
const AUTO_SYNC_DEBOUNCE: Duration = Duration::from_secs(3);
const AUTO_SYNC_POLL_INTERVAL: Duration = Duration::from_secs(90);
const MAX_AUTO_SYNC_FAST_RETRIES: u64 = 2;

struct VerifiedRestore {
    root_key: Zeroizing<[u8; 32]>,
    data: VaultData,
}

struct PreparedRestore {
    envelope: VaultEnvelope,
    verified: VerifiedRestore,
    source_updated_at: u64,
    source_generation: u64,
}

struct PendingRestore {
    token: Zeroizing<String>,
    selected_at: Instant,
    file_name: String,
    envelope: VaultEnvelope,
    verified: Option<VerifiedRestore>,
    target_fingerprint: Option<[u8; 32]>,
    backup_config_after_restore: Option<BackupConfig>,
}

fn prepare_verified_restore(
    master_password: &str,
    envelope: VaultEnvelope,
) -> VaultResult<PreparedRestore> {
    let (root_key, mut data) = decrypt_envelope(master_password, &envelope)?;
    let source_updated_at = data.updated_at;
    let source_generation = data.generation;
    if data.password_only_unlock {
        // Verify and strengthen a historical password slot before it can
        // become the active vault. The selected backup remains untouched.
        let envelope = upgrade_weak_kdf(master_password, &envelope, &root_key)?.unwrap_or(envelope);
        return Ok(PreparedRestore {
            envelope,
            verified: VerifiedRestore { root_key, data },
            source_updated_at,
            source_generation,
        });
    }

    // Never retain decrypted legacy-format material in pending restore state. Rotating the
    // root key here means a copied v0.3.1 device slot cannot decrypt the candidate that may
    // later become current, even before the user confirms the restore.
    data.password_only_unlock = true;
    data.generation = data.generation.saturating_add(1);
    data.updated_at = now_ms();
    let (migrated_envelope, migrated_root_key) =
        create_envelope_with_verified_password(master_password, &data)?;
    Ok(PreparedRestore {
        envelope: migrated_envelope,
        verified: VerifiedRestore {
            root_key: migrated_root_key,
            data,
        },
        source_updated_at,
        source_generation,
    })
}

struct PendingSyncPreview {
    token: Zeroizing<String>,
    inspected_at: Instant,
    endpoint: String,
    username: String,
    sync_id: String,
    snapshot_hash: String,
    sequence: u64,
    vault_id: String,
    session_id: String,
    local_generation: u64,
}

struct SyncOperationGuard {
    active: Arc<AtomicBool>,
}

impl SyncOperationGuard {
    fn acquire(active: &Arc<AtomicBool>) -> VaultResult<Self> {
        active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| VaultError::SyncBusy)?;
        Ok(Self {
            active: Arc::clone(active),
        })
    }
}

impl Drop for SyncOperationGuard {
    fn drop(&mut self) {
        self.active.store(false, Ordering::Release);
    }
}

enum SyncNetworkError {
    Cancelled,
    Sync(SyncError),
}

impl From<SyncNetworkError> for VaultError {
    fn from(error: SyncNetworkError) -> Self {
        match error {
            SyncNetworkError::Cancelled => VaultError::Locked,
            SyncNetworkError::Sync(error) => error.into(),
        }
    }
}

pub struct AppState {
    store: Arc<Mutex<VaultStore>>,
    clipboard: Arc<Mutex<Option<ClipboardLease>>>,
    pending_restore: Arc<Mutex<Option<PendingRestore>>>,
    pending_sync_preview: Arc<Mutex<Option<PendingSyncPreview>>>,
    sync_operation_active: Arc<AtomicBool>,
    sync_cancel_epoch: watch::Sender<u64>,
    auto_sync_cancel_epoch: watch::Sender<u64>,
    auto_sync_schedule_sequence: Arc<AtomicU64>,
    auto_sync_poll_sequence: Arc<AtomicU64>,
    auto_sync_fast_retry_count: Arc<AtomicU64>,
    last_auto_check_at: AtomicU64,
    backup_schedule_sequence: Arc<AtomicU64>,
    backup_configuration_epoch: Arc<AtomicU64>,
    backup_upload_queue: Arc<tokio::sync::Mutex<()>>,
}

impl AppState {
    pub fn new(vault_path: PathBuf) -> Self {
        let (sync_cancel_epoch, _) = watch::channel(0);
        let (auto_sync_cancel_epoch, _) = watch::channel(0);
        Self {
            store: Arc::new(Mutex::new(VaultStore::new(vault_path))),
            clipboard: Arc::new(Mutex::new(None)),
            pending_restore: Arc::new(Mutex::new(None)),
            pending_sync_preview: Arc::new(Mutex::new(None)),
            sync_operation_active: Arc::new(AtomicBool::new(false)),
            sync_cancel_epoch,
            auto_sync_cancel_epoch,
            auto_sync_schedule_sequence: Arc::new(AtomicU64::new(0)),
            auto_sync_poll_sequence: Arc::new(AtomicU64::new(0)),
            auto_sync_fast_retry_count: Arc::new(AtomicU64::new(0)),
            last_auto_check_at: AtomicU64::new(0),
            backup_schedule_sequence: Arc::new(AtomicU64::new(0)),
            backup_configuration_epoch: Arc::new(AtomicU64::new(0)),
            backup_upload_queue: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    fn cancel_sync_operations(&self) {
        self.sync_cancel_epoch
            .send_modify(|epoch| *epoch = epoch.wrapping_add(1));
        self.cancel_auto_sync();
        self.auto_sync_schedule_sequence
            .fetch_add(1, Ordering::AcqRel);
        self.auto_sync_poll_sequence.fetch_add(1, Ordering::AcqRel);
        self.last_auto_check_at.store(0, Ordering::Release);
    }

    fn cancel_auto_sync(&self) {
        self.auto_sync_cancel_epoch
            .send_modify(|epoch| *epoch = epoch.wrapping_add(1));
    }
}

async fn acquire_manual_sync_guard(state: &AppState) -> VaultResult<SyncOperationGuard> {
    // An explicit user operation takes priority over a background check.
    state.cancel_auto_sync();
    for _ in 0..30 {
        match SyncOperationGuard::acquire(&state.sync_operation_active) {
            Ok(guard) => return Ok(guard),
            Err(VaultError::SyncBusy) => tokio::time::sleep(Duration::from_millis(100)).await,
            Err(error) => return Err(error),
        }
    }
    Err(VaultError::SyncBusy)
}

struct AutoSyncAttempt {
    vault_id: String,
    session_id: String,
    state_digest: [u8; 32],
    commit_started: bool,
    commit_confirmed: bool,
}

impl AutoSyncAttempt {
    fn new(context: &ExistingSyncContext) -> Self {
        Self {
            vault_id: context.vault_id.clone(),
            session_id: context.session_id.clone(),
            state_digest: context.state_digest,
            commit_started: false,
            commit_confirmed: false,
        }
    }
}

fn schedule_auto_webdav_sync(app: &AppHandle, state: &AppState) {
    state.auto_sync_fast_retry_count.store(0, Ordering::Release);
    enqueue_auto_webdav_sync(app, state, AUTO_SYNC_DEBOUNCE);
}

fn auto_sync_fast_retry_delay(previous_retries: u64) -> Option<Duration> {
    (previous_retries < MAX_AUTO_SYNC_FAST_RETRIES)
        .then(|| AUTO_SYNC_DEBOUNCE.saturating_mul(1 << previous_retries))
}

fn schedule_auto_webdav_sync_retry(app: &AppHandle, state: &AppState) {
    let previous = state
        .auto_sync_fast_retry_count
        .fetch_add(1, Ordering::AcqRel);
    if let Some(delay) = auto_sync_fast_retry_delay(previous) {
        enqueue_auto_webdav_sync(app, state, delay);
    }
}

fn enqueue_auto_webdav_sync(app: &AppHandle, state: &AppState, delay: Duration) {
    let ticket = state
        .auto_sync_schedule_sequence
        .fetch_add(1, Ordering::AcqRel)
        + 1;
    let sequence = Arc::clone(&state.auto_sync_schedule_sequence);
    let cancellation = state.sync_cancel_epoch.clone();
    let authorized_epoch = *cancellation.borrow();
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(delay).await;
        if sequence.load(Ordering::Acquire) == ticket && *cancellation.borrow() == authorized_epoch
        {
            auto_sync_once(&app).await;
        }
    });
}

fn start_auto_webdav_sync_poller(app: &AppHandle, state: &AppState) {
    let ticket = state.auto_sync_poll_sequence.fetch_add(1, Ordering::AcqRel) + 1;
    let sequence = Arc::clone(&state.auto_sync_poll_sequence);
    let cancellation = state.sync_cancel_epoch.clone();
    let authorized_epoch = *cancellation.borrow();
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            tokio::time::sleep(AUTO_SYNC_POLL_INTERVAL).await;
            if sequence.load(Ordering::Acquire) != ticket
                || *cancellation.borrow() != authorized_epoch
            {
                return;
            }
            auto_sync_once(&app).await;
        }
    });
}

async fn auto_sync_once(app: &AppHandle) {
    let state = app.state::<AppState>();
    let _operation = match SyncOperationGuard::acquire(&state.sync_operation_active) {
        Ok(guard) => guard,
        Err(_) => return,
    };
    let authorized_epoch = *state.sync_cancel_epoch.borrow();
    let auto_epoch = *state.auto_sync_cancel_epoch.borrow();
    let context = match run_store(Arc::clone(&state.store), VaultStore::prepare_auto_sync).await {
        Ok(Some(context)) => context,
        Ok(None) | Err(VaultError::Locked) => return,
        Err(_) => {
            let _ = app.emit("ciphernest://webdav-sync-status", ());
            return;
        }
    };
    let mut attempt = AutoSyncAttempt::new(&context);
    let result = run_existing_sync_context(
        app,
        &state,
        context,
        authorized_epoch,
        Some(auto_epoch),
        &mut attempt,
    )
    .await;
    match result {
        Ok(outcome) => {
            state.auto_sync_fast_retry_count.store(0, Ordering::Release);
            state.last_auto_check_at.store(now_ms(), Ordering::Release);
            let _ = app.emit("ciphernest://webdav-sync-status", ());
            if matches!(
                outcome.kind,
                WebDavSyncOutcomeKind::Downloaded | WebDavSyncOutcomeKind::Merged
            ) {
                let _ = app.emit("ciphernest://vault-content-changed", ());
            }
        }
        Err(VaultError::Locked) => {}
        Err(error) => {
            let known_concurrent = matches!(
                &error,
                VaultError::Sync(message) if message == &SyncError::ConcurrentUpdate.to_string()
            );
            let local_race = matches!(&error, VaultError::SyncLocalChanged);
            let checkpoint_error = auto_sync_checkpoint_error(&error);
            let safe_retry = known_concurrent || (attempt.commit_confirmed && local_race);
            let fast_retry = local_race && (!attempt.commit_started || attempt.commit_confirmed);
            let paused = checkpoint_error || (attempt.commit_started && !safe_retry);
            let warning = if checkpoint_error {
                "自动同步已暂停：同步历史或本地检查点无法安全验证。请保留本机备份，检查其他设备后手动同步。".to_owned()
            } else if paused {
                "自动同步已暂停：远端提交结果无法确认。请先检查其他设备，再手动同步以核对结果。"
                    .to_owned()
            } else {
                format!("自动同步暂时失败：{error} 应用会在解锁期间定期重试。")
            };
            let vault_id = attempt.vault_id;
            let session_id = attempt.session_id;
            let digest = attempt.state_digest;
            let stored = run_store(Arc::clone(&state.store), move |store| {
                store.set_auto_sync_issue_if_unchanged(
                    &vault_id,
                    &session_id,
                    &digest,
                    warning,
                    paused,
                    safe_retry,
                )
            })
            .await;
            if matches!(stored, Ok(true)) {
                let _ = app.emit("ciphernest://webdav-sync-status", ());
                if fast_retry {
                    schedule_auto_webdav_sync_retry(app, &state);
                }
            }
        }
    }
}

fn auto_sync_checkpoint_error(error: &VaultError) -> bool {
    if matches!(error, VaultError::SyncLocalChanged) {
        return false;
    }
    match error {
        VaultError::Sync(message) => [
            SyncError::InvalidLocalState,
            SyncError::LocalRollback,
            SyncError::InvalidRemoteObject,
            SyncError::HashMismatch,
            SyncError::RemoteNotInitialized,
            SyncError::RollbackOrFork,
            SyncError::ChainTooLong,
            SyncError::UnsafeServer,
            SyncError::InvalidData,
        ]
        .iter()
        .any(|candidate| message == &candidate.to_string()),
        _ => false,
    }
}

fn schedule_auto_webdav_backup(app: &AppHandle, state: &State<'_, AppState>) {
    // Refresh the UI during the debounce window, when the current generation
    // is already durable locally but still pending remotely.
    let _ = app.emit("ciphernest://webdav-backup-status", ());
    let ticket = state
        .backup_schedule_sequence
        .fetch_add(1, Ordering::AcqRel)
        + 1;
    let sequence = Arc::clone(&state.backup_schedule_sequence);
    let upload_queue = Arc::clone(&state.backup_upload_queue);
    let store = Arc::clone(&state.store);
    let cancellation = state.sync_cancel_epoch.clone();
    let authorized_epoch = *cancellation.borrow();
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_secs(3)).await;
        if sequence.load(Ordering::Acquire) != ticket || *cancellation.borrow() != authorized_epoch
        {
            return;
        }
        let _queue_guard = upload_queue.lock().await;
        if sequence.load(Ordering::Acquire) != ticket || *cancellation.borrow() != authorized_epoch
        {
            return;
        }
        let context = match run_store(Arc::clone(&store), VaultStore::remote_backup_context).await {
            Ok(context) => context,
            Err(VaultError::Locked | VaultError::BackupNotConfigured) => return,
            Err(_) => {
                let _ = app.emit("ciphernest://webdav-backup-status", ());
                return;
            }
        };
        if !context.config.automatic
            || (context
                .config
                .last_uploaded_generation
                .is_some_and(|generation| generation >= context.generation)
                && context.config.last_uploaded_sha256.as_deref()
                    == Some(context.envelope_sha256.as_str()))
        {
            return;
        }
        let outcome = match WebDavBackupClient::new(
            &context.config.endpoint,
            context.config.username.clone(),
            context.config.app_password.clone(),
        ) {
            Ok(client) => await_backup_network(
                &cancellation,
                authorized_epoch,
                client.upload(
                    &context.bytes,
                    &context.vault_id,
                    context.generation,
                    context.updated_at,
                ),
            )
            .await
            .map(|_| ()),
            Err(error) => Err(error),
        };
        if *cancellation.borrow() != authorized_epoch {
            return;
        }
        match outcome {
            Ok(()) => {
                let uploaded_at = now_ms();
                let _ = run_store(Arc::clone(&store), move |store| {
                    store.mark_remote_backup_uploaded(&context, uploaded_at)
                })
                .await;
            }
            Err(error) => {
                let warning = format!("自动备份失败：{error}");
                let _ = run_store(Arc::clone(&store), move |store| {
                    store.mark_remote_backup_warning(&context, warning)
                })
                .await;
            }
        }
        let _ = app.emit("ciphernest://webdav-backup-status", ());
    });
}

pub(crate) fn lock_for_lifecycle(app: &AppHandle) {
    let Some(state) = app.try_state::<AppState>() else {
        return;
    };
    let _ = clear_pending_restore_state(&state.pending_restore);
    let _ = clear_pending_sync_preview_state(&state.pending_sync_preview);
    state.cancel_sync_operations();
    if let Ok(mut store) = state.store.lock() {
        store.lock();
    }
    clear_clipboard_if_owned_blocking(app, &state.clipboard, None);
}

#[tauri::command]
pub async fn vault_status(app: AppHandle, state: State<'_, AppState>) -> VaultResult<VaultStatus> {
    let store = Arc::clone(&state.store);
    let (status, just_locked) = run_store(store, |store| Ok(store.status())).await?;
    if just_locked {
        state.cancel_sync_operations();
        clear_pending_restore_state(&state.pending_restore)?;
        clear_pending_sync_preview_state(&state.pending_sync_preview)?;
        let _ = clear_clipboard_if_owned(app, Arc::clone(&state.clipboard), None).await;
    }
    Ok(status)
}

#[tauri::command]
pub async fn create_vault(
    state: State<'_, AppState>,
    master_password: String,
) -> VaultResult<VaultStatus> {
    clear_pending_sync_preview_state(&state.pending_sync_preview)?;
    let store = Arc::clone(&state.store);
    run_store(store, move |store| {
        let password = Zeroizing::new(master_password);
        store.create(password.as_str())
    })
    .await
}

#[tauri::command]
pub async fn unlock_vault(
    app: AppHandle,
    state: State<'_, AppState>,
    master_password: String,
) -> VaultResult<VaultStatus> {
    clear_pending_sync_preview_state(&state.pending_sync_preview)?;
    let store = Arc::clone(&state.store);
    let status = run_store(store, move |store| {
        let password = Zeroizing::new(master_password);
        store.unlock(password.as_str())
    })
    .await?;
    state.last_auto_check_at.store(0, Ordering::Release);
    schedule_auto_webdav_backup(&app, &state);
    schedule_auto_webdav_sync(&app, &state);
    start_auto_webdav_sync_poller(&app, &state);
    Ok(status)
}

#[tauri::command]
pub async fn lock_vault(app: AppHandle, state: State<'_, AppState>) -> VaultResult<()> {
    // A damaged pending preview must never prevent the unlocked root key from
    // being removed. Keep the pending-restore clear before the store lock so a
    // concurrent restore either commits first or sees its token invalidated.
    let restore_clear = clear_pending_restore_state(&state.pending_restore);
    let preview_clear = clear_pending_sync_preview_state(&state.pending_sync_preview);
    state.cancel_sync_operations();
    let store = Arc::clone(&state.store);
    run_store(store, |store| {
        store.lock();
        Ok(())
    })
    .await?;
    let clipboard_clear = clear_clipboard_if_owned(app, Arc::clone(&state.clipboard), None).await;
    restore_clear?;
    preview_clear?;
    clipboard_clear
}

#[tauri::command]
pub async fn list_entries(
    state: State<'_, AppState>,
    query: Option<String>,
    filter: Option<String>,
    sort: Option<String>,
) -> VaultResult<Vec<EntrySummary>> {
    let store = Arc::clone(&state.store);
    run_store(store, move |store| {
        store.list_entries(query.as_deref(), filter.as_deref(), sort.as_deref())
    })
    .await
}

#[tauri::command]
pub async fn vault_overview(state: State<'_, AppState>) -> VaultResult<VaultOverview> {
    let store = Arc::clone(&state.store);
    run_store(store, VaultStore::overview).await
}

#[tauri::command]
pub async fn get_entry(state: State<'_, AppState>, id: String) -> VaultResult<VaultEntry> {
    let store = Arc::clone(&state.store);
    run_store(store, move |store| store.get_entry(&id)).await
}

#[tauri::command]
pub async fn save_entry(
    app: AppHandle,
    state: State<'_, AppState>,
    input: EntryInput,
) -> VaultResult<EntrySummary> {
    let store = Arc::clone(&state.store);
    let saved = run_store(store, move |store| store.save_entry(input)).await?;
    schedule_auto_webdav_backup(&app, &state);
    schedule_auto_webdav_sync(&app, &state);
    Ok(saved)
}

#[tauri::command]
pub async fn delete_entry(
    app: AppHandle,
    state: State<'_, AppState>,
    id: String,
    expected_revision: u64,
) -> VaultResult<()> {
    let store = Arc::clone(&state.store);
    run_store(store, move |store| {
        store.delete_entry(&id, expected_revision)
    })
    .await?;
    schedule_auto_webdav_backup(&app, &state);
    schedule_auto_webdav_sync(&app, &state);
    Ok(())
}

#[tauri::command]
pub async fn set_favorite(
    app: AppHandle,
    state: State<'_, AppState>,
    id: String,
    favorite: bool,
    expected_revision: u64,
) -> VaultResult<u64> {
    let store = Arc::clone(&state.store);
    let revision = run_store(store, move |store| {
        store.set_favorite(&id, favorite, expected_revision)
    })
    .await?;
    schedule_auto_webdav_backup(&app, &state);
    schedule_auto_webdav_sync(&app, &state);
    Ok(revision)
}

#[tauri::command]
pub async fn generate_password(options: GeneratorOptions) -> VaultResult<GeneratedPassword> {
    tauri::async_runtime::spawn_blocking(move || generator::generate_password(&options))
        .await
        .map_err(|_| VaultError::StateUnavailable)?
}

#[tauri::command]
pub async fn get_settings(state: State<'_, AppState>) -> VaultResult<VaultSettings> {
    let store = Arc::clone(&state.store);
    run_store(store, VaultStore::settings).await
}

#[tauri::command]
pub async fn update_settings(
    app: AppHandle,
    state: State<'_, AppState>,
    settings: VaultSettings,
) -> VaultResult<()> {
    let store = Arc::clone(&state.store);
    run_store(store, move |store| store.update_settings(settings)).await?;
    schedule_auto_webdav_backup(&app, &state);
    schedule_auto_webdav_sync(&app, &state);
    Ok(())
}

#[tauri::command]
pub async fn webdav_sync_status(state: State<'_, AppState>) -> VaultResult<WebDavSyncStatus> {
    let status = run_store(Arc::clone(&state.store), VaultStore::webdav_sync_status).await?;
    Ok(with_session_auto_check(status, &state))
}

fn with_session_auto_check(mut status: WebDavSyncStatus, state: &AppState) -> WebDavSyncStatus {
    let checked_at = state.last_auto_check_at.load(Ordering::Acquire);
    if status.configured && status.automatic && checked_at != 0 {
        status.last_auto_check_at = Some(checked_at);
    }
    status
}

#[tauri::command]
pub async fn set_webdav_auto_sync(
    app: AppHandle,
    state: State<'_, AppState>,
    enabled: bool,
) -> VaultResult<WebDavSyncStatus> {
    let _operation = acquire_manual_sync_guard(&state).await?;
    let status = run_store(Arc::clone(&state.store), move |store| {
        store.set_webdav_auto_sync(enabled)
    })
    .await?;
    state.last_auto_check_at.store(0, Ordering::Release);
    state
        .auto_sync_schedule_sequence
        .fetch_add(1, Ordering::AcqRel);
    state.auto_sync_poll_sequence.fetch_add(1, Ordering::AcqRel);
    if enabled {
        schedule_auto_webdav_sync(&app, &state);
        start_auto_webdav_sync_poller(&app, &state);
    }
    let _ = app.emit("ciphernest://webdav-sync-status", ());
    Ok(status)
}

#[tauri::command]
pub async fn create_webdav_sync(
    app: AppHandle,
    state: State<'_, AppState>,
    mut credentials: WebDavCredentialsInput,
) -> VaultResult<WebDavCreateResult> {
    let _operation = acquire_manual_sync_guard(&state).await?;
    let authorized_epoch = *state.sync_cancel_epoch.borrow();
    let context = run_store(Arc::clone(&state.store), VaultStore::prepare_new_sync).await?;
    let client = take_webdav_client(&mut credentials)?;
    let (material, recovery_code) = sync::generate_recovery_material()?;
    let device_id = Uuid::new_v4().to_string();
    let timestamp = now_ms();
    let cursor = await_sync_network(
        &state.sync_cancel_epoch,
        authorized_epoch,
        client.create_remote(&material, &device_id, &context.content, timestamp),
    )
    .await?;
    require_cursor_checkpoint(&cursor, false)?;
    let sync_state = client.state_for_created_remote(
        &material,
        &device_id,
        context.generation,
        timestamp,
        &cursor,
    )?;
    if sync_state.sync_id() != material.sync_id() {
        return Err(SyncError::InvalidLocalState.into());
    }
    require_state_matches_client(&client, &sync_state)?;
    let expected_vault_id = context.vault_id;
    let expected_session_id = context.session_id;
    let captured_generation = context.generation;
    let status = run_store(Arc::clone(&state.store), move |store| {
        store.install_new_sync_state(
            &expected_vault_id,
            &expected_session_id,
            captured_generation,
            &sync_state,
        )
    })
    .await?;
    state.last_auto_check_at.store(0, Ordering::Release);
    schedule_auto_webdav_sync(&app, &state);
    start_auto_webdav_sync_poller(&app, &state);
    let _ = app.emit("ciphernest://webdav-sync-status", ());
    Ok(WebDavCreateResult {
        status,
        recovery_code: recovery_code.as_str().to_owned(),
    })
}

#[tauri::command]
pub async fn inspect_webdav_sync(
    state: State<'_, AppState>,
    mut request: WebDavInspectInput,
) -> VaultResult<WebDavRemotePreview> {
    let _operation = acquire_manual_sync_guard(&state).await?;
    clear_pending_sync_preview_state(&state.pending_sync_preview)?;
    let authorized_epoch = *state.sync_cancel_epoch.borrow();
    let context = run_store(Arc::clone(&state.store), VaultStore::prepare_new_sync).await?;
    let client = take_webdav_client(&mut request.credentials)?;
    let recovery_code = Zeroizing::new(std::mem::take(&mut request.recovery_code));
    let device_id = Uuid::new_v4().to_string();
    let (joined_state, cursor) = await_sync_network(
        &state.sync_cancel_epoch,
        authorized_epoch,
        client.join_remote(
            recovery_code.as_str(),
            &device_id,
            context.generation,
            now_ms(),
        ),
    )
    .await?;
    require_sync_epoch(&state.sync_cancel_epoch, authorized_epoch)?;
    require_cursor_checkpoint(&cursor, true)?;
    require_state_matches_client(&client, &joined_state)?;
    let local_has_history =
        !context.content.entries.is_empty() || !context.content.tombstones.is_empty();
    let preview_token = Uuid::new_v4().to_string();
    replace_pending_sync_preview(
        &state.pending_sync_preview,
        PendingSyncPreview {
            token: Zeroizing::new(preview_token.clone()),
            inspected_at: Instant::now(),
            endpoint: client.endpoint().to_owned(),
            username: client.username().to_owned(),
            sync_id: joined_state.sync_id().to_owned(),
            snapshot_hash: cursor.snapshot_hash().to_owned(),
            sequence: cursor.snapshot().sequence(),
            vault_id: context.vault_id,
            session_id: context.session_id,
            local_generation: context.generation,
        },
    )?;
    Ok(WebDavRemotePreview {
        preview_token,
        item_count: cursor.snapshot().content().entries.len(),
        updated_at: cursor.snapshot().created_at(),
        sequence: cursor.snapshot().sequence(),
        sync_id_short: joined_state.sync_id().chars().take(8).collect(),
        checkpoint_trusted: false,
        local_has_history,
    })
}

#[tauri::command]
pub async fn join_webdav_sync(
    app: AppHandle,
    state: State<'_, AppState>,
    mut request: WebDavJoinInput,
) -> VaultResult<WebDavSyncOutcome> {
    let _operation = acquire_manual_sync_guard(&state).await?;
    let authorized_epoch = *state.sync_cancel_epoch.borrow();
    let context = run_store(Arc::clone(&state.store), VaultStore::prepare_new_sync).await?;
    let client = take_webdav_client(&mut request.credentials)?;
    let preview_token = Zeroizing::new(std::mem::take(&mut request.preview_token));
    let pending = take_pending_sync_preview(&state.pending_sync_preview, preview_token.as_str())?;
    if pending.endpoint != client.endpoint()
        || pending.username != client.username()
        || pending.vault_id != context.vault_id
        || pending.session_id != context.session_id
        || pending.local_generation != context.generation
    {
        return Err(VaultError::PendingSyncPreviewUnavailable);
    }
    require_join_replace_confirmation(&context.content, request.mode, request.confirm_replace)?;
    let recovery_code = Zeroizing::new(std::mem::take(&mut request.recovery_code));
    let device_id = Uuid::new_v4().to_string();
    let timestamp = now_ms();
    let (mut sync_state, cursor) = await_sync_network(
        &state.sync_cancel_epoch,
        authorized_epoch,
        client.join_remote(
            recovery_code.as_str(),
            &device_id,
            context.generation,
            timestamp,
        ),
    )
    .await?;
    require_sync_epoch(&state.sync_cancel_epoch, authorized_epoch)?;
    require_cursor_checkpoint(&cursor, true)?;
    require_state_matches_client(&client, &sync_state)?;
    if pending.sync_id != sync_state.sync_id()
        || pending.snapshot_hash != cursor.snapshot_hash()
        || pending.sequence != cursor.snapshot().sequence()
    {
        return Err(VaultError::PendingSyncPreviewUnavailable);
    }
    let target_generation = next_sync_generation(context.generation)?;

    match request.mode {
        WebDavJoinMode::Remote => {
            let content = cursor.snapshot().content();
            client.accept_fetched_for_sync(
                &mut sync_state,
                &cursor,
                target_generation,
                timestamp,
            )?;
            let sequence = cursor.snapshot().sequence();
            let expected_vault_id = context.vault_id;
            let expected_session_id = context.session_id;
            let expected_generation = context.generation;
            let status = run_store(Arc::clone(&state.store), move |store| {
                store.install_joined_sync_state(
                    &expected_vault_id,
                    &expected_session_id,
                    expected_generation,
                    &sync_state,
                    content,
                )
            })
            .await?;
            state.last_auto_check_at.store(0, Ordering::Release);
            schedule_auto_webdav_backup(&app, &state);
            schedule_auto_webdav_sync(&app, &state);
            start_auto_webdav_sync_poller(&app, &state);
            let _ = app.emit("ciphernest://webdav-sync-status", ());
            Ok(WebDavSyncOutcome {
                kind: WebDavSyncOutcomeKind::Downloaded,
                conflicts: 0,
                sequence,
                status,
            })
        }
        WebDavJoinMode::Merge => {
            let merged = sync::merge_for_join(&context.content, cursor.snapshot(), timestamp)?;
            let conflict_count = merged.conflicts.len();
            let merged_content = merged.content.clone();
            let committed = await_sync_network(
                &state.sync_cancel_epoch,
                authorized_epoch,
                client.commit_for_sync(
                    &mut sync_state,
                    &cursor,
                    &merged_content,
                    target_generation,
                    timestamp,
                ),
            )
            .await?;
            require_sync_epoch(&state.sync_cancel_epoch, authorized_epoch)?;
            let sequence = committed.snapshot().sequence();
            let expected_vault_id = context.vault_id;
            let expected_session_id = context.session_id;
            let expected_generation = context.generation;
            let status = run_store(Arc::clone(&state.store), move |store| {
                store.install_joined_sync_state(
                    &expected_vault_id,
                    &expected_session_id,
                    expected_generation,
                    &sync_state,
                    merged_content,
                )
            })
            .await?;
            state.last_auto_check_at.store(0, Ordering::Release);
            schedule_auto_webdav_backup(&app, &state);
            schedule_auto_webdav_sync(&app, &state);
            start_auto_webdav_sync_poller(&app, &state);
            let _ = app.emit("ciphernest://webdav-sync-status", ());
            Ok(WebDavSyncOutcome {
                kind: WebDavSyncOutcomeKind::Merged,
                conflicts: conflict_count,
                sequence,
                status,
            })
        }
    }
}

#[tauri::command]
pub async fn sync_webdav_now(
    app: AppHandle,
    state: State<'_, AppState>,
) -> VaultResult<WebDavSyncOutcome> {
    let _operation = acquire_manual_sync_guard(&state).await?;
    let authorized_epoch = *state.sync_cancel_epoch.borrow();
    let context = run_store(Arc::clone(&state.store), VaultStore::prepare_existing_sync).await?;
    let mut attempt = AutoSyncAttempt::new(&context);
    let mut outcome =
        run_existing_sync_context(&app, &state, context, authorized_epoch, None, &mut attempt)
            .await?;
    outcome.status = with_session_auto_check(outcome.status, &state);
    let _ = app.emit("ciphernest://webdav-sync-status", ());
    Ok(outcome)
}

async fn run_existing_sync_context(
    app: &AppHandle,
    state: &AppState,
    mut context: ExistingSyncContext,
    authorized_epoch: u64,
    auto_epoch: Option<u64>,
    attempt: &mut AutoSyncAttempt,
) -> VaultResult<WebDavSyncOutcome> {
    let client = WebDavClient::from_local_state(&context.state)?;
    let timestamp = now_ms();
    let mut cursor = await_existing_sync_network(
        state,
        authorized_epoch,
        auto_epoch,
        client.fetch_for_sync(&context.state),
    )
    .await?;
    require_cursor_checkpoint(&cursor, true)?;

    for commit_attempt in 0..MAX_SYNC_COMMIT_ATTEMPTS {
        let base = context
            .state
            .base_snapshot()
            .cloned()
            .ok_or(SyncError::InvalidLocalState)?;
        let local_changed = !sync_contents_equal(&context.content, &base.content());
        let remote_changed = cursor.snapshot().sequence() != base.sequence();

        if !local_changed && !remote_changed {
            let no_op_background_check = auto_epoch.is_some()
                && context.state.auto_warning().is_none()
                && !context.state.auto_commit_inflight();
            client.accept_fetched_for_sync(
                &mut context.state,
                &cursor,
                context.generation,
                timestamp,
            )?;
            context.state.clear_auto_issue();
            let sequence = cursor.snapshot().sequence();
            require_existing_sync_epoch(state, authorized_epoch, auto_epoch)?;
            let status = if no_op_background_check {
                let vault_id = context.vault_id;
                let session_id = context.session_id;
                let generation = context.generation;
                let digest = context.state_digest;
                run_store(Arc::clone(&state.store), move |store| {
                    store.observe_auto_sync_unchanged(&vault_id, &session_id, generation, &digest)
                })
                .await?
            } else {
                commit_existing_sync_context(state, context, None, auto_epoch.is_some()).await?
            };
            return Ok(WebDavSyncOutcome {
                kind: WebDavSyncOutcomeKind::UpToDate,
                conflicts: 0,
                sequence,
                status,
            });
        }

        if !local_changed && remote_changed {
            let content = cursor.snapshot().content();
            let target_generation = next_sync_generation(context.generation)?;
            client.accept_fetched_for_sync(
                &mut context.state,
                &cursor,
                target_generation,
                timestamp,
            )?;
            context.state.clear_auto_issue();
            let sequence = cursor.snapshot().sequence();
            require_existing_sync_epoch(state, authorized_epoch, auto_epoch)?;
            let status =
                commit_existing_sync_context(state, context, Some(content), auto_epoch.is_some())
                    .await?;
            schedule_auto_webdav_backup(app, &app.state::<AppState>());
            return Ok(WebDavSyncOutcome {
                kind: WebDavSyncOutcomeKind::Downloaded,
                conflicts: 0,
                sequence,
                status,
            });
        }

        if local_changed && !remote_changed {
            prepare_auto_commit_if_needed(state, &mut context, attempt, auto_epoch).await?;
            match await_existing_sync_network(
                state,
                authorized_epoch,
                auto_epoch,
                client.commit_for_sync(
                    &mut context.state,
                    &cursor,
                    &context.content,
                    context.generation,
                    timestamp,
                ),
            )
            .await
            {
                Ok(committed) => {
                    attempt.commit_confirmed = auto_epoch.is_some();
                    context.state.clear_auto_issue();
                    let sequence = committed.snapshot().sequence();
                    require_existing_sync_epoch(state, authorized_epoch, auto_epoch)?;
                    let status =
                        commit_existing_sync_context(state, context, None, auto_epoch.is_some())
                            .await?;
                    return Ok(WebDavSyncOutcome {
                        kind: WebDavSyncOutcomeKind::Uploaded,
                        conflicts: 0,
                        sequence,
                        status,
                    });
                }
                Err(SyncNetworkError::Sync(SyncError::ConcurrentUpdate))
                    if commit_attempt + 1 < MAX_SYNC_COMMIT_ATTEMPTS =>
                {
                    cursor = await_existing_sync_network(
                        state,
                        authorized_epoch,
                        auto_epoch,
                        client.fetch_for_sync(&context.state),
                    )
                    .await?;
                    require_cursor_checkpoint(&cursor, true)?;
                    continue;
                }
                Err(error) => return Err(error.into()),
            }
        }

        let merged = sync::merge_three_way(&base, &context.content, cursor.snapshot(), timestamp)?;
        let conflict_count = merged.conflicts.len();
        let merged_content = merged.content.clone();
        let target_generation = next_sync_generation(context.generation)?;
        prepare_auto_commit_if_needed(state, &mut context, attempt, auto_epoch).await?;
        match await_existing_sync_network(
            state,
            authorized_epoch,
            auto_epoch,
            client.commit_for_sync(
                &mut context.state,
                &cursor,
                &merged_content,
                target_generation,
                timestamp,
            ),
        )
        .await
        {
            Ok(committed) => {
                attempt.commit_confirmed = auto_epoch.is_some();
                context.state.clear_auto_issue();
                let sequence = committed.snapshot().sequence();
                require_existing_sync_epoch(state, authorized_epoch, auto_epoch)?;
                let status = commit_existing_sync_context(
                    state,
                    context,
                    Some(merged_content),
                    auto_epoch.is_some(),
                )
                .await?;
                schedule_auto_webdav_backup(app, &app.state::<AppState>());
                return Ok(WebDavSyncOutcome {
                    kind: WebDavSyncOutcomeKind::Merged,
                    conflicts: conflict_count,
                    sequence,
                    status,
                });
            }
            Err(SyncNetworkError::Sync(SyncError::ConcurrentUpdate))
                if commit_attempt + 1 < MAX_SYNC_COMMIT_ATTEMPTS =>
            {
                cursor = await_existing_sync_network(
                    state,
                    authorized_epoch,
                    auto_epoch,
                    client.fetch_for_sync(&context.state),
                )
                .await?;
                require_cursor_checkpoint(&cursor, true)?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Err(SyncError::ConcurrentUpdate.into())
}

#[tauri::command]
pub async fn reveal_webdav_recovery_code(
    state: State<'_, AppState>,
    current_password: String,
) -> VaultResult<WebDavRecoveryCode> {
    let recovery_code = run_store(Arc::clone(&state.store), move |store| {
        let password = Zeroizing::new(current_password);
        store.webdav_recovery_code(password.as_str())
    })
    .await?;
    Ok(WebDavRecoveryCode {
        recovery_code: recovery_code.as_str().to_owned(),
    })
}

#[tauri::command]
pub async fn disable_webdav_sync(
    app: AppHandle,
    state: State<'_, AppState>,
    current_password: String,
) -> VaultResult<()> {
    let _operation = acquire_manual_sync_guard(&state).await?;
    run_store(Arc::clone(&state.store), move |store| {
        let password = Zeroizing::new(current_password);
        store.disable_webdav_sync(password.as_str())
    })
    .await?;
    state.last_auto_check_at.store(0, Ordering::Release);
    state
        .auto_sync_schedule_sequence
        .fetch_add(1, Ordering::AcqRel);
    state.auto_sync_poll_sequence.fetch_add(1, Ordering::AcqRel);
    let _ = app.emit("ciphernest://webdav-sync-status", ());
    Ok(())
}

#[tauri::command]
pub async fn security_report(state: State<'_, AppState>) -> VaultResult<SecurityReport> {
    let store = Arc::clone(&state.store);
    run_store(store, VaultStore::security_report).await
}

#[tauri::command]
pub async fn change_master_password(
    app: AppHandle,
    state: State<'_, AppState>,
    current_password: String,
    new_password: String,
) -> VaultResult<MasterPasswordChangeResult> {
    let store = Arc::clone(&state.store);
    let result = run_store(store, move |store| {
        let current = Zeroizing::new(current_password);
        let new = Zeroizing::new(new_password);
        store.change_master_password(current.as_str(), new.as_str())
    })
    .await?;
    state.cancel_sync_operations();
    clear_pending_sync_preview_state(&state.pending_sync_preview)?;
    schedule_auto_webdav_backup(&app, &state);
    schedule_auto_webdav_sync(&app, &state);
    start_auto_webdav_sync_poller(&app, &state);
    Ok(result)
}

#[tauri::command]
pub async fn copy_secret(
    app: AppHandle,
    state: State<'_, AppState>,
    secret: String,
) -> VaultResult<()> {
    if secret.is_empty() || secret.len() > 4096 {
        return Err(VaultError::InvalidInput("复制内容长度无效".into()));
    }
    let store = Arc::clone(&state.store);
    let clipboard = Arc::clone(&state.clipboard);
    let token = Uuid::new_v4().to_string();
    let timer_token = token.clone();
    let app_for_write = app.clone();

    let ttl = tauri::async_runtime::spawn_blocking(move || {
        let secret = Zeroizing::new(secret);
        // Keep the vault lock until the write is complete. Otherwise an explicit or
        // lifecycle lock can clear the clipboard between the authorization check and
        // this write, leaving a newly copied secret behind in a locked session.
        let mut store = store.lock().map_err(|_| VaultError::StateUnavailable)?;
        let ttl = store.prepare_sensitive_action()?;
        let mut lease = clipboard.lock().map_err(|_| VaultError::Clipboard)?;
        app_for_write
            .clipboard()
            .write_text(secret.as_str())
            .map_err(|_| VaultError::Clipboard)?;
        let digest: [u8; 32] = Sha256::digest(secret.as_bytes()).into();
        *lease = Some(ClipboardLease { token, digest });
        Ok::<u32, VaultError>(ttl)
    })
    .await
    .map_err(|_| VaultError::Clipboard)??;

    let timer_clipboard = Arc::clone(&state.clipboard);
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(ttl as u64));
        clear_clipboard_if_owned_blocking(&app, &timer_clipboard, Some(&timer_token));
    });
    Ok(())
}

#[tauri::command]
pub async fn clear_owned_clipboard(app: AppHandle, state: State<'_, AppState>) -> VaultResult<()> {
    clear_clipboard_if_owned(app, Arc::clone(&state.clipboard), None).await
}

#[tauri::command]
pub async fn export_backup(
    app: AppHandle,
    state: State<'_, AppState>,
) -> VaultResult<Option<String>> {
    let store = Arc::clone(&state.store);
    run_store(Arc::clone(&store), |store| {
        store.prepare_sensitive_action().map(|_| ())
    })
    .await?;

    let selected = app
        .dialog()
        .file()
        .set_title("导出加密备份")
        .set_file_name(format!("ciphernest-backup-{}.cnvault", now_ms()))
        .add_filter("CipherNest 加密保险库", &["cnvault"])
        .blocking_save_file();
    let Some(selected) = selected else {
        return Ok(None);
    };
    let target = selected
        .into_path()
        .map_err(|_| VaultError::InvalidInput("备份路径无效".into()))?;
    let display_name = target
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("加密备份")
        .to_string();
    run_store(store, move |store| store.export_to(&target)).await?;
    Ok(Some(display_name))
}

#[tauri::command]
pub async fn webdav_backup_status(state: State<'_, AppState>) -> VaultResult<WebDavBackupStatus> {
    run_store(Arc::clone(&state.store), VaultStore::remote_backup_status).await
}

#[tauri::command]
pub async fn webdav_backup_test_config(
    state: State<'_, AppState>,
    mut credentials: WebDavCredentialsInput,
) -> VaultResult<()> {
    run_store(Arc::clone(&state.store), |store| {
        store.prepare_sensitive_action().map(|_| ())
    })
    .await?;
    if credentials.app_password.is_empty() {
        let existing = run_store(Arc::clone(&state.store), VaultStore::remote_backup_config)
            .await?
            .ok_or_else(|| VaultError::InvalidInput("请输入 WebDAV 密码。".into()))?;
        if existing.endpoint != credentials.endpoint || existing.username != credentials.username {
            return Err(VaultError::InvalidInput(
                "修改 WebDAV 地址或用户名时需要重新输入密码。".into(),
            ));
        }
        credentials.app_password = existing.app_password.clone();
    }
    let client = backup_client_from_input(&credentials)?;
    client.test_read_write_delete().await
}

#[tauri::command]
pub async fn webdav_backup_save_config(
    app: AppHandle,
    state: State<'_, AppState>,
    mut credentials: WebDavCredentialsInput,
    automatic: bool,
) -> VaultResult<WebDavBackupStatus> {
    let configuration_epoch = state.backup_configuration_epoch.load(Ordering::Acquire);
    let (vault_id, session_id) = run_store(
        Arc::clone(&state.store),
        VaultStore::remote_backup_session_identity,
    )
    .await?;
    let existing = match run_store(Arc::clone(&state.store), VaultStore::remote_backup_config).await
    {
        Ok(config) => config,
        Err(VaultError::WebDavBackup(_)) if !credentials.app_password.is_empty() => None,
        Err(error) => return Err(error),
    };
    if credentials.app_password.is_empty() {
        let saved = existing
            .as_ref()
            .ok_or_else(|| VaultError::InvalidInput("请输入 WebDAV 密码。".into()))?;
        if saved.endpoint != credentials.endpoint || saved.username != credentials.username {
            return Err(VaultError::InvalidInput(
                "修改 WebDAV 地址或用户名时需要重新输入密码。".into(),
            ));
        }
        credentials.app_password = saved.app_password.clone();
    }
    run_store(Arc::clone(&state.store), |store| {
        store.prepare_sensitive_action().map(|_| ())
    })
    .await?;
    let client = backup_client_from_input(&credentials)?;
    client.test_read_write_delete().await?;
    let same_target = existing.as_ref().is_some_and(|saved| {
        saved.endpoint == credentials.endpoint
            && saved.username == credentials.username
            && saved.app_password == credentials.app_password
    });
    let config = BackupConfig {
        endpoint: std::mem::take(&mut credentials.endpoint),
        username: std::mem::take(&mut credentials.username),
        app_password: std::mem::take(&mut credentials.app_password),
        automatic,
        last_upload_at: same_target
            .then(|| existing.as_ref().and_then(|saved| saved.last_upload_at))
            .flatten(),
        last_uploaded_generation: same_target
            .then(|| {
                existing
                    .as_ref()
                    .and_then(|saved| saved.last_uploaded_generation)
            })
            .flatten(),
        last_uploaded_sha256: same_target
            .then(|| {
                existing
                    .as_ref()
                    .and_then(|saved| saved.last_uploaded_sha256.clone())
            })
            .flatten(),
        warning: None,
    };
    let queue_guard = state.backup_upload_queue.lock().await;
    if state.backup_configuration_epoch.load(Ordering::Acquire) != configuration_epoch {
        return Err(VaultError::InvalidInput(
            "备份配置在测试期间已变更，请重新提交。".into(),
        ));
    }
    let status = run_store(Arc::clone(&state.store), move |store| {
        store.save_remote_backup_config(&vault_id, &session_id, &config)
    })
    .await?;
    state
        .backup_configuration_epoch
        .fetch_add(1, Ordering::AcqRel);
    drop(queue_guard);
    if status.automatic {
        schedule_auto_webdav_backup(&app, &state);
    }
    Ok(status)
}

#[tauri::command]
pub async fn webdav_backup_disable(app: AppHandle, state: State<'_, AppState>) -> VaultResult<()> {
    // Invalidate debounced jobs first, then wait for any already-started PUT
    // and readback to finish before reporting that backup is disabled.
    state
        .backup_schedule_sequence
        .fetch_add(1, Ordering::AcqRel);
    state
        .backup_configuration_epoch
        .fetch_add(1, Ordering::AcqRel);
    let _queue_guard = state.backup_upload_queue.lock().await;
    run_store(Arc::clone(&state.store), VaultStore::disable_remote_backup).await?;
    let _ = app.emit("ciphernest://webdav-backup-status", ());
    Ok(())
}

#[tauri::command]
pub async fn webdav_backup_upload(
    app: AppHandle,
    state: State<'_, AppState>,
) -> VaultResult<WebDavBackupItem> {
    // An explicit upload supersedes a pending debounced automatic upload.
    state
        .backup_schedule_sequence
        .fetch_add(1, Ordering::AcqRel);
    let _queue_guard = state.backup_upload_queue.lock().await;
    let authorized_epoch = *state.sync_cancel_epoch.borrow();
    let context = run_store(Arc::clone(&state.store), VaultStore::remote_backup_context).await?;
    require_sync_epoch(&state.sync_cancel_epoch, authorized_epoch)?;
    let client = WebDavBackupClient::new(
        &context.config.endpoint,
        context.config.username.clone(),
        context.config.app_password.clone(),
    )?;
    let item = await_backup_network(
        &state.sync_cancel_epoch,
        authorized_epoch,
        client.upload(
            &context.bytes,
            &context.vault_id,
            context.generation,
            context.updated_at,
        ),
    )
    .await?;
    require_sync_epoch(&state.sync_cancel_epoch, authorized_epoch)?;
    let uploaded_at = now_ms();
    run_store(Arc::clone(&state.store), move |store| {
        store.mark_remote_backup_uploaded(&context, uploaded_at)
    })
    .await
    .map_err(|error| {
        VaultError::WebDavBackup(format!(
            "备份已上传并回读校验，但本机状态记录失败；远端可能已有该备份：{error}"
        ))
    })?;
    let _ = app.emit("ciphernest://webdav-backup-status", ());
    Ok(item)
}

#[tauri::command]
pub async fn webdav_backup_list(state: State<'_, AppState>) -> VaultResult<Vec<WebDavBackupItem>> {
    let config = run_store(Arc::clone(&state.store), VaultStore::remote_backup_config)
        .await?
        .ok_or(VaultError::BackupNotConfigured)?;
    let client = WebDavBackupClient::new(
        &config.endpoint,
        config.username.clone(),
        config.app_password.clone(),
    )?;
    client.list().await
}

#[tauri::command]
pub async fn webdav_backup_list_with_credentials(
    credentials: WebDavCredentialsInput,
) -> VaultResult<Vec<WebDavBackupItem>> {
    let client = backup_client_from_input(&credentials)?;
    client.list().await
}

#[tauri::command]
pub async fn webdav_backup_prepare_restore(
    state: State<'_, AppState>,
    file_name: String,
) -> VaultResult<RestoreSelection> {
    let config = run_store(Arc::clone(&state.store), VaultStore::remote_backup_config)
        .await?
        .ok_or(VaultError::BackupNotConfigured)?;
    let client = WebDavBackupClient::new(
        &config.endpoint,
        config.username.clone(),
        config.app_password.clone(),
    )?;
    // The user selected a recovery point through this device's saved backup
    // connection. Keep that device setting when the selected vault replaces
    // its contents, including when the source vault ID differs.
    prepare_remote_restore(&state, client, file_name, Some(config)).await
}

#[tauri::command]
pub async fn webdav_backup_prepare_restore_with_credentials(
    state: State<'_, AppState>,
    mut credentials: WebDavCredentialsInput,
    file_name: String,
    save_connection_after_restore: bool,
) -> VaultResult<RestoreSelection> {
    let client = backup_client_from_input(&credentials)?;
    let backup_config_after_restore = save_connection_after_restore.then(|| BackupConfig {
        endpoint: std::mem::take(&mut credentials.endpoint),
        username: std::mem::take(&mut credentials.username),
        app_password: std::mem::take(&mut credentials.app_password),
        automatic: true,
        last_upload_at: None,
        last_uploaded_generation: None,
        last_uploaded_sha256: None,
        warning: None,
    });
    prepare_remote_restore(&state, client, file_name, backup_config_after_restore).await
}

fn backup_client_from_input(
    credentials: &WebDavCredentialsInput,
) -> VaultResult<WebDavBackupClient> {
    WebDavBackupClient::new(
        &credentials.endpoint,
        credentials.username.clone(),
        credentials.app_password.clone(),
    )
}

async fn prepare_remote_restore(
    state: &State<'_, AppState>,
    client: WebDavBackupClient,
    file_name: String,
    backup_config_after_restore: Option<BackupConfig>,
) -> VaultResult<RestoreSelection> {
    let authorized_epoch = *state.sync_cancel_epoch.borrow();
    clear_pending_restore_state(&state.pending_restore)?;
    clear_pending_sync_preview_state(&state.pending_sync_preview)?;
    if !webdav_backup::valid_backup_name(&file_name) {
        return Err(VaultError::InvalidInput("远端备份文件名无效。".into()));
    }
    let bytes = Zeroizing::new(client.download(&file_name).await?);
    require_sync_epoch(&state.sync_cancel_epoch, authorized_epoch)?;
    let file_size = bytes.len() as u64;
    let envelope = parse_envelope_bytes(&bytes)?;
    let token = Uuid::new_v4().to_string();
    replace_pending_restore(
        &state.pending_restore,
        PendingRestore {
            token: Zeroizing::new(token.clone()),
            selected_at: Instant::now(),
            file_name: file_name.clone(),
            envelope,
            verified: None,
            target_fingerprint: None,
            backup_config_after_restore,
        },
    )?;
    Ok(RestoreSelection {
        token,
        file_name,
        file_size,
    })
}

#[tauri::command]
pub async fn select_backup_for_restore(
    app: AppHandle,
    state: State<'_, AppState>,
) -> VaultResult<Option<RestoreSelection>> {
    // Starting a new selection invalidates any previously verified plaintext and root key.
    clear_pending_restore_state(&state.pending_restore)?;
    clear_pending_sync_preview_state(&state.pending_sync_preview)?;
    let mut picker = app
        .dialog()
        .file()
        .set_title("选择要恢复的加密备份")
        .add_filter("CipherNest 加密保险库", &["cnvault"]);
    if let Ok(app_data) = app.path().app_data_dir() {
        let automatic_backups = app_data.join("backups");
        if automatic_backups.is_dir() {
            picker = picker.set_directory(automatic_backups);
        }
    }
    let selected = picker.blocking_pick_file();
    let Some(selected) = selected else {
        return Ok(None);
    };
    let source = selected
        .into_path()
        .map_err(|_| VaultError::InvalidInput("备份路径无效".into()))?;
    let file_name = safe_backup_file_name(&source);
    let (envelope, file_size) =
        tauri::async_runtime::spawn_blocking(move || read_bounded_backup_candidate(&source))
            .await
            .map_err(|_| VaultError::StateUnavailable)??;
    let token = Uuid::new_v4().to_string();
    let pending = PendingRestore {
        token: Zeroizing::new(token.clone()),
        selected_at: Instant::now(),
        file_name: file_name.clone(),
        envelope,
        verified: None,
        target_fingerprint: None,
        backup_config_after_restore: None,
    };
    replace_pending_restore(&state.pending_restore, pending)?;
    Ok(Some(RestoreSelection {
        token,
        file_name,
        file_size,
    }))
}

#[tauri::command]
pub async fn inspect_selected_backup(
    state: State<'_, AppState>,
    token: String,
    master_password: String,
) -> VaultResult<RestorePreview> {
    let token = Zeroizing::new(token);
    let password = Zeroizing::new(master_password);
    let envelope = pending_envelope_for_inspection(&state.pending_restore, &token)?;
    let token_for_failure = token.clone();
    let decrypted = tauri::async_runtime::spawn_blocking(move || {
        prepare_verified_restore(password.as_str(), envelope)
    })
    .await;

    let prepared = match decrypted {
        Ok(Ok(prepared)) => prepared,
        Ok(Err(_)) => {
            clear_pending_restore_if_token(&state.pending_restore, &token_for_failure)?;
            return Err(VaultError::UnlockFailed);
        }
        Err(_) => {
            clear_pending_restore_if_token(&state.pending_restore, &token_for_failure)?;
            return Err(VaultError::StateUnavailable);
        }
    };

    let vault_id = Uuid::parse_str(&prepared.verified.data.vault_id).map_err(|_| {
        let _ = clear_pending_restore_if_token(&state.pending_restore, &token);
        VaultError::InvalidVault
    })?;
    let canonical_vault_id = vault_id.to_string();
    let preview = RestorePreview {
        file_name: pending_file_name(&state.pending_restore, &token)?,
        item_count: prepared.verified.data.entries.len(),
        updated_at: prepared.source_updated_at,
        generation: prepared.source_generation,
        vault_id_short: canonical_vault_id[..8].to_string(),
    };
    let target_fingerprint = match run_store(Arc::clone(&state.store), |store| {
        store.restore_target_fingerprint()
    })
    .await
    {
        Ok(fingerprint) => fingerprint,
        Err(error) => {
            clear_pending_restore_if_token(&state.pending_restore, &token)?;
            return Err(error);
        }
    };
    commit_verified_restore(
        &state.pending_restore,
        &token,
        prepared.envelope,
        prepared.verified,
        target_fingerprint,
    )?;
    Ok(preview)
}

#[tauri::command]
pub async fn apply_selected_backup(
    app: AppHandle,
    state: State<'_, AppState>,
    token: String,
) -> VaultResult<VaultStatus> {
    let _sync_operation = acquire_manual_sync_guard(&state).await?;
    state
        .backup_schedule_sequence
        .fetch_add(1, Ordering::AcqRel);
    let backup_queue_guard = state.backup_upload_queue.lock().await;
    let token = Zeroizing::new(token);
    let store = Arc::clone(&state.store);
    let pending_restore = Arc::clone(&state.pending_restore);
    let applied = tauri::async_runtime::spawn_blocking(move || {
        // Keep the pending-state lock until the store lock is acquired. A concurrent explicit
        // lock therefore deterministically wins before apply, or runs after apply and leaves the
        // newly restored vault locked; it cannot be silently undone by this operation.
        let mut pending_guard = pending_restore
            .lock()
            .map_err(|_| VaultError::StateUnavailable)?;
        if pending_guard.as_ref().is_some_and(pending_restore_expired) {
            *pending_guard = None;
            return Err(VaultError::PendingRestoreUnavailable);
        }
        if pending_guard
            .as_ref()
            .is_none_or(|pending| pending.token.as_str() != token.as_str())
        {
            return Err(VaultError::PendingRestoreUnavailable);
        }
        let pending = pending_guard
            .take()
            .ok_or(VaultError::PendingRestoreUnavailable)?;
        let verified = pending
            .verified
            .ok_or(VaultError::PendingRestoreNotVerified)?;
        let mut store = store.lock().map_err(|_| VaultError::StateUnavailable)?;
        drop(pending_guard);

        ensure_restore_target_unchanged(&store, pending.target_fingerprint)?;
        store.replace_with_verified_backup_and_config(
            pending.envelope,
            verified.root_key,
            verified.data,
            pending.backup_config_after_restore,
        )?;
        Ok(store.status().0)
    })
    .await
    .map_err(|_| VaultError::StateUnavailable)?;
    let status = applied?;
    state.cancel_sync_operations();
    clear_pending_sync_preview_state(&state.pending_sync_preview)?;
    state
        .backup_configuration_epoch
        .fetch_add(1, Ordering::AcqRel);
    drop(backup_queue_guard);
    schedule_auto_webdav_backup(&app, &state);
    let _ = app.emit("ciphernest://webdav-backup-status", ());
    Ok(status)
}

#[tauri::command]
pub fn cancel_pending_restore(state: State<'_, AppState>) -> VaultResult<()> {
    clear_pending_restore_state(&state.pending_restore)
}

#[tauri::command]
pub async fn touch_activity(state: State<'_, AppState>) -> VaultResult<()> {
    let store = Arc::clone(&state.store);
    run_store(store, |store| {
        store.touch();
        Ok(())
    })
    .await
}

#[tauri::command]
pub async fn handle_focus_change(
    app: AppHandle,
    state: State<'_, AppState>,
    focused: bool,
) -> VaultResult<bool> {
    let store = Arc::clone(&state.store);
    let locked = run_store(store, move |store| Ok(store.handle_focus_change(focused))).await?;
    if locked {
        state.cancel_sync_operations();
        clear_pending_restore_state(&state.pending_restore)?;
        clear_pending_sync_preview_state(&state.pending_sync_preview)?;
        let _ = clear_clipboard_if_owned(app, Arc::clone(&state.clipboard), None).await;
    }
    Ok(locked)
}

fn take_webdav_client(credentials: &mut WebDavCredentialsInput) -> VaultResult<WebDavClient> {
    let endpoint = std::mem::take(&mut credentials.endpoint);
    let username = std::mem::take(&mut credentials.username);
    let app_password = std::mem::take(&mut credentials.app_password);
    WebDavClient::new(&endpoint, username, app_password).map_err(Into::into)
}

fn require_state_matches_client(
    client: &WebDavClient,
    state: &sync::LocalSyncState,
) -> VaultResult<()> {
    if state.endpoint() != client.endpoint() || state.username() != client.username() {
        return Err(SyncError::InvalidLocalState.into());
    }
    Ok(())
}

fn require_cursor_checkpoint(
    cursor: &sync::RemoteCursor,
    checkpoint_required: bool,
) -> VaultResult<()> {
    if cursor.snapshot_hash().is_empty() || cursor.checkpoint_proven() != checkpoint_required {
        return Err(SyncError::InvalidRemoteObject.into());
    }
    Ok(())
}

fn require_sync_epoch(cancel_epoch: &watch::Sender<u64>, authorized_epoch: u64) -> VaultResult<()> {
    if *cancel_epoch.borrow() != authorized_epoch {
        Err(VaultError::Locked)
    } else {
        Ok(())
    }
}

async fn await_backup_network<T, F>(
    cancel_epoch: &watch::Sender<u64>,
    authorized_epoch: u64,
    operation: F,
) -> VaultResult<T>
where
    F: Future<Output = VaultResult<T>>,
{
    let mut cancellation = cancel_epoch.subscribe();
    require_sync_epoch(cancel_epoch, authorized_epoch)?;
    tokio::select! {
        biased;
        changed = cancellation.changed() => {
            let _ = changed;
            Err(VaultError::Locked)
        }
        result = operation => result,
    }
}

async fn await_sync_network<T, F>(
    cancel_epoch: &watch::Sender<u64>,
    authorized_epoch: u64,
    operation: F,
) -> Result<T, SyncNetworkError>
where
    F: Future<Output = sync::SyncResult<T>>,
{
    let mut cancellation = cancel_epoch.subscribe();
    if *cancellation.borrow() != authorized_epoch {
        return Err(SyncNetworkError::Cancelled);
    }
    tokio::select! {
        biased;
        changed = cancellation.changed() => {
            let _ = changed;
            Err(SyncNetworkError::Cancelled)
        }
        result = operation => result.map_err(SyncNetworkError::Sync),
    }
}

fn require_existing_sync_epoch(
    state: &AppState,
    authorized_epoch: u64,
    auto_epoch: Option<u64>,
) -> VaultResult<()> {
    require_sync_epoch(&state.sync_cancel_epoch, authorized_epoch)?;
    if auto_epoch.is_some_and(|epoch| *state.auto_sync_cancel_epoch.borrow() != epoch) {
        return Err(VaultError::Locked);
    }
    Ok(())
}

async fn await_existing_sync_network<T, F>(
    state: &AppState,
    authorized_epoch: u64,
    auto_epoch: Option<u64>,
    operation: F,
) -> Result<T, SyncNetworkError>
where
    F: Future<Output = sync::SyncResult<T>>,
{
    let Some(auto_epoch) = auto_epoch else {
        return await_sync_network(&state.sync_cancel_epoch, authorized_epoch, operation).await;
    };
    let mut cancellation = state.auto_sync_cancel_epoch.subscribe();
    if *cancellation.borrow() != auto_epoch {
        return Err(SyncNetworkError::Cancelled);
    }
    tokio::select! {
        biased;
        changed = cancellation.changed() => {
            let _ = changed;
            Err(SyncNetworkError::Cancelled)
        }
        result = await_sync_network(&state.sync_cancel_epoch, authorized_epoch, operation) => result,
    }
}

async fn prepare_auto_commit_if_needed(
    state: &AppState,
    context: &mut ExistingSyncContext,
    attempt: &mut AutoSyncAttempt,
    auto_epoch: Option<u64>,
) -> VaultResult<()> {
    if auto_epoch.is_none() || attempt.commit_started {
        return Ok(());
    }
    let expected_vault_id = context.vault_id.clone();
    let expected_session_id = context.session_id.clone();
    let expected_generation = context.generation;
    let expected_digest = context.state_digest;
    let next_digest = run_store(Arc::clone(&state.store), move |store| {
        store.mark_auto_sync_commit_started(
            &expected_vault_id,
            &expected_session_id,
            expected_generation,
            &expected_digest,
        )
    })
    .await?;
    context.state.set_auto_commit_inflight(true);
    context.state_digest = next_digest;
    attempt.state_digest = next_digest;
    attempt.commit_started = true;
    Ok(())
}

fn next_sync_generation(current: u64) -> VaultResult<u64> {
    current
        .checked_add(1)
        .ok_or_else(|| VaultError::Sync("保险库版本已达到上限。".into()))
}

async fn commit_existing_sync_context(
    app_state: &AppState,
    context: ExistingSyncContext,
    content_to_apply: Option<sync::SyncContent>,
    background: bool,
) -> VaultResult<WebDavSyncStatus> {
    let store = Arc::clone(&app_state.store);
    run_store(store, move |store| {
        if background {
            store.commit_auto_sync_result(
                &context.vault_id,
                &context.session_id,
                context.generation,
                &context.state_digest,
                &context.state,
                content_to_apply,
            )
        } else {
            store.commit_sync_result(
                &context.vault_id,
                &context.session_id,
                context.generation,
                &context.state_digest,
                &context.state,
                content_to_apply,
            )
        }
    })
    .await
}

async fn run_store<T, F>(store: Arc<Mutex<VaultStore>>, operation: F) -> VaultResult<T>
where
    T: Send + 'static,
    F: FnOnce(&mut VaultStore) -> VaultResult<T> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(move || {
        let mut store = store.lock().map_err(|_| VaultError::StateUnavailable)?;
        operation(&mut store)
    })
    .await
    .map_err(|_| VaultError::StateUnavailable)?
}

fn read_bounded_backup_candidate(path: &std::path::Path) -> VaultResult<(VaultEnvelope, u64)> {
    let file = File::open(path).map_err(|_| VaultError::InvalidVault)?;
    let metadata = file.metadata().map_err(|_| VaultError::InvalidVault)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_VAULT_BYTES {
        return Err(VaultError::InvalidVault);
    }

    // The take limit remains authoritative if the file is swapped or grows after metadata().
    let mut bytes = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
    file.take(MAX_VAULT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| VaultError::InvalidVault)?;
    let file_size = bytes.len() as u64;
    if file_size == 0 || file_size > MAX_VAULT_BYTES {
        return Err(VaultError::InvalidVault);
    }
    parse_envelope_bytes(&bytes).map(|envelope| (envelope, file_size))
}

fn safe_backup_file_name(path: &std::path::Path) -> String {
    let sanitized: String = path
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_default()
        .chars()
        .filter(|character| !character.is_control())
        .take(255)
        .collect();
    if sanitized.is_empty() {
        "加密备份".into()
    } else {
        sanitized
    }
}

fn pending_restore_expired(pending: &PendingRestore) -> bool {
    pending.selected_at.elapsed() >= PENDING_RESTORE_TTL
}

fn pending_sync_preview_expired(pending: &PendingSyncPreview) -> bool {
    pending.inspected_at.elapsed() >= PENDING_SYNC_PREVIEW_TTL
}

fn clear_pending_sync_preview_state(
    pending_preview: &Arc<Mutex<Option<PendingSyncPreview>>>,
) -> VaultResult<()> {
    let mut pending = pending_preview
        .lock()
        .map_err(|_| VaultError::StateUnavailable)?;
    *pending = None;
    Ok(())
}

fn replace_pending_sync_preview(
    pending_preview: &Arc<Mutex<Option<PendingSyncPreview>>>,
    replacement: PendingSyncPreview,
) -> VaultResult<()> {
    let mut pending = pending_preview
        .lock()
        .map_err(|_| VaultError::StateUnavailable)?;
    *pending = Some(replacement);
    Ok(())
}

fn take_pending_sync_preview(
    pending_preview: &Arc<Mutex<Option<PendingSyncPreview>>>,
    token: &str,
) -> VaultResult<PendingSyncPreview> {
    let mut pending = pending_preview
        .lock()
        .map_err(|_| VaultError::StateUnavailable)?;
    if pending.as_ref().is_some_and(pending_sync_preview_expired) {
        *pending = None;
        return Err(VaultError::PendingSyncPreviewUnavailable);
    }
    if pending
        .as_ref()
        .is_none_or(|pending| pending.token.as_str() != token)
    {
        return Err(VaultError::PendingSyncPreviewUnavailable);
    }
    pending
        .take()
        .ok_or(VaultError::PendingSyncPreviewUnavailable)
}

fn clear_pending_restore_state(
    pending_restore: &Arc<Mutex<Option<PendingRestore>>>,
) -> VaultResult<()> {
    let mut pending = pending_restore
        .lock()
        .map_err(|_| VaultError::StateUnavailable)?;
    *pending = None;
    Ok(())
}

fn clear_pending_restore_if_token(
    pending_restore: &Arc<Mutex<Option<PendingRestore>>>,
    token: &str,
) -> VaultResult<()> {
    let mut pending = pending_restore
        .lock()
        .map_err(|_| VaultError::StateUnavailable)?;
    if pending
        .as_ref()
        .is_some_and(|pending| pending.token.as_str() == token)
    {
        *pending = None;
    }
    Ok(())
}

fn replace_pending_restore(
    pending_restore: &Arc<Mutex<Option<PendingRestore>>>,
    replacement: PendingRestore,
) -> VaultResult<()> {
    let mut pending = pending_restore
        .lock()
        .map_err(|_| VaultError::StateUnavailable)?;
    *pending = Some(replacement);
    Ok(())
}

fn pending_envelope_for_inspection(
    pending_restore: &Arc<Mutex<Option<PendingRestore>>>,
    token: &str,
) -> VaultResult<VaultEnvelope> {
    let mut pending = pending_restore
        .lock()
        .map_err(|_| VaultError::StateUnavailable)?;
    if pending.as_ref().is_some_and(pending_restore_expired) {
        *pending = None;
        return Err(VaultError::PendingRestoreUnavailable);
    }
    pending
        .as_ref()
        .filter(|pending| pending.token.as_str() == token)
        .map(|pending| pending.envelope.clone())
        .ok_or(VaultError::PendingRestoreUnavailable)
}

fn pending_file_name(
    pending_restore: &Arc<Mutex<Option<PendingRestore>>>,
    token: &str,
) -> VaultResult<String> {
    let mut pending = pending_restore
        .lock()
        .map_err(|_| VaultError::StateUnavailable)?;
    if pending.as_ref().is_some_and(pending_restore_expired) {
        *pending = None;
        return Err(VaultError::PendingRestoreUnavailable);
    }
    pending
        .as_ref()
        .filter(|pending| pending.token.as_str() == token)
        .map(|pending| pending.file_name.clone())
        .ok_or(VaultError::PendingRestoreUnavailable)
}

fn commit_verified_restore(
    pending_restore: &Arc<Mutex<Option<PendingRestore>>>,
    token: &str,
    envelope: VaultEnvelope,
    verified: VerifiedRestore,
    target_fingerprint: Option<[u8; 32]>,
) -> VaultResult<()> {
    let mut pending = pending_restore
        .lock()
        .map_err(|_| VaultError::StateUnavailable)?;
    if pending.as_ref().is_some_and(pending_restore_expired) {
        *pending = None;
        return Err(VaultError::PendingRestoreUnavailable);
    }
    let current = pending
        .as_mut()
        .filter(|pending| pending.token.as_str() == token)
        .ok_or(VaultError::PendingRestoreUnavailable)?;
    current.envelope = envelope;
    current.verified = Some(verified);
    current.target_fingerprint = target_fingerprint;
    Ok(())
}

fn ensure_restore_target_unchanged(
    store: &VaultStore,
    expected: Option<[u8; 32]>,
) -> VaultResult<()> {
    if store.restore_target_fingerprint()? == expected {
        Ok(())
    } else {
        Err(VaultError::RestoreTargetChanged)
    }
}

fn require_join_replace_confirmation(
    local: &SyncContent,
    mode: WebDavJoinMode,
    confirmed: bool,
) -> VaultResult<()> {
    let local_has_history = !local.entries.is_empty() || !local.tombstones.is_empty();
    if matches!(mode, WebDavJoinMode::Remote) && local_has_history && !confirmed {
        Err(VaultError::InvalidInput(
            "本机已有条目或删除记录，请明确确认以远端替换本机".into(),
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
fn take_pending_restore(
    pending_restore: &Arc<Mutex<Option<PendingRestore>>>,
    token: &str,
) -> VaultResult<PendingRestore> {
    let mut pending = pending_restore
        .lock()
        .map_err(|_| VaultError::StateUnavailable)?;
    if pending.as_ref().is_some_and(pending_restore_expired) {
        *pending = None;
        return Err(VaultError::PendingRestoreUnavailable);
    }
    if pending
        .as_ref()
        .is_none_or(|pending| pending.token.as_str() != token)
    {
        return Err(VaultError::PendingRestoreUnavailable);
    }
    pending.take().ok_or(VaultError::PendingRestoreUnavailable)
}

async fn clear_clipboard_if_owned(
    app: AppHandle,
    clipboard: Arc<Mutex<Option<ClipboardLease>>>,
    expected_token: Option<String>,
) -> VaultResult<()> {
    tauri::async_runtime::spawn_blocking(move || {
        clear_clipboard_if_owned_blocking(&app, &clipboard, expected_token.as_deref());
        Ok(())
    })
    .await
    .map_err(|_| VaultError::Clipboard)?
}

fn clear_clipboard_if_owned_blocking(
    app: &AppHandle,
    clipboard: &Arc<Mutex<Option<ClipboardLease>>>,
    expected_token: Option<&str>,
) {
    let Ok(mut lease_guard) = clipboard.lock() else {
        return;
    };
    let Some(lease) = lease_guard.as_ref() else {
        return;
    };
    if expected_token.is_some_and(|token| token != lease.token) {
        return;
    }
    let Ok(current) = app.clipboard().read_text() else {
        *lease_guard = None;
        return;
    };
    let current = Zeroizing::new(current);
    let digest: [u8; 32] = Sha256::digest(current.as_bytes()).into();
    if digest == lease.digest {
        let _ = app.clipboard().clear();
    }
    *lease_guard = None;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{
        decrypt_envelope_with_root_key, read_envelope, CipherBlock, KdfHeader, FORMAT_NAME,
        FORMAT_VERSION,
    };

    #[tokio::test]
    async fn cancelled_backup_network_drops_the_in_flight_request() {
        struct DropMarker(Arc<AtomicBool>);
        impl Drop for DropMarker {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }

        let (cancel_epoch, _) = watch::channel(0_u64);
        let request_epoch = cancel_epoch.clone();
        let dropped = Arc::new(AtomicBool::new(false));
        let dropped_for_request = Arc::clone(&dropped);
        let (started, ready) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            await_backup_network(&request_epoch, 0, async move {
                let _marker = DropMarker(dropped_for_request);
                let _ = started.send(());
                std::future::pending::<VaultResult<()>>().await
            })
            .await
        });
        ready.await.unwrap();
        cancel_epoch.send_modify(|epoch| *epoch += 1);
        let result = tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(result, Err(VaultError::Locked)));
        assert!(dropped.load(Ordering::Acquire));
    }

    #[test]
    fn automatic_sync_pauses_on_untrusted_history_but_retries_transient_network_errors() {
        for error in [
            SyncError::RollbackOrFork,
            SyncError::ChainTooLong,
            SyncError::HashMismatch,
            SyncError::InvalidRemoteObject,
            SyncError::UnsafeServer,
        ] {
            assert!(auto_sync_checkpoint_error(&error.into()));
        }
        for error in [
            SyncError::Transport,
            SyncError::Timeout,
            SyncError::UnexpectedStatus(401),
            SyncError::ConcurrentUpdate,
        ] {
            assert!(!auto_sync_checkpoint_error(&error.into()));
        }
    }

    #[test]
    fn automatic_sync_fast_retry_is_bounded_and_backed_off() {
        assert_eq!(auto_sync_fast_retry_delay(0), Some(Duration::from_secs(3)));
        assert_eq!(auto_sync_fast_retry_delay(1), Some(Duration::from_secs(6)));
        assert_eq!(auto_sync_fast_retry_delay(2), None);
        assert_eq!(auto_sync_fast_retry_delay(u64::MAX), None);
    }

    #[test]
    fn session_check_time_is_only_reported_for_enabled_automatic_sync() {
        let directory = tempfile::tempdir().unwrap();
        let state = AppState::new(directory.path().join("vault.cnvault"));
        state.last_auto_check_at.store(123, Ordering::Release);
        let absent = with_session_auto_check(WebDavSyncStatus::not_configured(), &state);
        assert_eq!(absent.last_auto_check_at, None);

        let mut configured = WebDavSyncStatus::not_configured();
        configured.configured = true;
        assert_eq!(
            with_session_auto_check(configured.clone(), &state).last_auto_check_at,
            None
        );
        configured.automatic = true;
        assert_eq!(
            with_session_auto_check(configured, &state).last_auto_check_at,
            Some(123)
        );
        state.cancel_sync_operations();
        assert_eq!(state.last_auto_check_at.load(Ordering::Acquire), 0);
    }

    fn test_envelope(vault_id: &str) -> VaultEnvelope {
        VaultEnvelope {
            format: FORMAT_NAME.into(),
            version: FORMAT_VERSION,
            vault_id: vault_id.into(),
            generation: 1,
            kdf: KdfHeader {
                algorithm: "argon2id".into(),
                version: 19,
                memory_kib: 19 * 1024,
                iterations: 1,
                parallelism: 1,
                salt: "AAAAAAAAAAAAAAAAAAAAAA".into(),
            },
            wrapped_key: CipherBlock {
                algorithm: "xchacha20poly1305".into(),
                nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
                ciphertext: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                    .into(),
            },
            payload: CipherBlock {
                algorithm: "xchacha20poly1305".into(),
                nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
                ciphertext: String::new(),
            },
        }
    }

    fn test_data(vault_id: &str) -> VaultData {
        VaultData {
            schema_version: 1,
            vault_id: vault_id.into(),
            generation: 1,
            created_at: 1,
            updated_at: 1,
            last_backup_at: None,
            password_only_unlock: true,
            settings: VaultSettings::default(),
            entries: Vec::new(),
            tombstones: Vec::new(),
        }
    }

    fn test_pending(token: &str, selected_at: Instant) -> PendingRestore {
        let vault_id = Uuid::new_v4().to_string();
        PendingRestore {
            token: Zeroizing::new(token.into()),
            selected_at,
            file_name: "backup.cnvault".into(),
            envelope: test_envelope(&vault_id),
            verified: None,
            target_fingerprint: None,
            backup_config_after_restore: None,
        }
    }

    fn test_pending_sync_preview(token: &str, inspected_at: Instant) -> PendingSyncPreview {
        PendingSyncPreview {
            token: Zeroizing::new(token.into()),
            inspected_at,
            endpoint: "https://dav.example.test/ciphernest/".into(),
            username: "sync-user".into(),
            sync_id: Uuid::new_v4().to_string(),
            snapshot_hash: "a".repeat(64),
            sequence: 7,
            vault_id: Uuid::new_v4().to_string(),
            session_id: Uuid::new_v4().to_string(),
            local_generation: 7,
        }
    }

    #[test]
    fn pending_restore_token_is_scoped_expiring_and_single_use() {
        let pending = Arc::new(Mutex::new(None));
        replace_pending_restore(&pending, test_pending("current-token", Instant::now())).unwrap();

        assert!(matches!(
            pending_envelope_for_inspection(&pending, "wrong-token"),
            Err(VaultError::PendingRestoreUnavailable)
        ));
        let envelope = pending_envelope_for_inspection(&pending, "current-token").unwrap();
        let verified = VerifiedRestore {
            root_key: Zeroizing::new([7_u8; 32]),
            data: test_data(&envelope.vault_id),
        };
        commit_verified_restore(&pending, "current-token", envelope, verified, None).unwrap();

        let consumed = take_pending_restore(&pending, "current-token").unwrap();
        assert!(consumed.verified.is_some());
        assert!(matches!(
            take_pending_restore(&pending, "current-token"),
            Err(VaultError::PendingRestoreUnavailable)
        ));

        let expired_at = Instant::now() - PENDING_RESTORE_TTL - Duration::from_secs(1);
        replace_pending_restore(&pending, test_pending("expired-token", expired_at)).unwrap();
        assert!(matches!(
            pending_envelope_for_inspection(&pending, "expired-token"),
            Err(VaultError::PendingRestoreUnavailable)
        ));
        assert!(pending.lock().unwrap().is_none());
    }

    #[test]
    fn restore_confirmation_rejects_a_target_changed_after_preview() {
        let directory = tempfile::tempdir().unwrap();
        let vault_path = directory.path().join("vault.cnvault");
        let mut store = VaultStore::new(vault_path.clone());
        let absent_at_preview = store.restore_target_fingerprint().unwrap();
        assert!(absent_at_preview.is_none());

        store
            .create("restore conflict passphrase long enough")
            .unwrap();
        assert!(matches!(
            ensure_restore_target_unchanged(&store, absent_at_preview),
            Err(VaultError::RestoreTargetChanged)
        ));

        let current_at_preview = store.restore_target_fingerprint().unwrap();
        ensure_restore_target_unchanged(&store, current_at_preview).unwrap();
        fs::write(&vault_path, b"changed by another process").unwrap();
        assert!(matches!(
            ensure_restore_target_unchanged(&store, current_at_preview),
            Err(VaultError::RestoreTargetChanged)
        ));
    }

    #[test]
    fn join_requires_explicit_replace_when_local_deletions_exist() {
        let empty = SyncContent {
            entries: Vec::new(),
            tombstones: Vec::new(),
        };
        require_join_replace_confirmation(&empty, WebDavJoinMode::Remote, false).unwrap();

        let deleted = SyncContent {
            entries: Vec::new(),
            tombstones: vec![crate::models::Tombstone {
                id: Uuid::new_v4().to_string(),
                revision: 2,
                deleted_at: 1,
            }],
        };
        assert!(matches!(
            require_join_replace_confirmation(&deleted, WebDavJoinMode::Remote, false),
            Err(VaultError::InvalidInput(_))
        ));
        require_join_replace_confirmation(&deleted, WebDavJoinMode::Remote, true).unwrap();
        require_join_replace_confirmation(&deleted, WebDavJoinMode::Merge, false).unwrap();
    }

    #[test]
    fn legacy_restore_is_rotated_before_pending_state_or_apply() {
        let directory = tempfile::tempdir().unwrap();
        let target_path = directory.path().join("vault.cnvault");
        let backup_password = "legacy backup passphrase long enough";
        let current_password = "current vault passphrase long enough";

        let mut legacy_data = test_data(&Uuid::new_v4().to_string());
        legacy_data.password_only_unlock = false;
        legacy_data.generation = 7;
        legacy_data.updated_at = 1;
        let (legacy_envelope, legacy_root_key) =
            create_envelope(backup_password, &legacy_data).unwrap();
        let legacy_envelope_for_hybrid = legacy_envelope.clone();

        let prepared = prepare_verified_restore(backup_password, legacy_envelope.clone()).unwrap();
        let migrated_envelope = prepared.envelope;
        let verified = prepared.verified;
        assert_eq!(prepared.source_updated_at, legacy_data.updated_at);
        assert_eq!(prepared.source_generation, legacy_data.generation);
        assert!(verified.data.password_only_unlock);
        assert_eq!(verified.data.generation, legacy_data.generation + 1);
        assert_eq!(migrated_envelope.generation, verified.data.generation);
        assert_eq!(migrated_envelope.vault_id, legacy_envelope.vault_id);
        assert!(verified.data.updated_at > legacy_data.updated_at);
        assert_ne!(verified.root_key.as_ref(), legacy_root_key.as_ref());
        assert!(decrypt_envelope_with_root_key(&migrated_envelope, &legacy_root_key).is_err());

        let pending = Arc::new(Mutex::new(Some(PendingRestore {
            token: Zeroizing::new("restore-token".into()),
            selected_at: Instant::now(),
            file_name: "legacy.cnvault".into(),
            envelope: legacy_envelope,
            verified: None,
            target_fingerprint: None,
            backup_config_after_restore: None,
        })));
        commit_verified_restore(
            &pending,
            "restore-token",
            migrated_envelope.clone(),
            verified,
            None,
        )
        .unwrap();
        let pending = take_pending_restore(&pending, "restore-token").unwrap();
        let verified = pending.verified.unwrap();
        assert!(verified.data.password_only_unlock);
        assert_eq!(pending.envelope.generation, legacy_data.generation + 1);

        let migrated_root_key = Zeroizing::new(*verified.root_key);
        let mut store = VaultStore::new(target_path.clone());
        store.create(current_password).unwrap();
        let current_before_restore = read_envelope(&target_path).unwrap();
        let (current_root_key, _) =
            decrypt_envelope(current_password, &current_before_restore).unwrap();
        assert!(matches!(
            store.replace_with_verified_backup(
                legacy_envelope_for_hybrid.clone(),
                Zeroizing::new(*legacy_root_key),
                legacy_data.clone(),
            ),
            Err(VaultError::InvalidVault)
        ));
        assert_eq!(
            serde_json::to_vec(&read_envelope(&target_path).unwrap()).unwrap(),
            serde_json::to_vec(&current_before_restore).unwrap()
        );
        assert!(store.status().0.unlocked);

        let mut legacy_slots_path = target_path.as_os_str().to_os_string();
        legacy_slots_path.push(".devices");
        let legacy_slots_path = PathBuf::from(legacy_slots_path);
        let mut legacy_auth_path = target_path.as_os_str().to_os_string();
        legacy_auth_path.push(".device-auth");
        let legacy_auth_path = PathBuf::from(legacy_auth_path);
        fs::write(&legacy_slots_path, b"retired-device-slot").unwrap();
        fs::write(&legacy_auth_path, b"retired-device-auth").unwrap();

        store
            .replace_with_verified_backup(pending.envelope, verified.root_key, verified.data)
            .unwrap();
        let current = read_envelope(&target_path).unwrap();
        let (current_key, current_data) = decrypt_envelope(backup_password, &current).unwrap();
        assert!(current_data.password_only_unlock);
        assert_eq!(current_data.generation, legacy_data.generation + 1);
        assert_eq!(current_key.as_ref(), migrated_root_key.as_ref());
        assert!(decrypt_envelope_with_root_key(&current, &legacy_root_key).is_err());
        assert!(decrypt_envelope_with_root_key(&current, &current_root_key).is_err());
        assert!(!legacy_slots_path.exists());
        assert!(!legacy_auth_path.exists());

        // Even combining the legacy password wrapper with the new current payload cannot
        // recreate access: the restore candidate was encrypted under a fresh random root key.
        let mut legacy_key_with_current_payload = legacy_envelope_for_hybrid;
        legacy_key_with_current_payload.generation = current.generation;
        legacy_key_with_current_payload.payload = current.payload.clone();
        assert!(decrypt_envelope(backup_password, &legacy_key_with_current_payload).is_err());

        assert!(store.lock());
        assert!(store.unlock(current_password).is_err());
        assert!(store.unlock(backup_password).unwrap().unlocked);
    }

    #[test]
    fn restore_preparation_upgrades_weak_slot_and_accepts_verified_historical_password() {
        let password = "a long independent backup passphrase";
        let data = test_data(&Uuid::new_v4().to_string());
        let (strong, root_key) = create_envelope(password, &data).unwrap();
        let weak =
            crate::crypto::rewrap_with_test_kdf(password, &strong, &root_key, 19 * 1024, 1, 1)
                .unwrap();
        let source_bytes = serde_json::to_vec(&weak).unwrap();
        let prepared = prepare_verified_restore(password, weak.clone()).unwrap();
        assert_eq!(prepared.source_generation, weak.generation);
        assert_eq!(prepared.envelope.kdf.memory_kib, 64 * 1024);
        assert_eq!(prepared.envelope.kdf.iterations, 3);
        assert_eq!(prepared.envelope.payload, weak.payload);
        assert_eq!(serde_json::to_vec(&weak).unwrap(), source_bytes);
        assert_eq!(
            decrypt_envelope(password, &prepared.envelope)
                .unwrap()
                .0
                .as_ref(),
            root_key.as_ref()
        );

        let short_password = "oldpass";
        let mut legacy_data = data;
        legacy_data.password_only_unlock = false;
        let (historical, _) =
            create_envelope_with_verified_password(short_password, &legacy_data).unwrap();
        let migrated = prepare_verified_restore(short_password, historical).unwrap();
        assert!(migrated.verified.data.password_only_unlock);
        assert!(decrypt_envelope(short_password, &migrated.envelope).is_ok());
    }

    #[test]
    fn pending_sync_preview_token_is_scoped_expiring_and_single_use() {
        let pending = Arc::new(Mutex::new(None));
        replace_pending_sync_preview(
            &pending,
            test_pending_sync_preview("current-token", Instant::now()),
        )
        .unwrap();

        assert!(matches!(
            take_pending_sync_preview(&pending, "wrong-token"),
            Err(VaultError::PendingSyncPreviewUnavailable)
        ));
        let consumed = take_pending_sync_preview(&pending, "current-token").unwrap();
        assert_eq!(consumed.sequence, 7);
        assert!(matches!(
            take_pending_sync_preview(&pending, "current-token"),
            Err(VaultError::PendingSyncPreviewUnavailable)
        ));

        let expired_at = Instant::now() - PENDING_SYNC_PREVIEW_TTL;
        replace_pending_sync_preview(
            &pending,
            test_pending_sync_preview("expired-token", expired_at),
        )
        .unwrap();
        assert!(matches!(
            take_pending_sync_preview(&pending, "expired-token"),
            Err(VaultError::PendingSyncPreviewUnavailable)
        ));
        assert!(pending.lock().unwrap().is_none());
    }

    #[test]
    fn backup_candidate_reader_enforces_the_size_bound_before_parsing() {
        let directory = tempfile::tempdir().unwrap();
        let valid_path = directory.path().join("valid.cnvault");
        let envelope = test_envelope(&Uuid::new_v4().to_string());
        let encoded = serde_json::to_vec(&envelope).unwrap();
        fs::write(&valid_path, &encoded).unwrap();

        let (parsed, size) = read_bounded_backup_candidate(&valid_path).unwrap();
        assert_eq!(parsed.vault_id, envelope.vault_id);
        assert_eq!(size, encoded.len() as u64);

        let oversized_path = directory.path().join("oversized.cnvault");
        let oversized = File::create(&oversized_path).unwrap();
        oversized.set_len(MAX_VAULT_BYTES + 1).unwrap();
        assert!(matches!(
            read_bounded_backup_candidate(&oversized_path),
            Err(VaultError::InvalidVault)
        ));
    }

    #[test]
    fn webdav_ipc_dtos_use_expected_names_and_never_serialize_credentials() {
        let credentials: WebDavCredentialsInput = serde_json::from_value(serde_json::json!({
            "endpoint": "https://example.test/dav/",
            "username": "alice",
            "appPassword": "secret-app-password"
        }))
        .unwrap();
        assert_eq!(credentials.username, "alice");
        assert!(
            serde_json::from_value::<WebDavCredentialsInput>(serde_json::json!({
                "endpoint": "https://example.test/dav/",
                "username": "alice",
                "appPassword": "secret-app-password",
                "unexpected": true
            }))
            .is_err()
        );

        let output = WebDavSyncOutcome {
            kind: WebDavSyncOutcomeKind::UpToDate,
            conflicts: 0,
            sequence: 7,
            status: WebDavSyncStatus::not_configured(),
        };
        let json = serde_json::to_value(&output).unwrap();
        assert_eq!(json["kind"], "upToDate");
        assert_eq!(json["status"]["pendingLocalChanges"], false);
        let encoded = serde_json::to_string(&output).unwrap();
        assert!(!encoded.contains("appPassword"));
        assert!(!encoded.contains("syncRootKey"));
    }
}
