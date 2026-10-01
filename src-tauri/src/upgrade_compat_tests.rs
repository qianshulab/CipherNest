//! Read authentic v0.3.7 files through the current vault and sidecar readers.

use std::fs;

use crate::vault::VaultStore;

const MASTER_PASSWORD: &str = "Synthetic fixture passphrase v0.3.7 L5!r8Qa2";
const VAULT: &[u8] = include_bytes!("../tests/fixtures/v0.3.7/vault.fixture.json");
const SYNC: &[u8] = include_bytes!("../tests/fixtures/v0.3.7/sync.fixture.json");
const BACKUP: &[u8] = include_bytes!("../tests/fixtures/v0.3.7/backup.fixture.json");

#[test]
fn v037_cover_install_keeps_vault_entries_and_encrypted_webdav_sidecars_readable() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("vault.cnvault");
    fs::write(&path, VAULT).unwrap();
    fs::write(directory.path().join("vault.cnvault.sync"), SYNC).unwrap();
    fs::write(directory.path().join("vault.cnvault.webdav-backup"), BACKUP).unwrap();

    let mut store = VaultStore::new(path.clone());
    let status = store.unlock(MASTER_PASSWORD).unwrap();
    assert!(status.unlocked);
    assert_eq!(status.item_count, 1);
    let entries = store.list_entries(None, None, None).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].title, "v0.3.7 compatibility entry");
    let entry = store.get_entry(&entries[0].id).unwrap();
    assert_eq!(entry.username, "local-user");
    assert_eq!(entry.password, "Z6!qL8@vN4#rT2$xP9");

    let sync_status = store.webdav_sync_status().unwrap();
    assert!(sync_status.configured);
    assert!(
        !sync_status.automatic,
        "old sync configuration must remain opt-in"
    );
    assert!(!sync_status.auto_paused);
    assert_eq!(sync_status.username.as_deref(), Some("sync-user"));
    let backup_status = store.remote_backup_status().unwrap();
    assert!(backup_status.configured);
    assert!(backup_status.automatic);
    assert_eq!(
        backup_status.username.as_deref(),
        Some("synthetic-backup-user")
    );
    let backup = store.remote_backup_config().unwrap().unwrap();
    assert_eq!(
        backup.endpoint,
        "https://backup.example.invalid/ciphernest/"
    );
    assert_eq!(
        backup.app_password,
        "synthetic-backup-secret-only-for-tests"
    );

    store.lock();
    let mut reopened = VaultStore::new(path);
    reopened.unlock(MASTER_PASSWORD).unwrap();
    assert_eq!(reopened.list_entries(None, None, None).unwrap().len(), 1);
    assert!(reopened.webdav_sync_status().unwrap().configured);
    assert!(!reopened.webdav_sync_status().unwrap().automatic);
    assert!(reopened.remote_backup_status().unwrap().configured);
}
