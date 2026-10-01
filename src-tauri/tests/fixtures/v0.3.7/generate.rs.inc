    // Append this test inside src-tauri/src/vault.rs's `mod tests` at tag v0.3.7.
    // Run with CIPHERNEST_FIXTURE_DIR set to this fixture directory.
    #[test]
    fn emit_v037_upgrade_fixture() {
        let output = PathBuf::from(std::env::var("CIPHERNEST_FIXTURE_DIR").unwrap());
        fs::create_dir_all(&output).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.cnvault");
        let mut store = VaultStore::new(path.clone());
        store
            .create("Synthetic fixture passphrase v0.3.7 L5!r8Qa2")
            .unwrap();
        store
            .save_entry(sample_entry_input(None, None, "v0.3.7 compatibility entry"))
            .unwrap();

        let vault = store.unlocked.as_ref().unwrap();
        let sync_state = test_sync_state(&vault.data, vault.data.generation);
        sync::write_local_sync_state(
            &store.sync_state_path,
            &vault.data.vault_id,
            &vault.root_key,
            &sync_state,
        )
        .unwrap();
        let (vault_id, session_id) = store.remote_backup_session_identity().unwrap();
        store
            .save_remote_backup_config(
                &vault_id,
                &session_id,
                &BackupConfig {
                    endpoint: "https://backup.example.invalid/ciphernest/".into(),
                    username: "synthetic-backup-user".into(),
                    app_password: "synthetic-backup-secret-only-for-tests".into(),
                    automatic: true,
                    last_upload_at: Some(1_700_000_000_000),
                    last_uploaded_generation: Some(2),
                    warning: None,
                },
            )
            .unwrap();
        store.lock();

        fs::copy(&path, output.join("vault.fixture.json")).unwrap();
        fs::copy(&store.sync_state_path, output.join("sync.fixture.json")).unwrap();
        fs::copy(
            &store.backup_config_path,
            output.join("backup.fixture.json"),
        )
        .unwrap();
    }
