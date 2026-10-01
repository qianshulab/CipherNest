mod commands;
mod crypto;
mod error;
mod generator;
mod models;
mod sync;
mod sync_v2;
mod vault;
mod webdav_backup;

#[cfg(test)]
mod upgrade_compat_tests;

use std::path::PathBuf;

use tauri::{Emitter, Manager, RunEvent};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.unminimize();
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .setup(|app| {
            let app_data = app.path().app_data_dir()?;
            let vault_path: PathBuf = app_data.join("vault.cnvault");
            app.manage(commands::AppState::new(vault_path));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::vault_status,
            commands::create_vault,
            commands::unlock_vault,
            commands::lock_vault,
            commands::list_entries,
            commands::vault_overview,
            commands::get_entry,
            commands::save_entry,
            commands::delete_entry,
            commands::set_favorite,
            commands::generate_password,
            commands::copy_secret,
            commands::clear_owned_clipboard,
            commands::get_settings,
            commands::update_settings,
            commands::webdav_sync_status,
            commands::set_webdav_auto_sync,
            commands::create_webdav_sync,
            commands::inspect_webdav_sync,
            commands::join_webdav_sync,
            commands::sync_webdav_now,
            commands::reveal_webdav_recovery_code,
            commands::disable_webdav_sync,
            commands::sync_v2_status,
            commands::sync_v2_create,
            commands::sync_v2_preview_join,
            commands::sync_v2_join,
            commands::sync_v2_now,
            commands::sync_v2_reveal_recovery_code,
            commands::sync_v2_disable,
            commands::security_report,
            commands::change_master_password,
            commands::export_backup,
            commands::webdav_backup_status,
            commands::webdav_backup_test_config,
            commands::webdav_backup_save_config,
            commands::webdav_backup_disable,
            commands::webdav_backup_upload,
            commands::webdav_backup_list,
            commands::webdav_backup_list_with_credentials,
            commands::webdav_backup_prepare_restore,
            commands::webdav_backup_prepare_restore_with_credentials,
            commands::select_backup_for_restore,
            commands::inspect_selected_backup,
            commands::apply_selected_backup,
            commands::cancel_pending_restore,
            commands::touch_activity,
            commands::handle_focus_change,
        ])
        .build(tauri::generate_context!())
        .expect("failed to build CipherNest");

    app.run(|app, event| match event {
        // Desktop runtimes emit Resumed after the event loop returns from a system
        // suspend. Locking here ensures the WebView never keeps a pre-sleep session.
        RunEvent::Resumed => {
            commands::lock_for_lifecycle(app);
            let _ = app.emit("ciphernest://vault-locked", ());
        }
        RunEvent::Exit | RunEvent::ExitRequested { .. } => {
            commands::lock_for_lifecycle(app);
        }
        _ => {}
    });
}
