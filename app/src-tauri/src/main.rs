// Hides the extra console window on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod cli;
mod commands;

use std::sync::Mutex;

use dca_core::catalog::Catalog;
use tauri::Manager;

/// Loaded once at startup. A load failure is kept and reported to the UI
/// instead of crashing, so the user sees what is wrong.
pub struct AppState {
    pub catalog: Mutex<Result<Catalog, String>>,
    /// The collector process while a collection runs, so it can be cancelled.
    pub collection: Mutex<Option<std::process::Child>>,
}

fn main() {
    let context = tauri::generate_context!();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Some(code) = cli::run(&args, &context) {
        std::process::exit(code);
    }
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_window_state::Builder::default().build())
        .setup(|app| {
            let catalog = app
                .path()
                .resource_dir()
                .map_err(|e| e.to_string())
                .and_then(|dir| Catalog::load(&dir.join("checks")).map_err(|e| e.to_string()));
            app.manage(AppState {
                catalog: Mutex::new(catalog),
                collection: Mutex::new(None),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_environment,
            commands::get_catalog_summary,
            commands::list_assessments,
            commands::open_assessments,
            commands::compare_assessments,
            commands::run_access_check,
            commands::run_collection,
            commands::cancel_collection,
            commands::export_report,
            commands::default_export_dir,
            commands::open_folder,
            commands::open_sign_in,
            commands::open_url,
            commands::list_exceptions,
            commands::accept_risk,
            commands::withdraw_risk,
            commands::assessments_folder,
            commands::open_bundle,
            commands::account_exists,
            commands::account_name,
            commands::create_account,
            commands::sign_in,
            commands::change_password,
        ])
        .run(context)
        .expect("error while running Benchmark");
}
