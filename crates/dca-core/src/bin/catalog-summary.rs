//! Prints the catalog summary as JSON. Used to validate the catalog in CI
//! and to feed the browser preview of the UI.
//!
//! Usage: catalog-summary [CATALOG_DIR]   (defaults to the repo's checks/)

use std::path::PathBuf;

fn main() {
    let dir = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../checks"));
    match dca_core::catalog::Catalog::load(&dir) {
        Ok(catalog) => println!(
            "{}",
            serde_json::to_string_pretty(&catalog.summary()).expect("summary serializes")
        ),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}
