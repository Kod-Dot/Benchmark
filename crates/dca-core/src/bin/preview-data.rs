//! Writes the data the browser preview of the UI reads (`npm run dev`), from
//! the real catalog and the EXAMPLE assessments in fixtures/. The desktop app
//! never uses these files; it reads the user's own assessments.
//!
//! Usage: preview-data [OUT_DIR]   (defaults to app/.preview)

use std::fs;
use std::path::{Path, PathBuf};

use dca_core::catalog::Catalog;
use dca_core::results::{self, Assessment};
use dca_core::{compare, store};

fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

fn save<T: serde::Serialize>(dir: &Path, name: &str, value: &T) -> std::io::Result<()> {
    fs::write(dir.join(name), serde_json::to_string(value)?)
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let repo = repo.canonicalize().unwrap_or(repo);
    let out = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| repo.join("app/.preview"));
    fs::create_dir_all(&out)?;

    let catalog = Catalog::load(&repo.join("checks"))?;
    save(&out, "catalog-summary.json", &catalog.summary())?;

    let examples = repo.join("fixtures/example-assessments");
    let mut listing = store::list(&examples);

    let mut loaded = Vec::new();
    for entry in &mut listing.assessments {
        let a = Assessment::load(Path::new(&entry.path))?;
        let view = results::view(&catalog, std::slice::from_ref(&a));
        // The examples were never analyzed by the app, so their manifests
        // carry no score; record the one analysis would have written.
        if entry.manifest.score.is_none() {
            entry.manifest.score = view.summary.score.map(f64::from);
        }
        save(&out, &format!("view-{}.json", entry.name), &view)?;
        loaded.push((entry.name.clone(), a));
    }
    save(&out, "listing.json", &listing)?;
    let get = |n: &str| {
        loaded
            .iter()
            .find(|(name, _)| name == n)
            .map(|(_, a)| a)
            .expect("example exists")
    };
    save(
        &out,
        "compare-q3-baseline-october-review.json",
        &compare::compare(&catalog, get("q3-baseline"), get("october-review")),
    )?;
    save(
        &out,
        "combine-october-review-branch-forest.json",
        &results::view(
            &catalog,
            &[get("october-review").clone(), get("branch-forest").clone()],
        ),
    )?;
    println!("wrote {}", out.display());
    Ok(())
}
