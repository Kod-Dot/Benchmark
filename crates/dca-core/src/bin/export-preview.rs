//! Exports every report for the EXAMPLE assessments in fixtures/, using the
//! built UI in app/dist (run `npm run build` in app/ first). For reviewing
//! the report layouts; the desktop app exports the user's own assessments.
//!
//! Usage: export-preview OUT_DIR [--pseudonymize] [--trial]
//! (DCA_BROWSER picks the browser for PDFs; --trial exports as an unlicensed trial)

use std::path::PathBuf;

use dca_core::catalog::Catalog;
use dca_core::report::{
    self, Branding, DirAssets, ExportRequest, Format, ReportChoice, ReportKind,
};

fn main() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let Some(out) = std::env::args().nth(1) else {
        eprintln!("Usage: export-preview OUT_DIR");
        std::process::exit(2);
    };
    let pseudonymize = std::env::args().any(|a| a == "--pseudonymize");
    let examples = repo.join("fixtures/example-assessments");
    let catalog = Catalog::load(&repo.join("checks")).expect("catalog");
    let all = |kind| ReportChoice {
        kind,
        formats: vec![
            Format::Pdf,
            Format::Html,
            Format::Xlsx,
            Format::Csv,
            Format::Json,
            Format::Sarif,
        ],
    };
    let req = ExportRequest {
        paths: vec![examples.join("october-review").display().to_string()],
        baseline: Some(examples.join("q3-baseline").display().to_string()),
        out_dir: out,
        reports: [
            ReportKind::Executive,
            ReportKind::Technical,
            ReportKind::Remediation,
            ReportKind::Dashboard,
            ReportKind::Changes,
            ReportKind::Raw,
        ]
        .into_iter()
        .map(all)
        .collect(),
        branding: Branding {
            organization: "Example organization".into(),
            prepared_by: "Example assessor".into(),
            classification: "Confidential".into(),
            logo: None,
        },
        pseudonymize,
        omit_accepted: true,
        exceptions: Default::default(),
    };
    let browser = report::find_browser();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    match report::export(
        &catalog,
        &req,
        &DirAssets(repo.join("app/dist")),
        browser.as_deref(),
        now,
    ) {
        Ok(o) => {
            println!("{}", o.folder);
            for f in o.files {
                println!("  {f}");
            }
            for w in o.warnings {
                println!("! {w}");
            }
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}
