use std::fs;
use std::path::Path;

use super::*;

/// A stand-in for the built UI: both entry pages and their assets.
fn fake_dist(dir: &Path) {
    fs::create_dir_all(dir.join("assets")).unwrap();
    for entry in ["index", "report"] {
        fs::write(
            dir.join(format!("{entry}.html")),
            format!("<!doctype html><html><head><title>Benchmark</title><script type=\"module\" crossorigin src=\"/assets/{entry}.js\"></script><link rel=\"stylesheet\" crossorigin href=\"/assets/{entry}.css\"></head><body><div id=\"app\"></div></body></html>"),
        )
        .unwrap();
        fs::write(
            dir.join(format!("assets/{entry}.js")),
            "document.title = window.__DCA__.title;",
        )
        .unwrap();
        fs::write(dir.join(format!("assets/{entry}.css")), "body{margin:0}").unwrap();
    }
}

fn assessment(root: &Path, name: &str, at: &str) -> String {
    let catalog = crate::results::tests::catalog();
    let spec = crate::analysis::NewAssessment {
        name: Some(name.into()),
        domains: vec!["corp.example.com".into()],
        tenant: None,
        areas: vec![],
    };
    let dir = crate::analysis::create(root, spec, time::parse_iso(at).unwrap()).unwrap();
    crate::ad::tests::write_domain(&crate::analysis::ad_raw_dir(&dir, "corp.example.com"), true);
    crate::analysis::analyze(&dir, &catalog).unwrap();
    dir.display().to_string()
}

fn all(formats: &[Format], kind: ReportKind) -> ReportChoice {
    ReportChoice {
        kind,
        formats: formats.to_vec(),
    }
}

#[test]
fn exports_every_report_without_a_browser() {
    let tmp = tempfile::tempdir().unwrap();
    let dist = tmp.path().join("dist");
    fake_dist(&dist);
    let earlier = assessment(
        &tmp.path().join("runs"),
        "Q3 baseline",
        "2026-07-01T09:00:00Z",
    );
    let later = assessment(
        &tmp.path().join("runs"),
        "October review",
        "2026-10-05T12:00:00Z",
    );
    let req = ExportRequest {
        paths: vec![later],
        baseline: Some(earlier),
        out_dir: tmp.path().join("out").display().to_string(),
        reports: vec![
            all(&[Format::Pdf], ReportKind::Executive),
            all(&[Format::Html], ReportKind::Technical),
            all(&[Format::Xlsx, Format::Csv], ReportKind::Remediation),
            all(&[Format::Html], ReportKind::Dashboard),
            all(&[Format::Html], ReportKind::Changes),
            all(&[Format::Json, Format::Csv, Format::Sarif], ReportKind::Raw),
        ],
        branding: Branding {
            organization: "Contoso".into(),
            ..Branding::default()
        },
        pseudonymize: false,
        omit_accepted: true,
        exceptions: Default::default(),
    };
    let catalog = crate::results::tests::catalog();
    let out = export(
        &catalog,
        &req,
        &DirAssets(dist),
        None,
        time::parse_iso("2026-10-06T08:30:00Z").unwrap(),
    )
    .unwrap();

    let names: Vec<String> = out
        .files
        .iter()
        .map(|f| {
            Path::new(f)
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert_eq!(
        names,
        [
            "Executive summary.html",
            "Technical report.html",
            "Remediation plan.xlsx",
            "Remediation plan.csv",
            "Offline dashboard.html",
            "Changes since Q3 baseline.html",
            "Results.json",
            "Results.csv",
            "Results.sarif",
        ]
    );
    assert!(out.folder.ends_with("October review 2026-10-06-0830"));
    assert_eq!(out.warnings.len(), 1, "{:?}", out.warnings);
    assert!(out.warnings[0].contains("PDF needs Microsoft Edge"));

    let exec = fs::read_to_string(&out.files[0]).unwrap();
    assert!(exec.contains("window.__DCA__={") && exec.contains("\"mode\":\"report\""));
    assert!(exec.contains("\"organization\":\"Contoso\""));
    let dash = fs::read_to_string(&out.files[4]).unwrap();
    assert!(dash.contains("\"mode\":\"offline\""));
    let changes = fs::read_to_string(&out.files[5]).unwrap();
    assert!(changes.contains("\"comparison\":{"));

    let xlsx = fs::read(&out.files[2]).unwrap();
    assert_eq!(&xlsx[..2], b"PK");
    let plan = fs::read_to_string(&out.files[3]).unwrap();
    assert!(
        plan.lines().nth(1).unwrap().starts_with("1,30,"),
        "{}",
        plan.lines().nth(1).unwrap()
    );

    let sarif: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&out.files[8]).unwrap()).unwrap();
    assert_eq!(sarif["version"], "2.1.0");
    assert!(!sarif["runs"][0]["results"].as_array().unwrap().is_empty());
}

#[test]
fn pseudonyms_hide_names_in_every_file() {
    let tmp = tempfile::tempdir().unwrap();
    let dist = tmp.path().join("dist");
    fake_dist(&dist);
    let run = assessment(
        &tmp.path().join("runs"),
        "October review",
        "2026-10-05T12:00:00Z",
    );
    let req = ExportRequest {
        paths: vec![run],
        baseline: None,
        out_dir: tmp.path().join("out").display().to_string(),
        reports: vec![
            all(&[Format::Html], ReportKind::Technical),
            all(&[Format::Json, Format::Csv], ReportKind::Raw),
            all(&[Format::Csv], ReportKind::Remediation),
        ],
        branding: Branding::default(),
        pseudonymize: true,
        omit_accepted: false,
        exceptions: Default::default(),
    };
    let catalog = crate::results::tests::catalog();
    let out = export(
        &catalog,
        &req,
        &DirAssets(dist),
        None,
        time::parse_iso(NOW).unwrap(),
    )
    .unwrap();
    for f in &out.files {
        let text = fs::read_to_string(f).unwrap().to_lowercase();
        for secret in [
            "svc-sql",
            "helpdesk-lead",
            "adm-jsmith",
            "corp.example.com",
            "dc=corp",
            "dc01",
            "jdoe",
            "it admins",
            "svc-legacy",
        ] {
            assert!(!text.contains(secret), "{secret} is in {f}");
        }
        assert!(text.contains("domain admins"), "built-in names stay in {f}");
    }
}

const NOW: &str = "2026-10-05T12:00:00Z";

#[test]
fn file_urls_are_encoded() {
    assert_eq!(
        file_url(Path::new("/tmp/a b/r#1.html")),
        "file:///tmp/a%20b/r%231.html"
    );
    assert_eq!(safe_name("Q3: review/final?"), "Q3- review-final-");
}

#[test]
fn verbatim_windows_paths_are_made_plain() {
    assert_eq!(
        plain(Path::new(r"\\?\C:\Reports\Technical report.pdf")),
        Path::new(r"C:\Reports\Technical report.pdf")
    );
    assert_eq!(
        plain(Path::new(r"\\?\UNC\server\share\r.pdf")),
        Path::new(r"\\server\share\r.pdf")
    );
    assert_eq!(plain(Path::new("/tmp/r.pdf")), Path::new("/tmp/r.pdf"));
}

/// Prints a real PDF when `DCA_BROWSER` names a browser (CI sets it).
#[test]
fn prints_a_pdf_with_the_installed_browser() {
    let Some(browser) = std::env::var_os("DCA_BROWSER").map(std::path::PathBuf::from) else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let folder = dir.path().join("Contoso 2026-10-08 (2)");
    fs::create_dir_all(&folder).unwrap();
    let html = folder.join("Technical report.html");
    fs::write(&html, "<!doctype html><h1>Report</h1>").unwrap();
    let pdf = folder.join("Technical report.pdf");
    print_pdf(&browser, &html, &pdf).unwrap();
    assert!(fs::read(&pdf).unwrap().starts_with(b"%PDF"));
}
