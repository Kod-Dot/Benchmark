//! Exports: the executive summary, technical report and changes report
//! (HTML, and PDF printed from that HTML by Edge or Chrome), the offline
//! dashboard, the remediation plan (XLSX, CSV) and raw results (JSON, CSV,
//! SARIF). Reports are pages of the app's own UI, so they look like it.

pub mod data;
pub mod inline;
pub mod pseudo;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::catalog::Catalog;
use crate::compare;
use crate::exceptions::{self, Exceptions};
use crate::results::{self, ResultStatus};
use crate::time;
use crate::{Error, Result};
pub use inline::{DirAssets, UiAssets};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportKind {
    Executive,
    Technical,
    Remediation,
    Dashboard,
    Changes,
    Raw,
}

impl ReportKind {
    fn title(self) -> &'static str {
        match self {
            ReportKind::Executive => "Executive summary",
            ReportKind::Technical => "Technical report",
            ReportKind::Remediation => "Remediation plan",
            ReportKind::Dashboard => "Offline dashboard",
            ReportKind::Changes => "Changes since baseline",
            ReportKind::Raw => "Results",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Pdf,
    Html,
    Xlsx,
    Csv,
    Json,
    Sarif,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportChoice {
    pub kind: ReportKind,
    pub formats: Vec<Format>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Branding {
    #[serde(default)]
    pub organization: String,
    #[serde(default)]
    pub prepared_by: String,
    #[serde(default)]
    pub classification: String,
    /// A PNG or SVG file; embedded in the reports.
    #[serde(default)]
    pub logo: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportRequest {
    /// One assessment, or several combined.
    pub paths: Vec<String>,
    /// The earlier assessment for the changes report.
    #[serde(default)]
    pub baseline: Option<String>,
    pub out_dir: String,
    pub reports: Vec<ReportChoice>,
    #[serde(default)]
    pub branding: Branding,
    #[serde(default)]
    pub pseudonymize: bool,
    #[serde(default)]
    pub omit_accepted: bool,
    /// Accepted risks to apply; filled in by the app, not sent by the UI.
    #[serde(skip)]
    pub exceptions: Exceptions,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExportOutcome {
    pub folder: String,
    pub files: Vec<String>,
    /// Things that did not go as asked, such as PDFs without a browser.
    pub warnings: Vec<String>,
}

/// Microsoft Edge or Google Chrome, to print reports to PDF. `DCA_BROWSER`
/// overrides the search.
pub fn find_browser() -> Option<PathBuf> {
    browsers().into_iter().next()
}

/// Every installed browser that can print, preferred first.
fn browsers() -> Vec<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(p) = std::env::var_os("DCA_BROWSER") {
        candidates.push(PathBuf::from(p));
    }
    for var in ["ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA"] {
        if let Some(base) = std::env::var_os(var).map(PathBuf::from) {
            candidates.push(base.join("Microsoft/Edge/Application/msedge.exe"));
            candidates.push(base.join("Google/Chrome/Application/chrome.exe"));
        }
    }
    for p in [
        "/usr/bin/microsoft-edge",
        "/usr/bin/google-chrome",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
    ] {
        candidates.push(PathBuf::from(p));
    }
    let mut seen = std::collections::BTreeSet::new();
    candidates
        .into_iter()
        .filter(|p| p.is_file() && seen.insert(p.clone()))
        .collect()
}

fn file_url(path: &Path) -> String {
    let p = path.display().to_string().replace('\\', "/");
    let mut out = String::from(if p.starts_with('/') {
        "file://"
    } else {
        "file:///"
    });
    for b in p.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'/' | b'-' | b'_' | b'.' | b'~' | b':' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Windows paths without the `\\?\` prefix, which browsers do not accept.
fn plain(path: &Path) -> PathBuf {
    let s = path.display().to_string();
    match s.strip_prefix(r"\\?\UNC\") {
        Some(rest) => PathBuf::from(format!(r"\\{rest}")),
        None => PathBuf::from(s.strip_prefix(r"\\?\").unwrap_or(&s)),
    }
}

/// Prints `html` to `pdf` with `browser`, then with any other installed
/// browser if that one fails.
pub fn print_pdf(browser: &Path, html: &Path, pdf: &Path) -> std::result::Result<(), String> {
    let mut errors = Vec::new();
    let others = browsers().into_iter().filter(|b| b != browser);
    for b in std::iter::once(browser.to_path_buf()).chain(others) {
        match print_with(&b, html, pdf) {
            Ok(()) => return Ok(()),
            Err(e) => errors.push(e),
        }
    }
    Err(errors.join(" "))
}

fn print_with(browser: &Path, html: &Path, pdf: &Path) -> std::result::Result<(), String> {
    let name = browser
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "The browser".into());
    let (html, pdf) = (plain(html), plain(pdf));
    let _ = fs::remove_file(&pdf);
    let profile =
        std::env::temp_dir().join(format!("dca-print-{}-{}", std::process::id(), time::now()));
    fs::create_dir_all(&profile).map_err(|e| e.to_string())?;
    let log_path = profile.join("print.log");
    let log = fs::File::create(&log_path).map_err(|e| e.to_string())?;
    let mut child = Command::new(browser)
        .arg("--headless")
        .arg("--disable-gpu")
        .arg("--no-first-run")
        .arg("--no-default-browser-check")
        .arg("--disable-extensions")
        .arg("--no-pdf-header-footer")
        .arg("--virtual-time-budget=15000")
        .arg(format!("--user-data-dir={}", profile.display()))
        .arg(format!("--print-to-pdf={}", pdf.display()))
        .arg(file_url(&html))
        .stdout(log.try_clone().map_err(|e| e.to_string())?)
        .stderr(log)
        .spawn()
        .map_err(|e| format!("Could not start {}: {e}.", browser.display()))?;
    let started = std::time::Instant::now();
    let limit = std::time::Duration::from_secs(120);
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            break status;
        }
        if started.elapsed() > limit {
            let _ = child.kill();
            let _ = child.wait();
            let _ = fs::remove_dir_all(&profile);
            return Err(format!("{name} did not finish printing within 2 minutes."));
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    };
    // The browser can hand the work to another of its processes and exit
    // first, so give the file a moment to appear.
    while status.success()
        && !pdf_ready(&pdf)
        && started.elapsed() < std::time::Duration::from_secs(30)
    {
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    let said = fs::read_to_string(&log_path).unwrap_or_default();
    let _ = fs::remove_dir_all(&profile);
    if pdf_ready(&pdf) {
        return Ok(());
    }
    let reason = said
        .lines()
        .map(str::trim)
        .rfind(|l| !l.is_empty() && !l.contains("dbus") && !l.contains("DevTools listening"))
        .map(|l| format!(" It said: {}", l.chars().take(300).collect::<String>()))
        .unwrap_or_default();
    Err(format!(
        "{name} could not print the report ({status}).{reason}"
    ))
}

fn pdf_ready(pdf: &Path) -> bool {
    fs::metadata(pdf).is_ok_and(|m| m.len() > 0)
}

/// A file or folder name without characters Windows refuses.
fn safe_name(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| {
            if matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*') || c.is_control() {
                '-'
            } else {
                c
            }
        })
        .collect();
    let cleaned = cleaned.trim().trim_end_matches('.').to_string();
    if cleaned.is_empty() {
        "Assessment".into()
    } else {
        cleaned
    }
}

fn logo_data(path: &str) -> std::result::Result<String, String> {
    let bytes = fs::read(path).map_err(|e| format!("Could not read the logo {path}: {e}"))?;
    if bytes.len() > 2 << 20 {
        return Err("The logo is larger than 2 MB.".into());
    }
    let mime = if path.to_lowercase().ends_with(".svg") {
        "image/svg+xml"
    } else {
        "image/png"
    };
    Ok(format!(
        "data:{mime};base64,{}",
        base64::engine::general_purpose::STANDARD.encode(bytes)
    ))
}

fn io(path: &Path) -> impl Fn(std::io::Error) -> Error + '_ {
    move |source| Error::Io {
        path: path.display().to_string(),
        source,
    }
}

pub fn export(
    catalog: &Catalog,
    req: &ExportRequest,
    assets: &dyn UiAssets,
    browser: Option<&Path>,
    now: i64,
) -> Result<ExportOutcome> {
    if req.reports.is_empty() {
        return Err(Error::Assessment("Choose at least one report.".into()));
    }
    let runs = exceptions::load_runs(&req.paths, &req.exceptions, now)?;
    if runs.is_empty() {
        return Err(Error::Assessment("Choose an assessment to export.".into()));
    }
    let mut view = results::view(catalog, &runs);
    let wants = |k: ReportKind| {
        req.reports
            .iter()
            .any(|r| r.kind == k && !r.formats.is_empty())
    };
    let mut comparison = match (&req.baseline, wants(ReportKind::Changes)) {
        (Some(b), true) => Some(compare::compare(
            catalog,
            &exceptions::load_runs(std::slice::from_ref(b), &req.exceptions, now)?[0],
            &runs[0],
        )),
        _ => None,
    };
    let mut warnings = Vec::new();
    if wants(ReportKind::Changes) && comparison.is_none() {
        warnings.push(
            "The changes report needs an earlier assessment of the same scope; it was skipped."
                .into(),
        );
    }
    // Recipients get the assessment's folder name, not a path on this computer.
    let folder_only = |p: &mut String| {
        *p = Path::new(p.as_str())
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
    };
    view.runs.iter_mut().for_each(|r| folder_only(&mut r.path));
    if let Some(c) = comparison.as_mut() {
        folder_only(&mut c.earlier.path);
        folder_only(&mut c.later.path);
    }
    if req.pseudonymize {
        let names = pseudo::Pseudonyms::new(&view, comparison.as_ref());
        names.apply(&mut view, comparison.as_mut());
    }

    let name = match runs.as_slice() {
        [one] => one.name.clone(),
        many => many
            .iter()
            .map(|r| r.name.as_str())
            .collect::<Vec<_>>()
            .join(" + "),
    };
    let stamp = time::iso(now);
    let base = Path::new(&req.out_dir);
    let mut folder = base.join(safe_name(&format!(
        "{name} {}-{}",
        &stamp[..10],
        stamp[11..16].replace(':', "")
    )));
    let mut n = 2;
    while folder.exists() {
        folder = base.join(safe_name(&format!(
            "{name} {}-{} ({n})",
            &stamp[..10],
            stamp[11..16].replace(':', "")
        )));
        n += 1;
    }
    fs::create_dir_all(&folder).map_err(io(&folder))?;

    let logo = match req
        .branding
        .logo
        .as_deref()
        .filter(|l| !l.trim().is_empty())
    {
        Some(path) => match logo_data(path) {
            Ok(d) => Some(d),
            Err(e) => {
                warnings.push(e);
                None
            }
        },
        None => None,
    };
    let accepted = view
        .findings
        .iter()
        .filter(|f| f.status == ResultStatus::Accepted)
        .count();
    let page_data = |kind: ReportKind, mode: &str| {
        json!({
            "mode": mode,
            "kind": kind,
            "title": match (&comparison, kind) {
                (Some(c), ReportKind::Changes) => format!("Changes since {} · {name}", c.earlier.name),
                _ => format!("{} · {name}", kind.title()),
            },
            "view": &view,
            "comparison": if kind == ReportKind::Changes { json!(&comparison) } else { json!(null) },
            "branding": {
                "organization": req.branding.organization,
                "prepared_by": req.branding.prepared_by,
                "classification": req.branding.classification,
                "logo": logo,
            },
            "plan": if matches!(kind, ReportKind::Executive | ReportKind::Technical) { json!(data::remediation(&view, req.omit_accepted)) } else { json!(null) },
            "omit_accepted": req.omit_accepted,
            "accepted": accepted,
            "pseudonymized": req.pseudonymize,
            "generated_at": stamp,
            "tool_version": crate::analysis::TOOL_VERSION,
        })
    };

    let mut files: Vec<PathBuf> = Vec::new();
    fn write(files: &mut Vec<PathBuf>, file: PathBuf, bytes: &[u8]) -> Result<()> {
        fs::write(&file, bytes).map_err(io(&file))?;
        files.push(file);
        Ok(())
    }

    for choice in &req.reports {
        let kind = choice.kind;
        let has = |f: Format| choice.formats.contains(&f);
        let title = kind.title();
        match kind {
            ReportKind::Executive | ReportKind::Technical | ReportKind::Changes => {
                if kind == ReportKind::Changes && comparison.is_none() {
                    continue;
                }
                let title = match (&comparison, kind) {
                    (Some(c), ReportKind::Changes) => {
                        format!("Changes since {}", safe_name(&c.earlier.name))
                    }
                    _ => title.to_string(),
                };
                let html = inline::page(
                    assets,
                    "report.html",
                    &format!("{title} · {name}"),
                    &page_data(kind, "report"),
                )
                .map_err(Error::Assessment)?;
                let html_path = folder.join(format!("{title}.html"));
                fs::write(&html_path, &html).map_err(io(&html_path))?;
                let mut keep_html = has(Format::Html);
                if has(Format::Pdf) {
                    let pdf = folder.join(format!("{title}.pdf"));
                    match browser {
                        Some(b) => match print_pdf(b, &html_path, &pdf) {
                            Ok(()) => files.push(pdf),
                            Err(e) => {
                                warnings.push(format!(
                                    "{title}: {e} The HTML version was saved instead."
                                ));
                                keep_html = true;
                            }
                        },
                        None => {
                            warnings.push(format!(
                                "{title}: PDF needs Microsoft Edge or Google Chrome, and neither was found. The HTML version was saved instead; print it to PDF from any browser."
                            ));
                            keep_html = true;
                        }
                    }
                }
                if keep_html {
                    files.push(html_path);
                } else {
                    let _ = fs::remove_file(&html_path);
                }
            }
            ReportKind::Dashboard => {
                let html = inline::page(
                    assets,
                    "index.html",
                    &format!("{name} · Benchmark"),
                    &page_data(kind, "offline"),
                )
                .map_err(Error::Assessment)?;
                write(
                    &mut files,
                    folder.join(format!("{title}.html")),
                    html.as_bytes(),
                )?;
            }
            ReportKind::Remediation => {
                let rows = data::remediation(&view, req.omit_accepted);
                if has(Format::Xlsx) {
                    let bytes =
                        data::remediation_xlsx(&rows, &view, &format!("Remediation plan · {name}"))
                            .map_err(Error::Assessment)?;
                    write(&mut files, folder.join(format!("{title}.xlsx")), &bytes)?;
                }
                if has(Format::Csv) {
                    write(
                        &mut files,
                        folder.join(format!("{title}.csv")),
                        data::remediation_csv(&rows).as_bytes(),
                    )?;
                }
            }
            ReportKind::Raw => {
                if has(Format::Json) {
                    let text = serde_json::to_string_pretty(&view)
                        .map_err(|e| Error::Assessment(e.to_string()))?;
                    write(&mut files, folder.join("Results.json"), text.as_bytes())?;
                }
                if has(Format::Csv) {
                    write(
                        &mut files,
                        folder.join("Results.csv"),
                        data::findings_csv(&view).as_bytes(),
                    )?;
                }
                if has(Format::Sarif) {
                    let s = data::sarif(&view, crate::analysis::TOOL_VERSION);
                    let text = serde_json::to_string_pretty(&s)
                        .map_err(|e| Error::Assessment(e.to_string()))?;
                    write(&mut files, folder.join("Results.sarif"), text.as_bytes())?;
                }
            }
        }
    }
    Ok(ExportOutcome {
        folder: folder.display().to_string(),
        files: files.iter().map(|f| f.display().to_string()).collect(),
        warnings,
    })
}

#[cfg(test)]
mod tests;
