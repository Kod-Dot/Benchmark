//! Commands the UI calls. Each is a thin wrapper over `dca-core`.

use dca_core::access::{self, ProbeResult};
use dca_core::account;
use dca_core::ad::raw::CollectEvent;
use dca_core::analysis::{self, NewAssessment};
use dca_core::catalog::{Catalog, CatalogSummary};
use dca_core::compare::{self, Comparison};
use dca_core::environment::{self, Environment};
use dca_core::exceptions::{self, ExceptionRow, Exceptions, RiskAcceptance};
use dca_core::report::{self, ExportOutcome, ExportRequest};
use dca_core::results::{self, Assessment, AssessmentView};
use dca_core::store::{self, Listing, Manifest};
use dca_core::time;
use tauri::{AppHandle, Emitter, Manager, State};

use crate::AppState;

#[tauri::command]
pub fn get_environment() -> Environment {
    environment::detect()
}

#[tauri::command]
pub fn get_catalog_summary(state: State<'_, AppState>) -> Result<CatalogSummary, String> {
    let guard = state.catalog.lock().map_err(|e| e.to_string())?;
    guard.as_ref().map(|c| c.summary()).map_err(|e| e.clone())
}

#[tauri::command]
pub fn list_assessments() -> Result<Listing, String> {
    let dir = store::default_dir().ok_or("Could not determine the assessments folder")?;
    Ok(store::list(&dir))
}

fn with_catalog<T>(
    state: &State<'_, AppState>,
    f: impl FnOnce(&Catalog) -> Result<T, String>,
) -> Result<T, String> {
    let guard = state.catalog.lock().map_err(|e| e.to_string())?;
    let catalog = guard.as_ref().map_err(|e| e.clone())?;
    f(catalog)
}

fn exceptions_file() -> Result<std::path::PathBuf, String> {
    store::default_dir()
        .map(|d| Exceptions::path_in(&d))
        .ok_or_else(|| "Could not determine the assessments folder".to_string())
}

fn load_exceptions() -> Result<Exceptions, String> {
    Exceptions::load(&exceptions_file()?).map_err(|e| e.to_string())
}

/// Assessments with accepted risks applied.
fn load(paths: &[String]) -> Result<Vec<Assessment>, String> {
    exceptions::load_runs(paths, &load_exceptions()?, time::now()).map_err(|e| e.to_string())
}

/// The domains or tenant of `run` that a check of `group` is about.
fn run_scope(run: &str, group: &str) -> Result<Vec<String>, String> {
    let a = Assessment::load(std::path::Path::new(run)).map_err(|e| e.to_string())?;
    let keys = exceptions::scope_for(&a.manifest, group);
    if keys.is_empty() {
        return Err("This assessment names no domain or tenant to accept the risk for.".into());
    }
    Ok(keys)
}

/// Accepted risks, for the Settings screen.
#[tauri::command]
pub fn list_exceptions(state: State<'_, AppState>) -> Result<Vec<ExceptionRow>, String> {
    let list = load_exceptions()?;
    with_catalog(&state, |c| Ok(list.rows(c, time::now())))
}

/// Accepts the risk of a failed check for the domains and tenant of `run`,
/// recorded under the Windows account running the app.
#[tauri::command]
pub fn accept_risk(
    check: String,
    group: String,
    run: String,
    reason: String,
    expires_on: Option<String>,
) -> Result<(), String> {
    let reason = reason.trim().to_string();
    if reason.is_empty() {
        return Err("Give a reason for accepting the risk.".into());
    }
    let today = time::iso(time::now())[..10].to_string();
    let expires_on = expires_on
        .map(|d| d.trim().to_string())
        .filter(|d| !d.is_empty());
    if let Some(d) = &expires_on {
        if time::parse_iso(d).is_none() || d.len() != 10 {
            return Err(format!("{d} is not a date (yyyy-mm-dd)."));
        }
        if d.as_str() < today.as_str() {
            return Err("The expiry date is in the past.".into());
        }
    }
    let path = exceptions_file()?;
    let mut list = Exceptions::load(&path).map_err(|e| e.to_string())?;
    list.add(RiskAcceptance {
        check,
        scope: run_scope(&run, &group)?,
        reason,
        accepted_by: environment::detect()
            .user
            .ok_or("Could not determine the Windows account running Benchmark.")?,
        accepted_on: today,
        expires_on,
    });
    list.save(&path).map_err(|e| e.to_string())
}

/// Withdraws the acceptance of `check`: for the domains and tenant of `run`,
/// or for exactly `scope` when it comes from the Settings list.
#[tauri::command]
pub fn withdraw_risk(
    check: String,
    group: String,
    run: Option<String>,
    scope: Option<Vec<String>>,
) -> Result<(), String> {
    let keys = match (run, scope) {
        (Some(r), _) => run_scope(&r, &group)?,
        (None, Some(s)) => s,
        (None, None) => return Err("Say which assessment or scope to withdraw it for.".into()),
    };
    let path = exceptions_file()?;
    let mut list = Exceptions::load(&path).map_err(|e| e.to_string())?;
    if list.remove(&check, &keys) == 0 {
        return Err(format!("No accepted risk for {check} was found."));
    }
    list.save(&path).map_err(|e| e.to_string())
}

/// Imports a bundle (.zip of an assessment, or of collector output from a
/// standalone run) into the assessments folder, analyzing it if needed.
/// Returns the new assessment's folder.
#[tauri::command]
pub async fn open_bundle(app: AppHandle, path: String) -> Result<String, String> {
    let root = store::default_dir().ok_or("Could not determine the assessments folder")?;
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        with_catalog(&state, |c| {
            dca_core::bundle::import(std::path::Path::new(&path), &root, c, time::now())
                .map(|d| d.display().to_string())
                .map_err(|e| e.to_string())
        })
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Where assessments and the accepted-risk list are kept.
#[tauri::command]
pub fn assessments_folder() -> Result<String, String> {
    store::default_dir()
        .map(|d| d.display().to_string())
        .ok_or_else(|| "Could not determine the assessments folder".to_string())
}

/// One assessment, or several combined into one dashboard.
#[tauri::command]
pub fn open_assessments(
    state: State<'_, AppState>,
    paths: Vec<String>,
) -> Result<AssessmentView, String> {
    if paths.is_empty() {
        return Err("Choose at least one assessment.".into());
    }
    let runs = load(&paths)?;
    with_catalog(&state, |c| Ok(results::view(c, &runs)))
}

#[tauri::command]
pub fn compare_assessments(
    state: State<'_, AppState>,
    earlier: String,
    later: String,
) -> Result<Comparison, String> {
    let runs = load(&[earlier, later])?;
    with_catalog(&state, |c| Ok(compare::compare(c, &runs[0], &runs[1])))
}

fn powershell(script: &std::path::Path) -> std::process::Command {
    use std::process::{Command, Stdio};
    let mut cmd = Command::new("powershell.exe");
    cmd.args([
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
    ])
    .arg(script)
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

fn collector(app: &AppHandle, name: &str) -> Result<std::path::PathBuf, String> {
    Ok(app
        .path()
        .resource_dir()
        .map_err(|e| e.to_string())?
        .join("collectors")
        .join(name))
}

/// What the Collect step shows: the collector's own events, then analysis.
#[derive(Clone, serde::Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum CollectProgress {
    /// `scope` is "entra" or "ad": both collectors have a `users` area.
    Event {
        scope: &'static str,
        event: CollectEvent,
    },
    Analyzing,
}

#[derive(serde::Serialize)]
pub struct CollectOutcome {
    pub path: String,
    pub manifest: Manifest,
}

/// Runs one collector, forwarding its progress events to the UI and to
/// `<out>/events.jsonl`. Returns `None` when the run was cancelled, else
/// whatever the collector wrote to stderr.
fn run_collector(
    app: &AppHandle,
    scope: &'static str,
    mut cmd: std::process::Command,
    out: &std::path::Path,
) -> Result<Option<String>, String> {
    use std::io::{BufRead, BufReader, Write};

    let state = app.state::<AppState>();
    std::fs::create_dir_all(out).map_err(|e| e.to_string())?;
    let mut log = std::fs::File::create(out.join("events.jsonl")).map_err(|e| e.to_string())?;
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("Could not start PowerShell: {e}"))?;
    let stdout = child.stdout.take().ok_or("PowerShell produced no output")?;
    // Drained on its own thread so a chatty stderr cannot fill the pipe
    // and stall the collector.
    let stderr = child.stderr.take().map(|mut err| {
        std::thread::spawn(move || {
            let mut text = String::new();
            let _ = std::io::Read::read_to_string(&mut err, &mut text);
            text
        })
    });
    *state.collection.lock().map_err(|e| e.to_string())? = Some(child);

    for line in BufReader::new(stdout).lines().map_while(Result::ok) {
        if let Some(event) = CollectEvent::parse(&line) {
            let _ = writeln!(log, "{}", line.trim());
            let _ = app.emit("collect-progress", CollectProgress::Event { scope, event });
        }
    }
    let child = state.collection.lock().map_err(|e| e.to_string())?.take();
    let stderr = stderr.and_then(|t| t.join().ok()).unwrap_or_default();
    let Some(mut child) = child else {
        return Ok(None);
    };
    let _ = child.wait();
    Ok(Some(stderr))
}

/// Why a collector wrote nothing: its first error event, else its stderr.
fn collector_failure(out: &std::path::Path, stderr: &str) -> String {
    std::fs::read_to_string(out.join("events.jsonl"))
        .ok()
        .and_then(|t| {
            t.lines()
                .filter_map(CollectEvent::parse)
                .find_map(|e| match e {
                    CollectEvent::Error { message, .. } => Some(message),
                    _ => None,
                })
        })
        .unwrap_or_else(|| stderr.trim().to_string())
}

/// Creates an assessment, runs the Entra collector for `tenant` (first, so
/// the Microsoft sign-in happens up front) and the on-prem collector for
/// `domain`, then analyzes the result. Either may be left out. Progress
/// arrives as `collect-progress` events.
#[tauri::command]
pub async fn run_collection(
    app: AppHandle,
    name: Option<String>,
    domain: String,
    tenant: Option<String>,
    areas: Vec<String>,
    sources: Vec<String>,
) -> Result<CollectOutcome, String> {
    if !cfg!(windows) {
        return Err("Collection runs on Windows only.".into());
    }
    let root = store::default_dir().ok_or("Could not determine the assessments folder")?;
    let domain = domain.trim().to_string();
    let tenant = tenant.map(|t| t.trim().to_string()).filter(|t| {
        !t.is_empty()
            && sources.iter().any(|s| {
                matches!(
                    s.as_str(),
                    "graph"
                        | "graph-logs"
                        | "exo"
                        | "arm"
                        | "spo"
                        | "teams"
                        | "purview"
                        | "defender"
                )
            })
    });
    if domain.is_empty() && tenant.is_none() {
        return Err("Choose a domain or a Microsoft tenant to assess.".into());
    }
    let ad_script = collector(&app, "Invoke-DCACollect.ps1")?;
    let entra_script = collector(&app, "Invoke-DCAEntra.ps1")?;

    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        let spec = NewAssessment {
            name,
            domains: if domain.is_empty() {
                Vec::new()
            } else {
                vec![domain.clone()]
            },
            tenant: tenant.clone(),
            areas,
        };
        let dir = analysis::create(&root, spec, time::now()).map_err(|e| e.to_string())?;
        // A run that collected nothing is removed so it does not appear in
        // the list of assessments.
        let discard = || {
            let _ = std::fs::remove_dir_all(&dir);
        };
        let mut failures = Vec::new();
        let mut collected = false;

        if let Some(tenant) = &tenant {
            let out = analysis::entra_raw_dir(&dir, tenant);
            let mut cmd = powershell(&entra_script);
            cmd.arg("-Tenant")
                .arg(tenant)
                .arg("-OutDir")
                .arg(&out)
                .arg("-Sources")
                .arg(sources.join(","));
            let Some(stderr) =
                run_collector(&app, "entra", cmd, &out).inspect_err(|_| discard())?
            else {
                discard();
                return Err("Collection was cancelled.".into());
            };
            if out.join("collection.json").is_file() {
                collected = true;
            } else {
                failures.push(format!(
                    "Could not read {tenant}: {}",
                    collector_failure(&out, &stderr)
                ));
            }
        }

        if !domain.is_empty() {
            let out = analysis::ad_raw_dir(&dir, &domain);
            let mut cmd = powershell(&ad_script);
            cmd.arg("-Domain")
                .arg(&domain)
                .arg("-OutDir")
                .arg(&out)
                .arg("-Sources")
                .arg(sources.join(","));
            let Some(stderr) = run_collector(&app, "ad", cmd, &out).inspect_err(|_| discard())?
            else {
                discard();
                return Err("Collection was cancelled.".into());
            };
            if out.join("collection.json").is_file() {
                collected = true;
            } else {
                failures.push(format!(
                    "Could not read {domain}: {}",
                    collector_failure(&out, &stderr)
                ));
            }
        }

        if !collected {
            discard();
            return Err(failures.join("\n"));
        }
        let _ = app.emit("collect-progress", CollectProgress::Analyzing);
        let guard = state.catalog.lock().map_err(|e| e.to_string())?;
        let catalog = guard.as_ref().map_err(|e| e.clone())?;
        let manifest = analysis::analyze(&dir, catalog).map_err(|e| e.to_string())?;
        Ok(CollectOutcome {
            path: dir.display().to_string(),
            manifest,
        })
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Stops a running collection. What was already written stays on disk.
#[tauri::command]
pub fn cancel_collection(state: State<'_, AppState>) -> Result<(), String> {
    if let Some(mut child) = state.collection.lock().map_err(|e| e.to_string())?.take() {
        child.kill().map_err(|e| e.to_string())?;
        let _ = child.wait();
    }
    Ok(())
}

/// Runs `collectors/Test-DCAAccess.ps1` for the given on-prem sources. Each
/// result is emitted as an `access-probe` event as soon as it arrives, so
/// the UI shows real progress, and all results are returned at the end.
#[tauri::command]
pub async fn run_access_check(
    app: AppHandle,
    domain: String,
    sources: Vec<String>,
) -> Result<Vec<ProbeResult>, String> {
    if !cfg!(windows) {
        return Err("Access checks run on Windows only.".into());
    }
    let script = collector(&app, "Test-DCAAccess.ps1")?;

    tauri::async_runtime::spawn_blocking(move || {
        use std::io::{BufRead, BufReader};

        let mut cmd = powershell(&script);
        cmd.args(["-Domain", &domain, "-Sources", &sources.join(",")]);
        let mut child = cmd
            .spawn()
            .map_err(|e| format!("Could not start PowerShell: {e}"))?;
        let stdout = child.stdout.take().ok_or("PowerShell produced no output")?;
        let mut results = Vec::new();
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if let Some(result) = access::parse_probe_line(&line) {
                let _ = app.emit("access-probe", &result);
                results.push(result);
            }
        }
        let output = child.wait_with_output().map_err(|e| e.to_string())?;
        if !output.status.success() && results.is_empty() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("The access check failed: {}", stderr.trim()));
        }
        Ok(results)
    })
    .await
    .map_err(|e| e.to_string())?
}

/// The UI files built into the app, for exports that reuse its pages.
struct EmbeddedUi(tauri::AssetResolver<tauri::Wry>);

impl report::UiAssets for EmbeddedUi {
    fn get(&self, path: &str) -> Option<Vec<u8>> {
        let rel = path.trim_start_matches("./").trim_start_matches('/');
        self.0
            .get(format!("/{rel}"))
            .or_else(|| self.0.get(rel.to_string()))
            .map(|a| a.bytes)
    }
}

/// Writes the chosen reports into a new folder under `out_dir`. PDFs are
/// printed by Microsoft Edge (or Chrome) when one is installed.
#[tauri::command]
pub async fn export_report(
    app: AppHandle,
    mut request: ExportRequest,
) -> Result<ExportOutcome, String> {
    request.exceptions = load_exceptions()?;
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        let assets = EmbeddedUi(app.asset_resolver());
        let browser = report::find_browser();
        with_catalog(&state, |c| {
            report::export(c, &request, &assets, browser.as_deref(), time::now())
                .map_err(|e| e.to_string())
        })
    })
    .await
    .map_err(|e| e.to_string())?
}

fn account_dir() -> Result<std::path::PathBuf, String> {
    account::dir().ok_or_else(|| "Could not determine the account folder".into())
}

/// Whether a sign-in account has been created on this computer.
#[tauri::command]
pub fn account_exists() -> bool {
    account::dir().map(|d| account::exists(&d)).unwrap_or(false)
}

/// The signed-in account's username, for showing who is signed in.
#[tauri::command]
pub fn account_name() -> Option<String> {
    account::dir().and_then(|d| account::username(&d))
}

/// Creates the one account, at install time.
#[tauri::command]
pub fn create_account(username: String, password: String) -> Result<(), String> {
    account::create(&account_dir()?, &username, &password, time::now())
}

/// Confirms a username and password at sign-in.
#[tauri::command]
pub fn sign_in(username: String, password: String) -> Result<(), String> {
    account::verify(&account_dir()?, &username, &password)
}

/// Changes the password after checking the current one.
#[tauri::command]
pub fn change_password(
    username: String,
    current: String,
    new_password: String,
) -> Result<(), String> {
    account::change(
        &account_dir()?,
        &username,
        &current,
        &new_password,
        time::now(),
    )
}

/// Documents\Benchmark\Reports, where exports go unless the user picks
/// another folder.
#[tauri::command]
pub fn default_export_dir(app: AppHandle) -> Result<String, String> {
    let docs = app.path().document_dir().map_err(|e| e.to_string())?;
    Ok(docs.join("Benchmark").join("Reports").display().to_string())
}

/// Opens the Microsoft sign-in page again, for when the browser window the
/// collector opened was closed. Only Microsoft sign-in addresses are opened.
#[tauri::command]
pub fn open_sign_in(url: String) -> Result<(), String> {
    const ALLOWED: [&str; 3] = [
        "https://login.microsoftonline.com/",
        "https://microsoft.com/devicelogin",
        "https://www.microsoft.com/devicelogin",
    ];
    if !ALLOWED.iter().any(|a| url.starts_with(a)) {
        return Err("That is not a Microsoft sign-in address.".into());
    }
    let mut cmd = if cfg!(windows) {
        let mut c = std::process::Command::new("rundll32.exe");
        c.arg("url.dll,FileProtocolHandler");
        c
    } else if cfg!(target_os = "macos") {
        std::process::Command::new("open")
    } else {
        std::process::Command::new("xdg-open")
    };
    cmd.arg(&url)
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("Could not open the browser: {e}"))
}

/// Opens a link in the system's default browser. Only http(s) links, so
/// the app never hands another protocol handler a crafted address.
#[tauri::command]
pub fn open_url(url: String) -> Result<(), String> {
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err("Only web links can be opened.".into());
    }
    let mut cmd = if cfg!(windows) {
        let mut c = std::process::Command::new("rundll32.exe");
        c.arg("url.dll,FileProtocolHandler");
        c
    } else if cfg!(target_os = "macos") {
        std::process::Command::new("open")
    } else {
        std::process::Command::new("xdg-open")
    };
    cmd.arg(&url)
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("Could not open the browser: {e}"))
}

/// Opens an export folder in File Explorer.
#[tauri::command]
pub fn open_folder(path: String) -> Result<(), String> {
    let dir = std::path::Path::new(&path);
    if !dir.is_dir() {
        return Err(format!("{path} is not a folder."));
    }
    let program = if cfg!(windows) {
        "explorer.exe"
    } else if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    std::process::Command::new(program)
        .arg(dir)
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("Could not open the folder: {e}"))
}
