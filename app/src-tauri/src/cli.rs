//! Command-line use of Benchmark.exe, for servers, scheduled runs and
//! scripts. Without arguments the app window opens as usual.
//!
//! Collection runs through the PowerShell collectors themselves (with
//! -Bundle); this analyzes their output and exports reports.

use std::path::{Path, PathBuf};

use dca_core::analysis;
use dca_core::bundle;
use dca_core::catalog::Catalog;
use dca_core::exceptions::Exceptions;
use dca_core::report::{self, Branding, ExportRequest, Format, ReportChoice, ReportKind};
use dca_core::results::Assessment;
use dca_core::store;
use dca_core::time;
use tauri::utils::assets::AssetKey;

const HELP: &str = "\
Benchmark command line

  Benchmark.exe analyze <bundle.zip | assessment folder> [--into <folder>]
      Imports a bundle (from a collector run with -Bundle, or a zipped
      assessment) into the assessments folder and analyzes it, or analyzes
      an assessment folder again in place.

  Benchmark.exe export <assessment folder>... --out <folder> [options]
      Writes reports for one assessment, or several combined.
        --reports   executive,technical,remediation,dashboard,changes,raw
                    (default: executive,technical,remediation)
        --formats   pdf,html,xlsx,csv,json,sarif; each report gets the ones
                    it supports (default: pdf,html,xlsx)
        --baseline <folder>     earlier assessment, for the changes report
        --organization <text>   --prepared-by <text>   --classification <text>
        --pseudonymize          replace names of people and objects
        --omit-accepted         leave accepted risks out of the plan

  Benchmark.exe list
      Lists the assessments in the assessments folder.

Accepted risks recorded in the app apply to analyze and export alike.
From PowerShell, pipe to Out-Host (Benchmark.exe list | Out-Host) so
the prompt waits for the command to finish; from cmd, use start /wait.
Exit code 0 on success, 1 on failure, 2 for a usage error.";

const COMMANDS: [&str; 5] = ["analyze", "export", "list", "help", "--help"];

/// Runs a command-line invocation. Returns None when `args` (without the
/// program name) do not start with a command, so the window should open.
pub fn run<R: tauri::Runtime>(args: &[String], ctx: &tauri::Context<R>) -> Option<i32> {
    let command = args.first()?.as_str();
    if !COMMANDS.contains(&command) && command != "/?" {
        return None;
    }
    attach_console();
    let rest = &args[1..];
    let outcome = match command {
        "analyze" => analyze(rest, ctx),
        "export" => export(rest, ctx),
        "list" => list(),
        _ => {
            println!("{HELP}");
            Ok(())
        }
    };
    Some(match outcome {
        Ok(()) => 0,
        Err(Failure::Usage(m)) => {
            eprintln!("{m}\n\nRun Benchmark.exe help for usage.");
            2
        }
        Err(Failure::Run(m)) => {
            eprintln!("Error: {m}");
            1
        }
    })
}

enum Failure {
    Usage(String),
    Run(String),
}

impl<E: std::fmt::Display> From<E> for Failure {
    fn from(e: E) -> Self {
        Failure::Run(e.to_string())
    }
}

type Outcome = Result<(), Failure>;

fn usage(m: impl Into<String>) -> Failure {
    Failure::Usage(m.into())
}

/// Positional arguments and `--name value` / `--flag` options.
struct Args {
    positional: Vec<String>,
    options: Vec<(String, Option<String>)>,
}

const FLAGS: [&str; 2] = ["--pseudonymize", "--omit-accepted"];

fn parse(args: &[String]) -> Result<Args, Failure> {
    let mut out = Args {
        positional: Vec::new(),
        options: Vec::new(),
    };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if let Some(name) = a.strip_prefix("--") {
            if FLAGS.contains(&a.as_str()) {
                out.options.push((name.to_string(), None));
            } else {
                let value = it
                    .next()
                    .ok_or_else(|| usage(format!("{a} needs a value")))?;
                out.options.push((name.to_string(), Some(value.clone())));
            }
        } else {
            out.positional.push(a.clone());
        }
    }
    Ok(out)
}

impl Args {
    fn get(&self, name: &str) -> Option<&str> {
        self.options
            .iter()
            .rev()
            .find(|(n, _)| n == name)
            .and_then(|(_, v)| v.as_deref())
    }

    fn flag(&self, name: &str) -> bool {
        self.options.iter().any(|(n, _)| n == name)
    }

    fn only(&self, allowed: &[&str]) -> Outcome {
        match self
            .options
            .iter()
            .find(|(n, _)| !allowed.contains(&n.as_str()))
        {
            Some((n, _)) => Err(usage(format!("Unknown option --{n}"))),
            None => Ok(()),
        }
    }
}

fn catalog<R: tauri::Runtime>(ctx: &tauri::Context<R>) -> Result<Catalog, Failure> {
    let dir = tauri::utils::platform::resource_dir(ctx.package_info(), &tauri::Env::default())
        .map_err(|e| Failure::Run(format!("Could not find the app's resources: {e}")))?;
    Ok(Catalog::load(&dir.join("checks"))?)
}

fn assessments_dir(into: Option<&str>) -> Result<PathBuf, Failure> {
    into.map(PathBuf::from)
        .or_else(store::default_dir)
        .ok_or_else(|| {
            Failure::Run("Could not determine the assessments folder; pass --into".into())
        })
}

fn exceptions() -> Result<Exceptions, Failure> {
    match store::default_dir() {
        Some(d) => Ok(Exceptions::load(&Exceptions::path_in(&d))?),
        None => Ok(Exceptions::default()),
    }
}

fn summary(dir: &Path, catalog: &Catalog) -> Outcome {
    let runs =
        dca_core::exceptions::load_runs(&[dir.display().to_string()], &exceptions()?, time::now())?;
    let view = dca_core::results::view(catalog, &runs);
    let s = &view.summary;
    println!("Assessment: {}", dir.display());
    match s.score {
        Some(score) => println!("Score: {score} of 100"),
        None => println!("Score: none (nothing was assessed)"),
    }
    println!(
        "Checks: {} failed ({} critical, {} high, {} medium, {} low), {} passed, {} not assessed, {} accepted",
        s.status.failed,
        s.severity.critical,
        s.severity.high,
        s.severity.medium,
        s.severity.low,
        s.status.passed,
        s.status.not_assessed,
        s.status.accepted
    );
    Ok(())
}

fn analyze<R: tauri::Runtime>(args: &[String], ctx: &tauri::Context<R>) -> Outcome {
    let a = parse(args)?;
    a.only(&["into"])?;
    let [source] = a.positional.as_slice() else {
        return Err(usage("analyze takes one bundle or assessment folder"));
    };
    let source = Path::new(source);
    let catalog = catalog(ctx)?;
    let dir = if source.is_dir() {
        if a.get("into").is_some() {
            return Err(usage(
                "--into is for bundles; a folder is analyzed in place",
            ));
        }
        println!("Analyzing {} ...", source.display());
        analysis::analyze(source, &catalog)?;
        source.to_path_buf()
    } else if source.is_file() {
        let root = assessments_dir(a.get("into"))?;
        println!("Importing {} into {} ...", source.display(), root.display());
        bundle::import(source, &root, &catalog, time::now())?
    } else {
        return Err(Failure::Run(format!("{} does not exist", source.display())));
    };
    summary(&dir, &catalog)
}

fn kind(name: &str) -> Result<ReportKind, Failure> {
    Ok(match name {
        "executive" => ReportKind::Executive,
        "technical" => ReportKind::Technical,
        "remediation" => ReportKind::Remediation,
        "dashboard" => ReportKind::Dashboard,
        "changes" => ReportKind::Changes,
        "raw" | "results" => ReportKind::Raw,
        other => return Err(usage(format!("Unknown report {other}"))),
    })
}

fn format(name: &str) -> Result<Format, Failure> {
    Ok(match name {
        "pdf" => Format::Pdf,
        "html" => Format::Html,
        "xlsx" => Format::Xlsx,
        "csv" => Format::Csv,
        "json" => Format::Json,
        "sarif" => Format::Sarif,
        other => return Err(usage(format!("Unknown format {other}"))),
    })
}

/// The formats each report can be written in, as the Export screen offers.
fn supported(k: ReportKind) -> &'static [Format] {
    match k {
        ReportKind::Executive | ReportKind::Technical | ReportKind::Changes => {
            &[Format::Pdf, Format::Html]
        }
        ReportKind::Remediation => &[Format::Xlsx, Format::Csv],
        ReportKind::Dashboard => &[Format::Html],
        ReportKind::Raw => &[Format::Json, Format::Csv, Format::Sarif],
    }
}

fn list_of<T>(text: &str, f: fn(&str) -> Result<T, Failure>) -> Result<Vec<T>, Failure> {
    text.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| f(&s.to_ascii_lowercase()))
        .collect()
}

struct Assets<'a, R: tauri::Runtime>(&'a dyn tauri::Assets<R>);

impl<R: tauri::Runtime> report::UiAssets for Assets<'_, R> {
    fn get(&self, path: &str) -> Option<Vec<u8>> {
        let rel = path.trim_start_matches("./").trim_start_matches('/');
        self.0
            .get(&AssetKey::from(format!("/{rel}").as_str()))
            .map(|b| b.into_owned())
    }
}

fn export<R: tauri::Runtime>(args: &[String], ctx: &tauri::Context<R>) -> Outcome {
    let a = parse(args)?;
    a.only(&[
        "out",
        "reports",
        "formats",
        "baseline",
        "organization",
        "prepared-by",
        "classification",
        "pseudonymize",
        "omit-accepted",
    ])?;
    if a.positional.is_empty() {
        return Err(usage("export needs at least one assessment folder"));
    }
    let out = a
        .get("out")
        .ok_or_else(|| usage("export needs --out <folder>"))?;
    let kinds = list_of(
        a.get("reports")
            .unwrap_or("executive,technical,remediation"),
        kind,
    )?;
    let formats = list_of(a.get("formats").unwrap_or("pdf,html,xlsx"), format)?;
    let reports: Vec<ReportChoice> = kinds
        .into_iter()
        .map(|k| ReportChoice {
            kind: k,
            formats: supported(k)
                .iter()
                .copied()
                .filter(|f| formats.contains(f))
                .collect(),
        })
        .filter(|r| !r.formats.is_empty())
        .collect();
    if reports.is_empty() {
        return Err(usage(
            "None of the chosen reports can be written in the chosen formats",
        ));
    }
    for p in &a.positional {
        Assessment::load(Path::new(p))?;
    }
    let request = ExportRequest {
        paths: a.positional.clone(),
        baseline: a.get("baseline").map(str::to_string),
        out_dir: out.to_string(),
        reports,
        branding: Branding {
            organization: a.get("organization").unwrap_or_default().to_string(),
            prepared_by: a.get("prepared-by").unwrap_or_default().to_string(),
            classification: a.get("classification").unwrap_or_default().to_string(),
            logo: None,
        },
        pseudonymize: a.flag("pseudonymize"),
        omit_accepted: a.flag("omit-accepted"),
        exceptions: exceptions()?,
    };
    let catalog = catalog(ctx)?;
    let browser = report::find_browser();
    let outcome = report::export(
        &catalog,
        &request,
        &Assets(ctx.assets()),
        browser.as_deref(),
        time::now(),
    )?;
    println!("Saved to {}", outcome.folder);
    for f in &outcome.files {
        println!("  {f}");
    }
    for w in &outcome.warnings {
        eprintln!("Warning: {w}");
    }
    Ok(())
}

fn list() -> Outcome {
    let dir = assessments_dir(None)?;
    let listing = store::list(&dir);
    println!("Assessments in {}", dir.display());
    if listing.assessments.is_empty() {
        println!("  (none)");
    }
    for a in &listing.assessments {
        let m = &a.manifest;
        let scope: Vec<&str> = m
            .scope
            .domains
            .iter()
            .map(String::as_str)
            .chain(m.scope.tenant.as_deref())
            .collect();
        let score = match m.score {
            Some(s) => format!("score {s}"),
            None if Path::new(&a.path).join("results.json").is_file() => "analyzed".into(),
            None => "not analyzed".into(),
        };
        println!(
            "  {}  {}  {}  {}",
            m.finished_at.as_deref().unwrap_or(&m.started_at),
            scope.join(", "),
            score,
            a.path
        );
    }
    for u in &listing.unreadable {
        println!("  unreadable: {} ({})", u.path, u.reason);
    }
    Ok(())
}

/// A release build is a Windows GUI program with no console of its own;
/// write to the console of the command prompt that started it.
#[cfg(windows)]
fn attach_console() {
    #[link(name = "kernel32")]
    extern "system" {
        fn AttachConsole(process: u32) -> i32;
    }
    const ATTACH_PARENT_PROCESS: u32 = u32::MAX;
    // SAFETY: AttachConsole takes a process id and has no other effects.
    unsafe {
        AttachConsole(ATTACH_PARENT_PROCESS);
    }
}

#[cfg(not(windows))]
fn attach_console() {}
