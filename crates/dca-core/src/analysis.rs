//! Creating an assessment folder and analyzing what was collected into it.
//!
//! ```text
//! <assessments>/<yyyyMMdd-HHmm>-<scope>/
//!   manifest.json            name, scope, areas, times, score
//!   raw/ad/<domain>/...      what Invoke-DCACollect.ps1 wrote, plus events.jsonl
//!   raw/entra/<tenant>/...   what Invoke-DCAEntra.ps1 wrote, plus events.jsonl
//!
//! Each domain and tenant is analyzed on its own; the hybrid checks then
//! read all of them together.
//!   results.json             written by analyze()
//!   directory.json           written by analyze()
//! ```

use std::fs;
use std::path::{Path, PathBuf};

use crate::ad;
use crate::catalog::Catalog;
use crate::entra;
use crate::hybrid;
use crate::results::{self, Assessment, CheckResult, DirectoryFile, ResultStatus, ResultsFile};
use crate::store::{Manifest, Scope};
use crate::{time, Error, Result};

pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

fn io(path: &Path) -> impl FnOnce(std::io::Error) -> Error + '_ {
    move |source| Error::Io {
        path: path.display().to_string(),
        source,
    }
}

fn write_json<T: serde::Serialize>(path: &Path, value: &T, pretty: bool) -> Result<()> {
    let text = if pretty {
        serde_json::to_string_pretty(value)
    } else {
        serde_json::to_string(value)
    }
    .map_err(|e| Error::Parse {
        path: path.display().to_string(),
        message: e.to_string(),
    })?;
    fs::write(path, text).map_err(io(path))
}

fn read_manifest(dir: &Path) -> Result<Manifest> {
    let path = dir.join("manifest.json");
    let text = fs::read_to_string(&path).map_err(io(&path))?;
    serde_json::from_str(&text).map_err(|e| Error::Parse {
        path: path.display().to_string(),
        message: e.to_string(),
    })
}

/// Characters kept in folder names; everything else becomes `-`.
fn slug(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect()
}

pub struct NewAssessment {
    pub name: Option<String>,
    pub domains: Vec<String>,
    pub tenant: Option<String>,
    pub areas: Vec<String>,
}

/// Creates the assessment folder under `root` with its manifest.
pub fn create(root: &Path, spec: NewAssessment, now: i64) -> Result<PathBuf> {
    let stamp = time::iso(now);
    let compact: String = stamp[..16].chars().filter(|c| c.is_ascii_digit()).collect();
    let scope = spec
        .domains
        .first()
        .or(spec.tenant.as_ref())
        .map(|s| slug(s))
        .unwrap_or_else(|| "assessment".into());
    let base = format!("{}-{}-{scope}", &compact[..8], &compact[8..12]);
    let mut dir = root.join(&base);
    let mut n = 2;
    while dir.exists() {
        dir = root.join(format!("{base}-{n}"));
        n += 1;
    }
    fs::create_dir_all(&dir).map_err(io(&dir))?;
    let manifest = Manifest {
        name: spec.name.filter(|n| !n.trim().is_empty()),
        tool_version: TOOL_VERSION.into(),
        catalog_version: TOOL_VERSION.into(),
        scope: Scope {
            domains: spec.domains,
            tenant: spec.tenant,
        },
        started_at: stamp,
        finished_at: None,
        score: None,
        areas: spec.areas,
    };
    write_json(&dir.join("manifest.json"), &manifest, true)?;
    Ok(dir)
}

/// Where the on-prem collector writes for `domain`.
pub fn ad_raw_dir(assessment: &Path, domain: &str) -> PathBuf {
    assessment.join("raw").join("ad").join(slug(domain))
}

/// Where the Entra collector writes for `tenant`.
pub fn entra_raw_dir(assessment: &Path, tenant: &str) -> PathBuf {
    assessment.join("raw").join("entra").join(slug(tenant))
}

/// Sub-folders of `root` that hold a `collection.json`, sorted.
fn collected(root: &Path) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = match fs::read_dir(root) {
        Ok(entries) => entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.join("collection.json").is_file())
            .collect(),
        Err(_) => Vec::new(),
    };
    dirs.sort();
    dirs
}

/// Folds a second domain's result for the same check into the first.
fn merge(into: &mut CheckResult, other: CheckResult) {
    use ResultStatus::*;
    into.status = match (into.status, other.status) {
        (Failed, _) | (_, Failed) => Failed,
        (Passed, _) | (_, Passed) => Passed,
        (s, _) => s,
    };
    into.affected_count = match (into.affected_count, other.affected_count) {
        (None, None) => None,
        (a, b) => Some(a.unwrap_or(0) + b.unwrap_or(0)),
    };
    into.affected_unit = into.affected_unit.take().or(other.affected_unit);
    into.affected.extend(other.affected);
    into.evidence.extend(other.evidence);
    // Keep the more severe override (the enum lists the most severe first).
    into.severity = match (into.severity, other.severity) {
        (Some(a), Some(b)) => Some(if (b as u8) < (a as u8) { b } else { a }),
        (a, b) => a.or(b),
    };
    into.found = match (into.found.take(), other.found) {
        (Some(a), Some(b)) if a != b => Some(format!("{a}; {b}")),
        (a, b) => a.or(b),
    };
    into.raw = match (into.raw.take(), other.raw) {
        (Some(a), Some(b)) => Some(format!("{a}\n{b}")),
        (a, b) => a.or(b),
    };
    into.note = into.note.take().or(other.note);
}

/// Analyzes everything collected into `dir`, writes `results.json` and
/// `directory.json`, and records the finish time and score in the manifest.
pub fn analyze(dir: &Path, catalog: &Catalog) -> Result<Manifest> {
    let mut manifest = read_manifest(dir)?;
    let mut checks: Vec<CheckResult> = Vec::new();
    let mut paths = Vec::new();
    let mut directory = DirectoryFile::default();
    let mut finished: Option<String> = None;

    let add = |found: Vec<CheckResult>, checks: &mut Vec<CheckResult>| {
        for r in found {
            match checks.iter_mut().find(|c| c.id == r.id) {
                Some(existing) => merge(existing, r),
                None => checks.push(r),
            }
        }
    };
    let mut latest = |f: &Option<String>| {
        if let Some(f) = f {
            if finished.as_ref().is_none_or(|x| f > x) {
                finished = Some(f.clone());
            }
        }
    };

    let domains = collected(&dir.join("raw").join("ad"))
        .iter()
        .map(|d| ad::raw::RawDomain::load(d))
        .collect::<Result<Vec<_>>>()?;
    let tenants = collected(&dir.join("raw").join("entra"))
        .iter()
        .map(|d| entra::raw::RawTenant::load(d))
        .collect::<Result<Vec<_>>>()?;
    let models: Vec<ad::model::Model> = domains.iter().map(ad::model::Model::build).collect();
    let clouds: Vec<entra::model::Tenant> =
        tenants.iter().map(entra::model::Tenant::build).collect();

    for m in &models {
        latest(&m.raw.finished_at);
        let out = ad::analyze_model(catalog, m, &manifest.areas);
        add(out.checks, &mut checks);
        paths.extend(out.paths);
        directory.sources.extend(out.directory.sources);
        directory.objects.extend(out.directory.objects);
        directory.edges.extend(out.directory.edges);
    }
    for t in &clouds {
        latest(&t.raw.finished_at);
        let out = entra::analyze_tenant(catalog, t, &manifest.areas);
        add(out.checks, &mut checks);
        directory.sources.extend(out.directory.sources);
        directory.objects.extend(out.directory.objects);
        directory.edges.extend(out.directory.edges);
    }
    if !checks.is_empty() {
        let ctx = hybrid::Ctx {
            domains: &models,
            tenant: clouds.first(),
        };
        add(hybrid::analyze(catalog, &ctx, &manifest.areas), &mut checks);
        directory
            .edges
            .extend(hybrid::sync_edges(&ctx, &directory.objects));
    }
    if checks.is_empty() {
        return Err(Error::Assessment(format!(
            "{} has no collected data to analyze",
            dir.display()
        )));
    }

    write_json(
        &dir.join("results.json"),
        &ResultsFile { checks, paths },
        true,
    )?;
    write_json(&dir.join("directory.json"), &directory, false)?;

    manifest.finished_at = Some(finished.unwrap_or_else(|| time::iso(time::now())));
    write_json(&dir.join("manifest.json"), &manifest, true)?;
    let assessment = Assessment::load(dir)?;
    let score = results::view(catalog, std::slice::from_ref(&assessment))
        .summary
        .score;
    manifest.score = score.map(f64::from);
    write_json(&dir.join("manifest.json"), &manifest, true)?;
    Ok(manifest)
}
