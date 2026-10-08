//! The assessments folder. Each assessment is a sub-folder holding its
//! telemetry bundle, a `manifest.json` and, once analyzed, its results.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Default location: `%LOCALAPPDATA%\Benchmark\Assessments` on Windows,
/// `$XDG_DATA_HOME/benchmark/assessments` (or `~/.local/share/...`) elsewhere.
/// Installs from before the rename to Benchmark kept assessments under
/// `DCAssessor`; while that folder exists and the new one does not, it stays
/// the default so earlier assessments do not disappear.
pub fn default_dir() -> Option<PathBuf> {
    let base = if cfg!(windows) {
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
    } else {
        std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
    }?;
    Some(pick_dir(&base))
}

fn pick_dir(base: &Path) -> PathBuf {
    let (current, legacy) = if cfg!(windows) {
        (
            base.join("Benchmark").join("Assessments"),
            base.join("DCAssessor").join("Assessments"),
        )
    } else {
        (
            base.join("benchmark").join("assessments"),
            base.join("dcassessor").join("assessments"),
        )
    };
    if !current.exists() && legacy.is_dir() {
        legacy
    } else {
        current
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scope {
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub tenant: Option<String>,
}

/// The subset of a bundle's `manifest.json` the Start screen needs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    /// Display name chosen by the user, for example "October review".
    #[serde(default)]
    pub name: Option<String>,
    pub tool_version: String,
    pub catalog_version: String,
    pub scope: Scope,
    pub started_at: String,
    #[serde(default)]
    pub finished_at: Option<String>,
    #[serde(default)]
    pub score: Option<f64>,
    /// Area codes chosen for this run. Empty means every area.
    #[serde(default)]
    pub areas: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AssessmentEntry {
    pub path: String,
    pub name: String,
    pub manifest: Manifest,
}

/// A folder that looked like an assessment but could not be read. Shown to
/// the user rather than silently skipped.
#[derive(Debug, Clone, Serialize)]
pub struct UnreadableEntry {
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Listing {
    pub dir: String,
    pub exists: bool,
    pub assessments: Vec<AssessmentEntry>,
    pub unreadable: Vec<UnreadableEntry>,
}

/// Lists assessments in `dir`, newest first. A missing folder is not an
/// error: it simply means no assessment has been run yet.
pub fn list(dir: &Path) -> Listing {
    let mut listing = Listing {
        dir: dir.display().to_string(),
        exists: dir.is_dir(),
        assessments: Vec::new(),
        unreadable: Vec::new(),
    };
    let Ok(entries) = fs::read_dir(dir) else {
        return listing;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let manifest_path = path.join("manifest.json");
        if !path.is_dir() || !manifest_path.is_file() {
            continue;
        }
        let parsed = fs::read_to_string(&manifest_path)
            .map_err(|e| e.to_string())
            .and_then(|t| serde_json::from_str::<Manifest>(&t).map_err(|e| e.to_string()));
        match parsed {
            Ok(manifest) => listing.assessments.push(AssessmentEntry {
                path: path.display().to_string(),
                name: entry.file_name().to_string_lossy().into_owned(),
                manifest,
            }),
            Err(reason) => listing.unreadable.push(UnreadableEntry {
                path: path.display().to_string(),
                reason,
            }),
        }
    }
    listing
        .assessments
        .sort_by(|a, b| b.manifest.started_at.cmp(&a.manifest.started_at));
    listing
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_folder_is_an_empty_listing() {
        let dir = tempfile::tempdir().unwrap();
        let listing = list(&dir.path().join("nope"));
        assert!(!listing.exists);
        assert!(listing.assessments.is_empty());
    }

    #[test]
    fn lists_newest_first_and_reports_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        let mk = |name: &str, body: &str| {
            let p = dir.path().join(name);
            fs::create_dir_all(&p).unwrap();
            fs::write(p.join("manifest.json"), body).unwrap();
        };
        let manifest = |started: &str| {
            format!(
                r#"{{"tool_version":"0.1.0","catalog_version":"1","scope":{{"domains":["corp.example"]}},"started_at":"{started}"}}"#
            )
        };
        mk("older", &manifest("2026-01-01T10:00:00Z"));
        mk("newer", &manifest("2026-02-01T10:00:00Z"));
        mk("broken", "{ not json");
        fs::create_dir_all(dir.path().join("not-an-assessment")).unwrap();

        let listing = list(dir.path());
        let names: Vec<_> = listing
            .assessments
            .iter()
            .map(|a| a.name.as_str())
            .collect();
        assert_eq!(names, ["newer", "older"]);
        assert_eq!(listing.unreadable.len(), 1);
    }
}

#[cfg(test)]
mod default_dir_tests {
    use super::pick_dir;

    #[test]
    fn keeps_the_folder_from_before_the_rename() {
        let base = std::env::temp_dir().join(format!("bm-store-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let (new, old) = if cfg!(windows) {
            (
                base.join("Benchmark").join("Assessments"),
                base.join("DCAssessor").join("Assessments"),
            )
        } else {
            (
                base.join("benchmark").join("assessments"),
                base.join("dcassessor").join("assessments"),
            )
        };
        assert_eq!(pick_dir(&base), new);
        std::fs::create_dir_all(&old).unwrap();
        assert_eq!(pick_dir(&base), old);
        std::fs::create_dir_all(&new).unwrap();
        assert_eq!(pick_dir(&base), new);
        let _ = std::fs::remove_dir_all(&base);
    }
}
