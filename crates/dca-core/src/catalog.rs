//! The check catalog: groups, areas, data sources and checks, loaded from the
//! TOML files under `checks/`.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub id: String,
    pub title: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Area {
    pub code: String,
    pub title: String,
    pub group: String,
    pub sources: Vec<String>,
    /// Areas whose checks are generated from baseline files instead of
    /// being written by hand.
    #[serde(default)]
    pub generated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceKind {
    Onprem,
    Cloud,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Source {
    pub id: String,
    pub title: String,
    pub needs: String,
    pub kind: SourceKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Planned,
    Implemented,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Check {
    pub id: String,
    pub title: String,
    pub status: CheckStatus,
    #[serde(default)]
    pub severity: Option<Severity>,
    /// Filled from the enclosing file's `area` key.
    #[serde(default)]
    pub area: String,
    /// What the finding page shows. Optional: most checks are still planned.
    #[serde(default)]
    pub detail: Option<CheckDetail>,
}

/// The explanation shown on a finding's page. Lives in the catalog, not in
/// results, so every run of a check explains it the same way.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CheckDetail {
    pub description: String,
    #[serde(default)]
    pub impact: Option<String>,
    /// How an attacker uses the weakness, one step per entry.
    #[serde(default)]
    pub attack: Vec<String>,
    #[serde(default)]
    pub remediation: Vec<String>,
    /// A read-only command or procedure that shows whether the fix worked.
    #[serde(default)]
    pub verify: Option<String>,
    /// CVSS 3.1 base vector, our estimate for the typical case.
    #[serde(default)]
    pub cvss: Option<String>,
    /// MITRE ATT&CK technique IDs; names and tactics come from `mitre.toml`.
    #[serde(default)]
    pub mitre: Vec<String>,
    #[serde(default)]
    pub frameworks: Vec<String>,
    #[serde(default)]
    pub references: Vec<Reference>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reference {
    pub title: String,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Technique {
    pub id: String,
    pub name: String,
    pub tactic: String,
}

#[derive(Debug, Clone, Default)]
pub struct Catalog {
    pub groups: Vec<Group>,
    pub areas: Vec<Area>,
    pub sources: Vec<Source>,
    pub checks: Vec<Check>,
    pub techniques: Vec<Technique>,
}

#[derive(Deserialize)]
struct TechniquesFile {
    technique: Vec<Technique>,
}

#[derive(Deserialize)]
struct GroupsFile {
    group: Vec<Group>,
}

#[derive(Deserialize)]
struct AreasFile {
    area: Vec<Area>,
}

#[derive(Deserialize)]
struct SourcesFile {
    source: Vec<Source>,
}

#[derive(Deserialize)]
struct ChecksFile {
    area: String,
    #[serde(default)]
    check: Vec<Check>,
}

const INDEX_FILES: [&str; 4] = ["groups.toml", "areas.toml", "sources.toml", "mitre.toml"];

fn read_toml<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let text = fs::read_to_string(path).map_err(|source| Error::Io {
        path: path.display().to_string(),
        source,
    })?;
    toml::from_str(&text).map_err(|e| Error::Parse {
        path: path.display().to_string(),
        message: e.to_string(),
    })
}

impl Catalog {
    /// Loads and validates the catalog rooted at `dir`.
    pub fn load(dir: &Path) -> Result<Catalog> {
        let groups = read_toml::<GroupsFile>(&dir.join("groups.toml"))?.group;
        let areas = read_toml::<AreasFile>(&dir.join("areas.toml"))?.area;
        let sources = read_toml::<SourcesFile>(&dir.join("sources.toml"))?.source;
        let mitre_path = dir.join("mitre.toml");
        let techniques = if mitre_path.is_file() {
            read_toml::<TechniquesFile>(&mitre_path)?.technique
        } else {
            Vec::new()
        };

        let mut files = Vec::new();
        collect_check_files(dir, dir, &mut files)?;
        files.sort();

        let mut checks = Vec::new();
        for path in files {
            let file: ChecksFile = read_toml(&path)?;
            for mut check in file.check {
                check.area = file.area.clone();
                checks.push(check);
            }
        }

        let catalog = Catalog {
            groups,
            areas,
            sources,
            checks,
            techniques,
        };
        catalog.validate()?;
        Ok(catalog)
    }

    fn validate(&self) -> Result<()> {
        let group_ids: HashSet<&str> = self.groups.iter().map(|g| g.id.as_str()).collect();
        let source_ids: HashSet<&str> = self.sources.iter().map(|s| s.id.as_str()).collect();
        let mut area_codes = HashSet::new();
        for area in &self.areas {
            if !area_codes.insert(area.code.as_str()) {
                return Err(Error::Catalog(format!("duplicate area {}", area.code)));
            }
            if !group_ids.contains(area.group.as_str()) {
                return Err(Error::Catalog(format!(
                    "area {} uses unknown group {}",
                    area.code, area.group
                )));
            }
            if let Some(s) = area
                .sources
                .iter()
                .find(|s| !source_ids.contains(s.as_str()))
            {
                return Err(Error::Catalog(format!(
                    "area {} uses unknown source {s}",
                    area.code
                )));
            }
        }
        let mut ids = HashSet::new();
        for check in &self.checks {
            if !ids.insert(check.id.as_str()) {
                return Err(Error::Catalog(format!("duplicate check {}", check.id)));
            }
            if !area_codes.contains(check.area.as_str()) {
                return Err(Error::Catalog(format!(
                    "check {} is in unknown area {}",
                    check.id, check.area
                )));
            }
            if !check.id.starts_with(&format!("{}-", check.area)) {
                return Err(Error::Catalog(format!(
                    "check {} does not start with its area code {}",
                    check.id, check.area
                )));
            }
            if let Some(detail) = &check.detail {
                if let Some(t) = detail.mitre.iter().find(|t| self.technique(t).is_none()) {
                    return Err(Error::Catalog(format!(
                        "check {} uses MITRE technique {t}, which is not in mitre.toml",
                        check.id
                    )));
                }
                if let Some(v) = &detail.cvss {
                    crate::cvss::base_score(v).map_err(|e| {
                        Error::Catalog(format!(
                            "check {} has an invalid CVSS vector: {e}",
                            check.id
                        ))
                    })?;
                }
            }
            if check.status == CheckStatus::Implemented && check.severity.is_none() {
                return Err(Error::Catalog(format!(
                    "implemented check {} has no severity",
                    check.id
                )));
            }
        }
        Ok(())
    }

    pub fn check(&self, id: &str) -> Option<&Check> {
        self.checks.iter().find(|c| c.id == id)
    }

    pub fn area(&self, code: &str) -> Option<&Area> {
        self.areas.iter().find(|a| a.code == code)
    }

    pub fn technique(&self, id: &str) -> Option<&Technique> {
        self.techniques.iter().find(|t| t.id == id)
    }

    /// Counts per group and per area, in catalog order, for the UI.
    pub fn summary(&self) -> CatalogSummary {
        let mut per_area: HashMap<&str, (usize, usize)> = HashMap::new();
        for check in &self.checks {
            let entry = per_area.entry(check.area.as_str()).or_default();
            entry.0 += 1;
            if check.status == CheckStatus::Implemented {
                entry.1 += 1;
            }
        }

        let groups = self
            .groups
            .iter()
            .map(|g| {
                let areas: Vec<AreaSummary> = self
                    .areas
                    .iter()
                    .filter(|a| a.group == g.id)
                    .map(|a| {
                        let (checks, implemented) =
                            per_area.get(a.code.as_str()).copied().unwrap_or_default();
                        AreaSummary {
                            code: a.code.clone(),
                            title: a.title.clone(),
                            sources: a.sources.clone(),
                            generated: a.generated,
                            checks,
                            implemented,
                        }
                    })
                    .collect();
                GroupSummary {
                    id: g.id.clone(),
                    title: g.title.clone(),
                    checks: areas.iter().map(|a| a.checks).sum(),
                    implemented: areas.iter().map(|a| a.implemented).sum(),
                    areas,
                }
            })
            .collect();

        CatalogSummary {
            groups,
            sources: self.sources.clone(),
            checks: self.checks.len(),
            implemented: self
                .checks
                .iter()
                .filter(|c| c.status == CheckStatus::Implemented)
                .count(),
        }
    }
}

fn collect_check_files(root: &Path, dir: &Path, out: &mut Vec<std::path::PathBuf>) -> Result<()> {
    let entries = fs::read_dir(dir).map_err(|source| Error::Io {
        path: dir.display().to_string(),
        source,
    })?;
    for entry in entries {
        let path = entry
            .map_err(|source| Error::Io {
                path: dir.display().to_string(),
                source,
            })?
            .path();
        if path.is_dir() {
            collect_check_files(root, &path, out)?;
        } else if path.extension().is_some_and(|e| e == "toml") {
            let is_index = path.parent() == Some(root)
                && path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| INDEX_FILES.contains(&n));
            if !is_index {
                out.push(path);
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
pub struct CatalogSummary {
    pub groups: Vec<GroupSummary>,
    pub sources: Vec<Source>,
    pub checks: usize,
    pub implemented: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct GroupSummary {
    pub id: String,
    pub title: String,
    pub areas: Vec<AreaSummary>,
    pub checks: usize,
    pub implemented: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct AreaSummary {
    pub code: String,
    pub title: String,
    pub sources: Vec<String>,
    pub generated: bool,
    pub checks: usize,
    pub implemented: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn repo_catalog() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../checks")
    }

    #[test]
    fn shipped_catalog_loads_and_validates() {
        let catalog = Catalog::load(&repo_catalog()).expect("catalog loads");
        assert_eq!(catalog.groups.len(), 8);
        assert_eq!(catalog.areas.len(), 47);
        assert_eq!(catalog.checks.len(), 804);
        let summary = catalog.summary();
        assert_eq!(summary.groups.iter().map(|g| g.checks).sum::<usize>(), 804);
    }

    fn write(dir: &Path, name: &str, text: &str) {
        let path = dir.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }

    fn minimal(dir: &Path, checks: &str) {
        write(dir, "groups.toml", "[[group]]\nid = \"g\"\ntitle = \"G\"\n");
        write(
            dir,
            "areas.toml",
            "[[area]]\ncode = \"AD-X\"\ntitle = \"X\"\ngroup = \"g\"\nsources = [\"ldap\"]\n",
        );
        write(
            dir,
            "sources.toml",
            "[[source]]\nid = \"ldap\"\ntitle = \"L\"\nneeds = \"n\"\nkind = \"onprem\"\n",
        );
        write(dir, "g/ad-x.toml", checks);
    }

    #[test]
    fn rejects_duplicate_ids() {
        let dir = tempfile::tempdir().unwrap();
        minimal(
            dir.path(),
            "area = \"AD-X\"\n[[check]]\nid = \"AD-X-001\"\ntitle = \"a\"\nstatus = \"planned\"\n\
             [[check]]\nid = \"AD-X-001\"\ntitle = \"b\"\nstatus = \"planned\"\n",
        );
        let err = Catalog::load(dir.path()).unwrap_err().to_string();
        assert!(err.contains("duplicate check AD-X-001"), "{err}");
    }

    #[test]
    fn rejects_implemented_check_without_severity() {
        let dir = tempfile::tempdir().unwrap();
        minimal(
            dir.path(),
            "area = \"AD-X\"\n[[check]]\nid = \"AD-X-001\"\ntitle = \"a\"\nstatus = \"implemented\"\n",
        );
        let err = Catalog::load(dir.path()).unwrap_err().to_string();
        assert!(err.contains("has no severity"), "{err}");
    }

    #[test]
    fn rejects_id_outside_its_area() {
        let dir = tempfile::tempdir().unwrap();
        minimal(
            dir.path(),
            "area = \"AD-X\"\n[[check]]\nid = \"AD-Y-001\"\ntitle = \"a\"\nstatus = \"planned\"\n",
        );
        let err = Catalog::load(dir.path()).unwrap_err().to_string();
        assert!(err.contains("does not start with its area code"), "{err}");
    }
}
