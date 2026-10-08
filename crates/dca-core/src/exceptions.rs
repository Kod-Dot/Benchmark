//! Accepted risks. A person reviewing an assessment can accept the risk of a
//! failed check, with a reason, their name and an optional expiry date. The
//! list lives in `exceptions.json` in the assessments folder, so it applies
//! to every assessment of the same domains or tenant, including later runs.
//!
//! An acceptance never changes the stored results: it is applied when an
//! assessment is opened, turning a failed check into an accepted risk. Once
//! it expires the check shows as failed again.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::catalog::Catalog;
use crate::results::{Assessment, ResultStatus};
use crate::store::Manifest;
use crate::time;
use crate::{Error, Result};

pub const FILE: &str = "exceptions.json";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RiskAcceptance {
    pub check: String,
    /// The domains and tenant it applies to, lower case. An assessment
    /// matches when it covers any of them.
    pub scope: Vec<String>,
    pub reason: String,
    pub accepted_by: String,
    /// yyyy-mm-dd
    pub accepted_on: String,
    /// yyyy-mm-dd, the last day it applies. None means until withdrawn.
    #[serde(default)]
    pub expires_on: Option<String>,
}

impl RiskAcceptance {
    pub fn active(&self, now: i64) -> bool {
        match self.expires_on.as_deref().and_then(time::parse_iso) {
            Some(last_day) => now < last_day + time::DAY,
            None => true,
        }
    }

    fn covers(&self, keys: &[String]) -> bool {
        self.scope.iter().any(|s| keys.contains(s))
    }

    fn note(&self) -> String {
        let until = match &self.expires_on {
            Some(d) => format!(" until {d}"),
            None => String::new(),
        };
        format!(
            "Risk accepted by {} on {}{until}: {}",
            self.accepted_by, self.accepted_on, self.reason
        )
    }
}

/// The domains and tenant an assessment covers, as acceptance scope keys.
pub fn scope_keys(m: &Manifest) -> Vec<String> {
    m.scope
        .domains
        .iter()
        .chain(m.scope.tenant.iter())
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

fn io(path: &Path, source: std::io::Error) -> Error {
    Error::Io {
        path: path.display().to_string(),
        source,
    }
}

/// The part of an assessment's scope a check of `group` is about: on-prem
/// and endpoint checks belong to the domains, cloud checks to the tenant,
/// and hybrid checks to both.
pub fn scope_for(m: &Manifest, group: &str) -> Vec<String> {
    let key = |s: &String| s.trim().to_ascii_lowercase();
    let domains = m.scope.domains.iter().map(key);
    let tenant = m.scope.tenant.iter().map(key);
    let keys: Vec<String> = match group {
        "onprem" | "endpoints" | "baselines" => domains.collect(),
        "entra" | "m365" | "azure" => tenant.collect(),
        _ => domains.chain(tenant).collect(),
    };
    keys.into_iter().filter(|s| !s.is_empty()).collect()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Exceptions {
    #[serde(default)]
    pub items: Vec<RiskAcceptance>,
}

impl Exceptions {
    pub fn path_in(dir: &Path) -> PathBuf {
        dir.join(FILE)
    }

    /// A missing file is an empty list.
    pub fn load(path: &Path) -> Result<Exceptions> {
        if !path.is_file() {
            return Ok(Exceptions::default());
        }
        let text = fs::read_to_string(path).map_err(|e| io(path, e))?;
        serde_json::from_str(&text).map_err(|e| Error::Parse {
            path: path.display().to_string(),
            message: e.to_string(),
        })
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).map_err(|e| io(dir, e))?;
        }
        let text =
            serde_json::to_string_pretty(self).map_err(|e| Error::Assessment(e.to_string()))?;
        // Write then rename, so a crash never leaves half a file.
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, text).map_err(|e| io(&tmp, e))?;
        fs::rename(&tmp, path).map_err(|e| io(path, e))?;
        Ok(())
    }

    /// Adds an acceptance, replacing one for the same check and scope.
    pub fn add(&mut self, item: RiskAcceptance) {
        self.items
            .retain(|e| !(e.check == item.check && e.scope == item.scope));
        self.items.push(item);
    }

    /// Removes every acceptance of `check` that covers any of `scope`.
    pub fn remove(&mut self, check: &str, scope: &[String]) -> usize {
        let before = self.items.len();
        self.items
            .retain(|e| !(e.check == check && e.covers(scope)));
        before - self.items.len()
    }

    /// Turns failed checks with an active acceptance into accepted risks.
    pub fn apply(&self, a: &mut Assessment, now: i64) {
        let keys = scope_keys(&a.manifest);
        for r in a
            .results
            .checks
            .iter_mut()
            .filter(|r| r.status == ResultStatus::Failed)
        {
            if let Some(e) = self
                .items
                .iter()
                .find(|e| e.check == r.id && e.covers(&keys) && e.active(now))
            {
                r.status = ResultStatus::Accepted;
                r.note = Some(e.note());
            }
        }
    }

    /// The list as the Settings screen shows it.
    pub fn rows(&self, catalog: &Catalog, now: i64) -> Vec<ExceptionRow> {
        let mut rows: Vec<ExceptionRow> = self
            .items
            .iter()
            .map(|e| ExceptionRow {
                title: catalog
                    .check(&e.check)
                    .map(|c| c.title.clone())
                    .unwrap_or_default(),
                active: e.active(now),
                acceptance: e.clone(),
            })
            .collect();
        rows.sort_by(|a, b| {
            (!a.active, &a.acceptance.check).cmp(&(!b.active, &b.acceptance.check))
        });
        rows
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ExceptionRow {
    #[serde(flatten)]
    pub acceptance: RiskAcceptance,
    pub title: String,
    pub active: bool,
}

/// Loads assessments with the acceptances applied.
pub fn load_runs(paths: &[String], exceptions: &Exceptions, now: i64) -> Result<Vec<Assessment>> {
    paths
        .iter()
        .map(|p| {
            let mut a = Assessment::load(Path::new(p))?;
            exceptions.apply(&mut a, now);
            Ok(a)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::results::{CheckResult, ResultsFile};
    use crate::store::Scope;

    fn result(id: &str, status: ResultStatus) -> CheckResult {
        serde_json::from_value(serde_json::json!({"id": id, "status": status})).unwrap()
    }

    fn assessment(domains: &[&str]) -> Assessment {
        Assessment {
            path: String::new(),
            name: "run".into(),
            manifest: Manifest {
                name: None,
                tool_version: "0".into(),
                catalog_version: "0".into(),
                scope: Scope {
                    domains: domains.iter().map(|d| d.to_string()).collect(),
                    tenant: None,
                },
                started_at: "2026-10-06T09:00:00Z".into(),
                finished_at: None,
                score: None,
                areas: vec![],
            },
            results: ResultsFile {
                checks: vec![
                    result("AD-KRB-001", ResultStatus::Failed),
                    result("AD-KRB-002", ResultStatus::Failed),
                    result("AD-KRB-003", ResultStatus::Passed),
                ],
                paths: vec![],
            },
            directory: None,
        }
    }

    fn accept(check: &str, scope: &str, expires: Option<&str>) -> RiskAcceptance {
        RiskAcceptance {
            check: check.into(),
            scope: vec![scope.into()],
            reason: "Legacy app until migration".into(),
            accepted_by: "CONTOSO\\mubie".into(),
            accepted_on: "2026-10-06".into(),
            expires_on: expires.map(str::to_string),
        }
    }

    #[test]
    fn applies_only_to_failed_checks_in_scope_until_expiry() {
        let now = time::parse_iso("2026-10-06T12:00:00Z").unwrap();
        let mut ex = Exceptions::default();
        ex.add(accept("AD-KRB-001", "contoso.com", Some("2026-10-06")));
        ex.add(accept("AD-KRB-002", "fabrikam.com", None));
        ex.add(accept("AD-KRB-003", "contoso.com", None));

        let mut a = assessment(&["Contoso.com"]);
        ex.apply(&mut a, now);
        let s: Vec<ResultStatus> = a.results.checks.iter().map(|c| c.status).collect();
        assert_eq!(
            s,
            [
                ResultStatus::Accepted,
                ResultStatus::Failed,
                ResultStatus::Passed
            ]
        );
        assert_eq!(
            a.results.checks[0].note.as_deref(),
            Some("Risk accepted by CONTOSO\\mubie on 2026-10-06 until 2026-10-06: Legacy app until migration")
        );

        // The day after the last day, it no longer applies.
        let mut later = assessment(&["contoso.com"]);
        ex.apply(&mut later, now + time::DAY);
        assert_eq!(later.results.checks[0].status, ResultStatus::Failed);
    }

    #[test]
    fn add_replaces_and_remove_matches_scope() {
        let mut ex = Exceptions::default();
        ex.add(accept("AD-KRB-001", "contoso.com", None));
        ex.add(accept("AD-KRB-001", "contoso.com", Some("2027-01-01")));
        assert_eq!(ex.items.len(), 1);
        assert_eq!(ex.items[0].expires_on.as_deref(), Some("2027-01-01"));
        assert_eq!(ex.remove("AD-KRB-001", &["fabrikam.com".into()]), 0);
        assert_eq!(ex.remove("AD-KRB-001", &["contoso.com".into()]), 1);
    }

    #[test]
    fn scope_follows_the_check_group() {
        let mut m = assessment(&["Corp.example.com"]).manifest;
        m.scope.tenant = Some("example.onmicrosoft.com".into());
        assert_eq!(scope_for(&m, "onprem"), ["corp.example.com"]);
        assert_eq!(scope_for(&m, "entra"), ["example.onmicrosoft.com"]);
        assert_eq!(scope_for(&m, "hybrid").len(), 2);
    }

    #[test]
    fn saves_and_loads() {
        let dir = tempfile::tempdir().unwrap();
        let path = Exceptions::path_in(dir.path());
        assert!(Exceptions::load(&path).unwrap().items.is_empty());
        let mut ex = Exceptions::default();
        ex.add(accept("AD-KRB-001", "contoso.com", None));
        ex.save(&path).unwrap();
        assert_eq!(Exceptions::load(&path).unwrap().items, ex.items);
    }
}
