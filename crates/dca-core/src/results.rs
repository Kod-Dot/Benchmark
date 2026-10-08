//! Results of an assessment and the views the UI shows: findings joined with
//! their catalog explanation, scores, attack paths and directory telemetry.
//!
//! An assessment folder holds `manifest.json`, `results.json` (one entry per
//! check that ran) and, when telemetry was collected, `directory.json`
//! (objects and the relationships between them). The analysis engine writes
//! these files; nothing here invents values that are not in them.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::catalog::{Catalog, CheckDetail, Severity, Technique};
use crate::cvss::{self, Cvss};
use crate::store::Manifest;
use crate::{Error, Result};

// ---------- Files ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultStatus {
    Failed,
    Passed,
    NotAssessed,
    /// Failed, but the owner accepted the risk. Not counted against the score.
    Accepted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Affected {
    pub name: String,
    pub kind: String,
    #[serde(default)]
    pub location: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    /// Id of the object in `directory.json`, when it is there.
    #[serde(default)]
    pub object: Option<String>,
    /// For threat-hunting observations: when it was seen in the logs (ISO
    /// 8601; the latest time for repeated events, the start for a burst),
    /// so the hunting view can place it on a timeline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
}

impl Affected {
    /// Records when a threat-hunting observation was last seen.
    pub fn seen_at(mut self, last: Option<&str>) -> Self {
        self.last_seen = last.filter(|l| !l.is_empty()).map(str::to_string);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub label: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub id: String,
    pub status: ResultStatus,
    /// Overrides the catalog severity when the analysis rates this instance
    /// higher or lower (for example more affected objects).
    #[serde(default)]
    pub severity: Option<Severity>,
    /// Total affected, which can exceed the objects listed in `affected`.
    #[serde(default)]
    pub affected_count: Option<u64>,
    /// How to read the count, for example "computers" or "days".
    #[serde(default)]
    pub affected_unit: Option<String>,
    #[serde(default)]
    pub affected: Vec<Affected>,
    #[serde(default)]
    pub expected: Option<String>,
    #[serde(default)]
    pub found: Option<String>,
    #[serde(default)]
    pub evidence: Vec<Evidence>,
    /// Raw attribute values as read, shown verbatim.
    #[serde(default)]
    pub raw: Option<String>,
    /// Why a check was not assessed, or a note on an accepted risk.
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathStep {
    pub name: String,
    pub kind: String,
    #[serde(default)]
    pub object: Option<String>,
    /// The relationship from this step to the next one.
    #[serde(default)]
    pub via: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPath {
    pub title: String,
    pub severity: Severity,
    pub steps: Vec<PathStep>,
    /// Checks whose fix breaks this path.
    #[serde(default)]
    pub checks: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultsFile {
    pub checks: Vec<CheckResult>,
    #[serde(default)]
    pub paths: Vec<AttackPath>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Flag {
    pub text: String,
    /// "crit", "warn", "ok" or "" for neutral.
    #[serde(default)]
    pub level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirObject {
    pub id: String,
    /// user, computer, group, ou, gpo, trust, template, ca, domain, role, app
    pub kind: String,
    pub name: String,
    #[serde(default)]
    pub display_name: Option<String>,
    /// The domain or tenant it was read from.
    pub source: String,
    /// The containing OU or container, by id.
    #[serde(default)]
    pub parent: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub tier0: bool,
    #[serde(default)]
    pub last_logon: Option<String>,
    #[serde(default)]
    pub password_last_set: Option<String>,
    #[serde(default)]
    pub flags: Vec<Flag>,
    #[serde(default)]
    pub attributes: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Edge {
    pub from: String,
    pub to: String,
    /// MemberOf, GenericAll, HasSession, AdminTo, DCSync, Enroll...
    pub kind: String,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirSource {
    pub name: String,
    /// "onprem" or "cloud"
    pub kind: String,
    pub read_at: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DirectoryFile {
    #[serde(default)]
    pub sources: Vec<DirSource>,
    #[serde(default)]
    pub objects: Vec<DirObject>,
    #[serde(default)]
    pub edges: Vec<Edge>,
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let text = fs::read_to_string(path).map_err(|source| Error::Io {
        path: path.display().to_string(),
        source,
    })?;
    serde_json::from_str(&text).map_err(|e| Error::Parse {
        path: path.display().to_string(),
        message: e.to_string(),
    })
}

/// Everything read from one assessment folder.
#[derive(Debug, Clone)]
pub struct Assessment {
    pub path: String,
    pub name: String,
    pub manifest: Manifest,
    pub results: ResultsFile,
    pub directory: Option<DirectoryFile>,
}

impl Assessment {
    pub fn load(dir: &Path) -> Result<Assessment> {
        let manifest: Manifest = read_json(&dir.join("manifest.json"))?;
        let results_path = dir.join("results.json");
        if !results_path.is_file() {
            return Err(Error::Assessment(format!(
                "{} has not been analyzed yet: results.json is missing",
                dir.display()
            )));
        }
        let results: ResultsFile = read_json(&results_path)?;
        let dir_path = dir.join("directory.json");
        let directory = if dir_path.is_file() {
            Some(read_json(&dir_path)?)
        } else {
            None
        };
        Ok(Assessment {
            path: dir.display().to_string(),
            name: manifest.name.clone().unwrap_or_else(|| {
                dir.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default()
            }),
            manifest,
            results,
            directory,
        })
    }
}

// ---------- Views ----------

#[derive(Debug, Clone, Serialize)]
pub struct Mitre {
    pub id: String,
    pub name: String,
    pub tactic: String,
    pub url: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub area: String,
    pub area_title: String,
    pub group: String,
    /// The run it came from. Matters when runs are combined.
    pub run: String,
    pub status: ResultStatus,
    pub severity: Severity,
    pub cvss: Option<Cvss>,
    pub mitre: Vec<Mitre>,
    pub detail: Option<CheckDetail>,
    pub data_sources: Vec<String>,
    pub affected_count: Option<u64>,
    pub affected_unit: Option<String>,
    pub affected: Vec<Affected>,
    pub expected: Option<String>,
    pub found: Option<String>,
    pub evidence: Vec<Evidence>,
    pub raw: Option<String>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct SeverityCounts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct StatusCounts {
    pub failed: usize,
    pub passed: usize,
    pub not_assessed: usize,
    pub accepted: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct AreaScore {
    pub code: String,
    pub title: String,
    pub group: String,
    /// None when nothing in the area was assessed.
    pub score: Option<u32>,
    pub failed: usize,
    pub assessed: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct GroupScore {
    pub id: String,
    pub title: String,
    pub score: Option<u32>,
    pub failed: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct TacticCount {
    pub tactic: String,
    pub findings: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChokePoint {
    pub check: String,
    pub title: String,
    pub paths: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct Summary {
    pub score: Option<u32>,
    pub status: StatusCounts,
    pub severity: SeverityCounts,
    pub groups: Vec<GroupScore>,
    pub areas: Vec<AreaScore>,
    pub tactics: Vec<TacticCount>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RunInfo {
    pub path: String,
    pub name: String,
    pub manifest: Manifest,
}

#[derive(Debug, Clone, Serialize)]
pub struct AssessmentView {
    pub runs: Vec<RunInfo>,
    pub catalog_version: String,
    pub summary: Summary,
    /// Every check result, failed first, then by severity and CVSS.
    pub findings: Vec<Finding>,
    pub paths: Vec<AttackPath>,
    pub choke_points: Vec<ChokePoint>,
    pub directory: Option<DirectoryFile>,
}

/// Score weights per severity. A passed critical check is worth ten low ones.
fn weight(s: Severity) -> u32 {
    match s {
        Severity::Critical => 10,
        Severity::High => 5,
        Severity::Medium => 2,
        Severity::Low => 1,
        Severity::Info => 0,
    }
}

/// Percentage of severity weight passed among checks that were assessed.
/// Accepted risks and checks that could not be assessed are left out.
fn score(findings: &[&Finding]) -> Option<u32> {
    let (mut passed, mut total) = (0u32, 0u32);
    for f in findings {
        let w = weight(f.severity);
        match f.status {
            ResultStatus::Passed => {
                passed += w;
                total += w;
            }
            ResultStatus::Failed => total += w,
            _ => {}
        }
    }
    (total > 0).then(|| ((passed as f64 / total as f64) * 100.0).round() as u32)
}

pub fn mitre_url(id: &str) -> String {
    format!(
        "https://attack.mitre.org/techniques/{}/",
        id.replace('.', "/")
    )
}

fn finding(catalog: &Catalog, run: &str, r: &CheckResult) -> Finding {
    let check = catalog.check(&r.id);
    let area_code = check.map(|c| c.area.clone()).unwrap_or_else(|| {
        r.id.rsplit_once('-')
            .map(|(a, _)| a.to_string())
            .unwrap_or_default()
    });
    let area = catalog.area(&area_code);
    let detail = check.and_then(|c| c.detail.clone());
    let mitre = detail
        .as_ref()
        .map(|d| {
            d.mitre
                .iter()
                .filter_map(|id| catalog.technique(id))
                .map(|t: &Technique| Mitre {
                    id: t.id.clone(),
                    name: t.name.clone(),
                    tactic: t.tactic.clone(),
                    url: mitre_url(&t.id),
                })
                .collect()
        })
        .unwrap_or_default();
    Finding {
        id: r.id.clone(),
        title: check
            .map(|c| c.title.clone())
            .unwrap_or_else(|| r.id.clone()),
        area: area_code.clone(),
        area_title: area.map(|a| a.title.clone()).unwrap_or_default(),
        group: area.map(|a| a.group.clone()).unwrap_or_default(),
        run: run.to_string(),
        status: r.status,
        severity: r
            .severity
            .or_else(|| check.and_then(|c| c.severity))
            .unwrap_or(Severity::Medium),
        cvss: detail
            .as_ref()
            .and_then(|d| d.cvss.as_deref())
            .and_then(|v| cvss::parse(v).ok()),
        mitre,
        detail,
        data_sources: area
            .map(|a| {
                a.sources
                    .iter()
                    .map(|id| {
                        catalog
                            .sources
                            .iter()
                            .find(|s| &s.id == id)
                            .map_or_else(|| id.clone(), |s| s.title.clone())
                    })
                    .collect()
            })
            .unwrap_or_default(),
        affected_count: r.affected_count,
        affected_unit: r.affected_unit.clone(),
        affected: r.affected.clone(),
        expected: r.expected.clone(),
        found: r.found.clone(),
        evidence: r.evidence.clone(),
        raw: r.raw.clone(),
        note: r.note.clone(),
    }
}

fn status_rank(s: ResultStatus) -> u8 {
    match s {
        ResultStatus::Failed => 0,
        ResultStatus::Accepted => 1,
        ResultStatus::NotAssessed => 2,
        ResultStatus::Passed => 3,
    }
}

fn sort_findings(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        status_rank(a.status)
            .cmp(&status_rank(b.status))
            .then(b.severity_rank().cmp(&a.severity_rank()))
            .then(
                b.cvss
                    .as_ref()
                    .map(|c| c.score)
                    .unwrap_or(0.0)
                    .total_cmp(&a.cvss.as_ref().map(|c| c.score).unwrap_or(0.0)),
            )
            .then(a.id.cmp(&b.id))
    });
}

impl Finding {
    fn severity_rank(&self) -> u32 {
        weight(self.severity)
    }
}

pub fn summarize(catalog: &Catalog, findings: &[Finding]) -> Summary {
    let mut status = StatusCounts::default();
    let mut severity = SeverityCounts::default();
    let mut tactics: BTreeMap<String, usize> = BTreeMap::new();
    for f in findings {
        match f.status {
            ResultStatus::Failed => {
                status.failed += 1;
                match f.severity {
                    Severity::Critical => severity.critical += 1,
                    Severity::High => severity.high += 1,
                    Severity::Medium => severity.medium += 1,
                    Severity::Low => severity.low += 1,
                    Severity::Info => {}
                }
                let mut seen = Vec::new();
                for m in &f.mitre {
                    if !seen.contains(&m.tactic) {
                        *tactics.entry(m.tactic.clone()).or_default() += 1;
                        seen.push(m.tactic.clone());
                    }
                }
            }
            ResultStatus::Passed => status.passed += 1,
            ResultStatus::NotAssessed => status.not_assessed += 1,
            ResultStatus::Accepted => status.accepted += 1,
        }
    }

    let mut by_area: HashMap<&str, Vec<&Finding>> = HashMap::new();
    for f in findings {
        by_area.entry(f.area.as_str()).or_default().push(f);
    }
    let areas: Vec<AreaScore> = catalog
        .areas
        .iter()
        .filter_map(|a| {
            let list = by_area.get(a.code.as_str())?;
            Some(AreaScore {
                code: a.code.clone(),
                title: a.title.clone(),
                group: a.group.clone(),
                score: score(list),
                failed: list
                    .iter()
                    .filter(|f| f.status == ResultStatus::Failed)
                    .count(),
                assessed: list
                    .iter()
                    .filter(|f| matches!(f.status, ResultStatus::Failed | ResultStatus::Passed))
                    .count(),
            })
        })
        .collect();
    let groups = catalog
        .groups
        .iter()
        .filter_map(|g| {
            let list: Vec<&Finding> = findings.iter().filter(|f| f.group == g.id).collect();
            (!list.is_empty()).then(|| GroupScore {
                id: g.id.clone(),
                title: g.title.clone(),
                score: score(&list),
                failed: list
                    .iter()
                    .filter(|f| f.status == ResultStatus::Failed)
                    .count(),
            })
        })
        .collect();
    let mut tactics: Vec<TacticCount> = tactics
        .into_iter()
        .map(|(tactic, findings)| TacticCount { tactic, findings })
        .collect();
    tactics.sort_by(|a, b| b.findings.cmp(&a.findings).then(a.tactic.cmp(&b.tactic)));

    Summary {
        score: score(&findings.iter().collect::<Vec<_>>()),
        status,
        severity,
        groups,
        areas,
        tactics,
    }
}

fn choke_points(catalog: &Catalog, paths: &[AttackPath]) -> Vec<ChokePoint> {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for p in paths {
        for c in &p.checks {
            *counts.entry(c.as_str()).or_default() += 1;
        }
    }
    let mut out: Vec<ChokePoint> = counts
        .into_iter()
        .map(|(check, paths)| ChokePoint {
            check: check.to_string(),
            title: catalog
                .check(check)
                .map(|c| c.title.clone())
                .unwrap_or_default(),
            paths,
        })
        .collect();
    out.sort_by(|a, b| b.paths.cmp(&a.paths).then(a.check.cmp(&b.check)));
    out
}

/// One run, or several runs combined into one dashboard. Combining keeps
/// every finding with the run it came from and scores them all together.
pub fn view(catalog: &Catalog, runs: &[Assessment]) -> AssessmentView {
    let mut findings: Vec<Finding> = runs
        .iter()
        .flat_map(|a| a.results.checks.iter().map(move |r| (a, r)))
        .map(|(a, r)| finding(catalog, &a.name, r))
        .collect();
    sort_findings(&mut findings);
    let paths: Vec<AttackPath> = runs.iter().flat_map(|a| a.results.paths.clone()).collect();
    let directory = runs
        .iter()
        .filter_map(|a| a.directory.clone())
        .reduce(|mut acc, d| {
            acc.sources.extend(d.sources);
            acc.objects.extend(d.objects);
            acc.edges.extend(d.edges);
            acc
        });
    let mut versions: Vec<&str> = runs
        .iter()
        .map(|a| a.manifest.catalog_version.as_str())
        .collect();
    versions.dedup();
    AssessmentView {
        runs: runs
            .iter()
            .map(|a| RunInfo {
                path: a.path.clone(),
                name: a.name.clone(),
                manifest: a.manifest.clone(),
            })
            .collect(),
        catalog_version: versions.join(", "),
        summary: summarize(catalog, &findings),
        choke_points: choke_points(catalog, &paths),
        findings,
        paths,
        directory,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::path::PathBuf;

    pub fn repo() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    pub fn example(name: &str) -> Assessment {
        Assessment::load(&repo().join("fixtures/example-assessments").join(name))
            .expect("fixture loads")
    }

    pub fn catalog() -> Catalog {
        Catalog::load(&repo().join("checks")).unwrap()
    }

    #[test]
    fn example_results_reference_real_checks() {
        let catalog = catalog();
        for name in ["q3-baseline", "october-review", "branch-forest"] {
            let a = example(name);
            for r in &a.results.checks {
                assert!(
                    catalog.check(&r.id).is_some(),
                    "{name}: unknown check {}",
                    r.id
                );
            }
            for p in &a.results.paths {
                for c in &p.checks {
                    assert!(
                        catalog.check(c).is_some(),
                        "{name}: path uses unknown check {c}"
                    );
                }
            }
        }
    }

    #[test]
    fn example_directory_edges_point_at_objects() {
        let a = example("october-review");
        let dir = a.directory.expect("has telemetry");
        let ids: std::collections::HashSet<&str> =
            dir.objects.iter().map(|o| o.id.as_str()).collect();
        for e in &dir.edges {
            assert!(
                ids.contains(e.from.as_str()) && ids.contains(e.to.as_str()),
                "{e:?}"
            );
        }
        for o in &dir.objects {
            if let Some(p) = &o.parent {
                assert!(ids.contains(p.as_str()), "{} has unknown parent {p}", o.id);
            }
        }
    }

    #[test]
    fn view_counts_and_scores() {
        let catalog = catalog();
        let v = view(&catalog, &[example("october-review")]);
        let failed = v
            .findings
            .iter()
            .filter(|f| f.status == ResultStatus::Failed)
            .count();
        assert_eq!(v.summary.status.failed, failed);
        let s = &v.summary.severity;
        assert_eq!(s.critical + s.high + s.medium + s.low, failed);
        // Failed findings come first, most severe first.
        assert_eq!(v.findings[0].status, ResultStatus::Failed);
        assert_eq!(v.findings[0].severity, Severity::Critical);
        let score = v.summary.score.unwrap();
        assert!(score <= 100);
        // ESC1 gets its detail, CVSS and MITRE names from the catalog.
        let esc1 = v.findings.iter().find(|f| f.id == "AD-PKI-002").unwrap();
        assert_eq!(esc1.cvss.as_ref().unwrap().score, 9.9);
        assert!(esc1.mitre.iter().any(|m| m.id == "T1649"));
    }

    #[test]
    fn score_ignores_accepted_and_not_assessed() {
        let mk = |status, severity| Finding {
            id: "X".into(),
            title: String::new(),
            area: String::new(),
            area_title: String::new(),
            group: String::new(),
            run: String::new(),
            status,
            severity,
            cvss: None,
            mitre: vec![],
            detail: None,
            data_sources: vec![],
            affected_count: None,
            affected_unit: None,
            affected: vec![],
            expected: None,
            found: None,
            evidence: vec![],
            raw: None,
            note: None,
        };
        let a = mk(ResultStatus::Passed, Severity::Critical);
        let b = mk(ResultStatus::Failed, Severity::Low);
        let c = mk(ResultStatus::Accepted, Severity::Critical);
        let d = mk(ResultStatus::NotAssessed, Severity::High);
        // 10 passed of 11 assessed weight.
        assert_eq!(score(&[&a, &b, &c, &d]), Some(91));
        assert_eq!(score(&[&c, &d]), None);
    }

    #[test]
    fn missing_results_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("manifest.json"),
            r#"{"tool_version":"0.1.0","catalog_version":"1","scope":{"domains":[]},"started_at":"2026-01-01T00:00:00Z"}"#,
        )
        .unwrap();
        let err = Assessment::load(dir.path()).unwrap_err().to_string();
        assert!(err.contains("not been analyzed"), "{err}");
    }
}
