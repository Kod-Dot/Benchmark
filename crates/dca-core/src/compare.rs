//! Comparing two runs: what was fixed, what is new, what got worse, and how
//! area scores and the directory changed. Combining runs is
//! [`crate::results::view`] with more than one run.

use std::collections::{BTreeMap, HashMap};

use serde::Serialize;

use crate::catalog::{Catalog, Severity};
use crate::results::{
    self, Assessment, AssessmentView, Finding, ResultStatus, RunInfo, SeverityCounts,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    /// Failing now, was passing or not run before.
    New,
    /// Failing before, passing now.
    Fixed,
    /// Failing in both, with more affected or a higher severity now.
    Worse,
    /// Failing in both, with fewer affected or a lower severity now.
    Better,
    /// Failing in both, unchanged.
    StillOpen,
}

#[derive(Debug, Clone, Serialize)]
pub struct Before {
    pub status: ResultStatus,
    pub severity: Severity,
    pub affected_count: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Change {
    pub kind: ChangeKind,
    /// The later result, or the earlier one for a fixed finding.
    pub finding: Finding,
    pub before: Option<Before>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AreaChange {
    pub code: String,
    pub title: String,
    pub before: Option<u32>,
    pub after: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CountChange {
    pub label: String,
    pub before: Option<usize>,
    pub after: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Comparison {
    pub earlier: RunInfo,
    pub later: RunInfo,
    pub same_scope: bool,
    pub same_catalog: bool,
    pub score_before: Option<u32>,
    pub score_after: Option<u32>,
    pub severity_before: SeverityCounts,
    pub severity_after: SeverityCounts,
    pub changes: Vec<Change>,
    pub areas: Vec<AreaChange>,
    pub directory: Vec<CountChange>,
}

fn rank(s: Severity) -> u8 {
    match s {
        Severity::Critical => 4,
        Severity::High => 3,
        Severity::Medium => 2,
        Severity::Low => 1,
        Severity::Info => 0,
    }
}

fn change_rank(k: ChangeKind) -> u8 {
    match k {
        ChangeKind::New => 0,
        ChangeKind::Worse => 1,
        ChangeKind::Fixed => 2,
        ChangeKind::Better => 3,
        ChangeKind::StillOpen => 4,
    }
}

fn directory_counts(v: &AssessmentView) -> Option<BTreeMap<&'static str, usize>> {
    let d = v.directory.as_ref()?;
    let mut m = BTreeMap::new();
    for (label, kind) in [
        ("Users", "user"),
        ("Computers", "computer"),
        ("Groups", "group"),
        ("OUs", "ou"),
        ("GPOs", "gpo"),
    ] {
        m.insert(label, d.objects.iter().filter(|o| o.kind == kind).count());
    }
    m.insert(
        "Tier 0 objects",
        d.objects.iter().filter(|o| o.tier0).count(),
    );
    Some(m)
}

pub fn compare(catalog: &Catalog, earlier: &Assessment, later: &Assessment) -> Comparison {
    let a = results::view(catalog, std::slice::from_ref(earlier));
    let b = results::view(catalog, std::slice::from_ref(later));
    let before: HashMap<&str, &Finding> = a.findings.iter().map(|f| (f.id.as_str(), f)).collect();
    let after: HashMap<&str, &Finding> = b.findings.iter().map(|f| (f.id.as_str(), f)).collect();

    let mut changes = Vec::new();
    for f in &b.findings {
        if f.status != ResultStatus::Failed {
            continue;
        }
        let prev = before.get(f.id.as_str()).copied();
        let kind = match prev {
            Some(p) if p.status == ResultStatus::Failed => {
                let sev = rank(f.severity).cmp(&rank(p.severity));
                let count = f
                    .affected_count
                    .unwrap_or(0)
                    .cmp(&p.affected_count.unwrap_or(0));
                match sev.then(count) {
                    std::cmp::Ordering::Greater => ChangeKind::Worse,
                    std::cmp::Ordering::Less => ChangeKind::Better,
                    std::cmp::Ordering::Equal => ChangeKind::StillOpen,
                }
            }
            _ => ChangeKind::New,
        };
        changes.push(Change {
            kind,
            finding: f.clone(),
            before: prev.map(|p| Before {
                status: p.status,
                severity: p.severity,
                affected_count: p.affected_count,
            }),
        });
    }
    for p in &a.findings {
        if p.status != ResultStatus::Failed {
            continue;
        }
        if let Some(now) = after.get(p.id.as_str()) {
            if now.status == ResultStatus::Passed {
                changes.push(Change {
                    kind: ChangeKind::Fixed,
                    finding: (*now).clone(),
                    before: Some(Before {
                        status: p.status,
                        severity: p.severity,
                        affected_count: p.affected_count,
                    }),
                });
            }
        }
    }
    changes.sort_by(|x, y| {
        change_rank(x.kind)
            .cmp(&change_rank(y.kind))
            .then(rank(y.finding.severity).cmp(&rank(x.finding.severity)))
            .then(x.finding.id.cmp(&y.finding.id))
    });

    let before_areas: HashMap<&str, Option<u32>> = a
        .summary
        .areas
        .iter()
        .map(|s| (s.code.as_str(), s.score))
        .collect();
    let after_areas: HashMap<&str, Option<u32>> = b
        .summary
        .areas
        .iter()
        .map(|s| (s.code.as_str(), s.score))
        .collect();
    let mut areas: Vec<AreaChange> = catalog
        .areas
        .iter()
        .filter(|ar| {
            before_areas.contains_key(ar.code.as_str())
                || after_areas.contains_key(ar.code.as_str())
        })
        .map(|ar| AreaChange {
            code: ar.code.clone(),
            title: ar.title.clone(),
            before: before_areas.get(ar.code.as_str()).copied().flatten(),
            after: after_areas.get(ar.code.as_str()).copied().flatten(),
        })
        .collect();
    // Weakest areas first: that is where attention goes.
    areas.sort_by_key(|x| x.after.unwrap_or(u32::MAX));

    let (da, db) = (directory_counts(&a), directory_counts(&b));
    let mut directory: Vec<CountChange> = [
        "Users",
        "Computers",
        "Groups",
        "OUs",
        "GPOs",
        "Tier 0 objects",
    ]
    .iter()
    .map(|label| CountChange {
        label: label.to_string(),
        before: da.as_ref().and_then(|m| m.get(label).copied()),
        after: db.as_ref().and_then(|m| m.get(label).copied()),
    })
    .collect();
    directory.push(CountChange {
        label: "Attack paths".into(),
        before: Some(a.paths.len()),
        after: Some(b.paths.len()),
    });

    let scope = |x: &Assessment| {
        let mut d = x.manifest.scope.domains.clone();
        d.sort();
        (d, x.manifest.scope.tenant.clone())
    };
    Comparison {
        same_scope: scope(earlier) == scope(later),
        same_catalog: earlier.manifest.catalog_version == later.manifest.catalog_version,
        earlier: a.runs[0].clone(),
        later: b.runs[0].clone(),
        score_before: a.summary.score,
        score_after: b.summary.score,
        severity_before: a.summary.severity.clone(),
        severity_after: b.summary.severity.clone(),
        changes,
        areas,
        directory,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::results::tests::{catalog, example};

    #[test]
    fn compares_example_runs() {
        let c = compare(
            &catalog(),
            &example("q3-baseline"),
            &example("october-review"),
        );
        assert!(c.same_scope);
        let count = |k| c.changes.iter().filter(|x| x.kind == k).count();
        assert!(count(ChangeKind::New) > 0);
        assert!(count(ChangeKind::Fixed) > 0);
        // A fixed finding was failing before.
        for x in c.changes.iter().filter(|x| x.kind == ChangeKind::Fixed) {
            assert_eq!(x.before.as_ref().unwrap().status, ResultStatus::Failed);
            assert_eq!(x.finding.status, ResultStatus::Passed);
        }
        // New first.
        assert_eq!(c.changes[0].kind, ChangeKind::New);
    }

    #[test]
    fn comparing_a_run_with_itself_changes_nothing() {
        let r = example("october-review");
        let c = compare(&catalog(), &r, &r);
        assert!(c.changes.iter().all(|x| x.kind == ChangeKind::StillOpen));
        assert_eq!(c.score_before, c.score_after);
    }

    #[test]
    fn combined_view_keeps_each_run() {
        let v = results::view(
            &catalog(),
            &[example("october-review"), example("branch-forest")],
        );
        assert_eq!(v.runs.len(), 2);
        assert!(v.findings.iter().any(|f| f.run == "Branch forest"));
        assert!(v.findings.iter().any(|f| f.run == "October review"));
    }
}
