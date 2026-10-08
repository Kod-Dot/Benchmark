//! Checks that read on-premises Active Directory and Microsoft Entra ID
//! together: the sync accounts, synchronized admins, and identities that are
//! privileged on both sides.

pub mod rules;
pub mod rules_az;
pub mod rules_servers;

#[cfg(test)]
mod tests;

use crate::ad::model::Model;
use crate::catalog::Catalog;
use crate::entra::model::Tenant;
use crate::entra::model::J;
use crate::results::{CheckResult, DirObject, Edge, ResultStatus};

/// Everything collected in one assessment: its domains and its tenant.
pub struct Ctx<'s, 'r> {
    pub domains: &'s [Model<'r>],
    pub tenant: Option<&'s Tenant<'r>>,
}

pub struct Rule {
    pub id: &'static str,
    /// On-prem collector areas the rule reads, in every domain.
    pub ad: &'static [&'static str],
    /// Entra collector areas the rule reads. Empty when the rule needs no
    /// tenant.
    pub entra: &'static [&'static str],
    pub run: fn(&Ctx) -> CheckResult,
}

fn not_assessed(id: &str, note: String) -> CheckResult {
    CheckResult {
        id: id.to_string(),
        status: ResultStatus::NotAssessed,
        severity: None,
        affected_count: None,
        affected_unit: None,
        affected: Vec::new(),
        expected: None,
        found: None,
        evidence: Vec::new(),
        raw: None,
        note: Some(note),
    }
}

/// Why a rule cannot run with what this assessment collected.
fn missing(ctx: &Ctx, r: &Rule) -> Option<String> {
    if !r.ad.is_empty() {
        if ctx.domains.is_empty() {
            return Some("This check also needs on-premises Active Directory, which this assessment did not collect.".into());
        }
        for m in ctx.domains {
            if let Some(note) = crate::ad::missing(m.raw, r.ad) {
                return Some(format!("{}: {note}", m.dns));
            }
        }
    }
    if !r.entra.is_empty() {
        let Some(t) = ctx.tenant else {
            return Some(
                "This check also needs Microsoft Entra ID, which this assessment did not collect."
                    .into(),
            );
        };
        if let Some(note) = crate::entra::missing(t.raw, r.entra) {
            return Some(note);
        }
    }
    None
}

/// Every hybrid rule.
pub fn all_rules() -> impl Iterator<Item = &'static Rule> {
    rules::RULES
        .iter()
        .chain(rules_az::RULES)
        .chain(rules_servers::RULES)
}

/// Runs every hybrid rule whose area is in `areas` (all of them when
/// `areas` is empty).
pub fn analyze(catalog: &Catalog, ctx: &Ctx, areas: &[String]) -> Vec<CheckResult> {
    let selected = |id: &str| {
        let area = catalog
            .check(id)
            .map(|c| c.area.as_str())
            .unwrap_or_default();
        areas.is_empty() || areas.iter().any(|a| a == area)
    };
    all_rules()
        .filter(|r| selected(r.id))
        .map(|r| match missing(ctx, r) {
            Some(note) => not_assessed(r.id, note),
            None => (r.run)(ctx),
        })
        .collect()
}

/// Links each AD account and group to the Entra object it is synchronized
/// to, for the directory explorer. Only objects already in the view.
pub fn sync_edges(ctx: &Ctx, objects: &[DirObject]) -> Vec<Edge> {
    let Some(t) = ctx.tenant else {
        return Vec::new();
    };
    let ids: std::collections::HashSet<&str> = objects.iter().map(|o| o.id.as_str()).collect();
    let mut out: Vec<Edge> = t
        .users
        .values()
        .chain(t.groups.values())
        .filter_map(|v| Some((v.s("onPremisesSecurityIdentifier")?, v.s("id")?)))
        .filter(|(sid, id)| ids.contains(sid) && ids.contains(id))
        .map(|(sid, id)| Edge {
            from: sid.to_string(),
            to: id.to_string(),
            kind: "SyncedTo".into(),
            note: None,
        })
        .collect();
    out.sort_by(|a, b| a.from.cmp(&b.from));
    out
}
