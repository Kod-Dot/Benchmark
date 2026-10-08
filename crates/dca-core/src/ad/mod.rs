//! On-premises Active Directory: reading what the collector wrote, building
//! the domain model and running the on-prem checks.

pub mod dc;
pub mod directory;
pub mod ep;
pub mod model;
pub mod paths;
pub mod raw;
pub mod rules;
pub mod rules_access;
pub mod rules_auth;
pub mod rules_ca;
pub mod rules_dc;
pub mod rules_ep;
pub mod rules_forest;
pub mod rules_gpo;
pub mod rules_host;
pub mod rules_hunt;
pub mod rules_ioc;
pub mod rules_last;
pub mod rules_misc;
pub mod rules_more;
pub mod rules_net;
pub mod rules_obj;
pub mod rules_pki;
pub mod rules_policy;
pub mod rules_svc;
pub mod rules_t0;
pub mod sd;
pub mod x509;

#[cfg(test)]
pub(crate) mod tests;
#[cfg(test)]
mod tests_ep;
#[cfg(test)]
mod tests_last;
#[cfg(test)]
mod tests_more;

use crate::catalog::Catalog;
use crate::results::{AttackPath, CheckResult, DirectoryFile, ResultStatus};
use raw::{AreaState, RawDomain};

pub struct DomainAnalysis {
    pub checks: Vec<CheckResult>,
    pub paths: Vec<AttackPath>,
    pub directory: DirectoryFile,
}

fn area_label(area: &str) -> &str {
    match area {
        "domain" => "The domain head",
        "partitions" => "The Partitions container",
        "dirservice" => "The Directory Service object",
        "schema" => "The schema",
        "users" => "Users",
        "computers" => "Computers",
        "groups" => "Groups",
        "containers" => "OUs and containers",
        "gpos" => "Group Policy objects",
        "trusts" => "Trusts",
        "acls" => "Permissions (security descriptors)",
        "sysvol" => "The SYSVOL share",
        "dcconfig" => "Domain controller configuration",
        "endpoints" => "Member server and workstation configuration",
        "dcevents" => "Domain controller event logs",
        "pki" => "Certificate services (AD CS) configuration",
        "msas" => "Managed service accounts",
        "kds" => "KDS root keys",
        "sites" => "Sites, subnets and site links",
        "dnszones" => "DNS zones in the domain",
        "dnsforestzones" => "DNS zones in the forest",
        "psos" => "Fine-grained password policies",
        "pwdattrs" => "Readable password attributes",
        "authn" => "Authentication policies and silos",
        "keycreds" => "Key credentials on accounts",
        "bitlocker" => "BitLocker recovery objects",
        "scripts" => "Logon and policy scripts",
        "roles" => "Operations master role objects",
        "querypolicy" => "The LDAP query policy",
        "ncheads" => "The configuration and schema partition heads",
        "dispspec" => "Display specifiers",
        "extrights" => "Extended rights",
        "privmeta" => "Replication metadata of privileged groups",
        "attrmeta" => "Replication metadata of accounts with SPNs or key credentials",
        "wmifilters" => "WMI filters",
        "computerowners" => "Computer object owners",
        "sacls" => "Audit entries (SACLs) of sensitive objects",
        "exchservers" => "Exchange servers",
        "scps" => "Service connection points",
        "sccm" => "The Configuration Manager System Management container",
        "gpsoftware" => "Software installation packages in GPOs",
        other => other,
    }
}

/// Why a rule cannot run, if one of the areas it reads is unavailable.
pub(crate) fn missing(raw: &RawDomain, needs: &[&str]) -> Option<String> {
    for area in needs {
        match raw.area(area) {
            AreaState::Read(_) => {}
            AreaState::Failed(message) => {
                return Some(format!("{} could not be read: {message}", area_label(area)))
            }
            AreaState::Missing => {
                return Some(format!(
                    "{} was not collected in this run.",
                    area_label(area)
                ))
            }
        }
    }
    None
}

/// Runs every implemented on-prem rule whose area is in `areas` (all of
/// them when `areas` is empty).
pub fn analyze(catalog: &Catalog, raw: &RawDomain, areas: &[String]) -> DomainAnalysis {
    analyze_model(catalog, &model::Model::build(raw), areas)
}

/// [`analyze`] for a domain model that is already built.
pub fn analyze_model(catalog: &Catalog, m: &model::Model, areas: &[String]) -> DomainAnalysis {
    let raw = m.raw;
    let selected = |id: &str| {
        let area = catalog
            .check(id)
            .map(|c| c.area.as_str())
            .unwrap_or_default();
        areas.is_empty() || areas.iter().any(|a| a == area)
    };
    let checks = rules::RULES
        .iter()
        .chain(rules_dc::RULES)
        .chain(rules_pki::RULES)
        .chain(rules_hunt::RULES)
        .chain(rules_ioc::RULES)
        .chain(rules_svc::RULES)
        .chain(rules_gpo::RULES)
        .chain(rules_net::RULES)
        .chain(rules_auth::RULES)
        .chain(rules_obj::RULES)
        .chain(rules_misc::RULES)
        .chain(rules_ep::RULES)
        .chain(rules_t0::RULES)
        .chain(rules_more::RULES)
        .chain(rules_forest::RULES)
        .chain(rules_access::RULES)
        .chain(rules_policy::RULES)
        .chain(rules_host::RULES)
        .chain(rules_ca::RULES)
        .chain(rules_last::RULES)
        .filter(|r| selected(r.id))
        .map(|r| match missing(raw, r.needs) {
            Some(note) => CheckResult {
                id: r.id.to_string(),
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
            },
            None => (r.run)(m),
        })
        .collect();
    let paths = if missing(raw, &["acls", "groups"]).is_none() {
        paths::find(m)
    } else {
        Vec::new()
    };
    DomainAnalysis {
        checks,
        paths,
        directory: directory::build(m),
    }
}
