//! Tier 0 servers beyond the domain controllers: certificate authorities,
//! the Entra Connect Sync and AD FS servers read as endpoints, and the
//! management agents and applications on domain controllers that hand
//! control of them to other systems.

use std::collections::BTreeSet;

use serde_json::Value;

use super::ep::Endpoint;
use super::model::Model;
use super::rules::{check, plural, Out, Rule};
use super::rules_dc::{age_days, dc_item};
use super::rules_ep::{laps_policy, running, EDR_SERVICES, PATCH_DAYS};
use super::rules_pki::cas;
use crate::entra::model::J;
use crate::results::{Affected, CheckResult};

/// Service name prefixes of agents that let another system run code on a
/// machine: (prefix, product).
const AGENTS: [(&str, &str); 14] = [
    ("HealthService", "System Center Operations Manager agent"),
    ("puppet", "Puppet"),
    ("chef-client", "Chef"),
    ("salt-minion", "Salt"),
    ("TaniumClient", "Tanium"),
    ("ScreenConnect", "ConnectWise ScreenConnect"),
    ("LTService", "ConnectWise Automate"),
    ("AnyDesk", "AnyDesk"),
    ("TeamViewer", "TeamViewer"),
    ("NinjaRMMAgent", "NinjaOne"),
    ("Kaseya", "Kaseya"),
    ("AteraAgent", "Atera"),
    ("SplashtopRemoteService", "Splashtop"),
    ("ManageEngine", "ManageEngine"),
];

/// Installed programs that browse the web or read mail.
const CLIENT_APPS: [&str; 9] = [
    "Google Chrome",
    "Mozilla Firefox",
    "Brave",
    "Opera Stable",
    "Mozilla Thunderbird",
    "Microsoft 365 Apps",
    "Microsoft Office Professional",
    "Microsoft Office Standard",
    "Microsoft Outlook",
];

fn same_host(a: &str, b: &str) -> bool {
    let short = |s: &str| s.split('.').next().unwrap_or(s).to_ascii_lowercase();
    a.eq_ignore_ascii_case(b) || short(a) == short(b)
}

fn endpoint<'a>(m: &'a Model, host: &str) -> Option<&'a Endpoint> {
    m.raw.endpoints.iter().find(|e| same_host(&e.name, host))
}

fn software(ep: &Endpoint) -> Vec<&str> {
    ep.part("software")
        .and_then(Value::as_array)
        .map(|l| l.iter().filter_map(|s| s.s("name")).collect())
        .unwrap_or_default()
}

fn has_service(ep: &Endpoint, name: &str) -> bool {
    ep.service(name).is_some()
}

/// Host names of the enterprise CAs.
fn ca_hosts(m: &Model) -> BTreeSet<String> {
    cas(m)
        .filter_map(|c| c.str("dnshostname"))
        .map(str::to_ascii_lowercase)
        .collect()
}

/// Entra Connect Sync servers: named in the MSOL_ account's description, or
/// read as endpoints with Connect installed.
fn connect_hosts(m: &Model) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for n in &m.nodes {
        let sam = n.attrs.str("samaccountname").unwrap_or_default();
        if !sam.to_ascii_lowercase().starts_with("msol_") {
            continue;
        }
        if let Some(d) = n.attrs.str("description") {
            if let Some((_, rest)) = d.split_once("running on computer ") {
                if let Some(h) = rest.split_whitespace().next() {
                    out.insert(h.to_ascii_lowercase());
                }
            }
        }
    }
    for ep in &m.raw.endpoints {
        if software(ep).iter().any(|s| {
            s.contains("Azure AD Connect")
                || s.contains("Entra Connect")
                || s.contains("Azure AD Sync")
        }) {
            out.insert(ep.name.to_ascii_lowercase());
        }
    }
    out
}

fn adfs_hosts(m: &Model) -> BTreeSet<String> {
    m.raw
        .endpoints
        .iter()
        .filter(|e| has_service(e, "adfssrv"))
        .map(|e| e.name.to_ascii_lowercase())
        .collect()
}

/// What a Tier 0 server lacks of the hardening a domain controller has.
fn tier0_gaps(m: &Model, ep: &Endpoint) -> Vec<String> {
    let mut gaps = Vec::new();
    if ep.part("registry").is_some() {
        if !matches!(ep.reg_int("lsa.runasppl"), Some(1 | 2)) {
            gaps.push("LSA protection off".to_string());
        }
        if !laps_policy(ep) {
            gaps.push("no LAPS".to_string());
        }
    }
    if let Some(dg) = ep.part("device_guard") {
        if !running(dg, 1) {
            gaps.push("Credential Guard not running".to_string());
        }
    }
    if let Some(smb) = ep.part("smb") {
        if smb.b("smb1") == Some(true) {
            gaps.push("SMBv1 on".to_string());
        }
        if smb.b("require_signing") != Some(true) {
            gaps.push("SMB signing not required".to_string());
        }
    }
    for (svc, label) in [("Spooler", "Print Spooler"), ("WebClient", "WebClient")] {
        if ep.service_active(svc) == Some(true) {
            gaps.push(format!("{label} running"));
        }
    }
    if ep.part("services").is_some()
        && !EDR_SERVICES.iter().any(|(svc, _)| {
            ep.service(svc)
                .is_some_and(|s| s.s("state") == Some("Running"))
        })
    {
        gaps.push("no EDR agent".to_string());
    }
    if let Some(h) = ep.part("hotfixes") {
        if age_days(m, h.s("last")).is_none_or(|d| d > PATCH_DAYS) {
            gaps.push(format!("no update in {PATCH_DAYS} days"));
        }
    }
    gaps
}

/// Local administrators other than the built-in Administrator, Domain
/// Admins and Enterprise Admins.
fn extra_admins(m: &Model, ep: &Endpoint) -> Vec<String> {
    let allowed = [
        format!("{}-512", m.domain_sid),
        format!("{}-519", m.domain_sid),
    ];
    ep.part("local_admins")
        .and_then(Value::as_array)
        .map(|l| {
            l.iter()
                .filter(|a| {
                    let sid = a.s("sid").unwrap_or_default();
                    !sid.ends_with("-500") && !allowed.iter().any(|x| x.eq_ignore_ascii_case(sid))
                })
                .filter_map(|a| a.s("name").map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Checks each server of one Tier 0 role.
fn role_check(
    m: &Model,
    id: &str,
    expected: &str,
    role: &str,
    hosts: &BTreeSet<String>,
    with_admins: bool,
) -> Out {
    let out = check(id).expected(expected);
    if hosts.is_empty() {
        return out.not_assessed(format!("No {role} was identified in the data collected."));
    }
    let mut bad = Vec::new();
    let mut lines = Vec::new();
    let mut unread = Vec::new();
    for h in hosts {
        let Some(ep) = endpoint(m, h).filter(|e| e.data.is_some()) else {
            unread.push(h.clone());
            continue;
        };
        let mut gaps = tier0_gaps(m, ep);
        if with_admins {
            let extra = extra_admins(m, ep);
            if !extra.is_empty() {
                gaps.push(format!("other local administrators: {}", extra.join(", ")));
            }
        }
        if gaps.is_empty() {
            lines.push(format!("{h}: hardened like a domain controller"));
        } else {
            let text = gaps.join("; ");
            lines.push(format!("{h}: {text}"));
            bad.push(dc_item(m, h, text));
        }
    }
    let read = hosts.len() - unread.len();
    if read == 0 {
        return out.not_assessed(format!(
            "{} {} identified ({}) but not read as endpoints. Include them in the endpoints source.",
            plural(hosts.len(), role, &format!("{role}s")),
            if hosts.len() == 1 { "was" } else { "were" },
            unread.join(", ")
        ));
    }
    let n = bad.len();
    let mut out = out
        .affected(bad, &format!("{role}s"))
        .found(format!(
            "{n} of {} with gaps",
            plural(read, role, &format!("{role}s"))
        ))
        .raw(lines.join("\n"));
    if !unread.is_empty() {
        out = out.evidence("Not read", unread.join(", "));
    }
    out
}

fn t0_001(m: &Model) -> CheckResult {
    let hosts = ca_hosts(m);
    if hosts.is_empty() {
        return check("EP-T0-001")
            .found("No enterprise CA is published in the forest")
            .done();
    }
    role_check(
        m,
        "EP-T0-001",
        "Every enterprise CA server is hardened like a domain controller: LSA protection, Credential Guard, LAPS, SMB signing, no SMBv1, Print Spooler or WebClient, an EDR agent and current updates",
        "certificate authority server",
        &hosts,
        false,
    )
    .done()
}

fn t0_002(m: &Model) -> CheckResult {
    role_check(
        m,
        "EP-T0-002",
        "The Entra Connect Sync server is hardened like a domain controller and only Domain Admins and Enterprise Admins administer it",
        "Entra Connect server",
        &connect_hosts(m),
        true,
    )
    .done()
}

fn t0_003(m: &Model) -> CheckResult {
    role_check(
        m,
        "EP-T0-003",
        "Every AD FS server is hardened like a domain controller and only Domain Admins and Enterprise Admins administer it",
        "AD FS server",
        &adfs_hosts(m),
        true,
    )
    .done()
}

/// Every DC whose configuration was read, with the services that match.
fn dc_services(
    m: &Model,
    id: &str,
    expected: &str,
    unit: &str,
    find: impl Fn(&str) -> Option<&'static str>,
) -> Out {
    let out = check(id).expected(expected);
    let mut bad: Vec<Affected> = Vec::new();
    let mut read = 0;
    let mut lines = Vec::new();
    for dc in &m.raw.dcconfig {
        let Some(services) = dc.data.as_ref().and_then(|d| d.services.as_ref()) else {
            continue;
        };
        read += 1;
        let mut found: Vec<&str> = services
            .iter()
            .filter(|s| s.state == "Running" || s.start == "Auto")
            .filter_map(|s| find(&s.name))
            .collect();
        found.sort_unstable();
        found.dedup();
        if found.is_empty() {
            lines.push(format!("{}: none", dc.name));
        } else {
            lines.push(format!("{}: {}", dc.name, found.join(", ")));
            bad.push(dc_item(m, &dc.name, format!("Runs {}", found.join(", "))));
        }
    }
    if read == 0 {
        return out.not_assessed("No domain controller's services were read.");
    }
    let n = bad.len();
    out.affected(bad, unit)
        .found(format!(
            "{n} of {}",
            plural(read, "domain controller", "domain controllers")
        ))
        .raw(lines.join("\n"))
}

fn t0_007(m: &Model) -> CheckResult {
    let site_servers: Vec<String> = m
        .raw
        .endpoints
        .iter()
        .filter(|e| has_service(e, "SMS_EXECUTIVE"))
        .map(|e| e.name.clone())
        .collect();
    dc_services(
        m,
        "EP-T0-007",
        "Domain controllers are not managed by Configuration Manager, or its site servers are administered as Tier 0",
        "domain controllers",
        |s| s.eq_ignore_ascii_case("CcmExec").then_some("the Configuration Manager client"),
    )
    .evidence(
        "Site servers read as endpoints",
        if site_servers.is_empty() {
            "None".to_string()
        } else {
            site_servers.join(", ")
        },
    )
    .done()
}

fn t0_008(m: &Model) -> CheckResult {
    dc_services(
        m,
        "EP-T0-008",
        "No monitoring, automation or remote management agent on a domain controller lets a non-Tier 0 system run code on it",
        "domain controllers",
        |s| {
            let lower = s.to_ascii_lowercase();
            AGENTS
                .iter()
                .find(|(p, _)| lower.starts_with(&p.to_ascii_lowercase()))
                .map(|(_, n)| *n)
        },
    )
    .done()
}

fn client_apps<'a>(names: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut found: Vec<String> = names
        .filter(|n| CLIENT_APPS.iter().any(|c| n.contains(c)))
        .map(str::to_string)
        .collect();
    found.sort();
    found.dedup();
    found
}

fn t0_010(m: &Model) -> CheckResult {
    let mut bad = Vec::new();
    let mut read = 0;
    for dc in &m.raw.dcconfig {
        let Some(list) = dc.data.as_ref().and_then(|d| d.software.as_ref()) else {
            continue;
        };
        read += 1;
        let found = client_apps(list.iter().map(|s| s.name.as_str()));
        if !found.is_empty() {
            bad.push(dc_item(
                m,
                &dc.name,
                format!("Domain controller with {}", found.join(", ")),
            ));
        }
    }
    let mut roles: BTreeSet<String> = ca_hosts(m);
    roles.extend(connect_hosts(m));
    roles.extend(adfs_hosts(m));
    for h in &roles {
        let Some(ep) = endpoint(m, h).filter(|e| e.part("software").is_some()) else {
            continue;
        };
        read += 1;
        let found = client_apps(software(ep).into_iter());
        if !found.is_empty() {
            bad.push(dc_item(
                m,
                h,
                format!("Tier 0 server with {}", found.join(", ")),
            ));
        }
    }
    let out = check("EP-T0-010").expected(
        "No browser or email client is installed on a domain controller or other Tier 0 server",
    );
    if read == 0 {
        return out
            .not_assessed("No installed software list was read from a Tier 0 server.")
            .done();
    }
    let n = bad.len();
    out.affected(bad, "servers")
        .found(format!(
            "{n} of {} with a browser or email client",
            plural(read, "Tier 0 server", "Tier 0 servers")
        ))
        .done()
}

pub static RULES: &[Rule] = &[
    Rule {
        id: "EP-T0-001",
        needs: &["endpoints", "pki"],
        run: t0_001,
    },
    Rule {
        id: "EP-T0-002",
        needs: &["endpoints", "users"],
        run: t0_002,
    },
    Rule {
        id: "EP-T0-003",
        needs: &["endpoints"],
        run: t0_003,
    },
    Rule {
        id: "EP-T0-007",
        needs: &["dcconfig"],
        run: t0_007,
    },
    Rule {
        id: "EP-T0-008",
        needs: &["dcconfig"],
        run: t0_008,
    },
    Rule {
        id: "EP-T0-010",
        needs: &["dcconfig"],
        run: t0_010,
    },
];
