//! Checks on the domain controllers themselves: their configuration, read
//! over PowerShell remoting (`dcconfig`), and what their event logs show
//! (`dcevents`). Each check reports per DC; DCs that could not be read are
//! named in the evidence, and the check is not assessed only when no DC
//! could be.

use std::collections::BTreeMap;

use super::dc::{DcConfig, DcData, DcEvents, EventSummary};
use super::model::{uac, Kind, Model};
use super::rules::{check, days_text, item, plural, Out, Rule};
use crate::catalog::Severity;
use crate::results::{Affected, CheckResult};
use crate::time;

const DAY: i64 = time::DAY;

/// Outcome of one check on one DC.
pub(super) enum Eval {
    Ok(String),
    Bad(String),
    /// The DC returned the data, but not the part this check needs.
    Unknown(String),
}

pub(super) fn short(name: &str) -> &str {
    name.split('.').next().unwrap_or(name)
}

/// The model's computer object for a DC host name, if LDAP returned it.
fn dc_node(m: &Model, name: &str) -> Option<usize> {
    let lower = name.to_ascii_lowercase();
    (0..m.nodes.len()).find(|&i| {
        let n = &m.nodes[i];
        n.kind == Kind::Computer
            && (n
                .attrs
                .str("dnshostname")
                .is_some_and(|d| d.eq_ignore_ascii_case(&lower))
                || n.name
                    .trim_end_matches('$')
                    .eq_ignore_ascii_case(short(name)))
    })
}

pub(super) fn dc_item(m: &Model, name: &str, reason: impl Into<String>) -> Affected {
    match dc_node(m, name) {
        Some(i) => {
            let mut a = item(m, i, reason);
            a.name = name.to_string();
            a
        }
        None => Affected {
            last_seen: None,
            name: name.to_string(),
            kind: "computer".into(),
            location: None,
            reason: Some(reason.into()),
            object: None,
        },
    }
}

fn read_from(m: &Model, what: &str) -> String {
    format!(
        "{what}, collected from {} as {}",
        m.raw.info.computer, m.raw.info.account
    )
}

/// Runs `eval` on every DC whose configuration was read.
pub(super) fn each_dc(
    m: &Model,
    id: &str,
    expected: &str,
    unit: &str,
    eval: impl Fn(&DcConfig, &DcData) -> Eval,
) -> Out {
    let mut bad = Vec::new();
    let mut lines = Vec::new();
    let mut skipped = Vec::new();
    let mut ok = 0;
    for dc in &m.raw.dcconfig {
        let Some(data) = &dc.data else {
            skipped.push(format!(
                "{} ({})",
                dc.name,
                dc.error.as_deref().unwrap_or("not read")
            ));
            continue;
        };
        match eval(dc, data) {
            Eval::Ok(found) => {
                ok += 1;
                lines.push(format!("{}: {found}", dc.name));
            }
            Eval::Bad(found) => {
                lines.push(format!("{}: {found}", dc.name));
                bad.push(dc_item(m, &dc.name, found));
            }
            Eval::Unknown(why) => skipped.push(format!("{} ({why})", dc.name)),
        }
    }
    summarize(
        m,
        id,
        expected,
        unit,
        bad,
        ok,
        lines,
        skipped,
        "Registry and system settings over PowerShell remoting",
    )
}

#[allow(clippy::too_many_arguments)]
fn summarize(
    m: &Model,
    id: &str,
    expected: &str,
    unit: &str,
    bad: Vec<Affected>,
    ok: usize,
    lines: Vec<String>,
    skipped: Vec<String>,
    how: &str,
) -> Out {
    let out = check(id).expected(expected);
    let assessed = bad.len() + ok;
    if assessed == 0 {
        let why = if skipped.is_empty() {
            "No domain controller was read.".to_string()
        } else {
            format!(
                "No domain controller could be assessed: {}.",
                skipped.join("; ")
            )
        };
        return out.not_assessed(why);
    }
    let found = if bad.is_empty() {
        format!(
            "All {} as expected",
            plural(assessed, "domain controller", "domain controllers")
        )
    } else {
        format!(
            "{} of {} not as expected",
            bad.len(),
            plural(assessed, "domain controller", "domain controllers")
        )
    };
    let mut out = out
        .affected(bad, unit)
        .found(found)
        .evidence("Read from", read_from(m, how))
        .raw(lines.join("\n"));
    if !skipped.is_empty() {
        out = out.evidence("Not assessed on", skipped.join("; "));
    }
    out
}

fn reg_text(v: Option<i64>) -> String {
    v.map_or_else(|| "not set".into(), |v| v.to_string())
}

pub(super) fn age_days(m: &Model, iso: Option<&str>) -> Option<i64> {
    iso.and_then(time::parse_iso)
        .map(|t| (m.now - t).div_euclid(DAY))
}

// ---------- Domain controller health and hardening ----------

/// Windows Server builds and the end of their extended support.
pub(super) fn os_support(build: i64) -> Option<(&'static str, &'static str)> {
    Some(match build {
        6001..=6003 => ("Windows Server 2008", "2020-01-14"),
        7600 | 7601 => ("Windows Server 2008 R2", "2020-01-14"),
        9200 => ("Windows Server 2012", "2023-10-10"),
        9600 => ("Windows Server 2012 R2", "2023-10-10"),
        14393 => ("Windows Server 2016", "2027-01-12"),
        17763 => ("Windows Server 2019", "2029-01-09"),
        20348 => ("Windows Server 2022", "2031-10-14"),
        26100 => ("Windows Server 2025", "2034-10-10"),
        _ => return None,
    })
}

pub(super) fn dc_nodes<'a>(m: &'a Model<'a>) -> impl Iterator<Item = usize> + 'a {
    (0..m.nodes.len()).filter(move |&i| {
        let n = &m.nodes[i];
        n.kind == Kind::Computer && (n.is_dc() || n.flag(uac::PARTIAL_SECRETS_ACCOUNT))
    })
}

fn dc_001(m: &Model) -> CheckResult {
    let mut bad = Vec::new();
    let mut lines = Vec::new();
    let mut worst = Severity::Low;
    let mut assessed = 0;
    for i in dc_nodes(m) {
        let n = &m.nodes[i];
        let version = n.attrs.str("operatingsystemversion").unwrap_or_default();
        let build = version
            .split(['(', ')'])
            .nth(1)
            .and_then(|b| b.trim().parse::<i64>().ok());
        let name = n.attrs.str("operatingsystem").unwrap_or("unknown");
        lines.push(format!("{}: {name} {version}", n.name));
        let Some((product, end)) = build.and_then(os_support) else {
            continue;
        };
        assessed += 1;
        let Some(end_t) = time::parse_iso(end) else {
            continue;
        };
        let left = (end_t - m.now).div_euclid(DAY);
        if left < 0 {
            worst = Severity::High;
            bad.push(item(
                m,
                i,
                format!("{product}: extended support ended on {end}"),
            ));
        } else if left < 365 {
            if worst == Severity::Low {
                worst = Severity::Medium;
            }
            bad.push(item(
                m,
                i,
                format!(
                    "{product}: extended support ends on {end}, in {}",
                    days_text(Some(left))
                ),
            ));
        }
    }
    let out = check("AD-DC-001").expected(
        "Every domain controller on a Windows Server version supported for at least another year",
    );
    if assessed == 0 {
        return out
            .not_assessed(
                "No domain controller reported a Windows Server build this check recognises.",
            )
            .raw(lines.join("\n"))
            .done();
    }
    let failed = !bad.is_empty();
    let out = out
        .found(format!(
            "{} of {} on an unsupported or soon unsupported version",
            bad.len(),
            assessed
        ))
        .affected(bad, "domain controllers")
        .evidence(
            "Read from",
            "operatingSystem and operatingSystemVersion of each DC's computer object (LDAP)",
        )
        .raw(lines.join("\n"));
    if failed { out.severity(worst) } else { out }.done()
}

fn dc_002(m: &Model) -> CheckResult {
    each_dc(
        m,
        "AD-DC-002",
        "An update installed on every DC in the last 60 days",
        "domain controllers",
        |_, d| {
            let Some(h) = &d.hotfixes else {
                return Eval::Unknown(d.why_missing("hotfixes"));
            };
            let Some(last) = h.last.as_deref() else {
                return Eval::Bad("No installed update has an install date".into());
            };
            let age = age_days(m, Some(last)).unwrap_or(0);
            let text = format!(
                "last update {} installed {} ago",
                h.last_id.as_deref().unwrap_or("?"),
                days_text(Some(age))
            );
            if age > 60 {
                Eval::Bad(text)
            } else {
                Eval::Ok(text)
            }
        },
    )
    .done()
}

fn dc_003(m: &Model) -> CheckResult {
    let ou = format!(
        "OU=Domain Controllers,{}",
        m.raw.domain.first().map(|d| d.dn()).unwrap_or_default()
    )
    .to_ascii_lowercase();
    let mut bad = Vec::new();
    let mut total = 0;
    for i in dc_nodes(m) {
        total += 1;
        let dn = m.nodes[i].dn.to_ascii_lowercase();
        if !dn.ends_with(&format!(",{ou}")) {
            bad.push(item(m, i, "Outside the Domain Controllers OU"));
        }
    }
    check("AD-DC-003")
        .expected("Every domain controller in the Domain Controllers OU, where the Default Domain Controllers Policy applies")
        .found(format!("{} of {} outside the Domain Controllers OU", bad.len(), total))
        .affected(bad, "domain controllers")
        .evidence("Read from", "distinguishedName of each DC's computer object (LDAP)")
        .done()
}

fn dc_004(m: &Model) -> CheckResult {
    let mut bad = Vec::new();
    let mut total = 0;
    for i in dc_nodes(m) {
        total += 1;
        for e in m.edges.iter().filter(|e| e.to == i && e.kind == "Owns") {
            bad.push(item(m, i, format!("Owned by {}", m.nodes[e.from].name)));
        }
    }
    check("AD-DC-004")
        .expected(
            "Every DC computer object owned by Domain Admins, Enterprise Admins or Administrators",
        )
        .found(format!(
            "{} of {} owned by another principal",
            bad.len(),
            total
        ))
        .affected(bad, "domain controllers")
        .evidence(
            "Read from",
            "Owner in nTSecurityDescriptor of each DC's computer object (LDAP)",
        )
        .done()
}

fn dc_005(m: &Model) -> CheckResult {
    each_dc(
        m,
        "AD-DC-005",
        "Every DC restarted in the last 60 days",
        "domain controllers",
        |_, d| {
            let Some(boot) = d.os.as_ref().and_then(|o| o.last_boot.as_deref()) else {
                return Eval::Unknown(d.why_missing("os"));
            };
            let days = age_days(m, Some(boot)).unwrap_or(0);
            let text = format!("up for {}", days_text(Some(days)));
            if days > 60 {
                Eval::Bad(text)
            } else {
                Eval::Ok(text)
            }
        },
    )
    .done()
}

fn service_check(
    m: &Model,
    id: &str,
    expected: &str,
    service: &'static str,
    label: &'static str,
) -> Out {
    each_dc(m, id, expected, "domain controllers", move |_, d| {
        if d.services.is_none() {
            return Eval::Unknown(d.why_missing("services"));
        }
        match d.service(service) {
            Some(s) if s.state.eq_ignore_ascii_case("Running") => {
                Eval::Bad(format!("{label} is running (start: {})", s.start))
            }
            Some(s) => Eval::Ok(format!(
                "{label} is {} (start: {})",
                s.state.to_lowercase(),
                s.start
            )),
            None => Eval::Ok(format!("{label} is not installed")),
        }
    })
}

fn dc_006(m: &Model) -> CheckResult {
    service_check(
        m,
        "AD-DC-006",
        "Print Spooler stopped and disabled on every DC",
        "Spooler",
        "Print Spooler",
    )
    .done()
}

const UNNEEDED_FEATURES: [(&str, &str); 14] = [
    ("Web-Server", "IIS web server"),
    ("Hyper-V", "Hyper-V"),
    ("ADCS-Cert-Authority", "AD CS certification authority"),
    ("ADCS-Web-Enrollment", "AD CS web enrollment"),
    ("Print-Services", "Print and Document Services"),
    ("Print-Server", "Print Server"),
    ("RDS-RD-Server", "Remote Desktop Session Host"),
    ("WDS", "Windows Deployment Services"),
    ("Fax", "Fax Server"),
    ("ADFS-Federation", "AD FS"),
    ("NPAS", "Network Policy and Access Services"),
    ("DirectAccess-VPN", "DirectAccess and VPN"),
    ("UpdateServices", "WSUS"),
    ("DHCP", "DHCP Server"),
];

fn dc_007(m: &Model) -> CheckResult {
    each_dc(
        m,
        "AD-DC-007",
        "Only the AD DS, DNS and management features on DCs",
        "domain controllers",
        |_, d| {
            let Some(features) = &d.features else {
                return Eval::Unknown(d.why_missing("features"));
            };
            let found: Vec<&str> = UNNEEDED_FEATURES
                .iter()
                .filter(|(f, _)| features.iter().any(|x| x.eq_ignore_ascii_case(f)))
                .map(|(_, label)| *label)
                .collect();
            if found.is_empty() {
                Eval::Ok("no unneeded roles".into())
            } else {
                Eval::Bad(format!("Installed: {}", found.join(", ")))
            }
        },
    )
    .done()
}

fn dc_009(m: &Model) -> CheckResult {
    each_dc(
        m,
        "AD-DC-009",
        "SMBv1 server disabled on every DC",
        "domain controllers",
        |_, d| match &d.smb {
            None => Eval::Unknown(d.why_missing("smb")),
            Some(s) if s.smb1 => Eval::Bad("SMBv1 is enabled".into()),
            Some(_) => Eval::Ok("SMBv1 is disabled".into()),
        },
    )
    .done()
}

fn dc_010(m: &Model) -> CheckResult {
    each_dc(
        m,
        "AD-DC-010",
        "SMB server signing required on every DC",
        "domain controllers",
        |_, d| match &d.smb {
            None => Eval::Unknown(d.why_missing("smb")),
            Some(s) if !s.require_signing => Eval::Bad("SMB signing is not required".into()),
            Some(_) => Eval::Ok("SMB signing is required".into()),
        },
    )
    .done()
}

pub(super) fn registry_ready(d: &DcData) -> Option<Eval> {
    d.registry
        .is_none()
        .then(|| Eval::Unknown(d.why_missing("registry")))
}

fn dc_011(m: &Model) -> CheckResult {
    each_dc(
        m,
        "AD-DC-011",
        "LDAPServerIntegrity = 2 (signing required) on every DC",
        "domain controllers",
        |_, d| {
            if let Some(e) = registry_ready(d) {
                return e;
            }
            let v = d.reg_int("ntds.ldapserverintegrity");
            let text = format!("LDAPServerIntegrity {}", reg_text(v));
            if v == Some(2) {
                Eval::Ok(text)
            } else {
                Eval::Bad(format!("{text}: signing is not required"))
            }
        },
    )
    .done()
}

fn dc_012(m: &Model) -> CheckResult {
    let mut weak_only = true;
    let out = each_dc(
        m,
        "AD-DC-012",
        "LdapEnforceChannelBinding = 2 (always) on every DC",
        "domain controllers",
        |_, d| {
            if let Some(e) = registry_ready(d) {
                return e;
            }
            let v = d.reg_int("ntds.ldapenforcechannelbinding");
            let text = format!("LdapEnforceChannelBinding {}", reg_text(v));
            match v {
                Some(2) => Eval::Ok(text),
                Some(1) => Eval::Bad(format!("{text}: enforced only for clients that support it")),
                _ => Eval::Bad(format!("{text}: channel binding is not enforced")),
            }
        },
    );
    // Only "when supported" everywhere is a smaller gap than none at all.
    for dc in &m.raw.dcconfig {
        if let Some(d) = &dc.data {
            if d.registry.is_some() && d.reg_int("ntds.ldapenforcechannelbinding").unwrap_or(0) == 0
            {
                weak_only = false;
            }
        }
    }
    if out.0.status == crate::results::ResultStatus::Failed && weak_only {
        out.severity(Severity::Low).done()
    } else {
        out.done()
    }
}

fn dc_013(m: &Model) -> CheckResult {
    each_dc(
        m,
        "AD-DC-013",
        "A server certificate for each DC's name, valid for more than 30 days",
        "domain controllers",
        |dc, d| {
            let Some(certs) = &d.certificates else {
                return Eval::Unknown(d.why_missing("certificates"));
            };
            let name = dc.name.to_ascii_lowercase();
            let best = certs
                .iter()
                .filter(|c| c.server_auth && c.dns.iter().any(|n| n.eq_ignore_ascii_case(&name)))
                .filter_map(|c| c.not_after.as_deref().and_then(time::parse_iso))
                .max();
            match best {
                None => Eval::Bad(
                    "No server authentication certificate for this name; LDAPS is not available"
                        .into(),
                ),
                Some(t) => {
                    let left = (t - m.now).div_euclid(DAY);
                    if left < 0 {
                        Eval::Bad(format!(
                            "The certificate expired on {}",
                            &time::iso(t)[..10]
                        ))
                    } else if left <= 30 {
                        Eval::Bad(format!(
                            "The certificate expires on {}, in {}",
                            &time::iso(t)[..10],
                            days_text(Some(left))
                        ))
                    } else {
                        Eval::Ok(format!("certificate valid until {}", &time::iso(t)[..10]))
                    }
                }
            }
        },
    )
    .done()
}

fn dc_014(m: &Model) -> CheckResult {
    each_dc(m, "AD-DC-014", "NTLM authentication audited on every DC, so it can then be restricted", "domain controllers", |_, d| {
        if let Some(e) = registry_ready(d) {
            return e;
        }
        let audit = d.reg_int("netlogon.auditntlmindomain").unwrap_or(0);
        let incoming = d.reg_int("msv1_0.auditreceivingntlmtraffic").unwrap_or(0);
        let restrict = d.reg_int("netlogon.restrictntlmindomain").unwrap_or(0);
        let text = format!("AuditNTLMInDomain {audit}, AuditReceivingNTLMTraffic {incoming}, RestrictNTLMInDomain {restrict}");
        if audit == 0 && incoming == 0 && restrict == 0 {
            Eval::Bad(format!("NTLM is neither audited nor restricted ({text})"))
        } else {
            Eval::Ok(text)
        }
    })
    .done()
}

fn dc_015(m: &Model) -> CheckResult {
    each_dc(
        m,
        "AD-DC-015",
        "NoLMHash = 1 on every DC",
        "domain controllers",
        |_, d| {
            if let Some(e) = registry_ready(d) {
                return e;
            }
            // Not set means the default, 1, since Windows Server 2008.
            match d.reg_int("lsa.nolmhash") {
                Some(0) => Eval::Bad("NoLMHash 0: LM hashes are stored for new passwords".into()),
                v => Eval::Ok(format!(
                    "NoLMHash {}",
                    v.map_or("not set (default 1)".into(), |v| v.to_string())
                )),
            }
        },
    )
    .done()
}

fn dc_016(m: &Model) -> CheckResult {
    each_dc(
        m,
        "AD-DC-016",
        "LmCompatibilityLevel = 5 (refuse LM and NTLMv1) on every DC",
        "domain controllers",
        |_, d| {
            if let Some(e) = registry_ready(d) {
                return e;
            }
            match d.reg_int("lsa.lmcompatibilitylevel") {
                Some(5) => Eval::Ok("LmCompatibilityLevel 5".into()),
                Some(v) => Eval::Bad(format!(
                    "LmCompatibilityLevel {v}: LM or NTLMv1 is still accepted"
                )),
                None => Eval::Bad(
                    "LmCompatibilityLevel not set (default 3): NTLMv1 is still accepted".into(),
                ),
            }
        },
    )
    .done()
}

fn dc_017(m: &Model) -> CheckResult {
    each_dc(
        m,
        "AD-DC-017",
        "RestrictAnonymousSAM = 1 and EveryoneIncludesAnonymous = 0 on every DC",
        "domain controllers",
        |_, d| {
            if let Some(e) = registry_ready(d) {
                return e;
            }
            let sam = d.reg_int("lsa.restrictanonymoussam").unwrap_or(1);
            let everyone = d.reg_int("lsa.everyoneincludesanonymous").unwrap_or(0);
            let mut problems = Vec::new();
            if sam == 0 {
                problems.push("RestrictAnonymousSAM 0: anonymous users can list accounts");
            }
            if everyone == 1 {
                problems.push("EveryoneIncludesAnonymous 1: anonymous users get Everyone's access");
            }
            if problems.is_empty() {
                Eval::Ok(format!(
                    "RestrictAnonymousSAM {sam}, EveryoneIncludesAnonymous {everyone}"
                ))
            } else {
                Eval::Bad(problems.join("; "))
            }
        },
    )
    .done()
}

fn dc_018(m: &Model) -> CheckResult {
    each_dc(
        m,
        "AD-DC-018",
        "No accounts allowed vulnerable Netlogon secure channel connections",
        "domain controllers",
        |_, d| {
            if let Some(e) = registry_ready(d) {
                return e;
            }
            match d.reg_str("netlogon.vulnerablechannelallowlist") {
                Some(list) if !list.trim().is_empty() => {
                    Eval::Bad(format!("VulnerableChannelAllowList is set: {list}"))
                }
                _ => {
                    if d.reg_int("netlogon.fullsecurechannelprotection") == Some(0) {
                        Eval::Bad("FullSecureChannelProtection 0".into())
                    } else {
                        Eval::Ok("no vulnerable channel exceptions".into())
                    }
                }
            }
        },
    )
    .done()
}

fn dc_019(m: &Model) -> CheckResult {
    each_dc(m, "AD-DC-019", "KDC certificate mapping in full enforcement (StrongCertificateBindingEnforcement 2 or not set)", "domain controllers", |_, d| {
        if let Some(e) = registry_ready(d) {
            return e;
        }
        match d.reg_int("kdc.strongcertificatebindingenforcement") {
            Some(0) => Eval::Bad("StrongCertificateBindingEnforcement 0: strong mapping disabled".into()),
            Some(1) => Eval::Bad("StrongCertificateBindingEnforcement 1: compatibility mode, weak mappings still accepted".into()),
            Some(v) => Eval::Ok(format!("StrongCertificateBindingEnforcement {v}")),
            None => Eval::Ok("StrongCertificateBindingEnforcement not set (full enforcement on current updates)".into()),
        }
    })
    .done()
}

fn dc_020(m: &Model) -> CheckResult {
    let mut network = false;
    let out = each_dc(
        m,
        "AD-DC-020",
        "DsrmAdminLogonBehavior = 0 (DSRM account usable only in DSRM)",
        "domain controllers",
        |_, d| {
            if let Some(e) = registry_ready(d) {
                return e;
            }
            match d.reg_int("lsa.dsrmadminlogonbehavior") {
                Some(2) => Eval::Bad(
                    "DsrmAdminLogonBehavior 2: the DSRM account can sign in over the network"
                        .into(),
                ),
                Some(1) => Eval::Bad(
                    "DsrmAdminLogonBehavior 1: the DSRM account can sign in when AD DS is stopped"
                        .into(),
                ),
                v => Eval::Ok(format!("DsrmAdminLogonBehavior {}", reg_text(v))),
            }
        },
    );
    for dc in &m.raw.dcconfig {
        if dc
            .data
            .as_ref()
            .and_then(|d| d.reg_int("lsa.dsrmadminlogonbehavior"))
            == Some(2)
        {
            network = true;
        }
    }
    if network {
        out.severity(Severity::High)
    } else {
        out
    }
    .done()
}

fn dc_021(m: &Model) -> CheckResult {
    each_dc(
        m,
        "AD-DC-021",
        "Windows Firewall on for the Domain, Private and Public profiles",
        "domain controllers",
        |_, d| {
            let Some(profiles) = &d.firewall else {
                return Eval::Unknown(d.why_missing("firewall"));
            };
            let off: Vec<&str> = profiles
                .iter()
                .filter(|p| !p.enabled)
                .map(|p| p.name.as_str())
                .collect();
            if off.is_empty() {
                Eval::Ok("all profiles on".into())
            } else {
                Eval::Bad(format!("Off for: {}", off.join(", ")))
            }
        },
    )
    .done()
}

fn dc_022(m: &Model) -> CheckResult {
    each_dc(
        m,
        "AD-DC-022",
        "Remote Desktop off, or on with Network Level Authentication required",
        "domain controllers",
        |_, d| {
            if let Some(e) = registry_ready(d) {
                return e;
            }
            if d.reg_int("rdp.fdenytsconnections").unwrap_or(1) != 0 {
                return Eval::Ok("Remote Desktop is off".into());
            }
            let nla = d
                .reg_int("rdp.policyuserauthentication")
                .or_else(|| d.reg_int("rdp.userauthentication"))
                .unwrap_or(1);
            if nla == 0 {
                Eval::Bad("Remote Desktop is on without Network Level Authentication".into())
            } else {
                Eval::Ok("Remote Desktop is on, NLA required".into())
            }
        },
    )
    .done()
}

fn dc_023(m: &Model) -> CheckResult {
    each_dc(
        m,
        "AD-DC-023",
        "WinRM service refuses unencrypted traffic and Basic authentication",
        "domain controllers",
        |_, d| {
            if let Some(e) = registry_ready(d) {
                return e;
            }
            let mut problems = Vec::new();
            if d.reg_int("winrm.allowunencryptedtraffic") == Some(1) {
                problems.push("unencrypted traffic allowed");
            }
            if d.reg_int("winrm.allowbasic") == Some(1) {
                problems.push("Basic authentication allowed");
            }
            if problems.is_empty() {
                Eval::Ok("defaults (encrypted, no Basic)".into())
            } else {
                Eval::Bad(format!("WinRM policy: {}", problems.join(", ")))
            }
        },
    )
    .done()
}

fn dc_024(m: &Model) -> CheckResult {
    each_dc(
        m,
        "AD-DC-024",
        "LSA protection (RunAsPPL) on every DC",
        "domain controllers",
        |_, d| {
            if let Some(e) = registry_ready(d) {
                return e;
            }
            let cg = d.credential_guard.as_ref().is_some_and(|s| s.contains(&1));
            let extra = if cg { ", Credential Guard running" } else { "" };
            match d.reg_int("lsa.runasppl") {
                Some(1 | 2) => Eval::Ok(format!("RunAsPPL on{extra}")),
                v => Eval::Bad(format!(
                    "RunAsPPL {}{extra}: LSASS is not a protected process",
                    reg_text(v)
                )),
            }
        },
    )
    .done()
}

fn dc_025(m: &Model) -> CheckResult {
    each_dc(
        m,
        "AD-DC-025",
        "WDigest UseLogonCredential = 0 or not set",
        "domain controllers",
        |_, d| {
            if let Some(e) = registry_ready(d) {
                return e;
            }
            match d.reg_int("wdigest.uselogoncredential") {
                Some(1) => Eval::Bad(
                    "UseLogonCredential 1: clear-text passwords are kept in memory".into(),
                ),
                v => Eval::Ok(format!("UseLogonCredential {}", reg_text(v))),
            }
        },
    )
    .done()
}

/// The host name (first label) of the PDC emulator, from fSMORoleOwner on
/// the domain head: CN=NTDS Settings,CN=<server>,CN=Servers,...
fn pdc_name(m: &Model) -> Option<String> {
    let owner = m.raw.domain.first()?.str("fsmoroleowner")?;
    let server = owner.split(',').nth(1)?;
    Some(
        server
            .trim_start_matches("CN=")
            .trim_start_matches("cn=")
            .to_string(),
    )
}

fn dc_028(m: &Model) -> CheckResult {
    let Some(pdc) = pdc_name(m) else {
        return check("AD-DC-028")
            .not_assessed(
                "The domain head did not return fSMORoleOwner, so the PDC emulator is not known.",
            )
            .done();
    };
    each_dc(
        m,
        "AD-DC-028",
        "PDC emulator syncs from an external NTP source; other DCs from the domain hierarchy",
        "domain controllers",
        |dc, d| {
            if let Some(e) = registry_ready(d) {
                return e;
            }
            let ty = d
                .reg_str("w32time.type")
                .unwrap_or_else(|| "not set".into());
            let server = d.reg_str("w32time.ntpserver").unwrap_or_default();
            let is_pdc = short(&dc.name).eq_ignore_ascii_case(&pdc);
            if is_pdc {
                let external = ty.eq_ignore_ascii_case("NTP") || ty.eq_ignore_ascii_case("AllSync");
                let text = format!(
                    "PDC emulator, Type {ty}, NtpServer {}",
                    if server.is_empty() {
                        "not set"
                    } else {
                        &server
                    }
                );
                if external && !server.trim().is_empty() {
                    Eval::Ok(text)
                } else {
                    Eval::Bad(format!("{text}: not syncing from an external source"))
                }
            } else {
                let text = format!("Type {ty}");
                if ty.eq_ignore_ascii_case("NT5DS") || ty.eq_ignore_ascii_case("AllSync") {
                    Eval::Ok(text)
                } else {
                    Eval::Bad(format!(
                        "{text}: should follow the domain hierarchy (NT5DS)"
                    ))
                }
            }
        },
    )
    .evidence("PDC emulator", pdc)
    .done()
}

fn dc_029(m: &Model) -> CheckResult {
    // Each DC's clock minus the collector's, at the moment it replied.
    let offsets: Vec<(&str, i64)> = m
        .raw
        .dcconfig
        .iter()
        .filter_map(|dc| {
            let theirs = time::parse_iso(dc.data.as_ref()?.now.as_deref()?)?;
            let ours = time::parse_iso(dc.read_at.as_deref()?)?;
            Some((dc.name.as_str(), theirs - ours))
        })
        .collect();
    let out = check("AD-DC-029")
        .expected("All DC clocks within 2 minutes of each other (Kerberos allows 5)");
    if offsets.len() < 2 {
        return out
            .not_assessed(
                "Clock offsets need at least two domain controllers read over PowerShell remoting.",
            )
            .done();
    }
    let mut sorted: Vec<i64> = offsets.iter().map(|(_, o)| *o).collect();
    sorted.sort();
    let spread = sorted[sorted.len() - 1] - sorted[0];
    // The PDC emulator is the domain's time source, so DCs are measured
    // against it; without it, against the median DC.
    let pdc = pdc_name(m);
    let (reference, against) = match offsets.iter().find(|(n, _)| {
        pdc.as_deref()
            .is_some_and(|p| short(n).eq_ignore_ascii_case(p))
    }) {
        Some((_, o)) => (*o, "the PDC emulator"),
        None => (sorted[sorted.len() / 2], "the other DCs"),
    };
    let bad = offsets
        .iter()
        .filter(|(_, o)| (o - reference).abs() > 120)
        .map(|(n, o)| {
            dc_item(
                m,
                n,
                format!("{} seconds from {against}", (o - reference).abs()),
            )
        })
        .collect();
    out.found(format!("Largest difference between DCs: {spread} seconds"))
        .affected(bad, "domain controllers")
        .evidence(
            "Read from",
            "Each DC's clock compared with the collecting computer's when it replied",
        )
        .raw(
            offsets
                .iter()
                .map(|(n, o)| format!("{n}: {o:+} s from the collecting computer"))
                .collect::<Vec<_>>()
                .join("\n"),
        )
        .done()
}

fn dc_030(m: &Model) -> CheckResult {
    const GIB: i64 = 1 << 30;
    each_dc(
        m,
        "AD-DC-030",
        "At least 10% and 5 GB free on the NTDS database, log and SYSVOL volumes",
        "domain controllers",
        |_, d| {
            let (Some(disks), Some(_)) = (&d.disks, &d.registry) else {
                return Eval::Unknown(d.why_missing(if d.disks.is_none() {
                    "disks"
                } else {
                    "registry"
                }));
            };
            let mut drives: Vec<(String, &str)> = Vec::new();
            for (key, what) in [
                ("ntds.database", "database"),
                ("ntds.logs", "logs"),
                ("netlogon.sysvol", "SYSVOL"),
            ] {
                if let Some(p) = d.reg_str(key) {
                    if let Some(drive) = p.get(..2) {
                        drives.push((drive.to_ascii_uppercase(), what));
                    }
                }
            }
            if drives.is_empty() {
                return Eval::Unknown("the NTDS and SYSVOL paths were not returned".into());
            }
            let mut low = Vec::new();
            let mut seen = Vec::new();
            for (drive, what) in &drives {
                let Some(disk) = disks.iter().find(|k| k.drive.eq_ignore_ascii_case(drive)) else {
                    continue;
                };
                let pct = if disk.size > 0 {
                    disk.free * 100 / disk.size
                } else {
                    0
                };
                let line = format!("{drive} ({what}) {} GB free, {pct}%", disk.free / GIB);
                if (pct < 10 || disk.free < 5 * GIB) && !low.contains(&line) {
                    low.push(line.clone());
                }
                if !seen.contains(&line) {
                    seen.push(line);
                }
            }
            if low.is_empty() {
                Eval::Ok(seen.join("; "))
            } else {
                Eval::Bad(format!("Low space: {}", low.join("; ")))
            }
        },
    )
    .done()
}

// ---------- Legacy and insecure protocols ----------

#[derive(Clone, Copy)]
struct EventCheck {
    id: &'static str,
    query: &'static str,
    expected: &'static str,
    /// What each listed source is: "client" or "account".
    kind: &'static str,
    unit: &'static str,
    what: &'static str,
    /// Why seeing none may not mean none happened.
    caveat: Option<&'static str>,
}

/// Lists the sources (clients or accounts) the DC logs name, merged across
/// DCs. Fails when any DC logged a matching event.
fn event_check(
    m: &Model,
    c: EventCheck,
    unknown: impl Fn(&DcEvents, &EventSummary) -> Option<String>,
) -> Out {
    let mut sources: BTreeMap<String, (u64, Vec<String>)> = BTreeMap::new();
    let mut lines = Vec::new();
    let mut skipped = Vec::new();
    let mut assessed = 0;
    let mut total = 0;
    let mut capped = false;
    let mut days = 0;
    for dc in &m.raw.dcevents {
        if let Some(e) = &dc.error {
            skipped.push(format!("{} ({e})", dc.name));
            continue;
        }
        let Some(q) = dc.queries.get(c.query) else {
            skipped.push(format!("{} (not queried)", dc.name));
            continue;
        };
        if let Some(e) = &q.error {
            skipped.push(format!("{} ({e})", dc.name));
            continue;
        }
        if let Some(why) = unknown(dc, q) {
            skipped.push(format!("{} ({why})", dc.name));
            continue;
        }
        assessed += 1;
        days = days.max(dc.days);
        let count = q.binds.filter(|b| *b > 0).unwrap_or(q.count);
        total += count;
        capped |= q.capped;
        lines.push(format!("{}: {} {}", dc.name, count, c.what));
        for s in &q.top {
            let entry = sources.entry(s.key.clone()).or_default();
            entry.0 += s.count;
            entry.1.push(short(&dc.name).to_string());
        }
    }
    let out = check(c.id).expected(c.expected);
    if assessed == 0 {
        let why = if skipped.is_empty() {
            "No domain controller's logs were read.".to_string()
        } else {
            format!(
                "No domain controller's logs could be assessed: {}.",
                skipped.join("; ")
            )
        };
        return out.not_assessed(why);
    }
    let mut list: Vec<(String, (u64, Vec<String>))> = sources.into_iter().collect();
    list.sort_by_key(|(_, (n, _))| std::cmp::Reverse(*n));
    let affected: Vec<Affected> = list
        .into_iter()
        .map(|(key, (n, dcs))| Affected {
            last_seen: None,
            name: key,
            kind: c.kind.into(),
            location: None,
            reason: Some(format!(
                "{} on {}",
                plural(n as usize, "event", "events"),
                dcs.join(", ")
            )),
            object: None,
        })
        .collect();
    let failed = total > 0;
    let mut out = out
        .found(format!(
            "{}{} {} in the last {}",
            total,
            if capped { "+" } else { "" },
            c.what,
            plural(days as usize, "day", "days")
        ))
        .evidence(
            "Read from",
            read_from(m, "Event logs of each DC over remote event log access"),
        )
        .raw(lines.join("\n"));
    out.0.affected_count = Some(affected.len() as u64);
    out.0.affected_unit = Some(c.unit.into());
    out.0.affected = affected;
    out = out.failed(failed);
    if !skipped.is_empty() {
        out = out.evidence("Not assessed on", skipped.join("; "));
    }
    if let (false, Some(caveat)) = (failed, c.caveat) {
        out = out.evidence("Note", caveat);
    }
    out
}

fn no_unknown(_: &DcEvents, _: &EventSummary) -> Option<String> {
    None
}

fn leg_001(m: &Model) -> CheckResult {
    event_check(
        m,
        EventCheck {
            id: "AD-LEG-001",
            query: "ntlmv1",
            expected: "No NTLMv1 logons",
            kind: "client",
            unit: "accounts and clients",
            what: "NTLMv1 logons",
            caveat: Some("Event 4624 is logged only when Logon auditing is on; see AD-AUD-001."),
        },
        no_unknown,
    )
    .done()
}

fn leg_002(m: &Model) -> CheckResult {
    event_check(
        m,
        EventCheck {
            id: "AD-LEG-002",
            query: "lm",
            expected: "No LM logons",
            kind: "client",
            unit: "accounts and clients",
            what: "LM logons",
            caveat: Some("Event 4624 is logged only when Logon auditing is on; see AD-AUD-001."),
        },
        no_unknown,
    )
    .done()
}

fn leg_003(m: &Model) -> CheckResult {
    event_check(m, EventCheck {
        id: "AD-LEG-003",
        query: "smb1",
        expected: "No clients connecting to DCs over SMBv1",
        kind: "client",
        unit: "clients",
        what: "SMBv1 connections",
        caveat: Some("Event 3000 is logged only when SMBv1 access auditing is on (Set-SmbServerConfiguration -AuditSmb1Access)."),
    }, |dc, q| {
        // No events from a DC with SMBv1 on and auditing off says nothing.
        let unaudited = m
            .raw
            .dcconfig
            .iter()
            .find(|d| d.name.eq_ignore_ascii_case(&dc.name))
            .and_then(|d| d.data.as_ref()?.smb.as_ref())
            .is_some_and(|s| s.smb1 && !s.audit_smb1);
        (q.count == 0 && unaudited).then(|| "SMBv1 is on and its access auditing is off".to_string())
    })
    .done()
}

fn leg_004(m: &Model) -> CheckResult {
    // 2887 is a daily total; 2889 names each client but needs diagnostic
    // logging. Either one counts.
    let mut out = event_check(m, EventCheck {
        id: "AD-LEG-004",
        query: "ldap_unsigned",
        expected: "No unsigned SASL or clear-text simple LDAP binds",
        kind: "client",
        unit: "clients",
        what: "unsigned or clear-text LDAP binds (event 2889)",
        caveat: Some("Event 2889 names each client only when LDAP Interface Events diagnostic logging is set to 2."),
    }, no_unknown);
    let summary: u64 = m
        .raw
        .dcevents
        .iter()
        .filter_map(|d| d.queries.get("ldap_unsigned_summary"))
        .filter_map(|q| q.binds)
        .sum();
    if summary > 0 {
        out = out.failed(true).evidence(
            "Event 2887 (daily summary)",
            format!("{summary} unsigned or clear-text binds reported"),
        );
        if out.0.affected_count == Some(0) {
            out.0.affected_count = None;
            out.0.affected_unit = None;
        }
    }
    out.done()
}

fn leg_005(m: &Model) -> CheckResult {
    event_check(m, EventCheck {
        id: "AD-LEG-005",
        query: "ldap_cbt",
        expected: "No LDAPS binds without channel binding tokens",
        kind: "client",
        unit: "clients",
        what: "LDAPS binds without channel binding (event 3039)",
        caveat: Some("Event 3039 is logged only when LDAP Interface Events diagnostic logging is set to 2."),
    }, no_unknown)
    .done()
}

fn leg_006(m: &Model) -> CheckResult {
    event_check(m, EventCheck {
        id: "AD-LEG-006",
        query: "rc4",
        expected: "No Kerberos service tickets issued with RC4",
        kind: "account",
        unit: "services",
        what: "RC4 service tickets",
        caveat: None,
    }, |dc, _| {
        let audited = dc.queries.get("audit_ticket_ops").is_some_and(|q| q.error.is_none() && q.count > 0);
        (!audited).then(|| "no Kerberos ticket events were logged; Kerberos Service Ticket Operations auditing is off".to_string())
    })
    .done()
}

fn leg_007(m: &Model) -> CheckResult {
    event_check(
        m,
        EventCheck {
            id: "AD-LEG-007",
            query: "netlogon",
            expected: "No vulnerable Netlogon secure channel connections",
            kind: "account",
            unit: "accounts",
            what: "vulnerable Netlogon connections (5827-5829)",
            caveat: None,
        },
        no_unknown,
    )
    .done()
}

fn leg_008(m: &Model) -> CheckResult {
    event_check(
        m,
        EventCheck {
            id: "AD-LEG-008",
            query: "kdc_cert",
            expected: "No KDC certificate mapping warnings",
            kind: "account",
            unit: "accounts",
            what: "KDC certificate mapping warnings (39-41)",
            caveat: None,
        },
        no_unknown,
    )
    .done()
}

fn tls_enabled(d: &DcData, proto: &str) -> bool {
    let enabled = d.reg_int(&format!("schannel.{proto}.enabled"));
    let off_by_default = d.reg_int(&format!("schannel.{proto}.disabledbydefault"));
    !(enabled == Some(0) || off_by_default == Some(1))
}

fn leg_009(m: &Model) -> CheckResult {
    each_dc(
        m,
        "AD-LEG-009",
        "TLS 1.0 and 1.1 disabled for the server side of SCHANNEL",
        "domain controllers",
        |_, d| {
            if let Some(e) = registry_ready(d) {
                return e;
            }
            let on: Vec<&str> = [("tls10", "TLS 1.0"), ("tls11", "TLS 1.1")]
                .into_iter()
                .filter(|(p, _)| tls_enabled(d, p))
                .map(|(_, l)| l)
                .collect();
            if on.is_empty() {
                Eval::Ok("TLS 1.0 and 1.1 disabled".into())
            } else {
                Eval::Bad(format!(
                    "Not disabled in SCHANNEL settings: {}",
                    on.join(", ")
                ))
            }
        },
    )
    .done()
}

fn leg_011(m: &Model) -> CheckResult {
    each_dc(
        m,
        "AD-LEG-011",
        "LLMNR off by policy and NetBIOS over TCP/IP off on every interface",
        "domain controllers",
        |_, d| {
            if let Some(e) = registry_ready(d) {
                return e;
            }
            let mut problems = Vec::new();
            if d.reg_int("dnsclient.enablemulticast") != Some(0) {
                problems.push("LLMNR is not turned off by policy".to_string());
            }
            if let Some(nb) = &d.netbios {
                let on = nb.iter().filter(|v| **v != 2).count();
                if on > 0 {
                    problems.push(format!(
                        "NetBIOS over TCP/IP not disabled on {}",
                        plural(on, "interface", "interfaces")
                    ));
                }
            }
            if problems.is_empty() {
                Eval::Ok("LLMNR and NetBIOS off".into())
            } else {
                Eval::Bad(problems.join("; "))
            }
        },
    )
    .done()
}

fn leg_012(m: &Model) -> CheckResult {
    service_check(
        m,
        "AD-LEG-012",
        "WebClient service not running on DCs",
        "WebClient",
        "WebClient",
    )
    .done()
}

// ---------- Auditing and monitoring readiness ----------

/// Subcategories a DC should audit (Microsoft's DC baseline), by GUID:
/// name, success needed, failure needed.
pub(super) const AUDIT_BASELINE: [(&str, &str, bool, bool); 18] = [
    (
        "0CCE923F-69AE-11D9-BED3-505054503030",
        "Credential Validation",
        true,
        true,
    ),
    (
        "0CCE9242-69AE-11D9-BED3-505054503030",
        "Kerberos Authentication Service",
        true,
        true,
    ),
    (
        "0CCE9240-69AE-11D9-BED3-505054503030",
        "Kerberos Service Ticket Operations",
        true,
        true,
    ),
    (
        "0CCE9236-69AE-11D9-BED3-505054503030",
        "Computer Account Management",
        true,
        false,
    ),
    (
        "0CCE923A-69AE-11D9-BED3-505054503030",
        "Other Account Management Events",
        true,
        false,
    ),
    (
        "0CCE9237-69AE-11D9-BED3-505054503030",
        "Security Group Management",
        true,
        false,
    ),
    (
        "0CCE9235-69AE-11D9-BED3-505054503030",
        "User Account Management",
        true,
        true,
    ),
    (
        "0CCE923B-69AE-11D9-BED3-505054503030",
        "Directory Service Access",
        true,
        true,
    ),
    (
        "0CCE923C-69AE-11D9-BED3-505054503030",
        "Directory Service Changes",
        true,
        false,
    ),
    (
        "0CCE9217-69AE-11D9-BED3-505054503030",
        "Account Lockout",
        false,
        true,
    ),
    ("0CCE9215-69AE-11D9-BED3-505054503030", "Logon", true, true),
    (
        "0CCE921B-69AE-11D9-BED3-505054503030",
        "Special Logon",
        true,
        false,
    ),
    (
        "0CCE922F-69AE-11D9-BED3-505054503030",
        "Audit Policy Change",
        true,
        false,
    ),
    (
        "0CCE9230-69AE-11D9-BED3-505054503030",
        "Authentication Policy Change",
        true,
        false,
    ),
    (
        "0CCE9228-69AE-11D9-BED3-505054503030",
        "Sensitive Privilege Use",
        true,
        true,
    ),
    (
        "0CCE9211-69AE-11D9-BED3-505054503030",
        "Security System Extension",
        true,
        false,
    ),
    (
        "0CCE9212-69AE-11D9-BED3-505054503030",
        "System Integrity",
        true,
        true,
    ),
    (
        "0CCE922B-69AE-11D9-BED3-505054503030",
        "Process Creation",
        true,
        false,
    ),
];

/// Which of success and failure an auditpol "Inclusion Setting" turns on.
pub(super) fn audit_setting(s: &str) -> (bool, bool) {
    let s = s.to_ascii_lowercase();
    (s.contains("success"), s.contains("failure"))
}

fn audit_gaps(d: &DcData, only: Option<&str>) -> Result<Vec<String>, String> {
    let Some(audit) = &d.audit else {
        return Err(d.why_missing("audit"));
    };
    let mut gaps = Vec::new();
    for (guid, name, s, f) in AUDIT_BASELINE {
        if only.is_some_and(|o| o != guid) {
            continue;
        }
        let (has_s, has_f) = audit
            .get(guid)
            .map(|v| audit_setting(v))
            .unwrap_or((false, false));
        let mut missing = Vec::new();
        if s && !has_s {
            missing.push("success");
        }
        if f && !has_f {
            missing.push("failure");
        }
        if !missing.is_empty() {
            gaps.push(format!("{name} ({})", missing.join(" and ")));
        }
    }
    Ok(gaps)
}

fn aud_001(m: &Model) -> CheckResult {
    each_dc(
        m,
        "AD-AUD-001",
        "Microsoft's DC audit baseline in effect on every DC (auditpol)",
        "domain controllers",
        |_, d| match audit_gaps(d, None) {
            Err(why) => Eval::Unknown(why),
            Ok(g) if g.is_empty() => Eval::Ok("baseline in effect".into()),
            Ok(g) => Eval::Bad(format!("Not audited: {}", g.join(", "))),
        },
    )
    .done()
}

fn aud_002(m: &Model) -> CheckResult {
    each_dc(
        m,
        "AD-AUD-002",
        "Directory Service Changes audited for success on every DC",
        "domain controllers",
        |_, d| match audit_gaps(d, Some("0CCE923C-69AE-11D9-BED3-505054503030")) {
            Err(why) => Eval::Unknown(why),
            Ok(g) if g.is_empty() => Eval::Ok("audited".into()),
            Ok(_) => Eval::Bad("Directory Service Changes is not audited".into()),
        },
    )
    .done()
}

fn aud_004(m: &Model) -> CheckResult {
    const GIB: i64 = 1 << 30;
    each_dc(
        m,
        "AD-AUD-004",
        "Security log at least 1 GB and set to overwrite or archive, not stop",
        "domain controllers",
        |dc, d| {
            let Some(log) = &d.security_log else {
                return Eval::Unknown(d.why_missing("security_log"));
            };
            let span = m
                .raw
                .dcevents
                .iter()
                .find(|e| e.name.eq_ignore_ascii_case(&dc.name))
                .and_then(|e| age_days(m, e.security_oldest.as_deref()))
                .map(|d| format!(", holds {}", days_text(Some(d))))
                .unwrap_or_default();
            let mb = log.max_bytes / (1 << 20);
            let text = format!("{mb} MB, mode {}{span}", log.mode);
            let mut problems = Vec::new();
            if log.max_bytes < GIB {
                problems.push(format!("only {mb} MB"));
            }
            if log.mode.eq_ignore_ascii_case("Retain") {
                problems.push("stops logging when full".to_string());
            }
            if problems.is_empty() {
                Eval::Ok(text)
            } else {
                Eval::Bad(format!("{text}: {}", problems.join(", ")))
            }
        },
    )
    .done()
}

fn aud_006(m: &Model) -> CheckResult {
    each_dc(
        m,
        "AD-AUD-006",
        "Microsoft Defender for Identity sensor running on every DC",
        "domain controllers",
        |_, d| {
            if d.services.is_none() {
                return Eval::Unknown(d.why_missing("services"));
            }
            match d.service("AATPSensor") {
                Some(s) if s.state.eq_ignore_ascii_case("Running") => {
                    Eval::Ok("sensor running".into())
                }
                Some(s) => Eval::Bad(format!("Sensor installed but {}", s.state.to_lowercase())),
                None => Eval::Bad("No Defender for Identity sensor".into()),
            }
        },
    )
    .done()
}

fn aud_011(m: &Model) -> CheckResult {
    let mut bad = Vec::new();
    let mut lines = Vec::new();
    let mut skipped = Vec::new();
    let mut ok = 0;
    for dc in &m.raw.dcevents {
        if let Some(e) = &dc.error {
            skipped.push(format!("{} ({e})", dc.name));
            continue;
        }
        match dc.last_clear.as_deref() {
            Some(t) => {
                let text = format!(
                    "Security log cleared on {} ({} ago)",
                    &t[..10.min(t.len())],
                    days_text(age_days(m, Some(t)))
                );
                lines.push(format!("{}: {text}", dc.name));
                bad.push(dc_item(m, &dc.name, text));
            }
            None => {
                ok += 1;
                lines.push(format!("{}: no clear event in the retained log", dc.name));
            }
        }
    }
    summarize(
        m,
        "AD-AUD-011",
        "No Security log clear (event 1102) in the retained log",
        "domain controllers",
        bad,
        ok,
        lines,
        skipped,
        "Event logs of each DC over remote event log access",
    )
    .done()
}

// ---------- Replication, DNS and backup ----------

fn rep_004(m: &Model) -> CheckResult {
    each_dc(
        m,
        "AD-REP-004",
        "Strict Replication Consistency = 1 on every DC",
        "domain controllers",
        |_, d| {
            if let Some(e) = registry_ready(d) {
                return e;
            }
            match d.reg_int("ntds.strictreplication") {
                Some(1) => Eval::Ok("Strict Replication Consistency 1".into()),
                v => Eval::Bad(format!(
                    "Strict Replication Consistency {}: lingering objects can be reintroduced",
                    reg_text(v)
                )),
            }
        },
    )
    .done()
}

fn rep_013(m: &Model) -> CheckResult {
    each_dc(
        m,
        "AD-REP-013",
        "SYSVOL and NETLOGON shared on every DC",
        "domain controllers",
        |_, d| {
            let Some(shares) = &d.shares else {
                return Eval::Unknown(d.why_missing("shares"));
            };
            let missing: Vec<&str> = ["SYSVOL", "NETLOGON"]
                .into_iter()
                .filter(|s| !shares.iter().any(|x| x.eq_ignore_ascii_case(s)))
                .collect();
            if missing.is_empty() {
                Eval::Ok("SYSVOL and NETLOGON shared".into())
            } else {
                Eval::Bad(format!("Not shared: {}", missing.join(", ")))
            }
        },
    )
    .done()
}

fn dns_011(m: &Model) -> CheckResult {
    each_dc(
        m,
        "AD-DNS-011",
        "No ServerLevelPluginDll on any DNS server DC",
        "domain controllers",
        |_, d| {
            if let Some(e) = registry_ready(d) {
                return e;
            }
            match d.reg_str("dns.serverlevelplugindll") {
                Some(dll) if !dll.trim().is_empty() => Eval::Bad(format!(
                    "ServerLevelPluginDll loads {dll} into the DNS service as SYSTEM"
                )),
                _ => Eval::Ok("no plugin DLL".into()),
            }
        },
    )
    .done()
}

/// When the domain partition was last backed up: the originating change
/// time of dSASignature on the domain head, which a backup updates.
fn last_backup(m: &Model) -> Option<i64> {
    let meta = m.raw.domain.first()?.strs("msds-replattributemetadata");
    meta.iter().find_map(|x| {
        let name = between(x, "<pszAttributeName>", "</pszAttributeName>")?;
        if !name.eq_ignore_ascii_case("dSASignature") {
            return None;
        }
        time::parse_iso(between(
            x,
            "<ftimeLastOriginatingChange>",
            "</ftimeLastOriginatingChange>",
        )?)
    })
}

fn between<'a>(s: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let a = s.find(start)? + start.len();
    let b = s[a..].find(end)? + a;
    Some(s[a..b].trim())
}

pub(super) fn tombstone_days(m: &Model) -> i64 {
    m.raw
        .dirservice
        .first()
        .and_then(|d| d.int("tombstonelifetime"))
        .unwrap_or(60)
}

fn bkp_001(m: &Model) -> CheckResult {
    let out =
        check("AD-BKP-001").expected("A system state backup of the domain in the last 7 days");
    let Some(t) = last_backup(m) else {
        return out
            .not_assessed("The domain head did not return replication metadata for dSASignature.")
            .done();
    };
    let days = (m.now - t).div_euclid(DAY);
    out.failed(days > 7)
        .found(format!(
            "Last backup {} ago ({})",
            days_text(Some(days)),
            &time::iso(t)[..10]
        ))
        .evidence(
            "Read from",
            "msDS-ReplAttributeMetaData (dSASignature) on the domain head (LDAP)",
        )
        .done()
}

fn bkp_002(m: &Model) -> CheckResult {
    let tsl = tombstone_days(m);
    let out = check("AD-BKP-002").expected(format!(
        "Last backup newer than the tombstone lifetime ({tsl} days)"
    ));
    let Some(t) = last_backup(m) else {
        return out
            .not_assessed("The domain head did not return replication metadata for dSASignature.")
            .done();
    };
    let days = (m.now - t).div_euclid(DAY);
    out.failed(days > tsl)
        .found(format!("Last backup {} ago; tombstone lifetime {tsl} days", days_text(Some(days))))
        .evidence("Read from", "msDS-ReplAttributeMetaData (dSASignature) on the domain head, tombstoneLifetime (LDAP)")
        .done()
}

/// What a forest recovery would rely on, from the data collected: recent
/// backups, the tombstone lifetime, the Recycle Bin and more than one DC.
fn bkp_005(m: &Model) -> CheckResult {
    let tsl = tombstone_days(m);
    let backup = last_backup(m).map(|t| (m.now - t).div_euclid(DAY));
    let recycle = super::rules_forest::crossref_container(m)
        .map(|c| c.strs("msds-enabledfeature"))
        .unwrap_or_default()
        .iter()
        .any(|f| f.to_ascii_lowercase().starts_with("cn=recycle bin feature"));
    let dcs = m
        .nodes
        .iter()
        .filter(|n| n.kind == super::model::Kind::Computer && n.is_dc() && n.enabled())
        .count();
    let mut gaps = Vec::new();
    match backup {
        None => gaps.push("No backup of the domain partition is recorded".to_string()),
        Some(d) if d > 7 => gaps.push(format!("The last backup is {} old", days_text(Some(d)))),
        _ => {}
    }
    if !recycle {
        gaps.push("The AD Recycle Bin is off: deleted objects lose their attributes".to_string());
    }
    if dcs < 2 {
        gaps.push(format!(
            "Only {dcs} domain controller: losing it loses the domain"
        ));
    }
    let rows = [
        format!(
            "Last backup: {}",
            backup
                .map(|d| format!("{} ago", days_text(Some(d))))
                .unwrap_or_else(|| "none recorded".into())
        ),
        format!("Tombstone lifetime: {tsl} days"),
        format!(
            "Recycle Bin: {}",
            if recycle { "enabled" } else { "not enabled" }
        ),
        format!("Domain controllers: {dcs}"),
    ];
    let list: Vec<Affected> = gaps
        .into_iter()
        .map(|g| Affected {
            last_seen: None,
            name: m.dns.clone(),
            kind: "domain".into(),
            location: None,
            reason: Some(g),
            object: None,
        })
        .collect();
    check("AD-BKP-005")
        .expected("Recovery artifacts are in place: a backup from the last 7 days, the Recycle Bin, and at least two DCs per domain")
        .found(format!("{}; {}", rows[0], plural(list.len(), "gap", "gaps")))
        .raw(rows.join("\n"))
        .affected(list, "gaps")
        .evidence("Read from", "Replication metadata of the domain head, CN=Partitions and DC computer objects (LDAP)")
        .evidence("Note", "The written forest recovery plan itself, and whether restores are tested, cannot be read; review them with the owner")
        .done()
}

const DCCONFIG: &[&str] = &["dcconfig"];
const DCEVENTS: &[&str] = &["dcevents"];

pub const RULES: &[Rule] = &[
    Rule {
        id: "AD-BKP-005",
        needs: &["computers", "domain", "partitions"],
        run: bkp_005,
    },
    Rule {
        id: "AD-DC-001",
        needs: &["computers"],
        run: dc_001,
    },
    Rule {
        id: "AD-DC-002",
        needs: DCCONFIG,
        run: dc_002,
    },
    Rule {
        id: "AD-DC-003",
        needs: &["computers", "domain"],
        run: dc_003,
    },
    Rule {
        id: "AD-DC-004",
        needs: &["computers", "acls"],
        run: dc_004,
    },
    Rule {
        id: "AD-DC-005",
        needs: DCCONFIG,
        run: dc_005,
    },
    Rule {
        id: "AD-DC-006",
        needs: DCCONFIG,
        run: dc_006,
    },
    Rule {
        id: "AD-DC-007",
        needs: DCCONFIG,
        run: dc_007,
    },
    Rule {
        id: "AD-DC-009",
        needs: DCCONFIG,
        run: dc_009,
    },
    Rule {
        id: "AD-DC-010",
        needs: DCCONFIG,
        run: dc_010,
    },
    Rule {
        id: "AD-DC-011",
        needs: DCCONFIG,
        run: dc_011,
    },
    Rule {
        id: "AD-DC-012",
        needs: DCCONFIG,
        run: dc_012,
    },
    Rule {
        id: "AD-DC-013",
        needs: DCCONFIG,
        run: dc_013,
    },
    Rule {
        id: "AD-DC-014",
        needs: DCCONFIG,
        run: dc_014,
    },
    Rule {
        id: "AD-DC-015",
        needs: DCCONFIG,
        run: dc_015,
    },
    Rule {
        id: "AD-DC-016",
        needs: DCCONFIG,
        run: dc_016,
    },
    Rule {
        id: "AD-DC-017",
        needs: DCCONFIG,
        run: dc_017,
    },
    Rule {
        id: "AD-DC-018",
        needs: DCCONFIG,
        run: dc_018,
    },
    Rule {
        id: "AD-DC-019",
        needs: DCCONFIG,
        run: dc_019,
    },
    Rule {
        id: "AD-DC-020",
        needs: DCCONFIG,
        run: dc_020,
    },
    Rule {
        id: "AD-DC-021",
        needs: DCCONFIG,
        run: dc_021,
    },
    Rule {
        id: "AD-DC-022",
        needs: DCCONFIG,
        run: dc_022,
    },
    Rule {
        id: "AD-DC-023",
        needs: DCCONFIG,
        run: dc_023,
    },
    Rule {
        id: "AD-DC-024",
        needs: DCCONFIG,
        run: dc_024,
    },
    Rule {
        id: "AD-DC-025",
        needs: DCCONFIG,
        run: dc_025,
    },
    Rule {
        id: "AD-DC-028",
        needs: &["dcconfig", "domain"],
        run: dc_028,
    },
    Rule {
        id: "AD-DC-029",
        needs: DCCONFIG,
        run: dc_029,
    },
    Rule {
        id: "AD-DC-030",
        needs: DCCONFIG,
        run: dc_030,
    },
    Rule {
        id: "AD-LEG-001",
        needs: DCEVENTS,
        run: leg_001,
    },
    Rule {
        id: "AD-LEG-002",
        needs: DCEVENTS,
        run: leg_002,
    },
    Rule {
        id: "AD-LEG-003",
        needs: DCEVENTS,
        run: leg_003,
    },
    Rule {
        id: "AD-LEG-004",
        needs: DCEVENTS,
        run: leg_004,
    },
    Rule {
        id: "AD-LEG-005",
        needs: DCEVENTS,
        run: leg_005,
    },
    Rule {
        id: "AD-LEG-006",
        needs: DCEVENTS,
        run: leg_006,
    },
    Rule {
        id: "AD-LEG-007",
        needs: DCEVENTS,
        run: leg_007,
    },
    Rule {
        id: "AD-LEG-008",
        needs: DCEVENTS,
        run: leg_008,
    },
    Rule {
        id: "AD-LEG-009",
        needs: DCCONFIG,
        run: leg_009,
    },
    Rule {
        id: "AD-LEG-011",
        needs: DCCONFIG,
        run: leg_011,
    },
    Rule {
        id: "AD-LEG-012",
        needs: DCCONFIG,
        run: leg_012,
    },
    Rule {
        id: "AD-AUD-001",
        needs: DCCONFIG,
        run: aud_001,
    },
    Rule {
        id: "AD-AUD-002",
        needs: DCCONFIG,
        run: aud_002,
    },
    Rule {
        id: "AD-AUD-004",
        needs: DCCONFIG,
        run: aud_004,
    },
    Rule {
        id: "AD-AUD-006",
        needs: DCCONFIG,
        run: aud_006,
    },
    Rule {
        id: "AD-AUD-011",
        needs: DCEVENTS,
        run: aud_011,
    },
    Rule {
        id: "AD-REP-004",
        needs: DCCONFIG,
        run: rep_004,
    },
    Rule {
        id: "AD-REP-013",
        needs: DCCONFIG,
        run: rep_013,
    },
    Rule {
        id: "AD-DNS-011",
        needs: DCCONFIG,
        run: dns_011,
    },
    Rule {
        id: "AD-BKP-001",
        needs: &["domain"],
        run: bkp_001,
    },
    Rule {
        id: "AD-BKP-002",
        needs: &["domain", "dirservice"],
        run: bkp_002,
    },
];
