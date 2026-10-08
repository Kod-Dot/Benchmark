//! Defender XDR posture from Microsoft Graph and Intune: tamper protection,
//! network protection, antivirus exclusions, automated remediation, Cloud
//! Apps session control, Defender for Office 365 coverage, who can run
//! live response, the Secure Score trend and old incidents.

use std::collections::BTreeMap;

use serde_json::Value;

use super::model::{Tenant, J};
use super::rules::{read_from, tenant_item};
use super::rules_ca::policies;
use super::Rule;
use crate::ad::rules::{check, plural, Out};
use crate::results::{Affected, CheckResult};
use crate::time;

const SECURITY_ADMIN: &str = "194ae4cb-b126-40b2-bd5b-6091b380977d";
const GLOBAL_ADMIN: &str = "62e90394-69f5-4237-9190-012177145e10";
/// Incidents open longer than this many days are reported.
const INCIDENT_DAYS: i64 = 30;

fn out(t: &Tenant, id: &str) -> Out {
    check(id).evidence(
        "Read from",
        format!("{}; Microsoft Defender XDR", read_from(t)),
    )
}

fn device_name(t: &Tenant, id: &str) -> String {
    t.raw
        .list("intunedevices")
        .iter()
        .find(|d| d.s("id") == Some(id))
        .and_then(|d| d.s("deviceName"))
        .unwrap_or(id)
        .to_string()
}

fn def_002(t: &Tenant) -> CheckResult {
    let states = t.raw.list("intuneprotection");
    let list: Vec<Affected> = states
        .iter()
        .filter(|s| s.b("tamperProtectionEnabled") == Some(false))
        .map(|s| {
            t.object(
                "device",
                device_name(t, s.s("@dca.parent").unwrap_or_default()),
                None,
                "Tamper protection is off: malware with admin rights can turn Defender off",
            )
        })
        .collect();
    out(t, "M365-DEF-002")
        .expected("Tamper protection is on for every Windows device")
        .found(format!(
            "{} of {} without tamper protection",
            list.len(),
            plural(states.len(), "device", "devices")
        ))
        .affected(list, "devices")
        .evidence("Note", "Up to 300 Windows devices are read")
        .done()
}

/// Assigned Intune settings catalog policies, as lower-case text.
fn policy_text<'a>(t: &Tenant<'a>) -> Vec<(&'a str, String)> {
    t.raw
        .list("intunepolicies")
        .iter()
        .filter(|p| !p.a("assignments").is_empty())
        .map(|p| {
            (
                p.s("name").unwrap_or("Unnamed policy"),
                p.get("settings")
                    .map(Value::to_string)
                    .unwrap_or_default()
                    .to_lowercase(),
            )
        })
        .collect()
}

fn def_004(t: &Tenant) -> CheckResult {
    let all = policy_text(t);
    let block = all
        .iter()
        .any(|(_, s)| s.contains("defender_enablenetworkprotection_1"));
    let audit = all
        .iter()
        .any(|(_, s)| s.contains("defender_enablenetworkprotection_2"));
    let list = if block {
        Vec::new()
    } else if audit {
        vec![tenant_item(
            t,
            "Network protection is in audit mode: malicious sites and domains are only logged",
        )]
    } else {
        vec![tenant_item(t, "No policy turns on network protection: web protection and indicators do not block outside Edge")]
    };
    out(t, "M365-DEF-004")
        .expected(
            "Network protection is in block mode, so web protection covers every browser and app",
        )
        .found(if block {
            "Block mode"
        } else if audit {
            "Audit mode"
        } else {
            "Not configured"
        })
        .affected(list, "tenant")
        .done()
}

fn def_005(t: &Tenant) -> CheckResult {
    let alerts = t.raw.list("mdealerts");
    let mut by: BTreeMap<String, usize> = BTreeMap::new();
    for a in alerts {
        for e in a.a("evidence") {
            *by.entry(e.s("remediationStatus").unwrap_or("none").to_string())
                .or_default() += 1;
        }
    }
    let automatic = ["remediated", "prevented", "blocked"]
        .iter()
        .map(|k| by.get(*k).copied().unwrap_or(0))
        .sum::<usize>();
    let list = if alerts.len() >= 5 && automatic == 0 {
        vec![tenant_item(t, format!("{} Defender for Endpoint alerts in 30 days and no evidence remediated automatically: automated remediation looks off or waits for approval", alerts.len()))]
    } else {
        Vec::new()
    };
    out(t, "M365-DEF-005")
        .expected("Automated investigation and remediation fixes threats without waiting for approval")
        .found(format!("{}; {automatic} evidence items remediated automatically", plural(alerts.len(), "alert", "alerts")))
        .raw(by.iter().map(|(k, n)| format!("{k}: {n}")).collect::<Vec<_>>().join("\n"))
        .affected(list, "tenant")
        .evidence("Note", "Inferred from the remediation status of alert evidence; the automation level itself is not exposed by an API")
        .done()
}

fn licensed(t: &Tenant, prefixes: &[&str]) -> bool {
    t.raw
        .list("skus")
        .iter()
        .filter(|s| s.s("capabilityStatus") != Some("Suspended"))
        .flat_map(|s| s.a("servicePlans"))
        .filter_map(|p| p.s("servicePlanName"))
        .any(|n| prefixes.iter().any(|p| n.starts_with(p)))
}

fn def_007(t: &Tenant) -> CheckResult {
    let mcas = licensed(t, &["ADALLOM_S"]);
    let session: Vec<String> = policies(t)
        .iter()
        .filter(|p| {
            p.enabled()
                && p.0
                    .at(&["sessionControls", "cloudAppSecurity", "isEnabled"])
                    .and_then(Value::as_bool)
                    == Some(true)
        })
        .map(|p| p.name().to_string())
        .collect();
    let list = if mcas && session.is_empty() {
        vec![tenant_item(t, "Defender for Cloud Apps is licensed but no Conditional Access policy routes sessions through it")]
    } else {
        Vec::new()
    };
    out(t, "M365-DEF-007")
        .expected("Defender for Cloud Apps session control covers risky sessions")
        .found(if !mcas {
            "Defender for Cloud Apps is not licensed".to_string()
        } else if session.is_empty() {
            "No session control".to_string()
        } else {
            format!("Session control in {}", session.join(", "))
        })
        .affected(list, "tenant")
        .done()
}

fn def_008(t: &Tenant) -> CheckResult {
    let mdo = licensed(t, &["ATP_ENTERPRISE", "THREAT_INTELLIGENCE"]);
    let on = |area: &str| {
        t.raw
            .list(area)
            .iter()
            .any(|r| r.s("State") == Some("Enabled"))
    };
    let builtin = t.raw.list("exosafelinks").iter().any(|p| {
        p.b("IsBuiltInProtection") == Some(true) || p.s("IsBuiltInProtection") == Some("True")
    });
    let preset = on("exopreset");
    let mut missing = Vec::new();
    if !mdo {
        missing.push("Defender for Office 365 is not licensed".to_string());
    } else {
        if !on("exosafelinksrules") && !preset && !builtin {
            missing.push("No Safe Links policy is applied to users".to_string());
        }
        if !on("exosafeattachrules") && !preset && !builtin {
            missing.push("No Safe Attachments policy is applied to users".to_string());
        }
    }
    out(t, "M365-DEF-008")
        .expected(
            "Defender for Office 365 protects every mailbox with Safe Links and Safe Attachments",
        )
        .found(if mdo {
            format!("Licensed; {}", plural(missing.len(), "gap", "gaps"))
        } else {
            "Not licensed".to_string()
        })
        .affected(
            missing.into_iter().map(|m| tenant_item(t, m)).collect(),
            "settings",
        )
        .done()
}

/// Exclusion values in assigned policies, by kind.
fn exclusions(t: &Tenant) -> Vec<(String, &'static str, String)> {
    let mut out = Vec::new();
    for p in t
        .raw
        .list("intunepolicies")
        .iter()
        .filter(|p| !p.a("assignments").is_empty())
    {
        for s in p.a("settings") {
            let Some(inst) = s.o("settingInstance") else {
                continue;
            };
            let id = inst
                .s("settingDefinitionId")
                .unwrap_or_default()
                .to_lowercase();
            let kind = if id.ends_with("excludedpaths") {
                "path"
            } else if id.ends_with("excludedprocesses") {
                "process"
            } else if id.ends_with("excludedextensions") {
                "extension"
            } else {
                continue;
            };
            for v in inst.a("simpleSettingCollectionValue") {
                if let Some(x) = v.s("value") {
                    out.push((
                        p.s("name").unwrap_or("Unnamed policy").to_string(),
                        kind,
                        x.to_string(),
                    ));
                }
            }
        }
    }
    out
}

fn too_broad(kind: &str, v: &str) -> Option<&'static str> {
    let l = v.to_lowercase().replace('/', "\\");
    let l = l.trim_end_matches('\\');
    match kind {
        "extension"
            if [
                "exe", ".exe", "dll", ".dll", "ps1", ".ps1", "bat", ".bat", "js", ".js", "vbs",
                ".vbs", "*",
            ]
            .contains(&l) =>
        {
            Some("excludes an executable file type everywhere")
        }
        "process"
            if [
                "powershell.exe",
                "pwsh.exe",
                "cmd.exe",
                "rundll32.exe",
                "regsvr32.exe",
                "mshta.exe",
                "wscript.exe",
                "cscript.exe",
                "*",
            ]
            .contains(&l) =>
        {
            Some("excludes a process attackers use to run code")
        }
        "path"
            if l.len() <= 3
                || [
                    "c:\\windows",
                    "c:\\users",
                    "c:\\program files",
                    "c:\\programdata",
                    "%temp%",
                    "%appdata%",
                    "c:\\temp",
                    "c:\\windows\\temp",
                ]
                .contains(&l)
                || l.contains("\\appdata")
                || l.contains("\\downloads")
                || l.starts_with('*') =>
        {
            Some("excludes a folder where users or malware can write")
        }
        _ => None,
    }
}

fn def_009(t: &Tenant) -> CheckResult {
    let all = exclusions(t);
    let list: Vec<Affected> = all
        .iter()
        .filter_map(|(policy, kind, v)| {
            too_broad(kind, v).map(|why| {
                t.object(
                    "exclusion",
                    v,
                    Some(policy.clone()),
                    format!("Antivirus {kind} exclusion {why}"),
                )
            })
        })
        .collect();
    out(t, "M365-DEF-009")
        .expected("Antivirus exclusions are narrow: specific files and trusted folders only")
        .found(format!(
            "{}; {} too broad",
            plural(all.len(), "exclusion", "exclusions"),
            list.len()
        ))
        .affected(list, "exclusions")
        .done()
}

fn def_010(t: &Tenant) -> CheckResult {
    let mut seen = std::collections::BTreeSet::new();
    let list: Vec<Affected> = t
        .holders_of(SECURITY_ADMIN)
        .chain(t.holders_of(GLOBAL_ADMIN))
        .filter(|h| seen.insert(h.principal.clone()))
        .map(|h| t.affected(&h.principal, format!("{}: can run live response on every onboarded device unless Defender unified RBAC narrows it", t.role_name(&h.role))))
        .collect();
    out(t, "M365-DEF-010")
        .expected(
            "Live response is limited to a few named responders through Defender unified RBAC",
        )
        .found(
            plural(list.len(), "admin has", "admins have")
                + " live response through their Entra role",
        )
        .affected(list, "accounts")
        .done()
}

fn def_012(t: &Tenant) -> CheckResult {
    let mut scores: Vec<(&str, f64, f64)> = t
        .raw
        .list("securescores")
        .iter()
        .filter_map(|s| {
            Some((
                s.s("createdDateTime")?,
                s.get("currentScore")?.as_f64()?,
                s.get("maxScore")?.as_f64()?,
            ))
        })
        .collect();
    scores.sort_by(|a, b| a.0.cmp(b.0));
    let pct = |s: &(&str, f64, f64)| if s.2 > 0.0 { s.1 * 100.0 / s.2 } else { 0.0 };
    let found = match (scores.first(), scores.last()) {
        (Some(a), Some(b)) => format!(
            "{:.0}% on {}, {:.0}% on {}",
            pct(a),
            a.0.get(..10).unwrap_or(a.0),
            pct(b),
            b.0.get(..10).unwrap_or(b.0)
        ),
        _ => "No Secure Score history".to_string(),
    };
    out(t, "M365-DEF-012")
        .expected("Microsoft Secure Score is tracked and rising")
        .found(found)
        .raw(
            scores
                .iter()
                .map(|s| format!("{} {:.0}%", s.0.get(..10).unwrap_or(s.0), pct(s)))
                .collect::<Vec<_>>()
                .join("\n"),
        )
        .done()
}

fn def_013(t: &Tenant) -> CheckResult {
    let list: Vec<Affected> = t
        .raw
        .list("incidents")
        .iter()
        .filter_map(|i| {
            let created = time::parse_iso(i.s("createdDateTime")?)?;
            let days = t.days_since(Some(created))?;
            (days > INCIDENT_DAYS).then(|| {
                t.object(
                    "incident",
                    i.s("displayName").unwrap_or("Incident"),
                    i.s("severity").map(str::to_string),
                    format!(
                        "{} for {days} days, assigned to {}",
                        i.s("status").unwrap_or("open"),
                        i.s("assignedTo")
                            .filter(|a| !a.is_empty())
                            .unwrap_or("nobody")
                    ),
                )
                .seen_at(i.s("lastUpdateDateTime"))
            })
        })
        .collect();
    out(t, "M365-DEF-013")
        .expected(format!(
            "No incident stays open more than {INCIDENT_DAYS} days"
        ))
        .found(plural(list.len(), "incident", "incidents") + " open too long")
        .affected(list, "incidents")
        .done()
}

pub static RULES: &[Rule] = &[
    Rule {
        id: "M365-DEF-002",
        needs: &["intuneprotection", "intunedevices"],
        run: def_002,
    },
    Rule {
        id: "M365-DEF-004",
        needs: &["intunepolicies"],
        run: def_004,
    },
    Rule {
        id: "M365-DEF-005",
        needs: &["mdealerts"],
        run: def_005,
    },
    Rule {
        id: "M365-DEF-007",
        needs: &["skus", "capolicies"],
        run: def_007,
    },
    Rule {
        id: "M365-DEF-008",
        needs: &[
            "skus",
            "exosafelinks",
            "exosafelinksrules",
            "exosafeattachrules",
            "exopreset",
        ],
        run: def_008,
    },
    Rule {
        id: "M365-DEF-009",
        needs: &["intunepolicies"],
        run: def_009,
    },
    Rule {
        id: "M365-DEF-010",
        needs: &["roleassignments"],
        run: def_010,
    },
    Rule {
        id: "M365-DEF-012",
        needs: &["securescores"],
        run: def_012,
    },
    Rule {
        id: "M365-DEF-013",
        needs: &["incidents"],
        run: def_013,
    },
];
