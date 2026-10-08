//! Group Policy settings for domain controllers that the earlier GPO checks
//! do not cover: network logon rights, advanced audit policy, event log
//! size, firewall, protocol hardening, application control, software
//! installation, WMI filters, loopback processing and baseline drift, and
//! interactive logon of service accounts.

use std::collections::BTreeSet;

use super::model::{rdn_value, Kind, Model};
use super::raw::SysvolPolicy;
use super::rules::{check, item, plural, Rule};
use super::rules_gpo::{
    applies_to_dcs, expected_right_holder, gpo_item, gpo_name, not_read, principal, read_from,
    read_policies,
};
use crate::results::{Affected, CheckResult};

const MIN_SECURITY_LOG_KB: i64 = 196_608;

fn setting(name: &str, reason: impl Into<String>) -> Affected {
    Affected {
        last_seen: None,
        name: name.to_string(),
        kind: "setting".into(),
        location: None,
        reason: Some(reason.into()),
        object: None,
    }
}

fn dc_policies<'a>(m: &'a Model, policies: &[&'a SysvolPolicy]) -> Vec<&'a SysvolPolicy> {
    policies
        .iter()
        .copied()
        .filter(|p| applies_to_dcs(m, p))
        .collect()
}

/// The last value of a [Registry Values] entry ("4,1" gives 1).
fn inf_registry(p: &SysvolPolicy, key: &str) -> Option<i64> {
    p.inf_values("Registry Values", key)?
        .last()?
        .trim()
        .trim_matches('"')
        .parse()
        .ok()
}

/// A setting delivered either in GptTmpl.inf [Registry Values]
/// (MACHINE\<path>\<value>) or in Registry.pol (Machine, <path>, <value>),
/// from the first DC GPO that sets it.
fn dc_value(dc: &[&SysvolPolicy], path: &str, value: &str) -> Option<(i64, String)> {
    let inf_key = format!("MACHINE\\{path}\\{value}");
    dc.iter().find_map(|p| {
        inf_registry(p, &inf_key)
            .or_else(|| p.policy("Machine", path, value).and_then(|v| v.int()))
            .map(|v| (v, p.folder.clone()))
    })
}

// ---------- User rights ----------

fn gpo_010(m: &Model) -> CheckResult {
    let expected = "Only Administrators, Authenticated Users and Enterprise Domain Controllers can access DCs from the network";
    let policies = read_policies(m);
    if let Some(r) = not_read(check("AD-GPO-010").expected(expected), &policies) {
        return r;
    }
    let allowed = |sid: Option<&str>, name: &str| {
        matches!(sid, Some("S-1-5-11" | "S-1-5-9" | "S-1-5-32-544"))
            || (sid.is_some_and(|s| s != "S-1-1-0" && s != "S-1-5-32-554" && s != "S-1-5-7")
                && expected_right_holder(m, name, sid))
    };
    let mut list = Vec::new();
    for p in dc_policies(m, &policies) {
        let Some(values) = p.inf_values("Privilege Rights", "SeNetworkLogonRight") else {
            continue;
        };
        let extra: Vec<String> = values
            .iter()
            .filter(|v| !v.is_empty())
            .map(|v| principal(m, v))
            .filter(|(name, sid)| !allowed(sid.as_deref(), name))
            .map(|(name, _)| name)
            .collect();
        if !extra.is_empty() {
            list.push(gpo_item(
                m,
                p,
                format!(
                    "Access this computer from the network (SeNetworkLogonRight) also granted to {}",
                    extra.join(", ")
                ),
            ));
        }
    }
    check("AD-GPO-010")
        .expected(expected)
        .found(
            plural(list.len(), "GPO grants", "GPOs grant") + " network access to extra principals",
        )
        .affected(list, "GPOs")
        .evidence(
            "Read from",
            format!("GptTmpl.inf [Privilege Rights] in {}", read_from(m)),
        )
        .done()
}

fn svc_005(m: &Model) -> CheckResult {
    let expected =
        "Service accounts are denied interactive and Remote Desktop sign-in by Group Policy";
    let policies = read_policies(m);
    if let Some(r) = not_read(check("AD-SVC-005").expected(expected), &policies) {
        return r;
    }
    let mut denied: BTreeSet<usize> = BTreeSet::new();
    for p in &policies {
        for key in [
            "SeDenyInteractiveLogonRight",
            "SeDenyRemoteInteractiveLogonRight",
        ] {
            for v in p.inf_values("Privilege Rights", key).into_iter().flatten() {
                let (_, sid) = principal(m, v);
                if let Some(i) = sid.as_deref().and_then(|s| m.by_sid(s)) {
                    denied.insert(i);
                    denied.extend(m.recursive_members(i));
                }
            }
        }
    }
    let list: Vec<Affected> = (0..m.nodes.len())
        .filter(|&i| {
            let n = &m.nodes[i];
            n.kind == Kind::User
                && n.enabled()
                && !super::rules::is_krbtgt(m, i)
                && !n.spns().is_empty()
        })
        .filter(|i| !denied.contains(i))
        .map(|i| {
            item(
                m,
                i,
                "A service account no GPO denies interactive or Remote Desktop sign-in: its password can be used to sign in to servers",
            )
        })
        .collect();
    check("AD-SVC-005")
        .expected(expected)
        .found(
            plural(list.len(), "service account", "service accounts")
                + " can sign in interactively",
        )
        .affected(list, "accounts")
        .evidence(
            "Read from",
            format!("GptTmpl.inf deny logon rights in {}", read_from(m)),
        )
        .done()
}

// ---------- Audit and logging ----------

/// (subcategory, GUID, required bits: 1 success, 2 failure).
const AUDIT_BASELINE: [(&str, &str, i64); 14] = [
    ("Credential Validation", "0cce923f", 3),
    ("Kerberos Authentication Service", "0cce9242", 3),
    ("Kerberos Service Ticket Operations", "0cce9240", 3),
    ("Computer Account Management", "0cce9236", 1),
    ("Security Group Management", "0cce9237", 1),
    ("User Account Management", "0cce9235", 3),
    ("Directory Service Access", "0cce923b", 2),
    ("Directory Service Changes", "0cce923c", 1),
    ("Logon", "0cce9215", 3),
    ("Special Logon", "0cce921b", 1),
    ("Process Creation", "0cce922b", 1),
    ("Audit Policy Change", "0cce922f", 1),
    ("Sensitive Privilege Use", "0cce9228", 3),
    ("Security System Extension", "0cce9211", 1),
];

fn bits_text(v: i64) -> &'static str {
    match v & 3 {
        0 => "no auditing",
        1 => "success",
        2 => "failure",
        _ => "success and failure",
    }
}

fn gpo_012(m: &Model) -> CheckResult {
    let expected = "GPOs that apply to DCs set the recommended advanced audit policy subcategories";
    let policies = read_policies(m);
    if let Some(r) = not_read(check("AD-GPO-012").expected(expected), &policies) {
        return r;
    }
    let dc = dc_policies(m, &policies);
    // A subcategory is covered by the union of what the DC GPOs set.
    let set = |prefix: &str| {
        dc.iter()
            .flat_map(|p| p.audit.iter().flatten())
            .filter(|a| a.guid.to_ascii_lowercase().starts_with(prefix))
            .fold(0, |acc, a| acc | a.value)
    };
    let list: Vec<Affected> = AUDIT_BASELINE
        .iter()
        .filter_map(|(name, guid, need)| {
            let have = set(guid);
            (have & need != *need).then(|| {
                setting(
                    name,
                    format!(
                        "Set to {} by DC GPOs; recommended: {}",
                        bits_text(have),
                        bits_text(*need)
                    ),
                )
            })
        })
        .collect();
    let any_audit = dc
        .iter()
        .any(|p| p.audit.as_ref().is_some_and(|a| !a.is_empty()));
    check("AD-GPO-012")
        .expected(expected)
        .found(if any_audit {
            plural(list.len(), "subcategory is", "subcategories are") + " below the recommendation"
        } else {
            "No GPO that applies to DCs sets an advanced audit policy".to_string()
        })
        .affected(list, "subcategories")
        .evidence("Read from", format!("audit.csv in {}", read_from(m)))
        .done()
}

fn gpo_013(m: &Model) -> CheckResult {
    let expected = format!(
        "The Security event log on DCs is at least {} MB",
        MIN_SECURITY_LOG_KB / 1024
    );
    let policies = read_policies(m);
    if let Some(r) = not_read(check("AD-GPO-013").expected(expected.clone()), &policies) {
        return r;
    }
    let dc = dc_policies(m, &policies);
    let size = dc.iter().find_map(|p| {
        p.inf_values("Security Log", "MaximumLogSize")
            .and_then(|v| v.first())
            .and_then(|v| v.trim().parse::<i64>().ok())
            .or_else(|| {
                p.policy(
                    "Machine",
                    "Software\\Policies\\Microsoft\\Windows\\EventLog\\Security",
                    "MaxSize",
                )
                .and_then(|v| v.int())
            })
            .map(|kb| (kb, gpo_name(m, p)))
    });
    let list = match &size {
        Some((kb, _)) if *kb >= MIN_SECURITY_LOG_KB => Vec::new(),
        Some((kb, gpo)) => vec![setting(
            "Security log size",
            format!("{} MB set by {gpo}: events from an attack are overwritten within hours", kb / 1024),
        )],
        None => vec![setting(
            "Security log size",
            "Not set by any GPO that applies to DCs: the default (128 MB) overwrites events quickly",
        )],
    };
    check("AD-GPO-013")
        .expected(expected)
        .found(match &size {
            Some((kb, gpo)) => format!("{} MB, set by {gpo}", kb / 1024),
            None => "Not set by Group Policy".into(),
        })
        .affected(list, "settings")
        .evidence(
            "Read from",
            format!(
                "GptTmpl.inf [Security Log] and Registry.pol in {}",
                read_from(m)
            ),
        )
        .done()
}

// ---------- Firewall and protocol hardening ----------

fn gpo_016(m: &Model) -> CheckResult {
    let expected = "Group Policy turns on Windows Firewall on DCs for every profile";
    let policies = read_policies(m);
    if let Some(r) = not_read(check("AD-GPO-016").expected(expected), &policies) {
        return r;
    }
    let dc = dc_policies(m, &policies);
    let mut list = Vec::new();
    for profile in ["DomainProfile", "PrivateProfile", "PublicProfile"] {
        let path = format!("Software\\Policies\\Microsoft\\WindowsFirewall\\{profile}");
        let values: Vec<(i64, &SysvolPolicy)> = dc
            .iter()
            .filter_map(|p| {
                p.policy("Machine", &path, "EnableFirewall")
                    .and_then(|v| v.int())
                    .map(|v| (v, *p))
            })
            .collect();
        if let Some((_, p)) = values.iter().find(|(v, _)| *v == 0) {
            list.push(gpo_item(
                m,
                p,
                format!("Turns the firewall off for the {profile}"),
            ));
        } else if values.is_empty() {
            list.push(setting(
                profile,
                "No GPO that applies to DCs turns the firewall on for this profile",
            ));
        }
    }
    check("AD-GPO-016")
        .expected(expected)
        .found(plural(list.len(), "firewall profile is", "firewall profiles are") + " not enforced")
        .affected(list, "profiles")
        .evidence(
            "Read from",
            format!("Registry.pol WindowsFirewall policies in {}", read_from(m)),
        )
        .done()
}

/// (label, registry path under HKLM, value, minimum).
const HARDENING: [(&str, &str, &str, i64); 4] = [
    (
        "SMB signing required (server)",
        "System\\CurrentControlSet\\Services\\LanManServer\\Parameters",
        "RequireSecuritySignature",
        1,
    ),
    (
        "LDAP signing required",
        "System\\CurrentControlSet\\Services\\NTDS\\Parameters",
        "LDAPServerIntegrity",
        2,
    ),
    (
        "LDAP channel binding enforced",
        "System\\CurrentControlSet\\Services\\NTDS\\Parameters",
        "LdapEnforceChannelBinding",
        2,
    ),
    (
        "NTLMv2 only (LAN Manager authentication level)",
        "System\\CurrentControlSet\\Control\\Lsa",
        "LmCompatibilityLevel",
        5,
    ),
];

fn gpo_017(m: &Model) -> CheckResult {
    let expected = "SMB signing, LDAP signing and channel binding, and NTLMv2-only are enforced on DCs by Group Policy, not only in the local registry";
    let policies = read_policies(m);
    if let Some(r) = not_read(check("AD-GPO-017").expected(expected), &policies) {
        return r;
    }
    let dc = dc_policies(m, &policies);
    let list: Vec<Affected> = HARDENING
        .iter()
        .filter_map(|(label, path, value, min)| match dc_value(&dc, path, value) {
            Some((v, _)) if v >= *min => None,
            Some((v, folder)) => Some(setting(label, format!("{value} is {v} in {folder}; needs {min}"))),
            None => Some(setting(
                label,
                format!("{value} is not set by any GPO that applies to DCs: a local change or a rebuilt DC loses it"),
            )),
        })
        .collect();
    check("AD-GPO-017")
        .expected(expected)
        .found(plural(list.len(), "setting is", "settings are") + " not enforced by Group Policy")
        .affected(list, "settings")
        .evidence(
            "Read from",
            format!(
                "GptTmpl.inf [Registry Values] and Registry.pol in {}",
                read_from(m)
            ),
        )
        .done()
}

// ---------- Inventory ----------

fn gpo_020(m: &Model) -> CheckResult {
    let policies = read_policies(m);
    let expected =
        "An inventory of AppLocker and WDAC (App Control) policies delivered by Group Policy";
    if let Some(r) = not_read(check("AD-GPO-020").expected(expected), &policies) {
        return r;
    }
    let mut lines = Vec::new();
    for p in &policies {
        let reg = p.registry.iter().flatten();
        let applocker: BTreeSet<String> = reg
            .clone()
            .filter_map(|v| {
                let k = v.key.to_ascii_lowercase();
                k.strip_prefix("software\\policies\\microsoft\\windows\\srpv2\\")
                    .map(|rest| rest.split('\\').next().unwrap_or(rest).to_string())
            })
            .collect();
        if !applocker.is_empty() {
            lines.push(format!(
                "AppLocker in {}: {}",
                gpo_name(m, p),
                applocker.into_iter().collect::<Vec<_>>().join(", ")
            ));
        }
        if reg.clone().any(|v| {
            v.key.to_ascii_lowercase().ends_with("windows\\deviceguard")
                && v.value.eq_ignore_ascii_case("DeployConfigCIPolicy")
                && v.int() == Some(1)
        }) {
            lines.push(format!("WDAC (App Control) in {}", gpo_name(m, p)));
        }
    }
    check("AD-GPO-020")
        .expected(expected)
        .found(if lines.is_empty() {
            "No GPO delivers AppLocker or WDAC policies".to_string()
        } else {
            plural(
                lines.len(),
                "application control policy",
                "application control policies",
            )
        })
        .raw(lines.join("\n"))
        .evidence("Read from", format!("Registry.pol in {}", read_from(m)))
        .done()
}

fn gpo_021(m: &Model) -> CheckResult {
    let sysvol = format!("\\\\{}\\sysvol\\", m.dns.to_ascii_lowercase());
    let netlogon = format!("\\\\{}\\netlogon\\", m.dns.to_ascii_lowercase());
    let packages = m.raw.objects("gpsoftware");
    let list: Vec<Affected> = packages
        .iter()
        .filter_map(|o| {
            let paths: Vec<String> = o
                .strs("msifilelist")
                .iter()
                .map(|p| p.split_once(':').map(|(_, x)| x).unwrap_or(p).to_string())
                .filter(|p| {
                    let l = p.to_ascii_lowercase();
                    !l.starts_with(&sysvol) && !l.starts_with(&netlogon)
                })
                .collect();
            let gpo = o
                .dn()
                .split(',')
                .find(|p| p.to_ascii_uppercase().starts_with("CN={"))
                .map(rdn_value)
                .unwrap_or_default();
            (!paths.is_empty()).then(|| Affected {
                last_seen: None,
                name: o.str("displayname").map(str::to_string).unwrap_or_else(|| rdn_value(o.dn())),
                kind: "package".into(),
                location: Some(o.dn().to_string()),
                reason: Some(format!(
                    "Installed by GPO {gpo} from {}: anyone who can write there runs code as SYSTEM on every target; confirm only admins can",
                    paths.join(", ")
                )),
                object: None,
            })
        })
        .collect();
    check("AD-GPO-021")
        .expected("GPO software packages install from shares only admins can write to")
        .found(format!(
            "{}; {} from shares to review",
            plural(packages.len(), "package", "packages"),
            list.len()
        ))
        .affected(list, "packages")
        .evidence(
            "Read from",
            format!(
                "packageRegistration objects via LDAP on {}",
                m.raw.info.server
            ),
        )
        .done()
}

fn gpo_024(m: &Model) -> CheckResult {
    let filters = m.raw.objects("wmifilters");
    let ids: BTreeSet<String> = filters
        .iter()
        .filter_map(|f| {
            f.str("mswmi-id")
                .map(|s| s.trim_matches(['{', '}']).to_ascii_lowercase())
        })
        .collect();
    let inventory: Vec<String> = filters
        .iter()
        .map(|f| {
            format!(
                "{}: {}",
                f.str("mswmi-name").unwrap_or_default(),
                f.str("mswmi-parm2").unwrap_or_default()
            )
        })
        .collect();
    // gPCWQLFilter: [domain;{GUID};0]
    let list: Vec<Affected> = (0..m.nodes.len())
        .filter(|&i| m.nodes[i].kind == Kind::Gpo)
        .filter_map(|i| {
            let f = m.nodes[i].attrs.str("gpcwqlfilter")?;
            let id = f.split(';').nth(1)?.trim_matches(['{', '}']).to_ascii_lowercase();
            (!ids.contains(&id)).then(|| {
                item(
                    m,
                    i,
                    format!("Uses WMI filter {{{id}}}, which does not exist: the GPO does not apply anywhere"),
                )
            })
        })
        .collect();
    check("AD-GPO-024")
        .expected("Every WMI filter a GPO uses exists")
        .found(format!(
            "{}; {} broken",
            plural(filters.len(), "WMI filter", "WMI filters"),
            plural(list.len(), "GPO reference", "GPO references")
        ))
        .affected(list, "GPOs")
        .raw(inventory.join("\n"))
        .evidence(
            "Read from",
            format!(
                "msWMI-Som objects and gPCWQLFilter via LDAP on {}",
                m.raw.info.server
            ),
        )
        .done()
}

fn gpo_025(m: &Model) -> CheckResult {
    let policies = read_policies(m);
    let expected = "An inventory of GPOs that turn on loopback processing";
    if let Some(r) = not_read(check("AD-GPO-025").expected(expected), &policies) {
        return r;
    }
    let lines: Vec<String> = policies
        .iter()
        .filter_map(|p| {
            let v = p
                .policy(
                    "Machine",
                    "Software\\Policies\\Microsoft\\Windows\\System",
                    "UserPolicyMode",
                )?
                .int()?;
            let mode = match v {
                1 => "merge",
                2 => "replace",
                _ => return None,
            };
            Some(format!("{}: loopback {mode}", gpo_name(m, p)))
        })
        .collect();
    check("AD-GPO-025")
        .expected(expected)
        .found(plural(lines.len(), "GPO uses", "GPOs use") + " loopback processing")
        .raw(lines.join("\n"))
        .evidence("Read from", format!("Registry.pol in {}", read_from(m)))
        .done()
}

/// Microsoft security baseline values for domain controllers that GPOs
/// set in GptTmpl.inf [Registry Values]: (label, path, value, expected).
const BASELINE: [(&str, &str, &str, i64); 8] = [
    (
        "LAN Manager authentication level",
        "System\\CurrentControlSet\\Control\\Lsa",
        "LmCompatibilityLevel",
        5,
    ),
    (
        "Do not store LAN Manager hash",
        "System\\CurrentControlSet\\Control\\Lsa",
        "NoLMHash",
        1,
    ),
    (
        "Restrict anonymous enumeration of SAM accounts",
        "System\\CurrentControlSet\\Control\\Lsa",
        "RestrictAnonymousSAM",
        1,
    ),
    (
        "Restrict anonymous enumeration of shares",
        "System\\CurrentControlSet\\Control\\Lsa",
        "RestrictAnonymous",
        1,
    ),
    (
        "Server SMB signing required",
        "System\\CurrentControlSet\\Services\\LanManServer\\Parameters",
        "RequireSecuritySignature",
        1,
    ),
    (
        "Client SMB signing required",
        "System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters",
        "RequireSecuritySignature",
        1,
    ),
    (
        "LDAP server signing required",
        "System\\CurrentControlSet\\Services\\NTDS\\Parameters",
        "LDAPServerIntegrity",
        2,
    ),
    (
        "User Account Control on",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        "EnableLUA",
        1,
    ),
];

fn gpo_030(m: &Model) -> CheckResult {
    let expected =
        "GPOs that apply to DCs match the Microsoft security baseline for these settings";
    let policies = read_policies(m);
    if let Some(r) = not_read(check("AD-GPO-030").expected(expected), &policies) {
        return r;
    }
    let dc = dc_policies(m, &policies);
    let mut lines = Vec::new();
    let list: Vec<Affected> = BASELINE
        .iter()
        .filter_map(|(label, path, value, want)| {
            let got = dc_value(&dc, path, value);
            lines.push(format!(
                "{label}: {} (baseline {want})",
                got.as_ref()
                    .map(|(v, _)| v.to_string())
                    .unwrap_or_else(|| "not set".into())
            ));
            match got {
                Some((v, _)) if v == *want => None,
                Some((v, folder)) => Some(setting(
                    label,
                    format!("{value} is {v} in {folder}; the baseline is {want}"),
                )),
                None => Some(setting(
                    label,
                    format!(
                        "{value} is not set by a GPO that applies to DCs; the baseline is {want}"
                    ),
                )),
            }
        })
        .collect();
    check("AD-GPO-030")
        .expected(expected)
        .found(format!(
            "{} of {} differ from the baseline",
            list.len(),
            plural(BASELINE.len(), "setting", "settings")
        ))
        .affected(list, "settings")
        .raw(lines.join("\n"))
        .evidence(
            "Read from",
            format!(
                "GptTmpl.inf [Registry Values] and Registry.pol in {}",
                read_from(m)
            ),
        )
        .done()
}

const SYSVOL: &[&str] = &["domain", "containers", "gpos", "sysvol"];

pub static RULES: &[Rule] = &[
    Rule {
        id: "AD-GPO-010",
        needs: &["domain", "containers", "gpos", "groups", "sysvol"],
        run: gpo_010,
    },
    Rule {
        id: "AD-SVC-005",
        needs: &["domain", "users", "groups", "gpos", "sysvol"],
        run: svc_005,
    },
    Rule {
        id: "AD-GPO-012",
        needs: SYSVOL,
        run: gpo_012,
    },
    Rule {
        id: "AD-GPO-013",
        needs: SYSVOL,
        run: gpo_013,
    },
    Rule {
        id: "AD-GPO-016",
        needs: SYSVOL,
        run: gpo_016,
    },
    Rule {
        id: "AD-GPO-017",
        needs: SYSVOL,
        run: gpo_017,
    },
    Rule {
        id: "AD-GPO-020",
        needs: &["gpos", "sysvol"],
        run: gpo_020,
    },
    Rule {
        id: "AD-GPO-021",
        needs: &["gpsoftware"],
        run: gpo_021,
    },
    Rule {
        id: "AD-GPO-024",
        needs: &["gpos", "wmifilters"],
        run: gpo_024,
    },
    Rule {
        id: "AD-GPO-025",
        needs: &["gpos", "sysvol"],
        run: gpo_025,
    },
    Rule {
        id: "AD-GPO-030",
        needs: SYSVOL,
        run: gpo_030,
    },
];
