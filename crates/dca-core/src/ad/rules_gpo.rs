//! Group Policy content: what each GPO in SYSVOL actually sets (security
//! template, Registry.pol, scripts, preferences), who can change it, and
//! where it applies.

use std::collections::{BTreeMap, BTreeSet};

use super::model::{rdn_value, well_known_name, Kind, Model};
use super::raw::SysvolPolicy;
use super::rules::{check, item, plural, Rule};
use super::sd::{right, AceType};
use crate::results::{Affected, CheckResult};

const DDP: &str = "{31b2f340-016d-11d2-945f-00c04fb984f9}";
const DDCP: &str = "{6ac1786c-016f-11d2-945f-00c04fb984f9}";

const READ_PROP: u32 = 0x10;
const GENERIC_READ: u32 = 0x8000_0000;

/// User rights that are as good as admin on a DC.
const SENSITIVE_RIGHTS: &[(&str, &str)] = &[
    ("SeDebugPrivilege", "Debug programs"),
    ("SeBackupPrivilege", "Back up files and directories"),
    ("SeRestorePrivilege", "Restore files and directories"),
    ("SeTcbPrivilege", "Act as part of the operating system"),
    (
        "SeImpersonatePrivilege",
        "Impersonate a client after authentication",
    ),
    ("SeLoadDriverPrivilege", "Load and unload device drivers"),
    (
        "SeEnableDelegationPrivilege",
        "Enable accounts to be trusted for delegation",
    ),
    (
        "SeTakeOwnershipPrivilege",
        "Take ownership of files or other objects",
    ),
];

const LOGON_RIGHTS: &[(&str, &str)] = &[
    ("SeInteractiveLogonRight", "Allow log on locally"),
    (
        "SeRemoteInteractiveLogonRight",
        "Allow log on through Remote Desktop Services",
    ),
];

pub(super) fn read_from(m: &Model) -> String {
    format!("\\\\{}\\SYSVOL\\{}\\Policies", m.dns, m.dns)
}

fn ldap_from(m: &Model) -> String {
    format!("LDAP on {} as {}", m.raw.info.server, m.raw.info.account)
}

/// The GPO node of a SYSVOL folder.
pub(super) fn gpo_of(m: &Model, p: &SysvolPolicy) -> Option<usize> {
    (0..m.nodes.len()).find(|&i| {
        m.nodes[i].kind == Kind::Gpo && rdn_value(&m.nodes[i].dn).eq_ignore_ascii_case(&p.folder)
    })
}

pub(super) fn gpo_name(m: &Model, p: &SysvolPolicy) -> String {
    gpo_of(m, p)
        .map(|g| m.nodes[g].name.clone())
        .unwrap_or_else(|| p.folder.clone())
}

pub(super) fn gpo_item(m: &Model, p: &SysvolPolicy, reason: impl Into<String>) -> Affected {
    match gpo_of(m, p) {
        Some(g) => item(m, g, reason),
        None => Affected {
            last_seen: None,
            name: p.folder.clone(),
            kind: "gpo".into(),
            location: Some(format!("{}\\{}", read_from(m), p.folder)),
            reason: Some(reason.into()),
            object: None,
        },
    }
}

fn dc_ou(m: &Model) -> Option<usize> {
    (0..m.nodes.len()).find(|&i| {
        m.nodes[i].kind == Kind::Ou
            && m.nodes[i]
                .dn
                .to_ascii_lowercase()
                .starts_with("ou=domain controllers,")
    })
}

/// Where a GPO is linked (enabled links only).
pub(super) fn links(m: &Model, p: &SysvolPolicy) -> Vec<usize> {
    gpo_of(m, p)
        .and_then(|g| m.gpo_links.get(&g))
        .cloned()
        .unwrap_or_default()
}

/// Linked to the Domain Controllers OU or the domain head.
pub(super) fn applies_to_dcs(m: &Model, p: &SysvolPolicy) -> bool {
    let ou = dc_ou(m);
    links(m, p)
        .iter()
        .any(|&h| Some(h) == ou || Some(h) == m.domain)
}

/// Linked anywhere other than the Domain Controllers OU.
fn applies_to_members(m: &Model, p: &SysvolPolicy) -> bool {
    let ou = dc_ou(m);
    links(m, p).iter().any(|&h| Some(h) != ou)
}

/// Policies whose content was read (collected by this version).
pub(super) fn read_policies<'a>(m: &'a Model) -> Vec<&'a SysvolPolicy> {
    m.raw.sysvol.iter().filter(|p| p.files.is_some()).collect()
}

pub(super) const OLD_COLLECTOR: &str =
    "GPO content was not collected; collect SYSVOL again with this version.";

/// A principal named in a security template or preference: "*S-1-5-32-544",
/// "CORP\name" or "name". Returns (display name, SID if known).
pub(super) fn principal(m: &Model, raw: &str) -> (String, Option<String>) {
    let v = raw.trim().trim_matches('"');
    if let Some(sid) = v.strip_prefix('*') {
        let name = m
            .by_sid(sid)
            .map(|i| m.nodes[i].name.clone())
            .or_else(|| well_known_name(sid).map(str::to_string))
            .unwrap_or_else(|| sid.to_string());
        return (name, Some(sid.to_string()));
    }
    let account = v.rsplit('\\').next().unwrap_or(v);
    let found = m.nodes.iter().find(|n| {
        matches!(n.kind, Kind::User | Kind::Group | Kind::Computer)
            && n.name.eq_ignore_ascii_case(account)
    });
    (v.to_string(), found.and_then(|n| n.sid.clone()))
}

/// Accounts expected to hold user rights on a DC by default.
pub(super) fn expected_right_holder(m: &Model, name: &str, sid: Option<&str>) -> bool {
    if let Some(sid) = sid {
        return m.is_default_admin(sid)
            || m.by_sid(sid).is_some_and(|i| m.nodes[i].tier0)
            || matches!(
                sid,
                "S-1-5-19"
                    | "S-1-5-20"
                    | "S-1-5-6"
                    | "S-1-5-32-568"
                    | "S-1-5-90-0"
                    | "S-1-5-32-559"
            )
            || sid.starts_with("S-1-5-80-")
            || sid.starts_with("S-1-5-82-");
    }
    let n = name
        .rsplit('\\')
        .next()
        .unwrap_or(name)
        .to_ascii_lowercase();
    matches!(
        n.as_str(),
        "administrators"
            | "local service"
            | "network service"
            | "service"
            | "iis_iusrs"
            | "backup operators"
            | "server operators"
            | "print operators"
            | "account operators"
            | "enterprise domain controllers"
            | "domain admins"
            | "enterprise admins"
    )
}

fn broad(m: &Model, sid: &str) -> bool {
    matches!(
        sid,
        "S-1-1-0" | "S-1-5-11" | "S-1-5-7" | "S-1-5-4" | "S-1-5-32-545"
    ) || sid
        .strip_prefix(&m.domain_sid)
        .is_some_and(|r| r == "-513" || r == "-515")
}

pub(super) fn not_read(out: super::rules::Out, policies: &[&SysvolPolicy]) -> Option<CheckResult> {
    policies
        .is_empty()
        .then(|| out.not_assessed(OLD_COLLECTOR).done())
}

// ---------- Inventory ----------

fn gpo_001(m: &Model) -> CheckResult {
    let mut list = Vec::new();
    let mut total = 0;
    for g in (0..m.nodes.len()).filter(|&i| m.nodes[i].kind == Kind::Gpo) {
        total += 1;
        let a = &m.nodes[g].attrs;
        let mut why = Vec::new();
        if m.gpo_links.get(&g).is_none_or(|l| l.is_empty()) {
            why.push("not linked anywhere");
        }
        if a.int("versionnumber") == Some(0) {
            why.push("empty (never edited)");
        }
        if a.int("flags") == Some(3) {
            why.push("all settings disabled");
        }
        if !why.is_empty() {
            list.push(item(m, g, why.join("; ")));
        }
    }
    check("AD-GPO-001")
        .expected("Every GPO is linked, has settings and is enabled")
        .found(format!(
            "{} of {} unlinked, empty or disabled",
            list.len(),
            plural(total, "GPO", "GPOs")
        ))
        .affected(list, "GPOs")
        .evidence(
            "Read from",
            format!("gPLink, versionNumber and flags via {}", ldap_from(m)),
        )
        .done()
}

fn gpo_026(m: &Model) -> CheckResult {
    let mut list = Vec::new();
    let mut enforced = Vec::new();
    for i in (0..m.nodes.len()).filter(|&i| matches!(m.nodes[i].kind, Kind::Ou | Kind::Domain)) {
        let a = &m.nodes[i].attrs;
        if a.int("gpoptions") == Some(1) {
            list.push(item(m, i, "Blocks inheritance: domain-level GPOs (security baselines included) do not apply here unless enforced"));
        }
        if let Some(link) = a.str("gplink") {
            let n = link
                .split('[')
                .filter(|p| p.trim_end_matches(']').ends_with(";2"))
                .count();
            if n > 0 {
                enforced.push(format!("{} ({})", m.nodes[i].name, n));
            }
        }
    }
    let mut out = check("AD-GPO-026")
        .expected("No OU blocks inheritance, so domain-wide security policy applies everywhere")
        .found(plural(list.len(), "OU blocks", "OUs block") + " inheritance")
        .affected(list, "OUs");
    if !enforced.is_empty() {
        out = out.evidence("Enforced links", enforced.join(", "));
    }
    out.evidence(
        "Read from",
        format!("gPOptions and gPLink via {}", ldap_from(m)),
    )
    .done()
}

// ---------- Who can change GPOs ----------

fn gpo_005(m: &Model) -> CheckResult {
    let mut by: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for h in &m.raw.scripts {
        by.entry(h.file.as_str()).or_default().push(format!(
            "line {} ({})",
            h.line,
            h.pattern.replace('_', " ")
        ));
    }
    let list: Vec<Affected> = by
        .into_iter()
        .map(|(file, hits)| Affected {
            last_seen: None,
            name: file.rsplit('\\').next().unwrap_or(file).to_string(),
            kind: "file".into(),
            location: Some(match file.strip_prefix("Policies") {
                Some(rest) => format!("{}{rest}", read_from(m)),
                None => format!("\\\\{}\\{}", m.dns, file.trim_start_matches('\\')),
            }),
            reason: Some(format!(
                "Looks like it holds a credential: {}",
                hits.join(", ")
            )),
            object: None,
        })
        .collect();
    check("AD-GPO-005")
        .expected("No script in NETLOGON or policy folders holds a password")
        .found(plural(list.len(), "script looks", "scripts look") + " like they hold credentials")
        .affected(list, "files")
        .evidence(
            "Note",
            "Only the file, line number and pattern are collected, never the line itself",
        )
        .evidence(
            "Read from",
            format!("\\\\{}\\NETLOGON and policy Scripts folders", m.dns),
        )
        .done()
}

fn gpo_006(m: &Model) -> CheckResult {
    let out = check("AD-GPO-006").expected("Only admins can write to GPO folders in SYSVOL");
    let policies: Vec<&SysvolPolicy> = read_policies(m)
        .into_iter()
        .filter(|p| p.acl.is_some())
        .collect();
    if let Some(r) = not_read(out, &policies) {
        return r;
    }
    let out = check("AD-GPO-006").expected("Only admins can write to GPO folders in SYSVOL");
    let mut list = Vec::new();
    for p in &policies {
        let acl = p.acl.as_ref().unwrap();
        let mut who: BTreeSet<String> = BTreeSet::new();
        if let Some(o) = acl
            .owner_sid
            .as_deref()
            .filter(|s| !expected_right_holder(m, "", Some(s)))
        {
            who.insert(format!("{} (owner)", acl.owner.as_deref().unwrap_or(o)));
        }
        for w in &acl.writers {
            let ok = match w.sid.as_deref() {
                Some(s) => {
                    m.is_default_admin(s)
                        || m.by_sid(s).is_some_and(|i| m.nodes[i].tier0)
                        || s == "S-1-3-0"
                }
                None => expected_right_holder(m, &w.identity, None),
            };
            if !ok {
                who.insert(format!("{}: {}", w.identity, w.rights));
            }
        }
        if !who.is_empty() {
            list.push(gpo_item(
                m,
                p,
                format!(
                    "Writable by {}",
                    who.into_iter().collect::<Vec<_>>().join("; ")
                ),
            ));
        }
    }
    out.found(plural(list.len(), "GPO folder is", "GPO folders are") + " writable by non-admins")
        .affected(list, "GPOs")
        .evidence("Read from", format!("NTFS permissions of {}", read_from(m)))
        .done()
}

fn gpo_007(m: &Model) -> CheckResult {
    let mut list = Vec::new();
    for g in (0..m.nodes.len()).filter(|&i| m.nodes[i].kind == Kind::Gpo) {
        let Some(sd) = m.sds.get(&g) else { continue };
        let mut who: BTreeSet<String> = BTreeSet::new();
        for a in sd
            .dacl
            .iter()
            .filter(|a| a.kind == AceType::Allow && !a.inherit_only())
        {
            if m.is_default_admin(&a.sid) || m.by_sid(&a.sid).is_some_and(|i| m.nodes[i].tier0) {
                continue;
            }
            let r = if a.mask & right::GENERIC_ALL != 0
                || a.mask & right::FULL_CONTROL == right::FULL_CONTROL
            {
                "Full control"
            } else if a.mask & right::WRITE_DACL != 0 {
                "Modify permissions"
            } else if a.mask & right::WRITE_OWNER != 0 {
                "Take ownership"
            } else if a.mask & right::GENERIC_WRITE != 0
                || (a.mask & right::WRITE_PROP != 0 && a.object_type.is_none())
            {
                "Edit settings"
            } else {
                continue;
            };
            let name = m
                .by_sid(&a.sid)
                .map(|i| m.nodes[i].name.clone())
                .or_else(|| well_known_name(&a.sid).map(str::to_string))
                .unwrap_or_else(|| a.sid.clone());
            who.insert(format!("{name}: {r}"));
        }
        if !who.is_empty() {
            list.push(item(m, g, who.into_iter().collect::<Vec<_>>().join("; ")));
        }
    }
    check("AD-GPO-007")
        .expected("Only admins can edit GPOs")
        .found(plural(list.len(), "GPO is", "GPOs are") + " editable by non-admins")
        .affected(list, "GPOs")
        .evidence(
            "Read from",
            format!("nTSecurityDescriptor of GPOs via {}", ldap_from(m)),
        )
        .done()
}

fn gpo_028(m: &Model) -> CheckResult {
    let list: Vec<Affected> = (0..m.nodes.len())
        .filter(|&i| m.nodes[i].kind == Kind::Gpo)
        .filter_map(|g| {
            let owner = m.sds.get(&g)?.owner.as_deref()?;
            if m.is_default_admin(owner) || m.by_sid(owner).is_some_and(|i| m.nodes[i].tier0) {
                return None;
            }
            let name = m
                .by_sid(owner)
                .map(|i| m.nodes[i].name.clone())
                .unwrap_or_else(|| owner.to_string());
            Some(item(
                m,
                g,
                format!("Owned by {name}, who can change its permissions and settings"),
            ))
        })
        .collect();
    check("AD-GPO-028")
        .expected("GPOs are owned by Domain Admins, Enterprise Admins or SYSTEM")
        .found(plural(list.len(), "GPO has", "GPOs have") + " a non-admin owner")
        .affected(list, "GPOs")
        .evidence(
            "Read from",
            format!("nTSecurityDescriptor owner of GPOs via {}", ldap_from(m)),
        )
        .done()
}

fn gpo_029(m: &Model) -> CheckResult {
    let readers = |sid: &str| {
        matches!(sid, "S-1-5-11" | "S-1-1-0" | "S-1-5-9")
            || sid
                .strip_prefix(&m.domain_sid)
                .is_some_and(|r| r == "-515" || r == "-516")
    };
    let mut list = Vec::new();
    for g in (0..m.nodes.len()).filter(|&i| m.nodes[i].kind == Kind::Gpo) {
        let Some(sd) = m.sds.get(&g) else { continue };
        let ok = sd.dacl.iter().any(|a| {
            a.kind == AceType::Allow
                && !a.inherit_only()
                && readers(&a.sid)
                && (a.mask & (GENERIC_READ | READ_PROP | right::GENERIC_ALL) != 0)
        });
        if !ok {
            list.push(item(
                m,
                g,
                "Neither Authenticated Users nor Domain Computers can read it: computers cannot process it (MS16-072)",
            ));
        }
    }
    check("AD-GPO-029")
        .expected("Every GPO is readable by Authenticated Users or Domain Computers")
        .found(plural(list.len(), "GPO is", "GPOs are") + " unreadable by computers")
        .affected(list, "GPOs")
        .evidence(
            "Read from",
            format!("nTSecurityDescriptor of GPOs via {}", ldap_from(m)),
        )
        .done()
}

// ---------- User rights ----------

pub(super) fn rights_check(
    m: &Model,
    id: &str,
    expected: &str,
    rights: &[(&str, &str)],
    noun: (&str, &str),
) -> CheckResult {
    let policies = read_policies(m);
    if let Some(r) = not_read(check(id).expected(expected), &policies) {
        return r;
    }
    let mut list = Vec::new();
    for p in policies.iter().filter(|p| applies_to_dcs(m, p)) {
        for (key, label) in rights {
            let Some(values) = p.inf_values("Privilege Rights", key) else {
                continue;
            };
            let extra: Vec<String> = values
                .iter()
                .filter(|v| !v.is_empty())
                .map(|v| principal(m, v))
                .filter(|(name, sid)| !expected_right_holder(m, name, sid.as_deref()))
                .map(|(name, _)| name)
                .collect();
            if !extra.is_empty() {
                list.push(gpo_item(
                    m,
                    p,
                    format!("{label} ({key}) granted to {}", extra.join(", ")),
                ));
            }
        }
    }
    check(id)
        .expected(expected)
        .found(plural(list.len(), noun.0, noun.1))
        .affected(list, "assignments")
        .evidence(
            "Scope",
            "GPOs linked to the Domain Controllers OU or the domain head",
        )
        .evidence(
            "Read from",
            format!("GptTmpl.inf [Privilege Rights] in {}", read_from(m)),
        )
        .done()
}

fn gpo_008(m: &Model) -> CheckResult {
    rights_check(
        m,
        "AD-GPO-008",
        "Sensitive user rights on DCs are held only by admins and built-in service identities",
        SENSITIVE_RIGHTS,
        (
            "sensitive right is granted to non-admins",
            "sensitive rights are granted to non-admins",
        ),
    )
}

fn gpo_009(m: &Model) -> CheckResult {
    rights_check(
        m,
        "AD-GPO-009",
        "Only admins and the built-in operator groups can sign in to DCs locally or over Remote Desktop",
        LOGON_RIGHTS,
        ("logon right is granted to non-admins", "logon rights are granted to non-admins"),
    )
}

fn gpo_011(m: &Model) -> CheckResult {
    let policies = read_policies(m);
    let expected = "GPOs outside the Domain Controllers OU deny Domain Admins and Enterprise Admins local and Remote Desktop sign-in";
    if let Some(r) = not_read(check("AD-GPO-011").expected(expected), &policies) {
        return r;
    }
    let admin = |v: &str| {
        let (name, sid) = principal(m, v);
        sid.as_deref()
            .and_then(|s| s.strip_prefix(&m.domain_sid))
            .is_some_and(|r| r == "-512" || r == "-519")
            || name.to_ascii_lowercase().ends_with("domain admins")
            || name.to_ascii_lowercase().ends_with("enterprise admins")
    };
    let mut denying = Vec::new();
    let mut missing: Vec<&str> = Vec::new();
    for (key, label) in [
        ("SeDenyInteractiveLogonRight", "Deny log on locally"),
        (
            "SeDenyRemoteInteractiveLogonRight",
            "Deny log on through Remote Desktop Services",
        ),
    ] {
        let by: Vec<String> = policies
            .iter()
            .filter(|p| applies_to_members(m, p))
            .filter(|p| {
                p.inf_values("Privilege Rights", key)
                    .is_some_and(|v| v.iter().any(|x| admin(x)))
            })
            .map(|p| gpo_name(m, p))
            .collect();
        if by.is_empty() {
            missing.push(label);
        } else {
            denying.push(format!("{label}: {}", by.join(", ")));
        }
    }
    let list: Vec<Affected> = missing
        .iter()
        .map(|label| Affected {
            last_seen: None,
            name: (*label).to_string(),
            kind: "setting".into(),
            location: None,
            reason: Some(
                "No GPO linked outside the Domain Controllers OU denies it to Domain Admins".into(),
            ),
            object: None,
        })
        .collect();
    let mut out = check("AD-GPO-011")
        .expected(expected)
        .found(
            plural(list.len(), "deny right is", "deny rights are")
                + " not enforced on member computers",
        )
        .affected(list, "settings");
    if !denying.is_empty() {
        out = out.evidence("Enforced by", denying.join("; "));
    }
    out.evidence(
        "Read from",
        format!("GptTmpl.inf [Privilege Rights] in {}", read_from(m)),
    )
    .done()
}

// ---------- Settings delivered by GPO ----------

fn gpo_014(m: &Model) -> CheckResult {
    let policies = read_policies(m);
    let expected = "PowerShell script block logging is turned on by a GPO that applies to DCs";
    if let Some(r) = not_read(check("AD-GPO-014").expected(expected), &policies) {
        return r;
    }
    let base = "Software\\Policies\\Microsoft\\Windows\\PowerShell";
    let settings = [
        (
            "ScriptBlockLogging",
            "EnableScriptBlockLogging",
            "Script block logging",
        ),
        ("ModuleLogging", "EnableModuleLogging", "Module logging"),
        ("Transcription", "EnableTranscripting", "Transcription"),
    ];
    let mut set_by = Vec::new();
    let mut list = Vec::new();
    for (sub, value, label) in settings {
        let key = format!("{base}\\{sub}");
        let by: Vec<String> = policies
            .iter()
            .filter(|p| applies_to_dcs(m, p))
            .filter(|p| p.policy("Machine", &key, value).and_then(|v| v.int()) == Some(1))
            .map(|p| gpo_name(m, p))
            .collect();
        if by.is_empty() {
            if sub == "ScriptBlockLogging" {
                list.push(Affected {
                    last_seen: None,
                    name: label.into(),
                    kind: "setting".into(),
                    location: Some(format!("HKLM\\{key}\\{value}")),
                    reason: Some("Not turned on by any GPO that applies to DCs".into()),
                    object: None,
                });
            }
        } else {
            set_by.push(format!("{label}: {}", by.join(", ")));
        }
    }
    let mut out = check("AD-GPO-014")
        .expected(expected)
        .found(if list.is_empty() {
            "Script block logging is set by GPO"
        } else {
            "Script block logging is not set by GPO"
        })
        .affected(list, "settings");
    if !set_by.is_empty() {
        out = out.evidence("Set by", set_by.join("; "));
    }
    out.evidence("Read from", format!("Registry.pol in {}", read_from(m)))
        .done()
}

fn gpo_015(m: &Model) -> CheckResult {
    let policies = read_policies(m);
    let expected = "No GPO adds broad groups (Domain Users, Authenticated Users, Everyone) to local Administrators or Remote Desktop Users";
    if let Some(r) = not_read(check("AD-GPO-015").expected(expected), &policies) {
        return r;
    }
    let local = |sid: &str, name: &str| {
        matches!(sid, "S-1-5-32-544" | "S-1-5-32-555")
            || name.to_ascii_lowercase().starts_with("administrators")
            || name
                .to_ascii_lowercase()
                .starts_with("remote desktop users")
    };
    let mut list = Vec::new();
    for p in &policies {
        if let Some(prefs) = &p.preferences {
            for g in prefs.groups.iter().filter(|g| local(&g.sid, &g.group)) {
                let wide: Vec<&str> = g
                    .members
                    .iter()
                    .filter(|x| !x.action.eq_ignore_ascii_case("REMOVE"))
                    .filter(|x| {
                        broad(m, &x.sid) || principal(m, &x.name).1.is_some_and(|s| broad(m, &s))
                    })
                    .map(|x| x.name.as_str())
                    .collect();
                if !wide.is_empty() {
                    list.push(gpo_item(
                        m,
                        p,
                        format!("Preferences add {} to {}", wide.join(", "), g.group),
                    ));
                }
            }
        }
        // Restricted Groups: "*S-1-5-32-544__Members = *S-...-513".
        if let Some(section) = p.inf.as_ref().and_then(|i| i.get("Group Membership")) {
            for (key, values) in section {
                let Some(group) = key.strip_suffix("__Members") else {
                    continue;
                };
                let (gname, gsid) = principal(m, group);
                if !local(gsid.as_deref().unwrap_or_default(), &gname) {
                    continue;
                }
                let wide: Vec<String> = values
                    .iter()
                    .filter(|v| !v.is_empty())
                    .map(|v| principal(m, v))
                    .filter(|(_, sid)| sid.as_deref().is_some_and(|s| broad(m, s)))
                    .map(|(n, _)| n)
                    .collect();
                if !wide.is_empty() {
                    list.push(gpo_item(
                        m,
                        p,
                        format!("Restricted Groups put {} in {gname}", wide.join(", ")),
                    ));
                }
            }
        }
    }
    check("AD-GPO-015")
        .expected(expected)
        .found(
            plural(list.len(), "GPO grants", "GPOs grant")
                + " broad local admin or Remote Desktop membership",
        )
        .affected(list, "GPOs")
        .evidence(
            "Read from",
            format!(
                "Groups.xml preferences and GptTmpl.inf [Group Membership] in {}",
                read_from(m)
            ),
        )
        .done()
}

fn gpo_018(m: &Model) -> CheckResult {
    let policies = read_policies(m);
    let expected = "No GPO lets computers send saved or default credentials to other servers (CredSSP delegation)";
    if let Some(r) = not_read(check("AD-GPO-018").expected(expected), &policies) {
        return r;
    }
    let key = "Software\\Policies\\Microsoft\\Windows\\CredentialsDelegation";
    let mut list = Vec::new();
    for p in &policies {
        for value in [
            "AllowDefaultCredentials",
            "AllowDefCredentialsWhenNTLMOnly",
            "AllowSavedCredentials",
            "AllowSavedCredentialsWhenNTLMOnly",
        ] {
            if p.policy("Machine", key, value).and_then(|v| v.int()) != Some(1) {
                continue;
            }
            let targets: Vec<&str> = p
                .registry
                .iter()
                .flatten()
                .filter(|v| v.key.eq_ignore_ascii_case(&format!("{key}\\{value}")))
                .filter_map(|v| v.text())
                .collect();
            list.push(gpo_item(
                m,
                p,
                format!(
                    "{value} turned on{}",
                    if targets.is_empty() {
                        String::new()
                    } else {
                        format!(" for {}", targets.join(", "))
                    }
                ),
            ));
        }
    }
    check("AD-GPO-018")
        .expected(expected)
        .found(
            plural(
                list.len(),
                "credential delegation setting",
                "credential delegation settings",
            ) + " turned on",
        )
        .affected(list, "settings")
        .evidence("Read from", format!("Registry.pol in {}", read_from(m)))
        .done()
}

fn gpo_019(m: &Model) -> CheckResult {
    let policies = read_policies(m);
    let expected = "Windows Update clients reach WSUS over HTTPS";
    if let Some(r) = not_read(check("AD-GPO-019").expected(expected), &policies) {
        return r;
    }
    let key = "Software\\Policies\\Microsoft\\Windows\\WindowsUpdate";
    let mut list = Vec::new();
    let mut servers = 0;
    for p in &policies {
        for value in ["WUServer", "WUStatusServer"] {
            let Some(url) = p.policy("Machine", key, value).and_then(|v| v.text()) else {
                continue;
            };
            servers += 1;
            if url.to_ascii_lowercase().starts_with("http://") {
                list.push(gpo_item(
                    m,
                    p,
                    format!(
                        "{value} is {url}: updates can be intercepted and replaced on the network"
                    ),
                ));
            }
        }
    }
    check("AD-GPO-019")
        .expected(expected)
        .found(if servers == 0 {
            "No GPO sets a WSUS server".to_string()
        } else {
            plural(list.len(), "WSUS address uses", "WSUS addresses use") + " plain HTTP"
        })
        .affected(list, "settings")
        .evidence("Read from", format!("Registry.pol in {}", read_from(m)))
        .done()
}

fn gpo_022(m: &Model) -> CheckResult {
    let policies = read_policies(m);
    let expected = "No GPO scheduled task runs as an admin account";
    if let Some(r) = not_read(check("AD-GPO-022").expected(expected), &policies) {
        return r;
    }
    let privileged = m.privileged_users();
    let mut list = Vec::new();
    for p in &policies {
        for t in p.preferences.iter().flat_map(|x| &x.tasks) {
            let Some(run_as) = t.run_as.as_deref().filter(|r| !r.is_empty()) else {
                continue;
            };
            let (_, sid) = principal(m, run_as);
            let admin = sid
                .as_deref()
                .and_then(|s| m.by_sid(s))
                .is_some_and(|i| privileged.contains_key(&i) || m.nodes[i].tier0);
            if admin {
                list.push(gpo_item(
                    m,
                    p,
                    format!("Task \"{}\" runs as {run_as}, whose credentials are stored on every computer it applies to", t.name),
                ));
            }
        }
    }
    check("AD-GPO-022")
        .expected(expected)
        .found(plural(list.len(), "GPO task runs", "GPO tasks run") + " as an admin")
        .affected(list, "tasks")
        .evidence(
            "Read from",
            format!("ScheduledTasks.xml preferences in {}", read_from(m)),
        )
        .done()
}

fn gpo_023(m: &Model) -> CheckResult {
    let policies = read_policies(m);
    let expected = "Startup and logon scripts run from SYSVOL or NETLOGON";
    if let Some(r) = not_read(check("AD-GPO-023").expected(expected), &policies) {
        return r;
    }
    let mut list = Vec::new();
    for p in &policies {
        for s in p.scripts.iter().flatten() {
            let path = s.path.to_ascii_lowercase();
            if path.starts_with("\\\\")
                && !path.contains("\\sysvol\\")
                && !path.contains("\\netlogon")
            {
                list.push(gpo_item(
                    m,
                    p,
                    format!(
                        "{} {} script runs from {}: whoever can write there runs code on every computer it applies to",
                        s.scope, s.kind, s.path
                    ),
                ));
            }
        }
    }
    check("AD-GPO-023")
        .expected(expected)
        .found(plural(list.len(), "script runs", "scripts run") + " from outside SYSVOL")
        .affected(list, "scripts")
        .evidence(
            "Read from",
            format!("scripts.ini and psscripts.ini in {}", read_from(m)),
        )
        .done()
}

fn gpo_027(m: &Model) -> CheckResult {
    let policies = read_policies(m);
    let expected = "The Default Domain Policy holds only account policies, and the Default Domain Controllers Policy only user rights and security options";
    if let Some(r) = not_read(check("AD-GPO-027").expected(expected), &policies) {
        return r;
    }
    let mut list = Vec::new();
    for p in &policies {
        let allowed: &[&str] = match p.folder.to_ascii_lowercase().as_str() {
            DDP => &[
                "Unicode",
                "Version",
                "System Access",
                "Kerberos Policy",
                "Registry Values",
                "Event Audit",
            ],
            DDCP => &[
                "Unicode",
                "Version",
                "Privilege Rights",
                "Registry Values",
                "Event Audit",
                "System Access",
            ],
            _ => continue,
        };
        let mut extra: Vec<String> = p
            .inf
            .iter()
            .flat_map(|i| i.keys())
            .filter(|k| !allowed.iter().any(|a| a.eq_ignore_ascii_case(k)))
            .map(|k| format!("[{k}]"))
            .collect();
        if p.registry.as_ref().is_some_and(|r| !r.is_empty()) {
            extra.push("Administrative Templates (Registry.pol)".into());
        }
        if p.scripts.as_ref().is_some_and(|s| !s.is_empty()) {
            extra.push("scripts".into());
        }
        if p.files
            .iter()
            .flatten()
            .any(|f| f.to_ascii_lowercase().contains("\\preferences\\"))
        {
            extra.push("Preferences".into());
        }
        if !extra.is_empty() {
            list.push(gpo_item(
                m,
                p,
                format!("Also sets {}; put these in their own GPO", extra.join(", ")),
            ));
        }
    }
    check("AD-GPO-027")
        .expected(expected)
        .found(plural(list.len(), "default GPO carries", "default GPOs carry") + " extra settings")
        .affected(list, "GPOs")
        .evidence("Read from", read_from(m))
        .done()
}

pub static RULES: &[Rule] = &[
    Rule {
        id: "AD-GPO-001",
        needs: &["gpos", "domain", "containers"],
        run: gpo_001,
    },
    Rule {
        id: "AD-GPO-005",
        needs: &["scripts"],
        run: gpo_005,
    },
    Rule {
        id: "AD-GPO-006",
        needs: &["sysvol", "groups"],
        run: gpo_006,
    },
    Rule {
        id: "AD-GPO-007",
        needs: &["gpos", "acls", "groups"],
        run: gpo_007,
    },
    Rule {
        id: "AD-GPO-008",
        needs: &["sysvol", "gpos", "containers", "groups"],
        run: gpo_008,
    },
    Rule {
        id: "AD-GPO-009",
        needs: &["sysvol", "gpos", "containers", "groups"],
        run: gpo_009,
    },
    Rule {
        id: "AD-GPO-011",
        needs: &["sysvol", "gpos", "containers", "groups"],
        run: gpo_011,
    },
    Rule {
        id: "AD-GPO-014",
        needs: &["sysvol", "gpos", "containers"],
        run: gpo_014,
    },
    Rule {
        id: "AD-GPO-015",
        needs: &["sysvol", "groups"],
        run: gpo_015,
    },
    Rule {
        id: "AD-GPO-018",
        needs: &["sysvol"],
        run: gpo_018,
    },
    Rule {
        id: "AD-GPO-019",
        needs: &["sysvol"],
        run: gpo_019,
    },
    Rule {
        id: "AD-GPO-022",
        needs: &["sysvol", "users", "groups"],
        run: gpo_022,
    },
    Rule {
        id: "AD-GPO-023",
        needs: &["sysvol"],
        run: gpo_023,
    },
    Rule {
        id: "AD-GPO-026",
        needs: &["domain", "containers"],
        run: gpo_026,
    },
    Rule {
        id: "AD-GPO-027",
        needs: &["sysvol"],
        run: gpo_027,
    },
    Rule {
        id: "AD-GPO-028",
        needs: &["gpos", "acls", "groups"],
        run: gpo_028,
    },
    Rule {
        id: "AD-GPO-029",
        needs: &["gpos", "acls"],
        run: gpo_029,
    },
];
