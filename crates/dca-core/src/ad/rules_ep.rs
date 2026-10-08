//! Member servers and workstations, read over PowerShell remoting
//! (`endpoints`): local accounts and groups, credential protection,
//! network protocols, remote access, application control, Defender,
//! patching, services and tasks, file system permissions and sessions of
//! privileged accounts. Each check reports per machine; machines that
//! could not be read are named in the evidence.

use std::collections::BTreeMap;

use serde_json::Value;

use super::ep::{Endpoint, WORKSTATION};
use super::model::Model;
use super::rules::{check, plural, Out, Rule};
use super::rules_dc::{age_days, audit_setting, dc_item, os_support, AUDIT_BASELINE};
use crate::entra::model::J;
use crate::results::CheckResult;
use crate::time;

/// Days since the last update before a machine counts as unpatched.
pub(super) const PATCH_DAYS: i64 = 45;
const SIGNATURE_DAYS: i64 = 7;
const CACHED_LOGONS: i64 = 4;
/// 192 MB, the CIS minimum for the Security log.
const SECURITY_LOG_BYTES: i64 = 196_608 * 1024;

/// Attack surface reduction rules every machine should block.
const ASR_RULES: [(&str, &str); 5] = [
    (
        "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2",
        "credential stealing from LSASS",
    ),
    (
        "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550",
        "executable content from email",
    ),
    (
        "d4f940ab-401b-4efc-aadc-ad5f3c50688a",
        "Office apps creating child processes",
    ),
    (
        "3b576869-a4ec-4529-8536-b80a7769e899",
        "Office apps creating executable content",
    ),
    ("5beb7efe-fd9a-4556-801d-275e5ffc04cc", "obfuscated scripts"),
];

/// Services of endpoint detection and response agents and Sysmon.
pub(super) const EDR_SERVICES: [(&str, &str); 12] = [
    ("Sense", "Microsoft Defender for Endpoint"),
    ("Sysmon", "Sysmon"),
    ("Sysmon64", "Sysmon"),
    ("CSFalconService", "CrowdStrike Falcon"),
    ("SentinelAgent", "SentinelOne"),
    ("CbDefense", "Carbon Black"),
    ("CylanceSvc", "Cylance"),
    ("cyserver", "Cortex XDR"),
    ("xagt", "Trellix HX"),
    ("elastic-agent", "Elastic Agent"),
    ("ekrn", "ESET"),
    ("SophosED", "Sophos"),
];

/// Accounts that services and tasks run as without a domain password.
fn builtin_account(account: &str) -> bool {
    let a = account.to_ascii_lowercase();
    a.is_empty()
        || a == "localsystem"
        || a.starts_with("nt authority\\")
        || a.starts_with("nt service\\")
        || a.starts_with(".\\")
        || a.starts_with("builtin\\")
}

#[derive(Clone, Copy, PartialEq)]
enum Scope {
    All,
    Servers,
    Workstations,
}

/// Outcome of one check on one machine.
enum Eval {
    Ok(String),
    Bad(String),
    /// The machine answered, but not with the part this check needs.
    Unknown(String),
}

fn scope_text(scope: Scope) -> (&'static str, &'static str) {
    match scope {
        Scope::All => ("machine", "machines"),
        Scope::Servers => ("member server", "member servers"),
        Scope::Workstations => ("workstation", "workstations"),
    }
}

/// Runs `eval` on every machine in `scope` that answered.
fn each_ep(
    m: &Model,
    id: &str,
    expected: &str,
    scope: Scope,
    eval: impl Fn(&Endpoint) -> Eval,
) -> Out {
    let mut bad = Vec::new();
    let mut lines = Vec::new();
    let mut skipped = Vec::new();
    let mut ok = 0;
    for ep in &m.raw.endpoints {
        if ep.data.is_none() {
            skipped.push(format!(
                "{} ({})",
                ep.name,
                ep.error.as_deref().unwrap_or("not read")
            ));
            continue;
        }
        let in_scope = match (scope, ep.product_type()) {
            (Scope::All, _) => true,
            (_, None) => {
                skipped.push(format!("{} ({})", ep.name, ep.why("os")));
                continue;
            }
            (Scope::Workstations, Some(t)) => t == WORKSTATION,
            (Scope::Servers, Some(t)) => t != WORKSTATION,
        };
        if !in_scope {
            continue;
        }
        match eval(ep) {
            Eval::Ok(found) => {
                ok += 1;
                lines.push(format!("{}: {found}", ep.name));
            }
            Eval::Bad(found) => {
                lines.push(format!("{}: {found}", ep.name));
                bad.push(dc_item(m, &ep.name, found));
            }
            Eval::Unknown(why) => skipped.push(format!("{} ({why})", ep.name)),
        }
    }
    let (one, many) = scope_text(scope);
    let out = check(id).expected(expected);
    let assessed = bad.len() + ok;
    if assessed == 0 {
        let why = if m.raw.endpoints.is_empty() {
            "No member server or workstation was read.".to_string()
        } else if skipped.is_empty() {
            format!("None of the machines read is a {one}.")
        } else {
            format!("No {one} could be assessed: {}.", skipped.join("; "))
        };
        return out.not_assessed(why);
    }
    let found = if bad.is_empty() {
        format!("All {} as expected", plural(assessed, one, many))
    } else {
        format!(
            "{} of {} not as expected",
            bad.len(),
            plural(assessed, one, many)
        )
    };
    let mut out = out
        .affected(bad, many)
        .found(found)
        .evidence(
            "Read from",
            format!(
                "Registry and system settings over PowerShell remoting, collected from {} as {}",
                m.raw.info.computer, m.raw.info.account
            ),
        )
        .raw(lines.join("\n"));
    if !skipped.is_empty() {
        out = out.evidence("Not assessed on", skipped.join("; "));
    }
    out
}

/// The registry part, or why it is missing.
fn registry(ep: &Endpoint) -> Result<(), Eval> {
    match ep.part("registry") {
        Some(_) => Ok(()),
        None => Err(Eval::Unknown(ep.why("registry"))),
    }
}

fn list<'a>(ep: &'a Endpoint, part: &str) -> Result<&'a [Value], Eval> {
    ep.part(part)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| Eval::Unknown(ep.why(part)))
}

fn short_list(items: &[String], max: usize) -> String {
    if items.len() <= max {
        items.join(", ")
    } else {
        format!("{} and {} more", items[..max].join(", "), items.len() - max)
    }
}

macro_rules! need {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(e) => return e,
        }
    };
}

/// sAMAccountName (lower case) of every privileged user, with its groups.
fn privileged_names(m: &Model) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (u, groups) in m.privileged_users() {
        let n = &m.nodes[u];
        let sam = n.attrs.str("samaccountname").unwrap_or(&n.name);
        let names: Vec<&str> = groups.iter().map(|&g| m.nodes[g].name.as_str()).collect();
        out.insert(sam.to_ascii_lowercase(), names.join(", "));
    }
    out
}

/// The privileged account a `DOMAIN\name` or `name@domain` refers to, if any.
fn privileged_account<'a>(
    privileged: &'a BTreeMap<String, String>,
    ep: &Endpoint,
    account: &str,
) -> Option<&'a String> {
    let (domain, name) = match account.split_once('\\') {
        Some((d, n)) => (d, n),
        None => match account.split_once('@') {
            Some((n, d)) => (d, n),
            None => ("", account),
        },
    };
    if domain.eq_ignore_ascii_case(&ep.short()) || domain == "." {
        return None;
    }
    privileged.get(&name.to_ascii_lowercase())
}

// ---------- Local accounts and groups ----------

fn hard_001(m: &Model) -> CheckResult {
    let domain = m.domain_sid.clone();
    let broad: Vec<(String, &str)> = vec![
        ("S-1-1-0".into(), "Everyone"),
        ("S-1-5-11".into(), "Authenticated Users"),
        ("S-1-5-32-545".into(), "Users"),
        (format!("{domain}-513"), "Domain Users"),
        (format!("{domain}-515"), "Domain Computers"),
    ];
    each_ep(
        m,
        "EP-HARD-001",
        "No broad group (Everyone, Authenticated Users, Domain Users, Domain Computers) is a local administrator",
        Scope::All,
        |ep| {
            let members = need!(list(ep, "local_admins"));
            let found: Vec<String> = members
                .iter()
                .filter_map(|mbr| {
                    let sid = mbr.s("sid").unwrap_or_default();
                    broad
                        .iter()
                        .find(|(s, _)| s.eq_ignore_ascii_case(sid))
                        .map(|(_, n)| n.to_string())
                })
                .collect();
            if found.is_empty() {
                Eval::Ok(format!("{} members", members.len()))
            } else {
                Eval::Bad(format!("Local administrators include {}", found.join(", ")))
            }
        },
    )
    .done()
}

pub(super) fn laps_policy(ep: &Endpoint) -> bool {
    matches!(ep.reg_int("laps.backupdirectory"), Some(1 | 2))
        || ep.reg_int("laps.policybackupdirectory") == Some(1)
}

fn hard_002(m: &Model) -> CheckResult {
    each_ep(
        m,
        "EP-HARD-002",
        "The Guest account is disabled; the built-in Administrator is disabled or its password is managed by LAPS",
        Scope::All,
        |ep| {
            let users = need!(list(ep, "local_users"));
            need!(registry(ep));
            let mut bad = Vec::new();
            for u in users.iter().filter(|u| u.b("enabled") == Some(true)) {
                let sid = u.s("sid").unwrap_or_default();
                let name = u.s("name").unwrap_or_default();
                if sid.ends_with("-501") {
                    bad.push(format!("Guest account '{name}' is enabled"));
                } else if sid.ends_with("-500") && !laps_policy(ep) {
                    bad.push(format!(
                        "Built-in Administrator '{name}' is enabled without LAPS"
                    ));
                }
            }
            if bad.is_empty() {
                Eval::Ok(format!("{} local accounts", users.len()))
            } else {
                Eval::Bad(bad.join("; "))
            }
        },
    )
    .done()
}

fn hard_003(m: &Model) -> CheckResult {
    each_ep(
        m,
        "EP-HARD-003",
        "A Windows LAPS or legacy LAPS policy manages the local administrator password",
        Scope::All,
        |ep| {
            need!(registry(ep));
            match (
                ep.reg_int("laps.backupdirectory"),
                ep.reg_int("laps.policybackupdirectory"),
            ) {
                (Some(1), _) => Eval::Ok("Windows LAPS, backed up to Entra ID".into()),
                (Some(2), _) => Eval::Ok("Windows LAPS, backed up to Active Directory".into()),
                (_, Some(1)) => Eval::Ok("Legacy LAPS".into()),
                _ => Eval::Bad("No LAPS policy applies".into()),
            }
        },
    )
    .done()
}

// ---------- Credential protection ----------

fn device_guard(ep: &Endpoint) -> Result<&Value, Eval> {
    ep.part("device_guard")
        .ok_or_else(|| Eval::Unknown(ep.why("device_guard")))
}

pub(super) fn running(dg: &Value, service: i64) -> bool {
    dg.a("running").iter().any(|v| v.as_i64() == Some(service))
}

fn hard_004(m: &Model) -> CheckResult {
    each_ep(
        m,
        "EP-HARD-004",
        "Credential Guard is running",
        Scope::All,
        |ep| {
            let dg = need!(device_guard(ep));
            if running(dg, 1) {
                Eval::Ok("Credential Guard running".into())
            } else {
                Eval::Bad("Credential Guard is not running".into())
            }
        },
    )
    .done()
}

fn hard_005(m: &Model) -> CheckResult {
    each_ep(
        m,
        "EP-HARD-005",
        "LSA protection is on (RunAsPPL 1 or 2)",
        Scope::All,
        |ep| {
            need!(registry(ep));
            match ep.reg_int("lsa.runasppl") {
                Some(v @ (1 | 2)) => Eval::Ok(format!("RunAsPPL {v}")),
                v => Eval::Bad(format!(
                    "RunAsPPL {}",
                    v.map_or("not set".into(), |v| v.to_string())
                )),
            }
        },
    )
    .done()
}

fn hard_006(m: &Model) -> CheckResult {
    each_ep(
        m,
        "EP-HARD-006",
        "WDigest does not keep passwords in memory (UseLogonCredential 0 or not set on Windows 8.1 and later)",
        Scope::All,
        |ep| {
            need!(registry(ep));
            match (ep.reg_int("wdigest.uselogoncredential"), ep.build()) {
                (Some(1), _) => Eval::Bad("UseLogonCredential is 1".into()),
                (None, Some(b)) if b < 9600 => {
                    Eval::Bad(format!("Build {b} keeps WDigest passwords unless UseLogonCredential is 0"))
                }
                (v, _) => Eval::Ok(format!(
                    "UseLogonCredential {}",
                    v.map_or("not set".into(), |v| v.to_string())
                )),
            }
        },
    )
    .done()
}

fn hard_007(m: &Model) -> CheckResult {
    each_ep(
        m,
        "EP-HARD-007",
        &format!("{CACHED_LOGONS} or fewer cached domain logons"),
        Scope::All,
        |ep| {
            need!(registry(ep));
            // Windows caches 10 logons when the value is not set.
            let n = ep.reg_int("winlogon.cachedlogonscount").unwrap_or(10);
            if n <= CACHED_LOGONS {
                Eval::Ok(format!("{n} cached logons"))
            } else {
                Eval::Bad(format!("{n} cached logons"))
            }
        },
    )
    .done()
}

// ---------- Network protocols ----------

fn smb(ep: &Endpoint) -> Result<&Value, Eval> {
    ep.part("smb").ok_or_else(|| Eval::Unknown(ep.why("smb")))
}

fn hard_008(m: &Model) -> CheckResult {
    each_ep(m, "EP-HARD-008", "SMBv1 is disabled", Scope::All, |ep| {
        let s = need!(smb(ep));
        if s.b("smb1") == Some(true) {
            Eval::Bad("SMBv1 server enabled".into())
        } else {
            Eval::Ok("SMBv1 disabled".into())
        }
    })
    .done()
}

fn hard_009(m: &Model) -> CheckResult {
    each_ep(
        m,
        "EP-HARD-009",
        "SMB signing is required by both the SMB server and client",
        Scope::All,
        |ep| {
            let s = need!(smb(ep));
            let mut off = Vec::new();
            if s.b("require_signing") != Some(true) {
                off.push("server");
            }
            if s.b("client_require_signing") != Some(true) {
                off.push("client");
            }
            if off.is_empty() {
                Eval::Ok("Signing required".into())
            } else {
                Eval::Bad(format!("Signing not required by the {}", off.join(" or ")))
            }
        },
    )
    .done()
}

fn hard_010(m: &Model) -> CheckResult {
    each_ep(
        m,
        "EP-HARD-010",
        "LLMNR is turned off by policy and NetBIOS over TCP/IP is disabled on every interface",
        Scope::All,
        |ep| {
            need!(registry(ep));
            let nb = need!(list(ep, "netbios"));
            let mut bad = Vec::new();
            if ep.reg_int("dnsclient.enablemulticast") != Some(0) {
                bad.push("LLMNR on".to_string());
            }
            let on = nb.iter().filter(|v| v.as_i64() != Some(2)).count();
            if on > 0 {
                bad.push(format!(
                    "NetBIOS not disabled on {}",
                    plural(on, "interface", "interfaces")
                ));
            }
            if bad.is_empty() {
                Eval::Ok("LLMNR and NetBIOS off".into())
            } else {
                Eval::Bad(bad.join("; "))
            }
        },
    )
    .done()
}

fn hard_011(m: &Model) -> CheckResult {
    each_ep(
        m,
        "EP-HARD-011",
        "Proxy auto-discovery (WPAD) is turned off",
        Scope::All,
        |ep| {
            need!(registry(ep));
            let Some(svc) = ep.service_active("WinHttpAutoProxySvc") else {
                return Eval::Unknown(ep.why("services"));
            };
            if ep.reg_int("winhttp.disablewpad") == Some(1) || !svc {
                Eval::Ok("WPAD off".into())
            } else {
                Eval::Bad("WinHTTP auto-proxy service active and WPAD not disabled".into())
            }
        },
    )
    .done()
}

fn service_off(m: &Model, id: &str, service: &str, label: &str, scope: Scope) -> CheckResult {
    each_ep(
        m,
        id,
        &format!("The {label} service is stopped and disabled"),
        scope,
        |ep| match ep.service_active(service) {
            None => Eval::Unknown(ep.why("services")),
            Some(true) => Eval::Bad(format!("{label} service running or automatic")),
            Some(false) => Eval::Ok(format!("{label} stopped")),
        },
    )
    .done()
}

fn hard_012(m: &Model) -> CheckResult {
    service_off(
        m,
        "EP-HARD-012",
        "WebClient",
        "WebClient (WebDAV)",
        Scope::All,
    )
}

fn hard_013(m: &Model) -> CheckResult {
    service_off(m, "EP-HARD-013", "Spooler", "Print Spooler", Scope::Servers)
}

// ---------- Remote access ----------

fn hard_014(m: &Model) -> CheckResult {
    each_ep(
        m,
        "EP-HARD-014",
        "Where Remote Desktop is on, Network Level Authentication is required",
        Scope::All,
        |ep| {
            need!(registry(ep));
            if ep.reg_int("rdp.fdenytsconnections") != Some(0) {
                return Eval::Ok("Remote Desktop off".into());
            }
            let nla = ep
                .reg_int("rdp.policyuserauthentication")
                .or(ep.reg_int("rdp.userauthentication"))
                == Some(1);
            let restricted = match ep.reg_int("credssp.restrictedremoteadministration") {
                Some(1..) => "Restricted Admin or Remote Credential Guard required",
                _ => "Restricted Admin and Remote Credential Guard not required",
            };
            if nla {
                Eval::Ok(format!("Remote Desktop on with NLA; {restricted}"))
            } else {
                Eval::Bad(format!("Remote Desktop on without NLA; {restricted}"))
            }
        },
    )
    .done()
}

fn hard_015(m: &Model) -> CheckResult {
    each_ep(
        m,
        "EP-HARD-015",
        "WinRM accepts neither Basic authentication nor unencrypted traffic",
        Scope::All,
        |ep| {
            need!(registry(ep));
            let listeners: Vec<String> = ep
                .part("winrm_listeners")
                .and_then(Value::as_array)
                .map(|l| {
                    l.iter()
                        .filter_map(|x| x.s("transport"))
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            let mut bad = Vec::new();
            if ep.reg_int("winrm.allowbasic") == Some(1) {
                bad.push("Basic authentication allowed");
            }
            if ep.reg_int("winrm.allowunencryptedtraffic") == Some(1) {
                bad.push("unencrypted traffic allowed");
            }
            let l = if listeners.is_empty() {
                "no listener read".to_string()
            } else {
                format!("listeners: {}", listeners.join(", "))
            };
            if bad.is_empty() {
                Eval::Ok(l)
            } else {
                Eval::Bad(format!("{}; {l}", bad.join(", ")))
            }
        },
    )
    .done()
}

// ---------- PowerShell and application control ----------

fn hard_016(m: &Model) -> CheckResult {
    each_ep(
        m,
        "EP-HARD-016",
        "The PowerShell 2.0 engine is removed",
        Scope::All,
        |ep| match ep.part("psv2").and_then(Value::as_bool) {
            None => Eval::Unknown(ep.why("psv2")),
            Some(true) => Eval::Bad("PowerShell 2.0 installed".into()),
            Some(false) => Eval::Ok("PowerShell 2.0 removed".into()),
        },
    )
    .done()
}

fn hard_017(m: &Model) -> CheckResult {
    each_ep(
        m,
        "EP-HARD-017",
        "PowerShell script block logging is on by policy",
        Scope::All,
        |ep| {
            need!(registry(ep));
            let tr = if ep.reg_int("powershell.enabletranscripting") == Some(1) {
                "transcription on"
            } else {
                "transcription off"
            };
            if ep.reg_int("powershell.enablescriptblocklogging") == Some(1) {
                Eval::Ok(format!("Script block logging on, {tr}"))
            } else {
                Eval::Bad(format!("Script block logging off, {tr}"))
            }
        },
    )
    .done()
}

fn hard_018(m: &Model) -> CheckResult {
    each_ep(
        m,
        "EP-HARD-018",
        "App Control for Business (WDAC) or AppLocker enforces which programs run",
        Scope::All,
        |ep| {
            let dg = need!(device_guard(ep));
            if dg.n("umci_policy") == Some(2) {
                return Eval::Ok("App Control user mode policy enforced".into());
            }
            let enforced: Vec<String> = ep
                .part("applocker")
                .and_then(Value::as_array)
                .map(|c| {
                    c.iter()
                        .filter(|x| x.s("mode") == Some("Enabled") && x.n("rules").unwrap_or(0) > 0)
                        .filter_map(|x| x.s("type"))
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            if enforced.iter().any(|t| t == "Exe") {
                Eval::Ok(format!("AppLocker enforced: {}", enforced.join(", ")))
            } else if ep.part("applocker").is_none() {
                Eval::Unknown(ep.why("applocker"))
            } else {
                Eval::Bad("No App Control or AppLocker policy enforced for programs".into())
            }
        },
    )
    .done()
}

fn hard_019(m: &Model) -> CheckResult {
    each_ep(
        m,
        "EP-HARD-019",
        "Windows Firewall is on in every profile and blocks inbound connections by default",
        Scope::All,
        |ep| {
            let profiles = need!(list(ep, "firewall"));
            let bad: Vec<String> = profiles
                .iter()
                .filter_map(|p| {
                    let name = p.s("name").unwrap_or("profile");
                    if p.b("enabled") != Some(true) {
                        Some(format!("{name} off"))
                    } else if p.s("inbound") == Some("Allow") {
                        Some(format!("{name} allows inbound"))
                    } else {
                        None
                    }
                })
                .collect();
            if bad.is_empty() {
                Eval::Ok("All profiles on".into())
            } else {
                Eval::Bad(bad.join(", "))
            }
        },
    )
    .done()
}

// ---------- Platform security ----------

fn hard_020(m: &Model) -> CheckResult {
    each_ep(
        m,
        "EP-HARD-020",
        "BitLocker protects the operating system drive",
        Scope::Workstations,
        |ep| match ep.part("bitlocker").and_then(|b| b.n("protection")) {
            None => Eval::Unknown(ep.why("bitlocker")),
            Some(1) => Eval::Ok("Protection on".into()),
            Some(_) => Eval::Bad("OS drive not protected by BitLocker".into()),
        },
    )
    .done()
}

fn hard_021(m: &Model) -> CheckResult {
    each_ep(
        m,
        "EP-HARD-021",
        "Secure Boot is on and a TPM is present",
        Scope::All,
        |ep| {
            let tpm = ep.part("tpm").and_then(|t| t.b("present"));
            let sb = ep.part("secure_boot").and_then(Value::as_bool);
            let mut bad = Vec::new();
            match sb {
                Some(false) => bad.push("Secure Boot off"),
                None => bad.push("Secure Boot not supported or not reported (legacy BIOS)"),
                Some(true) => {}
            }
            match tpm {
                Some(false) => bad.push("no TPM"),
                None => return Eval::Unknown(ep.why("tpm")),
                Some(true) => {}
            }
            if bad.is_empty() {
                Eval::Ok("Secure Boot on, TPM present".into())
            } else {
                Eval::Bad(bad.join(", "))
            }
        },
    )
    .done()
}

fn hard_022(m: &Model) -> CheckResult {
    each_ep(
        m,
        "EP-HARD-022",
        "Virtualization-based security and memory integrity (HVCI) are running",
        Scope::All,
        |ep| {
            let dg = need!(device_guard(ep));
            let vbs = dg.n("vbs") == Some(2);
            let hvci = running(dg, 2);
            match (vbs, hvci) {
                (true, true) => Eval::Ok("VBS and HVCI running".into()),
                (true, false) => Eval::Bad("VBS running, HVCI not running".into()),
                _ => Eval::Bad("VBS not running".into()),
            }
        },
    )
    .done()
}

// ---------- Defender ----------

fn defender(ep: &Endpoint) -> Result<&Value, Eval> {
    ep.part("defender").ok_or_else(|| {
        Eval::Unknown(format!(
            "{} (another antivirus may be in use)",
            ep.why("defender")
        ))
    })
}

fn hard_023(m: &Model) -> CheckResult {
    each_ep(
        m,
        "EP-HARD-023",
        &format!("Defender Antivirus runs with real-time protection and signatures under {SIGNATURE_DAYS} days old"),
        Scope::All,
        |ep| {
            let d = need!(defender(ep));
            let age = d.n("signature_age").unwrap_or(0);
            let mut bad = Vec::new();
            if d.b("enabled") != Some(true) {
                bad.push("antivirus service off".to_string());
            }
            if d.b("realtime") != Some(true) {
                bad.push("real-time protection off".to_string());
            }
            if age > SIGNATURE_DAYS {
                bad.push(format!("signatures {age} days old"));
            }
            if bad.is_empty() {
                Eval::Ok(format!("Real-time on, signatures {age} days old"))
            } else {
                Eval::Bad(bad.join(", "))
            }
        },
    )
    .done()
}

fn hard_024(m: &Model) -> CheckResult {
    each_ep(
        m,
        "EP-HARD-024",
        "Defender has no path, process or extension exclusions",
        Scope::All,
        |ep| {
            let d = need!(defender(ep));
            let ex: Vec<String> = d
                .strs("exclusions")
                .into_iter()
                .map(str::to_string)
                .collect();
            if ex.is_empty() {
                Eval::Ok("No exclusions".into())
            } else {
                Eval::Bad(format!(
                    "{}: {}",
                    plural(ex.len(), "exclusion", "exclusions"),
                    short_list(&ex, 5)
                ))
            }
        },
    )
    .done()
}

fn hard_025(m: &Model) -> CheckResult {
    each_ep(
        m,
        "EP-HARD-025",
        "Key attack surface reduction rules block (LSASS, email executables, Office child processes and executables, obfuscated scripts)",
        Scope::All,
        |ep| {
            let d = need!(defender(ep));
            let asr = d.o("asr");
            let missing: Vec<String> = ASR_RULES
                .iter()
                .filter(|(id, _)| {
                    !matches!(asr.and_then(|a| a.n(id)), Some(1 | 6))
                })
                .map(|(_, n)| n.to_string())
                .collect();
            if missing.is_empty() {
                Eval::Ok("All key rules block".into())
            } else {
                Eval::Bad(format!("Not blocking: {}", missing.join(", ")))
            }
        },
    )
    .done()
}

// ---------- Patching and lifecycle ----------

fn hard_026(m: &Model) -> CheckResult {
    each_ep(
        m,
        "EP-HARD-026",
        &format!("An update was installed within the last {PATCH_DAYS} days"),
        Scope::All,
        |ep| {
            let Some(h) = ep.part("hotfixes") else {
                return Eval::Unknown(ep.why("hotfixes"));
            };
            match age_days(m, h.s("last")) {
                None => Eval::Bad("No installed update with a date".into()),
                Some(d) if d > PATCH_DAYS => Eval::Bad(format!(
                    "Last update {} installed {d} days ago",
                    h.s("last_id").unwrap_or("(unnamed)")
                )),
                Some(d) => Eval::Ok(format!("Last update {d} days ago")),
            }
        },
    )
    .done()
}

/// Windows client builds and the end of their Enterprise servicing.
fn client_support(build: i64, caption: &str) -> Option<(&'static str, &'static str)> {
    let ltsc = caption.contains("LTSC") || caption.contains("LTSB");
    Some(match (build, ltsc) {
        (14393, true) => ("Windows 10 LTSB 2016", "2026-10-13"),
        (17763, true) => ("Windows 10 LTSC 2019", "2029-01-09"),
        (19044, true) => ("Windows 10 LTSC 2021", "2027-01-12"),
        (26100, true) => ("Windows 11 LTSC 2024", "2029-10-09"),
        (7600 | 7601, _) => ("Windows 7", "2020-01-14"),
        (9200, _) => ("Windows 8", "2016-01-12"),
        (9600, _) => ("Windows 8.1", "2023-01-10"),
        (10240..=19045, false) => ("Windows 10", "2025-10-14"),
        (22000, _) => ("Windows 11 21H2", "2024-10-08"),
        (22621, _) => ("Windows 11 22H2", "2025-10-14"),
        (22631, _) => ("Windows 11 23H2", "2026-11-10"),
        (26100, false) => ("Windows 11 24H2", "2027-10-12"),
        (26200, _) => ("Windows 11 25H2", "2028-10-10"),
        _ => return None,
    })
}

fn hard_027(m: &Model) -> CheckResult {
    each_ep(
        m,
        "EP-HARD-027",
        "Every machine runs a Windows version that still gets security updates",
        Scope::All,
        |ep| {
            let Some(os) = ep.part("os") else {
                return Eval::Unknown(ep.why("os"));
            };
            let build = os.n("build").unwrap_or(0);
            let caption = os.s("caption").unwrap_or_default();
            let support = if ep.product_type() == Some(WORKSTATION) {
                client_support(build, caption)
            } else {
                os_support(build)
            };
            let Some((name, end)) = support else {
                return Eval::Unknown(format!(
                    "build {build} ({caption}) is not in the support table"
                ));
            };
            match time::parse_iso(&format!("{end}T00:00:00Z")) {
                Some(t) if t <= m.now => Eval::Bad(format!("{name}, support ended {end}")),
                _ => Eval::Ok(format!("{name}, supported until {end}")),
            }
        },
    )
    .done()
}

// ---------- Services, tasks and permissions ----------

fn hard_029(m: &Model) -> CheckResult {
    let privileged = privileged_names(m);
    each_ep(
        m,
        "EP-HARD-029",
        "Services run as built-in or managed service accounts, not domain user accounts",
        Scope::All,
        |ep| {
            let services = need!(list(ep, "services"));
            let found: Vec<String> = services
                .iter()
                .filter_map(|s| {
                    let account = s.s("account").unwrap_or_default();
                    if builtin_account(account) || account.ends_with('$') {
                        return None;
                    }
                    let tier = privileged_account(&privileged, ep, account)
                        .map(|g| format!(", privileged through {g}"))
                        .unwrap_or_default();
                    Some(format!(
                        "{} as {account}{tier}",
                        s.s("name").unwrap_or_default()
                    ))
                })
                .collect();
            if found.is_empty() {
                Eval::Ok("No service runs as a domain account".into())
            } else {
                Eval::Bad(short_list(&found, 5))
            }
        },
    )
    .done()
}

fn hard_030(m: &Model) -> CheckResult {
    each_ep(
        m,
        "EP-HARD-030",
        "No service has an unquoted path with spaces or a program file that ordinary users can change",
        Scope::All,
        |ep| {
            let services = need!(list(ep, "services"));
            let mut found = Vec::new();
            for s in services {
                let name = s.s("name").unwrap_or_default();
                if s.b("writable") == Some(true) {
                    found.push(format!("{name}: program file writable by users"));
                } else if s.b("unquoted") == Some(true) {
                    found.push(format!("{name}: unquoted path with spaces"));
                }
            }
            if found.is_empty() {
                Eval::Ok(format!("{} services", services.len()))
            } else {
                Eval::Bad(short_list(&found, 5))
            }
        },
    )
    .done()
}

fn hard_031(m: &Model) -> CheckResult {
    let privileged = privileged_names(m);
    each_ep(
        m,
        "EP-HARD-031",
        "No scheduled task runs as a privileged domain account",
        Scope::All,
        |ep| {
            let tasks = need!(list(ep, "tasks"));
            let found: Vec<String> = tasks
                .iter()
                .filter_map(|t| {
                    let user = t.s("user").unwrap_or_default();
                    privileged_account(&privileged, ep, user)
                        .map(|g| format!("{} as {user} ({g})", t.s("name").unwrap_or_default()))
                })
                .collect();
            if found.is_empty() {
                Eval::Ok(format!(
                    "{} as domain accounts, none privileged",
                    plural(tasks.len(), "task", "tasks")
                ))
            } else {
                Eval::Bad(short_list(&found, 5))
            }
        },
    )
    .done()
}

fn writable_list(
    m: &Model,
    id: &str,
    expected: &str,
    part: &'static str,
    what: &'static str,
) -> CheckResult {
    each_ep(m, id, expected, Scope::All, |ep| {
        let items = need!(list(ep, part));
        let found: Vec<String> = items
            .iter()
            .filter_map(|i| {
                i.as_str().map(str::to_string).or_else(|| {
                    i.s("path")
                        .map(|p| format!("{} ({p})", i.s("name").unwrap_or_default()))
                })
            })
            .collect();
        if found.is_empty() {
            Eval::Ok(format!("No {what} writable by users"))
        } else {
            Eval::Bad(format!("Writable by users: {}", short_list(&found, 5)))
        }
    })
    .done()
}

fn hard_032(m: &Model) -> CheckResult {
    writable_list(
        m,
        "EP-HARD-032",
        "No machine-wide autorun points to a file ordinary users can change",
        "autoruns",
        "autoruns",
    )
}

fn hard_033(m: &Model) -> CheckResult {
    writable_list(
        m,
        "EP-HARD-033",
        "No folder in the system PATH is writable by ordinary users",
        "path_writable",
        "PATH folders",
    )
}

fn hard_034(m: &Model) -> CheckResult {
    each_ep(
        m,
        "EP-HARD-034",
        "AlwaysInstallElevated is not set",
        Scope::All,
        |ep| {
            need!(registry(ep));
            if ep.reg_int("installer.alwaysinstallelevated") == Some(1) {
                Eval::Bad("AlwaysInstallElevated is 1 for the machine".into())
            } else {
                Eval::Ok("Not set".into())
            }
        },
    )
    .done()
}

fn hard_035(m: &Model) -> CheckResult {
    each_ep(
        m,
        "EP-HARD-035",
        "UAC is on, prompts administrators and filters remote local-account tokens",
        Scope::All,
        |ep| {
            need!(registry(ep));
            let mut bad = Vec::new();
            if ep.reg_int("uac.enablelua") == Some(0) {
                bad.push("UAC off (EnableLUA 0)");
            }
            if ep.reg_int("uac.consentpromptbehavioradmin") == Some(0) {
                bad.push("administrators elevate without a prompt");
            }
            if ep.reg_int("uac.localaccounttokenfilterpolicy") == Some(1) {
                bad.push("LocalAccountTokenFilterPolicy 1 (local accounts get full admin tokens remotely)");
            }
            if bad.is_empty() {
                Eval::Ok("UAC as expected".into())
            } else {
                Eval::Bad(bad.join("; "))
            }
        },
    )
    .done()
}

fn hard_037(m: &Model) -> CheckResult {
    let privileged = privileged_names(m);
    each_ep(
        m,
        "EP-HARD-037",
        "No privileged domain account is signed in on a member server or workstation",
        Scope::All,
        |ep| {
            let sessions = need!(list(ep, "sessions"));
            let found: Vec<String> = sessions
                .iter()
                .filter_map(Value::as_str)
                .filter_map(|s| {
                    privileged_account(&privileged, ep, s).map(|g| format!("{s} ({g})"))
                })
                .collect();
            if found.is_empty() {
                Eval::Ok(format!(
                    "{}, none privileged",
                    plural(
                        sessions.len(),
                        "interactive session",
                        "interactive sessions"
                    )
                ))
            } else {
                Eval::Bad(format!("Signed in: {}", found.join(", ")))
            }
        },
    )
    .done()
}

fn hard_038(m: &Model) -> CheckResult {
    each_ep(
        m,
        "EP-HARD-038",
        "No share gives Everyone, Authenticated Users, Users or Domain Users change or full access",
        Scope::All,
        |ep| {
            let shares = need!(list(ep, "shares"));
            let found: Vec<String> = shares
                .iter()
                .filter(|s| !s.a("broad_write").is_empty())
                .map(|s| {
                    format!(
                        "{} ({})",
                        s.s("name").unwrap_or_default(),
                        s.strs("broad_write").join(", ")
                    )
                })
                .collect();
            if found.is_empty() {
                Eval::Ok(plural(shares.len(), "share", "shares"))
            } else {
                Eval::Bad(short_list(&found, 5))
            }
        },
    )
    .done()
}

// ---------- Protocol and logging settings ----------

fn hard_039(m: &Model) -> CheckResult {
    each_ep(
        m,
        "EP-HARD-039",
        "Only NTLMv2 is sent and LM and NTLM are refused (LmCompatibilityLevel 5)",
        Scope::All,
        |ep| {
            need!(registry(ep));
            // Windows uses level 3 when the value is not set.
            let level = ep.reg_int("lsa.lmcompatibilitylevel");
            let outgoing = match ep.reg_int("msv1_0.restrictsendingntlmtraffic") {
                Some(2) => "outgoing NTLM denied",
                Some(1) => "outgoing NTLM audited",
                _ => "outgoing NTLM allowed",
            };
            match level {
                Some(5) => Eval::Ok(format!("LmCompatibilityLevel 5, {outgoing}")),
                l => Eval::Bad(format!(
                    "LmCompatibilityLevel {}, {outgoing}",
                    l.map_or("not set (3)".into(), |l| l.to_string())
                )),
            }
        },
    )
    .done()
}

fn hard_040(m: &Model) -> CheckResult {
    each_ep(
        m,
        "EP-HARD-040",
        "TLS 1.0 and 1.1 are disabled for the server side of Schannel",
        Scope::All,
        |ep| {
            need!(registry(ep));
            let on: Vec<&str> = [
                ("schannel.tls10.enabled", "TLS 1.0"),
                ("schannel.tls11.enabled", "TLS 1.1"),
            ]
            .into_iter()
            .filter(|(k, _)| ep.reg_int(k) != Some(0))
            .map(|(_, n)| n)
            .collect();
            if on.is_empty() {
                Eval::Ok("TLS 1.0 and 1.1 disabled".into())
            } else {
                Eval::Bad(format!("Not disabled: {}", on.join(", ")))
            }
        },
    )
    .done()
}

fn hard_041(m: &Model) -> CheckResult {
    // Subcategories a member machine should audit: logons, process
    // creation, account and group changes, credential validation.
    let wanted = [
        "0CCE9215-69AE-11D9-BED3-505054503030",
        "0CCE921B-69AE-11D9-BED3-505054503030",
        "0CCE922B-69AE-11D9-BED3-505054503030",
        "0CCE9235-69AE-11D9-BED3-505054503030",
        "0CCE9237-69AE-11D9-BED3-505054503030",
        "0CCE923F-69AE-11D9-BED3-505054503030",
    ];
    each_ep(
        m,
        "EP-HARD-041",
        "Logon, process creation, account and group changes and credential validation are audited, and the Security log holds at least 192 MB",
        Scope::All,
        |ep| {
            let Some(audit) = ep.part("audit") else {
                return Eval::Unknown(ep.why("audit"));
            };
            let mut gaps = Vec::new();
            for (guid, name, s, f) in AUDIT_BASELINE.iter().filter(|a| wanted.contains(&a.0)) {
                let (has_s, has_f) = audit.s(guid).map(audit_setting).unwrap_or((false, false));
                if (*s && !has_s) || (*f && !has_f) {
                    gaps.push(name.to_string());
                }
            }
            if let Some(size) = ep.part("security_log").and_then(|l| l.n("max_bytes")) {
                if size < SECURITY_LOG_BYTES {
                    gaps.push(format!("Security log {} MB", size / 1024 / 1024));
                }
            }
            if gaps.is_empty() {
                Eval::Ok("Audited, log size as expected".into())
            } else {
                Eval::Bad(format!("Gaps: {}", gaps.join(", ")))
            }
        },
    )
    .done()
}

fn hard_042(m: &Model) -> CheckResult {
    each_ep(
        m,
        "EP-HARD-042",
        "An endpoint detection and response agent or Sysmon is running",
        Scope::All,
        |ep| {
            if ep.part("services").is_none() {
                return Eval::Unknown(ep.why("services"));
            }
            let found: Vec<&str> = EDR_SERVICES
                .iter()
                .filter(|(svc, _)| {
                    ep.service(svc)
                        .is_some_and(|s| s.s("state") == Some("Running"))
                })
                .map(|(_, n)| *n)
                .collect();
            if found.is_empty() {
                Eval::Bad("No known EDR agent or Sysmon running".into())
            } else {
                Eval::Ok(format!("Running: {}", found.join(", ")))
            }
        },
    )
    .done()
}

fn hard_043(m: &Model) -> CheckResult {
    service_off(
        m,
        "EP-HARD-043",
        "RemoteRegistry",
        "Remote Registry",
        Scope::Workstations,
    )
}

fn hard_044(m: &Model) -> CheckResult {
    each_ep(
        m,
        "EP-HARD-044",
        "Anonymous users cannot list accounts or shares (RestrictAnonymous 1, RestrictAnonymousSAM 1, EveryoneIncludesAnonymous 0)",
        Scope::All,
        |ep| {
            need!(registry(ep));
            let mut bad = Vec::new();
            if ep.reg_int("lsa.restrictanonymous").unwrap_or(0) < 1 {
                bad.push("RestrictAnonymous 0");
            }
            if ep.reg_int("lsa.restrictanonymoussam") == Some(0) {
                bad.push("RestrictAnonymousSAM 0");
            }
            if ep.reg_int("lsa.everyoneincludesanonymous") == Some(1) {
                bad.push("EveryoneIncludesAnonymous 1");
            }
            if bad.is_empty() {
                Eval::Ok("Anonymous enumeration restricted".into())
            } else {
                Eval::Bad(bad.join(", "))
            }
        },
    )
    .done()
}

fn hard_046(m: &Model) -> CheckResult {
    each_ep(
        m,
        "EP-HARD-046",
        "No machine signs in automatically with a password stored in the registry",
        Scope::All,
        |ep| {
            need!(registry(ep));
            let auto = ep.reg_str("winlogon.autoadminlogon").as_deref() == Some("1");
            let stored = ep
                .reg("winlogon.defaultpassword_present")
                .and_then(Value::as_bool)
                == Some(true);
            match (auto, stored) {
                (true, true) => Eval::Bad(format!(
                    "Automatic sign-in as {} with a stored password",
                    ep.reg_str("winlogon.defaultusername").unwrap_or_default()
                )),
                (false, true) => Eval::Bad("A DefaultPassword value is stored in Winlogon".into()),
                (true, false) => Eval::Ok("Automatic sign-in without a stored password".into()),
                (false, false) => Eval::Ok("No automatic sign-in".into()),
            }
        },
    )
    .done()
}

const fn rule(id: &'static str, run: fn(&Model) -> CheckResult) -> Rule {
    Rule {
        id,
        needs: &["endpoints"],
        run,
    }
}

// ---------- Added checks: coercion, local admins, software, Tier 0 hosts ----------

fn cmp_005(m: &Model) -> CheckResult {
    let du = format!("{}-513", m.domain_sid);
    each_ep(
        m,
        "AD-CMP-005",
        "Domain Users is not a local administrator on any computer",
        Scope::All,
        |ep| {
            let members = need!(list(ep, "local_admins"));
            if members
                .iter()
                .any(|mbr| mbr.s("sid").is_some_and(|s| s.eq_ignore_ascii_case(&du)))
            {
                Eval::Bad("Domain Users is a local administrator: every user in the domain is an admin here".into())
            } else {
                Eval::Ok(format!("{} members", members.len()))
            }
        },
    )
    .done()
}

fn cmp_009(m: &Model) -> CheckResult {
    each_ep(
        m,
        "AD-CMP-009",
        "Member servers do not run both the Print Spooler and WebClient services",
        Scope::Servers,
        |ep| {
            let (Some(spooler), Some(webdav)) =
                (ep.service_active("Spooler"), ep.service_active("WebClient"))
            else {
                return Eval::Unknown(ep.why("services"));
            };
            match (spooler, webdav) {
                (true, true) => Eval::Bad("Print Spooler and WebClient both on: the server can be coerced to authenticate over SMB and HTTP, which can be relayed".into()),
                (true, false) => Eval::Ok("Print Spooler on, WebClient off".into()),
                (false, true) => Eval::Ok("WebClient on, Print Spooler off".into()),
                _ => Eval::Ok("both off".into()),
            }
        },
    )
    .done()
}

/// Software with known exploited vulnerabilities: (name prefix, first fixed
/// version, CVE). A small list of widely deployed tools; it is not a full
/// vulnerability scan.
const VULNERABLE_SOFTWARE: [(&str, &str, &str); 8] = [
    ("7-zip", "24.07", "CVE-2024-11477"),
    ("winrar", "6.23", "CVE-2023-38831"),
    ("putty", "0.81", "CVE-2024-31497"),
    ("notepad++", "8.5.7", "CVE-2023-40031"),
    ("filezilla client", "3.63.1", "CVE-2023-48795"),
    ("winscp", "6.2.2", "CVE-2023-48795"),
    ("openssh", "9.6", "CVE-2023-48795"),
    ("vlc media player", "3.0.20", "CVE-2023-47359"),
];

fn version_parts(v: &str) -> Vec<u64> {
    v.split(|c: char| !c.is_ascii_digit())
        .filter(|p| !p.is_empty())
        .map(|p| p.parse().unwrap_or(0))
        .collect()
}

fn older(have: &str, fixed: &str) -> bool {
    let (a, b) = (version_parts(have), version_parts(fixed));
    if a.is_empty() {
        return false;
    }
    for i in 0..a.len().max(b.len()) {
        let (x, y) = (
            a.get(i).copied().unwrap_or(0),
            b.get(i).copied().unwrap_or(0),
        );
        if x != y {
            return x < y;
        }
    }
    false
}

fn hard_028(m: &Model) -> CheckResult {
    each_ep(
        m,
        "EP-HARD-028",
        "No installed software is older than the fix for a known exploited vulnerability",
        Scope::All,
        |ep| {
            let sw = need!(list(ep, "software"));
            let mut found: Vec<String> = sw
                .iter()
                .filter_map(|p| {
                    let name = p.s("name").unwrap_or_default().to_ascii_lowercase();
                    let version = p.s("version").unwrap_or_default();
                    VULNERABLE_SOFTWARE
                        .iter()
                        .find(|(n, fixed, _)| name.starts_with(n) && older(version, fixed))
                        .map(|(_, fixed, cve)| {
                            format!(
                                "{} {version} ({cve}, fixed in {fixed})",
                                p.s("name").unwrap_or_default()
                            )
                        })
                })
                .collect();
            found.sort();
            found.dedup();
            if found.is_empty() {
                Eval::Ok(format!(
                    "{} checked",
                    plural(sw.len(), "package", "packages")
                ))
            } else {
                Eval::Bad(found.join("; "))
            }
        },
    )
    .done()
}

fn hard_036(m: &Model) -> CheckResult {
    each_ep(
        m,
        "EP-HARD-036",
        "No saved Credential Manager entries on servers",
        Scope::Servers,
        |ep| match ep.part("credential_files").and_then(Value::as_i64) {
            None => Eval::Unknown(ep.why("credential_files")),
            Some(0) => Eval::Ok("none".into()),
            Some(n) => {
                Eval::Bad(format!(
                "{}: an admin who signs in can read them, and with them other accounts' passwords",
                plural(n as usize, "saved credential file", "saved credential files")
            ))
            }
        },
    )
    .done()
}

fn hard_045(m: &Model) -> CheckResult {
    each_ep(
        m,
        "EP-HARD-045",
        "Workstations use Windows Hello for Business or require smart cards",
        Scope::Workstations,
        |ep| {
            need!(registry(ep));
            let whfb = ep.reg_int("passportforwork.enabled") == Some(1);
            let sc = ep.reg_int("system.scforceoption") == Some(1);
            match (whfb, sc) {
                (false, false) => Eval::Bad("Neither Windows Hello for Business nor smart card sign-in is required: users sign in with a password only".into()),
                _ => Eval::Ok(format!(
                    "{}{}",
                    if whfb { "Windows Hello for Business" } else { "" },
                    if sc { " smart card required" } else { "" }
                )),
            }
        },
    )
    .done()
}

/// Domain principals in the local Administrators group that are not Tier 0.
fn non_tier0_admins(m: &Model, ep: &Endpoint) -> Result<Vec<String>, Eval> {
    let members = list(ep, "local_admins")?;
    Ok(members
        .iter()
        .filter_map(|mbr| {
            let sid = mbr.s("sid")?;
            if !sid.starts_with(&m.domain_sid) || m.is_default_admin(sid) {
                return None;
            }
            let tier0 = m.by_sid(sid).is_some_and(|i| m.nodes[i].tier0);
            (!tier0).then(|| mbr.s("name").unwrap_or(sid).to_string())
        })
        .collect())
}

fn has_software(ep: &Endpoint, words: &[&str]) -> Option<String> {
    ep.part("software")?.as_array()?.iter().find_map(|p| {
        let n = p.s("name")?;
        let l = n.to_ascii_lowercase();
        words.iter().any(|w| l.contains(w)).then(|| n.to_string())
    })
}

fn tier0_role_admins(
    m: &Model,
    id: &str,
    expected: &str,
    role: impl Fn(&Endpoint) -> Option<String>,
) -> CheckResult {
    each_ep(m, id, expected, Scope::Servers, |ep| {
        let Some(what) = role(ep) else {
            return Eval::Ok("not this kind of server".into());
        };
        match non_tier0_admins(m, ep) {
            Err(e) => e,
            Ok(extra) if extra.is_empty() => Eval::Ok(format!("{what}; local admins are Tier 0")),
            Ok(extra) => Eval::Bad(format!(
                "{what}; local admins outside Tier 0: {}",
                extra.join(", ")
            )),
        }
    })
    .done()
}

fn t0_004(m: &Model) -> CheckResult {
    tier0_role_admins(
        m,
        "EP-T0-004",
        "Jump servers and privileged access workstations are administered only by Tier 0",
        |ep| {
            let n = ep.short();
            ["jump", "paw", "bastion", "adminhost", "admin-"]
                .iter()
                .any(|w| n.contains(w))
                .then(|| "Jump server or PAW (by name)".to_string())
        },
    )
}

fn t0_005(m: &Model) -> CheckResult {
    tier0_role_admins(
        m,
        "EP-T0-005",
        "Backup servers that hold DC backups are administered only by Tier 0",
        |ep| {
            has_software(
                ep,
                &[
                    "veeam",
                    "commvault",
                    "netbackup",
                    "backup exec",
                    "rubrik",
                    "cohesity",
                    "acronis",
                    "arcserve",
                    "networker",
                    "data protection manager",
                ],
            )
            .map(|s| format!("Backup server ({s})"))
        },
    )
}

fn t0_006(m: &Model) -> CheckResult {
    tier0_role_admins(
        m,
        "EP-T0-006",
        "Hypervisor hosts and their management servers are administered only by Tier 0",
        |ep| {
            if ep.service_active("vmms") == Some(true) {
                return Some("Hyper-V host".to_string());
            }
            has_software(ep, &["vcenter", "system center virtual machine manager"])
                .map(|s| format!("Virtualization management ({s})"))
        },
    )
}

pub static RULES: &[Rule] = &[
    Rule {
        id: "AD-CMP-005",
        needs: &["endpoints"],
        run: cmp_005,
    },
    Rule {
        id: "AD-CMP-009",
        needs: &["endpoints"],
        run: cmp_009,
    },
    Rule {
        id: "EP-HARD-028",
        needs: &["endpoints"],
        run: hard_028,
    },
    Rule {
        id: "EP-HARD-036",
        needs: &["endpoints"],
        run: hard_036,
    },
    Rule {
        id: "EP-HARD-045",
        needs: &["endpoints"],
        run: hard_045,
    },
    Rule {
        id: "EP-T0-004",
        needs: &["endpoints", "groups"],
        run: t0_004,
    },
    Rule {
        id: "EP-T0-005",
        needs: &["endpoints", "groups"],
        run: t0_005,
    },
    Rule {
        id: "EP-T0-006",
        needs: &["endpoints", "groups"],
        run: t0_006,
    },
    rule("EP-HARD-001", hard_001),
    rule("EP-HARD-002", hard_002),
    rule("EP-HARD-003", hard_003),
    rule("EP-HARD-004", hard_004),
    rule("EP-HARD-005", hard_005),
    rule("EP-HARD-006", hard_006),
    rule("EP-HARD-007", hard_007),
    rule("EP-HARD-008", hard_008),
    rule("EP-HARD-009", hard_009),
    rule("EP-HARD-010", hard_010),
    rule("EP-HARD-011", hard_011),
    rule("EP-HARD-012", hard_012),
    rule("EP-HARD-013", hard_013),
    rule("EP-HARD-014", hard_014),
    rule("EP-HARD-015", hard_015),
    rule("EP-HARD-016", hard_016),
    rule("EP-HARD-017", hard_017),
    rule("EP-HARD-018", hard_018),
    rule("EP-HARD-019", hard_019),
    rule("EP-HARD-020", hard_020),
    rule("EP-HARD-021", hard_021),
    rule("EP-HARD-022", hard_022),
    rule("EP-HARD-023", hard_023),
    rule("EP-HARD-024", hard_024),
    rule("EP-HARD-025", hard_025),
    rule("EP-HARD-026", hard_026),
    rule("EP-HARD-027", hard_027),
    rule("EP-HARD-029", hard_029),
    rule("EP-HARD-030", hard_030),
    rule("EP-HARD-031", hard_031),
    rule("EP-HARD-032", hard_032),
    rule("EP-HARD-033", hard_033),
    rule("EP-HARD-034", hard_034),
    rule("EP-HARD-035", hard_035),
    rule("EP-HARD-037", hard_037),
    rule("EP-HARD-038", hard_038),
    rule("EP-HARD-039", hard_039),
    rule("EP-HARD-040", hard_040),
    rule("EP-HARD-041", hard_041),
    rule("EP-HARD-042", hard_042),
    rule("EP-HARD-043", hard_043),
    rule("EP-HARD-044", hard_044),
    rule("EP-HARD-046", hard_046),
];
