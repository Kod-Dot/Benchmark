//! Endpoint rules against the test domain plus `endpoints.jsonl` written the
//! way Invoke-DCACollect.ps1 writes it: one reply per machine.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use serde_json::{json, Value};

use super::raw::RawDomain;
use super::tests::{sid, write_domain};
use crate::results::{CheckResult, ResultStatus};

/// A hardened workstation's reply; `change` edits it.
pub(crate) fn reply(product_type: i64, change: impl Fn(&mut Value)) -> Value {
    let mut d = json!({
        "os": {"caption": "Microsoft Windows 11 Enterprise", "version": "10.0.26100", "build": 26100,
               "product_type": product_type, "last_boot": "2026-10-01T08:00:00Z"},
        "hotfixes": {"count": 12, "last": "2026-09-20T00:00:00Z", "last_id": "KB5065000"},
        "services": [
            {"name": "Sense", "state": "Running", "start": "Auto", "account": "LocalSystem", "unquoted": false, "writable": false},
            {"name": "WebClient", "state": "Stopped", "start": "Manual", "account": "NT AUTHORITY\\LocalService", "unquoted": false, "writable": false},
            {"name": "Spooler", "state": "Stopped", "start": "Disabled", "account": "LocalSystem", "unquoted": false, "writable": false},
        ],
        "registry": {
            "lsa.runasppl": 1, "lsa.lmcompatibilitylevel": 5, "lsa.restrictanonymous": 1, "lsa.restrictanonymoussam": 1,
            "lsa.everyoneincludesanonymous": 0, "winlogon.cachedlogonscount": "2", "winlogon.autoadminlogon": "0",
            "winlogon.defaultpassword_present": false, "dnsclient.enablemulticast": 0, "winhttp.disablewpad": 1,
            "rdp.fdenytsconnections": 1, "powershell.enablescriptblocklogging": 1, "uac.enablelua": 1,
            "uac.consentpromptbehavioradmin": 2, "laps.backupdirectory": 2,
            "schannel.tls10.enabled": 0, "schannel.tls11.enabled": 0,
        },
        "netbios": [2],
        "firewall": [{"name": "Domain", "enabled": true, "inbound": "NotConfigured"},
                     {"name": "Private", "enabled": true, "inbound": "Block"},
                     {"name": "Public", "enabled": true, "inbound": "Block"}],
        "smb": {"smb1": false, "require_signing": true, "client_require_signing": true},
        "shares": [],
        "local_admins": [{"name": "WS01\\Administrator", "sid": "S-1-5-21-9-9-9-500", "class": "User", "source": "Local"},
                         {"name": "CORP\\Domain Admins", "sid": sid(512), "class": "Group", "source": "ActiveDirectory"}],
        "local_users": [{"name": "Administrator", "sid": "S-1-5-21-9-9-9-500", "enabled": true},
                        {"name": "Guest", "sid": "S-1-5-21-9-9-9-501", "enabled": false}],
        "device_guard": {"vbs": 2, "running": [1, 2], "ci_policy": 2, "umci_policy": 2},
        "bitlocker": {"protection": 1},
        "secure_boot": true,
        "tpm": {"present": true, "enabled": true},
        "defender": {"enabled": true, "realtime": true, "signature_age": 1, "tamper": true, "exclusions": [],
                     "asr": {"9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2": 1, "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550": 1,
                             "d4f940ab-401b-4efc-aadc-ad5f3c50688a": 1, "3b576869-a4ec-4529-8536-b80a7769e899": 6,
                             "5beb7efe-fd9a-4556-801d-275e5ffc04cc": 1}},
        "psv2": false,
        "winrm_listeners": [{"transport": "HTTP", "address": "*"}],
        "applocker": [],
        "tasks": [],
        "autoruns": [],
        "path_writable": [],
        "sessions": ["WS01\\localuser"],
        "audit": {
            "0CCE9215-69AE-11D9-BED3-505054503030": "Success and Failure",
            "0CCE921B-69AE-11D9-BED3-505054503030": "Success",
            "0CCE922B-69AE-11D9-BED3-505054503030": "Success",
            "0CCE9235-69AE-11D9-BED3-505054503030": "Success and Failure",
            "0CCE9237-69AE-11D9-BED3-505054503030": "Success and Failure",
            "0CCE923F-69AE-11D9-BED3-505054503030": "Success and Failure",
        },
        "security_log": {"max_bytes": 1_073_741_824i64, "mode": "Circular"},
        "errors": {},
        "now": "2026-10-06T09:00:00.000Z",
    });
    change(&mut d);
    d
}

pub(crate) fn write_endpoints(dir: &Path) {
    let good = reply(1, |_| {});
    let weak = reply(3, |d| {
        d["os"] = json!({"caption": "Microsoft Windows Server 2012 R2 Standard", "build": 9600, "product_type": 3});
        d["hotfixes"]["last"] = json!("2026-05-01T00:00:00Z");
        d["services"] = json!([
            {"name": "Spooler", "state": "Running", "start": "Auto", "account": "LocalSystem", "unquoted": false, "writable": false},
            {"name": "BackupAgent", "state": "Running", "start": "Auto", "account": "CORP\\adm-jsmith",
             "unquoted": true, "writable": false},
            {"name": "WebClient", "state": "Running", "start": "Auto", "account": "NT AUTHORITY\\LocalService", "unquoted": false, "writable": false},
            {"name": "adfssrv", "state": "Running", "start": "Auto", "account": "CORP\\svc-adfs", "unquoted": false, "writable": false},
        ]);
        d["software"] =
            json!([{"name": "Google Chrome", "publisher": "Google LLC", "version": "129.0"}]);
        let r = &mut d["registry"];
        r["lsa.runasppl"] = Value::Null;
        r["lsa.lmcompatibilitylevel"] = Value::Null;
        r["winlogon.cachedlogonscount"] = Value::Null;
        r["winlogon.autoadminlogon"] = json!("1");
        r["winlogon.defaultusername"] = json!("kiosk");
        r["winlogon.defaultpassword_present"] = json!(true);
        r["dnsclient.enablemulticast"] = Value::Null;
        r["laps.backupdirectory"] = Value::Null;
        r["rdp.fdenytsconnections"] = json!(0);
        r["uac.localaccounttokenfilterpolicy"] = json!(1);
        r["installer.alwaysinstallelevated"] = json!(1);
        r["schannel.tls10.enabled"] = Value::Null;
        d["netbios"] = json!([0, 2]);
        d["smb"] = json!({"smb1": true, "require_signing": false, "client_require_signing": true});
        d["local_admins"].as_array_mut().unwrap().push(json!({"name": "CORP\\Domain Users", "sid": sid(513), "class": "Group", "source": "ActiveDirectory"}));
        d["local_users"][1]["enabled"] = json!(true);
        d["device_guard"] = json!({"vbs": 0, "running": [], "ci_policy": 0, "umci_policy": 0});
        d["defender"]["exclusions"] = json!(["C:\\Backup", "backup.exe"]);
        d["defender"]["asr"] = json!({});
        d["tasks"] =
            json!([{"name": "\\Nightly copy", "user": "CORP\\adm-jsmith", "logon": "Password"}]);
        d["sessions"] = json!(["CORP\\adm-jsmith", "CORP\\jdoe"]);
        d["shares"] =
            json!([{"name": "Drop", "path": "D:\\Drop", "broad_write": ["Everyone: Full"]}]);
        d["path_writable"] = json!(["C:\\Tools"]);
        d["firewall"][2]["enabled"] = json!(false);
        d["psv2"] = json!(true);
        d["errors"] = json!({"defender": "Invalid class"});
        d["defender"] = Value::Null;
    });
    let lines = [
        json!({"name": "ws01.corp.example.com", "read_at": "2026-10-06T09:00:01Z", "data": good}),
        json!({"name": "srv01.corp.example.com", "read_at": "2026-10-06T09:00:01Z", "data": weak}),
        json!({"name": "ws02.corp.example.com", "error": "WinRM cannot complete the operation."}),
    ];
    let text: String = lines.iter().map(|l| format!("{l}\n")).collect();
    fs::write(dir.join("endpoints.jsonl"), text).unwrap();
    // dc01 is a Configuration Manager client and runs TeamViewer.
    let dcs = fs::read_to_string(dir.join("dcconfig.jsonl")).unwrap();
    let patched: String = dcs
        .lines()
        .map(|l| {
            let mut v: Value = serde_json::from_str(l).unwrap();
            if v["name"] == "dc01.corp.example.com" {
                let services = v["data"]["services"].as_array_mut().unwrap();
                services.push(json!({"name": "CcmExec", "state": "Running", "start": "Auto"}));
                services.push(json!({"name": "TeamViewer", "state": "Running", "start": "Auto"}));
            }
            format!("{v}\n")
        })
        .collect();
    fs::write(dir.join("dcconfig.jsonl"), patched).unwrap();
    let events = fs::read_to_string(dir.join("events.jsonl")).unwrap();
    fs::write(
        dir.join("events.jsonl"),
        format!(
            "{}\n{events}",
            json!({"type": "done", "area": "endpoints", "count": 2})
        ),
    )
    .unwrap();
}

fn run() -> HashMap<String, CheckResult> {
    let dir = tempfile::tempdir().unwrap();
    write_domain(dir.path(), true);
    write_endpoints(dir.path());
    let raw = RawDomain::load(dir.path()).unwrap();
    let out = super::analyze(&crate::results::tests::catalog(), &raw, &[]);
    out.checks.into_iter().map(|c| (c.id.clone(), c)).collect()
}

fn failed<'a>(r: &'a HashMap<String, CheckResult>, id: &str) -> Vec<&'a str> {
    assert_eq!(r[id].status, ResultStatus::Failed, "{id}: {:?}", r[id]);
    r[id].affected.iter().map(|a| a.name.as_str()).collect()
}

fn reason(r: &HashMap<String, CheckResult>, id: &str) -> String {
    r[id].affected[0].reason.clone().unwrap_or_default()
}

const SRV: &str = "srv01.corp.example.com";

#[test]
fn hardened_workstation_passes_and_weak_server_fails() {
    let r = run();
    for id in [
        "EP-HARD-001",
        "EP-HARD-002",
        "EP-HARD-003",
        "EP-HARD-004",
        "EP-HARD-005",
        "EP-HARD-007",
        "EP-HARD-008",
        "EP-HARD-009",
        "EP-HARD-010",
        "EP-HARD-012",
        "EP-HARD-013",
        "EP-HARD-014",
        "EP-HARD-016",
        "EP-HARD-019",
        "EP-HARD-022",
        "EP-HARD-026",
        "EP-HARD-027",
        "EP-HARD-029",
        "EP-HARD-030",
        "EP-HARD-031",
        "EP-HARD-033",
        "EP-HARD-034",
        "EP-HARD-035",
        "EP-HARD-037",
        "EP-HARD-038",
        "EP-HARD-039",
        "EP-HARD-040",
        "EP-HARD-046",
    ] {
        assert_eq!(failed(&r, id), [SRV], "{id}");
    }
    assert!(reason(&r, "EP-HARD-001").contains("Domain Users"));
    assert!(reason(&r, "EP-HARD-002").contains("Guest"));
    assert!(reason(&r, "EP-HARD-027").contains("Windows Server 2012 R2"));
    assert!(reason(&r, "EP-HARD-029").contains("privileged through Domain Admins"));
    assert!(reason(&r, "EP-HARD-031").contains("adm-jsmith"));
    assert!(reason(&r, "EP-HARD-037").contains("CORP\\adm-jsmith"));
    assert!(!reason(&r, "EP-HARD-037").contains("jdoe"));
    assert!(reason(&r, "EP-HARD-046").contains("kiosk"));
    // The unreachable machine is named, not counted.
    assert!(r["EP-HARD-008"]
        .evidence
        .iter()
        .any(|e| e.label == "Not assessed on" && e.value.contains("ws02")));
}

#[test]
fn scope_and_missing_parts() {
    let r = run();
    // BitLocker and Remote Registry apply to workstations only; the one read passes.
    assert_eq!(r["EP-HARD-020"].status, ResultStatus::Passed);
    assert_eq!(r["EP-HARD-043"].status, ResultStatus::Passed);
    // Defender could not be read on the server, so only the workstation counts.
    assert_eq!(r["EP-HARD-023"].status, ResultStatus::Passed);
    assert!(r["EP-HARD-023"]
        .evidence
        .iter()
        .any(|e| e.value.contains("another antivirus")));
    assert_eq!(r["EP-HARD-042"].status, ResultStatus::Failed);
}

#[test]
fn endpoints_not_collected_are_not_assessed() {
    let dir = tempfile::tempdir().unwrap();
    write_domain(dir.path(), true);
    let raw = RawDomain::load(dir.path()).unwrap();
    let out = super::analyze(&crate::results::tests::catalog(), &raw, &[]);
    let c = out.checks.iter().find(|c| c.id == "EP-HARD-001").unwrap();
    assert_eq!(c.status, ResultStatus::NotAssessed);
}

#[test]
fn tier0_servers_and_agents_on_dcs() {
    let r = run();
    // The base test domain does not collect AD CS.
    assert_eq!(r["EP-T0-001"].status, ResultStatus::NotAssessed);
    assert!(
        r["EP-T0-001"]
            .note
            .as_deref()
            .unwrap()
            .contains("not collected"),
        "{:?}",
        r["EP-T0-001"]
    );
    assert_eq!(r["EP-T0-002"].status, ResultStatus::NotAssessed);
    assert_eq!(failed(&r, "EP-T0-003"), [SRV]);
    assert!(reason(&r, "EP-T0-003").contains("Domain Users"));
    assert_eq!(failed(&r, "EP-T0-007"), ["dc01.corp.example.com"]);
    assert_eq!(failed(&r, "EP-T0-008"), ["dc01.corp.example.com"]);
    assert!(reason(&r, "EP-T0-008").contains("TeamViewer"));
    assert!(failed(&r, "EP-T0-010").contains(&SRV));
}

/// The analysis against a real Windows machine's replies, written by
/// `tools/Read-LocalMachine.ps1` into DCA_LIVE_DIR (CI does this on a
/// Windows Server runner). The replies replace the test domain's endpoints,
/// domain controller configuration and event log counts. A part the machine
/// could not read is fine; a part the rules say "was not returned", or an
/// event query they say was "not queried", means the collector and the
/// analysis disagree on its name or shape, and fails the test.
#[test]
#[ignore = "needs DCA_LIVE_DIR from tools/Read-LocalMachine.ps1"]
fn live_windows_replies_are_understood() {
    let Some(live) = std::env::var_os("DCA_LIVE_DIR") else {
        panic!("set DCA_LIVE_DIR to the folder tools/Read-LocalMachine.ps1 wrote");
    };
    let live = Path::new(&live);
    let dir = tempfile::tempdir().unwrap();
    write_domain(dir.path(), true);
    // The live machine stands in for the test domain's dc01 and ws01, so the
    // rules match its replies to a computer in the directory.
    for (area, host) in [
        ("dcconfig", "dc01.corp.example.com"),
        ("endpoints", "ws01.corp.example.com"),
        ("dcevents", "dc01.corp.example.com"),
    ] {
        let text = fs::read_to_string(live.join(format!("{area}.jsonl")))
            .unwrap_or_else(|e| panic!("{area}.jsonl: {e}"));
        let mut v: Value = serde_json::from_str(text.trim_start_matches('\u{feff}').trim())
            .unwrap_or_else(|e| panic!("{area}.jsonl is not one JSON line: {e}"));
        v["name"] = json!(host);
        fs::write(dir.path().join(format!("{area}.jsonl")), format!("{v}\n")).unwrap();
    }
    // The areas the live replies stand in for, so the rules run on them.
    let events = fs::read_to_string(dir.path().join("events.jsonl")).unwrap();
    fs::write(
        dir.path().join("events.jsonl"),
        format!(
            "{}\n{}\n{events}",
            json!({"type": "done", "area": "endpoints", "count": 1}),
            // No AD CS objects in the test domain: the lab CA publishes no templates.
            json!({"type": "done", "area": "pki", "count": 0})
        ),
    )
    .unwrap();
    let raw = RawDomain::load(dir.path()).expect("the live replies load");
    let out = super::analyze(&crate::results::tests::catalog(), &raw, &[]);

    let mut problems = Vec::new();
    for c in &out.checks {
        let texts = c
            .note
            .iter()
            .chain(c.evidence.iter().map(|e| &e.value))
            .chain(c.affected.iter().filter_map(|a| a.reason.as_ref()));
        let mut mismatch = false;
        for t in texts {
            if t.contains("was not returned") || t.contains("(not queried)") {
                problems.push(format!("{}: {t}", c.id));
                mismatch = true;
            }
        }
        if !(c.id.starts_with("EP-")
            || c.id.starts_with("AD-DC-")
            || c.id.starts_with("AD-LEG-")
            || mismatch)
        {
            continue;
        }
        println!(
            "{:<14} {:?}{}",
            c.id,
            c.status,
            if mismatch { "  <- mismatch" } else { "" }
        );
    }
    assert!(
        problems.is_empty(),
        "parts the analysis did not understand:\n{}",
        problems.join("\n")
    );
    // On a real Windows machine the endpoint rules must actually run, rather
    // than report the reply as not assessed. A machine whose operating system
    // could not even be read (this test run on something other than Windows)
    // has nothing to assess.
    // The checks added for DC hosts and event logs must run on what a real
    // Windows Server returns: its registry, ciphers, hardware, Defender,
    // service accounts, DNS state, and the System and Security logs.
    if raw
        .dcconfig
        .iter()
        .any(|d| d.data.as_ref().is_some_and(|d| d.os.is_some()))
    {
        let status: HashMap<&str, ResultStatus> = out
            .checks
            .iter()
            .map(|c| (c.id.as_str(), c.status))
            .collect();
        let unassessed: Vec<&str> = [
            "AD-DC-008",
            "AD-DC-026",
            "AD-DC-027",
            "AD-IOC-007",
            "AD-LEG-010",
            "AD-DNS-007",
            "AD-AUD-009",
            "AD-BKP-007",
            "AD-BKP-008",
            "HUNT-AD-006",
            "HUNT-AD-007",
            "HUNT-AD-018",
            "HUNT-AD-021",
            "AD-AUD-012",
        ]
        .into_iter()
        .filter(|id| {
            status.get(id) != Some(&ResultStatus::Passed)
                && status.get(id) != Some(&ResultStatus::Failed)
        })
        .collect();
        assert!(
            unassessed.is_empty(),
            "not assessed on the live machine: {unassessed:?}"
        );
    }
    // CI installs a standalone CA with web enrollment over HTTP and ESC6 on
    // before reading the machine: the CA checks must read those settings.
    let ca = raw.dcconfig.iter().any(|d| {
        d.data
            .as_ref()
            .and_then(|d| d.certsvc.as_ref())
            .and_then(|c| c.get("installed"))
            .and_then(Value::as_bool)
            == Some(true)
    });
    if ca {
        let status: HashMap<&str, ResultStatus> = out
            .checks
            .iter()
            .map(|c| (c.id.as_str(), c.status))
            .collect();
        for id in ["AD-PKI-007", "AD-PKI-009", "AD-PKI-022", "AD-PKI-023"] {
            assert_eq!(status[id], ResultStatus::Failed, "{id} on the lab CA");
        }
        for id in ["AD-PKI-008", "AD-PKI-011", "AD-PKI-015", "AD-PKI-024"] {
            assert_ne!(status[id], ResultStatus::NotAssessed, "{id} on the lab CA");
        }
    }
    if raw.endpoints.iter().any(|ep| ep.part("os").is_some()) {
        let assessed = out
            .checks
            .iter()
            .filter(|c| c.id.starts_with("EP-HARD-") && c.status != ResultStatus::NotAssessed)
            .count();
        assert!(
            assessed > 0,
            "the live machine was read but no endpoint hardening check assessed it"
        );
    }
}
