//! End-to-end tests of the on-prem analysis against a small domain written
//! in the collector's own format.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use base64::Engine as _;
use serde_json::{json, Value};

use super::raw::RawDomain;
use super::sd::{build, right};
use crate::catalog::Severity;
use crate::results::{CheckResult, ResultStatus};
use crate::time;

pub(crate) const DOMAIN_DN: &str = "DC=corp,DC=example,DC=com";
const SID: &str = "S-1-5-21-1000-2000-3000";
const NOW: &str = "2026-10-05T12:00:00Z";
const DDP: &str = "{31B2F340-016D-11D2-945F-00C04FB984F9}";
const DDCP: &str = "{6AC1786C-016F-11D2-945F-00C04FB984F9}";

pub(crate) fn sid(rid: u32) -> String {
    format!("{SID}-{rid}")
}

pub(crate) fn ft_days_ago(days: i64) -> i64 {
    let now = time::parse_iso(NOW).unwrap();
    (now - days * time::DAY + 11_644_473_600) * 10_000_000
}

pub(crate) fn iso_days_ago(days: i64) -> String {
    time::iso(time::parse_iso(NOW).unwrap() - days * time::DAY)
}

pub(crate) fn dn(cn: &str, under: &str) -> String {
    format!("{cn},{under}")
}

/// Wraps every value in an array, as the collector writes them.
pub(crate) fn obj(attrs: Value) -> Value {
    let map = attrs.as_object().unwrap();
    Value::Object(
        map.iter()
            .map(|(k, v)| (k.clone(), if v.is_array() { v.clone() } else { json!([v]) }))
            .collect(),
    )
}

pub(crate) fn user(
    name: &str,
    rid: u32,
    uac: u32,
    pwd_days: i64,
    logon_days: Option<i64>,
    extra: Value,
) -> Value {
    let mut o = json!({
        "distinguishedname": dn(&format!("CN={name}"), &format!("CN=Users,{DOMAIN_DN}")),
        "samaccountname": name,
        "objectsid": sid(rid),
        "useraccountcontrol": uac,
        "pwdlastset": ft_days_ago(pwd_days),
        "primarygroupid": 513,
        "whencreated": iso_days_ago(1000),
    });
    if let Some(d) = logon_days {
        o["lastlogontimestamp"] = json!(ft_days_ago(d));
    }
    for (k, v) in extra.as_object().unwrap() {
        o[k] = v.clone();
    }
    obj(o)
}

pub(crate) fn group(name: &str, sid: &str, under: &str, members: &[String]) -> Value {
    obj(json!({
        "distinguishedname": dn(&format!("CN={name}"), under),
        "samaccountname": name,
        "objectsid": sid,
        "member": members,
    }))
}

fn acl(dn: &str, class: &str, sd: Vec<u8>) -> Value {
    obj(json!({
        "distinguishedname": dn,
        "objectclass": ["top", class],
        "ntsecuritydescriptor": base64::engine::general_purpose::STANDARD.encode(sd),
    }))
}

fn write(dir: &Path, area: &str, objects: &[Value]) {
    let text: String = objects.iter().map(|o| format!("{o}\n")).collect();
    fs::write(dir.join(format!("{area}.jsonl")), text).unwrap();
}

/// A small domain with one instance of most problems the rules look for.
pub fn write_domain(dir: &Path, sysvol: bool) {
    fs::create_dir_all(dir).unwrap();
    let users_dn = format!("CN=Users,{DOMAIN_DN}");
    let builtin_dn = format!("CN=Builtin,{DOMAIN_DN}");
    let dc_ou = format!("OU=Domain Controllers,{DOMAIN_DN}");
    let system = format!("CN=System,{DOMAIN_DN}");
    let policies = format!("CN=Policies,{system}");
    let u = |name: &str| dn(&format!("CN={name}"), &users_dn);

    fs::write(
        dir.join("collection.json"),
        json!({
            "domain": "corp.example.com",
            "server": "DC01.corp.example.com",
            "account": "CORP\\auditor",
            "computer": "AUDIT01",
            "started_at": "2026-10-05T11:50:00Z",
            "sources": if sysvol { json!(["ldap", "sysvol"]) } else { json!(["ldap"]) },
            "rootdse": {
                "defaultnamingcontext": DOMAIN_DN,
                "forestfunctionality": "7",
                "domainfunctionality": "6",
            }
        })
        .to_string(),
    )
    .unwrap();

    write(
        dir,
        "domain",
        &[obj(json!({
            "distinguishedname": DOMAIN_DN,
            "name": "corp",
            "objectsid": SID,
            "ms-ds-machineaccountquota": 10,
            "minpwdlength": 7,
            "pwdhistorylength": 24,
            "pwdproperties": 1,
            "maxpwdage": -36_288_000_000_000i64,
            "lockoutthreshold": 0,
            "gplink": format!("[LDAP://cn={DDP},{policies};0]"),
            "fsmoroleowner": "CN=NTDS Settings,CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=corp,DC=example,DC=com",
            "msds-replattributemetadata": [
                "<DS_REPL_ATTR_META_DATA>\n\t<pszAttributeName>objectSid</pszAttributeName>\n\t<ftimeLastOriginatingChange>2024-01-09T08:00:00Z</ftimeLastOriginatingChange>\n</DS_REPL_ATTR_META_DATA>",
                "<DS_REPL_ATTR_META_DATA>\n\t<pszAttributeName>dSASignature</pszAttributeName>\n\t<dwVersion>12</dwVersion>\n\t<ftimeLastOriginatingChange>2026-07-01T02:00:00Z</ftimeLastOriginatingChange>\n</DS_REPL_ATTR_META_DATA>",
            ],
        }))],
    );
    write(
        dir,
        "partitions",
        &[obj(
            json!({"distinguishedname": "CN=Partitions,CN=Configuration,DC=corp,DC=example,DC=com", "objectclass": ["top", "crossRefContainer"], "msds-behavior-version": 7}),
        )],
    );
    write(
        dir,
        "dirservice",
        &[obj(
            json!({"distinguishedname": "CN=Directory Service", "tombstonelifetime": 180, "dsheuristics": "0000002"}),
        )],
    );
    write(
        dir,
        "schema",
        &[
            obj(
                json!({"distinguishedname": "CN=Schema", "objectclass": ["top", "dMD"], "objectversion": 88}),
            ),
            obj(
                json!({"distinguishedname": "CN=ms-Mcs-AdmPwd,CN=Schema", "ldapdisplayname": "ms-Mcs-AdmPwd"}),
            ),
            obj(
                json!({"distinguishedname": "CN=ms-Mcs-AdmPwdExpirationTime,CN=Schema", "ldapdisplayname": "ms-Mcs-AdmPwdExpirationTime"}),
            ),
        ],
    );
    write(
        dir,
        "containers",
        &[
            obj(
                json!({"distinguishedname": users_dn, "name": "Users", "objectclass": ["top", "container"]}),
            ),
            obj(
                json!({"distinguishedname": builtin_dn, "name": "Builtin", "objectclass": ["top", "builtinDomain"]}),
            ),
            obj(
                json!({"distinguishedname": dc_ou, "name": "Domain Controllers", "objectclass": ["top", "organizationalUnit"], "gplink": format!("[LDAP://cn={DDCP},{policies};0][LDAP://cn={{00000000-0000-0000-0000-000000000000}},{policies};0]")}),
            ),
            obj(
                json!({"distinguishedname": format!("OU=Servers,{DOMAIN_DN}"), "name": "Servers", "objectclass": ["top", "organizationalUnit"]}),
            ),
            obj(
                json!({"distinguishedname": system, "name": "System", "objectclass": ["top", "container"]}),
            ),
            obj(
                json!({"distinguishedname": format!("CN=AdminSDHolder,{system}"), "name": "AdminSDHolder", "objectclass": ["top", "container"]}),
            ),
        ],
    );

    const NORMAL: u32 = 0x200;
    const DISABLED: u32 = 0x202;
    write(
        dir,
        "users",
        &[
            user(
                "Administrator",
                500,
                NORMAL,
                400,
                Some(10),
                json!({"admincount": 1}),
            ),
            user(
                "Guest",
                501,
                DISABLED | 0x20,
                3000,
                None,
                json!({"primarygroupid": 514}),
            ),
            user(
                "krbtgt",
                502,
                DISABLED,
                900,
                None,
                json!({"admincount": 1, "serviceprincipalname": ["kadmin/changepw"]}),
            ),
            user(
                "adm-jsmith",
                1101,
                NORMAL,
                100,
                Some(1),
                json!({"admincount": 1}),
            ),
            user(
                "adm-old",
                1102,
                DISABLED,
                800,
                Some(500),
                json!({"admincount": 1}),
            ),
            user(
                "svc-sql",
                1103,
                NORMAL | 0x10000,
                2000,
                Some(2),
                json!({"serviceprincipalname": ["MSSQLSvc/sql01.corp.example.com:1433"], "description": "SQL service pwd: Summer2019"}),
            ),
            user("helpdesk-lead", 1107, NORMAL, 30, Some(1), json!({})),
            user("jdoe", 1108, NORMAL | 0x400000, 200, Some(200), json!({})),
            user(
                "newbie",
                1109,
                NORMAL,
                0,
                None,
                json!({"pwdlastset": 0, "whencreated": iso_days_ago(60)}),
            ),
            user(
                "former-admin",
                1112,
                NORMAL,
                20,
                Some(3),
                json!({"admincount": 1}),
            ),
        ],
    );
    write(
        dir,
        "computers",
        &[
            obj(json!({
                "distinguishedname": dn("CN=DC01", &dc_ou), "samaccountname": "DC01$", "objectsid": sid(1000),
                "useraccountcontrol": 0x82000, "primarygroupid": 516, "pwdlastset": ft_days_ago(10),
                "lastlogontimestamp": ft_days_ago(1), "dnshostname": "dc01.corp.example.com",
                "operatingsystem": "Windows Server 2022 Datacenter", "operatingsystemversion": "10.0 (20348)",
            })),
            obj(json!({
                "distinguishedname": dn("CN=APP01", &format!("OU=Servers,{DOMAIN_DN}")), "samaccountname": "APP01$", "objectsid": sid(1110),
                "useraccountcontrol": 0x81000, "primarygroupid": 515, "pwdlastset": ft_days_ago(200),
                "lastlogontimestamp": ft_days_ago(5), "operatingsystem": "Windows Server 2012 R2 Standard",
                "msds-allowedtodelegateto": ["ldap/dc01.corp.example.com"],
            })),
            obj(json!({
                "distinguishedname": dn("CN=WS01", &format!("CN=Computers,{DOMAIN_DN}")), "samaccountname": "WS01$", "objectsid": sid(1111),
                "useraccountcontrol": 0x1000, "primarygroupid": 515, "pwdlastset": ft_days_ago(12),
                "lastlogontimestamp": ft_days_ago(2), "operatingsystem": "Windows 11 Enterprise",
                "ms-mcs-admpwdexpirationtime": ft_days_ago(-20), "ms-ds-creatorsid": sid(1108),
            })),
        ],
    );
    write(
        dir,
        "groups",
        &[
            group(
                "Domain Admins",
                &sid(512),
                &users_dn,
                &[u("Administrator"), u("adm-jsmith"), u("IT Admins")],
            ),
            group(
                "Enterprise Admins",
                &sid(519),
                &users_dn,
                &[u("Administrator")],
            ),
            group("Schema Admins", &sid(518), &users_dn, &[]),
            group("Domain Users", &sid(513), &users_dn, &[]),
            group("Domain Computers", &sid(515), &users_dn, &[]),
            group("Domain Controllers", &sid(516), &users_dn, &[]),
            group("Protected Users", &sid(525), &users_dn, &[u("adm-jsmith")]),
            group("DnsAdmins", &sid(1104), &users_dn, &[]),
            group("IT Admins", &sid(1105), &users_dn, &[u("adm-old")]),
            group("Helpdesk", &sid(1106), &users_dn, &[u("helpdesk-lead")]),
            group(
                "Administrators",
                "S-1-5-32-544",
                &builtin_dn,
                &[
                    u("Domain Admins"),
                    u("Enterprise Admins"),
                    u("Administrator"),
                ],
            ),
            group(
                "Account Operators",
                "S-1-5-32-548",
                &builtin_dn,
                &[u("helpdesk-lead")],
            ),
            group(
                "Pre-Windows 2000 Compatible Access",
                "S-1-5-32-554",
                &builtin_dn,
                &[format!(
                    "CN=S-1-5-11,CN=ForeignSecurityPrincipals,{DOMAIN_DN}"
                )],
            ),
        ],
    );
    write(
        dir,
        "gpos",
        &[
            obj(
                json!({"distinguishedname": dn(&format!("CN={DDP}"), &policies), "displayname": "Default Domain Policy"}),
            ),
            obj(
                json!({"distinguishedname": dn(&format!("CN={DDCP}"), &policies), "displayname": "Default Domain Controllers Policy"}),
            ),
        ],
    );
    write(
        dir,
        "trusts",
        &[obj(json!({
            "distinguishedname": dn("CN=partner.example.org", &system), "trustpartner": "partner.example.org",
            "trustdirection": 3, "trusttype": 2, "trustattributes": 0, "whenchanged": iso_days_ago(5),
        }))],
    );

    let da = sid(512);
    let helpdesk = sid(1106);
    let default = |extra: &[(bool, u8, u32, Option<&str>, &str)]| {
        let mut aces = vec![
            (true, 0u8, right::GENERIC_ALL, None, "S-1-5-18"),
            (true, 0, right::GENERIC_ALL, None, da.as_str()),
        ];
        aces.extend_from_slice(extra);
        build::sd(&da, &aces)
    };
    let svc = sid(1103);
    let du = sid(513);
    write(
        dir,
        "acls",
        &[
            acl(
                DOMAIN_DN,
                "domainDNS",
                default(&[
                    (
                        true,
                        0,
                        right::CONTROL_ACCESS,
                        Some(super::model::guid::GET_CHANGES),
                        svc.as_str(),
                    ),
                    (
                        true,
                        0,
                        right::CONTROL_ACCESS,
                        Some(super::model::guid::GET_CHANGES_ALL),
                        svc.as_str(),
                    ),
                    // Inherit-only: applies to children, not the domain head.
                    (true, 0x0a, right::GENERIC_ALL, None, helpdesk.as_str()),
                ]),
            ),
            acl(
                &format!("CN=AdminSDHolder,{system}"),
                "container",
                default(&[(true, 0, right::GENERIC_ALL, None, helpdesk.as_str())]),
            ),
            acl(&u("Domain Admins"), "group", default(&[])),
            acl(
                &u("IT Admins"),
                "group",
                default(&[(
                    true,
                    0,
                    right::WRITE_PROP,
                    Some(super::model::guid::MEMBER),
                    du.as_str(),
                )]),
            ),
            acl(
                &u("adm-jsmith"),
                "user",
                default(&[(
                    true,
                    0,
                    right::CONTROL_ACCESS,
                    Some(super::model::guid::FORCE_CHANGE_PASSWORD),
                    helpdesk.as_str(),
                )]),
            ),
            acl(
                &dn(&format!("CN={DDCP}"), &policies),
                "groupPolicyContainer",
                default(&[(true, 0, right::WRITE_PROP, None, helpdesk.as_str())]),
            ),
            acl(&dc_ou, "organizationalUnit", default(&[])),
            acl(
                &dn("CN=DC01", &dc_ou),
                "computer",
                default(&[(
                    true,
                    0,
                    right::WRITE_PROP,
                    Some(super::model::guid::KEY_CREDENTIAL_LINK),
                    &format!("{SID}-9999"),
                )]),
            ),
        ],
    );
    if sysvol {
        let lines = [
            json!({"folder": DDP, "cpasswords": [{"file": "Machine\\Preferences\\Groups\\Groups.xml", "element": "User", "user": "LocalAdmin"}]}),
            json!({"folder": DDCP, "cpasswords": []}),
            json!({"folder": "{11111111-2222-3333-4444-555555555555}", "cpasswords": []}),
        ];
        fs::write(
            dir.join("sysvol.jsonl"),
            lines.iter().map(|l| format!("{l}\n")).collect::<String>(),
        )
        .unwrap();
    }

    let mut events: Vec<Value> = super::raw::LDAP_AREAS
        .iter()
        .map(|a| json!({"type": "done", "area": a, "count": 1}))
        .collect();
    if sysvol {
        events.push(json!({"type": "done", "area": "sysvol", "count": 3}));
        write_dc_data(dir);
        events.push(json!({"type": "done", "area": "dcconfig", "count": 2}));
        events.push(json!({"type": "done", "area": "dcevents", "count": 2}));
    }
    events.push(json!({"type": "finished", "finished_at": NOW}));
    fs::write(
        dir.join("events.jsonl"),
        events.iter().map(|e| format!("{e}\n")).collect::<String>(),
    )
    .unwrap();
}

/// Three DCs: dc01 (the PDC emulator) with most problems, dc02 hardened but
/// with a drifting clock, dc03 unreachable.
pub(crate) fn write_dc_data(dir: &Path) {
    const GB: i64 = 1 << 30;
    let read_at = NOW;
    let all_audit: serde_json::Map<String, Value> = [
        "0CCE923F", "0CCE9242", "0CCE9240", "0CCE9236", "0CCE923A", "0CCE9237", "0CCE9235",
        "0CCE923B", "0CCE923C", "0CCE9217", "0CCE9215", "0CCE921B", "0CCE922F", "0CCE9230",
        "0CCE9228", "0CCE9211", "0CCE9212", "0CCE922B",
    ]
    .iter()
    .map(|g| {
        (
            format!("{g}-69AE-11D9-BED3-505054503030"),
            json!("Success and Failure"),
        )
    })
    .collect();
    let dc01 = json!({
        "name": "dc01.corp.example.com", "read_at": read_at,
        "data": {
            "os": {"caption": "Microsoft Windows Server 2022 Datacenter", "version": "10.0.20348", "build": 20348, "last_boot": iso_days_ago(90)},
            "hotfixes": {"count": 20, "last": iso_days_ago(100), "last_id": "KB5040437"},
            "services": [
                {"name": "Spooler", "state": "Running", "start": "Auto"},
                {"name": "WebClient", "state": "Stopped", "start": "Manual"},
                {"name": "NTDS", "state": "Running", "start": "Auto"},
            ],
            "registry": {
                "ntds.ldapserverintegrity": 1, "ntds.ldapenforcechannelbinding": 1,
                "ntds.database": "C:\\Windows\\NTDS\\ntds.dit", "ntds.logs": "C:\\Windows\\NTDS",
                "netlogon.sysvol": "C:\\Windows\\SYSVOL\\sysvol", "lsa.lmcompatibilitylevel": 3,
                "lsa.restrictanonymoussam": 1, "lsa.dsrmadminlogonbehavior": 2, "wdigest.uselogoncredential": 1,
                "rdp.fdenytsconnections": 0, "rdp.userauthentication": 0, "w32time.type": "NT5DS",
                "w32time.ntpserver": "time.windows.com,0x8", "dns.serverlevelplugindll": "C:\\Windows\\Temp\\x.dll",
                "netlogon.auditntlmindomain": 0,
            },
            "netbios": [0],
            "firewall": [{"name": "Domain", "enabled": true}, {"name": "Private", "enabled": true}, {"name": "Public", "enabled": false}],
            "features": ["AD-Domain-Services", "DNS", "Web-Server"],
            "smb": {"smb1": true, "require_signing": false, "audit_smb1": false},
            "shares": ["ADMIN$", "C$", "IPC$", "NETLOGON", "SYSVOL"],
            "audit": {"0CCE923F-69AE-11D9-BED3-505054503030": "Success"},
            "security_log": {"max_bytes": 128 * (1 << 20), "mode": "Circular", "records": 1000},
            "disks": [{"drive": "C:", "size": 100 * GB, "free": 3 * GB}],
            "certificates": [],
            "credential_guard": [],
            "errors": {},
            "now": read_at,
        }
    });
    let dc02 = json!({
        "name": "dc02.corp.example.com", "read_at": read_at,
        "data": {
            "os": {"caption": "Microsoft Windows Server 2019 Standard", "version": "10.0.17763", "build": 17763, "last_boot": iso_days_ago(10)},
            "hotfixes": {"count": 40, "last": iso_days_ago(10), "last_id": "KB5041578"},
            "services": [
                {"name": "Spooler", "state": "Stopped", "start": "Disabled"},
                {"name": "AATPSensor", "state": "Running", "start": "Auto"},
            ],
            "registry": {
                "ntds.ldapserverintegrity": 2, "ntds.ldapenforcechannelbinding": 2, "ntds.strictreplication": 1,
                "ntds.database": "D:\\NTDS\\ntds.dit", "ntds.logs": "D:\\NTDS", "netlogon.sysvol": "D:\\SYSVOL\\sysvol",
                "lsa.lmcompatibilitylevel": 5, "lsa.runasppl": 1, "lsa.dsrmadminlogonbehavior": 0,
                "rdp.fdenytsconnections": 1, "w32time.type": "NT5DS", "dnsclient.enablemulticast": 0,
                "schannel.tls10.enabled": 0, "schannel.tls11.enabled": 0, "netlogon.auditntlmindomain": 7,
            },
            "netbios": [2],
            "firewall": [{"name": "Domain", "enabled": true}, {"name": "Private", "enabled": true}, {"name": "Public", "enabled": true}],
            "features": ["AD-Domain-Services", "DNS", "GPMC"],
            "smb": {"smb1": false, "require_signing": true, "audit_smb1": false},
            "shares": ["NETLOGON", "SYSVOL"],
            "audit": all_audit,
            "security_log": {"max_bytes": 4 * GB, "mode": "Circular", "records": 900000},
            "disks": [{"drive": "C:", "size": 100 * GB, "free": 60 * GB}, {"drive": "D:", "size": 200 * GB, "free": 150 * GB}],
            "certificates": [{"subject": "CN=dc02.corp.example.com", "dns": ["dc02.corp.example.com"], "not_after": "2027-06-01T00:00:00Z", "server_auth": true}],
            "credential_guard": [1],
            "errors": {},
            "now": "2026-10-05T12:03:20Z",
        }
    });
    let dc03 =
        json!({"name": "dc03.corp.example.com", "error": "WinRM cannot complete the operation."});
    write(dir, "dcconfig", &[dc01, dc02, dc03]);

    let zero = json!({"count": 0, "capped": false, "top": []});
    let ev01 = json!({
        "name": "dc01.corp.example.com", "days": 7, "security_oldest": iso_days_ago(3), "last_clear": iso_days_ago(2),
        "queries": {
            "ntlmv1": {"count": 12, "capped": false, "first": iso_days_ago(5), "last": iso_days_ago(1), "top": [{"key": "CORP\\svc-legacy from 10.0.0.5", "count": 12}]},
            "lm": zero,
            "rc4": {"count": 30, "capped": false, "top": [{"key": "svc-sql", "count": 30}]},
            "audit_ticket_ops": {"count": 1, "capped": true, "top": []},
            "ldap_unsigned_summary": {"count": 2, "capped": false, "top": [], "binds": 40},
            "ldap_unsigned": zero, "ldap_cbt": zero, "netlogon": zero, "kdc_cert": zero,
            "smb1": {"error": "The specified channel could not be found."},
        }
    });
    let ev02 = json!({
        "name": "dc02.corp.example.com", "days": 7, "security_oldest": iso_days_ago(40),
        "queries": {
            "ntlmv1": zero, "lm": zero, "rc4": zero, "audit_ticket_ops": zero,
            "ldap_unsigned_summary": {"count": 0, "capped": false, "top": [], "binds": 0},
            "ldap_unsigned": zero, "ldap_cbt": zero, "netlogon": zero, "kdc_cert": zero, "smb1": zero,
        }
    });
    let ev03 = json!({"name": "dc03.corp.example.com", "days": 7, "error": "The RPC server is unavailable."});
    write(dir, "dcevents", &[ev01, ev02, ev03]);
}

pub(crate) fn run(sysvol: bool) -> (HashMap<String, CheckResult>, super::DomainAnalysis) {
    let dir = tempfile::tempdir().unwrap();
    write_domain(dir.path(), sysvol);
    let raw = RawDomain::load(dir.path()).unwrap();
    let catalog = crate::results::tests::catalog();
    let out = super::analyze(&catalog, &raw, &[]);
    let by_id = out
        .checks
        .iter()
        .map(|c| (c.id.clone(), c.clone()))
        .collect();
    (by_id, out)
}

pub(crate) fn names(r: &CheckResult) -> Vec<&str> {
    r.affected.iter().map(|a| a.name.as_str()).collect()
}

#[test]
fn every_rule_runs_and_matches_the_domain() {
    let (r, out) = run(true);
    assert_eq!(
        out.checks.len(),
        super::rules::RULES.len()
            + super::rules_dc::RULES.len()
            + super::rules_pki::RULES.len()
            + super::rules_hunt::RULES.len()
            + super::rules_ioc::RULES.len()
            + super::rules_svc::RULES.len()
            + super::rules_gpo::RULES.len()
            + super::rules_net::RULES.len()
            + super::rules_auth::RULES.len()
            + super::rules_obj::RULES.len()
            + super::rules_misc::RULES.len()
            + super::rules_ep::RULES.len()
            + super::rules_t0::RULES.len()
            + super::rules_more::RULES.len()
            + super::rules_forest::RULES.len()
            + super::rules_access::RULES.len()
            + super::rules_policy::RULES.len()
            + super::rules_host::RULES.len()
            + super::rules_ca::RULES.len()
            + super::rules_last::RULES.len()
    );
    let status = |id: &str| r[id].status;

    assert_eq!(status("AD-FND-001"), ResultStatus::Passed);
    assert_eq!(status("AD-FND-002"), ResultStatus::Failed);
    assert_eq!(status("AD-FND-007"), ResultStatus::Passed);
    assert_eq!(status("AD-FND-008"), ResultStatus::Failed);
    assert_eq!(status("AD-FND-011"), ResultStatus::Failed);
    assert_eq!(status("AD-FND-012"), ResultStatus::Failed);

    assert_eq!(names(&r["AD-PRIV-001"]), ["Administrator"]);
    assert_eq!(status("AD-PRIV-002"), ResultStatus::Passed);
    assert_eq!(status("AD-PRIV-003"), ResultStatus::Passed);
    assert_eq!(names(&r["AD-PRIV-005"]), ["helpdesk-lead"]);
    assert_eq!(names(&r["AD-PRIV-011"]), ["adm-old"]);
    assert_eq!(names(&r["AD-PRIV-014"]), ["Administrator"]);
    assert_eq!(names(&r["AD-PRIV-015"]), ["Administrator", "helpdesk-lead"]);
    assert_eq!(names(&r["AD-PRIV-020"]), Vec::<&str>::new());
    assert_eq!(status("AD-PRIV-021"), ResultStatus::Failed);
    assert_eq!(names(&r["AD-PRIV-024"]), ["former-admin"]);

    assert_eq!(names(&r["AD-KRB-001"]), ["svc-sql"]);
    assert_eq!(names(&r["AD-KRB-002"]), ["jdoe"]);
    assert_eq!(names(&r["AD-KRB-003"]), ["APP01$"]);
    assert_eq!(names(&r["AD-KRB-006"]), ["APP01$"]);

    assert_eq!(status("AD-PWD-001"), ResultStatus::Failed);
    assert_eq!(status("AD-PWD-002"), ResultStatus::Passed);
    assert_eq!(status("AD-PWD-004"), ResultStatus::Passed);
    assert_eq!(status("AD-PWD-006"), ResultStatus::Failed);
    assert_eq!(names(&r["AD-PWD-012"]), ["svc-sql"]);
    assert_eq!(names(&r["AD-PWD-016"]), ["newbie"]);
    assert_eq!(names(&r["AD-PWD-019"]), ["svc-sql"]);
    assert!(!r["AD-PWD-019"].affected[0]
        .reason
        .as_deref()
        .unwrap()
        .contains("Summer"));

    assert_eq!(names(&r["AD-ACC-001"]), ["jdoe"]);
    assert_eq!(names(&r["AD-ACC-005"]), ["APP01$"]);
    assert_eq!(names(&r["AD-ACC-010"]), ["Authenticated Users"]);
    assert_eq!(names(&r["AD-CMP-001"]), ["APP01$"]);
    assert_eq!(names(&r["AD-CMP-007"]), ["APP01$"]);
    assert_eq!(names(&r["AD-CMP-008"]), ["WS01$"]);
    assert_eq!(status("AD-LAPS-001"), ResultStatus::Passed);

    assert_eq!(names(&r["AD-TRU-002"]), ["partner.example.org"]);
    assert_eq!(names(&r["AD-TRU-004"]), ["partner.example.org"]);

    assert_eq!(
        names(&r["AD-ACL-001"]),
        Vec::<&str>::new(),
        "inherit-only ACEs do not apply to the domain head"
    );
    assert_eq!(names(&r["AD-ACL-002"]), ["svc-sql"]);
    assert_eq!(names(&r["AD-ACL-003"]), ["Helpdesk"]);
    assert_eq!(names(&r["AD-ACL-005"]), ["Domain Users"]);
    assert_eq!(names(&r["AD-ACL-006"]), ["Helpdesk"]);
    assert_eq!(names(&r["AD-ACL-008"]), ["Helpdesk"]);
    assert_eq!(names(&r["AD-ACL-010"]), [format!("{SID}-9999").as_str()]);
    assert_eq!(names(&r["AD-ACL-015"]), ["Domain Users"]);
    assert_eq!(names(&r["AD-ACL-027"]), [format!("{SID}-9999").as_str()]);
    assert_eq!(status("AD-ACL-028"), ResultStatus::Failed);

    assert_eq!(names(&r["AD-GPO-002"]), ["Domain Controllers"]);
    assert_eq!(
        names(&r["AD-GPO-003"]),
        ["{11111111-2222-3333-4444-555555555555}"]
    );
    assert_eq!(names(&r["AD-GPO-004"]), ["Default Domain Policy"]);
}

#[test]
fn domain_controller_checks_read_config_and_logs() {
    let (r, _) = run(true);
    let status = |id: &str| r[id].status;
    let dc01 = ["dc01.corp.example.com"];

    assert_eq!(status("AD-DC-001"), ResultStatus::Passed);
    for id in [
        "AD-DC-002",
        "AD-DC-005",
        "AD-DC-006",
        "AD-DC-007",
        "AD-DC-009",
        "AD-DC-010",
        "AD-DC-011",
        "AD-DC-012",
        "AD-DC-013",
        "AD-DC-014",
        "AD-DC-016",
        "AD-DC-020",
        "AD-DC-021",
        "AD-DC-022",
        "AD-DC-024",
        "AD-DC-025",
        "AD-DC-028",
        "AD-DC-030",
        "AD-LEG-009",
        "AD-LEG-011",
        "AD-AUD-001",
        "AD-AUD-002",
        "AD-AUD-004",
        "AD-AUD-006",
        "AD-AUD-011",
        "AD-REP-004",
        "AD-DNS-011",
    ] {
        assert_eq!(names(&r[id]), dc01, "{id}");
    }
    for id in [
        "AD-DC-003",
        "AD-DC-004",
        "AD-DC-015",
        "AD-DC-017",
        "AD-DC-018",
        "AD-DC-019",
        "AD-DC-023",
        "AD-LEG-002",
        "AD-LEG-003",
        "AD-LEG-005",
        "AD-LEG-007",
        "AD-LEG-008",
        "AD-LEG-012",
        "AD-REP-013",
        "AD-BKP-002",
    ] {
        assert_eq!(status(id), ResultStatus::Passed, "{id}");
    }
    // The unreachable DC is named, not silently skipped.
    let skipped = r["AD-DC-006"]
        .evidence
        .iter()
        .find(|e| e.label == "Not assessed on")
        .unwrap();
    assert!(skipped.value.contains("dc03.corp.example.com (WinRM"));
    // dc01 is linked to its computer object; dc02 is not in LDAP.
    assert!(r["AD-DC-006"].affected[0].object.is_some());

    assert_eq!(
        r["AD-DC-012"].severity,
        Some(Severity::Low),
        "only 'when supported'"
    );
    assert_eq!(r["AD-DC-020"].severity, Some(Severity::High));
    assert_eq!(names(&r["AD-DC-029"]), ["dc02.corp.example.com"]);
    assert!(r["AD-DC-029"].affected[0]
        .reason
        .as_deref()
        .unwrap()
        .contains("200 seconds from the PDC"));

    assert_eq!(names(&r["AD-LEG-001"]), ["CORP\\svc-legacy from 10.0.0.5"]);
    assert_eq!(
        status("AD-LEG-004"),
        ResultStatus::Failed,
        "2887 reported 40 binds"
    );
    assert_eq!(names(&r["AD-LEG-006"]), ["svc-sql"]);
    assert!(r["AD-LEG-006"].evidence.iter().any(|e| e
        .value
        .contains("dc02.corp.example.com (no Kerberos ticket events")));

    assert_eq!(status("AD-BKP-001"), ResultStatus::Failed);
    assert!(r["AD-BKP-001"]
        .found
        .as_deref()
        .unwrap()
        .contains("2026-07-01"));
}

#[test]
fn attack_paths_reach_tier0() {
    let (_, out) = run(true);
    let titles: Vec<&str> = out.paths.iter().map(|p| p.title.as_str()).collect();
    assert!(
        titles.contains(&"Any domain user can take over IT Admins in 1 step"),
        "{titles:?}"
    );
    let sql = out
        .paths
        .iter()
        .find(|p| p.title.starts_with("Kerberoastable account svc-sql"))
        .expect("svc-sql path");
    assert_eq!(sql.severity, Severity::High);
    assert_eq!(sql.steps.last().unwrap().kind, "domain");
    assert!(sql.checks.contains(&"AD-ACL-002".to_string()));
    assert!(sql.checks.contains(&"AD-KRB-001".to_string()));
}

#[test]
fn missing_sources_are_not_assessed() {
    let (r, _) = run(false);
    assert_eq!(r["AD-GPO-004"].status, ResultStatus::NotAssessed);
    assert!(r["AD-GPO-004"].note.as_deref().unwrap().contains("SYSVOL"));
    assert_eq!(r["AD-DC-006"].status, ResultStatus::NotAssessed);
    assert!(r["AD-DC-006"]
        .note
        .as_deref()
        .unwrap()
        .contains("Domain controller configuration"));
    assert_eq!(r["AD-LEG-001"].status, ResultStatus::NotAssessed);
}

#[test]
fn directory_hides_secrets_and_marks_tier0() {
    let (_, out) = run(true);
    let d = &out.directory;
    let by_name = |n: &str| {
        d.objects
            .iter()
            .find(|o| o.name == n)
            .unwrap_or_else(|| panic!("{n} missing"))
    };
    assert!(by_name("DC01$").tier0);
    assert!(by_name("IT Admins").tier0);
    assert!(!by_name("Helpdesk").tier0);
    let desc = by_name("svc-sql").attributes["description"]
        .as_str()
        .unwrap();
    assert!(!desc.contains("Summer"));
    assert!(by_name("Authenticated Users").kind == "group");
    assert!(d.objects.iter().any(|o| o.name == "Builtin"));
    assert!(d
        .edges
        .iter()
        .any(|e| e.kind == "AddMember" && e.from == sid(513)));
    assert!(d.edges.iter().any(|e| e.kind == "GPLink"));
    let admin = by_name("Administrator");
    assert_eq!(admin.flags[0].text, "Administrators");
}

#[test]
fn rules_and_catalog_agree() {
    use crate::catalog::CheckStatus;
    let catalog = crate::results::tests::catalog();
    let rules: Vec<&str> = super::rules::RULES
        .iter()
        .chain(super::rules_dc::RULES)
        .chain(super::rules_pki::RULES)
        .chain(super::rules_hunt::RULES)
        .chain(super::rules_ioc::RULES)
        .chain(super::rules_svc::RULES)
        .chain(super::rules_gpo::RULES)
        .chain(super::rules_net::RULES)
        .chain(super::rules_auth::RULES)
        .chain(super::rules_obj::RULES)
        .chain(super::rules_misc::RULES)
        .chain(super::rules_ep::RULES)
        .chain(super::rules_t0::RULES)
        .chain(super::rules_more::RULES)
        .chain(super::rules_forest::RULES)
        .chain(super::rules_access::RULES)
        .chain(super::rules_policy::RULES)
        .chain(super::rules_host::RULES)
        .chain(super::rules_ca::RULES)
        .chain(super::rules_last::RULES)
        .map(|r| r.id)
        .collect();
    for id in &rules {
        let check = catalog
            .check(id)
            .unwrap_or_else(|| panic!("{id} is not in the catalog"));
        assert_eq!(
            check.status,
            CheckStatus::Implemented,
            "{id} has a rule but is not marked implemented"
        );
        assert!(check.detail.is_some(), "{id} has no detail block");
    }
    for check in catalog.checks.iter().filter(|c| {
        c.status == CheckStatus::Implemented
            && (c.area.starts_with("AD-") || c.area == "HUNT-AD" || c.area.starts_with("EP-"))
    }) {
        assert!(
            rules.contains(&check.id.as_str()),
            "{} is marked implemented but has no rule",
            check.id
        );
    }
}

#[test]
fn analyzes_an_assessment_folder() {
    let root = tempfile::tempdir().unwrap();
    let catalog = crate::results::tests::catalog();
    let spec = crate::analysis::NewAssessment {
        name: Some("Test run".into()),
        domains: vec!["corp.example.com".into()],
        tenant: None,
        areas: vec!["AD-PRIV".into(), "AD-ACL".into()],
    };
    let dir = crate::analysis::create(root.path(), spec, time::parse_iso(NOW).unwrap()).unwrap();
    assert!(dir
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with("20261005-1200-corp.example.com"));
    write_domain(&crate::analysis::ad_raw_dir(&dir, "corp.example.com"), true);
    let manifest = crate::analysis::analyze(&dir, &catalog).unwrap();
    assert_eq!(manifest.finished_at.as_deref(), Some(NOW));
    assert!(manifest.score.is_some());

    let a = crate::results::Assessment::load(&dir).unwrap();
    assert!(a
        .results
        .checks
        .iter()
        .all(|c| c.id.starts_with("AD-PRIV") || c.id.starts_with("AD-ACL")));
    assert!(!a.results.paths.is_empty());
    let view = crate::results::view(&catalog, &[a]);
    assert!(view.summary.status.failed > 0);
    assert!(view.directory.unwrap().objects.len() > 20);
}

/// Adds certificate services to the test domain: two enterprise CAs, the
/// NTAuth store and one template for each problem the PKI rules look for.
fn write_pki(dir: &Path) {
    use super::x509::tests::certificate;
    let b64 = |b: Vec<u8>| base64::engine::general_purpose::STANDARD.encode(b);
    let pks = "CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=example,DC=com";
    let da = sid(512);
    let du = sid(513);
    let helpdesk = sid(1106);
    let sd = |extra: &[(bool, u8, u32, Option<&str>, &str)]| {
        let mut aces = vec![(true, 0u8, right::GENERIC_ALL, None, da.as_str())];
        aces.extend_from_slice(extra);
        b64(build::sd(&da, &aces))
    };
    let enroll = sd(&[(
        true,
        0,
        right::CONTROL_ACCESS,
        Some("0e10c968-78fb-11d2-90d4-00c04f79dc55"),
        du.as_str(),
    )]);
    // NOW is 2026-10-05: the issuing CA expires in about 100 days.
    let issuing = b64(certificate(
        "Corp Issuing CA",
        "Corp Root CA",
        "270113000000Z",
        true,
        128,
    ));
    let root = b64(certificate(
        "Corp Root CA",
        "Corp Root CA",
        "350101000000Z",
        false,
        512,
    ));
    let partner = b64(certificate(
        "Partner Root",
        "Partner Root",
        "350101000000Z",
        false,
        512,
    ));
    let template = |name: &str, extra: Value| {
        let mut o = json!({
            "distinguishedname": format!("CN={name},CN=Certificate Templates,{pks}"),
            "name": name,
            "objectclass": ["top", "pKICertificateTemplate"],
            "ntsecuritydescriptor": enroll,
            "mspki-template-schema-version": 2,
            "mspki-certificate-name-flag": 0,
            "mspki-enrollment-flag": 0,
            "mspki-ra-signature": 0,
            "pkiextendedkeyusage": [CLIENT_AUTH],
        });
        for (k, v) in extra.as_object().unwrap() {
            o[k] = v.clone();
        }
        obj(o)
    };
    // 5 years as a negative 100-nanosecond interval, little-endian.
    let five_years = b64((-(5 * 365 * 86_400i64) * 10_000_000).to_le_bytes().to_vec());
    let published = [
        "UserAuthSAN",
        "AnyPurpose",
        "Agent",
        "WebServerV1",
        "NoSecExt",
        "Linked",
        "Approved",
    ];
    write(
        dir,
        "pki",
        &[
            obj(json!({
                "distinguishedname": pks, "name": "Public Key Services", "objectclass": ["top", "container"],
                "ntsecuritydescriptor": sd(&[(true, 0, right::GENERIC_ALL, None, helpdesk.as_str())]),
            })),
            obj(json!({
                "distinguishedname": format!("CN=Corp-Issuing-CA,CN=Enrollment Services,{pks}"), "name": "Corp-Issuing-CA",
                "objectclass": ["top", "pKIEnrollmentService"], "dnshostname": "dc01.corp.example.com",
                "cacertificate": [issuing.clone()], "certificatetemplates": published.to_vec(),
                "ntsecuritydescriptor": sd(&[]),
            })),
            obj(json!({
                "distinguishedname": format!("CN=Corp-Root-CA,CN=Enrollment Services,{pks}"), "name": "Corp-Root-CA",
                "objectclass": ["top", "pKIEnrollmentService"], "dnshostname": "dc01.corp.example.com",
                "cacertificate": [root.clone()], "certificatetemplates": [],
            })),
            obj(json!({
                "distinguishedname": format!("CN=Corp Root CA,CN=Certification Authorities,{pks}"), "name": "Corp Root CA",
                "objectclass": ["top", "certificationAuthority"], "cacertificate": [root.clone()],
            })),
            obj(json!({
                "distinguishedname": format!("CN=NTAuthCertificates,{pks}"), "name": "NTAuthCertificates",
                "objectclass": ["top", "certificationAuthority"], "cacertificate": [issuing, partner],
            })),
            obj(json!({
                "distinguishedname": format!("CN=1234.5678,CN=OID,{pks}"), "name": "1234.5678",
                "objectclass": ["top", "msPKI-Enterprise-Oid"], "mspki-cert-template-oid": "1.3.6.1.4.1.99999.1",
                "msds-oidtogrouplink": format!("CN=IT Admins,CN=Users,{DOMAIN_DN}"),
            })),
            template("UserAuthSAN", json!({"mspki-certificate-name-flag": 1})),
            template("AnyPurpose", json!({"pkiextendedkeyusage": []})),
            template(
                "Agent",
                json!({"pkiextendedkeyusage": ["1.3.6.1.4.1.311.20.2.1"]}),
            ),
            template(
                "WebServerV1",
                json!({
                    "mspki-template-schema-version": 1, "mspki-certificate-name-flag": 1,
                    "pkiextendedkeyusage": ["1.3.6.1.5.5.7.3.1"], "pkiexpirationperiod": five_years,
                }),
            ),
            template("NoSecExt", json!({"mspki-enrollment-flag": 0x80000})),
            template(
                "Linked",
                json!({"mspki-certificate-policy": ["1.3.6.1.4.1.99999.1"]}),
            ),
            template(
                "Approved",
                json!({"mspki-certificate-name-flag": 1, "mspki-enrollment-flag": 2}),
            ),
            template(
                "Writable",
                json!({"ntsecuritydescriptor": sd(&[(true, 0, right::WRITE_DACL, None, helpdesk.as_str())])}),
            ),
        ],
    );
    let users = fs::read_to_string(dir.join("users.jsonl")).unwrap();
    let mapped = user(
        "mapped-user",
        1150,
        0x200,
        10,
        Some(1),
        json!({"altsecurityidentities": ["X509:<RFC822>mapped@corp.example.com", "X509:<I>DC=com,DC=example,CN=Corp Issuing CA<SR>0102"]}),
    );
    fs::write(dir.join("users.jsonl"), format!("{users}{mapped}\n")).unwrap();
    let events = fs::read_to_string(dir.join("events.jsonl")).unwrap();
    fs::write(
        dir.join("events.jsonl"),
        format!("{{\"type\":\"done\",\"area\":\"pki\",\"count\":14}}\n{events}"),
    )
    .unwrap();
}

const CLIENT_AUTH: &str = "1.3.6.1.5.5.7.3.2";

#[test]
fn certificate_services() {
    let dir = tempfile::tempdir().unwrap();
    write_domain(dir.path(), true);
    write_pki(dir.path());
    let raw = RawDomain::load(dir.path()).unwrap();
    let out = super::analyze(&crate::results::tests::catalog(), &raw, &[]);
    let r: HashMap<String, CheckResult> =
        out.checks.into_iter().map(|c| (c.id.clone(), c)).collect();

    assert_eq!(
        r["AD-PKI-001"].status,
        ResultStatus::Passed,
        "{:?}",
        r["AD-PKI-001"]
    );
    assert_eq!(names(&r["AD-PKI-002"]), ["UserAuthSAN"]);
    assert!(r["AD-PKI-002"].affected[0]
        .reason
        .as_deref()
        .unwrap()
        .contains("Domain Users"));
    assert_eq!(names(&r["AD-PKI-003"]), ["AnyPurpose"]);
    assert_eq!(names(&r["AD-PKI-004"]), ["Agent"]);
    assert_eq!(names(&r["AD-PKI-005"]), ["Writable"]);
    assert_eq!(names(&r["AD-PKI-006"]), ["Public Key Services"]);
    assert_eq!(names(&r["AD-PKI-010"]), ["NoSecExt"]);
    assert_eq!(names(&r["AD-PKI-012"]), ["Linked"]);
    assert!(r["AD-PKI-012"].affected[0]
        .reason
        .as_deref()
        .unwrap()
        .contains("IT Admins"));
    assert_eq!(names(&r["AD-PKI-013"]), ["mapped-user"]);
    assert_eq!(names(&r["AD-PKI-014"]), ["WebServerV1"]);
    assert_eq!(names(&r["AD-PKI-016"]), ["Corp-Issuing-CA"]);
    assert_eq!(names(&r["AD-PKI-017"]), ["Corp-Issuing-CA"]);
    assert_eq!(names(&r["AD-PKI-018"]), ["UserAuthSAN"]);
    assert_eq!(names(&r["AD-PKI-019"]), ["WebServerV1"]);
    assert_eq!(names(&r["AD-PKI-020"]), ["Partner Root"]);
    assert_eq!(names(&r["AD-PKI-021"]), ["Corp-Root-CA"]);
}

#[test]
fn certificate_services_not_collected() {
    let (r, _) = run(true);
    assert_eq!(r["AD-PKI-002"].status, ResultStatus::NotAssessed);
    assert_eq!(r["AD-PKI-013"].status, ResultStatus::Passed);
}

/// Adds the threat-hunting queries to dc01's event summary.
fn write_hunts(dir: &Path) {
    let k = |key: String, count: u64| json!({"key": key, "count": count, "last": iso_days_ago(1)});
    let q = |top: Vec<Value>| {
        let count: u64 = top.iter().map(|t| t["count"].as_u64().unwrap()).sum();
        json!({"count": count, "capped": false, "top": top})
    };
    let users = format!("CN=Users,{DOMAIN_DN}");
    let newbie = format!("CORP\\newbie|{}", sid(1109));
    let mut failures: Vec<Value> = (0..12)
        .map(|i| k(format!("10.0.0.66|user{i}"), 1))
        .collect();
    failures.push(k("10.0.0.7|jdoe".into(), 30));
    let hunts = json!({
        "hunt_dcsync": q(vec![
            k(format!("CORP\\DC01$|{}", sid(1000)), 50),
            k(newbie.clone(), 3),
            k(format!("CORP\\MSOL_0a1b|{}", sid(1200)), 10),
        ]),
        "hunt_kerberoast": q((0..6)
            .map(|i| k(format!("newbie@CORP.EXAMPLE.COM|svc{i}|10.0.0.66"), 1))
            .chain([k("app@CORP.EXAMPLE.COM|svc-sql|10.0.0.5".into(), 9), k("newbie@CORP.EXAMPLE.COM|adm-old|10.0.0.66".into(), 1)])
            .collect()),
        "hunt_asrep": q(vec![k("jdoe|10.0.0.9".into(), 2)]),
        "hunt_failures": q(failures),
        "hunt_lockouts": q(vec![k("jdoe|WS01".into(), 3)]),
        "hunt_ntlm": q(vec![
            k(format!("{}|Administrator|WS01|10.0.0.20", sid(500)), 4),
            k(format!("{}|svc-sql|APP01|10.0.0.5", sid(1103)), 40),
        ]),
        "hunt_dsobjects": q(vec![
            k(format!("CORP\\newbie|CN=NTDS Settings,CN=EVIL01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,{DOMAIN_DN}"), 1),
            k(format!("CORP\\Administrator|CN=NTDS Settings,CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,{DOMAIN_DN}"), 1),
        ]),
        "hunt_dschanges": q(vec![
            k(format!("nTSecurityDescriptor|CN=AdminSDHolder,CN=System,{DOMAIN_DN}|{newbie}"), 2),
            k(format!("msDS-KeyCredentialLink|CN=adm-jsmith,{users}|{newbie}"), 1),
            k(format!("msDS-KeyCredentialLink|CN=WS01,CN=Computers,{DOMAIN_DN}|CORP\\MSOL_0a1b|{}", sid(1200)), 1),
            k(format!("servicePrincipalName|CN=adm-old,{users}|{newbie}"), 1),
            k(format!("servicePrincipalName|CN=svc-sql,{users}|CORP\\Administrator|{}", sid(500)), 1),
        ]),
        "hunt_groupadds": q(vec![
            k(format!("{}|Domain Admins|{}|CN=newbie,{users}|CORP\\Administrator", sid(512), sid(1109)), 1),
            k(format!("{}|Helpdesk|{}|CN=jdoe,{users}|CORP\\Administrator", sid(1106), sid(1108)), 1),
        ]),
        "hunt_services": q(vec![
            k("PSEXESVC|%SystemRoot%\\PSEXESVC.exe|LocalSystem".into(), 1),
            k("GoogleUpdate|C:\\Program Files\\Google\\Update\\GoogleUpdate.exe|LocalSystem".into(), 1),
            k("updsvc|C:\\Users\\Public\\upd.exe|LocalSystem".into(), 1),
            k("XyZaBcDe|%COMSPEC%|LocalSystem".into(), 1),
        ]),
        "hunt_tasks": q(vec![
            k("\\AbCdEfGh|CORP\\newbie".into(), 1),
            k("\\Microsoft\\Windows\\UpdateOrchestrator\\Reboot|CORP\\DC01$".into(), 1),
        ]),
        "hunt_auditpolicy": q(vec![
            k(format!("CORP\\DC01$|{}", sid(1000)), 5),
            k(newbie.clone(), 1),
        ]),
        "hunt_clears": q(vec![k("CORP\\newbie".into(), 1)]),
        "hunt_sidhistory": q(vec![k("4765|newbie|S-1-5-21-9-9-9-500|CORP\\Administrator".into(), 1)]),
        "hunt_coercion": q(vec![k("efsrpc|10.0.0.66|ANONYMOUS LOGON".into(), 3)]),
    });
    let path = dir.join("dcevents.jsonl");
    let text = fs::read_to_string(&path).unwrap();
    let mut out = String::new();
    for line in text.lines() {
        let mut dc: Value = serde_json::from_str(line).unwrap();
        if dc["name"] == "dc01.corp.example.com" {
            for (name, v) in hunts.as_object().unwrap() {
                dc["queries"][name] = v.clone();
            }
        }
        out.push_str(&format!("{dc}\n"));
    }
    fs::write(path, out).unwrap();
}

#[test]
fn hunting_in_dc_event_logs() {
    let dir = tempfile::tempdir().unwrap();
    write_domain(dir.path(), true);
    write_hunts(dir.path());
    let raw = RawDomain::load(dir.path()).unwrap();
    let out = super::analyze(&crate::results::tests::catalog(), &raw, &[]);
    let r: HashMap<String, CheckResult> =
        out.checks.into_iter().map(|c| (c.id.clone(), c)).collect();
    let sorted = |id: &str| {
        let mut n: Vec<String> = r[id].affected.iter().map(|a| a.name.clone()).collect();
        n.sort();
        n
    };

    let dcsync = &r["HUNT-AD-001"];
    assert_eq!(names(dcsync), ["CORP\\newbie"]);
    // Observations carry when they were seen, for the hunting timeline.
    assert!(dcsync.affected[0].last_seen.is_some());
    assert!(dcsync
        .evidence
        .iter()
        .any(|e| e.value.contains("MSOL_0a1b")));
    assert!(dcsync
        .evidence
        .iter()
        .any(|e| e.label == "Not assessed on" && e.value.contains("dc02")));
    assert_eq!(names(&r["HUNT-AD-002"]), ["newbie@CORP.EXAMPLE.COM"]);
    assert_eq!(names(&r["HUNT-AD-003"]), ["jdoe"]);
    assert_eq!(names(&r["HUNT-AD-004"]), ["10.0.0.66"]);
    assert_eq!(names(&r["HUNT-AD-005"]), ["jdoe"]);
    assert_eq!(names(&r["HUNT-AD-008"]), ["Administrator"]);
    assert_eq!(names(&r["HUNT-AD-009"]), ["EVIL01"]);
    assert_eq!(names(&r["HUNT-AD-010"]), ["AdminSDHolder"]);
    assert_eq!(names(&r["HUNT-AD-011"]), ["newbie"]);
    assert_eq!(
        sorted("HUNT-AD-013"),
        ["PSEXESVC", "XyZaBcDe", "\\AbCdEfGh", "updsvc"]
    );
    assert_eq!(names(&r["HUNT-AD-014"]), ["CORP\\newbie", "CORP\\newbie"]);
    assert_eq!(names(&r["HUNT-AD-015"]), ["newbie"]);
    assert_eq!(names(&r["HUNT-AD-016"]), ["adm-jsmith"]);
    assert_eq!(names(&r["HUNT-AD-020"]), ["10.0.0.66"]);
    let spn = &r["HUNT-AD-022"];
    assert_eq!(names(spn), ["adm-old"]);
    assert!(spn.affected[0]
        .reason
        .as_deref()
        .unwrap()
        .contains("RC4 service ticket was then requested"));
    assert_eq!(
        sorted("HUNT-AD-024"),
        ["PSEXESVC", "XyZaBcDe", "\\AbCdEfGh"]
    );
}

#[test]
fn hunting_without_hunt_queries_is_not_assessed() {
    let (r, _) = run(true);
    let h = &r["HUNT-AD-001"];
    assert_eq!(h.status, ResultStatus::NotAssessed);
    assert!(h.note.as_deref().unwrap().contains("not queried"));
}

/// Rewrites each line of an area file through `f`; `None` drops the line.
pub(crate) fn patch(dir: &Path, area: &str, f: impl Fn(Value) -> Option<Value>) {
    let path = dir.join(format!("{area}.jsonl"));
    let text = fs::read_to_string(&path).unwrap();
    let out: String = text
        .lines()
        .filter(|l| !l.is_empty())
        .filter_map(|l| f(serde_json::from_str(l).unwrap()))
        .map(|v| format!("{v}\n"))
        .collect();
    fs::write(path, out).unwrap();
}

pub(crate) fn append_area(dir: &Path, area: &str, lines: &[Value]) {
    let path = dir.join(format!("{area}.jsonl"));
    let mut text = fs::read_to_string(&path).unwrap_or_default();
    for l in lines {
        text.push_str(&format!("{l}\n"));
    }
    fs::write(path, text).unwrap();
}

pub(crate) fn is(v: &Value, attr: &str, value: &str) -> bool {
    v[attr][0].as_str() == Some(value)
}

/// Service accounts, managed service accounts, a KDS root key, sites with a
/// rogue directory service agent, and a few planted compromise indicators.
fn write_indicators(dir: &Path) {
    let users = format!("CN=Users,{DOMAIN_DN}");
    let dc_ou = format!("OU=Domain Controllers,{DOMAIN_DN}");
    let da = sid(512);
    let config = "CN=Configuration,DC=corp,DC=example,DC=com";
    let site = format!("CN=Default-First-Site-Name,CN=Sites,{config}");
    let b64 = |b: Vec<u8>| base64::engine::general_purpose::STANDARD.encode(b);
    let sd = |aces: &[(bool, u8, u32, Option<&str>, &str)]| {
        let mut all = vec![(true, 0u8, right::GENERIC_ALL, None, da.as_str())];
        all.extend_from_slice(aces);
        build::sd(&da, &all)
    };

    patch(dir, "domain", |mut v| {
        v["wellknownobjects"] = json!([
            format!("B:32:A9D1CA15768811D1ADED00C04FD8D5CD:CN=Users,{DOMAIN_DN}"),
            format!("B:32:AA312825768811D1ADED00C04FD8D5CD:OU=Workstations,{DOMAIN_DN}"),
        ]);
        Some(v)
    });
    patch(dir, "users", |mut v| {
        if is(&v, "samaccountname", "adm-jsmith") {
            v["mail"] = json!(["jsmith@corp.example.com"]);
        }
        if is(&v, "samaccountname", "krbtgt") {
            v["msds-allowedtoactonbehalfofotheridentity"] = json!(["AQAEgA=="]);
        }
        Some(v)
    });
    append_area(
        dir,
        "users",
        &[
            user(
                "svc-web",
                1120,
                0x200,
                30,
                Some(1),
                json!({
                    "serviceprincipalname": ["HTTP/web.corp.example.com"], "msds-supportedencryptiontypes": 0x18,
                    "sidhistory": ["S-1-5-21-9-9-9-512"], "msds-allowedtodelegateto": ["krbtgt/CORP.EXAMPLE.COM"],
                }),
            ),
            user(
                "fresh-admin",
                1121,
                0x200,
                5,
                Some(1),
                json!({"whencreated": iso_days_ago(5), "admincount": 1}),
            ),
        ],
    );
    patch(dir, "groups", |mut v| {
        if is(&v, "samaccountname", "Domain Admins") {
            v["member"]
                .as_array_mut()
                .unwrap()
                .push(json!(format!("CN=fresh-admin,{users}")));
        }
        Some(v)
    });
    patch(dir, "computers", |mut v| {
        if is(&v, "samaccountname", "DC01$") {
            v["operatingsystem"] = json!(["Windows Server 2025 Datacenter"]);
        }
        Some(v)
    });
    patch(dir, "gpos", |mut v| {
        if v["distinguishedname"][0].as_str().unwrap().contains(DDCP) {
            v["whenchanged"] = json!([iso_days_ago(3)]);
        }
        Some(v)
    });
    patch(dir, "acls", |mut v| {
        if v["distinguishedname"][0]
            .as_str()
            .unwrap()
            .starts_with("CN=AdminSDHolder")
        {
            v["whenchanged"] = json!([iso_days_ago(2)]);
        }
        Some(v)
    });
    let du = sid(513);
    append_area(
        dir,
        "acls",
        &[
            acl(
                &format!("CN=fresh-admin,{users}"),
                "user",
                sd(&[(false, 0, 0x10 | 0x4, None, "S-1-1-0")]),
            ),
            acl(
                &format!("OU=Servers,{DOMAIN_DN}"),
                "organizationalUnit",
                sd(&[
                    (false, 0, 0x10000 | 0x40, None, "S-1-1-0"),
                    (
                        true,
                        0,
                        right::CREATE_CHILD,
                        Some("0feb936f-47b3-49f2-9386-1dedc2c23765"),
                        du.as_str(),
                    ),
                ]),
            ),
        ],
    );
    let membership = |who: &str| b64(build::sd(&da, &[(true, 0, 0x000F_01FF, None, who)]));
    write(
        dir,
        "msas",
        &[
            obj(json!({
                "distinguishedname": format!("CN=gmsa-web,CN=Managed Service Accounts,{DOMAIN_DN}"), "samaccountname": "gmsa-web$",
                "objectclass": ["top", "person", "organizationalPerson", "user", "computer", "msDS-GroupManagedServiceAccount"],
                "objectsid": sid(1300), "msds-groupmsamembership": membership(&sid(515)),
            })),
            obj(json!({
                "distinguishedname": format!("CN=gmsa-sql,CN=Managed Service Accounts,{DOMAIN_DN}"), "samaccountname": "gmsa-sql$",
                "objectclass": ["top", "msDS-GroupManagedServiceAccount"], "objectsid": sid(1301),
                "msds-groupmsamembership": membership(&sid(1000)),
            })),
            obj(json!({
                "distinguishedname": format!("CN=smsa-old,CN=Managed Service Accounts,{DOMAIN_DN}"), "samaccountname": "smsa-old$",
                "objectclass": ["top", "msDS-ManagedServiceAccount"], "objectsid": sid(1302),
            })),
            obj(json!({
                "distinguishedname": format!("CN=smsa-app,CN=Managed Service Accounts,{DOMAIN_DN}"), "samaccountname": "smsa-app$",
                "objectclass": ["top", "msDS-ManagedServiceAccount"], "objectsid": sid(1303),
                "msds-hostserviceaccountbl": [format!("CN=APP01,OU=Servers,{DOMAIN_DN}")],
            })),
        ],
    );
    write(
        dir,
        "kds",
        &[obj(json!({
            "distinguishedname": format!("CN=4f1a,CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,{config}"),
            "name": "4f1a", "whencreated": iso_days_ago(900),
            "ntsecuritydescriptor": b64(sd(&[(true, 0, 0x8000_0000, None, du.as_str())])),
        }))],
    );
    write(
        dir,
        "sites",
        &[
            obj(json!({"distinguishedname": site, "objectclass": ["top", "site"]})),
            obj(json!({
                "distinguishedname": format!("CN=DC01,CN=Servers,{site}"), "objectclass": ["top", "server"],
                "serverreference": format!("CN=DC01,{dc_ou}"),
            })),
            obj(
                json!({"distinguishedname": format!("CN=NTDS Settings,CN=DC01,CN=Servers,{site}"), "objectclass": ["top", "applicationSettings", "nTDSDSA"]}),
            ),
            obj(json!({
                "distinguishedname": format!("CN=EVIL01,CN=Servers,{site}"), "objectclass": ["top", "server"],
                "serverreference": format!("CN=APP01,OU=Servers,{DOMAIN_DN}"),
            })),
            obj(json!({
                "distinguishedname": format!("CN=NTDS Settings,CN=EVIL01,CN=Servers,{site}"), "objectclass": ["top", "nTDSDSA"],
                "whencreated": iso_days_ago(1),
            })),
        ],
    );
    patch(dir, "dcconfig", |mut v| {
        if v["name"] == "dc01.corp.example.com" {
            v["data"]["registry"]["lsa.securitypackages"] =
                json!(["kerberos", "msv1_0", "\"\"", "mimilib"]);
            v["data"]["registry"]["lsa.notificationpackages"] = json!(["scecli", "rassfm"]);
            v["data"]["registry"]["lsa.authenticationpackages"] = json!(["msv1_0"]);
        }
        Some(v)
    });
    let events = fs::read_to_string(dir.join("events.jsonl")).unwrap();
    let done: String = ["msas", "kds", "sites"]
        .iter()
        .map(|a| format!("{}\n", json!({"type": "done", "area": a, "count": 1})))
        .collect();
    fs::write(dir.join("events.jsonl"), format!("{done}{events}")).unwrap();
}

#[test]
fn service_accounts_ous_and_indicators() {
    let dir = tempfile::tempdir().unwrap();
    write_domain(dir.path(), true);
    write_indicators(dir.path());
    let raw = RawDomain::load(dir.path()).unwrap();
    let out = super::analyze(&crate::results::tests::catalog(), &raw, &[]);
    let r: HashMap<String, CheckResult> =
        out.checks.into_iter().map(|c| (c.id.clone(), c)).collect();
    let failed = |id: &str| {
        assert_eq!(r[id].status, ResultStatus::Failed, "{id}: {:?}", r[id]);
        names(&r[id])
    };
    assert_eq!(failed("AD-IOC-001"), ["AdminSDHolder"]);
    assert_eq!(failed("AD-IOC-002"), ["svc-web"]);
    assert_eq!(failed("AD-IOC-004"), ["EVIL01"]);
    assert_eq!(failed("AD-IOC-005"), ["Default Domain Controllers Policy"]);
    let lsa = &r["AD-IOC-006"];
    assert!(lsa.affected[0]
        .reason
        .as_deref()
        .unwrap()
        .contains("mimilib"));
    assert_eq!(failed("AD-IOC-008"), ["fresh-admin"]);
    assert_eq!(failed("AD-IOC-010"), ["fresh-admin"]);
    assert_eq!(failed("AD-IOC-011"), ["krbtgt", "svc-web"]);
    assert_eq!(failed("AD-IOC-013"), ["Domain Users"]);
    assert_eq!(r["AD-IOC-014"].status, ResultStatus::Passed);

    assert_eq!(failed("AD-SVC-001"), ["svc-sql", "svc-web"]);
    assert_eq!(failed("AD-SVC-002"), ["gmsa-web$"]);
    assert_eq!(r["AD-SVC-003"].status, ResultStatus::Passed);
    assert!(failed("AD-SVC-004").contains(&"Servers"));
    assert_eq!(failed("AD-SVC-006"), ["svc-sql"]);
    assert_eq!(failed("AD-SVC-007"), ["svc-sql"]);
    assert_eq!(r["AD-SVC-008"].status, ResultStatus::Passed);
    assert_eq!(failed("AD-SVC-009"), ["smsa-old$"]);
    assert_eq!(failed("AD-SVC-010"), ["svc-web"]);

    assert!(failed("AD-OU-002").contains(&"WS01$"));
    assert_eq!(failed("AD-OU-003"), ["Users"]);
    assert_eq!(failed("AD-OU-004"), ["Domain Controllers"]);
    assert_eq!(failed("AD-OU-007"), ["adm-jsmith"]);
}

#[test]
fn indicators_without_new_areas() {
    let (r, _) = run(true);
    assert_eq!(r["AD-IOC-004"].status, ResultStatus::NotAssessed);
    assert_eq!(r["AD-SVC-002"].status, ResultStatus::NotAssessed);
    // Without a 2025 DC, BadSuccessor exposure is listed but does not fail.
    assert_eq!(r["AD-SVC-004"].status, ResultStatus::Passed);
    assert_eq!(r["AD-OU-003"].status, ResultStatus::NotAssessed);
}

const BASELINE: &str = "{AAAAAAAA-1111-2222-3333-444444444444}";
const EMPTY_GPO: &str = "{BBBBBBBB-1111-2222-3333-444444444444}";

/// GPO content as the current collector reads it from SYSVOL: security
/// templates, Registry.pol, scripts, preferences and folder permissions.
fn write_gpo_content(dir: &Path) {
    let policies = format!("CN=Policies,CN=System,{DOMAIN_DN}");
    let servers = format!("OU=Servers,{DOMAIN_DN}");
    let da = sid(512);
    let (du, helpdesk, lead) = (sid(513), sid(1106), sid(1108));
    patch(dir, "containers", |mut v| {
        if is(&v, "distinguishedname", &servers) {
            v["gplink"] = json!([format!("[LDAP://cn={BASELINE},{policies};0]")]);
            v["gpoptions"] = json!([1]);
        }
        Some(v)
    });
    append_area(
        dir,
        "gpos",
        &[
            obj(json!({
                "distinguishedname": dn(&format!("CN={BASELINE}"), &policies), "displayname": "Server Baseline",
                "versionnumber": 7, "flags": 0,
            })),
            obj(json!({
                "distinguishedname": dn(&format!("CN={EMPTY_GPO}"), &policies), "displayname": "Empty Test GPO",
                "versionnumber": 0, "flags": 0,
            })),
        ],
    );
    append_area(
        dir,
        "acls",
        &[acl(
            &dn(&format!("CN={BASELINE}"), &policies),
            "groupPolicyContainer",
            build::sd(
                &lead,
                &[
                    (true, 0, right::GENERIC_ALL, None, da.as_str()),
                    (true, 0, 0x8000_0000, None, "S-1-5-11"),
                    (true, 0, right::WRITE_DACL, None, lead.as_str()),
                ],
            ),
        )],
    );
    let admins_acl = json!({
        "owner": "CORP\\Domain Admins", "owner_sid": da,
        "writers": [
            {"identity": "CORP\\Domain Admins", "sid": da, "rights": "FullControl", "inherit_only": false},
            {"identity": "NT AUTHORITY\\SYSTEM", "sid": "S-1-5-18", "rights": "FullControl", "inherit_only": false},
            {"identity": "CREATOR OWNER", "sid": "S-1-3-0", "rights": "FullControl", "inherit_only": true},
        ],
    });
    let mut ddcp_acl = admins_acl.clone();
    ddcp_acl["writers"].as_array_mut().unwrap().push(
        json!({"identity": "CORP\\Helpdesk", "sid": helpdesk, "rights": "Modify", "inherit_only": false}),
    );
    let wu = "Software\\Policies\\Microsoft\\Windows\\WindowsUpdate";
    let ps = "Software\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging";
    let cd = "Software\\Policies\\Microsoft\\Windows\\CredentialsDelegation";
    let lines = [
        json!({
            "folder": DDP,
            "cpasswords": [{"file": "Machine\\Preferences\\Groups\\Groups.xml", "element": "User", "user": "LocalAdmin"}],
            "files": ["GPT.INI", "Machine\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf", "Machine\\Registry.pol", "Machine\\Preferences\\Groups\\Groups.xml"],
            "inf": {"Unicode": {"Unicode": ["yes"]}, "System Access": {"MinimumPasswordLength": ["7"]}},
            "registry": [{"scope": "Machine", "key": wu, "value": "WUServer", "type": 1, "data": "http://wsus.corp.example.com:8530"}],
            "scripts": [], "preferences": {"tasks": [], "groups": []}, "acl": admins_acl,
        }),
        json!({
            "folder": DDCP, "cpasswords": [],
            "files": ["GPT.INI", "MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf"],
            "inf": {"Privilege Rights": {
                "SeDebugPrivilege": ["*S-1-5-32-544"],
                "SeBackupPrivilege": ["*S-1-5-32-544", "*S-1-5-32-551", format!("*{helpdesk}")],
                "SeInteractiveLogonRight": ["*S-1-5-32-544", "*S-1-5-32-548", "CORP\\jdoe"],
            }},
            "registry": [], "scripts": [], "acl": ddcp_acl,
        }),
        json!({"folder": "{11111111-2222-3333-4444-555555555555}", "cpasswords": []}),
        json!({
            "folder": BASELINE, "cpasswords": [],
            "files": ["GPT.INI", "Machine\\Registry.pol", "Machine\\Preferences\\ScheduledTasks\\ScheduledTasks.xml"],
            "inf": {
                "Privilege Rights": {"SeDenyInteractiveLogonRight": [format!("*{da}")]},
                "Group Membership": {"*S-1-5-32-544__Members": [format!("*{du}")], "*S-1-5-32-544__Memberof": []},
            },
            "registry": [
                {"scope": "Machine", "key": ps, "value": "EnableScriptBlockLogging", "type": 4, "data": 1},
                {"scope": "Machine", "key": cd, "value": "AllowDefaultCredentials", "type": 4, "data": 1},
                {"scope": "Machine", "key": format!("{cd}\\AllowDefaultCredentials"), "value": "1", "type": 1, "data": "TERMSRV/*"},
            ],
            "scripts": [
                {"scope": "Machine", "kind": "Startup", "path": "\\\\fs01\\deploy\\start.cmd"},
                {"scope": "User", "kind": "Logon", "path": "\\\\corp.example.com\\NETLOGON\\map.cmd"},
            ],
            "preferences": {
                "tasks": [
                    {"scope": "Machine", "name": "Cleanup", "run_as": "CORP\\adm-jsmith"},
                    {"scope": "Machine", "name": "Inventory", "run_as": "NT AUTHORITY\\System"},
                ],
                "groups": [{
                    "group": "Remote Desktop Users (built-in)", "sid": "S-1-5-32-555", "action": "U", "delete_all": false,
                    "members": [{"name": "CORP\\Domain Users", "sid": du, "action": "ADD"}],
                }],
            },
            "acl": admins_acl,
        }),
    ];
    write(dir, "sysvol", &lines);
    write(
        dir,
        "scripts",
        &[
            json!({"file": "NETLOGON\\map.cmd", "line": 3, "pattern": "net_use_user"}),
            json!({"file": "NETLOGON\\map.cmd", "line": 9, "pattern": "password_assignment"}),
            json!({"file": format!("Policies\\{BASELINE}\\Machine\\Scripts\\Startup\\start.ps1"), "line": 2, "pattern": "plain_securestring"}),
        ],
    );
    let events = fs::read_to_string(dir.join("events.jsonl")).unwrap();
    let done = json!({"type": "done", "area": "scripts", "count": 3});
    fs::write(dir.join("events.jsonl"), format!("{done}\n{events}")).unwrap();
}

#[test]
fn group_policy_content() {
    let dir = tempfile::tempdir().unwrap();
    write_domain(dir.path(), true);
    write_gpo_content(dir.path());
    let raw = RawDomain::load(dir.path()).unwrap();
    let out = super::analyze(&crate::results::tests::catalog(), &raw, &[]);
    let r: HashMap<String, CheckResult> =
        out.checks.into_iter().map(|c| (c.id.clone(), c)).collect();
    let failed = |id: &str| {
        assert_eq!(r[id].status, ResultStatus::Failed, "{id}: {:?}", r[id]);
        names(&r[id])
    };
    let reasons = |id: &str| -> String {
        r[id]
            .affected
            .iter()
            .filter_map(|a| a.reason.clone())
            .collect::<Vec<_>>()
            .join(" | ")
    };

    assert_eq!(failed("AD-GPO-001"), ["Empty Test GPO"]);
    assert!(
        reasons("AD-GPO-001").contains("not linked") && reasons("AD-GPO-001").contains("empty")
    );
    assert_eq!(failed("AD-GPO-005"), ["map.cmd", "start.ps1"]);
    let start = &r["AD-GPO-005"].affected[1];
    assert!(start
        .location
        .as_deref()
        .unwrap()
        .starts_with("\\\\corp.example.com\\SYSVOL\\corp.example.com\\Policies\\{AAAA"));
    assert_eq!(failed("AD-GPO-006"), ["Default Domain Controllers Policy"]);
    assert!(reasons("AD-GPO-006").contains("Helpdesk"));
    assert_eq!(
        failed("AD-GPO-007"),
        ["Default Domain Controllers Policy", "Server Baseline"]
    );
    assert!(reasons("AD-GPO-007").contains("jdoe: Modify permissions"));
    assert_eq!(failed("AD-GPO-008"), ["Default Domain Controllers Policy"]);
    let rights = reasons("AD-GPO-008");
    assert!(rights.contains("SeBackupPrivilege") && rights.contains("Helpdesk"));
    assert!(!rights.contains("Backup Operators"));
    assert_eq!(failed("AD-GPO-009"), ["Default Domain Controllers Policy"]);
    assert!(reasons("AD-GPO-009").contains("CORP\\jdoe"));
    assert_eq!(
        failed("AD-GPO-011"),
        ["Deny log on through Remote Desktop Services"]
    );
    assert_eq!(
        failed("AD-GPO-014"),
        ["Script block logging"],
        "set only on servers"
    );
    assert_eq!(failed("AD-GPO-015"), ["Server Baseline", "Server Baseline"]);
    assert_eq!(failed("AD-GPO-018"), ["Server Baseline"]);
    assert!(reasons("AD-GPO-018").contains("TERMSRV/*"));
    assert_eq!(failed("AD-GPO-019"), ["Default Domain Policy"]);
    assert_eq!(failed("AD-GPO-022"), ["Server Baseline"]);
    assert!(reasons("AD-GPO-022").contains("Cleanup"));
    assert_eq!(failed("AD-GPO-023"), ["Server Baseline"]);
    assert!(reasons("AD-GPO-023").contains("fs01"));
    assert_eq!(failed("AD-GPO-026"), ["Servers"]);
    assert_eq!(failed("AD-GPO-027"), ["Default Domain Policy"]);
    assert!(reasons("AD-GPO-027").contains("Registry.pol"));
    assert_eq!(failed("AD-GPO-028"), ["Server Baseline"]);
    assert_eq!(failed("AD-GPO-029"), ["Default Domain Controllers Policy"]);
}

#[test]
fn group_policy_content_from_an_older_collector() {
    let (r, _) = run(true);
    for id in [
        "AD-GPO-005",
        "AD-GPO-006",
        "AD-GPO-008",
        "AD-GPO-014",
        "AD-GPO-022",
        "AD-GPO-027",
    ] {
        assert_eq!(r[id].status, ResultStatus::NotAssessed, "{id}");
    }
    assert_eq!(r["AD-GPO-026"].status, ResultStatus::Passed);
    assert_eq!(
        names(&r["AD-GPO-029"]),
        ["Default Domain Controllers Policy"]
    );
}

/// DNS server, replication and DFSR state on the two DCs that were read,
/// a three-site topology and DNS zone permissions.
fn write_network(dir: &Path) {
    let config = "CN=Configuration,DC=corp,DC=example,DC=com";
    let sites = format!("CN=Sites,{config}");
    let main = format!("CN=Default-First-Site-Name,{sites}");
    let branch = format!("CN=Branch,{sites}");
    let empty = format!("CN=Empty,{sites}");
    let dsa = |server: &str, site: &str| format!("CN=NTDS Settings,CN={server},CN=Servers,{site}");
    let zone = |name: &str| {
        json!({
            "name": name, "type": "Primary", "ds": true, "reverse": false, "dynamic": "Secure",
            "scope": "Domain", "transfer": "NoTransfer", "signed": false, "aging": true,
        })
    };
    let mut corp_open = zone("corp.example.com");
    corp_open["dynamic"] = json!("NonsecureAndSecure");
    corp_open["transfer"] = json!("TransferAnyServer");
    corp_open["aging"] = json!(false);
    let mut legacy = zone("legacy.corp.example.com");
    legacy["scope"] = json!("Legacy");
    let mut lab = zone("lab.local");
    lab["ds"] = json!(false);
    let main_dsa = dsa("DC01", &main);
    let branch_dsa = dsa("DC02", &branch);
    patch(dir, "dcconfig", |mut v| {
        if v["name"] == "dc01.corp.example.com" {
            let d = &mut v["data"];
            d["dns"] = json!({
                "installed": true, "domain": "corp.example.com",
                "zones": [corp_open, zone("_msdcs.corp.example.com"), legacy, lab],
                "records": [{"zone": "corp.example.com", "name": "*", "type": "A"}],
                "dc_srv": ["dc01.corp.example.com.", "old-dc.corp.example.com"],
                "recursion": true, "forwarders": ["8.8.8.8"], "scavenging": false, "scavenging_days": 7,
                "block_list": {"enabled": true, "names": ["isatap"]}, "audit_log": false,
            });
            d["replication"] = json!([{
                "partner": branch_dsa, "partition": DOMAIN_DN, "last_success": iso_days_ago(3),
                "last_attempt": iso_days_ago(0), "last_result": 8453, "failures": 12,
            }]);
            d["dfsr"] =
                json!([{"folder": "SYSVOL Share", "group": "Domain System Volume", "state": 5}]);
            d["no_client_site"] = json!([{"client": "WS9", "ip": "10.9.1.5", "times": 40}]);
            d["registry"]["ntds.dsanotwritable"] = json!(4);
            d["services"]
                .as_array_mut()
                .unwrap()
                .push(json!({"name": "NtFrs", "state": "Running", "start": "Auto"}));
        } else if v["name"] == "dc02.corp.example.com" {
            let d = &mut v["data"];
            d["dns"] = json!({
                "installed": true, "domain": "corp.example.com", "zones": [zone("corp.example.com")],
                "records": [], "dc_srv": ["dc02.corp.example.com"], "recursion": true, "forwarders": ["10.0.0.53"],
                "scavenging": false, "block_list": {"enabled": true, "names": ["wpad", "isatap"]}, "audit_log": true,
            });
            d["replication"] = json!([{
                "partner": main_dsa, "partition": DOMAIN_DN, "last_success": NOW,
                "last_attempt": NOW, "last_result": 0, "failures": 0,
            }]);
            d["dfsr"] =
                json!([{"folder": "SYSVOL Share", "group": "Domain System Volume", "state": 4}]);
            d["no_client_site"] = json!([]);
            d["registry"]["dfsr.sysvolstate"] = json!(3);
        }
        Some(v)
    });
    let o = |dn: String, class: &str, extra: Value| {
        let mut v = json!({"distinguishedname": dn, "objectclass": ["top", class]});
        for (k, x) in extra.as_object().unwrap() {
            v[k] = x.clone();
        }
        obj(v)
    };
    write(
        dir,
        "sites",
        &[
            o(main.clone(), "site", json!({})),
            o(branch.clone(), "site", json!({})),
            o(empty.clone(), "site", json!({})),
            o(
                format!("CN=DC01,CN=Servers,{main}"),
                "server",
                json!({"serverreference": format!("CN=DC01,OU=Domain Controllers,{DOMAIN_DN}")}),
            ),
            o(main_dsa.clone(), "nTDSDSA", json!({"options": 1})),
            o(
                format!("CN=DC02,CN=Servers,{branch}"),
                "server",
                json!({"serverreference": format!("CN=DC02,OU=Domain Controllers,{DOMAIN_DN}")}),
            ),
            o(branch_dsa.clone(), "nTDSDSA", json!({"options": 0})),
            o(
                format!("CN=NTDS Site Settings,{main}"),
                "nTDSSiteSettings",
                json!({"intersitetopologygenerator": main_dsa}),
            ),
            o(
                format!("CN=NTDS Site Settings,{branch}"),
                "nTDSSiteSettings",
                json!({"intersitetopologygenerator": format!("CN=NTDS Settings\\0ADEL:1f2e,CN=OLD,CN=Servers,{branch}"), "options": 16}),
            ),
            o(
                format!("CN=10.0.0.0/24,CN=Subnets,{sites}"),
                "subnet",
                json!({"siteobject": main}),
            ),
            o(
                format!("CN=10.9.0.0/16,CN=Subnets,{sites}"),
                "subnet",
                json!({}),
            ),
            o(
                format!("CN=DEFAULTIPSITELINK,CN=IP,CN=Inter-Site Transports,{sites}"),
                "siteLink",
                json!({"cost": 100, "replinterval": 180, "sitelist": [main, branch]}),
            ),
            o(
                format!("CN=Lonely,CN=IP,CN=Inter-Site Transports,{sites}"),
                "siteLink",
                json!({"cost": 100, "replinterval": 720, "sitelist": [empty]}),
            ),
            o(
                format!("CN=IP,CN=Inter-Site Transports,{sites}"),
                "interSiteTransport",
                json!({"options": 2}),
            ),
        ],
    );
    let da = sid(512);
    let b64 = |b: Vec<u8>| base64::engine::general_purpose::STANDARD.encode(b);
    let zones = format!("CN=MicrosoftDNS,DC=DomainDnsZones,{DOMAIN_DN}");
    write(
        dir,
        "dnszones",
        &[
            obj(json!({
                "distinguishedname": format!("DC=corp.example.com,{zones}"), "name": "corp.example.com",
                "ntsecuritydescriptor": b64(build::sd(&da, &[
                    (true, 0, right::GENERIC_ALL, None, da.as_str()),
                    (true, 0, right::CREATE_CHILD, None, "S-1-5-11"),
                ])),
            })),
            obj(json!({
                "distinguishedname": format!("DC=RootDNSServers,{zones}"), "name": "RootDNSServers",
                "ntsecuritydescriptor": b64(build::sd(&da, &[(true, 0, right::CREATE_CHILD, None, "S-1-5-11")])),
            })),
        ],
    );
    write(
        dir,
        "dnsforestzones",
        &[obj(json!({
            "distinguishedname": format!("DC=_msdcs.corp.example.com,CN=MicrosoftDNS,DC=ForestDnsZones,{DOMAIN_DN}"),
            "ntsecuritydescriptor": b64(build::sd(&da, &[(true, 0, right::GENERIC_ALL, None, da.as_str())])),
        }))],
    );
    patch(dir, "gpos", |mut v| {
        let dn = v["distinguishedname"][0].as_str().unwrap().to_string();
        v["versionnumber"] = json!([if dn.contains(DDP) { 65538 } else { 3 }]);
        Some(v)
    });
    patch(dir, "sysvol", |mut v| {
        v["version"] = json!(if v["folder"] == DDP { 65537 } else { 3 });
        Some(v)
    });
    let events = fs::read_to_string(dir.join("events.jsonl")).unwrap();
    let done: String = ["sites", "dnszones", "dnsforestzones"]
        .iter()
        .map(|a| format!("{}\n", json!({"type": "done", "area": a, "count": 1})))
        .collect();
    fs::write(dir.join("events.jsonl"), format!("{done}{events}")).unwrap();
}

#[test]
fn dns_replication_and_sites() {
    let dir = tempfile::tempdir().unwrap();
    write_domain(dir.path(), true);
    write_network(dir.path());
    let raw = RawDomain::load(dir.path()).unwrap();
    let out = super::analyze(&crate::results::tests::catalog(), &raw, &[]);
    let r: HashMap<String, CheckResult> =
        out.checks.into_iter().map(|c| (c.id.clone(), c)).collect();
    let failed = |id: &str| {
        assert_eq!(r[id].status, ResultStatus::Failed, "{id}: {:?}", r[id]);
        names(&r[id])
    };
    let reasons = |id: &str| -> String {
        r[id]
            .affected
            .iter()
            .filter_map(|a| a.reason.clone())
            .collect::<Vec<_>>()
            .join(" | ")
    };
    let dc01 = ["dc01.corp.example.com"];

    assert_eq!(failed("AD-DNS-001"), dc01);
    assert_eq!(failed("AD-DNS-002"), dc01);
    assert_eq!(failed("AD-DNS-003"), dc01);
    assert!(reasons("AD-DNS-003").contains("Wildcard") && reasons("AD-DNS-003").contains("wpad"));
    assert!(!reasons("AD-DNS-003").contains("isatap"));
    assert_eq!(failed("AD-DNS-004"), ["corp.example.com"]);
    assert!(reasons("AD-DNS-004").contains("Authenticated Users"));
    assert_eq!(failed("AD-DNS-005"), ["Scavenging", "corp.example.com"]);
    assert_eq!(failed("AD-DNS-006").len(), 1);
    assert_eq!(failed("AD-DNS-009"), dc01);
    assert_eq!(
        failed("AD-DNS-010"),
        ["dc02.corp.example.com", "old-dc.corp.example.com"]
    );
    assert_eq!(
        failed("AD-DNS-012"),
        ["lab.local", "legacy.corp.example.com"]
    );

    assert_eq!(failed("AD-REP-001"), dc01);
    assert!(reasons("AD-REP-001").contains("DC02 / corp: error 8453"));
    assert_eq!(failed("AD-REP-002"), dc01);
    assert_eq!(failed("AD-REP-003"), dc01);
    assert_eq!(failed("AD-REP-005"), ["Branch"]);
    let istg = reasons("AD-REP-005");
    assert!(istg.contains("deleted") && istg.contains("inter-site"));
    assert_eq!(failed("AD-REP-006"), ["Empty"]);
    assert_eq!(failed("AD-REP-007"), ["10.9.0.0/16"]);
    assert_eq!(failed("AD-REP-008"), dc01);
    assert_eq!(failed("AD-REP-009"), ["Lonely"]);
    assert_eq!(failed("AD-REP-010"), ["IP"]);
    assert_eq!(failed("AD-REP-011"), dc01);
    assert!(reasons("AD-REP-011").contains("FRS"));
    assert_eq!(failed("AD-REP-012"), dc01);
    assert_eq!(failed("AD-REP-014"), ["Default Domain Policy"]);
    assert_eq!(failed("AD-REP-015"), ["DC02"]);
    assert_eq!(failed("AD-REP-016"), ["Branch"]);
}

#[test]
fn dns_and_replication_without_new_data() {
    let (r, _) = run(true);
    for id in [
        "AD-DNS-001",
        "AD-DNS-004",
        "AD-DNS-005",
        "AD-DNS-010",
        "AD-REP-001",
        "AD-REP-005",
        "AD-REP-012",
        "AD-REP-014",
    ] {
        assert_eq!(r[id].status, ResultStatus::NotAssessed, "{id}");
    }
    assert_eq!(r["AD-REP-003"].status, ResultStatus::Passed);
}

/// Kerberos and password settings on top of the GPO content fixture:
/// encryption types, ticket policy, silos, fine-grained policies and
/// readable password attributes.
fn write_auth(dir: &Path) {
    write_gpo_content(dir);
    let users = format!("CN=Users,{DOMAIN_DN}");
    patch(dir, "domain", |mut v| {
        v["maxpwdage"] = json!([i64::MIN]);
        v["lockoutthreshold"] = json!([5]);
        v["lockoutduration"] = json!([-6_000_000_000i64]);
        v["lockoutobservationwindow"] = json!([-18_000_000_000i64]);
        Some(v)
    });
    let config = "CN=Configuration,DC=corp,DC=example,DC=com";
    let authn = format!("CN=AuthN Policy Configuration,CN=Services,{config}");
    let silo = |name: &str| format!("CN={name},CN=AuthN Silos,{authn}");
    patch(dir, "users", |mut v| {
        let uac = v["useraccountcontrol"][0].as_i64().unwrap();
        if is(&v, "samaccountname", "krbtgt") {
            v["whencreated"] = json!([iso_days_ago(900)]);
            v["msds-supportedencryptiontypes"] = json!([0x1C]);
        }
        if is(&v, "samaccountname", "jdoe") {
            v["msds-supportedencryptiontypes"] = json!([4]);
        }
        if is(&v, "samaccountname", "Administrator") {
            v["useraccountcontrol"] = json!([uac | 0x40000]);
            v["msds-assignedauthnpolicysilo"] = json!([silo("Audit Silo")]);
        }
        if is(&v, "samaccountname", "adm-jsmith") {
            v["msds-assignedauthnpolicysilo"] = json!([silo("Tier0 Silo")]);
        }
        Some(v)
    });
    patch(dir, "computers", |mut v| {
        if is(&v, "samaccountname", "APP01$") {
            v["msds-supportedencryptiontypes"] = json!([3]);
        }
        Some(v)
    });
    patch(dir, "sysvol", |mut v| {
        if v["folder"] == DDP {
            v["inf"]["Kerberos Policy"] = json!({
                "MaxTicketAge": ["24"], "MaxRenewAge": ["7"], "MaxServiceAge": ["600"], "MaxClockSkew": ["5"],
            });
        } else if v["folder"] == DDCP {
            v["inf"]["Registry Values"] = json!({
                "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters\\SupportedEncryptionTypes": ["4", "2147483644"],
            });
        }
        Some(v)
    });
    patch(dir, "dcconfig", |mut v| {
        if v["name"] == "dc02.corp.example.com" {
            v["data"]["services"]
                .as_array_mut()
                .unwrap()
                .push(json!({"name": "AzureADPasswordProtectionDCAgent", "state": "Running", "start": "Auto"}));
        }
        Some(v)
    });
    write(
        dir,
        "authn",
        &[
            obj(
                json!({"distinguishedname": silo("Tier0 Silo"), "objectclass": ["top", "msDS-AuthNPolicySilo"], "msds-authnpolicysiloenforced": true}),
            ),
            obj(
                json!({"distinguishedname": silo("Audit Silo"), "objectclass": ["top", "msDS-AuthNPolicySilo"], "msds-authnpolicysiloenforced": false}),
            ),
            obj(
                json!({"distinguishedname": format!("CN=Tier0 Policy,CN=AuthN Policies,{authn}"), "objectclass": ["top", "msDS-AuthNPolicy"]}),
            ),
        ],
    );
    let pso = |name: &str, extra: Value| {
        let mut v = json!({
            "distinguishedname": format!("CN={name},CN=Password Settings Container,CN=System,{DOMAIN_DN}"), "name": name,
            "msds-passwordsettingsprecedence": 10, "msds-passwordhistorylength": 24,
            "msds-passwordcomplexityenabled": true, "msds-passwordreversibleencryptionenabled": false,
            "msds-lockoutthreshold": 5,
        });
        for (k, x) in extra.as_object().unwrap() {
            v[k] = x.clone();
        }
        obj(v)
    };
    write(
        dir,
        "psos",
        &[
            pso(
                "Admins PSO",
                json!({"msds-minimumpasswordlength": 16, "msds-psoappliesto": [format!("CN=Domain Admins,{users}")]}),
            ),
            pso(
                "Legacy PSO",
                json!({
                    "msds-minimumpasswordlength": 4, "msds-passwordhistorylength": 0, "msds-passwordcomplexityenabled": false,
                    "msds-passwordreversibleencryptionenabled": true, "msds-lockoutthreshold": 0,
                }),
            ),
        ],
    );
    write(
        dir,
        "pwdattrs",
        &[obj(
            json!({"distinguishedname": format!("CN=jdoe,{users}"), "samaccountname": "jdoe", "objectclass": ["top", "user"]}),
        )],
    );
    let events = fs::read_to_string(dir.join("events.jsonl")).unwrap();
    let done: String = ["authn", "psos", "pwdattrs"]
        .iter()
        .map(|a| format!("{}\n", json!({"type": "done", "area": a, "count": 1})))
        .collect();
    fs::write(dir.join("events.jsonl"), format!("{done}{events}")).unwrap();
}

#[test]
fn kerberos_and_password_policy() {
    let dir = tempfile::tempdir().unwrap();
    write_domain(dir.path(), true);
    write_auth(dir.path());
    let raw = RawDomain::load(dir.path()).unwrap();
    let out = super::analyze(&crate::results::tests::catalog(), &raw, &[]);
    let r: HashMap<String, CheckResult> =
        out.checks.into_iter().map(|c| (c.id.clone(), c)).collect();
    let failed = |id: &str| {
        assert_eq!(r[id].status, ResultStatus::Failed, "{id}: {:?}", r[id]);
        names(&r[id])
    };
    let reasons = |id: &str| -> String {
        r[id]
            .affected
            .iter()
            .filter_map(|a| a.reason.clone())
            .collect::<Vec<_>>()
            .join(" | ")
    };

    assert_eq!(failed("AD-KRB-008"), ["APP01$"]);
    assert_eq!(failed("AD-KRB-009"), ["svc-sql", "jdoe"]);
    assert_eq!(failed("AD-KRB-010"), ["Default Domain Controllers Policy"]);
    assert!(reasons("AD-KRB-010").contains("RC4"));
    assert_eq!(failed("AD-KRB-011"), ["Maximum lifetime for user ticket"]);
    assert_eq!(failed("AD-KRB-015").len(), 1);
    assert_eq!(failed("AD-KRB-016"), ["Administrator", "helpdesk-lead"]);
    assert!(reasons("AD-KRB-016").contains("only audited"));
    assert_eq!(failed("AD-KRB-019"), ["krbtgt"]);
    let krbtgt = reasons("AD-KRB-019");
    assert!(krbtgt.contains("never changed") && krbtgt.contains("RC4"));
    assert_eq!(failed("AD-KRB-020"), ["dc01.corp.example.com"]);

    assert_eq!(r["AD-PWD-003"].status, ResultStatus::Failed);
    assert!(r["AD-PWD-003"]
        .found
        .as_deref()
        .unwrap()
        .contains("Never expires"));
    assert_eq!(r["AD-PWD-007"].status, ResultStatus::Failed);
    assert_eq!(failed("AD-PWD-008"), ["Admins PSO", "Legacy PSO"]);
    assert_eq!(failed("AD-PWD-009"), ["Legacy PSO"]);
    assert!(reasons("AD-PWD-009").contains("no lockout"));
    assert_eq!(failed("AD-PWD-010"), ["helpdesk-lead"]);
    assert_eq!(failed("AD-PWD-020"), ["jdoe"]);
    assert_eq!(failed("AD-PWD-021"), ["dc01.corp.example.com"]);
    assert_eq!(failed("AD-PWD-022"), ["Administrator"]);
}

#[test]
fn kerberos_and_password_policy_defaults() {
    let (r, _) = run(true);
    for id in [
        "AD-KRB-010",
        "AD-KRB-016",
        "AD-PWD-008",
        "AD-PWD-010",
        "AD-PWD-020",
    ] {
        assert_eq!(r[id].status, ResultStatus::NotAssessed, "{id}");
    }
    assert_eq!(r["AD-PWD-003"].status, ResultStatus::Passed);
    assert_eq!(r["AD-PWD-007"].status, ResultStatus::Passed);
    assert_eq!(names(&r["AD-KRB-009"]), ["svc-sql"]);
}

/// Account leftovers, certificate mappings, key credentials, BitLocker
/// escrow and LAPS settings on top of the GPO content fixture.
fn write_objects(dir: &Path) {
    write_gpo_content(dir);
    let users = format!("CN=Users,{DOMAIN_DN}");
    let laps_guid = "11111111-aaaa-bbbb-cccc-000000000001";
    patch(dir, "users", |mut v| {
        if is(&v, "samaccountname", "jdoe") {
            v["displayname"] = json!(["John Doe"]);
            v["altsecurityidentities"] = json!(["X509:<I>CN=Corp CA<SR>1a2b3c"]);
        }
        if is(&v, "samaccountname", "newbie") {
            v["displayname"] = json!(["john doe"]);
        }
        if is(&v, "samaccountname", "Administrator") {
            v["altsecurityidentities"] = json!([
                "X509:<I>CN=Corp CA<S>CN=Administrator",
                "X509:<RFC822>admin@corp.example.com"
            ]);
        }
        Some(v)
    });
    let pre = format!("CN=PRE01,CN=Computers,{DOMAIN_DN}");
    append_area(
        dir,
        "computers",
        &[obj(json!({
            "distinguishedname": pre, "samaccountname": "PRE01$", "objectsid": sid(1130),
            "useraccountcontrol": 0x1020, "primarygroupid": 515, "pwdlastset": ft_days_ago(400),
            "operatingsystem": "Windows 10 Enterprise", "whencreated": iso_days_ago(400),
        }))],
    );
    patch(dir, "schema", |mut v| {
        if is(&v, "ldapdisplayname", "ms-Mcs-AdmPwd") {
            v["schemaidguid"] = json!([laps_guid]);
        }
        Some(v)
    });
    let da = sid(512);
    let du = sid(513);
    append_area(
        dir,
        "acls",
        &[acl(
            &format!("OU=Servers,{DOMAIN_DN}"),
            "organizationalUnit",
            build::sd(
                &da,
                &[
                    (true, 0, right::GENERIC_ALL, None, da.as_str()),
                    (
                        true,
                        0x0a,
                        right::CONTROL_ACCESS,
                        Some(laps_guid),
                        du.as_str(),
                    ),
                    // Applies to the OU itself only: not inherited by computers.
                    (true, 0, right::CONTROL_ACCESS, None, "S-1-5-11"),
                ],
            ),
        )],
    );
    let laps = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\LAPS";
    patch(dir, "sysvol", |mut v| {
        if v["folder"] == BASELINE {
            let reg = v["registry"].as_array_mut().unwrap();
            for (value, data) in [
                ("BackupDirectory", 2),
                ("ADPasswordEncryptionEnabled", 0),
                ("PasswordLength", 8),
                ("PasswordComplexity", 4),
                ("PasswordAgeDays", 30),
            ] {
                reg.push(json!({"scope": "Machine", "key": laps, "value": value, "type": 4, "data": data}));
            }
        }
        Some(v)
    });
    write(
        dir,
        "keycreds",
        &[
            obj(
                json!({"distinguishedname": format!("CN=adm-jsmith,{users}"), "samaccountname": "adm-jsmith"}),
            ),
            obj(
                json!({"distinguishedname": format!("CN=WS01,CN=Computers,{DOMAIN_DN}"), "samaccountname": "WS01$"}),
            ),
        ],
    );
    write(
        dir,
        "bitlocker",
        &[obj(json!({
            "distinguishedname": format!("CN=2026-01-01T00:00:00-08:00{{AB12}},CN=WS01,CN=Computers,{DOMAIN_DN}"),
            "whencreated": iso_days_ago(200),
        }))],
    );
    let events = fs::read_to_string(dir.join("events.jsonl")).unwrap();
    let done: String = ["keycreds", "bitlocker"]
        .iter()
        .map(|a| format!("{}\n", json!({"type": "done", "area": a, "count": 1})))
        .collect();
    fs::write(dir.join("events.jsonl"), format!("{done}{events}")).unwrap();
}

#[test]
fn accounts_computers_and_laps() {
    let dir = tempfile::tempdir().unwrap();
    write_domain(dir.path(), true);
    write_objects(dir.path());
    let raw = RawDomain::load(dir.path()).unwrap();
    let out = super::analyze(&crate::results::tests::catalog(), &raw, &[]);
    let r: HashMap<String, CheckResult> =
        out.checks.into_iter().map(|c| (c.id.clone(), c)).collect();
    let failed = |id: &str| {
        assert_eq!(r[id].status, ResultStatus::Failed, "{id}: {:?}", r[id]);
        names(&r[id])
    };
    let reasons = |id: &str| -> String {
        r[id]
            .affected
            .iter()
            .filter_map(|a| a.reason.clone())
            .collect::<Vec<_>>()
            .join(" | ")
    };

    assert_eq!(failed("AD-ACC-003"), ["adm-old"]);
    assert!(reasons("AD-ACC-003").contains("IT Admins"));
    assert_eq!(failed("AD-ACC-008"), ["jdoe", "newbie"]);
    assert_eq!(failed("AD-ACC-011"), ["PRE01$"]);
    assert_eq!(failed("AD-ACC-012"), ["Administrator"]);
    let maps = reasons("AD-ACC-012");
    assert!(maps.contains("Issuer and subject") && maps.contains("RFC822"));
    assert_eq!(failed("AD-ACC-013"), ["adm-jsmith"]);
    assert_eq!(failed("AD-ACC-016"), ["DnsAdmins"]);
    assert_eq!(r["AD-CMP-002"].status, ResultStatus::Passed);
    assert!(r["AD-CMP-002"]
        .raw
        .as_deref()
        .unwrap()
        .contains("Windows 11 Enterprise"));
    assert_eq!(failed("AD-CMP-006"), ["PRE01$"]);
    assert_eq!(failed("AD-LAPS-004"), ["Server Baseline"]);
    assert_eq!(failed("AD-LAPS-005"), ["Server Baseline"]);
    assert!(reasons("AD-LAPS-005").contains("length 8"));
    assert_eq!(failed("AD-LAPS-006"), ["DSRM password"]);
    assert_eq!(failed("AD-LAPS-007"), ["Domain Users", "Helpdesk"]);
    assert!(!reasons("AD-LAPS-007").contains("Authenticated Users"));
}

#[test]
fn accounts_computers_and_laps_defaults() {
    let (r, _) = run(true);
    assert_eq!(names(&r["AD-ACC-003"]), ["adm-old"]);
    assert_eq!(r["AD-ACC-008"].status, ResultStatus::Passed);
    for id in ["AD-ACC-013", "AD-CMP-006", "AD-LAPS-004", "AD-LAPS-005"] {
        assert_eq!(r[id].status, ResultStatus::NotAssessed, "{id}");
    }
}

/// Schema definitions, extra trusts, a foreign admin, log agents, Exchange
/// groups and an Entra Connect account on top of the GPO content fixture.
fn write_misc(dir: &Path) {
    write_gpo_content(dir);
    let users = format!("CN=Users,{DOMAIN_DN}");
    let system = format!("CN=System,{DOMAIN_DN}");
    let schema = |name: &str, class: &str, extra: Value| {
        let mut v = json!({
            "distinguishedname": format!("CN={name},CN=Schema"), "ldapdisplayname": name,
            "objectclass": ["top", class],
        });
        for (k, x) in extra.as_object().unwrap() {
            v[k] = x.clone();
        }
        obj(v)
    };
    patch(dir, "schema", |mut v| {
        if is(&v, "ldapdisplayname", "ms-Mcs-AdmPwd") {
            v["objectclass"] = json!(["top", "attributeSchema"]);
            v["searchflags"] = json!([904]);
        }
        Some(v)
    });
    append_area(
        dir,
        "schema",
        &[
            schema(
                "msFVE-RecoveryPassword",
                "attributeSchema",
                json!({"searchflags": 8, "systemflags": 16}),
            ),
            schema(
                "appSecretKey",
                "attributeSchema",
                json!({"searchflags": 0, "systemflags": 0, "whencreated": iso_days_ago(10), "whenchanged": iso_days_ago(10)}),
            ),
            schema(
                "user",
                "classSchema",
                json!({"systemflags": 16, "whencreated": iso_days_ago(3000), "whenchanged": iso_days_ago(30)}),
            ),
        ],
    );
    patch(dir, "trusts", |mut v| {
        v["securityidentifier"] = json!(["S-1-5-21-7-7-7"]);
        Some(v)
    });
    append_area(
        dir,
        "trusts",
        &[
            obj(json!({
                "distinguishedname": format!("CN=child.corp.example.com,{system}"), "trustpartner": "child.corp.example.com",
                "trustdirection": 3, "trusttype": 2, "trustattributes": 0x20, "msds-supportedencryptiontypes": 0x18,
            })),
            obj(json!({
                "distinguishedname": format!("CN=REALM.EXAMPLE,{system}"), "trustpartner": "REALM.EXAMPLE",
                "trustdirection": 2, "trusttype": 3, "trustattributes": 0,
            })),
        ],
    );
    let ewp = sid(1140);
    append_area(
        dir,
        "users",
        &[
            user("exadmin", 1141, 0x200, 30, Some(1), json!({})),
            user("MSOL_0a1b2c3d", 1142, 0x200, 600, Some(200), json!({})),
        ],
    );
    patch(dir, "groups", |mut v| {
        if is(&v, "samaccountname", "Domain Admins") {
            v["member"].as_array_mut().unwrap().push(json!(format!(
                "CN=S-1-5-21-7-7-7-1105,CN=ForeignSecurityPrincipals,{DOMAIN_DN}"
            )));
        }
        Some(v)
    });
    append_area(
        dir,
        "groups",
        &[group(
            "Exchange Windows Permissions",
            &ewp,
            &users,
            &[format!("CN=exadmin,{users}")],
        )],
    );
    let da = sid(512);
    patch(dir, "acls", |v| {
        if v["distinguishedname"][0] == DOMAIN_DN {
            return Some(acl(
                DOMAIN_DN,
                "domainDNS",
                build::sd(
                    &da,
                    &[
                        (true, 0, right::GENERIC_ALL, None, "S-1-5-18"),
                        (true, 0, right::GENERIC_ALL, None, da.as_str()),
                        (true, 0, right::WRITE_DACL, None, ewp.as_str()),
                    ],
                ),
            ));
        }
        Some(v)
    });
    let helpdesk = sid(1106);
    patch(dir, "sysvol", |mut v| {
        if v["folder"] == DDCP {
            v["inf"]["Privilege Rights"]["SeSecurityPrivilege"] =
                json!(["*S-1-5-32-544", format!("*{helpdesk}")]);
        }
        Some(v)
    });
    patch(dir, "dcconfig", |mut v| {
        if v["name"] == "dc02.corp.example.com" {
            v["data"]["software"] = json!([{"name": "Splunk Universal Forwarder", "publisher": "Splunk", "version": "9.2"}]);
            v["data"]["services"]
                .as_array_mut()
                .unwrap()
                .push(json!({"name": "Sysmon64", "state": "Running", "start": "Auto"}));
        }
        Some(v)
    });
}

#[test]
fn schema_trusts_audit_and_applications() {
    let dir = tempfile::tempdir().unwrap();
    write_domain(dir.path(), true);
    write_misc(dir.path());
    let raw = RawDomain::load(dir.path()).unwrap();
    let out = super::analyze(&crate::results::tests::catalog(), &raw, &[]);
    let r: HashMap<String, CheckResult> =
        out.checks.into_iter().map(|c| (c.id.clone(), c)).collect();
    let failed = |id: &str| {
        assert_eq!(r[id].status, ResultStatus::Failed, "{id}: {:?}", r[id]);
        names(&r[id])
    };
    let reasons = |id: &str| -> String {
        r[id]
            .affected
            .iter()
            .filter_map(|a| a.reason.clone())
            .collect::<Vec<_>>()
            .join(" | ")
    };

    assert_eq!(failed("AD-SCH-001"), ["msFVE-RecoveryPassword"]);
    assert_eq!(failed("AD-SCH-002"), ["appSecretKey"]);
    assert_eq!(failed("AD-SCH-006"), ["appSecretKey", "user"]);
    assert_eq!(
        failed("AD-TRU-005"),
        ["partner.example.org", "REALM.EXAMPLE"]
    );
    assert_eq!(failed("AD-TRU-008"), ["partner.example.org"]);
    assert_eq!(r["AD-TRU-010"].status, ResultStatus::Passed);
    assert!(r["AD-TRU-010"]
        .raw
        .as_deref()
        .unwrap()
        .contains("REALM.EXAMPLE"));
    assert_eq!(failed("AD-TRU-012"), ["S-1-5-21-7-7-7-1105"]);
    assert!(reasons("AD-TRU-012").contains("partner.example.org"));
    assert_eq!(failed("AD-AUD-005"), ["dc01.corp.example.com"]);
    assert_eq!(failed("AD-AUD-008"), ["dc01.corp.example.com"]);
    assert_eq!(failed("AD-AUD-010"), ["Default Domain Controllers Policy"]);
    assert_eq!(failed("AD-APP-001"), ["Exchange Windows Permissions"]);
    assert_eq!(failed("AD-APP-002"), ["exadmin"]);
    assert_eq!(failed("AD-APP-006"), ["MSOL_0a1b2c3d"]);
}

#[test]
fn schema_trusts_audit_and_applications_defaults() {
    let (r, _) = run(true);
    for id in ["AD-SCH-001", "AD-SCH-002", "AD-SCH-006", "AD-AUD-010"] {
        assert_eq!(r[id].status, ResultStatus::NotAssessed, "{id}");
    }
    assert_eq!(r["AD-APP-001"].status, ResultStatus::Passed);
    assert_eq!(r["AD-APP-006"].status, ResultStatus::Passed);
    assert_eq!(names(&r["AD-TRU-008"]), ["partner.example.org"]);
}

/// Writes a view of the hunting fixtures for the browser preview:
/// `DCA_PREVIEW_OUT=app/.preview cargo test -p dca-core preview_hunting -- --ignored`
#[test]
#[ignore]
fn preview_hunting() {
    let Ok(out) = std::env::var("DCA_PREVIEW_OUT") else {
        return;
    };
    let root = tempfile::tempdir().unwrap();
    let dir = crate::analysis::create(
        root.path(),
        crate::analysis::NewAssessment {
            name: Some("Hunting test".into()),
            domains: vec!["corp.example.com".into()],
            tenant: None,
            areas: vec![],
        },
        crate::time::now(),
    )
    .unwrap();
    let raw = crate::analysis::ad_raw_dir(&dir, "corp.example.com");
    fs::create_dir_all(&raw).unwrap();
    write_domain(&raw, true);
    write_hunts(&raw);
    let catalog = crate::results::tests::catalog();
    crate::analysis::analyze(&dir, &catalog).unwrap();
    let a = crate::results::Assessment::load(&dir).unwrap();
    let view = crate::results::view(&catalog, &[a]);
    fs::write(
        Path::new(&out).join("view-hunting-test.json"),
        serde_json::to_string(&view).unwrap(),
    )
    .unwrap();
}

/// Scale: a domain with 100,000 users, 30,000 computers and 3,000 nested
/// groups must be read and analyzed within a time budget. Run in release
/// mode: `cargo test --release -p dca-core -- --ignored large_directory`.
#[test]
#[ignore = "slow in debug builds; CI runs it in release mode"]
fn large_directory_is_analyzed_within_budget() {
    const USERS: u32 = 100_000;
    const COMPUTERS: u32 = 30_000;
    const GROUPS: u32 = 3_000;
    const BUDGET_SECS: f64 = 30.0;

    let dir = tempfile::tempdir().unwrap();
    write_domain(dir.path(), true);
    let ou = |i: u32| format!("OU=Dept{},OU=People,{DOMAIN_DN}", i % 50);
    let user_dn = |i: u32| format!("CN=user{i},{}", ou(i));
    let users: Vec<Value> = (0..USERS)
        .map(|i| {
            let mut o = json!({
                "distinguishedname": user_dn(i),
                "samaccountname": format!("user{i}"),
                "objectsid": sid(200_000 + i),
                "useraccountcontrol": if i % 20 == 0 { 0x202 } else { 0x200 },
                "pwdlastset": ft_days_ago(i64::from(i % 900)),
                "primarygroupid": 513,
                "whencreated": iso_days_ago(1000 + i64::from(i % 400)),
            });
            if i % 7 != 0 {
                o["lastlogontimestamp"] = json!(ft_days_ago(i64::from(i % 400)));
            }
            if i % 1000 == 0 {
                o["serviceprincipalname"] = json!([format!("HTTP/app{i}.corp.example.com")]);
            }
            obj(o)
        })
        .collect();
    append_area(dir.path(), "users", &users);
    let computers: Vec<Value> = (0..COMPUTERS)
        .map(|i| {
            obj(json!({
                "distinguishedname": format!("CN=WS{i:05},OU=Workstations,{DOMAIN_DN}"),
                "samaccountname": format!("WS{i:05}$"),
                "objectsid": sid(400_000 + i),
                "useraccountcontrol": 0x1000,
                "pwdlastset": ft_days_ago(i64::from(i % 120)),
                "lastlogontimestamp": ft_days_ago(i64::from(i % 200)),
                "operatingsystem": "Windows 11 Enterprise",
                "primarygroupid": 515,
                "whencreated": iso_days_ago(500),
            }))
        })
        .collect();
    append_area(dir.path(), "computers", &computers);
    let group_dn = |g: u32| format!("CN=Group{g},OU=Groups,{DOMAIN_DN}");
    let groups: Vec<Value> = (0..GROUPS)
        .map(|g| {
            // 100 users each, and every tenth group nests the next one.
            let mut members: Vec<String> =
                (0..100).map(|k| user_dn((g * 100 + k) % USERS)).collect();
            if g % 10 == 0 && g + 1 < GROUPS {
                members.push(group_dn(g + 1));
            }
            obj(json!({
                "distinguishedname": group_dn(g),
                "samaccountname": format!("Group{g}"),
                "objectsid": sid(500_000 + g),
                "member": members,
            }))
        })
        .collect();
    append_area(dir.path(), "groups", &groups);

    let catalog = crate::results::tests::catalog();
    let started = std::time::Instant::now();
    let raw = RawDomain::load(dir.path()).unwrap();
    let out = super::analyze(&catalog, &raw, &[]);
    let secs = started.elapsed().as_secs_f64();
    println!(
        "read and analyzed {} directory objects in {secs:.1} s",
        out.directory.objects.len()
    );

    assert!(out.directory.objects.len() > (USERS + COMPUTERS + GROUPS) as usize);
    assert!(!out.checks.is_empty());
    assert!(
        secs < BUDGET_SECS,
        "took {secs:.1} s, budget {BUDGET_SECS} s"
    );
}
