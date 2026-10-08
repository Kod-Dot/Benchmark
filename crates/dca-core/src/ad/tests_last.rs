//! Tests for computer owners, delegated groups, SACLs, service connection
//! points, Configuration Manager, management ports, DSRM, replication
//! timelines and certificate requests for other users.

use std::collections::HashMap;

use serde_json::{json, Value};

use super::raw::RawDomain;
use super::sd::{build, right};
use super::tests::{append_area, iso_days_ago, names, obj, patch, sid, write_domain, DOMAIN_DN};
use crate::results::{CheckResult, ResultStatus};

fn b64(bytes: Vec<u8>) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn mark_done(dir: &std::path::Path, areas: &[&str]) {
    let events = std::fs::read_to_string(dir.join("events.jsonl")).unwrap();
    let done: String = areas
        .iter()
        .map(|a| format!("{}\n", json!({"type": "done", "area": a, "count": 1})))
        .collect();
    std::fs::write(dir.join("events.jsonl"), format!("{done}{events}")).unwrap();
}

fn run(setup: impl Fn(&std::path::Path)) -> HashMap<String, CheckResult> {
    let dir = tempfile::tempdir().unwrap();
    write_domain(dir.path(), true);
    setup(dir.path());
    let raw = RawDomain::load(dir.path()).unwrap();
    super::analyze(&crate::results::tests::catalog(), &raw, &[])
        .checks
        .into_iter()
        .map(|c| (c.id.clone(), c))
        .collect()
}

fn failed<'a>(r: &'a HashMap<String, CheckResult>, id: &str) -> &'a CheckResult {
    assert_eq!(r[id].status, ResultStatus::Failed, "{id}: {:?}", r[id]);
    &r[id]
}

fn reason(r: &CheckResult, i: usize) -> &str {
    r.affected[i].reason.as_deref().unwrap_or_default()
}

fn write_objects(dir: &std::path::Path) {
    let da = sid(512);
    let jdoe = sid(1108);
    let comp = |name: &str, ou: &str, owner: &str| {
        obj(
            json!({"distinguishedname": format!("CN={name},{ou}"), "samaccountname": format!("{name}$"),
                   "ntsecuritydescriptor": b64(build::sd(owner, &[]))}),
        )
    };
    append_area(
        dir,
        "computerowners",
        &[
            comp("DC01", &format!("OU=Domain Controllers,{DOMAIN_DN}"), &da),
            comp("WS01", &format!("CN=Computers,{DOMAIN_DN}"), &jdoe),
            comp("APP01", &format!("OU=Servers,{DOMAIN_DN}"), "S-1-5-32-544"),
        ],
    );
    // Audit entries: the domain head audits writes by Everyone; AdminSDHolder
    // audits only failures; a protected group has no SACL at all.
    let sacl = |dn: &str, aces: &[(u8, u32, bool, &str)]| {
        obj(json!({"distinguishedname": dn, "ntsecuritydescriptor": b64(build::sacl(aces))}))
    };
    append_area(
        dir,
        "sacls",
        &[
            sacl(
                DOMAIN_DN,
                &[(
                    0x40,
                    right::WRITE_PROP | right::WRITE_DACL,
                    false,
                    "S-1-1-0",
                )],
            ),
            sacl(
                &format!("CN=AdminSDHolder,CN=System,{DOMAIN_DN}"),
                &[(0x80, right::WRITE_PROP, false, "S-1-1-0")],
            ),
            sacl(&format!("CN=Domain Admins,CN=Users,{DOMAIN_DN}"), &[]),
        ],
    );
    append_area(
        dir,
        "scps",
        &[
            obj(
                json!({"distinguishedname": format!("CN=SQL,CN=WS01,CN=Computers,{DOMAIN_DN}"), "serviceclassname": "MSSQLSvc", "servicednsname": "ws01.corp.example.com"}),
            ),
            obj(
                json!({"distinguishedname": format!("CN=Old app,CN=System,{DOMAIN_DN}"), "serviceclassname": "LegacyApp", "servicednsname": "gone01.corp.example.com"}),
            ),
        ],
    );
    let sm = format!("CN=System Management,CN=System,{DOMAIN_DN}");
    append_area(
        dir,
        "sccm",
        &[
            obj(
                json!({"distinguishedname": sm, "objectclass": ["top", "container"],
                       "ntsecuritydescriptor": b64(build::sd(&da, &[(true, 0, right::GENERIC_ALL, None, &sid(1110)), (true, 0, right::GENERIC_ALL, None, &sid(1106))]))}),
            ),
            obj(
                json!({"distinguishedname": format!("CN=SMS-Site-P01,{sm}"), "objectclass": ["top", "mSSMSSite"], "mssmssitecode": "P01"}),
            ),
        ],
    );
    // A delegated group in an admin OU whose member lives in CN=Users.
    let admin_ou = format!("OU=Admin,{DOMAIN_DN}");
    let group_dn = format!("CN=Server Admins,{admin_ou}");
    append_area(
        dir,
        "groups",
        &[obj(
            json!({"distinguishedname": group_dn, "samaccountname": "Server Admins", "objectsid": sid(1150), "grouptype": -2147483646,
                     "member": [format!("CN=jdoe,CN=Users,{DOMAIN_DN}")]}),
        )],
    );
    append_area(
        dir,
        "acls",
        &[obj(
            json!({"distinguishedname": format!("OU=Servers,{DOMAIN_DN}"), "objectclass": ["top", "organizationalUnit"],
                     "ntsecuritydescriptor": b64(build::sd(&da, &[(true, 0, right::GENERIC_ALL, None, &da), (true, 0, right::GENERIC_ALL, None, &sid(1150))]))}),
        )],
    );
    mark_done(dir, &["computerowners", "sacls", "scps", "sccm"]);
}

#[test]
fn directory_objects_owners_and_audit() {
    let r = run(write_objects);
    let o = failed(&r, "AD-CMP-010");
    assert_eq!(names(o), ["WS01$"], "built-in owners are fine");
    assert!(reason(o, 0).contains("jdoe"));
    let a = failed(&r, "AD-AUD-003");
    assert_eq!(names(a), ["AdminSDHolder", "Domain Admins"]);
    let s = failed(&r, "AD-APP-008");
    assert_eq!(
        names(s),
        ["Old app"],
        "the SCP under an existing computer is fine"
    );
    let c = failed(&r, "AD-APP-003");
    assert_eq!(
        names(c),
        ["Helpdesk"],
        "the site server's computer account may control System Management"
    );
    let d = failed(&r, "AD-OU-008");
    assert_eq!(names(d), ["jdoe"]);
    assert!(reason(d, 0).contains("Server Admins") && reason(d, 0).contains("Servers"));
}

#[test]
fn sacls_need_the_auditing_right() {
    let r = run(|dir| {
        append_area(
            dir,
            "sacls",
            &[obj(json!({"distinguishedname": DOMAIN_DN}))],
        );
        mark_done(dir, &["sacls"]);
    });
    assert_eq!(r["AD-AUD-003"].status, ResultStatus::NotAssessed);
    assert!(r["AD-AUD-003"]
        .note
        .as_deref()
        .unwrap()
        .contains("Manage auditing"));
}

fn summary(rows: Vec<Value>) -> Value {
    json!({"count": rows.len(), "top": rows})
}

#[test]
fn hosts_events_and_ca_requests() {
    let r = run(|dir| {
        super::tests::write_dc_data(dir);
        super::tests_ep::write_endpoints(dir);
        patch(dir, "dcconfig", |mut v| {
            if v["name"] == "dc01.corp.example.com" {
                v["data"]["mgmtrules"] = json!([
                    {"name": "Remote Desktop - User Mode (TCP-In)", "ports": ["3389"], "remote": ["Any"]},
                    {"name": "WinRM from PAWs", "ports": ["5985"], "remote": ["10.10.0.0/24"]},
                ]);
                v["data"]["certsvc"] = json!({
                    "installed": true, "name": "corp-DC01-CA", "edit_flags": 0, "interface_flags": 0x641, "audit_filter": 127,
                    "aces": [], "web": {"installed": false}, "issued_templates": ["User"],
                    "san_requests": [
                        {"requester": "CORP\\jdoe", "template": "WebServer", "upn": "adm-jsmith@corp.example.com", "from_attributes": false, "issued": iso_days_ago(3)},
                        {"requester": "CORP\\helpdesk-lead", "template": "User", "upn": "jdoe@corp.example.com", "from_attributes": true, "issued": iso_days_ago(4)},
                    ],
                });
            }
            Some(v)
        });
        patch(dir, "dcevents", |mut v| {
            if v["name"] == "dc01.corp.example.com" {
                v["queries"]["hunt_dsrm"] = summary(vec![]);
            }
            Some(v)
        });
    });
    let t = failed(&r, "EP-T0-009");
    assert_eq!(names(t), ["dc01.corp.example.com"]);
    assert!(reason(t, 0).contains("Remote Desktop") && !reason(t, 0).contains("WinRM"));
    let h = failed(&r, "HUNT-AD-017");
    assert_eq!(h.affected.len(), 1, "jdoe is not privileged");
    assert!(reason(h, 0).contains("CORP\\jdoe obtained a certificate for adm-jsmith"));
    let d = failed(&r, "AD-BKP-004");
    assert!(reason(d, 0).contains("No DSRM password change"));
}

#[test]
fn dsrm_password_set_recently_passes() {
    let r = run(|dir| {
        super::tests::write_dc_data(dir);
        patch(dir, "dcevents", |mut v| {
            if v["name"] == "dc01.corp.example.com" {
                v["queries"]["hunt_dsrm"] = summary(vec![
                    json!({"key": "CORP\\Administrator|0x0", "count": 1, "last": iso_days_ago(20)}),
                ]);
            }
            Some(v)
        });
    });
    assert_eq!(
        r["AD-BKP-004"].status,
        ResultStatus::Passed,
        "{:?}",
        r["AD-BKP-004"]
    );
    assert!(r["AD-BKP-004"]
        .found
        .as_deref()
        .unwrap()
        .contains("CORP\\Administrator"));
}

#[test]
fn replication_metadata_timeline() {
    let r = run(|dir| {
        let meta = |attr: &str, when: &str, dsa: &str| {
            format!("<DS_REPL_ATTR_META_DATA><pszAttributeName>{attr}</pszAttributeName><ftimeLastOriginatingChange>{when}</ftimeLastOriginatingChange><pszLastOriginatingDsaDN>{dsa}</pszLastOriginatingDsaDN></DS_REPL_ATTR_META_DATA>")
        };
        let ntds = |dc: &str| {
            format!("CN=NTDS Settings,CN={dc},CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,{DOMAIN_DN}")
        };
        let day = iso_days_ago(2);
        let at = |h: &str| format!("{}T{h}:00:00Z", &day[..10]);
        append_area(
            dir,
            "attrmeta",
            &[obj(
                json!({"distinguishedname": format!("CN=svc-sql,CN=Users,{DOMAIN_DN}"), "samaccountname": "svc-sql",
                "msds-replattributemetadata": [
                    meta("servicePrincipalName", &at("14"), &ntds("DC01")),
                    meta("msDS-KeyCredentialLink", &at("13"), &ntds("ROGUE7")),
                    meta("description", &at("03"), &ntds("DC01")),
                ]}),
            )],
        );
        mark_done(dir, &["attrmeta", "privmeta"]);
    });
    let h = failed(&r, "HUNT-AD-023");
    assert_eq!(h.affected.len(), 2);
    assert!(h.affected.iter().any(|a| a
        .reason
        .as_deref()
        .unwrap()
        .contains("rogue7, which is not a current domain controller")));
    assert!(h.affected.iter().any(|a| a
        .reason
        .as_deref()
        .unwrap()
        .contains("description changed at")
        && a.reason
            .as_deref()
            .unwrap()
            .contains("outside working hours")));
}

#[test]
fn recovery_readiness() {
    let r = run(|_| {});
    let c = &r["AD-BKP-005"];
    assert_ne!(c.status, ResultStatus::NotAssessed, "{c:?}");
    let raw = c.raw.as_deref().unwrap();
    assert!(
        raw.contains("Tombstone lifetime") && raw.contains("Domain controllers: "),
        "{raw}"
    );
}
