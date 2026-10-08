//! Tests for the account, group and OU checks in `rules_more`.

use std::collections::HashMap;

use serde_json::json;

use super::raw::RawDomain;
use super::tests::{append_area, group, is, names, obj, patch, user, write_domain, DOMAIN_DN};
use crate::results::{CheckResult, ResultStatus};

fn users_dn() -> String {
    format!("CN=Users,{DOMAIN_DN}")
}

fn run_batch(setup: impl Fn(&std::path::Path)) -> HashMap<String, CheckResult> {
    let dir = tempfile::tempdir().unwrap();
    write_domain(dir.path(), true);
    setup(dir.path());
    let raw = RawDomain::load(dir.path()).unwrap();
    let out = super::analyze(&crate::results::tests::catalog(), &raw, &[]);
    out.checks.into_iter().map(|c| (c.id.clone(), c)).collect()
}

fn add_members(dir: &std::path::Path, name: &str, members: Vec<String>) {
    patch(dir, "groups", |mut v| {
        if is(&v, "samaccountname", name) {
            let list = v["member"].as_array_mut().unwrap();
            list.extend(members.iter().map(|m| json!(m)));
        }
        Some(v)
    });
}

#[test]
fn accounts_groups_and_ous_from_existing_data() {
    let u = users_dn();
    let r = run_batch(|dir| {
        let fsp = format!("CN=S-1-5-21-9-9-9-1234,CN=ForeignSecurityPrincipals,{DOMAIN_DN}");
        add_members(dir, "Domain Admins", vec![fsp, format!("CN=svc-sql,{u}")]);
        add_members(dir, "Administrators", vec![format!("CN=helpdesk-lead,{u}")]);
        append_area(
            dir,
            "groups",
            &[
                group(
                    "Group Policy Creator Owners",
                    &super::tests::sid(520),
                    &u,
                    &[format!("CN=helpdesk-lead,{u}")],
                ),
                group(
                    "Key Admins",
                    &super::tests::sid(526),
                    &u,
                    &[format!("CN=jdoe,{u}")],
                ),
                obj(json!({
                    "distinguishedname": format!("CN=Everyone Team,{u}"),
                    "samaccountname": "Everyone Team",
                    "objectsid": super::tests::sid(1700),
                    "member": (0..501).map(|i| format!("CN=u{i},{u}")).collect::<Vec<_>>(),
                })),
            ],
        );
        patch(dir, "users", |mut v| {
            if is(&v, "samaccountname", "jdoe") {
                v["primarygroupid"] = json!([512]);
            }
            Some(v)
        });
        append_area(
            dir,
            "users",
            &[user(
                "krbtgt_55555",
                1500,
                0x202,
                800,
                None,
                json!({"description": "Key Distribution Center Service Account for read-only domain controller"}),
            )],
        );
        let deep: String = (0..11).map(|i| format!("OU=l{i},")).collect();
        append_area(
            dir,
            "containers",
            &[obj(json!({
                "distinguishedname": format!("{deep}{DOMAIN_DN}"),
                "name": "l0",
                "objectclass": ["top", "organizationalUnit"],
            }))],
        );
    });
    let failed = |id: &str| {
        assert_eq!(r[id].status, ResultStatus::Failed, "{id}: {:?}", r[id]);
        names(&r[id])
    };
    assert!(failed("AD-ACC-009").contains(&"svc-sql"));
    assert_eq!(
        failed("AD-ACC-015"),
        ["S-1-5-21-9-9-9-1234", "S-1-5-21-1000-2000-3000-9999"]
    );
    assert_eq!(failed("AD-ACC-018"), ["Everyone Team"]);
    assert_eq!(failed("AD-CMP-003"), ["APP01$"]);
    assert!(failed("AD-KRB-017").contains(&"Administrator"));
    assert!(!failed("AD-KRB-017").contains(&"adm-jsmith"));
    assert_eq!(failed("AD-PRIV-004"), ["helpdesk-lead"]);
    assert_eq!(failed("AD-PRIV-007"), ["helpdesk-lead"]);
    assert_eq!(failed("AD-PRIV-008"), ["jdoe"]);
    assert_eq!(failed("AD-PRIV-012"), ["svc-sql"]);
    assert_eq!(failed("AD-PRIV-019"), ["Administrator"]);
    assert_eq!(failed("AD-PRIV-022"), ["krbtgt_55555"]);
    assert_eq!(failed("AD-PRIV-026"), ["S-1-5-21-9-9-9-1234"]);
    assert_eq!(failed("AD-IOC-009"), ["jdoe"]);
    assert_eq!(failed("AD-LAPS-002"), ["APP01$"]);
    assert_eq!(failed("AD-OU-001").len(), 1);
    assert!(r["AD-ACC-014"]
        .found
        .as_deref()
        .unwrap()
        .contains("without a workstation restriction"));
}

#[test]
fn a_clean_domain_passes_the_account_checks() {
    let r = run_batch(|dir| {
        patch(dir, "users", |v| {
            (!is(&v, "samaccountname", "svc-sql")).then_some(v)
        });
        patch(dir, "computers", |mut v| {
            if is(&v, "samaccountname", "APP01$") {
                v["useraccountcontrol"] = json!([0x1000]);
                v["ms-mcs-admpwdexpirationtime"] = json!([1]);
            }
            Some(v)
        });
    });
    for id in [
        "AD-ACC-009",
        "AD-ACC-018",
        "AD-CMP-003",
        "AD-PRIV-007",
        "AD-PRIV-022",
        "AD-IOC-009",
        "AD-LAPS-002",
    ] {
        assert_eq!(r[id].status, ResultStatus::Passed, "{id}: {:?}", r[id]);
    }
}

/// Runs in CI against a real directory: a Samba Active Directory domain
/// built by tools/lab/start-domain.sh, seeded by tools/lab/seed.sh and read
/// by the shipped collector. Every expectation in tools/lab/expected.json
/// must hold, and no check may be left unassessed because an area the
/// collector read could not be understood.
#[test]
#[ignore]
fn live_lab_domain_matches_expectations() {
    let Some(dir) = std::env::var_os("DCA_LAB_DIR") else {
        panic!("set DCA_LAB_DIR to the folder the collector wrote for the lab domain");
    };
    let raw = RawDomain::load(std::path::Path::new(&dir)).expect("the lab collection loads");
    let out = super::analyze(&crate::results::tests::catalog(), &raw, &[]);
    let r: HashMap<String, CheckResult> =
        out.checks.into_iter().map(|c| (c.id.clone(), c)).collect();

    let mut ids: Vec<&String> = r.keys().collect();
    ids.sort();
    for id in &ids {
        let c = &r[*id];
        println!(
            "{id}\t{:?}\t{}\t{}",
            c.status,
            c.affected_count.unwrap_or(0),
            c.note.as_deref().or(c.found.as_deref()).unwrap_or_default()
        );
    }

    let mut problems = Vec::new();
    let expected: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/lab/expected.json"),
        )
        .unwrap(),
    )
    .unwrap();
    for (id, want) in expected.as_object().unwrap() {
        if id.starts_with('_') {
            continue;
        }
        let Some(c) = r.get(id) else {
            problems.push(format!("{id}: did not run"));
            continue;
        };
        let status = match want["status"].as_str().unwrap() {
            "failed" => ResultStatus::Failed,
            "passed" => ResultStatus::Passed,
            "not_assessed" => ResultStatus::NotAssessed,
            other => panic!("{id}: unknown status {other}"),
        };
        if c.status != status {
            problems.push(format!(
                "{id}: expected {status:?}, got {:?} ({c:?})",
                c.status
            ));
        }
        if let Some(text) = want["found_contains"].as_str() {
            if !c.found.as_deref().unwrap_or_default().contains(text) {
                problems.push(format!(
                    "{id}: found {:?} does not contain {text:?}",
                    c.found
                ));
            }
        }
        let got = names(c);
        for name in want["includes"].as_array().into_iter().flatten() {
            let name = name.as_str().unwrap();
            if !got.contains(&name) {
                problems.push(format!("{id}: {name} not among {got:?}"));
            }
        }
    }
    // Areas the lab collection holds must be understood: a check may only be
    // unassessed when its data was not collected at all.
    for id in ids {
        let c = &r[id];
        if c.status == ResultStatus::NotAssessed
            && c.note
                .as_deref()
                .is_some_and(|n| n.contains("could not be read"))
        {
            problems.push(format!("{id}: {}", c.note.as_deref().unwrap()));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

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

fn write_forest(dir: &std::path::Path) {
    use super::sd::{build, right};
    let config = format!("CN=Configuration,{DOMAIN_DN}");
    let helpdesk = super::tests::sid(1106);
    let site = format!("CN=Default-First-Site-Name,CN=Sites,{config}");
    let ntds = |dc: &str| format!("CN=NTDS Settings,CN={dc},CN=Servers,{site}");
    let da = super::tests::sid(512);
    append_area(
        dir,
        "roles",
        &[
            obj(json!({
                "distinguishedname": format!("CN=RID Manager$,CN=System,{DOMAIN_DN}"),
                "objectclass": ["top", "rIDManager"],
                "fsmoroleowner": format!("CN=NTDS Settings\\0ADEL:1234,CN=OLDDC,CN=Servers,{site}"),
            })),
            obj(json!({
                "distinguishedname": format!("CN=Infrastructure,{DOMAIN_DN}"),
                "objectclass": ["top", "infrastructureUpdate"],
                "fsmoroleowner": ntds("DC01"),
            })),
        ],
    );
    append_area(
        dir,
        "sites",
        &[obj(json!({
            "distinguishedname": ntds("DC01"),
            "objectclass": ["top", "applicationSettings", "nTDSDSA"],
        }))],
    );
    patch(dir, "domain", |mut v| {
        v["fsmoroleowner"] = json!([ntds("DC01")]);
        Some(v)
    });
    patch(dir, "schema", |mut v| {
        if v["objectclass"].to_string().contains("dMD") {
            v["fsmoroleowner"] = json!([ntds("DC01")]);
            v["whencreated"] = json!(["2024-01-01T00:00:00Z"]);
        }
        Some(v)
    });
    patch(dir, "partitions", |mut v| {
        v["upnsuffixes"] = json!(["contoso.com"]);
        v["fsmoroleowner"] = json!([ntds("DC01")]);
        Some(v)
    });
    append_area(
        dir,
        "partitions",
        &[
            obj(json!({
                "distinguishedname": format!("CN=OLD,CN=Partitions,{config}"),
                "objectclass": ["top", "crossRef"],
                "ncname": "DC=old,DC=example,DC=com", "dnsroot": "old.example.com",
                "enabled": false, "systemflags": 3,
            })),
            obj(json!({
                "distinguishedname": format!("CN=AppData,CN=Partitions,{config}"),
                "objectclass": ["top", "crossRef"],
                "ncname": "DC=AppData,DC=corp,DC=example,DC=com", "systemflags": 5,
            })),
        ],
    );
    append_area(
        dir,
        "querypolicy",
        &[obj(json!({
            "distinguishedname": format!("CN=Default Query Policy,CN=Query-Policies,CN=Directory Service,CN=Windows NT,CN=Services,{config}"),
            "ldapadminlimits": ["MaxPageSize=5000", "MaxQueryDuration=120"],
        }))],
    );
    append_area(
        dir,
        "dispspec",
        &[obj(json!({
            "distinguishedname": format!("CN=user-Display,CN=409,CN=DisplaySpecifiers,{config}"),
            "admincontextmenu": ["4,&Reset tool,\\\\fileserver\\tools\\reset.exe"],
        }))],
    );
    append_area(
        dir,
        "extrights",
        &[obj(json!({
            "distinguishedname": format!("CN=Old-Right,CN=Extended-Rights,{config}"),
            "whencreated": "2025-06-01T00:00:00Z",
        }))],
    );
    append_area(
        dir,
        "ncheads",
        &[obj(json!({
            "distinguishedname": config,
            "objectclass": ["top", "configuration"],
            "ntsecuritydescriptor": b64(build::sd(&da, &[(true, 0, right::GENERIC_ALL, None, &helpdesk)])),
        }))],
    );
    // An Exchange group with WriteDACL on the domain, a protected Tier 0 OU,
    // a deny entry hiding an OU and a delegation on the Password Settings
    // Container.
    append_area(
        dir,
        "groups",
        &[group(
            "Exchange Windows Permissions",
            &super::tests::sid(1800),
            &users_dn(),
            &[],
        )],
    );
    let exchange = super::tests::sid(1800);
    patch(dir, "acls", |mut v| {
        let dn = v["distinguishedname"][0]
            .as_str()
            .unwrap_or_default()
            .to_string();
        if dn == DOMAIN_DN {
            v["ntsecuritydescriptor"] = json!([b64(build::sd(
                &da,
                &[(true, 0, right::WRITE_DACL, None, &exchange)]
            ))]);
        } else if dn.starts_with("OU=Domain Controllers,") {
            let mut sd = build::sd(&da, &[(true, 0, right::GENERIC_ALL, None, &da)]);
            sd[3] |= 0x10; // SE_DACL_PROTECTED
            v["ntsecuritydescriptor"] = json!([b64(sd)]);
        } else if dn.starts_with("OU=Servers,") {
            v["ntsecuritydescriptor"] =
                json!([b64(build::sd(&da, &[(false, 0, 0x14, None, "S-1-1-0")]))]);
        }
        Some(v)
    });
    append_area(
        dir,
        "acls",
        &[
            obj(json!({
                "distinguishedname": format!("OU=Servers,{DOMAIN_DN}"),
                "objectclass": ["top", "organizationalUnit"],
                "ntsecuritydescriptor": b64(build::sd(&da, &[(false, 0, 0x14, None, "S-1-1-0")])),
            })),
            obj(json!({
                "distinguishedname": format!("CN=Password Settings Container,CN=System,{DOMAIN_DN}"),
                "objectclass": ["top", "msDS-PasswordSettingsContainer"],
                "ntsecuritydescriptor": b64(build::sd(&da, &[(true, 0, right::CREATE_CHILD, None, &helpdesk)])),
            })),
        ],
    );
    patch(dir, "computers", |mut v| {
        if is(&v, "samaccountname", "DC01$") {
            v["operatingsystem"] = json!(["Windows Server 2012 R2 Standard"]);
        }
        Some(v)
    });
    patch(dir, "users", |mut v| {
        if is(&v, "samaccountname", "jdoe") {
            v["userprincipalname"] = json!(["jdoe@fabrikam.test"]);
        }
        Some(v)
    });
    mark_done(
        dir,
        &[
            "roles",
            "sites",
            "querypolicy",
            "dispspec",
            "extrights",
            "ncheads",
        ],
    );
}

#[test]
fn forest_configuration_and_permissions() {
    let r = run_batch(write_forest);
    let failed = |id: &str| {
        assert_eq!(r[id].status, ResultStatus::Failed, "{id}: {:?}", r[id]);
        names(&r[id])
    };
    assert_eq!(failed("AD-FND-003"), ["DC01$"]);
    assert_eq!(
        r["AD-FND-005"].status,
        ResultStatus::Passed,
        "{:?}",
        r["AD-FND-005"]
    );
    assert!(r["AD-FND-005"]
        .raw
        .as_deref()
        .unwrap()
        .contains("RID master: OLDDC"));
    assert_eq!(failed("AD-FND-006"), ["RID master"]);
    assert_eq!(failed("AD-FND-014"), ["jdoe"]);
    assert_eq!(failed("AD-FND-016"), ["OLD"]);
    assert_eq!(failed("AD-FND-017"), ["AppData"]);
    assert_eq!(failed("AD-FND-018"), ["Default Query Policy"]);
    assert_eq!(failed("AD-SCH-004"), ["user-Display"]);
    assert_eq!(failed("AD-SCH-005"), ["Old-Right"]);
    assert_eq!(failed("AD-ACL-007"), ["Configuration"]);
    assert_eq!(failed("AD-ACL-017"), ["Domain Controllers"]);
    assert_eq!(failed("AD-ACL-018"), ["Servers"]);
    assert_eq!(failed("AD-ACL-019"), ["Exchange Windows Permissions"]);
    assert_eq!(failed("AD-ACL-026"), ["Password Settings Container"]);
    assert!(failed("AD-ACL-024").contains(&"S-1-5-21-1000-2000-3000-9999"));
    for id in [
        "AD-FND-004",
        "AD-FND-009",
        "AD-FND-010",
        "AD-FND-013",
        "AD-FND-015",
        "AD-TRU-011",
        "AD-ACL-022",
    ] {
        assert_eq!(r[id].status, ResultStatus::Passed, "{id}: {:?}", r[id]);
    }
}

#[test]
fn forest_areas_not_collected_are_not_assessed() {
    let r = run_batch(|_| {});
    for id in ["AD-FND-005", "AD-FND-018", "AD-SCH-004", "AD-ACL-007"] {
        assert_eq!(r[id].status, ResultStatus::NotAssessed, "{id}");
    }
}

fn meta_value(member_dn: &str, created: &str, deleted: &str) -> String {
    format!(
        "<DS_REPL_VALUE_META_DATA><pszAttributeName>member</pszAttributeName><pszObjectDn>{member_dn}</pszObjectDn><ftimeDeleted>{deleted}</ftimeDeleted><ftimeCreated>{created}</ftimeCreated><dwVersion>1</dwVersion><ftimeLastOriginatingChange>{created}</ftimeLastOriginatingChange></DS_REPL_VALUE_META_DATA>"
    )
}

fn meta_attr(attr: &str, changed: &str) -> String {
    format!(
        "<DS_REPL_ATTR_META_DATA><pszAttributeName>{attr}</pszAttributeName><dwVersion>2</dwVersion><ftimeLastOriginatingChange>{changed}</ftimeLastOriginatingChange></DS_REPL_ATTR_META_DATA>"
    )
}

fn write_access(dir: &std::path::Path) {
    use super::sd::{build, right};
    use super::tests::{iso_days_ago, sid};
    let u = users_dn();
    let da = sid(512);
    let helpdesk = sid(1106);
    let never = "1601-01-01T00:00:00Z";
    // Replication metadata: a Domain Admins member added 5 days ago and
    // one added long ago; an SPN changed 3 days ago; the domain head's
    // permissions changed 2 days ago.
    append_area(
        dir,
        "privmeta",
        &[obj(json!({
            "distinguishedname": format!("CN=Domain Admins,{u}"),
            "msds-replvaluemetadata": [
                meta_value(&format!("CN=adm-jsmith,{u}"), &iso_days_ago(5), never),
                meta_value(&format!("CN=Administrator,{u}"), &iso_days_ago(900), never),
            ],
        }))],
    );
    append_area(
        dir,
        "attrmeta",
        &[obj(json!({
            "distinguishedname": format!("CN=svc-sql,{u}"),
            "samaccountname": "svc-sql",
            "whencreated": iso_days_ago(1000),
            "msds-replattributemetadata": [meta_attr("servicePrincipalName", &iso_days_ago(3))],
        }))],
    );
    patch(dir, "domain", |mut v| {
        v["msds-replattributemetadata"] =
            json!([meta_attr("nTSecurityDescriptor", &iso_days_ago(2))]);
        Some(v)
    });
    // svc-sql: privileged, a Varonis account (it holds DCSync in the base
    // domain), and has an SPN for a host that does not exist.
    add_members(dir, "Domain Admins", vec![format!("CN=svc-sql,{u}")]);
    patch(dir, "users", |mut v| {
        if is(&v, "samaccountname", "svc-sql") {
            v["description"] = json!(["Varonis collector"]);
        }
        if is(&v, "samaccountname", "adm-jsmith") {
            v["mail"] = json!(["jsmith@corp.example.com"]);
        }
        Some(v)
    });
    append_area(
        dir,
        "users",
        &[user(
            "honey-admin",
            1900,
            0x200,
            10,
            None,
            json!({"description": "Decoy account"}),
        )],
    );
    // A read-only DC allowed to cache Domain Admins, and a computer with
    // protocol transition.
    append_area(
        dir,
        "computers",
        &[obj(json!({
            "distinguishedname": format!("CN=RODC01,OU=Domain Controllers,{DOMAIN_DN}"),
            "samaccountname": "RODC01$", "objectsid": sid(1950),
            "useraccountcontrol": 0x0400_1000, "primarygroupid": 521,
            "msds-revealondemandgroup": [format!("CN=Domain Admins,{u}")],
        }))],
    );
    patch(dir, "computers", |mut v| {
        if is(&v, "samaccountname", "WS01$") {
            v["useraccountcontrol"] = json!([0x0100_1000]);
        }
        Some(v)
    });
    // Groups nested three levels into Domain Admins (through IT Admins),
    // and a member of Backup Operators.
    append_area(
        dir,
        "groups",
        &[
            group("Nest2", &sid(1960), &u, &[format!("CN=Nest3,{u}")]),
            group("Nest3", &sid(1961), &u, &[]),
            group(
                "Backup Operators",
                "S-1-5-32-551",
                &format!("CN=Builtin,{DOMAIN_DN}"),
                &[format!("CN=jdoe,{u}")],
            ),
        ],
    );
    add_members(dir, "IT Admins", vec![format!("CN=Nest2,{u}")]);
    // Permissions: altSecurityIdentities write on a Tier 0 user, all
    // extended rights for Domain Users on an OU, a DNS zone and a PKI
    // container controlled by Helpdesk, and create-child on the Tier 0 OU.
    let mut dc_ou = build::sd(&da, &[(true, 0, right::CREATE_CHILD, None, &helpdesk)]);
    dc_ou[3] &= !0x10;
    append_area(
        dir,
        "acls",
        &[
            obj(json!({
                "distinguishedname": format!("CN=adm-jsmith,{u}"),
                "objectclass": ["top", "person", "user"],
                "ntsecuritydescriptor": b64(build::sd(&da, &[(true, 0, right::WRITE_PROP, Some("00fbf30c-91fe-11d1-aebc-0000f80367c1"), &helpdesk)])),
            })),
            obj(json!({
                "distinguishedname": format!("OU=Servers,{DOMAIN_DN}"),
                "objectclass": ["top", "organizationalUnit"],
                "ntsecuritydescriptor": b64(build::sd(&da, &[(true, 0, right::CONTROL_ACCESS, None, &sid(513))])),
            })),
            obj(json!({
                "distinguishedname": format!("OU=Domain Controllers,{DOMAIN_DN}"),
                "objectclass": ["top", "organizationalUnit"],
                "ntsecuritydescriptor": b64(dc_ou),
            })),
        ],
    );
    append_area(
        dir,
        "dnszones",
        &[obj(json!({
            "distinguishedname": format!("DC=corp.example.com,CN=MicrosoftDNS,DC=DomainDnsZones,{DOMAIN_DN}"),
            "ntsecuritydescriptor": b64(build::sd(&da, &[(true, 0, right::GENERIC_ALL, None, &helpdesk)])),
        }))],
    );
    append_area(
        dir,
        "pki",
        &[obj(json!({
            "distinguishedname": format!("CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{DOMAIN_DN}"),
            "objectclass": ["top", "container"],
            "ntsecuritydescriptor": b64(build::sd(&da, &[(true, 0, right::WRITE_DACL, None, &helpdesk)])),
        }))],
    );
    mark_done(dir, &["privmeta", "attrmeta", "dnszones", "pki"]);
}

#[test]
fn access_structure_and_change_history() {
    let r = run_batch(write_access);
    let failed = |id: &str| {
        assert_eq!(r[id].status, ResultStatus::Failed, "{id}: {:?}", r[id]);
        names(&r[id])
    };
    assert_eq!(failed("AD-ACL-012"), ["adm-jsmith"]);
    assert_eq!(failed("AD-ACL-013"), ["Servers"]);
    assert_eq!(failed("AD-ACL-020"), ["corp.example.com"]);
    assert_eq!(failed("AD-ACL-021"), ["Certificate Templates"]);
    assert_eq!(failed("AD-ACL-023"), ["Domain Controllers"]);
    assert_eq!(failed("AD-PRIV-023"), ["AdminSDHolder"]);
    assert_eq!(failed("AD-APP-004"), ["svc-sql"]);
    assert_eq!(failed("AD-APP-007"), ["svc-sql"]);
    assert_eq!(r["AD-AUD-007"].status, ResultStatus::Passed);
    assert_eq!(failed("AD-BKP-003"), ["jdoe"]);
    assert_eq!(failed("AD-KRB-013"), ["svc-sql"]);
    assert_eq!(failed("AD-KRB-018"), ["WS01$"]);
    assert_eq!(failed("AD-OU-005").len(), 0);
    assert!(failed("AD-OU-006").contains(&"svc-sql"));
    assert_eq!(failed("AD-PRIV-010"), ["Nest3"]);
    assert!(failed("AD-PRIV-018").contains(&"adm-jsmith"));
    assert_eq!(failed("AD-PRIV-030").len(), 0);
    assert_eq!(failed("AD-DC-032"), ["RODC01$"]);
    assert_eq!(failed("AD-PRIV-027"), ["Domain Admins"]);
    assert!(r["AD-PRIV-027"].affected[0]
        .reason
        .as_deref()
        .unwrap()
        .contains("adm-jsmith added"));
    assert_eq!(failed("AD-IOC-003"), ["svc-sql"]);
    assert!(failed("AD-IOC-012").contains(&"svc-sql"));
    assert!(r["AD-PRIV-028"]
        .raw
        .as_deref()
        .unwrap()
        .contains("Domain controller: dc01.corp.example.com"));
}

#[test]
fn change_history_needs_metadata() {
    let r = run_batch(|dir| {
        append_area(
            dir,
            "privmeta",
            &[obj(
                json!({"distinguishedname": format!("CN=Domain Admins,{}", users_dn())}),
            )],
        );
        mark_done(dir, &["privmeta", "attrmeta"]);
    });
    for id in ["AD-PRIV-027", "AD-IOC-003"] {
        assert_eq!(r[id].status, ResultStatus::NotAssessed, "{id}: {:?}", r[id]);
    }
    // The base domain has metadata, but none for its permissions.
    assert_eq!(r["AD-IOC-012"].status, ResultStatus::Passed);
}

const DDP_GUID: &str = "{31B2F340-016D-11D2-945F-00C04FB984F9}";
const DDCP_GUID: &str = "{6AC1786C-016F-11D2-945F-00C04FB984F9}";

fn write_policy_settings(dir: &std::path::Path) {
    let policies = format!("CN=Policies,CN=System,{DOMAIN_DN}");
    let svc_sql = super::tests::sid(1103);
    patch(dir, "domain", |mut v| {
        v["gplink"] = json!([format!("[LDAP://cn={DDP_GUID},{policies};0]")]);
        Some(v)
    });
    patch(dir, "sysvol", |v| {
        let f = v["folder"]
            .as_str()
            .unwrap_or_default()
            .to_ascii_uppercase();
        (f != DDP_GUID && f != DDCP_GUID).then_some(v)
    });
    patch(dir, "gpos", |mut v| {
        if v["distinguishedname"][0]
            .as_str()
            .unwrap_or_default()
            .contains(DDP_GUID)
        {
            v["gpcwqlfilter"] =
                json!(["[corp.example.com;{11111111-2222-3333-4444-555555555555};0]"]);
        }
        Some(v)
    });
    append_area(
        dir,
        "sysvol",
        &[
            json!({
                "folder": DDCP_GUID,
                "files": ["GPT.INI"],
                "inf": {
                    "Privilege Rights": {"SeNetworkLogonRight": ["*S-1-1-0", "*S-1-5-11", "*S-1-5-32-544", "*S-1-5-9", "*S-1-5-32-554"]},
                    "Security Log": {"MaximumLogSize": ["131072"]},
                    "Registry Values": {
                        "MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters\\LDAPServerIntegrity": ["4", "1"],
                        "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel": ["4", "5"],
                    },
                },
                "registry": [
                    {"scope": "Machine", "key": "Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile", "value": "EnableFirewall", "type": 4, "data": 1},
                    {"scope": "Machine", "key": "Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile", "value": "EnableFirewall", "type": 4, "data": 0},
                    {"scope": "Machine", "key": "Software\\Policies\\Microsoft\\Windows\\System", "value": "UserPolicyMode", "type": 4, "data": 2},
                    {"scope": "Machine", "key": "Software\\Policies\\Microsoft\\Windows\\SrpV2\\Exe", "value": "EnforcementMode", "type": 4, "data": 1},
                ],
                "audit": [
                    {"subcategory": "Logon", "guid": "0cce9215-69ae-11d9-bed3-505054503030", "value": 3},
                    {"subcategory": "Credential Validation", "guid": "0cce923f-69ae-11d9-bed3-505054503030", "value": 1},
                ],
            }),
            json!({
                "folder": DDP_GUID,
                "files": ["GPT.INI"],
                "inf": {"Privilege Rights": {"SeDenyInteractiveLogonRight": [format!("*{svc_sql}")]}},
            }),
        ],
    );
    append_area(
        dir,
        "wmifilters",
        &[obj(json!({
            "distinguishedname": format!("CN={{AAAA0000-0000-0000-0000-000000000000}},CN=SOM,CN=WMIPolicy,CN=System,{DOMAIN_DN}"),
            "mswmi-name": "Servers only",
            "mswmi-id": "{AAAA0000-0000-0000-0000-000000000000}",
            "mswmi-parm2": "1;3;10;43;WQL;root\\CIMv2;SELECT * FROM Win32_OperatingSystem WHERE ProductType = 3;",
        }))],
    );
    append_area(
        dir,
        "gpsoftware",
        &[obj(json!({
            "distinguishedname": format!("CN={{BBBB0000-0000-0000-0000-000000000000}},CN=Packages,CN=Class Store,CN=Machine,CN={DDP_GUID},{policies}"),
            "displayname": "Monitoring Agent",
            "msifilelist": ["0:\\\\fileserver\\apps\\agent.msi"],
        }))],
    );
    mark_done(dir, &["wmifilters", "gpsoftware"]);
}

#[test]
fn group_policy_settings_for_dcs() {
    let r = run_batch(write_policy_settings);
    let failed = |id: &str| {
        assert_eq!(r[id].status, ResultStatus::Failed, "{id}: {:?}", r[id]);
        names(&r[id])
    };
    assert_eq!(failed("AD-GPO-010"), ["Default Domain Controllers Policy"]);
    assert!(r["AD-GPO-010"].affected[0]
        .reason
        .as_deref()
        .unwrap()
        .contains("Everyone"));
    let audit = failed("AD-GPO-012");
    assert!(audit.contains(&"Credential Validation") && !audit.contains(&"Logon"));
    assert_eq!(failed("AD-GPO-013"), ["Security log size"]);
    assert_eq!(
        failed("AD-GPO-016"),
        ["PrivateProfile", "Default Domain Controllers Policy"]
    );
    let hardening = failed("AD-GPO-017");
    assert!(hardening.contains(&"LDAP signing required"));
    assert!(!hardening.iter().any(|h| h.starts_with("NTLMv2")));
    assert_eq!(r["AD-GPO-020"].status, ResultStatus::Passed);
    assert!(r["AD-GPO-020"]
        .raw
        .as_deref()
        .unwrap()
        .contains("AppLocker in Default Domain Controllers Policy: exe"));
    assert_eq!(failed("AD-GPO-021"), ["Monitoring Agent"]);
    assert_eq!(failed("AD-GPO-024"), ["Default Domain Policy"]);
    assert!(r["AD-GPO-025"]
        .raw
        .as_deref()
        .unwrap()
        .contains("loopback replace"));
    assert!(failed("AD-GPO-030").contains(&"Do not store LAN Manager hash"));
    // svc-sql, the only service account here, is denied by the Default
    // Domain Policy.
    assert_eq!(r["AD-SVC-005"].status, ResultStatus::Passed);
}

#[test]
fn group_policy_settings_need_sysvol_content() {
    let r = run_batch(|_| {});
    for id in ["AD-GPO-010", "AD-GPO-012", "AD-GPO-017", "AD-GPO-030"] {
        assert_eq!(r[id].status, ResultStatus::NotAssessed, "{id}: {:?}", r[id]);
    }
}

fn write_hosts(dir: &std::path::Path) {
    super::tests::write_dc_data(dir);
    super::tests_ep::write_endpoints(dir);
    patch(dir, "dcconfig", |mut v| {
        if v["name"] == "dc01.corp.example.com" {
            let d = &mut v["data"];
            d["ciphers"] =
                json!({"enabled": {"RC4 128/128": -1, "Triple DES 168": 0}, "suite_policy": null});
            d["hardware"] = json!({"manufacturer": "VMware, Inc.", "model": "VMware7,1", "hypervisor": true, "vm_generation_id": false});
            d["addresses"] = json!(["203.0.113.10"]);
            d["defender"] = json!({"enabled": true, "realtime": true, "mode": "Normal", "exclusions": ["C:\\"]});
            d["service_accounts"] = json!([{"name": "VeeamTransportSvc", "display": "Veeam Backup Transport", "account": "CORP\\adm-jsmith", "state": "Running"}]);
            d["trust_dns"] = json!([{"partner": "old.example.org", "resolves": false}]);
            d["software"] =
                json!([{"name": "TeamViewer", "publisher": "TeamViewer GmbH", "version": "15.0"}]);
            d["registry"]["winlogon.cachedlogonscount"] = json!("10");
            d["registry"]["powershell.enabletranscripting"] = json!(1);
            d["dns"] = json!({
                "installed": true, "domain": "corp.example.com",
                "zones": [{"name": "corp.example.com", "type": "Primary", "signed": false}],
                "recursion": true, "forwarders": ["8.8.8.8"], "root_hints": 13,
                "own_a": ["203.0.113.10", "10.0.0.99"],
            });
        }
        Some(v)
    });
    let row =
        |key: &str, count: u64| json!({"key": key, "count": count, "last": "2026-10-04T23:10:00Z"});
    let gpo = format!("CN={DDCP_GUID},CN=Policies,CN=System,{DOMAIN_DN}");
    patch(dir, "dcevents", |mut v| {
        if v["name"] == "dc01.corp.example.com" {
            let q = &mut v["queries"];
            let summary = |rows: Vec<Value>| json!({"count": rows.len(), "top": rows});
            q["hunt_golden"] = summary(vec![row("corp.example.com|Administrator|10.0.0.5", 3)]);
            q["hunt_pac"] = summary(vec![row("37|jdoe", 1)]);
            q["hunt_gpochanges"] = summary(vec![
                row(&format!("23|2|{gpo}|CORP\\helpdesk-lead"), 1),
                row(&format!("10|3|{gpo}|CORP\\adm-jsmith"), 1),
            ]);
            q["hunt_ntds"] = summary(vec![row("ntdsutil.exe|CORP\\helpdesk-lead", 1)]);
            q["hunt_lsass"] = summary(vec![
                row("C:\\Windows\\System32\\svchost.exe", 5),
                row("C:\\Users\\x\\procdump64.exe", 1),
            ]);
            q["hunt_ticketuse"] = summary(vec![
                row("adm-jsmith|WS01$", 4),
                row("adm-jsmith|DC01$", 9),
                row("jdoe|WS01$", 2),
            ]);
            q["hunt_computerchanges"] = summary(vec![row("DC01$|CORP\\helpdesk-lead", 1)]);
            q["ldap_simple"] = summary(vec![row("CORP\\svc-sql from 10.0.0.7", 20)]);
        }
        Some(v)
    });
}

use serde_json::Value;

#[test]
fn domain_controller_hosts_endpoints_and_hunts() {
    let r = run_batch(write_hosts);
    let failed = |id: &str| {
        assert_eq!(r[id].status, ResultStatus::Failed, "{id}: {:?}", r[id]);
        names(&r[id])
    };
    let reason = |id: &str| r[id].affected[0].reason.clone().unwrap_or_default();
    assert_eq!(r["AD-DC-008"].status, ResultStatus::Passed);
    assert!(r["AD-DC-008"]
        .raw
        .as_deref()
        .unwrap()
        .contains("TeamViewer"));
    assert!(failed("AD-DC-026").contains(&"dc01.corp.example.com"));
    assert!(reason("AD-DC-027").contains("exclusions are broad"));
    assert!(failed("AD-DC-031").contains(&"dc01.corp.example.com"));
    assert!(failed("AD-IOC-007").contains(&"dc01.corp.example.com"));
    assert!(reason("AD-LEG-010").contains("RC4 128/128"));
    assert!(reason("AD-DNS-007").contains("203.0.113.10"));
    assert!(r["AD-DNS-008"]
        .raw
        .as_deref()
        .unwrap()
        .contains("0 of 1 zone signed"));
    assert!(reason("AD-DNS-013").contains("10.0.0.99"));
    assert!(r["AD-DNS-014"].raw.as_deref().unwrap().contains("8.8.8.8"));
    assert!(reason("AD-AUD-009").contains("Documents"));
    assert!(reason("AD-BKP-007").contains("adm-jsmith"));
    assert!(reason("AD-BKP-008").contains("VM-GenerationID"));
    assert!(reason("AD-TRU-007").contains("old.example.org"));

    assert_eq!(failed("AD-CMP-005"), ["srv01.corp.example.com"]);
    assert_eq!(failed("AD-CMP-009"), ["srv01.corp.example.com"]);
    assert_eq!(r["EP-HARD-045"].status, ResultStatus::Failed);

    assert_eq!(failed("HUNT-AD-006"), ["Administrator"]);
    assert_eq!(failed("HUNT-AD-007"), ["jdoe"]);
    assert_eq!(failed("HUNT-AD-012"), ["Default Domain Controllers Policy"]);
    assert_eq!(failed("HUNT-AD-018"), ["CORP\\helpdesk-lead"]);
    assert_eq!(failed("HUNT-AD-019"), ["procdump64.exe"]);
    assert_eq!(failed("HUNT-AD-021"), ["adm-jsmith"]);
    assert!(reason("HUNT-AD-021").contains("WS01"));
    assert_eq!(failed("AD-PRIV-029"), ["adm-jsmith"]);
    assert!(failed("AD-AUD-012").contains(&"DC01$"));
    assert_eq!(failed("AD-APP-005"), ["CORP\\svc-sql from 10.0.0.7"]);
}

#[test]
fn version_comparison_for_vulnerable_software() {
    let r = run_batch(|dir| {
        super::tests::write_dc_data(dir);
        super::tests_ep::write_endpoints(dir);
        patch(dir, "endpoints", |mut v| {
            if v["name"] == "ws01.corp.example.com" {
                v["data"]["software"] = json!([
                    {"name": "7-Zip 23.01 (x64)", "publisher": "Igor Pavlov", "version": "23.01"},
                    {"name": "PuTTY release 0.81 (64-bit)", "publisher": "Simon Tatham", "version": "0.81.0.0"},
                ]);
            }
            Some(v)
        });
    });
    assert_eq!(r["EP-HARD-028"].status, ResultStatus::Failed);
    let reason = r["EP-HARD-028"].affected[0].reason.clone().unwrap();
    assert!(
        reason.contains("7-Zip") && !reason.contains("PuTTY"),
        "{reason}"
    );
}

#[test]
fn certification_authority_configuration() {
    let r = run_batch(|dir| {
        super::tests::write_dc_data(dir);
        super::tests_ep::write_endpoints(dir);
        let helpdesk = super::tests::sid(1106);
        patch(dir, "dcconfig", |mut v| {
            if v["name"] == "dc01.corp.example.com" {
                v["data"]["certsvc"] = json!({
                    "installed": true, "name": "corp-DC01-CA", "state": "Running",
                    "edit_flags": 0x0004_0000 | 0x11_014e, "interface_flags": 0x41,
                    "audit_filter": 0, "disabled_extensions": ["1.3.6.1.4.1.311.25.2"],
                    "provider": "Microsoft Software Key Storage Provider",
                    "aces": [
                        {"sid": "S-1-5-32-544", "mask": 3, "allow": true},
                        {"sid": helpdesk, "mask": 2, "allow": true},
                    ],
                    "web": {"installed": true, "http": true, "https": false, "epa": "None"},
                    "issued_templates": ["User"],
                });
            }
            Some(v)
        });
        patch(dir, "endpoints", |mut v| {
            if v["name"] == "srv01.corp.example.com" {
                v["data"]["certsvc"] = json!({
                    "installed": true, "name": "corp-SRV01-CA", "edit_flags": 0x11_014e,
                    "interface_flags": 0x641, "audit_filter": 127, "disabled_extensions": [],
                    "provider": "SafeNet Key Storage Provider",
                    "aces": [{"sid": "S-1-5-32-544", "mask": 3, "allow": true}],
                    "web": {"installed": false}, "issued_templates": [],
                });
            }
            Some(v)
        });
        append_area(
            dir,
            "pki",
            &[obj(json!({
                "distinguishedname": format!("CN=corp-DC01-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,{DOMAIN_DN}"),
                "objectclass": ["top", "pKIEnrollmentService"],
                "certificatetemplates": ["User", "WebServer"],
            }))],
        );
        mark_done(dir, &["pki"]);
    });
    let failed = |id: &str| {
        assert_eq!(r[id].status, ResultStatus::Failed, "{id}: {:?}", r[id]);
        names(&r[id])
    };
    for id in [
        "AD-PKI-007",
        "AD-PKI-008",
        "AD-PKI-009",
        "AD-PKI-011",
        "AD-PKI-015",
        "AD-PKI-022",
        "AD-PKI-023",
    ] {
        assert_eq!(failed(id), ["corp-DC01-CA"], "{id}");
    }
    assert!(r["AD-PKI-008"].affected[0]
        .reason
        .as_deref()
        .unwrap()
        .contains("Helpdesk"));
    assert!(r["AD-PKI-024"].affected[0]
        .reason
        .as_deref()
        .unwrap()
        .contains("WebServer"));
    assert!(!r["AD-PKI-024"].affected[0]
        .reason
        .as_deref()
        .unwrap()
        .contains("User,"));
}

#[test]
fn certification_authority_checks_without_cas() {
    let r = run_batch(|dir| {
        super::tests::write_dc_data(dir);
        patch(dir, "dcconfig", |mut v| {
            if v["data"].is_object() {
                v["data"]["certsvc"] = json!({"installed": false});
            }
            Some(v)
        });
    });
    assert_eq!(r["AD-PKI-007"].status, ResultStatus::Passed);
    assert!(r["AD-PKI-007"]
        .found
        .as_deref()
        .unwrap()
        .contains("No machine"));
    // DC replies from a collector that did not read Certificate Services.
    let r = run_batch(super::tests::write_dc_data);
    assert_eq!(r["AD-PKI-007"].status, ResultStatus::NotAssessed);
}
