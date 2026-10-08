//! The hybrid checks against the on-prem test domain and the Entra test
//! tenant, joined by on-premises SIDs.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use serde_json::{json, Value};

use super::{analyze, sync_edges, Ctx};
use crate::ad::model::Model;
use crate::ad::raw::RawDomain;
use crate::ad::tests::{ft_days_ago, obj, sid, write_domain, DOMAIN_DN};
use crate::entra::model::Tenant;
use crate::entra::raw::RawTenant;
use crate::entra::tests::{write_tenant, ACTIVE, ADMIN, APP_SP, STALE};
use crate::results::tests::catalog;
use crate::results::{CheckResult, DirObject, ResultStatus};

fn append(path: &Path, lines: &[Value]) {
    let mut text = fs::read_to_string(path).unwrap_or_default();
    for l in lines {
        text.push_str(&format!("{l}\n"));
    }
    fs::write(path, text).unwrap();
}

/// Rewrites every item of an area file through `edit`.
fn edit(path: &Path, edit: impl Fn(&mut Value)) {
    let text = fs::read_to_string(path).unwrap();
    let mut out = String::new();
    for line in text.lines().filter(|l| !l.is_empty()) {
        let mut page: Value = serde_json::from_str(line).unwrap();
        match page.get_mut("value").and_then(Value::as_array_mut) {
            Some(items) => items.iter_mut().for_each(&edit),
            None => edit(&mut page),
        }
        out.push_str(&format!("{page}\n"));
    }
    fs::write(path, out).unwrap();
}

/// The test domain plus an Entra Connect connector account and a Seamless
/// SSO account; the test tenant with adm-jsmith, svc-sql and Domain Admins
/// synchronized, password writeback and hash sync on.
fn write_both(ad: &Path, entra: &Path) {
    write_domain(ad, false);
    let users = format!("CN=Users,{DOMAIN_DN}");
    append(
        &ad.join("users.jsonl"),
        &[obj(json!({
            "distinguishedname": format!("CN=MSOL_0a1b2c3d4e5f,{users}"),
            "samaccountname": "MSOL_0a1b2c3d4e5f",
            "objectsid": sid(1200),
            "useraccountcontrol": 0x10200,
            "pwdlastset": ft_days_ago(800),
            "primarygroupid": 513,
            "description": "Account created by Microsoft Azure Active Directory Connect with installation identifier 0a1b running on computer SYNC01",
        }))],
    );
    append(
        &ad.join("computers.jsonl"),
        &[obj(json!({
            "distinguishedname": format!("CN=AZUREADSSOACC,CN=Computers,{DOMAIN_DN}"),
            "samaccountname": "AZUREADSSOACC$",
            "objectsid": sid(1201),
            "useraccountcontrol": 0x1000,
            "pwdlastset": ft_days_ago(90),
            "primarygroupid": 515,
        }))],
    );

    write_tenant(entra);
    edit(&entra.join("users.jsonl"), |u| {
        match u["id"].as_str() {
            Some(ADMIN) => u["onPremisesSecurityIdentifier"] = json!(sid(1101)),
            Some(STALE) => u["onPremisesSecurityIdentifier"] = json!(sid(1103)),
            Some(ACTIVE) => {
                u["onPremisesProvisioningErrors"] = json!([{
                    "category": "PropertyConflict",
                    "propertyCausingError": "UserPrincipalName",
                    "value": "worker@contoso.com",
                }])
            }
            _ => {}
        }
        u["onPremisesSyncEnabled"] = json!(u["onPremisesSecurityIdentifier"].is_string());
    });
    edit(&entra.join("serviceprincipals.jsonl"), |s| {
        if s["id"] == APP_SP {
            s["owners"] = json!([{"@odata.type": "#microsoft.graph.user", "id": STALE}]);
        }
    });
    append(
        &entra.join("groups.jsonl"),
        &[json!({"value": [{
            "id": "bbbbbbbb-0000-0000-0000-000000000512",
            "displayName": "Domain Admins",
            "securityEnabled": true,
            "groupTypes": [],
            "onPremisesSyncEnabled": true,
            "onPremisesSecurityIdentifier": sid(512),
        }]})],
    );
    edit(&entra.join("organization.jsonl"), |o| {
        o["onPremisesSyncEnabled"] = json!(true)
    });
    fs::write(
        entra.join("onpremsync.jsonl"),
        format!(
            "{}\n",
            json!({"value": [{"id": "sync", "features": {"passwordWritebackEnabled": true, "passwordSyncEnabled": true}}]})
        ),
    )
    .unwrap();
    let events = fs::read_to_string(entra.join("events.jsonl")).unwrap();
    fs::write(
        entra.join("events.jsonl"),
        format!("{{\"type\":\"done\",\"area\":\"onpremsync\",\"count\":1}}\n{events}"),
    )
    .unwrap();
}

struct Loaded {
    domain: RawDomain,
    tenant: RawTenant,
}

fn load() -> Loaded {
    let ad = tempfile::tempdir().unwrap();
    let entra = tempfile::tempdir().unwrap();
    write_both(ad.path(), entra.path());
    Loaded {
        domain: RawDomain::load(ad.path()).unwrap(),
        tenant: RawTenant::load(entra.path()).unwrap(),
    }
}

fn run(both: bool) -> HashMap<String, CheckResult> {
    let l = load();
    let models = if both {
        vec![Model::build(&l.domain)]
    } else {
        Vec::new()
    };
    let t = Tenant::build(&l.tenant);
    let ctx = Ctx {
        domains: &models,
        tenant: Some(&t),
    };
    analyze(&catalog(), &ctx, &[])
        .into_iter()
        .map(|c| (c.id.clone(), c))
        .collect()
}

fn names(r: &CheckResult) -> Vec<&str> {
    r.affected.iter().map(|a| a.name.as_str()).collect()
}

#[test]
fn every_rule_is_implemented_in_the_catalog() {
    let catalog = catalog();
    for r in super::all_rules() {
        let c = catalog
            .check(r.id)
            .unwrap_or_else(|| panic!("{} is not in the catalog", r.id));
        assert_eq!(
            c.status,
            crate::catalog::CheckStatus::Implemented,
            "{}",
            r.id
        );
    }
}

#[test]
fn sync_accounts_and_keys() {
    let r = run(true);
    let connector = &r["HY-SYNC-004"];
    assert_eq!(connector.status, ResultStatus::Passed, "{connector:?}");
    assert!(connector
        .evidence
        .iter()
        .any(|e| e.value.contains("MSOL_0a1b2c3d4e5f")));
    assert_eq!(names(&r["HY-SYNC-005"]), ["MSOL_0a1b2c3d4e5f"]);
    assert_eq!(names(&r["HY-SYNC-014"]), ["AZUREADSSOACC$"]);
    // Writeback is on, but the connector cannot reset Tier 0 passwords.
    assert_eq!(r["HY-SYNC-009"].status, ResultStatus::Passed);
    assert_eq!(r["HY-SYNC-006"].status, ResultStatus::Passed);
}

#[test]
fn synchronized_admins_and_groups() {
    let r = run(true);
    assert_eq!(names(&r["HY-SYNC-007"]), ["adm-jsmith"]);
    assert_eq!(names(&r["HY-SYNC-008"]), ["Domain Admins"]);
    assert_eq!(names(&r["HY-PATH-001"]), ["admin@contoso.com"]);
    // adm-jsmith is in Protected Users with a recent password.
    assert_eq!(
        r["HY-PATH-004"].status,
        ResultStatus::Passed,
        "{:?}",
        r["HY-PATH-004"]
    );
    let svc = &r["HY-PATH-005"];
    assert_eq!(names(svc), ["old@contoso.com"]);
    assert!(svc.affected[0]
        .reason
        .as_deref()
        .unwrap()
        .contains("Provisioning connector"));
    assert_eq!(names(&r["HY-SYNC-016"]), ["worker@contoso.com"]);
    let fed = &r["HY-FED-008"];
    assert_eq!(names(fed), ["fed.contoso.com"]);
    assert!(fed.affected[0]
        .reason
        .as_deref()
        .unwrap()
        .contains("staged rollout"));
}

#[test]
fn tenant_only_runs_leave_ad_checks_not_assessed() {
    let r = run(false);
    let s = &r["HY-SYNC-007"];
    assert_eq!(s.status, ResultStatus::NotAssessed);
    assert!(s
        .note
        .as_deref()
        .unwrap()
        .contains("on-premises Active Directory"));
    assert_eq!(r["HY-SYNC-016"].status, ResultStatus::Failed);
}

#[test]
fn synced_objects_are_linked() {
    let l = load();
    let models = vec![Model::build(&l.domain)];
    let t = Tenant::build(&l.tenant);
    let ctx = Ctx {
        domains: &models,
        tenant: Some(&t),
    };
    let mut objects: Vec<DirObject> = crate::ad::directory::build(&models[0]).objects;
    objects.extend(crate::entra::directory::build(&t).objects);
    let edges = sync_edges(&ctx, &objects);
    assert!(edges
        .iter()
        .any(|e| e.from == sid(1101) && e.to == ADMIN && e.kind == "SyncedTo"));
}

/// Writes an Entra area and marks it read.
fn entra_area(dir: &Path, name: &str, items: &[Value]) {
    let lines: Vec<String> = items.iter().map(Value::to_string).collect();
    fs::write(dir.join(format!("{name}.jsonl")), lines.join("\n") + "\n").unwrap();
    let events = fs::read_to_string(dir.join("events.jsonl")).unwrap();
    fs::write(
        dir.join("events.jsonl"),
        format!(
            "{}\n{events}",
            json!({"type": "done", "area": name, "count": items.len()})
        ),
    )
    .unwrap();
}

#[test]
fn cloud_paths_into_tier0() {
    let ad = tempfile::tempdir().unwrap();
    let entra = tempfile::tempdir().unwrap();
    write_both(ad.path(), entra.path());
    entra_area(
        entra.path(),
        "intunedevices",
        &[
            json!({"deviceName": "DC01", "managementAgent": "configurationManagerClientMdm"}),
            json!({"deviceName": "PC-7", "managementAgent": "mdm"}),
        ],
    );
    let helpdesk = "729827e3-9c14-49f7-bb1b-9608f156bbb8";
    let hybrid = "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2";
    let assign = |p: &str, kind: &str, role: &str| {
        json!({"principalId": p, "roleDefinitionId": role, "directoryScopeId": "/",
               "principal": {"@odata.type": format!("#microsoft.graph.{kind}"), "id": p}})
    };
    append(
        &entra.path().join("roleassignments.jsonl"),
        &[
            assign(ACTIVE, "user", helpdesk),
            assign(STALE, "user", hybrid),
            assign("bbbbbbbb-0000-0000-0000-000000000512", "group", helpdesk),
        ],
    );
    entra_area(
        entra.path(),
        "azroleassignments",
        &[
            json!({"id": "/ra/1", "properties": {"principalId": "bbbbbbbb-0000-0000-0000-000000000512",
                 "roleDefinitionId": "/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
                 "scope": "/subscriptions/s1"}}),
        ],
    );
    let domain = RawDomain::load(ad.path()).unwrap();
    let tenant = RawTenant::load(entra.path()).unwrap();
    let models = vec![Model::build(&domain)];
    let t = Tenant::build(&tenant);
    let ctx = Ctx {
        domains: &models,
        tenant: Some(&t),
    };
    let r: HashMap<String, CheckResult> = analyze(&catalog(), &ctx, &[])
        .into_iter()
        .map(|c| (c.id.clone(), c))
        .collect();

    for id in ["M365-INT-020", "HY-PATH-007"] {
        assert_eq!(names(&r[id]), ["DC01$"], "{id}: {:?}", r[id]);
        assert!(r[id].affected[0]
            .reason
            .as_deref()
            .unwrap()
            .starts_with("Domain controller"));
    }
    assert_eq!(names(&r["EN-AUTH-013"]), ["AZUREADSSOACC$"]);

    let p2 = &r["HY-PATH-002"];
    let mut got = names(p2);
    got.sort_unstable();
    assert_eq!(got, ["old@contoso.com", "worker@contoso.com"], "{p2:?}");
    assert!(p2
        .affected
        .iter()
        .any(|a| a.reason.as_deref().unwrap().contains("adm-jsmith")
            || a.reason.as_deref().unwrap().contains("admin@contoso.com")));

    let p3 = &r["HY-PATH-003"];
    assert_eq!(names(p3), ["Domain Admins"]);
    let why = p3.affected[0].reason.as_deref().unwrap();
    assert!(
        why.contains("Entra role Helpdesk Administrator") || why.contains("Entra role"),
        "{why}"
    );
    assert!(why.contains("Azure Owner on /subscriptions/s1"), "{why}");
    assert_eq!(
        p3.affected[0].location.as_deref(),
        Some("Domain Admins in corp.example.com")
    );
}

#[test]
fn cloud_paths_need_the_cloud_areas() {
    let r = run(true);
    assert_eq!(r["M365-INT-020"].status, ResultStatus::NotAssessed);
    // Without Hybrid Identity or reset-role holders there is no path.
    assert_eq!(
        r["HY-PATH-002"].status,
        ResultStatus::Passed,
        "{:?}",
        r["HY-PATH-002"]
    );
    assert_eq!(
        r["HY-PATH-003"].status,
        ResultStatus::Passed,
        "{:?}",
        r["HY-PATH-003"]
    );
}

#[test]
fn domain_controllers_in_azure() {
    let ad = tempfile::tempdir().unwrap();
    let entra = tempfile::tempdir().unwrap();
    write_both(ad.path(), entra.path());
    let sub = "/subscriptions/s1";
    let vm =
        format!("{sub}/resourceGroups/rg-dc/providers/Microsoft.Compute/virtualMachines/vm-dc01");
    let app_vm =
        format!("{sub}/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/vm-app");
    let role = |n: u32, p: &str, r: &str, scope: &str| {
        json!({"id": format!("/ra/{n}"), "properties": {"principalId": p, "principalType": "User", "scope": scope,
               "roleDefinitionId": format!("/providers/Microsoft.Authorization/roleDefinitions/{r}")}})
    };
    entra_area(
        entra.path(),
        "azvms",
        &[
            json!({"id": vm, "name": "vm-dc01", "@dca.parent": "s1", "properties": {"osProfile": {"computerName": "DC01"}}}),
            json!({"id": app_vm, "name": "vm-app", "@dca.parent": "s1", "properties": {"osProfile": {"computerName": "APP01"}}}),
        ],
    );
    entra_area(
        entra.path(),
        "azarc",
        &[
            json!({"id": format!("{sub}/resourceGroups/rg-arc/providers/Microsoft.HybridCompute/machines/dc01"), "name": "dc01",
                 "@dca.parent": "s1", "properties": {"machineFqdn": "DC01.corp.example.com", "agentVersion": "1.44", "status": "Connected"}}),
        ],
    );
    entra_area(
        entra.path(),
        "azroleassignments",
        &[
            // VM Contributor on the DC's resource group, Reader on the subscription,
            // Contributor on another VM.
            role(
                1,
                ACTIVE,
                "9980e02c-c2be-4d73-94e8-173b1dc7cf3c",
                &format!("{sub}/resourceGroups/rg-dc"),
            ),
            role(2, STALE, "acdd72a7-3385-48ef-bd42-f606fba81ae7", sub),
            role(3, STALE, "b24988ac-6180-42a0-ab88-20f7382dd24c", &app_vm),
            role(4, ADMIN, "cd570a14-e51a-42ad-bac8-bafd67325302", sub),
        ],
    );
    entra_area(entra.path(), "azjit", &[]);
    entra_area(entra.path(), "azbastion", &[]);
    entra_area(
        entra.path(),
        "azlocks",
        &[
            json!({"id": format!("{sub}/resourceGroups/rg-app/providers/Microsoft.Authorization/locks/keep"), "properties": {"level": "CanNotDelete"}}),
        ],
    );
    for a in ["azvaults", "azkvsecrets", "azkvkeys"] {
        entra_area(entra.path(), a, &[]);
    }
    let domain = RawDomain::load(ad.path()).unwrap();
    let tenant = RawTenant::load(entra.path()).unwrap();
    let models = vec![Model::build(&domain)];
    let t = Tenant::build(&tenant);
    let ctx = Ctx {
        domains: &models,
        tenant: Some(&t),
    };
    let r: HashMap<String, CheckResult> = analyze(&catalog(), &ctx, &[])
        .into_iter()
        .map(|c| (c.id.clone(), c))
        .collect();

    let vm_access = &r["AZ-RBAC-020"];
    assert_eq!(names(vm_access), ["worker@contoso.com"], "{vm_access:?}");
    assert!(vm_access.affected[0]
        .reason
        .as_deref()
        .unwrap()
        .contains("vm-dc01 (domain controller DC01)"));
    let arc = &r["AZ-RBAC-021"];
    assert_eq!(names(arc), ["admin@contoso.com"], "{arc:?}");
    assert_eq!(names(&r["HY-PATH-008"]), ["DC01$"]);
    assert!(r["HY-PATH-008"].affected[0]
        .reason
        .as_deref()
        .unwrap()
        .contains("agent 1.44 (Connected)"));
    assert_eq!(names(&r["AZ-RBAC-022"]), ["DC01$"]);
    let locks = &r["AZ-RBAC-010"];
    assert_eq!(
        names(locks),
        ["vm-dc01"],
        "the app VM is locked but not critical: {locks:?}"
    );
}

#[test]
fn identity_sensors_cover_domain_controllers() {
    let ad = tempfile::tempdir().unwrap();
    let entra = tempfile::tempdir().unwrap();
    write_both(ad.path(), entra.path());
    entra_area(entra.path(), "mdisensors", &[]);
    entra_area(
        entra.path(),
        "mdihealth",
        &[
            json!({"displayName": "Directory services object auditing is not configured", "severity": "medium", "status": "open"}),
        ],
    );
    let domain = RawDomain::load(ad.path()).unwrap();
    let tenant = RawTenant::load(entra.path()).unwrap();
    let models = vec![Model::build(&domain)];
    let t = Tenant::build(&tenant);
    let ctx = Ctx {
        domains: &models,
        tenant: Some(&t),
    };
    let r: HashMap<String, CheckResult> = analyze(&catalog(), &ctx, &[])
        .into_iter()
        .map(|c| (c.id.clone(), c))
        .collect();
    let s = &r["M365-DEF-006"];
    assert_eq!(
        names(s),
        [
            "DC01$",
            "Directory services object auditing is not configured"
        ],
        "{s:?}"
    );

    // With a healthy sensor on DC01 only the health issue remains.
    entra_area(
        entra.path(),
        "mdisensors",
        &[json!({"displayName": "dc01.corp.example.com", "healthStatus": "healthy"})],
    );
    entra_area(entra.path(), "mdihealth", &[]);
    let tenant = RawTenant::load(entra.path()).unwrap();
    let t = Tenant::build(&tenant);
    let ctx = Ctx {
        domains: &models,
        tenant: Some(&t),
    };
    let r: HashMap<String, CheckResult> = analyze(&catalog(), &ctx, &[])
        .into_iter()
        .map(|c| (c.id.clone(), c))
        .collect();
    assert_eq!(
        r["M365-DEF-006"].status,
        ResultStatus::Passed,
        "{:?}",
        r["M365-DEF-006"]
    );
}

#[test]
fn on_premises_paths_to_cloud_admins_and_old_exchange() {
    use crate::ad::sd::{build, right};
    let ad = tempfile::tempdir().unwrap();
    let entra = tempfile::tempdir().unwrap();
    write_both(ad.path(), entra.path());
    // Domain Users have full control of adm-jsmith (an ACE on the account).
    let da = sid(512);
    let sd = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(build::sd(
            &da,
            &[(true, 0, right::GENERIC_ALL, None, &sid(513))],
        ))
    };
    append(
        &ad.path().join("acls.jsonl"),
        &[obj(
            json!({"distinguishedname": format!("CN=adm-jsmith,CN=Users,{DOMAIN_DN}"), "objectclass": ["top", "user"], "ntsecuritydescriptor": sd}),
        )],
    );
    append(
        &ad.path().join("exchservers.jsonl"),
        &[
            obj(
                json!({"distinguishedname": format!("CN=EX01,CN=Servers,CN=Microsoft Exchange,CN=Services,CN=Configuration,{DOMAIN_DN}"), "serialnumber": "Version 15.2 (Build 1544.4)"}),
            ),
            obj(
                json!({"distinguishedname": format!("CN=EX02,CN=Servers,CN=Microsoft Exchange,CN=Services,CN=Configuration,{DOMAIN_DN}"), "serialnumber": "Version 15.2 (Build 2562.17)"}),
            ),
        ],
    );
    let events = fs::read_to_string(ad.path().join("events.jsonl")).unwrap();
    fs::write(
        ad.path().join("events.jsonl"),
        format!(
            "{}\n{events}",
            json!({"type": "done", "area": "exchservers", "count": 2})
        ),
    )
    .unwrap();
    entra_area(
        entra.path(),
        "exoinbound",
        &[json!({"Name": "From on-premises", "ConnectorType": "OnPremises", "Enabled": true})],
    );
    entra_area(entra.path(), "exooutbound", &[]);
    let domain = RawDomain::load(ad.path()).unwrap();
    let tenant = RawTenant::load(entra.path()).unwrap();
    let models = vec![Model::build(&domain)];
    let t = Tenant::build(&tenant);
    let ctx = Ctx {
        domains: &models,
        tenant: Some(&t),
    };
    let r: HashMap<String, CheckResult> = analyze(&catalog(), &ctx, &[])
        .into_iter()
        .map(|c| (c.id.clone(), c))
        .collect();

    let p = &r["HY-PATH-006"];
    assert_eq!(names(p), ["admin@contoso.com"], "{p:?}");
    let why = p.affected[0].reason.as_deref().unwrap();
    assert!(
        why.starts_with("On-premises: Domain Users → full control → adm-jsmith"),
        "{why}"
    );
    assert!(why.contains("Global Administrator"), "{why}");

    let x = &r["M365-EXO-029"];
    assert_eq!(names(x), ["EX01"], "Exchange Server SE is supported: {x:?}");
    assert!(x.affected[0]
        .reason
        .as_deref()
        .unwrap()
        .contains("Exchange Online exchanges mail"));
}

#[test]
fn identity_servers() {
    let ad = tempfile::tempdir().unwrap();
    let entra = tempfile::tempdir().unwrap();
    write_both(ad.path(), entra.path());
    crate::ad::tests::write_dc_data(ad.path());
    let adfs = json!({
        "services": {"adfssrv": {"account": "CORP\\svc-sql", "state": "Running", "version": "10.0.17763.1"}},
        "adfs": {
            "properties": {"host": "sts.contoso.com", "identifier": "http://sts.contoso.com/adfs/services/trust", "lockout_enabled": true,
                           "lockout_mode": "ADFSSmartLockoutLogOnly", "audit_level": "None", "log_level": ["Errors", "Warnings"]},
            "farm_behavior": 3,
            "certificates": [
                {"type": "Token-Signing", "thumbprint": "AA11", "not_before": "2023-01-01T00:00:00Z", "provider": "Microsoft Enhanced RSA and AES Cryptographic Provider", "raw": "TUlJQ0FEFS"},
                {"type": "Service-Communications", "thumbprint": "BB22", "not_before": "2026-09-01T00:00:00Z", "provider": "", "raw": "X"},
            ],
            "endpoints": [
                {"path": "/adfs/services/trust/2005/usernamemixed", "proxy": true},
                {"path": "/adfs/ls/", "proxy": true},
                {"path": "/adfs/services/trust/13/windowstransport", "proxy": false},
            ],
            "relying_parties": [
                {"name": "Old portal", "enabled": true, "access_policy": "", "authorization": "=> issue(Type = \"http://schemas.microsoft.com/authorization/claims/permit\", Value = \"true\");", "signature": "http://www.w3.org/2000/09/xmldsig#rsa-sha1"},
                {"name": "Payroll", "enabled": true, "access_policy": "Permit specific group", "authorization": "", "signature": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"},
            ],
        },
    });
    let sync = json!({
        "services": {
            "ADSync": {"account": "NT SERVICE\\ADSync", "state": "Running", "version": "1.6.16.0"},
            "AADConnectProvisioningAgent": {"account": "NT SERVICE\\AADConnectProvisioningAgent", "version": "1.1.1586.0"},
            "AzureADConnectAuthenticationAgent": {"account": "NT AUTHORITY\\NetworkService", "version": "1.5.2482.0"},
        },
        "sync": {"staging": false, "cycle_enabled": true, "features": {"PasswordHashSync": true, "PasswordWriteBack": true, "UnifiedGroupWriteback": true}},
    });
    let endpoints = [
        json!({"name": "app01.corp.example.com", "data": {"identity": adfs, "os": {"build": 17763}, "hotfixes": {"last": "2026-05-01T00:00:00Z"},
                                                         "audit": {"0CCE9222-69AE-11D9-BED3-505054503030": "No Auditing"}}}),
        json!({"name": "ws01.corp.example.com", "data": {"identity": sync, "os": {"build": 20348}, "hotfixes": {"last": "2026-10-01T00:00:00Z"},
                                                        "local_admins": [{"name": "CORP\\jdoe", "sid": sid(1108)}, {"name": "CORP\\Domain Admins", "sid": sid(512)}],
                                                        "sessions": ["CORP\\jdoe"]}}),
    ];
    fs::write(
        ad.path().join("endpoints.jsonl"),
        endpoints
            .iter()
            .map(|l| format!("{l}\n"))
            .collect::<String>(),
    )
    .unwrap();
    // A pass-through agent on DC01 is on Tier 0, as it should be.
    let dcs = fs::read_to_string(ad.path().join("dcconfig.jsonl")).unwrap();
    let patched: String = dcs
        .lines()
        .map(|l| {
            let mut v: Value = serde_json::from_str(l).unwrap();
            if v["name"] == "dc01.corp.example.com" {
                v["data"]["identity"] = json!({"services": {"AzureADConnectAuthenticationAgent": {"account": "NT AUTHORITY\\NetworkService", "version": "1.5.2482.0"}}});
            }
            format!("{v}\n")
        })
        .collect();
    fs::write(ad.path().join("dcconfig.jsonl"), patched).unwrap();
    entra_area(
        entra.path(),
        "federation",
        &[
            json!({"@dca.parent": "fed.contoso.com", "issuerUri": "http://sts.contoso.com/adfs/services/trust", "signingCertificate": "TUlJQ0FEFS",
                 "nextSigningCertificate": "TUlJQkFDS0RPT1I="}),
        ],
    );
    let domain = RawDomain::load(ad.path()).unwrap();
    let tenant = RawTenant::load(entra.path()).unwrap();
    let models = vec![Model::build(&domain)];
    let t = Tenant::build(&tenant);
    let ctx = Ctx {
        domains: &models,
        tenant: Some(&t),
    };
    let r: HashMap<String, CheckResult> = analyze(&catalog(), &ctx, &[])
        .into_iter()
        .map(|c| (c.id.clone(), c))
        .collect();
    let reasons = |id: &str| -> Vec<String> {
        assert_eq!(r[id].status, ResultStatus::Failed, "{id}: {:?}", r[id]);
        r[id]
            .affected
            .iter()
            .map(|a| format!("{}: {}", a.name, a.reason.as_deref().unwrap_or_default()))
            .collect()
    };
    let patch = reasons("HY-FED-001");
    assert_eq!(patch.len(), 1, "{patch:?}");
    assert!(
        patch[0].starts_with("app01.corp.example.com: last update installed 15"),
        "{patch:?}"
    );
    let certs = reasons("HY-FED-002");
    assert_eq!(
        certs.len(),
        2,
        "age and key storage of the token-signing certificate only: {certs:?}"
    );
    let svc = reasons("HY-FED-003");
    assert!(
        svc.iter()
            .any(|x| x.contains("not a group managed service account")),
        "{svc:?}"
    );
    assert!(reasons("HY-FED-004")[0].contains("ADFSSmartLockoutLogOnly mode"));
    assert_eq!(
        reasons("HY-FED-005").len(),
        1,
        "only the proxied legacy endpoint"
    );
    let fed = reasons("HY-FED-007");
    assert_eq!(fed.len(), 1, "{fed:?}");
    assert!(fed[0].contains("nextSigningCertificate"));
    assert_eq!(reasons("HY-FED-009").len(), 4);
    assert_eq!(
        reasons("HY-FED-010").len(),
        2,
        "Old portal permits everyone and signs with SHA-1"
    );

    assert!(reasons("HY-SYNC-001")[0].contains("version 1 is retired"));
    let t0 = reasons("HY-SYNC-003");
    assert!(t0.iter().any(|x| x.contains("not treated as Tier 0")));
    assert!(t0
        .iter()
        .any(|x| x.contains("CORP\\jdoe is a local administrator")));
    assert!(t0.iter().any(|x| x.contains("CORP\\jdoe is signed in")));
    assert_eq!(
        reasons("HY-SYNC-010").len(),
        1,
        "password writeback is not group or device writeback"
    );
    assert_eq!(
        r["HY-SYNC-012"].status,
        ResultStatus::Passed,
        "{:?}",
        r["HY-SYNC-012"]
    );
    assert_eq!(reasons("HY-SYNC-013").len(), 2);
    assert_eq!(reasons("HY-SYNC-015"), ["ws01.corp.example.com: Pass-through agent 1.5.2482.0 on a server that is not Tier 0: it sees every cloud sign-in password"]);
}

#[test]
fn identity_server_checks_need_the_servers() {
    let r = run(true);
    for id in ["HY-FED-001", "HY-FED-004", "HY-SYNC-001", "HY-SYNC-015"] {
        assert_eq!(r[id].status, ResultStatus::NotAssessed, "{id}");
        assert!(
            r[id].note.as_deref().unwrap().contains("endpoint targets"),
            "{id}"
        );
    }
}
