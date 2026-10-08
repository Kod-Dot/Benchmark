//! The checks in rules_mon.rs and rules_azmon.rs against the test tenant
//! plus the areas they read, written the way Invoke-DCAEntra.ps1 writes them.

use std::path::Path;

use serde_json::{json, Value};

use super::raw::RawTenant;
use super::tests::{write_tenant, ACTIVE, ADMIN, APP_SP, GUEST, NOW};
use super::tests_exo::area;
use super::{analyze, TenantAnalysis};
use crate::results::tests::catalog;
use crate::results::{CheckResult, ResultStatus};

const APP_ID: &str = "dddddddd-0000-0000-0000-000000000001";
const GLASS: &str = "aaaaaaaa-0000-0000-0000-000000000010";

fn users(dir: &Path) {
    let u = |id: &str, upn: &str, kind: &str| json!({"id": id, "userPrincipalName": upn, "displayName": upn.split('@').next().unwrap(), "userType": kind, "accountEnabled": true});
    area(
        dir,
        "users",
        &[
            u(ADMIN, "admin@contoso.com", "Member"),
            u(ACTIVE, "worker@contoso.com", "Member"),
            u(
                GUEST,
                "partner_fabrikam.com#EXT#@contoso.onmicrosoft.com",
                "Guest",
            ),
            u(GLASS, "breakglass01@contoso.onmicrosoft.com", "Member"),
        ],
    );
}

fn signin(upn: &str, country: &str, device: Value) -> Value {
    json!({"userPrincipalName": upn, "createdDateTime": NOW, "appDisplayName": "Office 365 Exchange Online",
           "status": {"errorCode": 0}, "location": {"countryOrRegion": country}, "deviceDetail": device})
}

fn detection(user: &str, upn: &str, kind: &str, level: &str, state: &str) -> Value {
    json!({"id": format!("{kind}-{user}"), "userId": user, "userPrincipalName": upn, "riskEventType": kind,
           "riskLevel": level, "riskState": state, "detectedDateTime": NOW, "ipAddress": "198.51.100.20",
           "location": {"countryOrRegion": "KP"}})
}

fn activity(op: &str, vm: &str, status: &str, at: &str) -> Value {
    let suffix = if op.contains("extensions") {
        "/extensions/CustomScript"
    } else {
        ""
    };
    json!({"operationName": {"value": op}, "status": {"value": status}, "caller": "admin@contoso.com", "eventTimestamp": at,
           "resourceId": format!("/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/{vm}{suffix}")})
}

fn write_weak(dir: &Path) {
    users(dir);
    area(dir, "spsignins", &[]);
    area(
        dir,
        "fedcreds",
        &[
            json!({"id": "app-1", "appId": APP_ID, "displayName": "Deploy pipeline", "federatedIdentityCredentials": [
            {"name": "prs", "issuer": "https://token.actions.githubusercontent.com", "subject": "repo:contoso/infra:pull_request"},
            {"name": "main", "issuer": "https://token.actions.githubusercontent.com", "subject": "repo:contoso/infra:ref:refs/heads/main"},
            {"name": "odd", "issuer": "https://idp.example.net", "subject": "deploy"}]}),
        ],
    );
    area(
        dir,
        "riskysps",
        &[
            json!({"id": APP_SP, "appId": APP_ID, "displayName": "Provisioning connector", "riskState": "atRisk",
                 "riskLevel": "high", "riskLastUpdatedDateTime": NOW}),
        ],
    );
    let mut signins: Vec<Value> = (0..150)
        .map(|_| signin("worker@contoso.com", "NL", json!({"deviceId": ""})))
        .collect();
    signins.push(signin(
        "admin@contoso.com",
        "KP",
        json!({"deviceId": "dev-1", "displayName": "LAPTOP-7", "isCompliant": false}),
    ));
    signins.push(signin(
        "admin@contoso.com",
        "NL",
        json!({"deviceId": "dev-1", "displayName": "LAPTOP-7", "isCompliant": false}),
    ));
    signins.push(signin(
        "worker@contoso.com",
        "NL",
        json!({"deviceId": "dev-2", "displayName": "LAPTOP-8", "isCompliant": true}),
    ));
    area(dir, "signins", &signins);
    area(dir, "accessreviews", &[]);
    area(
        dir,
        "pimalerts",
        &[
            json!({"id": "a1", "alertDefinitionId": "TooManyGlobalAdminsAssignedToTenantAlert", "isActive": true, "incidentCount": 6,
                   "lastScannedDateTime": NOW, "alertDefinition": {"displayName": "There are too many global administrators", "severityLevel": "low"}}),
            json!({"id": "a2", "alertDefinitionId": "RolesAssignedOutsidePimAlert", "isActive": false, "incidentCount": 0}),
        ],
    );
    area(
        dir,
        "branding",
        &[
            json!({"@dca.parent": "org", "customPrivacyAndCookiesUrl": "https://login-contoso.example.net/privacy",
                 "customTermsOfUseUrl": "https://www.contoso.com/terms"}),
        ],
    );
    area(
        dir,
        "riskdetections",
        &[
            detection(
                ADMIN,
                "admin@contoso.com",
                "impossibleTravel",
                "high",
                "atRisk",
            ),
            detection(
                ACTIVE,
                "worker@contoso.com",
                "anonymizedIPAddress",
                "low",
                "remediated",
            ),
            detection(
                ACTIVE,
                "worker@contoso.com",
                "anomalousToken",
                "medium",
                "dismissed",
            ),
        ],
    );
    let failed = |code: i64, at: &str| json!({"userPrincipalName": "admin@contoso.com", "createdDateTime": at, "status": {"errorCode": code}});
    area(
        dir,
        "signinsfailed",
        &[
            failed(500121, NOW),
            failed(500121, "2026-09-20T10:00:00Z"),
            failed(53003, NOW),
            failed(50126, NOW),
        ],
    );
    let sp = |country: &str| json!({"servicePrincipalId": APP_SP, "servicePrincipalName": "Provisioning connector", "createdDateTime": NOW, "location": {"countryOrRegion": country}});
    area(dir, "signinssp", &[sp("NL"), sp("NL"), sp("US")]);
    area(
        dir,
        "aaddiagnostics",
        &[
            json!({"name": "audit-only", "properties": {"workspaceId": "/w", "logs": [
            {"category": "AuditLogs", "enabled": true}, {"category": "SignInLogs", "enabled": false}]}}),
        ],
    );
    area(dir, "azalertrules", &[]);
    area(
        dir,
        "azactivity",
        &[
            activity(
                "Microsoft.Compute/virtualMachines/runCommand/action",
                "DC01",
                "Started",
                "2026-10-05T10:00:01Z",
            ),
            activity(
                "Microsoft.Compute/virtualMachines/runCommand/action",
                "DC01",
                "Succeeded",
                "2026-10-05T10:00:40Z",
            ),
            activity(
                "Microsoft.Compute/virtualMachines/extensions/write",
                "APP01",
                "Succeeded",
                "2026-10-04T08:00:00Z",
            ),
            activity(
                "Microsoft.Compute/virtualMachines/runCommand/action",
                "APP02",
                "Failed",
                "2026-10-04T09:00:00Z",
            ),
            activity(
                "Microsoft.Compute/virtualMachines/start/action",
                "APP01",
                "Succeeded",
                "2026-10-04T07:00:00Z",
            ),
        ],
    );
}

fn write_strong(dir: &Path) {
    users(dir);
    area(
        dir,
        "spsignins",
        &[json!({"appId": APP_ID, "lastSignInActivity": {"lastSignInDateTime": NOW}})],
    );
    area(
        dir,
        "fedcreds",
        &[
            json!({"id": "app-1", "displayName": "Deploy pipeline", "federatedIdentityCredentials": [
            {"name": "main", "issuer": "https://token.actions.githubusercontent.com", "subject": "repo:contoso/infra:environment:prod"}]}),
        ],
    );
    area(dir, "riskysps", &[]);
    area(
        dir,
        "accessreviews",
        &[
            json!({"displayName": "Guests quarterly", "status": "InProgress", "scope": {"query": "/users?$filter=(userType eq 'Guest')"}}),
            json!({"displayName": "Admins", "status": "InProgress", "scope": {"query": "/roleManagement/directory/roleAssignmentScheduleInstances?$filter=roleDefinitionId eq 'x'"}}),
        ],
    );
    area(dir, "pimalerts", &[json!({"id": "a2", "isActive": false})]);
    area(
        dir,
        "branding",
        &[json!({"customTermsOfUseUrl": "https://www.contoso.com/terms"})],
    );
    area(dir, "riskdetections", &[]);
    area(
        dir,
        "skus",
        &[
            json!({"skuPartNumber": "SPE_E5", "capabilityStatus": "Enabled", "servicePlans": [{"servicePlanName": "ATP_ENTERPRISE"}, {"servicePlanName": "MTP"}]}),
        ],
    );
    area(
        dir,
        "signinssp",
        &[json!({"servicePrincipalId": APP_SP, "location": {"countryOrRegion": "NL"}})],
    );
    area(
        dir,
        "aaddiagnostics",
        &[
            json!({"name": "to-sentinel", "properties": {"workspaceId": "/w", "logs": [
            {"category": "AuditLogs", "enabled": true}, {"category": "SignInLogs", "enabled": true}]}}),
        ],
    );
    area(
        dir,
        "azalertrules",
        &[
            json!({"name": "break-glass sign-in", "properties": {"enabled": true, "criteria": {"allOf": [
            {"query": "SigninLogs | where UserPrincipalName =~ 'BreakGlass01@contoso.onmicrosoft.com'"}]}}}),
        ],
    );
    area(dir, "azactivity", &[]);
}

fn run(write: fn(&Path)) -> TenantAnalysis {
    let dir = tempfile::tempdir().unwrap();
    write_tenant(dir.path());
    write(dir.path());
    let raw = RawTenant::load(dir.path()).unwrap();
    analyze(&catalog(), &raw, &[])
}

fn result<'a>(a: &'a TenantAnalysis, id: &str) -> &'a CheckResult {
    a.checks
        .iter()
        .find(|c| c.id == id)
        .unwrap_or_else(|| panic!("{id} did not run"))
}

fn names(r: &CheckResult) -> Vec<&str> {
    let mut v: Vec<&str> = r.affected.iter().map(|a| a.name.as_str()).collect();
    v.sort_unstable();
    v
}

fn found(r: &CheckResult) -> &str {
    r.found.as_deref().unwrap_or_default()
}

fn failed<'a>(a: &'a TenantAnalysis, id: &str) -> &'a CheckResult {
    let r = result(a, id);
    assert_eq!(r.status, ResultStatus::Failed, "{id}: {r:?}");
    r
}

#[test]
fn weak_tenant_findings() {
    let a = run(write_weak);

    assert_eq!(names(failed(&a, "EN-APP-012")), ["Provisioning connector"]);
    let r = failed(&a, "EN-APP-014");
    assert_eq!(
        r.affected.len(),
        2,
        "the main-branch credential is narrow: {r:?}"
    );
    assert!(found(r).starts_with("3 federated credentials"));
    assert_eq!(names(failed(&a, "EN-APP-023")), ["Provisioning connector"]);
    assert_eq!(names(failed(&a, "EN-DEV-012")), ["LAPTOP-7"]);

    failed(&a, "EN-ID-016");
    failed(&a, "EN-PRIV-013");
    assert_eq!(
        names(failed(&a, "EN-PRIV-012")),
        ["There are too many global administrators"]
    );
    let r = failed(&a, "EN-TEN-016");
    assert_eq!(r.affected.len(), 1);
    assert!(r.affected[0]
        .reason
        .as_deref()
        .unwrap()
        .contains("login-contoso.example.net"));

    let r = failed(&a, "EN-MON-003");
    assert_eq!(names(r), ["admin@contoso.com"]);
    assert!(r.raw.as_deref().unwrap().contains("impossibleTravel: 1"));
    assert_eq!(names(failed(&a, "EN-MON-004")), ["admin@contoso.com"]);
    let r = failed(&a, "EN-MON-005");
    assert_eq!(names(r), ["KP"], "NL is where the tenant works");
    let r = result(&a, "EN-MON-007");
    assert_eq!(
        found(r),
        "2 failed MFA prompts and 1 blocked sign-ins in 30 days"
    );
    assert_eq!(r.raw.as_deref().unwrap().lines().count(), 2, "two weeks");
    failed(&a, "EN-MON-008");

    assert_eq!(names(failed(&a, "HUNT-EN-001")), ["admin@contoso.com"]);
    assert_eq!(names(failed(&a, "HUNT-EN-002")), ["worker@contoso.com"]);
    assert_eq!(names(failed(&a, "HUNT-EN-013")), ["worker@contoso.com"]);
    let r = failed(&a, "HUNT-EN-019");
    assert!(r.affected[0].reason.as_deref().unwrap().contains("US (1)"));

    failed(&a, "EN-MON-001");
    failed(&a, "EN-MON-002");
    assert_eq!(
        names(failed(&a, "EN-MON-009")),
        ["breakglass01@contoso.onmicrosoft.com"]
    );
    let r = failed(&a, "HUNT-EN-017");
    assert_eq!(
        names(r),
        ["APP01", "DC01"],
        "start and end of one command count once; failures do not count"
    );
}

#[test]
fn strong_tenant_passes() {
    let a = run(write_strong);
    for id in [
        "EN-APP-012",
        "EN-APP-014",
        "EN-APP-023",
        "EN-ID-016",
        "EN-PRIV-012",
        "EN-PRIV-013",
        "EN-TEN-016",
        "EN-MON-001",
        "EN-MON-002",
        "EN-MON-003",
        "EN-MON-004",
        "EN-MON-008",
        "EN-MON-009",
        "HUNT-EN-001",
        "HUNT-EN-017",
        "HUNT-EN-019",
    ] {
        let r = result(&a, id);
        assert_eq!(r.status, ResultStatus::Passed, "{id}: {r:?}");
    }
}

#[test]
fn missing_areas_are_not_assessed() {
    let a = run(|_| {});
    for id in [
        "EN-APP-012",
        "EN-APP-014",
        "EN-APP-023",
        "EN-DEV-012",
        "EN-ID-016",
        "EN-PRIV-012",
        "EN-TEN-016",
        "EN-MON-001",
        "EN-MON-003",
        "EN-MON-005",
        "EN-MON-009",
        "HUNT-EN-017",
        "HUNT-EN-019",
    ] {
        assert_eq!(result(&a, id).status, ResultStatus::NotAssessed, "{id}");
    }
}
