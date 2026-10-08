//! The checks in rules_more.rs against the test tenant plus the areas they
//! read, written the way Invoke-DCAEntra.ps1 writes them.

use std::path::Path;

use serde_json::{json, Value};

use super::model::GLOBAL_ADMIN;
use super::raw::RawTenant;
use super::tests::{write_tenant, ACTIVE, ADMIN, APP_SP, GUEST, NOW, STALE, TENANT};
use super::tests_exo::area;
use super::{analyze, TenantAnalysis};
use crate::results::tests::catalog;
use crate::results::{CheckResult, ResultStatus};

const ROLE_GROUP: &str = "bbbbbbbb-0000-0000-0000-000000000001";
const PRIV_GROUP: &str = "bbbbbbbb-0000-0000-0000-000000000002";
const NESTED: &str = "bbbbbbbb-0000-0000-0000-000000000003";
const GLASS: &str = "aaaaaaaa-0000-0000-0000-000000000010";
const SHARED: &str = "aaaaaaaa-0000-0000-0000-000000000011";
const HELPDESK: &str = "729827e3-9c14-49f7-bb1b-9608f156bbb8";
const AZ_OWNER: &str = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635";
const AZ_UAA: &str = "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9";

fn user(id: &str, upn: &str, extra: Value) -> Value {
    let mut u = json!({
        "id": id,
        "userPrincipalName": upn,
        "displayName": upn.split('@').next().unwrap(),
        "userType": "Member",
        "accountEnabled": true,
    });
    for (k, v) in extra.as_object().unwrap() {
        u[k] = v.clone();
    }
    u
}

fn assignment(principal: &str, kind: &str, role: &str) -> Value {
    json!({"principalId": principal, "roleDefinitionId": role, "directoryScopeId": "/",
           "principal": {"@odata.type": format!("#microsoft.graph.{kind}"), "id": principal}})
}

fn policy(name: &str, users: Value, clients: &[&str], grant: &str) -> Value {
    json!({
        "id": format!("ca-{name}"),
        "displayName": name,
        "state": "enabled",
        "conditions": {
            "users": users,
            "applications": {"includeApplications": ["All"]},
            "clientAppTypes": clients,
        },
        "grantControls": {"operator": "OR", "builtInControls": [grant]},
    })
}

fn audit(activity: &str, target: Value) -> Value {
    json!({"activityDisplayName": activity, "activityDateTime": NOW,
           "initiatedBy": {"user": {"userPrincipalName": "admin@contoso.com"}}, "targetResources": [target]})
}

fn az(id: u32, principal: &str, role: &str, scope: &str) -> Value {
    json!({"id": format!("/ra/{id}"), "properties": {
        "principalId": principal, "principalType": "User", "scope": scope,
        "roleDefinitionId": format!("/providers/Microsoft.Authorization/roleDefinitions/{role}")}})
}

/// A tenant where every check in rules_more.rs has something to find.
fn write_weak(dir: &Path) {
    let direct = json!([{"skuId": "s", "assignedByGroup": null, "state": "Active"}]);
    area(
        dir,
        "users",
        &[
            user(
                ADMIN,
                "admin@contoso.com",
                json!({"mail": "admin@contoso.com", "assignedLicenses": [{"skuId": "s"}],
                       "licenseAssignmentStates": direct, "passwordPolicies": "DisablePasswordExpiration",
                       "proxyAddresses": ["SMTP:admin@contoso.com"]}),
            ),
            user(
                ACTIVE,
                "worker@contoso.com",
                json!({"licenseAssignmentStates": [{"skuId": "s", "assignedByGroup": PRIV_GROUP}],
                       "proxyAddresses": ["smtp:sales@contoso.com"]}),
            ),
            user(
                STALE,
                "old@contoso.com",
                json!({"proxyAddresses": ["SMTP:sales@contoso.com"], "onPremisesImmutableId": "c2VlZA==",
                       "onPremisesProvisioningErrors": [{"propertyCausingError": "UserPrincipalName", "value": "old@contoso.com"}]}),
            ),
            user(
                GUEST,
                "partner_fabrikam.com#EXT#@contoso.onmicrosoft.com",
                json!({"userType": "Guest"}),
            ),
            user(GLASS, "breakglass01@contoso.onmicrosoft.com", json!({})),
            user(SHARED, "info@contoso.com", json!({})),
            // Synced accounts are governed by the on-premises policy.
            user(
                "aaaaaaaa-0000-0000-0000-000000000012",
                "synced@contoso.com",
                json!({"onPremisesSyncEnabled": true, "passwordPolicies": "DisablePasswordExpiration",
                       "onPremisesImmutableId": "c3luYw=="}),
            ),
        ],
    );
    area(
        dir,
        "groups",
        &[
            json!({"id": ROLE_GROUP, "displayName": "Tenant admins", "isAssignableToRole": true, "groupTypes": [],
                   "owners": [{"@odata.type": "#microsoft.graph.user", "id": ACTIVE}]}),
            json!({"id": PRIV_GROUP, "displayName": "Helpdesk leads", "isAssignableToRole": true, "groupTypes": [],
                   "owners": []}),
            json!({"id": NESTED, "displayName": "Ops", "groupTypes": [], "owners": []}),
            json!({"id": "g-fin", "displayName": "Finance Team", "groupTypes": ["Unified"], "visibility": "Public", "owners": []}),
            json!({"id": "g-fun", "displayName": "Running club", "groupTypes": ["Unified"], "visibility": "Public", "owners": []}),
            json!({"id": "g-hr", "displayName": "HR private", "groupTypes": ["Unified"], "visibility": "Private", "owners": []}),
        ],
    );
    // Owners came with the groups, so the collector marks the area read.
    area(dir, "groupowners", &[]);
    area(
        dir,
        "rolegroupmembers",
        &[json!({"@dca.parent": ROLE_GROUP, "value": [
                {"@odata.type": "#microsoft.graph.user", "id": GUEST, "userPrincipalName": "partner_fabrikam.com#EXT#@contoso.onmicrosoft.com"},
                {"@odata.type": "#microsoft.graph.group", "id": NESTED, "displayName": "Ops"}]})],
    );
    area(
        dir,
        "roledefinitions",
        &[
            json!({"id": GLOBAL_ADMIN, "templateId": GLOBAL_ADMIN, "displayName": "Global Administrator", "isBuiltIn": true}),
            json!({"id": HELPDESK, "templateId": HELPDESK, "displayName": "Helpdesk Administrator", "isBuiltIn": true}),
        ],
    );
    let mut roles = vec![
        assignment(ADMIN, "user", GLOBAL_ADMIN),
        assignment(ROLE_GROUP, "group", GLOBAL_ADMIN),
        assignment(PRIV_GROUP, "group", GLOBAL_ADMIN),
    ];
    roles.extend((0..6).map(|i| assignment(&format!("hd-{i}"), "user", HELPDESK)));
    area(dir, "roleassignments", &roles);
    area(
        dir,
        "capolicies",
        &[
            policy(
                "MFA for everyone",
                json!({"includeUsers": ["All"], "excludeUsers": [STALE], "excludeRoles": [HELPDESK]}),
                &["all"],
                "mfa",
            ),
            policy(
                "Block legacy A",
                json!({"includeUsers": ["All"]}),
                &["exchangeActiveSync", "other"],
                "block",
            ),
            policy(
                "Block legacy B",
                json!({"includeUsers": ["All"]}),
                &["exchangeActiveSync", "other"],
                "block",
            ),
        ],
    );
    area(
        dir,
        "applications",
        &[
            json!({"id": "app-1", "appId": "11", "displayName": "Payroll sync", "notes": "Service account password is in the vault"}),
            json!({"id": "app-2", "appId": "22", "displayName": "Intranet", "description": "Staff portal"}),
        ],
    );
    area(
        dir,
        "grants",
        &[
            json!({"clientId": APP_SP, "consentType": "AllPrincipals", "resourceId": "graph", "scope": "User.Read Mail.ReadWrite"}),
        ],
    );
    area(dir, "approleassignments", &[]);
    area(
        dir,
        "audits",
        &[
            audit(
                "Consent to application",
                json!({"id": "unknown-sp", "displayName": "Mail Reader"}),
            ),
            audit(
                "Consent to application",
                json!({"id": APP_SP, "displayName": "Provisioning connector"}),
            ),
            audit(
                "Update conditional access policy",
                json!({"displayName": "MFA for everyone"}),
            ),
            audit(
                "Add partner to company",
                json!({"displayName": "Fabrikam CSP"}),
            ),
        ],
    );
    let denied: Vec<Value> = (0..10)
        .map(|_| json!({"userId": ADMIN, "userPrincipalName": "admin@contoso.com", "createdDateTime": NOW, "status": {"errorCode": 500121}}))
        .chain([json!({"userId": ACTIVE, "userPrincipalName": "worker@contoso.com", "createdDateTime": NOW, "status": {"errorCode": 500121}})])
        .collect();
    area(dir, "signinsfailed", &denied);
    area(
        dir,
        "authmethods",
        &[
            json!({"policyMigrationState": "migrationInProgress", "authenticationMethodConfigurations": [
            {"id": "X509Certificate", "state": "enabled", "certificateUserBindings": [
                {"x509CertificateField": "PrincipalName", "userProperty": "userPrincipalName", "priority": 1, "trustAffinityLevel": "low"},
                {"x509CertificateField": "SubjectKeyIdentifier", "userProperty": "certificateUserIds", "priority": 2, "trustAffinityLevel": "high"}]},
            {"id": "Email", "state": "enabled", "allowExternalIdToUseEmailOtp": "disabled"}]}),
        ],
    );
    area(
        dir,
        "registration",
        &[
            json!({"id": ADMIN, "userType": "member", "isSsprEnabled": false, "isSsprCapable": false}),
            json!({"id": ACTIVE, "userType": "member", "isSsprEnabled": false, "isSsprCapable": false}),
        ],
    );
    area(
        dir,
        "authorization",
        &[json!({"id": "authorizationPolicy", "allowedToUseSSPR": true})],
    );
    area(
        dir,
        "skus",
        &[json!({"skuPartNumber": "EMS", "servicePlans": [{"servicePlanName": "INTUNE_A"}]})],
    );
    area(
        dir,
        "devices",
        &[
            json!({"displayName": "PC-PENDING", "operatingSystem": "Windows", "trustType": "ServerAd", "isCompliant": null, "registrationDateTime": null, "accountEnabled": true}),
            json!({"displayName": "PC-OK", "operatingSystem": "Windows", "trustType": "ServerAd", "isCompliant": true, "registrationDateTime": NOW, "accountEnabled": true}),
        ],
    );
    area(
        dir,
        "deviceregistration",
        &[
            json!({"azureADRegistration": {"allowedToRegister": {"@odata.type": "#microsoft.graph.allDeviceRegistrationMembership"}}}),
        ],
    );
    area(
        dir,
        "groupsettings",
        &[
            json!({"displayName": "Group.Unified", "values": [{"name": "EnableMIPLabels", "value": "False"}]}),
        ],
    );
    area(
        dir,
        "exomailboxes",
        &[
            json!({"DisplayName": "info", "RecipientTypeDetails": "SharedMailbox", "ExternalDirectoryObjectId": SHARED}),
            json!({"DisplayName": "worker", "RecipientTypeDetails": "UserMailbox", "ExternalDirectoryObjectId": ACTIVE}),
        ],
    );
    area(
        dir,
        "azroleassignments",
        &[
            az(1, ADMIN, AZ_OWNER, "/subscriptions/s1"),
            az(2, ADMIN, AZ_UAA, "/"),
            // The same assignment read once per subscription.
            az(2, ADMIN, AZ_UAA, "/"),
            az(3, ACTIVE, AZ_OWNER, "/subscriptions/s1"),
        ],
    );
    area(
        dir,
        "crosstenant",
        &[
            json!({"b2bDirectConnectInbound": {"usersAndGroups": {"accessType": "allowed"}},
                 "b2bDirectConnectOutbound": {"usersAndGroups": {"accessType": "blocked"}}}),
        ],
    );
    area(
        dir,
        "crosstenantpartners",
        &[
            json!({"tenantId": "partner-1", "automaticUserConsentSettings": {"inboundAllowed": true},
                 "b2bDirectConnectInbound": {"usersAndGroups": {"accessType": "allowed"}}}),
        ],
    );
}

/// The same tenant configured well.
fn write_strong(dir: &Path) {
    area(
        dir,
        "authmethods",
        &[
            json!({"policyMigrationState": "migrationComplete", "authenticationMethodConfigurations": [
            {"id": "X509Certificate", "state": "disabled"},
            {"id": "Email", "state": "enabled", "allowExternalIdToUseEmailOtp": "enabled"}]}),
        ],
    );
    area(
        dir,
        "registration",
        &[
            json!({"id": ACTIVE, "userType": "member", "isSsprEnabled": true, "isSsprCapable": true}),
        ],
    );
    area(
        dir,
        "authorization",
        &[json!({"id": "authorizationPolicy"})],
    );
    area(
        dir,
        "deviceregistration",
        &[
            json!({"azureADRegistration": {"allowedToRegister": {"@odata.type": "#microsoft.graph.enumeratedDeviceRegistrationMembership"}}}),
        ],
    );
    area(
        dir,
        "groupsettings",
        &[
            json!({"displayName": "Group.Unified", "values": [{"name": "EnableMIPLabels", "value": "True"}]}),
        ],
    );
    area(
        dir,
        "crosstenant",
        &[
            json!({"b2bDirectConnectInbound": {"usersAndGroups": {"accessType": "blocked"}},
                 "b2bDirectConnectOutbound": {"usersAndGroups": {"accessType": "blocked"}}}),
        ],
    );
    area(dir, "crosstenantpartners", &[]);
    area(
        dir,
        "capolicies",
        &[
            policy(
                "MFA for everyone",
                json!({"includeUsers": ["All"], "excludeUsers": [GLASS]}),
                &["all"],
                "mfa",
            ),
            json!({"id": "ca-wid", "displayName": "Workload identities from known networks", "state": "enabled",
                   "conditions": {"clientApplications": {"includeServicePrincipals": ["ServicePrincipalsInMyTenant"]},
                                  "applications": {"includeApplications": ["All"]},
                                  "locations": {"includeLocations": ["All"], "excludeLocations": ["AllTrusted"]}},
                   "grantControls": {"operator": "OR", "builtInControls": ["block"]}}),
        ],
    );
    area(
        dir,
        "users",
        &[
            user(GLASS, "breakglass01@contoso.onmicrosoft.com", json!({})),
            user(ACTIVE, "worker@contoso.com", json!({})),
        ],
    );
    area(
        dir,
        "azroleassignments",
        &[az(1, ACTIVE, AZ_OWNER, "/subscriptions/s1")],
    );
    area(
        dir,
        "applications",
        &[
            json!({"id": "app-2", "appId": "22", "displayName": "Intranet", "description": "Staff portal"}),
        ],
    );
    area(dir, "devices", &[]);
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

fn failed<'a>(a: &'a TenantAnalysis, id: &str) -> &'a CheckResult {
    let r = result(a, id);
    assert_eq!(r.status, ResultStatus::Failed, "{id}: {r:?}");
    r
}

#[test]
fn weak_tenant_findings() {
    let a = run(write_weak);
    let has = |id: &str, name: &str| {
        let r = failed(&a, id);
        assert!(
            names(r).iter().any(|n| n.contains(name)),
            "{id} should name {name}: {:?}",
            names(r)
        );
        r
    };

    has("EN-APP-018", "Provisioning connector");
    let r = has("EN-APP-019", "Mail Reader");
    assert_eq!(r.affected.len(), 1, "the tenant's own app is expected");
    let r = has("EN-APP-022", "Payroll sync");
    assert_eq!(r.affected.len(), 1);

    has("EN-AUTH-005", "Contoso");
    let r = has("EN-AUTH-009", "Contoso");
    assert!(reason(r).contains("PrincipalName to userPrincipalName"));
    assert!(!reason(r).contains("SubjectKeyIdentifier"));
    let r = failed(&a, "EN-AUTH-010");
    assert!(
        found(r).starts_with("0 of 2 members enabled"),
        "{}",
        found(r)
    );
    let r = has("EN-AUTH-018", "admin@contoso.com");
    assert_eq!(r.affected.len(), 1, "one denial is not fatigue");
    has("EN-AUTH-019", "Contoso");

    has("EN-CA-017", "MFA for everyone");
    let r = has("EN-CA-018", "old@contoso.com");
    assert_eq!(r.affected.len(), 1);
    has("EN-CA-020", "Block legacy A, Block legacy B");
    has("EN-CA-021", "Contoso");
    has("EN-CA-023", "breakglass01");
    has("EN-CA-024", "MFA for everyone");

    let r = has("EN-DEV-006", "PC-PENDING");
    assert_eq!(r.affected.len(), 1);
    let r = has("EN-DEV-007", "PC-PENDING");
    assert_eq!(r.affected.len(), 1);
    has("EN-DEV-011", "Contoso");

    let r = has("EN-GRP-002", "Tenant admins");
    assert!(reason(r).contains("worker@contoso.com"));
    assert!(
        !names(r).contains(&"Helpdesk leads"),
        "a group without owners has no outsiders"
    );
    has("EN-GRP-005", "Helpdesk leads");
    let r = has("EN-GRP-007", "Finance Team");
    assert_eq!(
        r.affected.len(),
        1,
        "private and unremarkable groups are fine"
    );
    has("EN-GRP-009", "Contoso");

    let r = has("EN-ID-005", "admin@contoso.com");
    assert_eq!(
        r.affected.len(),
        1,
        "synced accounts follow the on-premises policy"
    );
    has("EN-ID-009", "info@contoso.com");
    let r = has("EN-ID-010", "old@contoso.com");
    assert_eq!(r.affected.len(), 1);
    assert_eq!(
        names(failed(&a, "EN-ID-014")),
        ["old@contoso.com", "old@contoso.com", "worker@contoso.com"]
    );
    let r = has("EN-ID-015", "admin@contoso.com");
    assert_eq!(r.affected.len(), 1);
    assert_eq!(r.severity, Some(crate::catalog::Severity::Info));

    let r = has("EN-PRIV-010", "admin@contoso.com");
    assert_eq!(r.affected.len(), 1);
    let r = has("EN-PRIV-015", "admin@contoso.com");
    assert_eq!(
        r.affected.len(),
        2,
        "duplicates count once, non-admins not at all"
    );
    let r = has("EN-PRIV-016", "admin@contoso.com");
    assert_eq!(r.affected.len(), 1);
    let r = has("EN-PRIV-019", "Tenant admins");
    assert!(reason(r).contains("Ops"));
    let r = result(&a, "EN-PRIV-020");
    assert!(
        found(r).contains("Exchange Administrator: none"),
        "{}",
        found(r)
    );

    let r = failed(&a, "EN-TEN-010");
    assert_eq!(r.affected.len(), 2);
    assert!(found(r).contains("1 partners can sync"), "{}", found(r));
    has("HUNT-EN-015", "Fabrikam CSP");
    has("HUNT-EN-016", "admin@contoso.com");
}

#[test]
fn strong_tenant_passes() {
    let a = run(write_strong);
    for id in [
        "EN-APP-022",
        "EN-AUTH-005",
        "EN-AUTH-009",
        "EN-AUTH-010",
        "EN-AUTH-019",
        "EN-CA-018",
        "EN-CA-020",
        "EN-CA-021",
        "EN-CA-023",
        "EN-DEV-011",
        "EN-GRP-009",
        "EN-PRIV-015",
        "EN-PRIV-016",
        "EN-TEN-010",
        "HUNT-EN-016",
    ] {
        let r = result(&a, id);
        assert_eq!(r.status, ResultStatus::Passed, "{id}: {r:?}");
    }
}

#[test]
fn missing_areas_are_not_assessed() {
    // The base tenant has no authentication methods, devices, Azure or
    // Exchange data.
    let a = run(|_| {});
    for id in [
        "EN-AUTH-005",
        "EN-DEV-007",
        "EN-DEV-011",
        "EN-ID-009",
        "EN-PRIV-016",
        "EN-TEN-010",
        "HUNT-EN-015",
    ] {
        assert_eq!(result(&a, id).status, ResultStatus::NotAssessed, "{id}");
    }
    let _ = TENANT;
}

fn reason(r: &CheckResult) -> &str {
    r.affected[0].reason.as_deref().unwrap_or_default()
}

fn found(r: &CheckResult) -> &str {
    r.found.as_deref().unwrap_or_default()
}
