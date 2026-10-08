//! Azure rules against the test tenant plus Azure Resource Manager areas
//! written the way Invoke-DCAEntra.ps1 writes them: one object per line,
//! with `@dca.parent` on items read per subscription or per vault.

use std::path::Path;

use serde_json::{json, Value};

use super::raw::RawTenant;
use super::tests::{write_tenant, ACTIVE, ADMIN, APP_SP, GUEST, TENANT};
use super::tests_exo::area;
use super::{analyze, TenantAnalysis};
use crate::results::tests::catalog;
use crate::results::{CheckResult, ResultStatus};

const OWNER: &str = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635";
const CONTRIBUTOR: &str = "b24988ac-6180-42a0-ab88-20f7382dd24c";
const READER: &str = "acdd72a7-3385-48ef-bd42-f606fba81ae7";
const KV_SECRETS_USER: &str = "4633458b-17de-408a-b874-0445c86b69e6";
const SUB1: &str = "5ub00000-0000-0000-0000-000000000001";
const SUB2: &str = "5ub00000-0000-0000-0000-000000000002";
const MG: &str = "/providers/Microsoft.Management/managementGroups/platform";
const GONE: &str = "eeeeeeee-0000-0000-0000-000000000009";

fn role(id: u32, principal: &str, kind: &str, role: &str, scope: &str) -> Value {
    json!({
        "id": format!("/ra/{id}"),
        "properties": {
            "principalId": principal,
            "principalType": kind,
            "roleDefinitionId": format!("/providers/Microsoft.Authorization/roleDefinitions/{role}"),
            "scope": scope,
        },
    })
}

fn sub_scope(sub: &str) -> String {
    format!("/subscriptions/{sub}")
}

fn vault(sub: &str, name: &str, props: Value) -> Value {
    json!({
        "id": format!("/subscriptions/{sub}/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/{name}"),
        "name": name,
        "properties": props,
        "@dca.parent": sub,
    })
}

fn write_az(dir: &Path) {
    area(
        dir,
        "azmgmtgroups",
        &[
            json!({"name": TENANT, "properties": {"displayName": "Tenant Root Group"}}),
            json!({"name": "platform", "properties": {"displayName": "Platform"}}),
        ],
    );
    area(
        dir,
        "azsubscriptions",
        &[
            json!({"subscriptionId": SUB1, "displayName": "Production", "state": "Enabled"}),
            json!({"subscriptionId": SUB2, "displayName": "Sandbox", "state": "Enabled"}),
            json!({"subscriptionId": "5ub-off", "displayName": "Retired", "state": "Disabled"}),
        ],
    );
    let s1 = sub_scope(SUB1);
    let s2 = sub_scope(SUB2);
    area(
        dir,
        "azroleassignments",
        &[
            role(1, ADMIN, "User", OWNER, "/"),
            role(2, ADMIN, "User", OWNER, MG),
            role(3, ACTIVE, "User", OWNER, &s1),
            // The same assignment read twice, once per subscription.
            role(3, ACTIVE, "User", OWNER, &s1),
            role(4, GUEST, "User", READER, &s2),
            role(5, APP_SP, "ServicePrincipal", OWNER, &s1),
            role(6, APP_SP, "ServicePrincipal", KV_SECRETS_USER, &s1),
            role(
                7,
                GONE,
                "User",
                CONTRIBUTOR,
                &format!("{s2}/resourceGroups/rg"),
            ),
        ],
    );
    area(
        dir,
        "azeligible",
        &[role(20, ADMIN, "User", CONTRIBUTOR, &s2)],
    );
    area(
        dir,
        "azactive",
        &[
            json!({"properties": {"principalId": ACTIVE, "principalType": "User", "assignmentType": "Assigned",
                 "roleDefinitionId": format!("/x/roleDefinitions/{OWNER}"), "scope": s1}}),
            json!({"properties": {"principalId": ADMIN, "principalType": "User", "assignmentType": "Activated",
                 "roleDefinitionId": format!("/x/roleDefinitions/{CONTRIBUTOR}"), "scope": s2,
                 "endDateTime": "2026-10-06T17:00:00Z"}}),
        ],
    );
    area(
        dir,
        "azroledefinitions",
        &[
            json!({"name": "c1", "properties": {"roleName": "Ops everything", "type": "CustomRole",
                 "permissions": [{"actions": ["*"], "notActions": []}]}}),
            json!({"name": "c2", "properties": {"roleName": "VM operator", "type": "CustomRole",
                 "permissions": [{"actions": ["Microsoft.Compute/virtualMachines/start/action"], "notActions": []}]}}),
        ],
    );
    area(
        dir,
        "azcontacts",
        &[
            json!({"name": "default", "properties": {"emails": "secops@contoso.com"}, "@dca.parent": SUB1}),
        ],
    );
    let mcsb = "/providers/Microsoft.Authorization/policySetDefinitions/1f3afdf9-d0c9-4c3d-847f-89da613e70a8";
    area(
        dir,
        "azpolicies",
        &[json!({"name": "asb", "properties": {"policyDefinitionId": mcsb}, "@dca.parent": SUB1})],
    );
    let mut pricings: Vec<Value> = [
        "VirtualMachines",
        "SqlServers",
        "StorageAccounts",
        "KeyVaults",
        "Arm",
        "Containers",
    ]
    .iter()
    .map(|p| json!({"name": p, "properties": {"pricingTier": "Standard"}, "@dca.parent": SUB1}))
    .collect();
    pricings.push(json!({"name": "VirtualMachines", "properties": {"pricingTier": "Free"}, "@dca.parent": SUB2}));
    area(dir, "azpricings", &pricings);
    area(
        dir,
        "azsecurescore",
        &[
            json!({"name": "ascScore", "properties": {"score": {"current": 31.5, "max": 45, "percentage": 0.7}}, "@dca.parent": SUB1}),
        ],
    );
    area(
        dir,
        "azdiagnostics",
        &[
            json!({"name": "to-la", "properties": {"workspaceId": "/la/1",
                 "logs": [{"category": "Administrative", "enabled": true}]}, "@dca.parent": SUB1}),
            json!({"name": "off", "properties": {"workspaceId": "/la/1",
                 "logs": [{"category": "Administrative", "enabled": false}]}, "@dca.parent": SUB2}),
        ],
    );
    area(
        dir,
        "azlighthouse",
        &[
            json!({"name": "msp", "@dca.parent": SUB2, "properties": {"registrationDefinition": {"properties": {
                "managedByTenantName": "Fabrikam MSP",
                "authorizations": [
                    {"principalId": "x", "roleDefinitionId": CONTRIBUTOR},
                    {"principalId": "y", "roleDefinitionId": READER},
                ],
            }}}}),
        ],
    );
    area(
        dir,
        "azstorage",
        &[
            json!({"name": "prodlogs", "properties": {"allowBlobPublicAccess": false, "allowSharedKeyAccess": false}, "@dca.parent": SUB1}),
            json!({"name": "sandboxweb", "properties": {"allowBlobPublicAccess": true}, "@dca.parent": SUB2}),
        ],
    );
    area(
        dir,
        "azvaults",
        &[
            vault(
                SUB1,
                "kv-prod",
                json!({"enableRbacAuthorization": true, "enableSoftDelete": true, "enablePurgeProtection": true,
                       "publicNetworkAccess": "Disabled", "networkAcls": {"defaultAction": "Deny"}}),
            ),
            vault(
                SUB2,
                "kv-legacy",
                json!({"enableRbacAuthorization": false, "enableSoftDelete": true,
                       "publicNetworkAccess": "Enabled", "networkAcls": {"defaultAction": "Allow"},
                       "accessPolicies": [{"objectId": ADMIN, "permissions": {"secrets": ["Get", "List", "Purge"], "keys": ["all"]}}]}),
            ),
        ],
    );
    let prod = format!(
        "/subscriptions/{SUB1}/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv-prod"
    );
    area(
        dir,
        "azvaultdiagnostics",
        &[
            json!({"name": "audit", "properties": {"workspaceId": "/la/1",
                 "logs": [{"categoryGroup": "audit", "enabled": true}]}, "@dca.parent": prod}),
        ],
    );
}

fn run() -> TenantAnalysis {
    let dir = tempfile::tempdir().unwrap();
    write_tenant(dir.path());
    write_az(dir.path());
    let raw = RawTenant::load(dir.path()).unwrap();
    analyze(&catalog(), &raw, &[])
}

fn is<'a>(a: &'a TenantAnalysis, id: &str, status: ResultStatus) -> &'a CheckResult {
    let r = a
        .checks
        .iter()
        .find(|c| c.id == id)
        .unwrap_or_else(|| panic!("{id} did not run"));
    assert_eq!(r.status, status, "{id}: {r:?}");
    r
}

fn names(r: &CheckResult) -> Vec<&str> {
    r.affected.iter().map(|a| a.name.as_str()).collect()
}

fn reasons(r: &CheckResult) -> Vec<&str> {
    r.affected
        .iter()
        .map(|a| a.reason.as_deref().unwrap_or_default())
        .collect()
}

#[test]
fn role_assignments() {
    let a = run();
    let root = is(&a, "AZ-RBAC-001", ResultStatus::Failed);
    assert_eq!(reasons(root), ["Owner at root (/)"]);
    let broad = is(&a, "AZ-RBAC-002", ResultStatus::Failed);
    assert_eq!(
        reasons(broad),
        [
            "Owner at root (/), inherited by every subscription below",
            "Owner at management group Platform, inherited by every subscription below",
        ]
    );
    // The duplicate read of assignment 3 is counted once.
    assert!(broad
        .evidence
        .iter()
        .any(|e| e.value == "subscription Production: 2"));
    // Only the permanent assignment counts; the activated one ends.
    let standing = is(&a, "AZ-RBAC-003", ResultStatus::Failed);
    assert_eq!(names(standing), ["worker@contoso.com"]);
    let guests = is(&a, "AZ-RBAC-004", ResultStatus::Failed);
    assert_eq!(
        reasons(guests),
        ["Guest with active role acdd72a7-3385-48ef-bd42-f606fba81ae7 at subscription Sandbox"]
    );
    let apps = is(&a, "AZ-RBAC-005", ResultStatus::Failed);
    assert_eq!(names(apps), ["Provisioning connector"]);
    assert_eq!(
        names(is(&a, "AZ-RBAC-006", ResultStatus::Failed)),
        ["Ops everything"]
    );
    let orphan = is(&a, "AZ-RBAC-008", ResultStatus::Failed);
    assert_eq!(names(orphan), [GONE]);
    assert!(reasons(orphan)[0].contains("rg in subscription Sandbox"));
}

#[test]
fn subscription_settings() {
    let a = run();
    let owners = is(&a, "AZ-RBAC-009", ResultStatus::Failed);
    // Sandbox inherits the root and Platform Owners but has no contact.
    assert_eq!(names(owners), ["Sandbox"]);
    assert_eq!(reasons(owners), ["no security contact email"]);
    assert_eq!(
        names(is(&a, "AZ-RBAC-011", ResultStatus::Failed)),
        ["Sandbox"]
    );
    let plans = is(&a, "AZ-RBAC-012", ResultStatus::Failed);
    assert_eq!(names(plans), ["Sandbox"]);
    assert!(reasons(plans)[0].starts_with("Plans off: VirtualMachines, SqlServers"));
    let score = is(&a, "AZ-RBAC-013", ResultStatus::Passed);
    assert!(score.evidence.iter().any(|e| e.value == "Production: 70%"));
    assert_eq!(
        names(is(&a, "AZ-RBAC-014", ResultStatus::Failed)),
        ["Sandbox"]
    );
    let msp = is(&a, "AZ-RBAC-015", ResultStatus::Failed);
    assert_eq!(names(msp), ["Fabrikam MSP"]);
    assert_eq!(reasons(msp), ["Delegated Contributor on Sandbox"]);
    let storage = is(&a, "AZ-RBAC-018", ResultStatus::Failed);
    assert_eq!(names(storage), ["sandboxweb"]);
    assert_eq!(
        reasons(storage),
        ["anonymous blob access allowed, shared key access allowed"]
    );
}

#[test]
fn key_vaults() {
    let a = run();
    for id in [
        "AZ-KV-001",
        "AZ-KV-003",
        "AZ-KV-004",
        "AZ-KV-007",
        "AZ-KV-010",
    ] {
        let r = is(&a, id, ResultStatus::Failed);
        assert_eq!(names(r), ["kv-legacy"], "{id}");
    }
    assert_eq!(
        reasons(is(&a, "AZ-KV-003", ResultStatus::Failed)),
        ["Off: purge protection"]
    );
    let grants = is(&a, "AZ-KV-002", ResultStatus::Failed);
    assert_eq!(
        reasons(grants),
        [
            "admin@contoso.com has purge secrets, all keys permissions",
            "Key Vault Secrets User at subscription Production: reaches every vault below",
        ]
    );
}

#[test]
fn azure_not_collected_is_not_assessed() {
    let dir = tempfile::tempdir().unwrap();
    write_tenant(dir.path());
    let raw = RawTenant::load(dir.path()).unwrap();
    let a = analyze(&catalog(), &raw, &[]);
    for id in ["AZ-RBAC-001", "AZ-KV-001"] {
        let r = is(&a, id, ResultStatus::NotAssessed);
        assert!(r.note.as_deref().unwrap().contains("not collected"), "{id}");
    }
}

#[test]
fn azure_rules_and_catalog_agree() {
    use crate::catalog::CheckStatus;
    let catalog = catalog();
    let rules: Vec<&str> = super::rules_az::RULES
        .iter()
        .chain(super::rules_az2::RULES)
        .map(|r| r.id)
        .chain(crate::hybrid::rules_az::RULES.iter().map(|r| r.id))
        .filter(|id| id.starts_with("AZ-"))
        .collect();
    for id in &rules {
        let c = catalog.check(id).unwrap();
        assert_eq!(c.status, CheckStatus::Implemented, "{id}");
        assert!(c.detail.is_some(), "{id} has no detail block");
    }
    for c in catalog.checks.iter().filter(|c| {
        (c.area == "AZ-RBAC" || c.area == "AZ-KV") && c.status == CheckStatus::Implemented
    }) {
        assert!(rules.contains(&c.id.as_str()), "{} has no rule", c.id);
    }
}
