//! The checks in rules_az2.rs against the test tenant plus Azure Resource
//! Manager areas shaped like ARM's responses.

use std::path::Path;

use serde_json::{json, Value};

use super::raw::RawTenant;
use super::tests::{write_tenant, ACTIVE, ADMIN, APP_SP, NOW};
use super::tests_exo::area;
use super::{analyze, TenantAnalysis};
use crate::results::tests::catalog;
use crate::results::{CheckResult, ResultStatus};
use crate::time;

const SUB: &str = "5ub00000-0000-0000-0000-000000000001";
const OWNER: &str = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635";
const CONTRIBUTOR: &str = "b24988ac-6180-42a0-ab88-20f7382dd24c";
const READER: &str = "acdd72a7-3385-48ef-bd42-f606fba81ae7";
const MI: &str = "eeeeeeee-0000-0000-0000-00000000000a";

fn vault_id(name: &str) -> String {
    format!("/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/{name}")
}

fn days(d: i64) -> i64 {
    time::parse_iso(NOW).unwrap() + d * time::DAY
}

fn secret(vault: &str, name: &str, attrs: Value) -> Value {
    json!({"id": format!("{}/secrets/{name}", vault_id(vault)), "name": name, "@dca.parent": vault_id(vault),
           "properties": {"attributes": attrs}})
}

fn key(vault: &str, name: &str, kty: &str, size: i64) -> Value {
    json!({"id": format!("{}/keys/{name}", vault_id(vault)), "name": name, "@dca.parent": vault_id(vault),
           "properties": {"kty": kty, "keySize": size, "attributes": {"enabled": true, "exp": days(200)}}})
}

fn role(n: u32, principal: &str, role: &str, scope: &str) -> Value {
    json!({"id": format!("/ra/{n}"), "properties": {"principalId": principal, "principalType": "User", "scope": scope,
        "roleDefinitionId": format!("/providers/Microsoft.Authorization/roleDefinitions/{role}")}})
}

fn write(dir: &Path) {
    area(
        dir,
        "azsubscriptions",
        &[json!({"subscriptionId": SUB, "displayName": "Production", "state": "Enabled"})],
    );
    area(
        dir,
        "azvaults",
        &[
            json!({"id": vault_id("kv-apps"), "name": "kv-apps", "@dca.parent": SUB, "properties": {}}),
            json!({"id": vault_id("kv-identity"), "name": "kv-identity", "@dca.parent": SUB, "properties": {}}),
        ],
    );
    area(
        dir,
        "azkvsecrets",
        &[
            secret(
                "kv-apps",
                "db-password",
                json!({"enabled": true, "created": days(-800), "updated": days(-500)}),
            ),
            secret(
                "kv-apps",
                "api-token",
                json!({"enabled": true, "exp": days(10), "updated": days(-20)}),
            ),
            secret(
                "kv-apps",
                "old-cert",
                json!({"enabled": true, "exp": days(-3), "updated": days(-20)}),
            ),
            secret(
                "kv-apps",
                "fine",
                json!({"enabled": true, "exp": days(300), "updated": days(-20)}),
            ),
            secret(
                "kv-apps",
                "disabled",
                json!({"enabled": false, "updated": days(-900)}),
            ),
            secret(
                "kv-identity",
                "ADFS-TokenSigning-pfx",
                json!({"enabled": true, "exp": days(300), "updated": days(-20)}),
            ),
        ],
    );
    area(
        dir,
        "azkvkeys",
        &[
            key("kv-apps", "legacy", "RSA", 1024),
            key("kv-apps", "app", "RSA", 2048),
            key("kv-identity", "entraconnect-key", "RSA", 3072),
        ],
    );
    area(
        dir,
        "azroleassignments",
        &[
            role(1, ADMIN, OWNER, &format!("/subscriptions/{SUB}")),
            role(2, ACTIVE, READER, &vault_id("kv-identity")),
            role(3, MI, CONTRIBUTOR, &format!("/subscriptions/{SUB}")),
            role(4, ACTIVE, CONTRIBUTOR, &vault_id("kv-apps")),
        ],
    );
    area(
        dir,
        "azclassicadmins",
        &[
            json!({"@dca.parent": SUB, "properties": {"emailAddress": "olduser@contoso.com", "role": "CoAdministrator"}}),
        ],
    );
    area(
        dir,
        "azautomation",
        &[
            json!({"id": "/subscriptions/x/aa1", "name": "aa-ops", "@dca.parent": SUB, "identity": {"principalId": MI}}),
            json!({"id": "/subscriptions/x/aa2", "name": "aa-reports", "@dca.parent": SUB, "identity": {"principalId": "nobody"}}),
        ],
    );
    area(
        dir,
        "azlogicapps",
        &[
            json!({"name": "la-sync", "@dca.parent": SUB, "identity": {"userAssignedIdentities": {"/uai/1": {"principalId": APP_SP}}}}),
        ],
    );
    area(
        dir,
        "azwebapps",
        &[
            json!({"name": "fn-export", "kind": "functionapp", "@dca.parent": SUB, "identity": {"principalId": "nobody"}}),
        ],
    );
    area(
        dir,
        "azscriptscan",
        &[
            json!({"kind": "runbook", "id": "/rb/1", "name": "Reset-Passwords", "matches": [{"line": 4, "keyword": "password"}, {"line": 9, "keyword": "password"}]}),
        ],
    );
    area(
        dir,
        "azautomationvars",
        &[
            json!({"account": "/subscriptions/x/aa1", "name": "SqlPassword", "isEncrypted": false, "hasValue": true}),
            json!({"account": "/subscriptions/x/aa1", "name": "ApiKey", "isEncrypted": true, "hasValue": false}),
            json!({"account": "/subscriptions/x/aa1", "name": "Region", "isEncrypted": false, "hasValue": true}),
        ],
    );
}

fn run(w: fn(&Path)) -> TenantAnalysis {
    let dir = tempfile::tempdir().unwrap();
    write_tenant(dir.path());
    w(dir.path());
    let raw = RawTenant::load(dir.path()).unwrap();
    analyze(&catalog(), &raw, &[])
}

fn result<'a>(a: &'a TenantAnalysis, id: &str) -> &'a CheckResult {
    a.checks
        .iter()
        .find(|c| c.id == id)
        .unwrap_or_else(|| panic!("{id} did not run"))
}

fn failed<'a>(a: &'a TenantAnalysis, id: &str) -> &'a CheckResult {
    let r = result(a, id);
    assert_eq!(r.status, ResultStatus::Failed, "{id}: {r:?}");
    r
}

fn lines(r: &CheckResult) -> Vec<String> {
    let mut v: Vec<String> = r
        .affected
        .iter()
        .map(|a| format!("{}: {}", a.name, a.reason.as_deref().unwrap_or_default()))
        .collect();
    v.sort();
    v
}

#[test]
fn key_vault_contents() {
    let a = run(write);
    assert_eq!(
        lines(failed(&a, "AZ-KV-005")),
        [
            "kv-apps/api-token: Expires in 10 days",
            "kv-apps/db-password: The secret has no expiry date",
            "kv-apps/old-cert: Expired 3 days ago and still enabled",
        ]
    );
    assert_eq!(
        lines(failed(&a, "AZ-KV-006")),
        ["kv-apps/db-password: Not rotated for 500 days"]
    );
    assert_eq!(
        lines(failed(&a, "AZ-KV-008")),
        [
            "kv-apps/legacy: RSA key of 1024 bits",
            "kv-identity/entraconnect-key: Software-protected RSA key in a vault holding Tier 0 material",
        ]
    );
    let r = failed(&a, "AZ-KV-009");
    assert_eq!(r.affected.len(), 1);
    let why = r.affected[0].reason.as_deref().unwrap();
    assert!(
        why.contains("ADFS-TokenSigning-pfx") && why.contains("entraconnect-key"),
        "{why}"
    );
    assert!(why.contains("admin@contoso.com (Owner)"), "{why}");
    assert!(
        !why.contains("Reader"),
        "Reader cannot reach secrets: {why}"
    );
}

#[test]
fn identities_and_credentials() {
    let a = run(write);
    assert_eq!(lines(failed(&a, "AZ-RBAC-007")), ["olduser@contoso.com: Classic CoAdministrator: has Owner-equivalent rights outside Azure RBAC and PIM"]);
    let r = failed(&a, "AZ-RBAC-016");
    assert_eq!(r.affected.len(), 1);
    assert!(lines(r)[0].starts_with("aa-ops: Automation account whose managed identity holds Contributor on subscription Production"));
    let r = failed(&a, "AZ-RBAC-017");
    assert_eq!(
        r.affected.len(),
        1,
        "an Entra role holder's identity counts too"
    );
    assert!(
        lines(r)[0].contains("Entra Application Administrator"),
        "{:?}",
        lines(r)
    );
    assert_eq!(
        lines(failed(&a, "AZ-RBAC-019")),
        [
            "Reset-Passwords: Runbook looks like it holds a credential (password) on line 4, 9",
            "aa1/SqlPassword: Unencrypted variable named like a credential: anyone with Reader on the account can read it",
        ]
    );
}

#[test]
fn azure_areas_not_read_are_not_assessed() {
    let a = run(|_| {});
    for id in [
        "AZ-KV-005",
        "AZ-KV-009",
        "AZ-RBAC-007",
        "AZ-RBAC-016",
        "AZ-RBAC-019",
    ] {
        assert_eq!(result(&a, id).status, ResultStatus::NotAssessed, "{id}");
    }
}
