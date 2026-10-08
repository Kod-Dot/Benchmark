//! The checks in rules_rest.rs, and Entra Connect Health, against the test
//! tenant plus the areas they read.

use std::path::Path;

use serde_json::json;

use super::raw::RawTenant;
use super::tests::{write_tenant, NOW};
use super::tests_exo::area;
use super::{analyze, TenantAnalysis};
use crate::results::tests::catalog;
use crate::results::{CheckResult, ResultStatus};

fn weak(dir: &Path) {
    area(
        dir,
        "appproxy",
        &[
            json!({"@dca.parent": "a1", "displayName": "Intranet", "onPremisesPublishing": {"externalAuthenticationType": "passthru", "externalUrl": "https://intranet-contoso.msappproxy.net/", "internalUrl": "http://intranet/"}}),
            json!({"@dca.parent": "a2", "displayName": "HR portal", "onPremisesPublishing": {"externalAuthenticationType": "aadPreAuthentication"}}),
        ],
    );
    let dev = |name: &str, id: &str, trust: &str| json!({"displayName": name, "deviceId": id, "operatingSystem": "Windows", "trustType": trust, "accountEnabled": true, "approximateLastSignInDateTime": NOW});
    area(
        dir,
        "devices",
        &[
            dev("PC-1", "d1", "AzureAd"),
            dev("PC-2", "d2", "ServerAd"),
            dev("PC-HOME", "d3", "Workplace"),
        ],
    );
    area(
        dir,
        "bitlockerkeys",
        &[
            json!({"id": "k1", "deviceId": "D1", "volumeType": "operatingSystemVolume"}),
            json!({"id": "k2", "deviceId": "d2", "volumeType": "fixedDataVolume"}),
        ],
    );
    area(
        dir,
        "groupmembers",
        &[
            json!({"id": "g1", "displayName": "A", "groupTypes": [], "members": [{"id": "g2"}]}),
            json!({"id": "g2", "displayName": "B", "groupTypes": [], "members": [{"id": "g1"}, {"id": "u1"}]}),
            json!({"id": "g3", "displayName": "Placeholder", "groupTypes": [], "members": []}),
            json!({"id": "g4", "displayName": "Dynamic", "groupTypes": ["DynamicMembership"], "membershipRule": "user.department -eq \"x\"", "members": []}),
        ],
    );
    area(
        dir,
        "b2bmanagement",
        &[json!({"definition": ["{\"B2BManagementPolicy\":{\"PreviewPolicy\":{}}}"]})],
    );
    area(
        dir,
        "authorization",
        &[json!({"allowInvitesFrom": "everyone"})],
    );
    area(
        dir,
        "uxsetting",
        &[json!({"restrictNonAdminAccess": "false"})],
    );
    area(
        dir,
        "azconnecthealth",
        &[
            json!({"serviceName": "AdFederationService-sts.contoso.com", "serviceType": "AdFederationService", "health": "Error", "displayName": "sts.contoso.com"}),
        ],
    );
    area(
        dir,
        "organization",
        &[
            json!({"id": "11111111-2222-3333-4444-555555555555", "displayName": "Contoso", "onPremisesSyncEnabled": true}),
        ],
    );
}

fn strong(dir: &Path) {
    area(
        dir,
        "appproxy",
        &[
            json!({"displayName": "HR portal", "onPremisesPublishing": {"externalAuthenticationType": "aadPreAuthentication"}}),
        ],
    );
    area(
        dir,
        "devices",
        &[
            json!({"displayName": "PC-1", "deviceId": "d1", "operatingSystem": "Windows", "trustType": "AzureAd", "accountEnabled": true, "approximateLastSignInDateTime": NOW}),
        ],
    );
    area(
        dir,
        "bitlockerkeys",
        &[json!({"deviceId": "d1", "volumeType": "operatingSystemVolume"})],
    );
    area(
        dir,
        "groupmembers",
        &[json!({"id": "g1", "displayName": "A", "members": [{"id": "u1"}]})],
    );
    area(
        dir,
        "b2bmanagement",
        &[
            json!({"definition": ["{\"B2BManagementPolicy\":{\"InvitationsAllowedAndBlockedDomainsPolicy\":{\"AllowedDomains\":[\"fabrikam.com\"]}}}"]}),
        ],
    );
    area(
        dir,
        "authorization",
        &[json!({"allowInvitesFrom": "adminsAndGuestInviters"})],
    );
    area(
        dir,
        "uxsetting",
        &[json!({"restrictNonAdminAccess": "true"})],
    );
    area(
        dir,
        "azconnecthealth",
        &[
            json!({"serviceName": "AadSyncService-contoso", "serviceType": "AadSyncService", "health": "Healthy"}),
        ],
    );
    area(
        dir,
        "organization",
        &[
            json!({"id": "11111111-2222-3333-4444-555555555555", "displayName": "Contoso", "onPremisesSyncEnabled": true}),
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

fn lines(r: &CheckResult) -> Vec<String> {
    assert_eq!(r.status, ResultStatus::Failed, "{}: {r:?}", r.id);
    let mut v: Vec<String> = r
        .affected
        .iter()
        .map(|a| format!("{}: {}", a.name, a.reason.as_deref().unwrap_or_default()))
        .collect();
    v.sort();
    v
}

#[test]
fn remaining_entra_findings() {
    let a = run(weak);
    assert_eq!(lines(result(&a, "EN-APP-021")), ["Intranet: Published without pre-authentication: anyone on the internet reaches http://intranet/"]);
    assert_eq!(
        lines(result(&a, "EN-DEV-008")),
        ["PC-2: No BitLocker recovery key for the system drive is stored in Entra ID"],
        "a data-volume key does not count; registered personal devices are not expected"
    );
    let g = lines(result(&a, "EN-GRP-010"));
    assert_eq!(g.len(), 2, "{g:?}");
    assert!(g.iter().any(|x| x.starts_with("Placeholder: Empty group")));
    assert!(g.iter().any(|x| x.contains("Nesting loop: A → B → A")));
    assert_eq!(lines(result(&a, "EN-TEN-008")).len(), 2);
    lines(result(&a, "EN-TEN-012"));
    let h = lines(result(&a, "EN-MON-011"));
    assert_eq!(h.len(), 2, "{h:?}");
}

#[test]
fn remaining_entra_checks_pass_when_configured() {
    let a = run(strong);
    for id in [
        "EN-APP-021",
        "EN-DEV-008",
        "EN-GRP-010",
        "EN-TEN-008",
        "EN-TEN-012",
        "EN-MON-011",
    ] {
        let r = result(&a, id);
        assert_eq!(r.status, ResultStatus::Passed, "{id}: {r:?}");
    }
}

#[test]
fn key_vault_secret_reads() {
    let a = run(|dir| {
        area(
            dir,
            "azvaults",
            &[json!({"id": "/subscriptions/s/vaults/kv-apps", "name": "kv-apps"})],
        );
        area(
            dir,
            "kvreads",
            &[
                json!({"@dca.parent": "ws-1", "tables": [{"name": "PrimaryResult",
                "columns": [{"name": "Resource"}, {"name": "Caller"}, {"name": "Reads"}, {"name": "First"}, {"name": "Last"}],
                "rows": [
                    ["KV-APPS", "app-payroll", 900, "2026-09-07T10:00:00Z", "2026-10-05T10:00:00Z"],
                    ["KV-APPS", "198.51.100.23", 14, "2026-10-04T02:00:00Z", "2026-10-04T02:10:00Z"],
                ]}]}),
            ],
        );
    });
    let r = result(&a, "HUNT-EN-018");
    assert_eq!(lines(r), ["198.51.100.23: Started reading secrets on 2026-10-04 (14 reads): a caller not seen in the weeks before"]);
    assert!(r.found.as_deref().unwrap().starts_with("2 callers"));
}
