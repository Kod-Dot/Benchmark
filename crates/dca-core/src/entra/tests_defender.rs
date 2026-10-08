//! The Defender checks against the test tenant plus Graph, Defender for
//! Endpoint API and ARM areas shaped like their responses.

use std::path::Path;

use serde_json::{json, Value};

use super::raw::RawTenant;
use super::tests::{write_tenant, NOW};
use super::tests_exo::area;
use super::{analyze, TenantAnalysis};
use crate::results::tests::catalog;
use crate::results::{CheckResult, ResultStatus};

fn setting(id: &str, values: &[&str]) -> Value {
    json!({"settingInstance": {"settingDefinitionId": id,
        "simpleSettingCollectionValue": values.iter().map(|v| json!({"value": v})).collect::<Vec<_>>()}})
}

fn choice(v: &str) -> Value {
    json!({"settingInstance": {"settingDefinitionId": "x", "choiceSettingValue": {"value": v}}})
}

fn policy(name: &str, settings: Vec<Value>) -> Value {
    json!({"name": name, "settings": settings, "assignments": [{"id": "a"}]})
}

fn device(name: &str, id: &str, days_ago: &str) -> Value {
    json!({"displayName": name, "deviceId": id, "operatingSystem": "Windows", "accountEnabled": true, "approximateLastSignInDateTime": days_ago})
}

fn weak(dir: &Path) {
    area(
        dir,
        "devices",
        &[
            device("PC-ON", "d-on", NOW),
            device("PC-OFF", "d-off", NOW),
            device("PC-GONE", "d-gone", "2025-01-01T00:00:00Z"),
        ],
    );
    area(
        dir,
        "mdemachines",
        &[
            json!({"computerDnsName": "pc-on.contoso.com", "aadDeviceId": "D-ON", "onboardingStatus": "Onboarded", "healthStatus": "Active", "defenderAvStatus": "Passive", "osPlatform": "Windows11"}),
            json!({"computerDnsName": "srv-old.contoso.com", "aadDeviceId": "d-srv", "onboardingStatus": "Onboarded", "healthStatus": "Inactive", "osPlatform": "WindowsServer2019"}),
        ],
    );
    area(
        dir,
        "intunedevices",
        &[
            json!({"id": "m1", "deviceName": "PC-ON", "operatingSystem": "Windows"}),
            json!({"id": "m2", "deviceName": "PC-OFF", "operatingSystem": "Windows"}),
        ],
    );
    area(
        dir,
        "intuneprotection",
        &[
            json!({"@dca.parent": "m1", "tamperProtectionEnabled": true}),
            json!({"@dca.parent": "m2", "tamperProtectionEnabled": false}),
        ],
    );
    area(
        dir,
        "intunepolicies",
        &[policy(
            "AV",
            vec![
                choice("device_vendor_msft_policy_config_defender_enablenetworkprotection_2"),
                setting(
                    "device_vendor_msft_policy_config_defender_excludedpaths",
                    &["C:\\Users\\", "D:\\SQL\\Data\\db.mdf", "%TEMP%"],
                ),
                setting(
                    "device_vendor_msft_policy_config_defender_excludedprocesses",
                    &["powershell.exe", "sqlservr.exe"],
                ),
                setting(
                    "device_vendor_msft_policy_config_defender_excludedextensions",
                    &[".exe", ".mdf"],
                ),
            ],
        )],
    );
    let alert = |status: &str| json!({"title": "Suspicious PowerShell", "serviceSource": "microsoftDefenderForEndpoint", "evidence": [{"remediationStatus": status}]});
    area(
        dir,
        "mdealerts",
        &[
            alert("none"),
            alert("none"),
            alert("notFound"),
            alert("none"),
            alert("none"),
        ],
    );
    area(
        dir,
        "skus",
        &[
            json!({"skuPartNumber": "SPE_E5", "capabilityStatus": "Enabled", "servicePlans": [{"servicePlanName": "ADALLOM_S_STANDALONE"}, {"servicePlanName": "ATP_ENTERPRISE"}]}),
        ],
    );
    area(dir, "capolicies", &[]);
    area(
        dir,
        "exosafelinks",
        &[json!({"Name": "Custom", "IsBuiltInProtection": false})],
    );
    area(
        dir,
        "exosafelinksrules",
        &[json!({"Name": "Custom", "State": "Disabled"})],
    );
    area(dir, "exosafeattachrules", &[]);
    area(dir, "exopreset", &[]);
    // The base tenant's admin is a Global Administrator.
    area(
        dir,
        "securescores",
        &[
            json!({"createdDateTime": "2026-09-07T00:00:00Z", "currentScore": 40.0, "maxScore": 100.0}),
            json!({"createdDateTime": "2026-10-06T00:00:00Z", "currentScore": 55.0, "maxScore": 100.0}),
        ],
    );
    area(
        dir,
        "incidents",
        &[
            json!({"displayName": "Multi-stage incident", "severity": "high", "status": "active", "createdDateTime": "2026-07-01T00:00:00Z", "assignedTo": null}),
            json!({"displayName": "New phishing", "severity": "medium", "status": "active", "createdDateTime": NOW}),
        ],
    );
    area(
        dir,
        "azworkspaces",
        &[json!({"id": "/subscriptions/s/workspaces/law"})],
    );
    area(
        dir,
        "azsentinel",
        &[json!({"kind": "AzureActiveDirectory"})],
    );
}

fn strong(dir: &Path) {
    area(dir, "devices", &[device("PC-ON", "d-on", NOW)]);
    area(
        dir,
        "mdemachines",
        &[
            json!({"computerDnsName": "pc-on", "aadDeviceId": "d-on", "onboardingStatus": "Onboarded", "healthStatus": "Active", "defenderAvStatus": "Active"}),
        ],
    );
    area(
        dir,
        "intunedevices",
        &[json!({"id": "m1", "deviceName": "PC-ON", "operatingSystem": "Windows"})],
    );
    area(
        dir,
        "intuneprotection",
        &[json!({"@dca.parent": "m1", "tamperProtectionEnabled": true})],
    );
    area(
        dir,
        "intunepolicies",
        &[policy(
            "AV",
            vec![
                choice("device_vendor_msft_policy_config_defender_enablenetworkprotection_1"),
                setting(
                    "device_vendor_msft_policy_config_defender_excludedpaths",
                    &["D:\\SQL\\Data\\db.mdf"],
                ),
            ],
        )],
    );
    area(
        dir,
        "mdealerts",
        &[json!({"evidence": [{"remediationStatus": "remediated"}]})],
    );
    area(
        dir,
        "skus",
        &[
            json!({"skuPartNumber": "SPE_E5", "servicePlans": [{"servicePlanName": "ADALLOM_S_STANDALONE"}, {"servicePlanName": "ATP_ENTERPRISE"}]}),
        ],
    );
    area(
        dir,
        "capolicies",
        &[
            json!({"displayName": "MDCA session", "state": "enabled", "conditions": {"users": {"includeUsers": ["All"]}},
                 "sessionControls": {"cloudAppSecurity": {"isEnabled": true, "cloudAppSecurityType": "monitorOnly"}}}),
        ],
    );
    area(
        dir,
        "exosafelinks",
        &[json!({"Name": "Built-In Protection Policy", "IsBuiltInProtection": true})],
    );
    area(dir, "exosafelinksrules", &[]);
    area(
        dir,
        "exosafeattachrules",
        &[json!({"Name": "All", "State": "Enabled"})],
    );
    area(dir, "exopreset", &[]);
    area(
        dir,
        "incidents",
        &[json!({"displayName": "New phishing", "status": "active", "createdDateTime": NOW})],
    );
    area(
        dir,
        "azworkspaces",
        &[json!({"id": "/subscriptions/s/workspaces/law"})],
    );
    area(
        dir,
        "azsentinel",
        &[json!({"kind": "MicrosoftThreatProtection"})],
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

fn names(r: &CheckResult) -> Vec<&str> {
    let mut v: Vec<&str> = r.affected.iter().map(|a| a.name.as_str()).collect();
    v.sort_unstable();
    v
}

#[test]
fn defender_findings() {
    let a = run(weak);
    let r = failed(&a, "M365-DEF-001");
    assert_eq!(
        names(r),
        ["PC-OFF", "srv-old.contoso.com"],
        "device ids match without case; stale devices are not expected"
    );
    assert_eq!(names(failed(&a, "M365-DEF-002")), ["PC-OFF"]);
    assert_eq!(names(failed(&a, "M365-DEF-003")), ["pc-on.contoso.com"]);
    assert!(failed(&a, "M365-DEF-004").affected[0]
        .reason
        .as_deref()
        .unwrap()
        .contains("audit mode"));
    failed(&a, "M365-DEF-005");
    failed(&a, "M365-DEF-007");
    assert_eq!(failed(&a, "M365-DEF-008").affected.len(), 2);
    let r = failed(&a, "M365-DEF-009");
    assert_eq!(
        names(r),
        ["%TEMP%", ".exe", "C:\\Users\\", "powershell.exe"],
        "the database file and process are narrow"
    );
    // The guest holds Global Administrator through the role-assignable group.
    assert_eq!(
        names(failed(&a, "M365-DEF-010")),
        [
            "admin@contoso.com",
            "partner_fabrikam.com#EXT#@contoso.onmicrosoft.com"
        ]
    );
    let r = result(&a, "M365-DEF-012");
    assert_eq!(
        r.found.as_deref(),
        Some("40% on 2026-09-07, 55% on 2026-10-06")
    );
    assert_eq!(names(failed(&a, "M365-DEF-013")), ["Multi-stage incident"]);
    failed(&a, "M365-DEF-014");
}

#[test]
fn well_configured_defender_passes() {
    let a = run(strong);
    for id in [
        "M365-DEF-001",
        "M365-DEF-002",
        "M365-DEF-003",
        "M365-DEF-004",
        "M365-DEF-005",
        "M365-DEF-007",
        "M365-DEF-008",
        "M365-DEF-009",
        "M365-DEF-013",
        "M365-DEF-014",
    ] {
        let r = result(&a, id);
        assert_eq!(r.status, ResultStatus::Passed, "{id}: {r:?}");
    }
}

#[test]
fn defender_not_read_is_not_assessed() {
    let a = run(|_| {});
    for id in [
        "M365-DEF-001",
        "M365-DEF-002",
        "M365-DEF-005",
        "M365-DEF-012",
        "M365-DEF-013",
        "M365-DEF-014",
    ] {
        assert_eq!(result(&a, id).status, ResultStatus::NotAssessed, "{id}");
    }
}
