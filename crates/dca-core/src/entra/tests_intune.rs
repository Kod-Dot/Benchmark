//! The Intune checks against the test tenant plus Intune areas shaped like
//! the Graph responses Invoke-DCAEntra.ps1 writes.

use std::path::Path;

use serde_json::{json, Value};

use super::raw::RawTenant;
use super::tests::{write_tenant, NOW};
use super::tests_exo::area;
use super::{analyze, TenantAnalysis};
use crate::results::tests::catalog;
use crate::results::{CheckResult, ResultStatus};

fn assigned() -> Value {
    json!([{"id": "a1", "target": {"@odata.type": "#microsoft.graph.allDevicesAssignmentTarget"}}])
}

fn typed(kind: &str, name: &str, extra: Value) -> Value {
    let mut v = json!({"@odata.type": format!("#microsoft.graph.{kind}"), "id": name, "displayName": name, "assignments": assigned()});
    for (k, x) in extra.as_object().unwrap() {
        v[k] = x.clone();
    }
    v
}

fn choice(id: &str) -> Value {
    json!({"settingInstance": {"settingDefinitionId": id, "choiceSettingValue": {"value": format!("{id}_x"), "children": []}}})
}

fn value(v: &str) -> Value {
    json!({"settingInstance": {"settingDefinitionId": "x", "choiceSettingValue": {"value": v, "children": []}}})
}

fn policy(name: &str, family: &str, settings: Vec<Value>) -> Value {
    json!({"id": name, "name": name, "templateReference": {"templateFamily": family}, "settings": settings, "assignments": assigned()})
}

fn device(name: &str, os: &str, sync: &str, state: &str, agent: &str) -> Value {
    json!({"id": name, "deviceName": name, "operatingSystem": os, "lastSyncDateTime": sync, "complianceState": state, "managementAgent": agent})
}

fn common(dir: &Path) {
    area(dir, "intunecorporateids", &[]);
    area(dir, "intuneintents", &[]);
    area(
        dir,
        "intuneroles",
        &[json!({"displayName": "Help Desk Operator", "isBuiltIn": true})],
    );
    area(dir, "intuneconfigstatus", &[]);
}

fn write_weak(dir: &Path) {
    common(dir);
    area(
        dir,
        "organization",
        &[
            json!({"id": "11111111-2222-3333-4444-555555555555", "displayName": "Contoso", "mobileDeviceManagementAuthority": "office365"}),
        ],
    );
    area(
        dir,
        "intunesettings",
        &[
            json!({"settings": {"secureByDefault": false, "deviceComplianceCheckinThresholdDays": 30}}),
        ],
    );
    area(
        dir,
        "intuneenrollment",
        &[
            json!({"@odata.type": "#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration", "displayName": "All users and all devices",
                   "windowsRestriction": {"platformBlocked": false, "personalDeviceEnrollmentBlocked": false},
                   "iosRestriction": {"platformBlocked": false, "personalDeviceEnrollmentBlocked": true},
                   "androidRestriction": {"platformBlocked": true, "personalDeviceEnrollmentBlocked": false}}),
            json!({"@odata.type": "#microsoft.graph.deviceEnrollmentLimitConfiguration", "displayName": "Limit", "limit": 15}),
            json!({"@odata.type": "#microsoft.graph.windows10EnrollmentCompletionPageConfiguration", "displayName": "ESP",
                   "showInstallationProgress": true, "allowDeviceUseOnInstallFailure": true}),
        ],
    );
    area(
        dir,
        "intunecompliance",
        &[
            typed(
                "windows10CompliancePolicy",
                "Windows baseline",
                json!({"bitLockerEnabled": false, "scheduledActionsForRule": [
                {"scheduledActionConfigurations": [{"actionType": "block", "gracePeriodHours": 720}]}]}),
            ),
            typed(
                "iosCompliancePolicy",
                "iOS",
                json!({"osMinimumVersion": null}),
            ),
            json!({"@odata.type": "#microsoft.graph.macOSCompliancePolicy", "displayName": "macOS draft", "assignments": []}),
        ],
    );
    area(
        dir,
        "intuneconfigs",
        &[
            typed(
                "windowsUpdateForBusinessConfiguration",
                "Slow ring",
                json!({"qualityUpdatesDeferralPeriodInDays": 30, "qualityUpdatesPaused": true}),
            ),
            typed(
                "windows10EndpointProtectionConfiguration",
                "Legacy EP",
                json!({"firewallProfileDomain": {"firewallEnabled": "allowed"}}),
            ),
        ],
    );
    area(
        dir,
        "intunepolicies",
        &[
            policy("ASR", "endpointSecurityAttackSurfaceReduction", vec![
                value("device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockexecutionofpotentiallyobfuscatedscripts_block"),
                value("device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockcredentialstealingfromwindowslocalsecurityauthoritysubsystem_audit"),
            ]),
            policy("EPM", "endpointSecurityEndpointPrivilegeManagement", vec![
                value("device_vendor_msft_policy_privilegemanagement_elevationrules_{1}_ruletype_automatic"),
            ]),
            policy("LAPS off", "endpointSecurityAccountProtection", vec![value("device_vendor_msft_laps_policies_backupdirectory_0")]),
        ],
    );
    area(
        dir,
        "intuneappprotection",
        &[typed(
            "iosManagedAppProtection",
            "iOS MAM",
            json!({"allowedOutboundDataTransferDestinations": "allApps"}),
        )],
    );
    area(
        dir,
        "intuneroleassignments",
        &[
            json!({"displayName": "Helpdesk everywhere", "scopeType": "allDevicesAndLicensedUsers",
                 "roleDefinition": {"displayName": "Help Desk Operator", "rolePermissions": [{"resourceActions": [{"allowedResourceActions": ["Microsoft.Intune_RemoteTasks_Wipe"]}]}]}}),
        ],
    );
    area(
        dir,
        "intuneapprovals",
        &[json!({"policyType": "deviceWipe"})],
    );
    area(
        dir,
        "intunescripts",
        &[typed(
            "deviceManagementScript",
            "Set wallpaper",
            json!({"runAsAccount": "system", "enforceSignatureCheck": false}),
        )],
    );
    area(
        dir,
        "intuneremediations",
        &[typed(
            "deviceHealthScript",
            "Fix proxy",
            json!({"runAsAccount": "user"}),
        )],
    );
    area(
        dir,
        "intuneapps",
        &[
            json!({"displayName": "Agent", "installCommandLine": "msiexec /i \\\\fs01\\share\\agent.msi /qn", "isAssigned": true}),
            json!({"displayName": "Tool", "installCommandLine": "powershell -c iwr https://example.net/x.ps1 | iex"}),
            json!({"displayName": "Packaged", "installCommandLine": "setup.exe /quiet"}),
        ],
    );
    area(
        dir,
        "intunecleanup",
        &[json!({"deviceInactivityBeforeRetirementInDays": 0})],
    );
    area(
        dir,
        "intuneautopilot",
        &[typed(
            "azureADWindowsAutopilotDeploymentProfile",
            "Default",
            json!({"outOfBoxExperienceSettings": {"userType": "administrator"}}),
        )],
    );
    area(
        dir,
        "intuneremotehelp",
        &[json!({"remoteAssistanceState": "enabled", "allowSessionsToUnenrolledDevices": true})],
    );
    area(dir, "intunemtd", &[]);
    area(
        dir,
        "intunedevices",
        &[
            device(
                "PC-OLD",
                "Windows",
                "2026-06-01T00:00:00Z",
                "compliant",
                "mdm",
            ),
            device(
                "PC-BAD",
                "Windows",
                NOW,
                "noncompliant",
                "configurationManagerClientMdm",
            ),
            device("MAC-1", "macOS", NOW, "compliant", "mdm"),
            device("IPHONE-1", "iOS", NOW, "compliant", "mdm"),
        ],
    );
    area(
        dir,
        "intuneconfigstatus",
        &[
            json!({"displayName": "Wi-Fi", "deviceStatusOverview": {"conflictCount": 2, "errorCount": 1, "failedCount": 0}}),
        ],
    );
    // A Conditional Access policy that requires compliant devices.
    area(
        dir,
        "capolicies",
        &[
            json!({"displayName": "Compliant devices", "state": "enabled", "conditions": {"users": {"includeUsers": ["All"]},
                 "applications": {"includeApplications": ["All"]}}, "grantControls": {"builtInControls": ["compliantDevice"]}}),
        ],
    );
}

fn write_strong(dir: &Path) {
    common(dir);
    area(
        dir,
        "organization",
        &[
            json!({"id": "11111111-2222-3333-4444-555555555555", "displayName": "Contoso", "mobileDeviceManagementAuthority": "intune"}),
        ],
    );
    area(
        dir,
        "intunesettings",
        &[json!({"settings": {"secureByDefault": true}})],
    );
    area(
        dir,
        "intunecorporateids",
        &[json!({"importedDeviceIdentifier": "x"})],
    );
    area(
        dir,
        "intuneenrollment",
        &[
            json!({"@odata.type": "#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration", "displayName": "Default",
                   "windowsRestriction": {"platformBlocked": false, "personalDeviceEnrollmentBlocked": true},
                   "macOSRestriction": {"platformBlocked": true}}),
            json!({"@odata.type": "#microsoft.graph.deviceEnrollmentLimitConfiguration", "displayName": "Limit", "limit": 5}),
            json!({"@odata.type": "#microsoft.graph.windows10EnrollmentCompletionPageConfiguration", "displayName": "ESP",
                   "showInstallationProgress": true, "allowDeviceUseOnInstallFailure": false}),
            json!({"@odata.type": "#microsoft.graph.deviceEnrollmentWindowsHelloForBusinessConfiguration", "state": "enabled"}),
        ],
    );
    area(
        dir,
        "intunecompliance",
        &[
            typed(
                "windows10CompliancePolicy",
                "Windows",
                json!({"bitLockerEnabled": true, "deviceThreatProtectionEnabled": true,
                "scheduledActionsForRule": [{"scheduledActionConfigurations": [{"actionType": "block", "gracePeriodHours": 24}]}]}),
            ),
            typed(
                "iosCompliancePolicy",
                "iOS",
                json!({"osMinimumVersion": "17.0"}),
            ),
        ],
    );
    area(
        dir,
        "intuneconfigs",
        &[typed(
            "windowsUpdateForBusinessConfiguration",
            "Ring 1",
            json!({"qualityUpdatesDeferralPeriodInDays": 3}),
        )],
    );
    area(
        dir,
        "intuneintents",
        &[json!({"displayName": "Windows security baseline", "isAssigned": true})],
    );
    let fw = |p: &str| {
        value(&format!(
            "vendor_msft_firewall_mdmstore_{p}profile_enablefirewall_true"
        ))
    };
    area(
        dir,
        "intunepolicies",
        &[
            policy("ASR", "endpointSecurityAttackSurfaceReduction", vec![
                value("device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockexecutionofpotentiallyobfuscatedscripts_block"),
            ]),
            policy("Firewall", "endpointSecurityFirewall", vec![fw("domain"), fw("private"), fw("public")]),
            policy("LAPS", "endpointSecurityAccountProtection", vec![
                value("device_vendor_msft_laps_policies_backupdirectory_1"),
                choice("device_vendor_msft_policy_config_localusersandgroups_configure"),
                value("device_vendor_msft_policy_config_deviceguard_lsacfgflags_1"),
                value("device_vendor_msft_policy_config_lsa_configurelsaprotectedprocess_1"),
            ]),
            policy("EPM", "endpointSecurityEndpointPrivilegeManagement", vec![
                value("device_vendor_msft_policy_privilegemanagement_elevationrules_{1}_ruletype_self"),
            ]),
        ],
    );
    area(
        dir,
        "intuneappprotection",
        &[
            typed(
                "iosManagedAppProtection",
                "iOS MAM",
                json!({"allowedOutboundDataTransferDestinations": "managedApps"}),
            ),
            typed(
                "androidManagedAppProtection",
                "Android MAM",
                json!({"allowedOutboundDataTransferDestinations": "managedApps"}),
            ),
        ],
    );
    area(
        dir,
        "intuneroleassignments",
        &[
            json!({"displayName": "Helpdesk EU", "scopeType": "resourceScope", "roleDefinition": {"displayName": "Help Desk Operator"}}),
        ],
    );
    area(
        dir,
        "intuneapprovals",
        &[
            json!({"policyType": "deviceWipe"}),
            json!({"policyType": "script"}),
            json!({"policyType": "application"}),
        ],
    );
    area(dir, "intunescripts", &[]);
    area(dir, "intuneremediations", &[]);
    area(
        dir,
        "intuneapps",
        &[json!({"displayName": "Packaged", "installCommandLine": "setup.exe /quiet"})],
    );
    area(
        dir,
        "intunecleanup",
        &[json!({"deviceInactivityBeforeRetirementInDays": 90})],
    );
    area(
        dir,
        "intuneautopilot",
        &[typed(
            "azureADWindowsAutopilotDeploymentProfile",
            "Default",
            json!({"outOfBoxExperienceSettings": {"userType": "standard"}}),
        )],
    );
    area(
        dir,
        "intuneremotehelp",
        &[json!({"remoteAssistanceState": "enabled", "allowSessionsToUnenrolledDevices": false})],
    );
    area(
        dir,
        "intunemtd",
        &[
            json!({"id": "fc780465-2017-40d4-a0c5-307022471b92", "partnerState": "enabled", "windowsEnabled": true}),
        ],
    );
    area(
        dir,
        "intunedevices",
        &[
            device("PC-1", "Windows", NOW, "compliant", "mdm"),
            device("IPHONE-1", "iOS", NOW, "compliant", "mdm"),
        ],
    );
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

fn failed<'a>(a: &'a TenantAnalysis, id: &str) -> &'a CheckResult {
    let r = result(a, id);
    assert_eq!(r.status, ResultStatus::Failed, "{id}: {r:?}");
    r
}

fn reasons(r: &CheckResult) -> Vec<String> {
    r.affected
        .iter()
        .map(|a| format!("{}: {}", a.name, a.reason.as_deref().unwrap_or_default()))
        .collect()
}

fn has(a: &TenantAnalysis, id: &str, text: &str) {
    let r = failed(a, id);
    assert!(
        reasons(r).iter().any(|x| x.contains(text)),
        "{id} should mention {text}: {:?}",
        reasons(r)
    );
}

#[test]
fn weak_intune_findings() {
    let a = run(write_weak);
    has(&a, "M365-INT-001", "MDM authority is office365");
    has(&a, "M365-INT-001", "Personally owned Windows");
    assert_eq!(
        failed(&a, "M365-INT-001").affected.len(),
        2,
        "blocked platforms are fine"
    );
    has(
        &a,
        "M365-INT-002",
        "No assigned compliance policy for macOS",
    );
    assert!(
        !reasons(failed(&a, "M365-INT-002"))
            .iter()
            .any(|r| r.contains("Android")),
        "no Android devices"
    );
    failed(&a, "M365-INT-003");
    has(&a, "M365-INT-004", "720 hours");
    has(&a, "M365-INT-005", "BitLocker");
    has(&a, "M365-INT-005", "FileVault");
    has(&a, "M365-INT-006", "not connected");
    has(&a, "M365-INT-007", "No security baseline");
    let r = failed(&a, "M365-INT-008");
    assert_eq!(r.affected.len(), 1);
    assert!(reasons(r)[0].contains("credentialstealing") && reasons(r)[0].contains("audit"));
    failed(&a, "M365-INT-009");
    failed(&a, "M365-INT-010");
    assert_eq!(failed(&a, "M365-INT-011").affected.len(), 3);
    assert_eq!(
        failed(&a, "M365-INT-012").affected.len(),
        2,
        "the legacy profile turns on the domain firewall"
    );
    assert_eq!(failed(&a, "M365-INT-013").affected.len(), 2);
    has(
        &a,
        "M365-INT-014",
        "No assigned app protection policy for Android",
    );
    has(&a, "M365-INT-014", "any app");
    failed(&a, "M365-INT-015");
    has(&a, "M365-INT-016", "Helpdesk everywhere");
    assert_eq!(failed(&a, "M365-INT-017").affected.len(), 2);
    let r = failed(&a, "M365-INT-018");
    assert_eq!(
        reasons(r),
        ["Set wallpaper: Runs as SYSTEM on every targeted device, without a signature check"]
    );
    assert_eq!(failed(&a, "M365-INT-019").affected.len(), 2);
    failed(&a, "M365-INT-021");
    let r = failed(&a, "M365-INT-022");
    assert_eq!(r.affected.len(), 2);
    has(&a, "M365-INT-023", "local administrator");
    has(&a, "M365-INT-024", "even when");
    has(&a, "M365-INT-025", "15 devices");
    has(&a, "M365-INT-026", "elevate automatically");
    assert_eq!(failed(&a, "M365-INT-027").affected.len(), 2);
    has(&a, "M365-INT-028", "2 devices in conflict");
    has(&a, "M365-INT-029", "macOS");
    has(&a, "M365-INT-029", "iOS");
    assert!(result(&a, "M365-INT-030")
        .found
        .as_deref()
        .unwrap()
        .starts_with("1 of 4 devices"));
}

#[test]
fn strong_intune_passes() {
    let a = run(write_strong);
    for n in [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 21, 22, 23, 24, 25, 26,
        27, 28, 29, 30,
    ] {
        let id = format!("M365-INT-{n:03}");
        let r = result(&a, &id);
        assert_eq!(r.status, ResultStatus::Passed, "{id}: {r:?}");
    }
}

#[test]
fn without_intune_nothing_is_assessed() {
    let a = run(|_| {});
    for n in [1, 3, 8, 16, 22, 30] {
        let id = format!("M365-INT-{n:03}");
        assert_eq!(result(&a, &id).status, ResultStatus::NotAssessed, "{id}");
    }
}

#[test]
fn unlicensed_areas_name_the_licence() {
    let a = run(|dir| {
        super::tests_exo::event(
            dir,
            json!({"type": "error", "area": "intunecompliance", "message": "BadRequest: Request not applicable to target tenant. (HTTP 400)"}),
        );
    });
    let r = a.checks.iter().find(|c| c.id == "M365-INT-004").unwrap();
    assert_eq!(r.status, ResultStatus::NotAssessed);
    let note = r.note.as_deref().unwrap();
    assert!(note.contains("needs a Microsoft Intune licence"), "{note}");
}
