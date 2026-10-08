//! SharePoint, Teams and Purview checks against the test tenant plus the
//! areas Invoke-DCAEntra.ps1 writes for them: Graph responses, and module
//! output with only the listed properties, enums as text.

use std::path::Path;

use serde_json::{json, Value};

use super::raw::RawTenant;
use super::tests::{write_tenant, ACTIVE, ADMIN, GUEST, NOW};
use super::tests_exo::area;
use super::{analyze, TenantAnalysis};
use crate::results::tests::catalog;
use crate::results::{CheckResult, ResultStatus};

const TEAM: &str = "bbbbbbbb-0000-0000-0000-0000000000a1";
const TEAM2: &str = "bbbbbbbb-0000-0000-0000-0000000000a2";

fn site(url: &str, extra: Value) -> Value {
    let mut s = json!({"Url": format!("https://contoso.sharepoint.com/sites/{url}"), "Title": url, "Template": "GROUP#0",
                       "Owner": "admin@contoso.com", "SharingCapability": "ExternalUserSharingOnly", "DenyAddAndCustomizePages": "Enabled",
                       "SensitivityLabel": "", "GroupId": "00000000-0000-0000-0000-000000000000"});
    for (k, v) in extra.as_object().unwrap() {
        s[k] = v.clone();
    }
    s
}

fn weak(dir: &Path) {
    area(
        dir,
        "sposettings",
        &[
            json!({"sharingCapability": "externalUserAndGuestSharing", "sharingDomainRestrictionMode": "none",
                 "isLegacyAuthProtocolsEnabled": true, "idleSessionSignOut": {"isEnabled": false},
                 "isUnmanagedSyncAppForTenantRestricted": false, "isSiteCreationEnabled": true,
                 "deletedUserPersonalSiteRetentionPeriodInDays": 30}),
        ],
    );
    area(
        dir,
        "spotenant",
        &[
            json!({"SharingCapability": "ExternalUserAndGuestSharing", "OneDriveSharingCapability": "ExternalUserAndGuestSharing",
                 "DefaultSharingLinkType": "AnonymousAccess", "DefaultLinkPermission": "Edit", "RequireAnonymousLinksExpireInDays": -1,
                 "ExternalUserExpirationRequired": false, "EmailAttestationRequired": false, "ConditionalAccessPolicy": "AllowFullAccess",
                 "DisallowInfectedFileDownload": false}),
        ],
    );
    area(
        dir,
        "sposites",
        &[
            site(
                "finance",
                json!({"SharingCapability": "ExternalUserAndGuestSharing", "DenyAddAndCustomizePages": "Disabled"}),
            ),
            site("orphan", json!({"Owner": ""})),
            site("team", json!({"GroupId": TEAM})),
            site("hr", json!({})),
            json!({"Url": "https://contoso-my.sharepoint.com/personal/x", "Template": "SPSPERS#10", "Owner": ""}),
        ],
    );
    let user = |s: &str, login: &str, name: &str, admin: bool, broad: bool, kind: &str| {
        json!({"Site": format!("https://contoso.sharepoint.com/sites/{s}"), "LoginName": login, "DisplayName": name,
               "IsSiteAdmin": admin, "IsGroup": false, "UserType": kind, "Broad": broad})
    };
    area(
        dir,
        "spositeusers",
        &[
            user(
                "hr",
                "c:0-.f|rolemanager|spo-grid-all-users/11111111",
                "Everyone except external users",
                false,
                true,
                "Member",
            ),
            user("finance", "c:0(.s|true", "Everyone", false, true, "Member"),
            user(
                "finance",
                "i:0#.f|membership|admin@contoso.com",
                "Admin",
                true,
                false,
                "Member",
            ),
            user(
                "finance",
                "i:0#.f|membership|partner_fabrikam.com#ext#@contoso.onmicrosoft.com",
                "Partner",
                true,
                false,
                "Guest",
            ),
            user(
                "hr",
                "i:0#.f|membership|leaver@contoso.com",
                "Leaver",
                true,
                false,
                "Member",
            ),
        ],
    );
    area(
        dir,
        "groups",
        &[
            json!({"id": TEAM, "displayName": "Finance leadership", "resourceProvisioningOptions": ["Team"], "groupTypes": ["Unified"], "owners": [],
                   "assignedLabels": [{"displayName": "Confidential"}]}),
            json!({"id": TEAM2, "displayName": "Social club", "resourceProvisioningOptions": ["Team"], "groupTypes": ["Unified"],
                   "owners": [{"id": ADMIN}]}),
        ],
    );
    area(dir, "groupowners", &[]);
    area(
        dir,
        "teamguests",
        &[
            json!({"@dca.parent": TEAM, "@odata.count": 3, "value": [{"id": GUEST}]}),
            json!({"@dca.parent": TEAM2, "@odata.count": 2, "value": []}),
        ],
    );
    area(
        dir,
        "tmsfederation",
        &[
            json!({"AllowFederatedUsers": true, "AllowedDomains": "AllowAllKnownDomains", "AllowTeamsConsumer": true, "AllowTeamsConsumerInbound": true}),
        ],
    );
    area(
        dir,
        "tmsclient",
        &[
            json!({"Identity": "Global", "AllowGuestUser": true, "AllowEmailIntoChannel": true, "RestrictedSenderList": null,
                 "AllowDropBox": true, "AllowBox": false, "AllowGoogleDrive": true, "AllowShareFile": false, "AllowEgnyte": false}),
        ],
    );
    area(
        dir,
        "tmsmeetingconfig",
        &[json!({"Identity": "Global", "DisableAnonymousJoin": false})],
    );
    area(
        dir,
        "tmsmeeting",
        &[
            json!({"Identity": "Global", "AllowAnonymousUsersToJoinMeeting": true, "AllowAnonymousUsersToStartMeeting": true,
                 "AutoAdmittedUsers": "Everyone", "AllowPSTNUsersToBypassLobby": true, "AllowCloudRecording": true,
                 "NewMeetingRecordingExpirationDays": -1}),
        ],
    );
    area(
        dir,
        "tmsguestmeeting",
        &[json!({"ScreenSharingMode": "EntireScreen", "AllowMeetNow": true})],
    );
    area(
        dir,
        "tmsguestmessaging",
        &[json!({"AllowUserDeleteMessage": true})],
    );
    area(
        dir,
        "tmsappsetup",
        &[
            json!({"Identity": "Global", "AllowSideLoading": true}),
            json!({"Identity": "Tag:Developers", "AllowSideLoading": true}),
        ],
    );
    area(
        dir,
        "tmsapppermission",
        &[
            json!({"Identity": "Global", "GlobalCatalogAppsType": "BlockedAppList", "GlobalCatalogApps": [], "PrivateCatalogAppsType": "AllowedAppList", "PrivateCatalogApps": []}),
        ],
    );
    area(
        dir,
        "exoadminaudit",
        &[json!({"UnifiedAuditLogIngestionEnabled": false})],
    );
    area(dir, "purauditretention", &[]);
    area(
        dir,
        "purrolegroups",
        &[
            json!({"Name": "Organization Management", "Roles": ["Audit Logs", "Compliance Search"], "Members": ["Admin", "Helpdesk"]}),
            json!({"Name": "eDiscoveryManager", "Roles": ["Compliance Search", "Case Management"], "Members": ["a", "b", "c", "d", "e", "f"]}),
        ],
    );
    area(
        dir,
        "purcaseadmins",
        &[json!({"Name": "Legal Admin", "PrimarySmtpAddress": "legal@contoso.com"})],
    );
    area(dir, "pursecurityfilters", &[]);
    area(
        dir,
        "purlabels",
        &[json!({"Name": "Confidential", "Disabled": false})],
    );
    area(
        dir,
        "purlabelpolicies",
        &[
            json!({"Name": "Global", "Enabled": true, "Settings": ["[requiredowngradejustification, true]"]}),
        ],
    );
    area(
        dir,
        "purautolabel",
        &[json!({"Name": "Credit cards", "Enabled": true, "Mode": "TestWithoutNotifications"})],
    );
    area(
        dir,
        "purdlp",
        &[
            json!({"Name": "PII mail", "Enabled": true, "Mode": "Enable", "Workload": "Exchange", "WhenChangedUTC": NOW}),
            json!({"Name": "PII files", "Enabled": true, "Mode": "TestWithNotifications", "Workload": ["SharePoint", "OneDriveForBusiness"],
                   "WhenChangedUTC": "2026-01-01T00:00:00Z"}),
        ],
    );
    area(
        dir,
        "purretention",
        &[
            json!({"Name": "Mail 7 years", "Enabled": true, "ExchangeLocation": ["All"], "SharePointLocation": []}),
        ],
    );
    area(
        dir,
        "puralerts",
        &[
            json!({"Name": "Elevation of Exchange admin privilege", "Severity": "High", "Disabled": true, "IsSystemRule": true}),
            json!({"Name": "Custom", "Severity": "High", "Disabled": true, "IsSystemRule": false}),
        ],
    );
    area(dir, "purinsider", &[]);
    area(
        dir,
        "purcommunication",
        &[json!({"Name": "Harassment", "Enabled": true})],
    );
    area(dir, "purbarriers", &[]);
}

fn strong(dir: &Path) {
    area(
        dir,
        "sposettings",
        &[
            json!({"sharingCapability": "externalUserSharingOnly", "sharingDomainRestrictionMode": "allowList",
                 "isLegacyAuthProtocolsEnabled": false, "idleSessionSignOut": {"isEnabled": true, "signOutAfterInSeconds": 3600},
                 "isUnmanagedSyncAppForTenantRestricted": true, "isSiteCreationEnabled": false,
                 "deletedUserPersonalSiteRetentionPeriodInDays": 365}),
        ],
    );
    area(
        dir,
        "spotenant",
        &[
            json!({"SharingCapability": "ExternalUserSharingOnly", "OneDriveSharingCapability": "ExistingExternalUserSharingOnly",
                 "DefaultSharingLinkType": "Direct", "DefaultLinkPermission": "View", "ExternalUserExpirationRequired": true,
                 "EmailAttestationRequired": true, "ConditionalAccessPolicy": "AllowLimitedAccess", "DisallowInfectedFileDownload": true}),
        ],
    );
    area(
        dir,
        "sposites",
        &[site(
            "hr",
            json!({"SensitivityLabel": "d9f2c2b5-1111-2222-3333-444455556666"}),
        )],
    );
    area(dir, "spositeusers", &[]);
    area(
        dir,
        "tmsfederation",
        &[
            json!({"AllowFederatedUsers": true, "AllowedDomains": ["Domain=fabrikam.com"], "AllowTeamsConsumer": false}),
        ],
    );
    area(
        dir,
        "tmsclient",
        &[
            json!({"Identity": "Global", "AllowGuestUser": true, "AllowEmailIntoChannel": false, "AllowDropBox": false}),
        ],
    );
    area(
        dir,
        "tmsmeetingconfig",
        &[json!({"Identity": "Global", "DisableAnonymousJoin": true})],
    );
    area(
        dir,
        "tmsmeeting",
        &[
            json!({"Identity": "Global", "AllowAnonymousUsersToStartMeeting": false, "AutoAdmittedUsers": "EveryoneInCompanyExcludingGuests",
                 "AllowPSTNUsersToBypassLobby": false, "NewMeetingRecordingExpirationDays": 120}),
        ],
    );
    area(
        dir,
        "tmsguestmeeting",
        &[json!({"ScreenSharingMode": "SingleApplication", "AllowMeetNow": false})],
    );
    area(
        dir,
        "tmsguestmessaging",
        &[json!({"AllowUserDeleteMessage": false})],
    );
    area(
        dir,
        "tmsappsetup",
        &[json!({"Identity": "Global", "AllowSideLoading": false})],
    );
    area(
        dir,
        "tmsapppermission",
        &[
            json!({"Identity": "Global", "GlobalCatalogAppsType": "AllowedAppList", "PrivateCatalogAppsType": "AllowedAppList"}),
        ],
    );
    area(
        dir,
        "exoadminaudit",
        &[json!({"UnifiedAuditLogIngestionEnabled": true})],
    );
    area(
        dir,
        "purlabels",
        &[json!({"Name": "General", "Disabled": false})],
    );
    area(
        dir,
        "purlabelpolicies",
        &[json!({"Name": "Global", "Enabled": true, "Settings": ["[defaultlabelid, 1234]"]})],
    );
    area(
        dir,
        "purautolabel",
        &[json!({"Name": "Credit cards", "Enabled": true, "Mode": "Enable"})],
    );
    area(
        dir,
        "purdlp",
        &[
            json!({"Name": "All", "Enabled": true, "Mode": "Enable", "Workload": "Exchange, SharePoint, OneDriveForBusiness, Teams, EndpointDevices"}),
        ],
    );
    area(
        dir,
        "purretention",
        &[
            json!({"Name": "All", "Enabled": true, "ExchangeLocation": ["All"], "SharePointLocation": ["All"], "OneDriveLocation": ["All"],
                 "TeamsChannelLocation": ["All"], "TeamsChatLocation": ["All"]}),
        ],
    );
    area(
        dir,
        "purrolegroups",
        &[
            json!({"Name": "eDiscoveryManager", "Roles": ["Compliance Search"], "Members": ["Legal"]}),
        ],
    );
    area(dir, "purcaseadmins", &[]);
    area(
        dir,
        "pursecurityfilters",
        &[json!({"FilterName": "EU only"})],
    );
    area(
        dir,
        "puralerts",
        &[
            json!({"Name": "Elevation of Exchange admin privilege", "Severity": "High", "Disabled": false, "IsSystemRule": true}),
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

fn names(r: &CheckResult) -> Vec<&str> {
    let mut v: Vec<&str> = r.affected.iter().map(|a| a.name.as_str()).collect();
    v.sort_unstable();
    v
}

fn count(a: &TenantAnalysis, id: &str) -> usize {
    failed(a, id).affected.len()
}

#[test]
fn sharepoint_findings() {
    let a = run(weak);
    let r = failed(&a, "M365-SPO-001");
    assert_eq!(
        names(r),
        ["Contoso", "https://contoso.sharepoint.com/sites/finance"]
    );
    assert_eq!(count(&a, "M365-SPO-002"), 2);
    assert_eq!(count(&a, "M365-SPO-003"), 2);
    failed(&a, "M365-SPO-004");
    assert_eq!(
        names(failed(&a, "M365-SPO-005")),
        [
            "https://contoso.sharepoint.com/sites/finance",
            "https://contoso.sharepoint.com/sites/hr"
        ]
    );
    failed(&a, "M365-SPO-006");
    failed(&a, "M365-SPO-007");
    failed(&a, "M365-SPO-008");
    failed(&a, "M365-SPO-009");
    assert_eq!(count(&a, "M365-SPO-010"), 2);
    let r = failed(&a, "M365-SPO-011");
    assert_eq!(
        names(r),
        ["Leaver", "Partner"],
        "the current internal admin is fine"
    );
    assert_eq!(
        names(failed(&a, "M365-SPO-012")),
        [
            "https://contoso.sharepoint.com/sites/orphan",
            "https://contoso.sharepoint.com/sites/team"
        ],
        "personal sites are skipped; the group site has an ownerless group"
    );
    failed(&a, "M365-SPO-013");
    assert_eq!(
        names(failed(&a, "M365-SPO-014")),
        ["https://contoso.sharepoint.com/sites/finance"]
    );
    failed(&a, "M365-SPO-015");
    failed(&a, "M365-SPO-016");
    failed(&a, "M365-SPO-017");
    let r = failed(&a, "M365-SPO-018");
    assert_eq!(
        r.affected[0].name, "https://contoso.sharepoint.com/sites/finance",
        "the most overshared site comes first"
    );
}

#[test]
fn teams_findings() {
    let a = run(weak);
    failed(&a, "M365-TMS-001");
    assert_eq!(count(&a, "M365-TMS-002"), 2);
    assert_eq!(count(&a, "M365-TMS-003"), 3);
    assert_eq!(count(&a, "M365-TMS-004"), 2);
    assert_eq!(count(&a, "M365-TMS-005"), 2);
    assert_eq!(count(&a, "M365-TMS-006"), 2);
    assert_eq!(
        count(&a, "M365-TMS-007"),
        1,
        "only third-party apps are all allowed"
    );
    assert_eq!(names(failed(&a, "M365-TMS-008")), ["Finance leadership"]);
    let r = failed(&a, "M365-TMS-009");
    assert_eq!(
        names(r),
        ["Finance leadership"],
        "the social club has guests but is not sensitive"
    );
    assert!(r.affected[0]
        .reason
        .as_deref()
        .unwrap()
        .starts_with("3 guests"));
    failed(&a, "M365-TMS-010");
    assert_eq!(count(&a, "M365-TMS-011"), 2);
    failed(&a, "M365-TMS-012");
    failed(&a, "M365-TMS-013");
    let r = result(&a, "M365-TMS-014");
    assert!(r
        .found
        .as_deref()
        .unwrap()
        .contains("Teams Administrator: none"));
}

#[test]
fn purview_findings() {
    let a = run(weak);
    failed(&a, "M365-PUR-001");
    let r = result(&a, "M365-PUR-002");
    assert!(r
        .raw
        .as_deref()
        .unwrap()
        .contains("Organization Management (Audit Logs): Admin, Helpdesk"));
    assert!(failed(&a, "M365-PUR-003").affected[0]
        .reason
        .as_deref()
        .unwrap()
        .contains("default label"));
    assert_eq!(names(failed(&a, "M365-PUR-004")), ["Credit cards"]);
    assert_eq!(count(&a, "M365-PUR-005"), 4, "only Exchange is enforced");
    assert_eq!(names(failed(&a, "M365-PUR-006")), ["PII files"]);
    assert_eq!(count(&a, "M365-PUR-007"), 4);
    assert_eq!(count(&a, "M365-PUR-008"), 2);
    assert_eq!(
        names(failed(&a, "M365-PUR-012")),
        ["Elevation of Exchange admin privilege"]
    );
    assert_eq!(
        names(failed(&a, "M365-PUR-014")),
        ["Organization Management", "eDiscoveryManager"]
    );
    assert!(result(&a, "M365-PUR-010")
        .found
        .as_deref()
        .unwrap()
        .starts_with("1 of 1"));
    let _ = ACTIVE;
}

#[test]
fn well_configured_services_pass() {
    let a = run(strong);
    for id in [
        "M365-SPO-001",
        "M365-SPO-002",
        "M365-SPO-003",
        "M365-SPO-004",
        "M365-SPO-005",
        "M365-SPO-006",
        "M365-SPO-007",
        "M365-SPO-008",
        "M365-SPO-009",
        "M365-SPO-010",
        "M365-SPO-011",
        "M365-SPO-013",
        "M365-SPO-014",
        "M365-SPO-015",
        "M365-SPO-016",
        "M365-SPO-017",
        "M365-SPO-018",
        "M365-TMS-001",
        "M365-TMS-002",
        "M365-TMS-003",
        "M365-TMS-004",
        "M365-TMS-005",
        "M365-TMS-006",
        "M365-TMS-007",
        "M365-TMS-010",
        "M365-TMS-011",
        "M365-TMS-012",
        "M365-TMS-013",
        "M365-PUR-001",
        "M365-PUR-003",
        "M365-PUR-004",
        "M365-PUR-005",
        "M365-PUR-006",
        "M365-PUR-007",
        "M365-PUR-008",
        "M365-PUR-012",
        "M365-PUR-014",
    ] {
        let r = result(&a, id);
        assert_eq!(r.status, ResultStatus::Passed, "{id}: {r:?}");
    }
}

#[test]
fn modules_not_run_leave_checks_not_assessed() {
    let a = run(|_| {});
    for id in [
        "M365-SPO-002",
        "M365-SPO-014",
        "M365-TMS-001",
        "M365-TMS-009",
        "M365-PUR-005",
        "M365-PUR-012",
    ] {
        assert_eq!(result(&a, id).status, ResultStatus::NotAssessed, "{id}");
    }
}
