//! The checks in rules_exo2.rs against the test tenant plus Exchange Online
//! areas as the module writes them (listed properties, values as text).

use std::path::Path;

use serde_json::json;

use super::raw::RawTenant;
use super::tests::{write_tenant, ADMIN};
use super::tests_exo::area;
use super::{analyze, TenantAnalysis};
use crate::results::tests::catalog;
use crate::results::{CheckResult, ResultStatus};

fn weak(dir: &Path) {
    area(
        dir,
        "exoaccepteddomains",
        &[json!({"DomainName": "contoso.com"})],
    );
    area(
        dir,
        "exoinboxrules",
        &[
            json!({"MailboxOwnerId": "worker", "Name": ".", "Enabled": true, "ForwardTo": ["\"Box\" [SMTP:drop@evil.example]"], "DeleteMessage": false}),
            json!({"MailboxOwnerId": "old", "Name": "Hide invoices", "Enabled": true, "MoveToFolder": "old@contoso.com:\\RSS Feeds", "MarkAsRead": true}),
            json!({"MailboxOwnerId": "admin", "Name": "To my team", "Enabled": true, "RedirectTo": ["\"Team\" [SMTP:team@contoso.com]"]}),
            json!({"MailboxOwnerId": "admin", "Name": "Off", "Enabled": false, "DeleteMessage": true}),
        ],
    );
    let full = |id: &str, user: &str| json!({"Identity": id, "User": user, "AccessRights": ["FullAccess"]});
    let mut fa = vec![
        full("admin@contoso.com", "worker@contoso.com"),
        full(
            "finance@contoso.com",
            "partner_fabrikam.com#EXT#@contoso.onmicrosoft.com",
        ),
    ];
    fa.extend((0..10).map(|i| full(&format!("box{i}@contoso.com"), "assistant@contoso.com")));
    area(dir, "exofullaccess", &fa);
    area(
        dir,
        "exosendas",
        &[
            json!({"Identity": "admin@contoso.com", "Trustee": "pa@contoso.com", "AccessRights": ["SendAs"]}),
        ],
    );
    area(
        dir,
        "exomailboxes",
        &[
            json!({"UserPrincipalName": "ceo@contoso.com", "GrantSendOnBehalfTo": ["guest#EXT#@contoso.onmicrosoft.com"]}),
        ],
    );
    area(
        dir,
        "exoquarantine",
        &[
            json!({"Name": "Custom release", "EndUserQuarantinePermissions": "PermissionToViewHeader: False, PermissionToRelease: True, PermissionToPreview: True"}),
        ],
    );
    area(
        dir,
        "exocontentfilter",
        &[
            json!({"Name": "Default", "HighConfidencePhishQuarantineTag": "DefaultFullAccessPolicy"}),
        ],
    );
    area(
        dir,
        "exomalware",
        &[json!({"Name": "Default", "QuarantineTag": "Custom release"})],
    );
    area(
        dir,
        "exodistgroups",
        &[
            json!({"Name": "Finance approvers", "GroupType": "Universal, SecurityEnabled", "MemberJoinRestriction": "Open"}),
            json!({"Name": "Newsletter", "GroupType": "Universal", "MemberJoinRestriction": "Open"}),
            json!({"Name": "Admins", "GroupType": "Universal, SecurityEnabled", "MemberJoinRestriction": "Closed"}),
        ],
    );
    area(
        dir,
        "riskdetections",
        &[
            json!({"userPrincipalName": "worker@contoso.com", "detectedDateTime": "2026-10-01T08:00:00Z", "riskEventType": "unfamiliarFeatures"}),
        ],
    );
    area(
        dir,
        "exoualinbox",
        &[
            json!({"UserIds": "worker@contoso.com", "Operations": "New-InboxRule", "CreationDate": "10/01/2026 10:30:00"}),
            json!({"UserIds": "worker@contoso.com", "Operations": "Set-InboxRule", "CreationDate": "2026-09-20T10:30:00Z"}),
            json!({"UserIds": "admin@contoso.com", "Operations": "New-InboxRule", "CreationDate": "2026-10-01T09:00:00Z"}),
        ],
    );
    area(
        dir,
        "exoualfiles",
        &[
            json!({"UserIds": "leaver@contoso.com", "Day": "2026-10-02", "Operation": "FileSyncDownloadedFull", "Count": 2400}),
            json!({"UserIds": "worker@contoso.com", "Day": "2026-10-02", "Operation": "FileDownloaded", "Count": 40}),
            json!({"UserIds": "sales@contoso.com", "Day": "2026-10-03", "Operation": "AnonymousLinkCreated", "Count": 35}),
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

fn failed<'a>(a: &'a TenantAnalysis, id: &str) -> &'a CheckResult {
    let r = a
        .checks
        .iter()
        .find(|c| c.id == id)
        .unwrap_or_else(|| panic!("{id} did not run"));
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
fn exchange_findings() {
    let a = run(weak);
    assert_eq!(
        lines(failed(&a, "M365-EXO-006")),
        [
            ".: Inbox rule forwards to drop@evil.example; has a name made of symbols only",
            "Hide invoices: Inbox rule moves mail to old@contoso.com:\\RSS Feeds out of sight",
        ],
        "internal redirects and disabled rules are fine"
    );
    let r = failed(&a, "M365-EXO-009");
    let l = lines(r);
    assert!(
        l.iter().any(|x| x.starts_with(
            "worker@contoso.com → admin@contoso.com: Full Access: on the mailbox of an admin"
        )),
        "{l:?}"
    );
    assert!(l
        .iter()
        .any(|x| x.contains("partner_fabrikam") && x.contains("an external guest")));
    assert_eq!(
        l.iter().filter(|x| x.starts_with("assistant@")).count(),
        10,
        "each of the ten mailboxes is listed"
    );
    assert!(l
        .iter()
        .any(|x| x.starts_with("pa@contoso.com → admin@contoso.com: Send As: on the mailbox")));
    assert!(l
        .iter()
        .any(|x| x.contains("Send on Behalf: an external guest")));
    assert_eq!(lines(failed(&a, "M365-EXO-027")).len(), 2);
    assert_eq!(failed(&a, "EN-GRP-008").affected.len(), 1);
    let h = failed(&a, "HUNT-EN-010");
    assert_eq!(
        lines(h),
        ["worker@contoso.com: New-InboxRule 2 hours after a risk detection"]
    );
    assert_eq!(lines(failed(&a, "HUNT-EN-011")).len(), 2);
    let _ = ADMIN;
}

#[test]
fn exchange_areas_not_read_are_not_assessed() {
    let a = run(|_| {});
    for id in [
        "M365-EXO-006",
        "M365-EXO-009",
        "M365-EXO-027",
        "EN-GRP-008",
        "HUNT-EN-010",
        "HUNT-EN-011",
    ] {
        let r = a.checks.iter().find(|c| c.id == id).unwrap();
        assert_eq!(r.status, ResultStatus::NotAssessed, "{id}");
    }
}
