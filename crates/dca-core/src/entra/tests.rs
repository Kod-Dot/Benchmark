//! End-to-end tests of the Entra analysis against a small tenant written in
//! the Graph collector's own format.

use std::fs;
use std::path::Path;

use serde_json::{json, Value};

use super::model::{APP_ADMIN, GLOBAL_ADMIN};
use super::raw::RawTenant;
use super::{all_rules, analyze, TenantAnalysis};
use crate::catalog::Severity;
use crate::results::tests::catalog;
use crate::results::{CheckResult, ResultStatus};
use crate::time;

pub(crate) const TENANT: &str = "11111111-2222-3333-4444-555555555555";
pub(crate) const NOW: &str = "2026-10-06T09:00:00Z";
pub(crate) const ADMIN: &str = "aaaaaaaa-0000-0000-0000-000000000001";
pub(crate) const GUEST: &str = "aaaaaaaa-0000-0000-0000-000000000002";
pub(crate) const STALE: &str = "aaaaaaaa-0000-0000-0000-000000000003";
pub(crate) const ACTIVE: &str = "aaaaaaaa-0000-0000-0000-000000000004";
const ROLE_GROUP: &str = "bbbbbbbb-0000-0000-0000-000000000001";
pub(crate) const APP_SP: &str = "cccccccc-0000-0000-0000-000000000001";

fn days_ago(days: i64) -> String {
    time::iso(time::parse_iso(NOW).unwrap() - days * time::DAY)
}

fn page(items: Vec<Value>) -> Value {
    json!({"@odata.context": "https://graph.microsoft.com/v1.0/$metadata", "value": items})
}

fn user(id: &str, upn: &str, kind: &str, signin_days: Option<i64>) -> Value {
    let mut u = json!({
        "id": id,
        "userPrincipalName": upn,
        "displayName": upn.split('@').next().unwrap(),
        "userType": kind,
        "accountEnabled": true,
        "createdDateTime": days_ago(400),
    });
    if let Some(d) = signin_days {
        u["signInActivity"] = json!({"lastSignInDateTime": days_ago(d)});
    }
    u
}

fn ca(name: &str, state: &str, clients: &[&str], grant: &str) -> Value {
    json!({
        "id": format!("ca-{name}"),
        "displayName": name,
        "state": state,
        "conditions": {
            "users": {"includeUsers": ["All"], "excludeUsers": []},
            "applications": {"includeApplications": ["All"]},
            "clientAppTypes": clients,
        },
        "grantControls": {"operator": "OR", "builtInControls": [grant]},
    })
}

/// Writes the tenant the way Invoke-DCAEntra.ps1 does. `riskyusers` is not
/// collected and `roleschedules` fails, as on a tenant without P2.
pub(crate) fn write_tenant(dir: &Path) {
    fs::write(
        dir.join("collection.json"),
        json!({
            "tenant": "contoso.onmicrosoft.com",
            "tenant_id": TENANT,
            "account": "auditor@contoso.com",
            "client_id": "14d82eec-204b-4c2f-b7e8-296a70dab67e",
            "computer": "AUDIT01",
            "started_at": days_ago(0),
            "sources": ["graph"],
            "scopes": ["Directory.Read.All"],
        })
        .to_string(),
    )
    .unwrap();

    let areas: Vec<(&str, Vec<Value>)> = vec![
        (
            "organization",
            vec![page(vec![json!({
                "id": TENANT,
                "displayName": "Contoso",
                "onPremisesSyncEnabled": false,
                "technicalNotificationMails": ["it@contoso.com"],
            })])],
        ),
        (
            "skus",
            vec![page(vec![json!({
                "skuPartNumber": "AAD_PREMIUM",
                "capabilityStatus": "Enabled",
                "servicePlans": [{"servicePlanName": "AAD_PREMIUM"}],
            })])],
        ),
        (
            "domains",
            vec![page(vec![
                json!({"id": "contoso.com", "isVerified": true, "authenticationType": "Managed"}),
                json!({"id": "fed.contoso.com", "isVerified": true, "authenticationType": "Federated"}),
            ])],
        ),
        (
            "users",
            vec![page(vec![
                user(ADMIN, "admin@contoso.com", "Member", Some(2)),
                user(
                    GUEST,
                    "partner_fabrikam.com#EXT#@contoso.onmicrosoft.com",
                    "Guest",
                    Some(5),
                ),
                user(STALE, "old@contoso.com", "Member", Some(200)),
                user(ACTIVE, "worker@contoso.com", "Member", Some(1)),
            ])],
        ),
        (
            "groups",
            vec![page(vec![json!({
                "id": ROLE_GROUP,
                "displayName": "Tenant admins",
                "isAssignableToRole": true,
                "securityEnabled": true,
                "groupTypes": [],
                "owners": [{"@odata.type": "#microsoft.graph.user", "id": ADMIN}],
            })])],
        ),
        (
            "rolegroupmembers",
            vec![json!({
                "@dca.parent": ROLE_GROUP,
                "value": [{"@odata.type": "#microsoft.graph.user", "id": GUEST, "userPrincipalName": "partner_fabrikam.com#EXT#@contoso.onmicrosoft.com"}],
            })],
        ),
        (
            "roledefinitions",
            vec![page(vec![
                json!({"id": GLOBAL_ADMIN, "templateId": GLOBAL_ADMIN, "displayName": "Global Administrator", "isBuiltIn": true}),
                json!({"id": APP_ADMIN, "templateId": APP_ADMIN, "displayName": "Application Administrator", "isBuiltIn": true}),
            ])],
        ),
        (
            "roleassignments",
            vec![page(vec![
                json!({"principalId": ADMIN, "roleDefinitionId": GLOBAL_ADMIN, "directoryScopeId": "/",
                       "principal": {"@odata.type": "#microsoft.graph.user", "id": ADMIN}}),
                json!({"principalId": ROLE_GROUP, "roleDefinitionId": GLOBAL_ADMIN, "directoryScopeId": "/",
                       "principal": {"@odata.type": "#microsoft.graph.group", "id": ROLE_GROUP}}),
                json!({"principalId": APP_SP, "roleDefinitionId": APP_ADMIN, "directoryScopeId": "/",
                       "principal": {"@odata.type": "#microsoft.graph.servicePrincipal", "id": APP_SP}}),
            ])],
        ),
        (
            "capolicies",
            vec![page(vec![
                ca(
                    "Require MFA for everyone",
                    "enabledForReportingButNotEnforced",
                    &["all"],
                    "mfa",
                ),
                ca(
                    "Block legacy authentication",
                    "enabled",
                    &["exchangeActiveSync", "other"],
                    "block",
                ),
            ])],
        ),
        (
            "securitydefaults",
            vec![json!({"id": "00000000-0000-0000-0000-000000000000", "isEnabled": false})],
        ),
        (
            "authorization",
            vec![json!({
                "id": "authorizationPolicy",
                "defaultUserRolePermissions": {"allowedToCreateApps": true, "allowedToCreateTenants": false},
            })],
        ),
        (
            "registration",
            vec![page(vec![
                json!({"id": ADMIN, "userPrincipalName": "admin@contoso.com", "userType": "member", "isMfaRegistered": false, "methodsRegistered": []}),
                json!({"id": ACTIVE, "userPrincipalName": "worker@contoso.com", "userType": "member", "isMfaRegistered": true, "methodsRegistered": ["microsoftAuthenticatorPush"]}),
            ])],
        ),
        (
            "serviceprincipals",
            vec![page(vec![json!({
                "id": APP_SP,
                "appId": "dddddddd-0000-0000-0000-000000000001",
                "displayName": "Provisioning connector",
                "servicePrincipalType": "Application",
                "appOwnerOrganizationId": TENANT,
                "accountEnabled": true,
                "owners": [],
            })])],
        ),
    ];

    let mut events = Vec::new();
    for (area, pages) in &areas {
        let lines: Vec<String> = pages.iter().map(Value::to_string).collect();
        fs::write(dir.join(format!("{area}.jsonl")), lines.join("\n") + "\n").unwrap();
        let count: usize = pages
            .iter()
            .map(|p| p["value"].as_array().map_or(1, Vec::len))
            .sum();
        events.push(json!({"type": "done", "area": area, "count": count}));
    }
    events.push(json!({"type": "done", "area": "signinactivity", "count": 4}));
    events.push(json!({"type": "error", "area": "roleschedules", "message": "403 Forbidden: the tenant needs Entra ID P2"}));
    events.push(json!({"type": "finished", "finished_at": NOW}));
    let lines: Vec<String> = events.iter().map(Value::to_string).collect();
    fs::write(dir.join("events.jsonl"), lines.join("\n") + "\n").unwrap();
}

fn run() -> TenantAnalysis {
    let dir = tempfile::tempdir().unwrap();
    write_tenant(dir.path());
    let raw = RawTenant::load(dir.path()).unwrap();
    analyze(&catalog(), &raw, &[])
}

fn result<'a>(a: &'a TenantAnalysis, id: &str) -> &'a CheckResult {
    a.checks
        .iter()
        .find(|c| c.id == id)
        .unwrap_or_else(|| panic!("{id} did not run"))
}

fn affected(r: &CheckResult) -> Vec<&str> {
    r.affected.iter().map(|a| a.name.as_str()).collect()
}

#[test]
fn every_rule_is_in_the_catalog() {
    let catalog = catalog();
    for r in all_rules() {
        assert!(
            catalog.check(r.id).is_some(),
            "{} is not in the catalog",
            r.id
        );
    }
}

#[test]
fn roles_held_through_groups_count() {
    let a = run();
    let ga = result(&a, "EN-PRIV-001");
    assert_eq!(ga.status, ResultStatus::Passed, "{ga:?}");
    assert_eq!(ga.affected_count, Some(2));

    let guests = result(&a, "EN-ID-003");
    assert_eq!(guests.status, ResultStatus::Failed);
    assert_eq!(
        affected(guests),
        ["partner_fabrikam.com#EXT#@contoso.onmicrosoft.com"]
    );
    assert!(guests.affected[0]
        .reason
        .as_deref()
        .unwrap()
        .contains("through Tenant admins"));

    // Without PIM schedules every active assignment counts as permanent.
    let permanent = result(&a, "EN-PRIV-002");
    assert_eq!(permanent.affected_count, Some(3));
    assert!(permanent.evidence.iter().any(|e| e.label == "Note"));

    let apps = result(&a, "EN-PRIV-006");
    assert_eq!(affected(apps), ["Provisioning connector"]);
}

#[test]
fn conditional_access_report_only_does_not_count() {
    let a = run();
    let mfa = result(&a, "EN-CA-002");
    assert_eq!(mfa.status, ResultStatus::Failed);
    assert!(mfa
        .evidence
        .iter()
        .any(|e| e.label.starts_with("Report-only") && e.value == "Require MFA for everyone"));
    assert_eq!(result(&a, "EN-CA-004").status, ResultStatus::Passed);
    assert_eq!(result(&a, "EN-TEN-002").status, ResultStatus::Failed);
}

#[test]
fn tenant_settings_and_accounts() {
    let a = run();
    assert_eq!(result(&a, "EN-TEN-003").status, ResultStatus::Failed);
    assert_eq!(result(&a, "EN-TEN-004").status, ResultStatus::Passed);
    assert_eq!(affected(result(&a, "EN-TEN-018")), ["fed.contoso.com"]);
    assert_eq!(affected(result(&a, "EN-ID-001")), ["old@contoso.com"]);

    // An admin without MFA raises the severity.
    let mfa = result(&a, "EN-AUTH-001");
    assert_eq!(affected(mfa), ["admin@contoso.com"]);
    assert_eq!(mfa.severity, Some(Severity::Critical));
}

#[test]
fn unread_areas_are_not_assessed() {
    let a = run();
    let risky = result(&a, "EN-ID-012");
    assert_eq!(risky.status, ResultStatus::NotAssessed);
    assert!(risky.note.as_deref().unwrap().contains("was not collected"));
    // Areas that were read never produce "not collected" notes.
    for c in &a.checks {
        if let Some(note) = &c.note {
            assert!(!note.starts_with("Users "), "{}: {note}", c.id);
        }
    }
}

#[test]
fn directory_view_links_roles_and_groups() {
    let a = run();
    let d = &a.directory;
    assert_eq!(d.sources[0].kind, "cloud");
    assert_eq!(d.sources[0].name, "Contoso");
    let ids: Vec<&str> = d.objects.iter().map(|o| o.id.as_str()).collect();
    for e in &d.edges {
        assert!(
            ids.contains(&e.from.as_str()) && ids.contains(&e.to.as_str()),
            "{e:?}"
        );
    }
    let ga = format!("{TENANT}:role:{GLOBAL_ADMIN}");
    let has = |from: &str, kind: &str, to: &str| {
        d.edges
            .iter()
            .any(|e| e.from == from && e.kind == kind && e.to == to)
    };
    assert!(has(ADMIN, "HasRole", &ga));
    assert!(has(ROLE_GROUP, "HasRole", &ga));
    assert!(has(GUEST, "MemberOf", ROLE_GROUP));
    assert!(has(ADMIN, "Owns", ROLE_GROUP));
    assert!(d.objects.iter().find(|o| o.id == GUEST).unwrap().tier0);
    assert!(!d.objects.iter().find(|o| o.id == STALE).unwrap().tier0);
}

#[test]
fn entra_only_assessment_analyzes() {
    use crate::analysis::{self, NewAssessment};

    let root = tempfile::tempdir().unwrap();
    let spec = NewAssessment {
        name: None,
        domains: Vec::new(),
        tenant: Some("contoso.onmicrosoft.com".into()),
        areas: Vec::new(),
    };
    let dir = analysis::create(root.path(), spec, time::parse_iso(NOW).unwrap()).unwrap();
    let raw = analysis::entra_raw_dir(&dir, "contoso.onmicrosoft.com");
    fs::create_dir_all(&raw).unwrap();
    write_tenant(&raw);

    let manifest = analysis::analyze(&dir, &catalog()).unwrap();
    assert_eq!(manifest.finished_at.as_deref(), Some(NOW));
    assert!(manifest.score.is_some());
    let a = crate::results::Assessment::load(&dir).unwrap();
    assert!(a.results.checks.iter().any(|c| c.id == "EN-PRIV-001"));
    assert_eq!(a.directory.unwrap().sources[0].kind, "cloud");
}

/// Adds 30 days of sign-in and audit logs to the test tenant.
fn write_logs(dir: &Path) {
    let at = |minutes: i64| time::iso(time::parse_iso(NOW).unwrap() - 86_400 + minutes * 60);
    let signin = |upn: &str, code: i64, client: &str, ip: &str, minutes: i64| {
        json!({"userPrincipalName": upn, "userId": null, "clientAppUsed": client, "appDisplayName": "Office 365 Exchange Online",
               "ipAddress": ip, "createdDateTime": at(minutes), "status": {"errorCode": code},
               "location": {"countryOrRegion": "NL"}})
    };
    let mut legacy = vec![signin("worker@contoso.com", 0, "IMAP4", "203.0.113.5", 0)];
    legacy[0]["userId"] = json!(ACTIVE);
    legacy.push(signin(
        "old@contoso.com",
        50126,
        "Authenticated SMTP",
        "203.0.113.9",
        5,
    ));
    // A spray: one address, twelve accounts, one attempt each. Plus an MFA
    // fatigue run: six denied prompts in 30 minutes.
    let mut failed: Vec<Value> = (0..12)
        .map(|i| {
            signin(
                &format!("user{i}@contoso.com"),
                50126,
                "Browser",
                "198.51.100.7",
                i,
            )
        })
        .collect();
    failed.extend((0..6).map(|i| {
        signin(
            "admin@contoso.com",
            500121,
            "Browser",
            "192.0.2.4",
            100 + i * 5,
        )
    }));
    let device = vec![signin(
        "worker@contoso.com",
        0,
        "Mobile Apps and Desktop clients",
        "203.0.113.5",
        300,
    )];
    let audit = |activity: &str, target: Value, app: Option<&str>, minutes: i64| {
        let initiated = match app {
            Some(a) => json!({"app": {"displayName": a}}),
            None => json!({"user": {"userPrincipalName": "admin@contoso.com"}}),
        };
        json!({"activityDisplayName": activity, "activityDateTime": at(minutes), "initiatedBy": initiated, "targetResources": [target]})
    };
    let audits = vec![
        audit(
            "Add member to role",
            json!({"id": STALE, "userPrincipalName": "old@contoso.com",
                   "modifiedProperties": [{"displayName": "Role.DisplayName", "newValue": "\"Global Administrator\""}]}),
            None,
            10,
        ),
        audit(
            "Add member to role",
            json!({"id": ACTIVE, "userPrincipalName": "worker@contoso.com"}),
            Some("MS-PIM"),
            20,
        ),
        audit(
            "Update application – Certificates and secrets management ",
            json!({"displayName": "Payroll"}),
            None,
            30,
        ),
        audit(
            "Update conditional access policy",
            json!({"displayName": "Require MFA for everyone"}),
            None,
            40,
        ),
        audit(
            "Consent to application",
            json!({"displayName": "Mail Reader", "modifiedProperties": [{"displayName": "ConsentContext.IsAdminConsent", "newValue": "\"True\""}]}),
            None,
            50,
        ),
    ];
    let invites: Vec<Value> = (0..21)
        .map(|i| {
            audit(
                "Invite external user",
                json!({"displayName": format!("guest{i}")}),
                None,
                i,
            )
        })
        .collect();

    let mut events = fs::read_to_string(dir.join("events.jsonl")).unwrap();
    for (area, items) in [
        ("signinslegacy", legacy),
        ("signinsfailed", failed),
        ("signinsdevicecode", device),
        ("audits", audits),
        ("invites", invites),
    ] {
        events = format!(
            "{}\n{events}",
            json!({"type": "done", "area": area, "count": items.len()})
        );
        fs::write(
            dir.join(format!("{area}.jsonl")),
            format!("{}\n", page(items)),
        )
        .unwrap();
    }
    fs::write(dir.join("events.jsonl"), events).unwrap();
}

#[test]
fn log_patterns_are_found() {
    let dir = tempfile::tempdir().unwrap();
    write_tenant(dir.path());
    write_logs(dir.path());
    let raw = RawTenant::load(dir.path()).unwrap();
    let a = analyze(&catalog(), &raw, &[]);

    assert_eq!(affected(result(&a, "EN-ID-011")), ["worker@contoso.com"]);
    assert_eq!(affected(result(&a, "EN-MON-006")), ["IMAP4"]);
    assert_eq!(affected(result(&a, "HUNT-EN-003")), ["198.51.100.7"]);
    assert!(result(&a, "HUNT-EN-003").affected[0]
        .last_seen
        .as_deref()
        .is_some_and(|t| t.starts_with("20")));
    assert_eq!(affected(result(&a, "HUNT-EN-004")), ["admin@contoso.com"]);
    assert_eq!(affected(result(&a, "HUNT-EN-012")), ["worker@contoso.com"]);
    // The PIM activation is not a direct assignment.
    let direct = result(&a, "HUNT-EN-008");
    assert_eq!(affected(direct), ["old@contoso.com"]);
    assert!(direct.affected[0]
        .reason
        .as_deref()
        .unwrap()
        .contains("Global Administrator"));
    assert_eq!(affected(result(&a, "HUNT-EN-005")), ["Payroll"]);
    assert_eq!(
        affected(result(&a, "HUNT-EN-009")),
        ["Require MFA for everyone"]
    );
    let consent = result(&a, "HUNT-EN-007");
    assert!(consent.affected[0]
        .reason
        .as_deref()
        .unwrap()
        .starts_with("Admin consent"));
    assert_eq!(affected(result(&a, "HUNT-EN-014")), ["admin@contoso.com"]);
    assert_eq!(result(&a, "HUNT-EN-006").status, ResultStatus::Passed);
    assert_eq!(result(&a, "EN-MON-010").status, ResultStatus::Passed);
}

#[test]
fn logs_not_collected_are_not_assessed() {
    let a = run();
    let r = result(&a, "HUNT-EN-003");
    assert_eq!(r.status, ResultStatus::NotAssessed);
    assert!(r.note.as_deref().unwrap().contains("needs Entra ID P1"));
}

/// Runs in CI when a test tenant is configured: the cloud collector signs in
/// as an app and reads a real Microsoft 365 / Entra tenant, and the analysis
/// must understand every area it returned. Areas the tenant cannot provide
/// (no licence, no consent) are reported, not failed.
#[test]
#[ignore]
fn live_tenant_is_understood() {
    let Some(dir) = std::env::var_os("DCA_TENANT_DIR") else {
        panic!("set DCA_TENANT_DIR to the folder Invoke-DCAEntra.ps1 wrote");
    };
    let raw = RawTenant::load(Path::new(&dir)).expect("the tenant collection loads");
    let out = analyze(&catalog(), &raw, &[]);
    for (area, state) in &raw.areas {
        println!("area {area:<24} {state:?}");
    }
    let mut problems = Vec::new();
    let mut assessed = 0;
    for c in &out.checks {
        if c.status != ResultStatus::NotAssessed {
            assessed += 1;
        }
        println!(
            "{:<14} {:?}  {}",
            c.id,
            c.status,
            c.note.as_deref().or(c.found.as_deref()).unwrap_or_default()
        );
        let texts = c
            .note
            .iter()
            .chain(c.evidence.iter().map(|e| &e.value))
            .chain(c.affected.iter().filter_map(|a| a.reason.as_ref()));
        for t in texts {
            if t.contains("was not returned") || t.contains("could not be parsed") {
                problems.push(format!("{}: {t}", c.id));
            }
        }
    }
    assert!(
        assessed > 0,
        "no cloud check was assessed on the live tenant"
    );
    assert!(
        problems.is_empty(),
        "parts the analysis did not understand:\n{}",
        problems.join("\n")
    );
}
