//! Exchange Online rules against the test tenant plus Exchange Online areas
//! written the way Invoke-DCAEntra.ps1 writes them: one object per line.

use std::fs;
use std::io::Write;
use std::path::Path;

use serde_json::{json, Value};

use super::raw::RawTenant;
use super::tests::{write_tenant, ACTIVE, ADMIN, APP_SP, TENANT};
use super::{analyze, TenantAnalysis};
use crate::results::tests::catalog;
use crate::results::{CheckResult, ResultStatus};

pub(super) fn area(dir: &Path, name: &str, items: &[Value]) {
    let lines: Vec<String> = items.iter().map(Value::to_string).collect();
    fs::write(dir.join(format!("{name}.jsonl")), lines.join("\n") + "\n").unwrap();
    event(
        dir,
        json!({"type": "done", "area": name, "count": items.len()}),
    );
}

pub(crate) fn event(dir: &Path, e: Value) {
    let mut f = fs::OpenOptions::new()
        .append(true)
        .open(dir.join("events.jsonl"))
        .unwrap();
    writeln!(f, "{e}").unwrap();
}

fn mailbox(name: &str, id: &str, kind: &str, extra: Value) -> Value {
    let mut m = json!({
        "DisplayName": name,
        "UserPrincipalName": format!("{name}@contoso.com"),
        "PrimarySmtpAddress": format!("{name}@contoso.com"),
        "RecipientTypeDetails": kind,
        "ExternalDirectoryObjectId": id,
        "ForwardingSmtpAddress": null,
        "DeliverToMailboxAndForward": false,
        "LitigationHoldEnabled": false,
    });
    for (k, v) in extra.as_object().unwrap() {
        m[k] = v.clone();
    }
    m
}

fn write_exo(dir: &Path) {
    // Mail.Read for the test app, from the Graph resource.
    area(
        dir,
        "resources",
        &[
            json!({"id": "graph-sp", "appId": "00000003-0000-0000-c000-000000000000",
                 "appRoles": [{"id": "role-mail-read", "value": "Mail.Read"}]}),
        ],
    );
    area(
        dir,
        "approleassignments",
        &[
            json!({"principalType": "ServicePrincipal", "principalId": APP_SP, "appRoleId": "role-mail-read", "resourceId": "graph-sp"}),
        ],
    );
    area(
        dir,
        "exoorg",
        &[
            json!({"OAuth2ClientProfileEnabled": true, "AuditDisabled": false, "CustomerLockBoxEnabled": false}),
        ],
    );
    area(
        dir,
        "exotransport",
        &[json!({"SmtpClientAuthenticationDisabled": true})],
    );
    area(
        dir,
        "exoadminaudit",
        &[json!({"UnifiedAuditLogIngestionEnabled": true})],
    );
    area(
        dir,
        "exoaccepteddomains",
        &[
            json!({"DomainName": "contoso.com", "DomainType": "Authoritative", "Default": true}),
            json!({"DomainName": "contoso.onmicrosoft.com", "DomainType": "Authoritative", "Default": false}),
            json!({"DomainName": "fabrikam.com", "DomainType": "Authoritative", "Default": false}),
        ],
    );
    area(
        dir,
        "exomailboxes",
        &[
            mailbox(
                "admin",
                ADMIN,
                "UserMailbox",
                json!({"LitigationHoldEnabled": true}),
            ),
            mailbox(
                "worker",
                ACTIVE,
                "UserMailbox",
                json!({"ForwardingSmtpAddress": "smtp:someone@gmail.com"}),
            ),
            mailbox(
                "sales",
                "aaaaaaaa-0000-0000-0000-000000000003",
                "SharedMailbox",
                json!({"ForwardingSmtpAddress": "smtp:team@fabrikam.com"}),
            ),
        ],
    );
    area(
        dir,
        "exocas",
        &[
            json!({"PrimarySmtpAddress": "admin@contoso.com", "PopEnabled": false, "ImapEnabled": false,
                   "ActiveSyncEnabled": true, "EwsEnabled": true, "SmtpClientAuthenticationDisabled": null}),
            json!({"PrimarySmtpAddress": "worker@contoso.com", "PopEnabled": true, "ImapEnabled": false,
                   "ActiveSyncEnabled": true, "EwsEnabled": true, "SmtpClientAuthenticationDisabled": false}),
        ],
    );
    area(
        dir,
        "exoauditbypass",
        &[json!({"Name": "svc-archive", "AuditBypassEnabled": true})],
    );
    area(
        dir,
        "exoremotedomains",
        &[json!({"Name": "Default", "DomainName": "*", "AutoForwardEnabled": true})],
    );
    area(
        dir,
        "exooutboundspam",
        &[
            json!({"Name": "Default", "IsDefault": true, "AutoForwardingMode": "Automatic"}),
            json!({"Name": "Executives", "IsDefault": false, "AutoForwardingMode": "On"}),
        ],
    );
    area(
        dir,
        "exooutboundspamrules",
        &[
            json!({"Name": "Executives", "State": "Enabled", "HostedOutboundSpamFilterPolicy": "Executives"}),
        ],
    );
    area(dir, "exoappaccess", &[]);
    area(
        dir,
        "exoimpersonation",
        &[
            json!({"Name": "ApplicationImpersonation-svc", "RoleAssigneeName": "svc-migration", "RoleAssigneeType": "User", "Enabled": true, "CustomRecipientWriteScope": null}),
        ],
    );
    area(
        dir,
        "exorolegroups",
        &[
            json!({"Name": "Organization Management", "Members": ["TenantAdmins_-1785523426", "ExchangeServiceAdmins_-1532434893", "jdoe"]}),
            json!({"Name": "View-Only Organization Management", "Members": ["auditor"]}),
        ],
    );
    area(
        dir,
        "exoantiphish",
        &[
            json!({"Name": "Office365 AntiPhish Default", "IsDefault": true, "Enabled": true, "EnableSpoofIntelligence": true,
                 "EnableMailboxIntelligence": true, "EnableMailboxIntelligenceProtection": false,
                 "EnableTargetedUserProtection": false, "EnableOrganizationDomainsProtection": false}),
        ],
    );
    area(dir, "exoantiphishrules", &[]);
    event(
        dir,
        json!({"type": "error", "area": "exosafelinks", "message": "The term 'Get-SafeLinksPolicy' is not recognized"}),
    );
    area(dir, "exosafelinksrules", &[]);
    area(
        dir,
        "exomalware",
        &[
            json!({"Name": "Default", "IsDefault": true, "EnableFileFilter": true, "ZapEnabled": true}),
        ],
    );
    area(dir, "exomalwarerules", &[]);
    area(
        dir,
        "exocontentfilter",
        &[
            json!({"Name": "Default", "IsDefault": true, "BulkThreshold": 7, "AllowedSenders": [], "AllowedSenderDomains": []}),
            json!({"Name": "Partners", "IsDefault": false, "BulkThreshold": 6, "AllowedSenders": [], "AllowedSenderDomains": ["contoso.com", "gmail.com", "partner.example"]}),
            json!({"Name": "Unused", "IsDefault": false, "BulkThreshold": 9, "AllowedSenders": [], "AllowedSenderDomains": ["gmail.com"]}),
        ],
    );
    area(
        dir,
        "exocontentfilterrules",
        &[
            json!({"Name": "Partners", "State": "Enabled", "HostedContentFilterPolicy": "Partners"}),
            json!({"Name": "Unused", "State": "Disabled", "HostedContentFilterPolicy": "Unused"}),
        ],
    );
    area(
        dir,
        "exotransportrules",
        &[
            json!({"Name": "Skip filtering for scanner", "State": "Enabled", "Priority": 0, "SetSCL": -1}),
            json!({"Name": "Copy CFO mail", "State": "Enabled", "Priority": 1, "BlindCopyTo": ["archive@outside.example"]}),
            json!({"Name": "Disclaimer", "State": "Enabled", "Priority": 2}),
            json!({"Name": "Old bypass", "State": "Disabled", "Priority": 3, "SetSCL": -1}),
        ],
    );
    area(
        dir,
        "exoinbound",
        &[
            json!({"Name": "Scanner", "Enabled": true, "ConnectorType": "OnPremises", "RequireTls": false, "SenderIPAddresses": ["203.0.113.5"]}),
        ],
    );
    area(
        dir,
        "exooutbound",
        &[
            json!({"Name": "Relay", "Enabled": true, "ConnectorType": "Partner", "UseMXRecord": false, "SmartHosts": ["relay.example.net"], "TlsSettings": null}),
        ],
    );
    area(
        dir,
        "exodkim",
        &[
            json!({"Domain": "contoso.com", "Enabled": true}),
            json!({"Domain": "fabrikam.com", "Enabled": false}),
        ],
    );
    area(
        dir,
        "exodns",
        &[
            json!({"domain": "contoso.com", "spf": ["v=spf1 include:spf.protection.outlook.com -all"],
                   "dmarc": ["v=DMARC1; p=reject; rua=mailto:d@contoso.com"], "mtasts": ["v=STSv1; id=1"], "tlsrpt": ["v=TLSRPTv1; rua=mailto:t@contoso.com"]}),
            json!({"domain": "contoso.onmicrosoft.com", "spf": [], "dmarc": [], "mtasts": [], "tlsrpt": []}),
            json!({"domain": "fabrikam.com", "spf": ["v=spf1 +all"], "dmarc": ["v=DMARC1; p=none"], "mtasts": [], "tlsrpt": []}),
        ],
    );
    area(dir, "exopreset", &[]);
    area(
        dir,
        "exoowa",
        &[
            json!({"Name": "OwaMailboxPolicy-Default", "IsDefault": true, "AdditionalStorageProvidersAvailable": true, "ConditionalAccessPolicy": "Off"}),
        ],
    );
    area(
        dir,
        "exosharing",
        &[
            json!({"Name": "Default Sharing Policy", "Enabled": true, "Default": true,
                 "Domains": ["*:CalendarSharingFreeBusyDetail", "Anonymous:CalendarSharingFreeBusySimple"]}),
        ],
    );
}

fn run() -> TenantAnalysis {
    let dir = tempfile::tempdir().unwrap();
    write_tenant(dir.path());
    write_exo(dir.path());
    let raw = RawTenant::load(dir.path()).unwrap();
    assert_eq!(raw.info.tenant_id, TENANT);
    analyze(&catalog(), &raw, &[])
}

fn result<'a>(a: &'a TenantAnalysis, id: &str) -> &'a CheckResult {
    a.checks
        .iter()
        .find(|c| c.id == id)
        .unwrap_or_else(|| panic!("{id} did not run"))
}

fn names(r: &CheckResult) -> Vec<&str> {
    r.affected.iter().map(|a| a.name.as_str()).collect()
}

fn is<'a>(a: &'a TenantAnalysis, id: &str, status: ResultStatus) -> &'a CheckResult {
    let r = result(a, id);
    assert_eq!(r.status, status, "{id}: {r:?}");
    r
}

#[test]
fn authentication_and_forwarding() {
    let a = run();
    is(&a, "M365-EXO-001", ResultStatus::Passed);
    is(&a, "M365-EXO-003", ResultStatus::Passed);
    let protocols = is(&a, "M365-EXO-002", ResultStatus::Failed);
    assert_eq!(names(protocols), ["worker"]);
    assert!(protocols.affected[0]
        .reason
        .as_deref()
        .unwrap()
        .contains("POP, SMTP AUTH"));

    let auto = is(&a, "M365-EXO-004", ResultStatus::Failed);
    assert_eq!(names(auto), ["Executives", "*"]);

    // fabrikam.com is an accepted domain, so only the gmail.com forward counts.
    let fwd = is(&a, "M365-EXO-005", ResultStatus::Failed);
    assert_eq!(names(fwd), ["worker"]);
    assert_eq!(fwd.affected[0].object.as_deref(), Some(ACTIVE));
}

#[test]
fn auditing_and_admin_access() {
    let a = run();
    assert_eq!(
        names(is(&a, "M365-EXO-007", ResultStatus::Failed)),
        ["svc-archive"]
    );
    is(&a, "M365-EXO-008", ResultStatus::Passed);
    let apps = is(&a, "M365-EXO-010", ResultStatus::Failed);
    assert_eq!(names(apps), ["Provisioning connector"]);
    assert_eq!(
        names(is(&a, "M365-EXO-011", ResultStatus::Failed)),
        ["svc-migration"]
    );
    // Entra-linked members are expected; jdoe is not, and View-Only is not an admin group.
    assert_eq!(
        names(is(&a, "M365-EXO-012", ResultStatus::Failed)),
        ["jdoe"]
    );
    // The shared mailbox's Entra account (STALE in the tenant) is enabled.
    assert_eq!(
        names(is(&a, "M365-EXO-013", ResultStatus::Failed)),
        ["sales"]
    );
    is(&a, "M365-EXO-030", ResultStatus::Failed);
    let holds = is(&a, "M365-EXO-031", ResultStatus::Passed);
    assert_eq!(
        holds.found.as_deref(),
        Some("1 of 2 user mailboxes on litigation hold")
    );
}

#[test]
fn threat_protection_policies() {
    let a = run();
    let phish = is(&a, "M365-EXO-014", ResultStatus::Failed);
    assert!(phish.affected[0]
        .reason
        .as_deref()
        .unwrap()
        .contains("impersonation"));
    // Safe Links could not be read (no Defender for Office 365 licence).
    let links = is(&a, "M365-EXO-015", ResultStatus::NotAssessed);
    assert!(links
        .note
        .as_deref()
        .unwrap()
        .contains("Safe Links policies"));
    is(&a, "M365-EXO-017", ResultStatus::Passed);
    // The disabled rule's policy is not in force.
    assert_eq!(
        names(is(&a, "M365-EXO-018", ResultStatus::Failed)),
        ["Default", "Partners"]
    );
    let allow = is(&a, "M365-EXO-019", ResultStatus::Failed);
    assert_eq!(names(allow), ["Partners"]);
    let reason = allow.affected[0].reason.as_deref().unwrap();
    assert!(reason.contains("contoso.com (own domain)") && reason.contains("gmail.com (public"));
    assert!(!reason.contains("partner.example"));
    is(&a, "M365-EXO-026", ResultStatus::Failed);
    is(&a, "M365-EXO-028", ResultStatus::Failed);
    is(&a, "M365-EXO-032", ResultStatus::Failed);
}

#[test]
fn mail_flow_and_domains() {
    let a = run();
    assert_eq!(
        names(is(&a, "M365-EXO-020", ResultStatus::Failed)),
        ["Skip filtering for scanner", "Copy CFO mail"]
    );
    assert_eq!(
        names(is(&a, "M365-EXO-021", ResultStatus::Failed)),
        ["Scanner", "Relay"]
    );
    // The onmicrosoft.com domain is left out of the DNS checks.
    assert_eq!(
        names(is(&a, "M365-EXO-022", ResultStatus::Failed)),
        ["fabrikam.com"]
    );
    assert_eq!(
        names(is(&a, "M365-EXO-023", ResultStatus::Failed)),
        ["fabrikam.com"]
    );
    let dmarc = is(&a, "M365-EXO-024", ResultStatus::Failed);
    assert_eq!(names(dmarc), ["fabrikam.com"]);
    assert!(dmarc.affected[0]
        .reason
        .as_deref()
        .unwrap()
        .contains("p=none"));
    assert_eq!(
        names(is(&a, "M365-EXO-025", ResultStatus::Failed)),
        ["fabrikam.com"]
    );
}

#[test]
fn exchange_not_collected_is_not_assessed() {
    let dir = tempfile::tempdir().unwrap();
    write_tenant(dir.path());
    let raw = RawTenant::load(dir.path()).unwrap();
    let a = analyze(&catalog(), &raw, &[]);
    let r = is(&a, "M365-EXO-001", ResultStatus::NotAssessed);
    assert!(r.note.as_deref().unwrap().contains("not collected"));
}

#[test]
fn exchange_rules_and_catalog_agree() {
    use crate::catalog::CheckStatus;
    let catalog = catalog();
    let rules: Vec<&str> = super::all_rules()
        .map(|r| r.id)
        .chain(crate::hybrid::all_rules().map(|r| r.id))
        .filter(|id| id.starts_with("M365-EXO"))
        .collect();
    for id in &rules {
        let c = catalog.check(id).unwrap();
        assert_eq!(c.status, CheckStatus::Implemented, "{id}");
        assert!(c.detail.is_some(), "{id} has no detail block");
    }
    for c in catalog
        .checks
        .iter()
        .filter(|c| c.area == "M365-EXO" && c.status == CheckStatus::Implemented)
    {
        assert!(rules.contains(&c.id.as_str()), "{} has no rule", c.id);
    }
}
