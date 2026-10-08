//! Exchange Online: authentication protocols, forwarding, auditing, admin
//! and application access, the Defender for Office 365 and Exchange Online
//! Protection policies, connectors, mail flow rules, and the SPF, DKIM,
//! DMARC and MTA-STS records of the accepted domains.

use std::collections::BTreeSet;

use serde_json::Value;

use super::model::{is_microsoft_tenant, Tenant, J};
use super::rules::tenant_item;
use super::rules_priv::{app_permissions, sp_item};
use super::Rule;
use crate::ad::rules::{check, plural, Out};
use crate::results::{Affected, CheckResult};

/// Anti-spam bulk threshold above which bulk mail reaches inboxes.
const BULK_THRESHOLD: i64 = 6;

/// Free mail providers: allowing them by domain allows anyone.
const PUBLIC_DOMAINS: [&str; 14] = [
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "msn.com",
    "yahoo.com",
    "aol.com",
    "icloud.com",
    "me.com",
    "gmx.com",
    "gmx.net",
    "proton.me",
    "protonmail.com",
];

/// Application permissions that reach every mailbox unless an application
/// access policy or RBAC for Applications scopes them.
const MAILBOX_PERMISSIONS: [&str; 13] = [
    "Mail.Read",
    "Mail.ReadBasic",
    "Mail.ReadBasic.All",
    "Mail.ReadWrite",
    "Mail.Send",
    "MailboxSettings.Read",
    "MailboxSettings.ReadWrite",
    "Calendars.Read",
    "Calendars.ReadBasic.All",
    "Calendars.ReadWrite",
    "Contacts.Read",
    "Contacts.ReadWrite",
    "full_access_as_app",
];

/// Exchange role groups whose members administer or search every mailbox.
const ADMIN_ROLE_GROUPS: [&str; 6] = [
    "Organization Management",
    "Recipient Management",
    "Discovery Management",
    "Compliance Management",
    "Records Management",
    "Hygiene Management",
];

fn exo(t: &Tenant, id: &str) -> Out {
    check(id).evidence(
        "Read from",
        format!("Exchange Online, signed in as {}", t.raw.info.account),
    )
}

fn dns(t: &Tenant, id: &str) -> Out {
    check(id).evidence(
        "Read from",
        format!(
            "DNS TXT records of the accepted domains, looked up from {}",
            if t.raw.info.computer.is_empty() {
                "the collecting computer".to_string()
            } else {
                t.raw.info.computer.clone()
            }
        ),
    )
}

fn yes_no(b: bool) -> &'static str {
    if b {
        "Yes"
    } else {
        "No"
    }
}

fn policy(t: &Tenant, name: &str, reason: impl Into<String>) -> Affected {
    t.object("policy", name, None, reason)
}

fn name(v: &Value) -> &str {
    v.s("Name").unwrap_or("(unnamed)")
}

fn mailbox(t: &Tenant, m: &Value, reason: impl Into<String>) -> Affected {
    let id = m
        .s("ExternalDirectoryObjectId")
        .filter(|id| t.users.contains_key(id));
    Affected {
        last_seen: None,
        name: m
            .s("DisplayName")
            .or(m.s("UserPrincipalName"))
            .or(m.s("PrimarySmtpAddress"))
            .unwrap_or("(mailbox)")
            .to_string(),
        kind: "mailbox".into(),
        location: m.s("PrimarySmtpAddress").map(str::to_string),
        reason: Some(reason.into()),
        object: id.map(str::to_string),
    }
}

/// The domain of an address, lowercase, without an `smtp:` prefix.
fn domain_of(address: &str) -> Option<String> {
    let a = address.trim();
    let a = a
        .strip_prefix("smtp:")
        .or_else(|| a.strip_prefix("SMTP:"))
        .unwrap_or(a);
    a.rsplit_once('@')
        .map(|(_, d)| d.trim_end_matches('>').to_ascii_lowercase())
}

fn accepted(t: &Tenant) -> BTreeSet<String> {
    t.raw
        .list("exoaccepteddomains")
        .iter()
        .filter_map(|d| d.s("DomainName"))
        .map(str::to_ascii_lowercase)
        .collect()
}

fn is_internal(accepted: &BTreeSet<String>, domain: &str) -> bool {
    accepted
        .iter()
        .any(|a| domain == a || domain.ends_with(&format!(".{a}")))
}

fn initial_domain(d: &str) -> bool {
    d.ends_with(".onmicrosoft.com")
}

/// The policies in force: the default or built-in one, and every policy an
/// enabled rule applies.
fn in_force<'a>(t: &'a Tenant, policies: &str, rules: &str, key: &str) -> Vec<&'a Value> {
    let applied: BTreeSet<&str> = t
        .raw
        .list(rules)
        .iter()
        .filter(|r| r.s("State") == Some("Enabled"))
        .filter_map(|r| r.s(key))
        .collect();
    t.raw
        .list(policies)
        .iter()
        .filter(|p| {
            p.b("IsDefault") == Some(true)
                || p.b("IsBuiltInProtection") == Some(true)
                || applied.contains(name(p))
        })
        .collect()
}

fn names(list: &[&Value]) -> String {
    list.iter().map(|p| name(p)).collect::<Vec<_>>().join(", ")
}

fn flag(v: &Value, key: &str) -> bool {
    v.b(key) == Some(true)
}

// ---------- Authentication ----------

fn exo_001(t: &Tenant) -> CheckResult {
    let out = exo(t, "M365-EXO-001").expected("Modern authentication is on for Outlook clients");
    match t
        .raw
        .first("exoorg")
        .and_then(|o| o.b("OAuth2ClientProfileEnabled"))
    {
        Some(true) => out.found("Modern authentication: on").done(),
        Some(false) => out
            .affected(
                vec![tenant_item(t, "OAuth2ClientProfileEnabled is False")],
                "tenant",
            )
            .found("Modern authentication: off")
            .done(),
        None => out
            .not_assessed(
                "The organization configuration did not include OAuth2ClientProfileEnabled.",
            )
            .done(),
    }
}

/// Tenant-wide SMTP AUTH: true when the transport configuration allows it.
fn smtp_auth_allowed(t: &Tenant) -> Option<bool> {
    t.raw
        .first("exotransport")
        .and_then(|c| c.b("SmtpClientAuthenticationDisabled"))
        .map(|d| !d)
}

fn exo_002(t: &Tenant) -> CheckResult {
    let tenant_smtp = smtp_auth_allowed(t).unwrap_or(false);
    let cas = t.raw.list("exocas");
    let mailboxes = t.raw.list("exomailboxes");
    let by_address = |addr: Option<&str>| {
        addr.and_then(|a| {
            mailboxes.iter().find(|m| {
                m.s("PrimarySmtpAddress")
                    .is_some_and(|p| p.eq_ignore_ascii_case(a))
            })
        })
    };
    let mut affected = Vec::new();
    let (mut pop, mut imap, mut smtp, mut ews, mut eas) = (0, 0, 0, 0, 0);
    for c in cas {
        let mut on = Vec::new();
        if flag(c, "PopEnabled") {
            pop += 1;
            on.push("POP");
        }
        if flag(c, "ImapEnabled") {
            imap += 1;
            on.push("IMAP");
        }
        let smtp_on = match c.b("SmtpClientAuthenticationDisabled") {
            Some(disabled) => !disabled,
            None => tenant_smtp,
        };
        if smtp_on {
            smtp += 1;
            on.push("SMTP AUTH");
        }
        if flag(c, "EwsEnabled") {
            ews += 1;
        }
        if flag(c, "ActiveSyncEnabled") {
            eas += 1;
        }
        if on.is_empty() {
            continue;
        }
        let reason = format!("{} enabled", on.join(", "));
        affected.push(match by_address(c.s("PrimarySmtpAddress")) {
            Some(m) => mailbox(t, m, reason),
            None => t.object(
                "mailbox",
                c.s("PrimarySmtpAddress").unwrap_or("(mailbox)"),
                None,
                reason,
            ),
        });
    }
    let n = affected.len();
    exo(t, "M365-EXO-002")
        .expected("POP, IMAP and SMTP AUTH are off except on the mailboxes that need them")
        .affected(affected, "mailboxes")
        .found(format!(
            "{} of {} with POP, IMAP or SMTP AUTH enabled",
            plural(n, "mailbox", "mailboxes"),
            cas.len()
        ))
        .evidence(
            "Protocols enabled",
            format!("POP {pop}, IMAP {imap}, SMTP AUTH {smtp}, EWS {ews}, ActiveSync {eas}"),
        )
        .evidence(
            "SMTP AUTH for the organization",
            if tenant_smtp { "Allowed" } else { "Disabled" },
        )
        .done()
}

fn exo_003(t: &Tenant) -> CheckResult {
    let out = exo(t, "M365-EXO-003").expected("SMTP AUTH is disabled for the organization");
    match smtp_auth_allowed(t) {
        Some(true) => out
            .affected(
                vec![tenant_item(t, "SmtpClientAuthenticationDisabled is False")],
                "tenant",
            )
            .found("SMTP AUTH: allowed for the organization")
            .done(),
        Some(false) => out.found("SMTP AUTH: disabled for the organization").done(),
        None => out
            .not_assessed(
                "The transport configuration did not include SmtpClientAuthenticationDisabled.",
            )
            .done(),
    }
}

// ---------- Forwarding ----------

fn exo_004(t: &Tenant) -> CheckResult {
    let policies = in_force(
        t,
        "exooutboundspam",
        "exooutboundspamrules",
        "HostedOutboundSpamFilterPolicy",
    );
    let on: Vec<&Value> = policies
        .iter()
        .copied()
        .filter(|p| p.s("AutoForwardingMode") == Some("On"))
        .collect();
    let remote: Vec<&Value> = t
        .raw
        .list("exoremotedomains")
        .iter()
        .filter(|d| flag(d, "AutoForwardEnabled"))
        .collect();
    let mut affected = Vec::new();
    if !remote.is_empty() {
        for p in &on {
            affected.push(policy(
                t,
                name(p),
                "Outbound spam policy allows automatic forwarding (AutoForwardingMode On)",
            ));
        }
    }
    if !on.is_empty() {
        for d in &remote {
            affected.push(t.object(
                "domain",
                d.s("DomainName").unwrap_or(name(d)),
                None,
                "Remote domain allows automatic forwarding",
            ));
        }
    }
    let found = if affected.is_empty() {
        "Automatic forwarding to external recipients is blocked".to_string()
    } else {
        format!(
            "{} and {} allow automatic forwarding",
            plural(on.len(), "outbound spam policy", "outbound spam policies"),
            plural(remote.len(), "remote domain", "remote domains")
        )
    };
    exo(t, "M365-EXO-004")
        .expected(
            "Outbound spam policies set automatic forwarding to Off, or remote domains block it",
        )
        .affected(affected, "settings")
        .found(found)
        .evidence(
            "Outbound spam policies in force",
            policies
                .iter()
                .map(|p| {
                    format!(
                        "{}: {}",
                        name(p),
                        p.s("AutoForwardingMode").unwrap_or("not set")
                    )
                })
                .collect::<Vec<_>>()
                .join("; "),
        )
        .evidence(
            "Remote domains allowing forwarding",
            if remote.is_empty() {
                "None".to_string()
            } else {
                remote
                    .iter()
                    .filter_map(|d| d.s("DomainName"))
                    .collect::<Vec<_>>()
                    .join(", ")
            },
        )
        .done()
}

fn exo_005(t: &Tenant) -> CheckResult {
    let ours = accepted(t);
    let mailboxes = t.raw.list("exomailboxes");
    let mut affected = Vec::new();
    let mut internal = 0;
    for m in mailboxes {
        let Some(fwd) = m
            .s("ForwardingSmtpAddress")
            .filter(|s| !s.trim().is_empty())
        else {
            continue;
        };
        let Some(d) = domain_of(fwd) else { continue };
        if is_internal(&ours, &d) {
            internal += 1;
            continue;
        }
        let keep = if flag(m, "DeliverToMailboxAndForward") {
            "a copy is kept"
        } else {
            "no copy is kept"
        };
        affected.push(mailbox(
            t,
            m,
            format!(
                "Forwards to {} ({keep})",
                fwd.trim_start_matches("smtp:").trim_start_matches("SMTP:")
            ),
        ));
    }
    let n = affected.len();
    exo(t, "M365-EXO-005")
        .expected("No mailbox forwards to an address outside the organization's domains")
        .affected(affected, "mailboxes")
        .found(format!(
            "{} forwarding outside the organization",
            plural(n, "mailbox", "mailboxes")
        ))
        .evidence("Mailboxes read", mailboxes.len().to_string())
        .evidence("Forwarding to internal addresses", internal.to_string())
        .done()
}

// ---------- Auditing ----------

fn exo_007(t: &Tenant) -> CheckResult {
    let disabled = t.raw.first("exoorg").and_then(|o| o.b("AuditDisabled"));
    let bypass = t.raw.list("exoauditbypass");
    let mut affected = Vec::new();
    if disabled == Some(true) {
        affected.push(tenant_item(
            t,
            "Mailbox auditing by default is off (AuditDisabled True)",
        ));
    }
    for b in bypass.iter().filter(|b| flag(b, "AuditBypassEnabled")) {
        affected.push(t.object(
            "account",
            name(b),
            None,
            "Audit bypass: its mailbox actions are not logged",
        ));
    }
    let n = affected.len();
    exo(t, "M365-EXO-007")
        .expected("Mailbox auditing is on by default and no account bypasses it")
        .affected(affected, "findings")
        .found(format!(
            "Default mailbox auditing: {}; {}",
            match disabled {
                Some(true) => "off",
                Some(false) => "on",
                None => "not reported",
            },
            plural(
                n - usize::from(disabled == Some(true)),
                "account with audit bypass",
                "accounts with audit bypass"
            )
        ))
        .done()
}

fn exo_008(t: &Tenant) -> CheckResult {
    let out = exo(t, "M365-EXO-008").expected("The unified audit log records activity");
    match t
        .raw
        .first("exoadminaudit")
        .and_then(|c| c.b("UnifiedAuditLogIngestionEnabled"))
    {
        Some(true) => out.found("Unified audit log: on").done(),
        Some(false) => out
            .affected(
                vec![tenant_item(t, "UnifiedAuditLogIngestionEnabled is False")],
                "tenant",
            )
            .found("Unified audit log: off")
            .done(),
        None => out
            .not_assessed("The admin audit log configuration did not include UnifiedAuditLogIngestionEnabled.")
            .done(),
    }
}

// ---------- Admin and application access ----------

fn exo_010(t: &Tenant) -> CheckResult {
    let scoped: BTreeSet<String> = t
        .raw
        .list("exoappaccess")
        .iter()
        .filter_map(|p| p.s("AppId"))
        .map(str::to_ascii_lowercase)
        .collect();
    let mut affected = Vec::new();
    let mut with_mail = 0;
    let mut perms: Vec<(String, Vec<String>)> = app_permissions(t).into_iter().collect();
    perms.sort();
    for (sp, list) in perms {
        let mail: BTreeSet<&str> = list
            .iter()
            .map(String::as_str)
            .filter(|p| MAILBOX_PERMISSIONS.contains(p))
            .collect();
        if mail.is_empty() {
            continue;
        }
        let Some(s) = t.sps.get(sp.as_str()) else {
            continue;
        };
        if s.s("appOwnerOrganizationId")
            .is_some_and(is_microsoft_tenant)
        {
            continue;
        }
        with_mail += 1;
        let app = s.s("appId").unwrap_or_default().to_ascii_lowercase();
        if scoped.contains(&app) {
            continue;
        }
        affected.push(sp_item(
            t,
            &sp,
            format!(
                "{} on every mailbox; no application access policy",
                mail.into_iter().collect::<Vec<_>>().join(", ")
            ),
        ));
    }
    let n = affected.len();
    exo(t, "M365-EXO-010")
        .expected("Applications with mailbox application permissions are limited to the mailboxes they need (application access policy or RBAC for Applications)")
        .affected(affected, "applications")
        .found(format!(
            "{} of {} with mailbox permissions not scoped by an application access policy",
            plural(n, "application", "applications"),
            with_mail
        ))
        .evidence("Application access policies", scoped.len().to_string())
        .evidence(
            "Not read",
            "RBAC for Applications assignments are not collected; an application scoped that way is listed here too",
        )
        .done()
}

fn exo_011(t: &Tenant) -> CheckResult {
    let list = t.raw.list("exoimpersonation");
    let affected: Vec<Affected> = list
        .iter()
        .filter(|a| a.b("Enabled") != Some(false))
        .map(|a| {
            let scope = a
                .s("CustomRecipientWriteScope")
                .filter(|s| !s.is_empty())
                .map(|s| format!("scope {s}"))
                .unwrap_or_else(|| "every mailbox".to_string());
            t.object(
                "account",
                a.s("RoleAssigneeName").unwrap_or(name(a)),
                a.s("RoleAssigneeType").map(str::to_string),
                format!("ApplicationImpersonation on {scope}"),
            )
        })
        .collect();
    let n = affected.len();
    exo(t, "M365-EXO-011")
        .expected("No account holds the ApplicationImpersonation role")
        .affected(affected, "assignments")
        .found(plural(
            n,
            "ApplicationImpersonation assignment",
            "ApplicationImpersonation assignments",
        ))
        .done()
}

/// Members Exchange Online adds for Entra roles look like TenantAdmins_-123456789.
fn linked_role_group(member: &str) -> bool {
    member.rsplit_once('_').is_some_and(|(_, n)| {
        let n = n.trim_start_matches('-');
        n.len() >= 6 && n.chars().all(|c| c.is_ascii_digit())
    })
}

fn exo_012(t: &Tenant) -> CheckResult {
    let groups = t.raw.list("exorolegroups");
    let mut affected = Vec::new();
    let mut summary = Vec::new();
    for g in groups {
        let gname = name(g);
        if !ADMIN_ROLE_GROUPS.contains(&gname) {
            continue;
        }
        let members = g.strs("Members");
        let direct: Vec<&str> = members
            .iter()
            .copied()
            .filter(|m| !linked_role_group(m))
            .collect();
        summary.push(format!("{gname}: {}", members.len()));
        for m in direct {
            affected.push(t.object(
                "account",
                m,
                Some(gname.to_string()),
                format!("Direct member of {gname}"),
            ));
        }
    }
    let n = affected.len();
    exo(t, "M365-EXO-012")
        .expected("Exchange admin role groups are held through Entra roles, where PIM and access reviews govern them, not by direct membership")
        .affected(affected, "members")
        .found(format!(
            "{} of Exchange admin role groups",
            plural(n, "direct member", "direct members")
        ))
        .evidence("Members per role group", summary.join("; "))
        .done()
}

fn exo_013(t: &Tenant) -> CheckResult {
    let shared: Vec<&Value> = t
        .raw
        .list("exomailboxes")
        .iter()
        .filter(|m| m.s("RecipientTypeDetails") == Some("SharedMailbox"))
        .collect();
    let mut affected = Vec::new();
    let mut matched = 0;
    for m in &shared {
        let Some(u) = m
            .s("ExternalDirectoryObjectId")
            .and_then(|id| t.users.get(id))
        else {
            continue;
        };
        matched += 1;
        if u.b("accountEnabled") == Some(true) {
            affected.push(mailbox(t, m, "Shared mailbox account can sign in"));
        }
    }
    let n = affected.len();
    exo(t, "M365-EXO-013")
        .expected("Shared mailbox accounts are blocked from signing in")
        .affected(affected, "mailboxes")
        .found(format!(
            "{} of {} with sign-in allowed",
            plural(n, "shared mailbox", "shared mailboxes"),
            shared.len()
        ))
        .evidence("Matched to Entra accounts", matched.to_string())
        .done()
}

// ---------- Threat protection ----------

fn exo_014(t: &Tenant) -> CheckResult {
    let policies = in_force(t, "exoantiphish", "exoantiphishrules", "AntiPhishPolicy");
    let mut affected = Vec::new();
    for p in &policies {
        if p.b("Enabled") == Some(false) {
            affected.push(policy(t, name(p), "Policy is turned off"));
            continue;
        }
        let mut missing = Vec::new();
        if !flag(p, "EnableSpoofIntelligence") {
            missing.push("spoof intelligence");
        }
        if !flag(p, "EnableMailboxIntelligence") {
            missing.push("mailbox intelligence");
        }
        if !flag(p, "EnableMailboxIntelligenceProtection") {
            missing.push("mailbox intelligence protection");
        }
        if !flag(p, "EnableTargetedUserProtection")
            && !flag(p, "EnableOrganizationDomainsProtection")
        {
            missing.push("user and domain impersonation protection");
        }
        if !missing.is_empty() {
            affected.push(policy(t, name(p), format!("Off: {}", missing.join(", "))));
        }
    }
    let n = affected.len();
    let out = exo(t, "M365-EXO-014")
        .expected("Every anti-phishing policy in force has spoof intelligence, mailbox intelligence and impersonation protection on");
    if policies.is_empty() {
        return out
            .not_assessed("No anti-phishing policy was returned.")
            .done();
    }
    out.affected(affected, "policies")
        .found(format!(
            "{} of {} in force missing protections",
            plural(n, "policy", "policies"),
            policies.len()
        ))
        .evidence("Policies in force", names(&policies))
        .evidence(
            "Note",
            "Impersonation and mailbox intelligence protection need Defender for Office 365 Plan 1",
        )
        .done()
}

fn exo_015(t: &Tenant) -> CheckResult {
    let policies = in_force(t, "exosafelinks", "exosafelinksrules", "SafeLinksPolicy");
    let mut affected = Vec::new();
    for p in &policies {
        let mut issues = Vec::new();
        if !flag(p, "EnableSafeLinksForEmail") {
            issues.push("email links not checked");
        }
        if p.b("ScanUrls") == Some(false) {
            issues.push("links are not scanned in real time");
        }
        if flag(p, "AllowClickThrough") {
            issues.push("users can click through warnings");
        }
        if !issues.is_empty() {
            affected.push(policy(t, name(p), issues.join("; ")));
        }
    }
    let covered = policies.iter().any(|p| flag(p, "EnableSafeLinksForEmail"));
    if !covered {
        affected.insert(
            0,
            tenant_item(t, "No Safe Links policy in force checks email links"),
        );
    }
    let n = affected.len();
    exo(t, "M365-EXO-015")
        .expected("Safe Links checks email links for everyone, scans them on click and does not let users click through")
        .affected(affected, "findings")
        .found(if covered {
            format!(
                "{} of {} in force with weaker settings",
                plural(n, "policy", "policies"),
                policies.len()
            )
        } else {
            "No Safe Links policy in force checks email links".to_string()
        })
        .evidence(
            "Policies in force",
            if policies.is_empty() {
                "None".to_string()
            } else {
                names(&policies)
            },
        )
        .done()
}

fn exo_016(t: &Tenant) -> CheckResult {
    let policies = in_force(
        t,
        "exosafeattach",
        "exosafeattachrules",
        "SafeAttachmentPolicy",
    );
    let mut affected = Vec::new();
    for p in &policies {
        let action = p.s("Action").unwrap_or("not set");
        if p.b("Enable") == Some(false) || action == "Allow" {
            affected.push(policy(
                t,
                name(p),
                format!("Scanning off or attachments delivered anyway (action {action})"),
            ));
        }
    }
    let covered = policies
        .iter()
        .any(|p| p.b("Enable") != Some(false) && p.s("Action") != Some("Allow"));
    if !covered {
        affected.insert(
            0,
            tenant_item(
                t,
                "No Safe Attachments policy in force blocks malicious attachments",
            ),
        );
    }
    let atp = t.raw.first("exoatpo365");
    if atp.and_then(|a| a.b("EnableATPForSPOTeamsODB")) == Some(false) {
        affected.push(tenant_item(
            t,
            "Safe Attachments for SharePoint, OneDrive and Teams is off",
        ));
    }
    let n = affected.len();
    exo(t, "M365-EXO-016")
        .expected("Safe Attachments blocks or dynamically delivers for everyone, and covers SharePoint, OneDrive and Teams")
        .affected(affected, "findings")
        .found(if n == 0 {
            "Safe Attachments covers email, SharePoint, OneDrive and Teams".to_string()
        } else {
            plural(n, "gap", "gaps")
        })
        .evidence(
            "Policies in force",
            policies
                .iter()
                .map(|p| format!("{}: {}", name(p), p.s("Action").unwrap_or("not set")))
                .collect::<Vec<_>>()
                .join("; "),
        )
        .evidence(
            "SharePoint, OneDrive and Teams",
            match atp.and_then(|a| a.b("EnableATPForSPOTeamsODB")) {
                Some(b) => yes_no(b).to_string(),
                None => "Not reported".to_string(),
            },
        )
        .done()
}

fn exo_017(t: &Tenant) -> CheckResult {
    let policies = in_force(t, "exomalware", "exomalwarerules", "MalwareFilterPolicy");
    let mut affected = Vec::new();
    for p in &policies {
        let mut off = Vec::new();
        if !flag(p, "EnableFileFilter") {
            off.push("common attachments filter");
        }
        if !flag(p, "ZapEnabled") {
            off.push("zero-hour auto purge");
        }
        if !off.is_empty() {
            affected.push(policy(t, name(p), format!("Off: {}", off.join(", "))));
        }
    }
    let n = affected.len();
    exo(t, "M365-EXO-017")
        .expected("Every anti-malware policy in force has the common attachments filter and zero-hour auto purge on")
        .affected(affected, "policies")
        .found(format!(
            "{} of {} in force missing protections",
            plural(n, "policy", "policies"),
            policies.len()
        ))
        .evidence("Policies in force", names(&policies))
        .done()
}

fn exo_018(t: &Tenant) -> CheckResult {
    let policies = in_force(
        t,
        "exocontentfilter",
        "exocontentfilterrules",
        "HostedContentFilterPolicy",
    );
    let mut affected = Vec::new();
    for p in &policies {
        let mut issues = Vec::new();
        if let Some(b) = p.n("BulkThreshold").filter(|b| *b > BULK_THRESHOLD) {
            issues.push(format!("bulk threshold {b}"));
        }
        let senders = p.strs("AllowedSenders").len();
        let domains = p.strs("AllowedSenderDomains").len();
        if senders + domains > 0 {
            issues.push(format!(
                "{} and {} skip spam filtering",
                plural(senders, "allowed sender", "allowed senders"),
                plural(domains, "allowed domain", "allowed domains")
            ));
        }
        if !issues.is_empty() {
            affected.push(policy(t, name(p), issues.join("; ")));
        }
    }
    let n = affected.len();
    exo(t, "M365-EXO-018")
        .expected(format!(
            "Anti-spam policies use a bulk threshold of {BULK_THRESHOLD} or lower and have no allowed sender or domain lists"
        ))
        .affected(affected, "policies")
        .found(format!(
            "{} of {} in force with weaker settings",
            plural(n, "policy", "policies"),
            policies.len()
        ))
        .evidence(
            "Bulk thresholds",
            policies
                .iter()
                .map(|p| {
                    format!(
                        "{}: {}",
                        name(p),
                        p.n("BulkThreshold")
                            .map(|b| b.to_string())
                            .unwrap_or_else(|| "not set".into())
                    )
                })
                .collect::<Vec<_>>()
                .join("; "),
        )
        .done()
}

fn exo_019(t: &Tenant) -> CheckResult {
    let ours = accepted(t);
    let policies = in_force(
        t,
        "exocontentfilter",
        "exocontentfilterrules",
        "HostedContentFilterPolicy",
    );
    let mut affected = Vec::new();
    for p in &policies {
        let mut bad: Vec<String> = Vec::new();
        for d in p.strs("AllowedSenderDomains") {
            let d = d.to_ascii_lowercase();
            if is_internal(&ours, &d) {
                bad.push(format!("{d} (own domain)"));
            } else if PUBLIC_DOMAINS.contains(&d.as_str()) {
                bad.push(format!("{d} (public mail provider)"));
            }
        }
        for s in p.strs("AllowedSenders") {
            if let Some(d) = domain_of(s).filter(|d| is_internal(&ours, d)) {
                bad.push(format!("{s} (own domain {d})"));
            }
        }
        if !bad.is_empty() {
            affected.push(policy(t, name(p), format!("Allows {}", bad.join(", "))));
        }
    }
    let n = affected.len();
    exo(t, "M365-EXO-019")
        .expected("No anti-spam allow list contains the organization's own domains or public mail providers")
        .affected(affected, "policies")
        .found(format!(
            "{} allowing own or public domains",
            plural(n, "policy", "policies")
        ))
        .done()
}

/// Mail flow rule headers that skip Defender for Office 365 or spam checks.
const BYPASS_HEADERS: [&str; 4] = [
    "X-MS-Exchange-Organization-SkipSafeLinksProcessing",
    "X-MS-Exchange-Organization-SkipSafeAttachmentProcessing",
    "X-MS-Exchange-Organization-BypassFocusedInbox",
    "X-Forefront-Antispam-Report",
];

fn exo_020(t: &Tenant) -> CheckResult {
    let ours = accepted(t);
    let rules = t.raw.list("exotransportrules");
    let mut affected = Vec::new();
    for r in rules.iter().filter(|r| r.s("State") != Some("Disabled")) {
        let mut issues = Vec::new();
        if r.n("SetSCL") == Some(-1) {
            issues.push("sets SCL -1 (skips spam filtering)".to_string());
        }
        if let Some(h) = r
            .s("SetHeaderName")
            .filter(|h| BYPASS_HEADERS.iter().any(|b| h.eq_ignore_ascii_case(b)))
        {
            issues.push(format!("sets {h}"));
        }
        for key in [
            "RedirectMessageTo",
            "BlindCopyTo",
            "AddToRecipients",
            "CopyTo",
        ] {
            let external: Vec<&str> = r
                .strs(key)
                .into_iter()
                .filter(|a| domain_of(a).is_some_and(|d| !is_internal(&ours, &d)))
                .collect();
            if !external.is_empty() {
                let verb = match key {
                    "RedirectMessageTo" => "redirects to",
                    "BlindCopyTo" => "blind copies to",
                    "AddToRecipients" => "adds recipients",
                    _ => "copies to",
                };
                issues.push(format!("{verb} {}", external.join(", ")));
            }
        }
        if !issues.is_empty() {
            affected.push(t.object(
                "policy",
                name(r),
                r.n("Priority").map(|p| format!("Priority {p}")),
                issues.join("; "),
            ));
        }
    }
    let n = affected.len();
    exo(t, "M365-EXO-020")
        .expected(
            "No enabled mail flow rule skips filtering or sends mail outside the organization",
        )
        .affected(affected, "rules")
        .found(format!(
            "{} of {} enabled",
            plural(n, "risky mail flow rule", "risky mail flow rules"),
            rules
                .iter()
                .filter(|r| r.s("State") != Some("Disabled"))
                .count()
        ))
        .done()
}

fn exo_021(t: &Tenant) -> CheckResult {
    let mut affected = Vec::new();
    for c in t
        .raw
        .list("exoinbound")
        .iter()
        .filter(|c| c.b("Enabled") != Some(false))
    {
        let cert = c
            .s("TlsSenderCertificateName")
            .is_some_and(|s| !s.is_empty());
        let ips = !c.strs("SenderIPAddresses").is_empty();
        let mut issues = Vec::new();
        if c.b("RequireTls") != Some(true) {
            issues.push("TLS not required");
        }
        if !cert && !ips {
            issues.push("not limited to a certificate or IP addresses");
        }
        if !issues.is_empty() {
            affected.push(t.object(
                "connector",
                name(c),
                Some(format!(
                    "Inbound, {}",
                    c.s("ConnectorType").unwrap_or("connector")
                )),
                issues.join("; "),
            ));
        }
    }
    for c in t
        .raw
        .list("exooutbound")
        .iter()
        .filter(|c| c.b("Enabled") != Some(false))
    {
        let hosts = c.strs("SmartHosts");
        if hosts.is_empty() || c.b("UseMXRecord") == Some(true) {
            continue;
        }
        let tls = c.s("TlsSettings").filter(|s| !s.is_empty());
        if tls.is_none() {
            affected.push(t.object(
                "connector",
                name(c),
                Some(format!(
                    "Outbound, {}",
                    c.s("ConnectorType").unwrap_or("connector")
                )),
                format!("Sends to {} without requiring TLS", hosts.join(", ")),
            ));
        }
    }
    let n = affected.len();
    exo(t, "M365-EXO-021")
        .expected("Inbound connectors require TLS and a certificate or IP restriction; outbound connectors to smart hosts require TLS")
        .affected(affected, "connectors")
        .found(plural(n, "weak connector", "weak connectors"))
        .evidence(
            "Connectors",
            format!(
                "{} inbound, {} outbound",
                t.raw.list("exoinbound").len(),
                t.raw.list("exooutbound").len()
            ),
        )
        .done()
}

// ---------- Domains ----------

/// Accepted domains other than the initial onmicrosoft.com ones, with their
/// DNS answers.
fn dns_rows<'a>(t: &'a Tenant) -> Vec<&'a Value> {
    t.raw
        .list("exodns")
        .iter()
        .filter(|r| {
            r.s("domain")
                .is_some_and(|d| !initial_domain(&d.to_ascii_lowercase()))
        })
        .collect()
}

fn domain_item(t: &Tenant, d: &str, reason: impl Into<String>) -> Affected {
    t.object("domain", d, None, reason)
}

fn exo_022(t: &Tenant) -> CheckResult {
    let rows = dns_rows(t);
    let mut affected = Vec::new();
    for r in &rows {
        let d = r.s("domain").unwrap_or_default();
        let spf = r.strs("spf");
        let issue = match spf.as_slice() {
            [] => Some("No SPF record".to_string()),
            [one] => {
                let all = one
                    .split_whitespace()
                    .find(|p| p.trim_start_matches(['+', '-', '~', '?']) == "all");
                match all {
                    None => Some(format!("SPF record has no 'all' mechanism: {one}")),
                    Some("+all" | "all") => Some(format!("SPF allows any sender (+all): {one}")),
                    Some("?all") => Some(format!("SPF ends in neutral ?all: {one}")),
                    _ => None,
                }
            }
            _ => Some(format!(
                "{} SPF records; receivers treat this as an error",
                spf.len()
            )),
        };
        if let Some(i) = issue {
            affected.push(domain_item(t, d, i));
        }
    }
    let n = affected.len();
    dns(t, "M365-EXO-022")
        .expected("Every accepted domain publishes one SPF record ending in -all or ~all")
        .affected(affected, "domains")
        .found(format!(
            "{} of {} without a valid SPF record",
            plural(n, "domain", "domains"),
            rows.len()
        ))
        .done()
}

fn exo_023(t: &Tenant) -> CheckResult {
    let enabled: BTreeSet<String> = t
        .raw
        .list("exodkim")
        .iter()
        .filter(|c| flag(c, "Enabled"))
        .filter_map(|c| c.s("Domain"))
        .map(str::to_ascii_lowercase)
        .collect();
    let domains: Vec<String> = accepted(t)
        .into_iter()
        .filter(|d| !initial_domain(d))
        .collect();
    let affected: Vec<Affected> = domains
        .iter()
        .filter(|d| !enabled.contains(*d))
        .map(|d| domain_item(t, d, "DKIM signing is not enabled"))
        .collect();
    let n = affected.len();
    exo(t, "M365-EXO-023")
        .expected("DKIM signing is enabled for every accepted domain")
        .affected(affected, "domains")
        .found(format!(
            "{} of {} without DKIM signing",
            plural(n, "domain", "domains"),
            domains.len()
        ))
        .done()
}

/// The value of a tag in a DMARC record (`p`, `pct`...).
fn dmarc_tag<'a>(record: &'a str, tag: &str) -> Option<&'a str> {
    record.split(';').find_map(|part| {
        let (k, v) = part.split_once('=')?;
        (k.trim().eq_ignore_ascii_case(tag)).then(|| v.trim())
    })
}

fn exo_024(t: &Tenant) -> CheckResult {
    let rows = dns_rows(t);
    let mut affected = Vec::new();
    let mut summary = Vec::new();
    for r in &rows {
        let d = r.s("domain").unwrap_or_default();
        let records = r.strs("dmarc");
        let issue = match records.as_slice() {
            [] => Some("No DMARC record".to_string()),
            [one] => {
                let p = dmarc_tag(one, "p").unwrap_or("").to_ascii_lowercase();
                let pct = dmarc_tag(one, "pct").and_then(|v| v.parse::<u32>().ok());
                summary.push(format!("{d}: p={p}"));
                match (p.as_str(), pct) {
                    ("quarantine" | "reject", Some(n)) if n < 100 => {
                        Some(format!("Policy p={p} applies to {n}% of failing mail"))
                    }
                    ("quarantine" | "reject", _) => None,
                    ("none", _) => {
                        Some("Policy p=none only monitors; spoofed mail is delivered".to_string())
                    }
                    _ => Some(format!("DMARC record has no valid policy: {one}")),
                }
            }
            _ => Some(format!(
                "{} DMARC records; receivers ignore them all",
                records.len()
            )),
        };
        if let Some(i) = issue {
            affected.push(domain_item(t, d, i));
        }
    }
    let n = affected.len();
    dns(t, "M365-EXO-024")
        .expected("Every accepted domain publishes a DMARC record with p=quarantine or p=reject for all mail")
        .affected(affected, "domains")
        .found(format!(
            "{} of {} without an enforcing DMARC policy",
            plural(n, "domain", "domains"),
            rows.len()
        ))
        .evidence(
            "Policies",
            if summary.is_empty() {
                "None".to_string()
            } else {
                summary.join("; ")
            },
        )
        .done()
}

fn exo_025(t: &Tenant) -> CheckResult {
    let rows = dns_rows(t);
    let mut affected = Vec::new();
    for r in &rows {
        let mut missing = Vec::new();
        if r.strs("mtasts").is_empty() {
            missing.push("MTA-STS");
        }
        if r.strs("tlsrpt").is_empty() {
            missing.push("TLS-RPT");
        }
        if !missing.is_empty() {
            affected.push(domain_item(
                t,
                r.s("domain").unwrap_or_default(),
                format!("No {} record", missing.join(" or ")),
            ));
        }
    }
    let n = affected.len();
    dns(t, "M365-EXO-025")
        .expected("Accepted domains publish MTA-STS and TLS-RPT records")
        .affected(affected, "domains")
        .found(format!(
            "{} of {} without MTA-STS or TLS-RPT",
            plural(n, "domain", "domains"),
            rows.len()
        ))
        .done()
}

fn exo_026(t: &Tenant) -> CheckResult {
    let rules = t.raw.list("exopreset");
    let enabled: Vec<&str> = rules
        .iter()
        .filter(|r| r.s("State") == Some("Enabled"))
        .map(name)
        .collect();
    let out = exo(t, "M365-EXO-026")
        .expected("The Standard or Strict preset security policy is turned on")
        .evidence(
            "Preset policies",
            if rules.is_empty() {
                "None configured".to_string()
            } else {
                rules
                    .iter()
                    .map(|r| format!("{}: {}", name(r), r.s("State").unwrap_or("not set")))
                    .collect::<Vec<_>>()
                    .join("; ")
            },
        );
    if enabled.is_empty() {
        out.affected(
            vec![tenant_item(
                t,
                "Neither the Standard nor the Strict preset security policy is on",
            )],
            "tenant",
        )
        .found("No preset security policy is on")
        .done()
    } else {
        out.found(format!("On: {}", enabled.join(", "))).done()
    }
}

fn exo_028(t: &Tenant) -> CheckResult {
    let policies = t.raw.list("exoowa");
    let mut affected = Vec::new();
    for p in policies {
        if flag(p, "AdditionalStorageProvidersAvailable") {
            affected.push(policy(
                t,
                name(p),
                format!(
                    "Users can open and save files to other storage providers; unmanaged devices: {}",
                    p.s("ConditionalAccessPolicy").unwrap_or("not set")
                ),
            ));
        }
    }
    let n = affected.len();
    exo(t, "M365-EXO-028")
        .expected("Outlook on the web policies do not allow other storage providers")
        .affected(affected, "policies")
        .found(format!(
            "{} of {} allowing other storage providers",
            plural(n, "policy", "policies"),
            policies.len()
        ))
        .evidence(
            "Unmanaged device access",
            policies
                .iter()
                .map(|p| {
                    format!(
                        "{}: {}",
                        name(p),
                        p.s("ConditionalAccessPolicy").unwrap_or("not set")
                    )
                })
                .collect::<Vec<_>>()
                .join("; "),
        )
        .done()
}

fn exo_030(t: &Tenant) -> CheckResult {
    let out = exo(t, "M365-EXO-030").expected("Customer Lockbox is on");
    match t
        .raw
        .first("exoorg")
        .and_then(|o| o.b("CustomerLockBoxEnabled"))
    {
        Some(true) => out.found("Customer Lockbox: on").done(),
        Some(false) => out
            .affected(
                vec![tenant_item(t, "CustomerLockBoxEnabled is False")],
                "tenant",
            )
            .found("Customer Lockbox: off")
            .done(),
        None => out
            .not_assessed("The organization configuration did not include CustomerLockBoxEnabled.")
            .done(),
    }
}

fn exo_031(t: &Tenant) -> CheckResult {
    let mailboxes = t.raw.list("exomailboxes");
    let users: Vec<&Value> = mailboxes
        .iter()
        .filter(|m| m.s("RecipientTypeDetails") == Some("UserMailbox"))
        .collect();
    let held = users
        .iter()
        .filter(|m| flag(m, "LitigationHoldEnabled"))
        .count();
    let shared = mailboxes
        .iter()
        .filter(|m| m.s("RecipientTypeDetails") == Some("SharedMailbox"))
        .count();
    exo(t, "M365-EXO-031")
        .found(format!(
            "{held} of {} on litigation hold",
            plural(users.len(), "user mailbox", "user mailboxes")
        ))
        .evidence("Mailboxes", mailboxes.len().to_string())
        .evidence("Shared mailboxes", shared.to_string())
        .evidence(
            "Note",
            "Retention policies from Microsoft Purview are not part of this count",
        )
        .done()
}

fn exo_032(t: &Tenant) -> CheckResult {
    let policies = t.raw.list("exosharing");
    let mut affected = Vec::new();
    for p in policies.iter().filter(|p| p.b("Enabled") != Some(false)) {
        let wide: Vec<&str> = p
            .strs("Domains")
            .into_iter()
            .filter(|d| {
                let (who, what) = d.split_once(':').unwrap_or((d, ""));
                (who == "*" || who.eq_ignore_ascii_case("Anonymous"))
                    && (what.contains("FreeBusyDetail")
                        || what.contains("FreeBusyReviewer")
                        || what.contains("ContactsSharing"))
            })
            .collect();
        if !wide.is_empty() {
            affected.push(policy(
                t,
                name(p),
                format!(
                    "Shares calendar details with any domain: {}",
                    wide.join(", ")
                ),
            ));
        }
    }
    let n = affected.len();
    exo(t, "M365-EXO-032")
        .expected("Sharing policies share free/busy times only, or details only with named partner domains")
        .affected(affected, "policies")
        .found(format!(
            "{} sharing calendar details with any domain",
            plural(n, "policy", "policies")
        ))
        .evidence(
            "Sharing policies",
            policies
                .iter()
                .map(|p| format!("{}: {}", name(p), p.strs("Domains").join(", ")))
                .collect::<Vec<_>>()
                .join("; "),
        )
        .done()
}

pub static RULES: &[Rule] = &[
    Rule {
        id: "M365-EXO-001",
        needs: &["exoorg"],
        run: exo_001,
    },
    Rule {
        id: "M365-EXO-002",
        needs: &["exocas", "exotransport"],
        run: exo_002,
    },
    Rule {
        id: "M365-EXO-003",
        needs: &["exotransport"],
        run: exo_003,
    },
    Rule {
        id: "M365-EXO-004",
        needs: &[
            "exooutboundspam",
            "exooutboundspamrules",
            "exoremotedomains",
        ],
        run: exo_004,
    },
    Rule {
        id: "M365-EXO-005",
        needs: &["exomailboxes", "exoaccepteddomains"],
        run: exo_005,
    },
    Rule {
        id: "M365-EXO-007",
        needs: &["exoorg", "exoauditbypass"],
        run: exo_007,
    },
    Rule {
        id: "M365-EXO-008",
        needs: &["exoadminaudit"],
        run: exo_008,
    },
    Rule {
        id: "M365-EXO-010",
        needs: &[
            "exoappaccess",
            "resources",
            "approleassignments",
            "serviceprincipals",
        ],
        run: exo_010,
    },
    Rule {
        id: "M365-EXO-011",
        needs: &["exoimpersonation"],
        run: exo_011,
    },
    Rule {
        id: "M365-EXO-012",
        needs: &["exorolegroups"],
        run: exo_012,
    },
    Rule {
        id: "M365-EXO-013",
        needs: &["exomailboxes", "users"],
        run: exo_013,
    },
    Rule {
        id: "M365-EXO-014",
        needs: &["exoantiphish", "exoantiphishrules"],
        run: exo_014,
    },
    Rule {
        id: "M365-EXO-015",
        needs: &["exosafelinks", "exosafelinksrules"],
        run: exo_015,
    },
    Rule {
        id: "M365-EXO-016",
        needs: &["exosafeattach", "exosafeattachrules", "exoatpo365"],
        run: exo_016,
    },
    Rule {
        id: "M365-EXO-017",
        needs: &["exomalware", "exomalwarerules"],
        run: exo_017,
    },
    Rule {
        id: "M365-EXO-018",
        needs: &["exocontentfilter", "exocontentfilterrules"],
        run: exo_018,
    },
    Rule {
        id: "M365-EXO-019",
        needs: &[
            "exocontentfilter",
            "exocontentfilterrules",
            "exoaccepteddomains",
        ],
        run: exo_019,
    },
    Rule {
        id: "M365-EXO-020",
        needs: &["exotransportrules", "exoaccepteddomains"],
        run: exo_020,
    },
    Rule {
        id: "M365-EXO-021",
        needs: &["exoinbound", "exooutbound"],
        run: exo_021,
    },
    Rule {
        id: "M365-EXO-022",
        needs: &["exodns"],
        run: exo_022,
    },
    Rule {
        id: "M365-EXO-023",
        needs: &["exodkim", "exoaccepteddomains"],
        run: exo_023,
    },
    Rule {
        id: "M365-EXO-024",
        needs: &["exodns"],
        run: exo_024,
    },
    Rule {
        id: "M365-EXO-025",
        needs: &["exodns"],
        run: exo_025,
    },
    Rule {
        id: "M365-EXO-026",
        needs: &["exopreset"],
        run: exo_026,
    },
    Rule {
        id: "M365-EXO-028",
        needs: &["exoowa"],
        run: exo_028,
    },
    Rule {
        id: "M365-EXO-030",
        needs: &["exoorg"],
        run: exo_030,
    },
    Rule {
        id: "M365-EXO-031",
        needs: &["exomailboxes"],
        run: exo_031,
    },
    Rule {
        id: "M365-EXO-032",
        needs: &["exosharing"],
        run: exo_032,
    },
];
