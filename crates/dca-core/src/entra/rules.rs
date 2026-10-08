//! Tenant settings, identities, groups, devices, monitoring and the hybrid
//! settings Entra holds. Conditional Access and authentication rules are in
//! `rules_ca`, roles and applications in `rules_priv`.

use serde_json::Value;

use super::model::{Tenant, GLOBAL_ADMIN, J};
use super::Rule;
use crate::ad::rules::{check, plural};
use crate::catalog::Severity;
use crate::results::{Affected, CheckResult};

pub const STALE_DAYS: i64 = 90;

pub(crate) fn read_from(t: &Tenant) -> String {
    format!("Microsoft Graph, signed in as {}", t.raw.info.account)
}

pub(crate) fn tenant_item(t: &Tenant, reason: impl Into<String>) -> Affected {
    t.object("tenant", t.name.clone(), Some(t.id.clone()), reason)
}

fn yes_no(b: bool) -> &'static str {
    if b {
        "Yes"
    } else {
        "No"
    }
}

/// A directory setting value, from the settings object named `name`
/// (Group.Unified, Password Rule Settings...).
pub(crate) fn setting<'a>(t: &'a Tenant, name: &str, key: &str) -> Option<&'a str> {
    t.raw
        .list("groupsettings")
        .iter()
        .filter(|s| s.s("displayName") == Some(name))
        .flat_map(|s| s.a("values"))
        .find(|v| v.s("name") == Some(key))
        .and_then(|v| v.s("value"))
}

fn authz<'a>(t: &'a Tenant) -> Option<&'a Value> {
    t.raw.first("authorization")
}

fn user_perm(t: &Tenant, key: &str) -> Option<bool> {
    authz(t)?
        .at(&["defaultUserRolePermissions", key])?
        .as_bool()
}

/// A tenant-wide switch: fails when the default user permission is on.
fn user_permission(t: &Tenant, id: &str, key: &str, what: &str, expected: &str) -> CheckResult {
    let on = user_perm(t, key);
    let out = check(id)
        .expected(expected)
        .evidence("Read from", read_from(t));
    match on {
        Some(true) => out
            .affected(vec![tenant_item(t, format!("{what}: Yes"))], "tenant")
            .found(format!("{what}: Yes"))
            .done(),
        Some(false) => out.found(format!("{what}: No")).done(),
        None => out
            .not_assessed("The authorization policy does not include this setting.")
            .done(),
    }
}

// ---------- EN-TEN ----------

fn ten_001(t: &Tenant) -> CheckResult {
    let level = if !t.licences_known {
        "Unknown"
    } else if t.p2 {
        "Entra ID P2"
    } else if t.p1 {
        "Entra ID P1"
    } else {
        "Entra ID Free"
    };
    let domains = t.raw.list("domains");
    let verified: Vec<&str> = domains
        .iter()
        .filter(|d| d.b("isVerified") == Some(true))
        .filter_map(|d| d.s("id"))
        .collect();
    let org = t.raw.first("organization");
    let mut out = check("EN-TEN-001")
        .found(format!(
            "{level}, {}",
            plural(verified.len(), "verified domain", "verified domains")
        ))
        .evidence("Tenant", format!("{} ({})", t.name, t.id))
        .evidence("Licence level", level)
        .evidence("Verified domains", verified.join(", "));
    if let Some(o) = org {
        if let Some(c) = o.s("countryLetterCode") {
            out = out.evidence("Country", c);
        }
        if let Some(c) = o.s("createdDateTime") {
            out = out.evidence("Created", c.get(..10).unwrap_or(c));
        }
    }
    out.evidence("Read from", read_from(t)).done()
}

fn ten_003(t: &Tenant) -> CheckResult {
    user_permission(
        t,
        "EN-TEN-003",
        "allowedToCreateApps",
        "Users can register applications",
        "Only admins and developers given the Application Developer role register applications",
    )
}

fn ten_004(t: &Tenant) -> CheckResult {
    user_permission(
        t,
        "EN-TEN-004",
        "allowedToCreateTenants",
        "Users can create tenants",
        "Only admins create tenants",
    )
}

fn ten_005(t: &Tenant) -> CheckResult {
    user_permission(
        t,
        "EN-TEN-005",
        "allowedToCreateSecurityGroups",
        "Users can create security groups",
        "Only admins create security groups",
    )
}

const GUEST_SAME_AS_MEMBER: &str = "a0b1b346-4d3e-4e8b-98f8-753987be4970";
const GUEST_LIMITED: &str = "10dae51f-b6af-4016-8d66-8c2a99b929b3";
const GUEST_RESTRICTED: &str = "2af84b1e-32c8-42b7-82bc-daa82404023b";

fn ten_006(t: &Tenant) -> CheckResult {
    let Some(role) = authz(t).and_then(|a| a.s("guestUserRoleId")) else {
        return check("EN-TEN-006")
            .not_assessed("The authorization policy does not include the guest access level.")
            .done();
    };
    let (text, sev) = match role {
        GUEST_RESTRICTED => (
            "Restricted: guests see only their own directory objects",
            None,
        ),
        GUEST_LIMITED => (
            "Limited: guests can see members of groups they belong to and other objects they know",
            None,
        ),
        GUEST_SAME_AS_MEMBER => (
            "Same as members: guests can read the whole directory",
            Some(Severity::High),
        ),
        _ => ("A guest role this tool does not recognize", None),
    };
    let mut out = check("EN-TEN-006")
        .expected(
            "Guest access restricted to properties and memberships of their own directory objects",
        )
        .found(text)
        .evidence("guestUserRoleId", role)
        .evidence("Read from", read_from(t));
    if role != GUEST_RESTRICTED {
        out = out.affected(vec![tenant_item(t, text)], "tenant");
    }
    if let Some(s) = sev {
        out = out.severity(s);
    }
    out.done()
}

fn ten_007(t: &Tenant) -> CheckResult {
    let Some(from) = authz(t).and_then(|a| a.s("allowInvitesFrom")) else {
        return check("EN-TEN-007")
            .not_assessed("The authorization policy does not include the guest invite setting.")
            .done();
    };
    let text = match from {
        "everyone" => "Anyone in the organization, including guests, can invite guests",
        "adminsGuestInvitersAndAllMembers" => "Members and admins can invite guests",
        "adminsAndGuestInviters" => {
            "Only admins and users in the Guest Inviter role can invite guests"
        }
        "none" => "Nobody can invite guests",
        _ => "A setting this tool does not recognize",
    };
    let mut out = check("EN-TEN-007")
        .expected("Only admins and the Guest Inviter role invite guests, or members at most")
        .found(text)
        .evidence("allowInvitesFrom", from)
        .evidence("Read from", read_from(t));
    if from == "everyone" {
        out = out.affected(vec![tenant_item(t, text)], "tenant");
    }
    out.done()
}

fn all_allowed(v: Option<&Value>) -> bool {
    let Some(v) = v else { return false };
    let open = |side: &str| {
        v.o(side).is_some_and(|s| {
            s.s("accessType") == Some("allowed")
                && s.a("targets")
                    .iter()
                    .any(|x| matches!(x.s("target"), Some("AllUsers" | "AllApplications")))
        })
    };
    open("usersAndGroups") && open("applications")
}

fn ten_009(t: &Tenant) -> CheckResult {
    let Some(d) = t.raw.first("crosstenant") else {
        return check("EN-TEN-009")
            .not_assessed("The cross-tenant access defaults were empty.")
            .done();
    };
    let mut found = Vec::new();
    if all_allowed(d.o("b2bDirectConnectInbound")) {
        found.push("B2B direct connect is allowed inbound for all users and applications of every organization");
    }
    if d.at(&["automaticUserConsentSettings", "inboundAllowed"])
        .and_then(Value::as_bool)
        == Some(true)
    {
        found.push("Invitations from every organization are redeemed automatically");
    }
    let partners = t.raw.list("crosstenantpartners").len();
    let mut out = check("EN-TEN-009")
        .expected("Default settings block B2B direct connect and automatic redemption; trusted organizations are configured as partners")
        .evidence("Partner organizations configured", partners.to_string())
        .evidence("Read from", read_from(t));
    out = out.affected(
        found.iter().map(|f| tenant_item(t, *f)).collect(),
        "settings",
    );
    if found.is_empty() {
        out = out.found(
            "Defaults do not open B2B direct connect or automatic redemption to all organizations",
        );
    } else {
        out = out.found(found.join("; "));
    }
    out.done()
}

fn ten_011(t: &Tenant) -> CheckResult {
    user_permission(
        t,
        "EN-TEN-011",
        "allowedToReadOtherUsers",
        "Users can read other users",
        "Users cannot enumerate the directory (where business allows)",
    )
}

fn ten_014(t: &Tenant) -> CheckResult {
    let a = authz(t);
    let (Some(sub), Some(join)) = (
        a.and_then(|a| a.b("allowedToSignUpEmailBasedSubscriptions")),
        a.and_then(|a| a.b("allowEmailVerifiedUsersToJoinOrganization")),
    ) else {
        return check("EN-TEN-014")
            .not_assessed(
                "The authorization policy does not include the self-service sign-up settings.",
            )
            .done();
    };
    let mut list = Vec::new();
    if sub {
        list.push(tenant_item(
            t,
            "Users can sign up for email-based subscriptions",
        ));
    }
    if join {
        list.push(tenant_item(
            t,
            "Email-verified users can join the organization",
        ));
    }
    check("EN-TEN-014")
        .expected("Self-service sign-up and email-verified joins off")
        .found(format!(
            "Email-based subscriptions: {}; email-verified users can join: {}",
            yes_no(sub),
            yes_no(join)
        ))
        .affected(list, "settings")
        .evidence("Read from", read_from(t))
        .done()
}

fn ten_015(t: &Tenant) -> CheckResult {
    let Some(o) = t.raw.first("organization") else {
        return check("EN-TEN-015")
            .not_assessed("The organization object was empty.")
            .done();
    };
    let sec = o.strs("securityComplianceNotificationMails");
    let tech = o.strs("technicalNotificationMails");
    let missing = sec.is_empty() && tech.is_empty();
    let mut out = check("EN-TEN-015")
        .expected("A security or technical notification address that a monitored team reads")
        .found(if missing {
            "No security or technical notification address".to_string()
        } else {
            [("Security", &sec), ("Technical", &tech)]
                .iter()
                .filter(|(_, l)| !l.is_empty())
                .map(|(k, l)| format!("{k}: {}", l.join(", ")))
                .collect::<Vec<_>>()
                .join("; ")
        })
        .evidence("Read from", read_from(t));
    if missing {
        out = out.affected(vec![tenant_item(t, "No notification addresses")], "tenant");
    }
    out.done()
}

fn ten_017(t: &Tenant) -> CheckResult {
    let list: Vec<Affected> = t
        .raw
        .list("domains")
        .iter()
        .filter(|d| d.b("isVerified") == Some(false))
        .filter_map(|d| d.s("id"))
        .map(|d| t.object("domain", d, None, "Added but not verified"))
        .collect();
    check("EN-TEN-017")
        .expected("Every custom domain verified, or removed")
        .found(plural(
            list.len(),
            "unverified domain",
            "unverified domains",
        ))
        .affected(list, "domains")
        .evidence("Read from", read_from(t))
        .done()
}

fn ten_018(t: &Tenant) -> CheckResult {
    let list: Vec<Affected> = t
        .raw
        .list("domains")
        .iter()
        .filter(|d| d.s("authenticationType") == Some("Federated"))
        .filter_map(|d| d.s("id"))
        .map(|d| {
            t.object(
                "domain",
                d,
                None,
                "Sign-in is federated to an on-premises or third-party identity provider",
            )
        })
        .collect();
    check("EN-TEN-018")
        .expected("Managed (cloud) authentication for every domain")
        .found(plural(list.len(), "federated domain", "federated domains"))
        .affected(list, "domains")
        .evidence("Read from", read_from(t))
        .done()
}

// ---------- EN-ID ----------

fn enabled_members<'a>(t: &'a Tenant<'a>) -> impl Iterator<Item = &'a Value> + 'a {
    t.raw
        .list("users")
        .iter()
        .filter(|u| u.b("accountEnabled") == Some(true) && u.s("userType") != Some("Guest"))
}

fn id_001(t: &Tenant) -> CheckResult {
    let mut list = Vec::new();
    for u in enabled_members(t) {
        let last = t.last_signin(u);
        let created = t.days_since(u.t("createdDateTime")).unwrap_or(0);
        let reason = match t.days_since(last) {
            Some(d) if d > STALE_DAYS => format!("Last sign-in {d} days ago"),
            None if created > STALE_DAYS => format!("Never signed in; created {created} days ago"),
            _ => continue,
        };
        list.push(t.affected(u.s("id").unwrap_or_default(), reason));
    }
    check("EN-ID-001")
        .expected(format!(
            "Every enabled member account signed in within {STALE_DAYS} days, or disabled"
        ))
        .found(plural(list.len(), "stale account", "stale accounts"))
        .affected(list, "users")
        .evidence("Read from", read_from(t))
        .done()
}

fn id_002(t: &Tenant) -> CheckResult {
    let mut list = Vec::new();
    let activity = t.raw.read("signinactivity");
    for u in t
        .raw
        .list("users")
        .iter()
        .filter(|u| u.s("userType") == Some("Guest"))
    {
        let created = t.days_since(u.t("createdDateTime")).unwrap_or(0);
        let reason = if u.s("externalUserState") == Some("PendingAcceptance") && created > 30 {
            format!("Invitation not redeemed after {created} days")
        } else if activity && u.b("accountEnabled") == Some(true) {
            match t.days_since(t.last_signin(u)) {
                Some(d) if d > STALE_DAYS => format!("Last sign-in {d} days ago"),
                None if created > STALE_DAYS => {
                    format!("Never signed in; invited {created} days ago")
                }
                _ => continue,
            }
        } else {
            continue;
        };
        list.push(t.affected(u.s("id").unwrap_or_default(), reason));
    }
    let mut out = check("EN-ID-002")
        .expected("Guests that never redeemed or no longer sign in are removed")
        .found(plural(list.len(), "stale guest", "stale guests"))
        .affected(list, "guests")
        .evidence("Read from", read_from(t));
    if !activity {
        out = out.evidence(
            "Note",
            "Sign-in activity was not readable, so only unredeemed invitations are counted",
        );
    }
    out.done()
}

fn id_004(t: &Tenant) -> CheckResult {
    let mut list = Vec::new();
    for u in t
        .raw
        .list("users")
        .iter()
        .filter(|u| u.b("accountEnabled") == Some(false))
    {
        let id = u.s("id").unwrap_or_default();
        let roles: Vec<_> = t.holders.iter().filter(|h| h.principal == id).collect();
        let licences = u.a("assignedLicenses").len();
        let mut why = Vec::new();
        if !roles.is_empty() {
            why.push(format!("Holds {}", t.roles_text(&roles)));
        }
        if licences > 0 {
            why.push(plural(licences, "licence assigned", "licences assigned"));
        }
        if !why.is_empty() {
            list.push(t.affected(id, why.join("; ")));
        }
    }
    check("EN-ID-004")
        .expected("Disabled accounts hold no roles or licences")
        .found(plural(list.len(), "disabled account", "disabled accounts"))
        .affected(list, "users")
        .evidence("Read from", read_from(t))
        .done()
}

fn id_006(t: &Tenant) -> CheckResult {
    let members: Vec<&Value> = t
        .raw
        .list("users")
        .iter()
        .filter(|u| u.s("userType") != Some("Guest"))
        .collect();
    let synced = members
        .iter()
        .filter(|u| u.b("onPremisesSyncEnabled") == Some(true))
        .count();
    let guests = t.raw.list("users").len() - members.len();
    check("EN-ID-006")
        .found(format!(
            "{} synced from on-premises AD, {} cloud-only, {}",
            plural(synced, "member", "members"),
            members.len() - synced,
            plural(guests, "guest", "guests")
        ))
        .evidence("Synced members", synced.to_string())
        .evidence("Cloud-only members", (members.len() - synced).to_string())
        .evidence("Guests", guests.to_string())
        .evidence("Read from", read_from(t))
        .done()
}

fn id_012(t: &Tenant) -> CheckResult {
    let list: Vec<Affected> = t
        .raw
        .list("riskyusers")
        .iter()
        .filter(|r| r.s("riskState") == Some("atRisk"))
        .map(|r| {
            let id = r.s("id").unwrap_or_default();
            let mut a = t.affected(
                id,
                format!("Risk level {}", r.s("riskLevel").unwrap_or("unknown")),
            );
            if a.name == id {
                a.name = r.s("userPrincipalName").unwrap_or(id).to_string();
            }
            a
        })
        .collect();
    let high = t
        .raw
        .list("riskyusers")
        .iter()
        .any(|r| r.s("riskState") == Some("atRisk") && r.s("riskLevel") == Some("high"));
    let mut out = check("EN-ID-012")
        .expected("Every risky user remediated (password reset) or the risk dismissed after review")
        .found(plural(list.len(), "user at risk", "users at risk"))
        .affected(list, "users")
        .evidence("Read from", read_from(t));
    if high {
        out = out.severity(Severity::Critical);
    }
    out.done()
}

// ---------- EN-GRP ----------

fn grp_001(t: &Tenant) -> CheckResult {
    const CONTROLLED: [&str; 5] = [
        "user.displayname",
        "user.mail",
        "user.othermails",
        "user.userprincipalname",
        "user.proxyaddresses",
    ];
    let mut list = Vec::new();
    for g in t.raw.list("groups") {
        let Some(rule) = g.s("membershipRule") else {
            continue;
        };
        let lower = rule.to_lowercase();
        let used: Vec<&str> = CONTROLLED
            .iter()
            .copied()
            .filter(|a| lower.contains(a))
            .collect();
        if used.is_empty() || lower.contains("user.usertype -eq \"member\"") {
            continue;
        }
        let mut a = t.affected(
            g.s("id").unwrap_or_default(),
            format!("Rule uses {}", used.join(", ")),
        );
        a.location = Some(rule.to_string());
        list.push(a);
    }
    check("EN-GRP-001")
        .expected("Dynamic rules use attributes only admins set, or are limited to userType Member")
        .found(
            plural(list.len(), "dynamic group uses", "dynamic groups use")
                + " attributes users can change",
        )
        .affected(list, "groups")
        .evidence("Read from", read_from(t))
        .done()
}

fn grp_003(t: &Tenant) -> CheckResult {
    let mut list = Vec::new();
    for g in t.raw.list("groups") {
        let guests: Vec<&str> = g
            .a("owners")
            .iter()
            .filter(|o| {
                o.s("userType") == Some("Guest") || t.is_guest(o.s("id").unwrap_or_default())
            })
            .map(|o| {
                o.s("userPrincipalName")
                    .or(o.s("displayName"))
                    .unwrap_or("guest")
            })
            .collect();
        if !guests.is_empty() {
            list.push(t.affected(
                g.s("id").unwrap_or_default(),
                format!("Guest owner: {}", guests.join(", ")),
            ));
        }
    }
    check("EN-GRP-003")
        .expected("Group owners are members of the organization")
        .found(plural(list.len(), "group", "groups"))
        .affected(list, "groups")
        .evidence("Read from", read_from(t))
        .done()
}

fn grp_004(t: &Tenant) -> CheckResult {
    let value = setting(t, "Group.Unified", "EnableGroupCreation");
    let open = !value.is_some_and(|v| v.eq_ignore_ascii_case("false"));
    let mut out = check("EN-GRP-004")
        .expected("Microsoft 365 group creation limited to a security group of approved users")
        .found(match value {
            Some(v) if v.eq_ignore_ascii_case("false") => {
                "Limited to the allowed group".to_string()
            }
            Some(_) => "Any user can create Microsoft 365 groups".to_string(),
            None => "Not configured: any user can create Microsoft 365 groups".to_string(),
        })
        .evidence("Read from", read_from(t));
    if open {
        out = out.affected(
            vec![tenant_item(t, "Any user can create Microsoft 365 groups")],
            "tenant",
        );
    }
    out.done()
}

fn grp_006(t: &Tenant) -> CheckResult {
    let policies = t.raw.list("grouplifecycle");
    let mut out = check("EN-GRP-006")
        .expected("A group expiration policy for Microsoft 365 groups")
        .evidence("Read from", read_from(t));
    if policies.is_empty() {
        out = out
            .found("No expiration policy")
            .affected(vec![tenant_item(t, "No group expiration policy")], "tenant");
    } else {
        let p = &policies[0];
        out = out.found(format!(
            "Groups expire after {} days ({})",
            p.n("groupLifetimeInDays").unwrap_or(0),
            p.s("managedGroupTypes").unwrap_or("unknown")
        ));
    }
    out.done()
}

// ---------- EN-MON ----------

fn mon_012(t: &Tenant) -> CheckResult {
    let Some(s) = t.raw.first("securescore") else {
        return check("EN-MON-012")
            .not_assessed("Secure Score returned no data.")
            .done();
    };
    let current = s.get("currentScore").and_then(Value::as_f64).unwrap_or(0.0);
    let max = s.get("maxScore").and_then(Value::as_f64).unwrap_or(0.0);
    if max <= 0.0 {
        return check("EN-MON-012")
            .not_assessed("Secure Score has no maximum.")
            .done();
    }
    let pct = (current / max * 100.0).round();
    let mut out = check("EN-MON-012")
        .expected("At least 50 percent of the maximum Secure Score")
        .found(format!("{current:.0} of {max:.0} ({pct}%)"))
        .evidence(
            "Measured",
            s.s("createdDateTime")
                .unwrap_or_default()
                .get(..10)
                .unwrap_or_default(),
        )
        .evidence("Read from", read_from(t));
    if pct < 50.0 {
        out = out.affected(
            vec![tenant_item(t, format!("Secure Score {pct}%"))],
            "tenant",
        );
    }
    out.done()
}

// ---------- Hybrid settings held in Entra ----------

fn fed_006(t: &Tenant) -> CheckResult {
    let mut list = Vec::new();
    let configs = t.raw.list("federation");
    for c in configs {
        let domain = c.s("@dca.parent").unwrap_or("domain");
        let mfa = c
            .s("federatedIdpMfaBehavior")
            .unwrap_or("acceptIfMfaDoneByFederatedIdp");
        if mfa != "rejectMfaByFederatedIdp" {
            list.push(t.object(
                "domain",
                domain,
                None,
                format!("federatedIdpMfaBehavior is {mfa}"),
            ));
        }
    }
    let out = check("HY-FED-006")
        .expected(
            "federatedIdpMfaBehavior is rejectMfaByFederatedIdp, so Entra performs MFA itself",
        )
        .evidence("Read from", read_from(t));
    if t.raw
        .list("domains")
        .iter()
        .all(|d| d.s("authenticationType") != Some("Federated"))
    {
        return out.found("No federated domains").done();
    }
    out.found(format!(
        "{} the federation server's MFA claim",
        plural(list.len(), "domain trusts", "domains trust")
    ))
    .affected(list, "domains")
    .done()
}

fn sync_features<'a>(t: &'a Tenant) -> Option<&'a Value> {
    t.raw.first("onpremsync").and_then(|s| s.o("features"))
}

fn sync_002(t: &Tenant) -> CheckResult {
    let Some(org) = t.raw.first("organization") else {
        return check("HY-SYNC-002")
            .not_assessed("The organization object was empty.")
            .done();
    };
    let out = check("HY-SYNC-002")
        .expected("Directory synchronization ran within the last 24 hours")
        .evidence("Read from", read_from(t));
    if !t.synced() {
        return out
            .found("Directory synchronization is not enabled (cloud-only tenant)")
            .done();
    }
    let last = org.t("onPremisesLastSyncDateTime");
    let hours = last.map(|l| (t.now - l) / 3600);
    let found = match hours {
        Some(h) => format!("Last sync {h} hours before collection"),
        None => "No sync time recorded".to_string(),
    };
    let mut out = out.found(found.clone());
    if hours.is_none_or(|h| h > 24) {
        out = out.affected(vec![tenant_item(t, found)], "tenant");
    }
    out.done()
}

fn sync_011(t: &Tenant) -> CheckResult {
    let out = check("HY-SYNC-011")
        .expected("Soft match and hard-match takeover of cloud objects blocked")
        .evidence("Read from", read_from(t));
    if !t.synced() {
        return out
            .found("Directory synchronization is not enabled (cloud-only tenant)")
            .done();
    }
    let Some(f) = sync_features(t) else {
        return out
            .not_assessed("The directory synchronization features were empty.")
            .done();
    };
    let soft = f.b("blockSoftMatchEnabled").unwrap_or(false);
    let hard = f
        .b("blockCloudObjectTakeoverThroughHardMatchEnabled")
        .unwrap_or(false);
    let mut list = Vec::new();
    if !soft {
        list.push(tenant_item(
            t,
            "Soft match is allowed (blockSoftMatchEnabled is off)",
        ));
    }
    if !hard {
        list.push(tenant_item(t, "Hard match can take over cloud objects (blockCloudObjectTakeoverThroughHardMatchEnabled is off)"));
    }
    out.found(format!(
        "Soft match blocked: {}; hard-match takeover blocked: {}",
        yes_no(soft),
        yes_no(hard)
    ))
    .affected(list, "settings")
    .done()
}

// ---------- EN-DEV ----------

fn device_policy<'a>(t: &'a Tenant) -> Option<&'a Value> {
    t.raw.first("deviceregistration")
}

fn everyone(v: Option<&Value>) -> bool {
    v.and_then(|v| v.s("@odata.type")) == Some("#microsoft.graph.allDeviceRegistrationMembership")
}

fn dev_001(t: &Tenant) -> CheckResult {
    let Some(p) = device_policy(t) else {
        return check("EN-DEV-001")
            .not_assessed("The device registration policy was empty.")
            .done();
    };
    let all = everyone(p.at(&["azureADJoin", "allowedToJoin"]));
    let mut out = check("EN-DEV-001")
        .expected("Only selected users or groups can join devices to Entra ID")
        .found(if all {
            "All users can join devices"
        } else {
            "Limited to selected users or nobody"
        })
        .evidence("Read from", read_from(t));
    if all {
        out = out.affected(
            vec![tenant_item(t, "All users can join devices to Entra ID")],
            "tenant",
        );
    }
    out.done()
}

fn dev_003(t: &Tenant) -> CheckResult {
    let Some(p) = device_policy(t) else {
        return check("EN-DEV-003")
            .not_assessed("The device registration policy was empty.")
            .done();
    };
    let quota = p.n("userDeviceQuota").unwrap_or(50);
    let mut out = check("EN-DEV-003")
        .expected("20 devices per user or fewer")
        .found(format!("{quota} devices per user"))
        .evidence("Read from", read_from(t));
    if quota > 20 {
        out = out.affected(
            vec![tenant_item(
                t,
                format!("Users can register {quota} devices"),
            )],
            "tenant",
        );
    }
    out.done()
}

fn dev_004(t: &Tenant) -> CheckResult {
    let Some(p) = device_policy(t) else {
        return check("EN-DEV-004")
            .not_assessed("The device registration policy was empty.")
            .done();
    };
    let all = everyone(p.at(&["azureADJoin", "localAdmins", "registeringUsers"]));
    let mut out = check("EN-DEV-004")
        .expected("The registering user does not become local administrator (use Windows LAPS and a managed admin group)")
        .found(if all {
            "Every user who joins a device becomes its local administrator"
        } else {
            "Registering users are not all made local administrators"
        })
        .evidence("Read from", read_from(t));
    if all {
        out = out.affected(
            vec![tenant_item(
                t,
                "Registering users become local administrators",
            )],
            "tenant",
        );
    }
    out.done()
}

fn dev_005(t: &Tenant) -> CheckResult {
    let mut list = Vec::new();
    for d in t
        .raw
        .list("devices")
        .iter()
        .filter(|d| d.b("accountEnabled") == Some(true))
    {
        let Some(days) = t.days_since(d.t("approximateLastSignInDateTime")) else {
            continue;
        };
        if days > STALE_DAYS {
            list.push(Affected {
                last_seen: None,
                name: d.s("displayName").unwrap_or("device").to_string(),
                kind: "device".into(),
                location: d.s("operatingSystem").map(|o| {
                    format!("{o} {}", d.s("operatingSystemVersion").unwrap_or_default())
                        .trim()
                        .to_string()
                }),
                reason: Some(format!("Last activity {days} days ago")),
                object: d.s("id").map(str::to_string),
            });
        }
    }
    check("EN-DEV-005")
        .expected(format!(
            "Devices with no activity in {STALE_DAYS} days are disabled, then removed"
        ))
        .found(plural(list.len(), "stale device", "stale devices"))
        .affected(list, "devices")
        .evidence("Read from", read_from(t))
        .done()
}

fn dev_009(t: &Tenant) -> CheckResult {
    user_permission(
        t,
        "EN-DEV-009",
        "allowedToReadBitlockerKeysForOwnedDevice",
        "Users can read BitLocker keys of their own devices",
        "Only the help desk and admins read BitLocker recovery keys",
    )
}

fn dev_010(t: &Tenant) -> CheckResult {
    let Some(p) = device_policy(t) else {
        return check("EN-DEV-010")
            .not_assessed("The device registration policy was empty.")
            .done();
    };
    let on = p
        .at(&["localAdminPassword", "isEnabled"])
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let mut out = check("EN-DEV-010")
        .expected("Windows LAPS enabled in Entra device settings")
        .found(if on { "Enabled" } else { "Not enabled" })
        .evidence("Read from", read_from(t));
    if !on {
        out = out.affected(
            vec![tenant_item(
                t,
                "Windows LAPS is not enabled for Entra-joined devices",
            )],
            "tenant",
        );
    }
    out.done()
}

/// Global Administrator ids, for rules that single them out.
pub(crate) fn global_admins<'a>(t: &'a Tenant) -> Vec<&'a str> {
    let mut ids: Vec<&str> = t
        .holders_of(GLOBAL_ADMIN)
        .map(|h| h.principal.as_str())
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

pub static RULES: &[Rule] = &[
    Rule {
        id: "EN-TEN-001",
        needs: &["organization", "skus", "domains"],
        run: ten_001,
    },
    Rule {
        id: "EN-TEN-003",
        needs: &["authorization"],
        run: ten_003,
    },
    Rule {
        id: "EN-TEN-004",
        needs: &["authorization"],
        run: ten_004,
    },
    Rule {
        id: "EN-TEN-005",
        needs: &["authorization"],
        run: ten_005,
    },
    Rule {
        id: "EN-TEN-006",
        needs: &["authorization"],
        run: ten_006,
    },
    Rule {
        id: "EN-TEN-007",
        needs: &["authorization"],
        run: ten_007,
    },
    Rule {
        id: "EN-TEN-009",
        needs: &["crosstenant", "crosstenantpartners"],
        run: ten_009,
    },
    Rule {
        id: "EN-TEN-011",
        needs: &["authorization"],
        run: ten_011,
    },
    Rule {
        id: "EN-TEN-014",
        needs: &["authorization"],
        run: ten_014,
    },
    Rule {
        id: "EN-TEN-015",
        needs: &["organization"],
        run: ten_015,
    },
    Rule {
        id: "EN-TEN-017",
        needs: &["domains"],
        run: ten_017,
    },
    Rule {
        id: "EN-TEN-018",
        needs: &["domains"],
        run: ten_018,
    },
    Rule {
        id: "EN-ID-001",
        needs: &["users", "signinactivity"],
        run: id_001,
    },
    Rule {
        id: "EN-ID-002",
        needs: &["users"],
        run: id_002,
    },
    Rule {
        id: "EN-ID-004",
        needs: &["users", "roleassignments"],
        run: id_004,
    },
    Rule {
        id: "EN-ID-006",
        needs: &["users"],
        run: id_006,
    },
    Rule {
        id: "EN-ID-012",
        needs: &["riskyusers"],
        run: id_012,
    },
    Rule {
        id: "EN-GRP-001",
        needs: &["groups"],
        run: grp_001,
    },
    Rule {
        id: "EN-GRP-003",
        needs: &["groups", "groupowners"],
        run: grp_003,
    },
    Rule {
        id: "EN-GRP-004",
        needs: &["groupsettings"],
        run: grp_004,
    },
    Rule {
        id: "EN-GRP-006",
        needs: &["grouplifecycle"],
        run: grp_006,
    },
    Rule {
        id: "EN-MON-012",
        needs: &["securescore"],
        run: mon_012,
    },
    Rule {
        id: "HY-FED-006",
        needs: &["domains", "federation"],
        run: fed_006,
    },
    Rule {
        id: "HY-SYNC-002",
        needs: &["organization"],
        run: sync_002,
    },
    Rule {
        id: "HY-SYNC-011",
        needs: &["organization", "onpremsync"],
        run: sync_011,
    },
    Rule {
        id: "EN-DEV-001",
        needs: &["deviceregistration"],
        run: dev_001,
    },
    Rule {
        id: "EN-DEV-003",
        needs: &["deviceregistration"],
        run: dev_003,
    },
    Rule {
        id: "EN-DEV-004",
        needs: &["deviceregistration"],
        run: dev_004,
    },
    Rule {
        id: "EN-DEV-005",
        needs: &["devices"],
        run: dev_005,
    },
    Rule {
        id: "EN-DEV-009",
        needs: &["authorization"],
        run: dev_009,
    },
    Rule {
        id: "EN-DEV-010",
        needs: &["deviceregistration"],
        run: dev_010,
    },
];
