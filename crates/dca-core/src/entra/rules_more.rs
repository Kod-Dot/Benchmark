//! More Entra checks on data the Graph collector already reads: app
//! exposure, authentication settings, Conditional Access coverage and
//! hygiene, devices, groups, identities, privileged roles across Entra and
//! Azure, cross-tenant settings, and audit-log hunts.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use super::model::{PrincipalKind, Tenant, J};
use super::rules::{read_from, setting, tenant_item};
use super::rules_ca::{method, methods_policy, policies, Ca};
use super::rules_logs::{audit_check, logs, user_item};
use super::rules_priv::{risky_app_permissions, sp_item, RISKY_DELEGATED};
use super::Rule;
use crate::ad::rules::{check, plural};
use crate::results::{Affected, CheckResult};

const INTUNE_ADMIN: &str = "3a2c62db-5318-420d-8d74-23affee5d9d5";
const EXCHANGE_ADMIN: &str = "29232cdf-9323-42fd-ade2-1d097af3e4de";
const SHAREPOINT_ADMIN: &str = "f28a1f50-f6e7-4571-818b-6a12f2af6b6c";
const AZ_OWNER: &str = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635";
const AZ_USER_ACCESS_ADMIN: &str = "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9";
/// Roles excluded from an "All users" policy that are too big to exclude.
const BIG_EXCLUSION: usize = 5;
/// MFA denials for one account that look like push fatigue.
const FATIGUE_DENIALS: usize = 10;

fn is_break_glass(u: &Value) -> bool {
    let text = format!(
        "{} {}",
        u.s("userPrincipalName").unwrap_or_default(),
        u.s("displayName").unwrap_or_default()
    )
    .to_ascii_lowercase()
    .replace(['-', '_', '.', ' '], "");
    text.contains("breakglass") || text.contains("emergency")
}

fn guid_of(path: &str) -> String {
    path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase()
}

// ---------- Applications ----------

fn app_018(t: &Tenant) -> CheckResult {
    let risky = risky_app_permissions(t);
    let mut delegated: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for g in t.raw.list("grants") {
        if g.s("consentType") != Some("AllPrincipals") {
            continue;
        }
        let Some(client) = g.s("clientId") else {
            continue;
        };
        for scope in g.s("scope").unwrap_or_default().split_whitespace() {
            if RISKY_DELEGATED.contains(&scope) {
                delegated
                    .entry(client.to_string())
                    .or_default()
                    .insert(scope.to_string());
            }
        }
    }
    let mut list = Vec::new();
    for (id, sp) in &t.sps {
        if sp.b("appRoleAssignmentRequired") == Some(true) || sp.b("accountEnabled") == Some(false)
        {
            continue;
        }
        let mut perms: BTreeSet<String> = delegated.get(*id).cloned().unwrap_or_default();
        perms.extend(risky.get(*id).cloned().unwrap_or_default());
        if !perms.is_empty() {
            list.push(sp_item(
                t,
                id,
                format!(
                    "Any user can sign in to it, and it holds {}",
                    perms.into_iter().collect::<Vec<_>>().join(", ")
                ),
            ));
        }
    }
    list.sort_by(|a, b| a.name.cmp(&b.name));
    check("EN-APP-018")
        .expected("Apps with broad permissions require user assignment")
        .found(
            plural(list.len(), "app", "apps")
                + " with broad permissions and no assignment requirement",
        )
        .affected(list, "apps")
        .evidence("Read from", read_from(t))
        .done()
}

fn app_019(t: &Tenant) -> CheckResult {
    audit_check(
        t,
        "EN-APP-019",
        "app",
        "Consents in the last 30 days are only to known, verified apps",
        (
            "consent to an app from an unverified publisher",
            "consents to apps from unverified publishers",
        ),
        |e| {
            let act = e.s("activityDisplayName").unwrap_or_default();
            if !act.eq_ignore_ascii_case("Consent to application") {
                return false;
            }
            // Verified publishers and the tenant's own apps are expected.
            let app = e
                .a("targetResources")
                .first()
                .and_then(|r| r.s("id"))
                .and_then(|id| t.sps.get(id));
            !app.is_some_and(|sp| {
                sp.at(&["verifiedPublisher", "verifiedPublisherId"])
                    .is_some()
                    || sp.s("appOwnerOrganizationId") == Some(t.id.as_str())
            })
        },
    )
}

fn secret_like(text: &str) -> bool {
    let l = text.to_ascii_lowercase();
    [
        "password",
        "passwd",
        "pwd=",
        "secret",
        "client_secret",
        "apikey",
        "api key",
        "token=",
    ]
    .iter()
    .any(|w| l.contains(w))
}

fn app_022(t: &Tenant) -> CheckResult {
    let list: Vec<Affected> = t
        .raw
        .list("applications")
        .iter()
        .filter(|a| {
            a.s("notes").is_some_and(secret_like) || a.s("description").is_some_and(secret_like)
        })
        .map(|a| {
            t.object(
                "app",
                a.s("displayName").unwrap_or_default(),
                a.s("appId").map(|x| format!("App id {x}")),
                "Its notes or description mention a password or secret",
            )
        })
        .collect();
    check("EN-APP-022")
        .expected("App registrations do not hold credentials in their notes or description")
        .found(plural(list.len(), "app", "apps") + " with secret-like text")
        .affected(list, "apps")
        .evidence("Read from", read_from(t))
        .done()
}

// ---------- Authentication ----------

fn auth_005(t: &Tenant) -> CheckResult {
    let out = check("EN-AUTH-005")
        .expected("Authentication methods are managed in the authentication methods policy (migration complete)")
        .evidence("Read from", read_from(t));
    let Some(state) = methods_policy(t).and_then(|p| p.s("policyMigrationState")) else {
        return out
            .not_assessed("The authentication methods policy did not include its migration state.")
            .done();
    };
    if state == "migrationComplete" {
        out.found("Migration complete").done()
    } else {
        out.found(format!("Migration state: {state}"))
            .affected(
                vec![tenant_item(
                    t,
                    format!("Legacy per-user MFA and SSPR settings still apply ({state})"),
                )],
                "tenant",
            )
            .done()
    }
}

fn auth_009(t: &Tenant) -> CheckResult {
    let out = check("EN-AUTH-009")
        .expected("Certificate-based authentication, when on, uses strong user bindings")
        .evidence("Read from", read_from(t));
    let Some(m) = method(t, "X509Certificate") else {
        return out
            .found("Certificate-based authentication is not configured")
            .done();
    };
    if m.s("state") != Some("enabled") {
        return out.found("Certificate-based authentication is off").done();
    }
    let weak: Vec<String> = m
        .a("certificateUserBindings")
        .iter()
        .filter(|b| b.s("trustAffinityLevel") == Some("low"))
        .map(|b| {
            format!(
                "{} to {}",
                b.s("x509CertificateField").unwrap_or_default(),
                b.s("userProperty").unwrap_or_default()
            )
        })
        .collect();
    let list = if weak.is_empty() {
        Vec::new()
    } else {
        vec![tenant_item(
            t,
            format!("Low-affinity certificate bindings: {}", weak.join("; ")),
        )]
    };
    out.found(format!(
        "On, {}",
        plural(
            m.a("certificateUserBindings").len(),
            "user binding",
            "user bindings"
        )
    ))
    .affected(list, "tenant")
    .done()
}

fn auth_010(t: &Tenant) -> CheckResult {
    let reg = t.raw.list("registration");
    let members: Vec<&Value> = reg
        .iter()
        .filter(|r| {
            r.s("userType")
                .is_none_or(|u| u.eq_ignore_ascii_case("member"))
        })
        .collect();
    let capable = members
        .iter()
        .filter(|r| r.b("isSsprCapable") == Some(true))
        .count();
    let enabled = members
        .iter()
        .filter(|r| r.b("isSsprEnabled") == Some(true))
        .count();
    let admin_sspr = t
        .raw
        .first("authorization")
        .and_then(|a| a.b("allowedToUseSSPR"));
    let mut out = check("EN-AUTH-010")
        .expected("Self-service password reset is enabled and users are registered for it")
        .evidence("Read from", read_from(t));
    if let Some(a) = admin_sspr {
        out = out.evidence("Admins can use SSPR", if a { "Yes" } else { "No" });
    }
    let list = if !members.is_empty() && enabled == 0 {
        vec![tenant_item(t, "No user is enabled for self-service password reset: help desk resets are open to social engineering")]
    } else {
        Vec::new()
    };
    out.found(format!(
        "{enabled} of {} members enabled, {capable} registered and able to use it",
        members.len()
    ))
    .affected(list, "tenant")
    .done()
}

fn auth_018(t: &Tenant) -> CheckResult {
    let mut per_user: BTreeMap<(Option<&str>, Option<&str>), usize> = BTreeMap::new();
    for s in t.raw.list("signinsfailed") {
        if s.at(&["status", "errorCode"]).and_then(Value::as_i64) != Some(500121) {
            continue;
        }
        *per_user
            .entry((s.s("userId"), s.s("userPrincipalName")))
            .or_default() += 1;
    }
    let list: Vec<Affected> = per_user
        .into_iter()
        .filter(|(_, n)| *n >= FATIGUE_DENIALS)
        .map(|((id, upn), n)| {
            user_item(
                t,
                id,
                upn,
                format!("{n} MFA prompts denied or not answered in 30 days: someone may hold the password and be pushing prompts"),
            )
        })
        .collect();
    logs(t, "EN-AUTH-018", &["signinsfailed"])
        .expected(format!(
            "No account has {FATIGUE_DENIALS} or more failed MFA prompts in 30 days"
        ))
        .found(plural(list.len(), "account", "accounts") + " with repeated MFA denials")
        .affected(list, "accounts")
        .done()
}

fn auth_019(t: &Tenant) -> CheckResult {
    let out = check("EN-AUTH-019")
        .expected("Email one-time passcodes for guests are on (so guests without an Entra account get a verified sign-in)")
        .evidence("Read from", read_from(t));
    match method(t, "Email") {
        None => out
            .not_assessed(
                "The authentication methods policy did not include the email OTP settings.",
            )
            .done(),
        Some(m) => {
            let on = m.s("state") == Some("enabled");
            let guests = m.s("allowExternalIdToUseEmailOtp").unwrap_or("default");
            let list = if !on || guests == "disabled" {
                vec![tenant_item(
                    t,
                    format!(
                        "Email OTP state {}, for external IDs {guests}",
                        m.s("state").unwrap_or("unknown")
                    ),
                )]
            } else {
                Vec::new()
            };
            out.found(format!(
                "Email OTP {}; for external IDs: {guests}",
                m.s("state").unwrap_or("unknown")
            ))
            .affected(list, "tenant")
            .done()
        }
    }
}

// ---------- Conditional Access ----------

fn role_members(t: &Tenant, role: &str) -> usize {
    t.holders_of(role)
        .map(|h| h.principal.as_str())
        .collect::<BTreeSet<_>>()
        .len()
}

fn ca_017(t: &Tenant) -> CheckResult {
    let mut list = Vec::new();
    for p in policies(t).iter().filter(|p| p.enabled() && p.all_users()) {
        for role in p.users("excludeRoles") {
            let n = role_members(t, &t.template(role));
            if n > BIG_EXCLUSION {
                list.push(t.object(
                    "policy",
                    p.name(),
                    None,
                    format!(
                        "Excludes {} ({n} members): all of them skip this policy",
                        t.role_name(role)
                    ),
                ));
            }
        }
    }
    check("EN-CA-017")
        .expected(format!(
            "Policies for all users do not exclude roles with more than {BIG_EXCLUSION} members"
        ))
        .found(plural(list.len(), "broad exclusion", "broad exclusions"))
        .affected(list, "policies")
        .evidence("Read from", read_from(t))
        .done()
}

fn ca_018(t: &Tenant) -> CheckResult {
    let all = policies(t);
    let covering: Vec<&Ca> = all
        .iter()
        .filter(|p| p.enabled() && p.all_users() && p.all_apps() && p.all_clients() && p.mfa())
        .collect();
    let mut out = check("EN-CA-018")
        .expected("Every user is covered by an enforced MFA policy on all resources")
        .evidence("Read from", read_from(t));
    if covering.is_empty() {
        return out
            .found("No enforced policy requires MFA for all users on all resources")
            .affected(
                vec![tenant_item(t, "Users outside the policies that target specific groups, roles or apps sign in without MFA")],
                "tenant",
            )
            .done();
    }
    // Users and groups excluded from every covering policy are uncovered.
    let excluded = |key: &str| -> BTreeSet<&str> {
        let mut sets = covering
            .iter()
            .map(|p| p.users(key).into_iter().collect::<BTreeSet<_>>());
        let first = sets.next().unwrap_or_default();
        sets.fold(first, |acc, s| acc.intersection(&s).copied().collect())
    };
    let mut list: Vec<Affected> = excluded("excludeUsers")
        .into_iter()
        .filter(|id| *id != "GuestsOrExternalUsers")
        // Break-glass accounts are meant to be excluded; EN-CA-023 checks them.
        .filter(|id| !t.users.get(id).is_some_and(|u| is_break_glass(u)))
        .map(|id| {
            t.affected(
                id,
                "Excluded from every policy that requires MFA for everyone",
            )
        })
        .collect();
    list.extend(excluded("excludeGroups").into_iter().map(|g| {
        t.affected(g, "Group excluded from every policy that requires MFA for everyone: its members are not covered")
    }));
    out = out.evidence(
        "Covering policies",
        covering
            .iter()
            .map(|p| p.name())
            .collect::<Vec<_>>()
            .join(", "),
    );
    out.found(
        plural(list.len(), "principal is", "principals are")
            + " outside every all-users MFA policy",
    )
    .affected(list, "principals")
    .done()
}

/// What a policy applies to and requires, for comparing policies.
fn fingerprint(p: &Ca) -> String {
    let c = p.0.get("conditions").cloned().unwrap_or(Value::Null);
    let g = p.0.get("grantControls").cloned().unwrap_or(Value::Null);
    let s = p.0.get("sessionControls").cloned().unwrap_or(Value::Null);
    format!("{c}|{g}|{s}")
}

fn ca_020(t: &Tenant) -> CheckResult {
    let all = policies(t);
    let enabled: Vec<&Ca> = all.iter().filter(|p| p.enabled()).collect();
    let mut groups: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    for p in &enabled {
        groups.entry(fingerprint(p)).or_default().push(p.name());
    }
    let mut list: Vec<Affected> = groups
        .values()
        .filter(|names| names.len() > 1)
        .map(|names| {
            t.object(
                "policy",
                names.join(", "),
                None,
                "Identical conditions and controls: one of them is redundant",
            )
        })
        .collect();
    // Same users, apps and clients, one blocking and one granting access.
    let scope = |p: &Ca| {
        format!(
            "{}|{}|{}",
            p.0.at(&["conditions", "users"])
                .cloned()
                .unwrap_or(Value::Null),
            p.0.at(&["conditions", "applications"])
                .cloned()
                .unwrap_or(Value::Null),
            p.0.at(&["conditions", "clientAppTypes"])
                .cloned()
                .unwrap_or(Value::Null)
        )
    };
    for (i, a) in enabled.iter().enumerate() {
        for b in enabled.iter().skip(i + 1) {
            if a.blocks() != b.blocks()
                && scope(a) == scope(b)
                && a.0.at(&["conditions", "locations"]) == b.0.at(&["conditions", "locations"])
            {
                list.push(t.object(
                    "policy",
                    format!("{}, {}", a.name(), b.name()),
                    None,
                    "Same scope, one blocks and one grants: the block always wins, so the grant does nothing",
                ));
            }
        }
    }
    check("EN-CA-020")
        .expected("No two enabled policies are identical or contradict each other")
        .found(plural(
            list.len(),
            "redundant or conflicting set",
            "redundant or conflicting sets",
        ))
        .affected(list, "policies")
        .evidence("Read from", read_from(t))
        .done()
}

fn ca_021(t: &Tenant) -> CheckResult {
    let found: Vec<String> = policies(t)
        .iter()
        .filter(|p| p.enabled())
        .filter(|p| {
            !p.list(&[
                "conditions",
                "clientApplications",
                "includeServicePrincipals",
            ])
            .is_empty()
        })
        .map(|p| p.name().to_string())
        .collect();
    let tenant_apps = t
        .sps
        .values()
        .filter(|s| {
            s.s("appOwnerOrganizationId") == Some(t.id.as_str())
                && s.s("servicePrincipalType") == Some("Application")
        })
        .count();
    let list = if found.is_empty() && tenant_apps > 0 {
        vec![tenant_item(
            t,
            format!(
                "{} of the tenant's own sign in without any Conditional Access policy",
                plural(tenant_apps, "service principal", "service principals")
            ),
        )]
    } else {
        Vec::new()
    };
    check("EN-CA-021")
        .expected("A Conditional Access policy for workload identities restricts where service principals sign in from")
        .found(if found.is_empty() {
            "No policy targets service principals".to_string()
        } else {
            format!("Enforced by {}", found.join(", "))
        })
        .affected(list, "tenant")
        .evidence("Read from", read_from(t))
        .done()
}

fn ca_023(t: &Tenant) -> CheckResult {
    let glass: Vec<(&str, &Value)> = t
        .users
        .iter()
        .filter(|(_, u)| is_break_glass(u) && u.b("accountEnabled") != Some(false))
        .map(|(id, u)| (*id, *u))
        .collect();
    let out = check("EN-CA-023")
        .expected("Break-glass accounts are excluded from every policy that could lock them out")
        .evidence("Read from", read_from(t));
    if glass.is_empty() {
        return out
            .found("No account is named or described as break-glass or emergency")
            .affected(
                vec![tenant_item(t, "No break-glass account found to check")],
                "tenant",
            )
            .done();
    }
    let mut list = Vec::new();
    for (id, _) in &glass {
        let blocking: Vec<&str> = policies(t)
            .iter()
            .filter(|p| p.enabled() && (p.blocks() || p.mfa() || !p.grants().is_empty()))
            .filter(|p| {
                let included = p.all_users() || p.users("includeUsers").contains(id);
                included && !p.users("excludeUsers").contains(id)
            })
            .map(|p| p.name())
            .collect();
        if !blocking.is_empty() {
            list.push(t.affected(id, format!("Not excluded from {}", blocking.join(", "))));
        }
    }
    out.found(format!(
        "{}; {} not excluded everywhere",
        plural(glass.len(), "break-glass account", "break-glass accounts"),
        list.len()
    ))
    .affected(list, "accounts")
    .done()
}

fn ca_024(t: &Tenant) -> CheckResult {
    audit_check(
        t,
        "EN-CA-024",
        "policy",
        "Conditional Access changes in the last 30 days are all known",
        ("Conditional Access change", "Conditional Access changes"),
        |e| {
            e.s("activityDisplayName")
                .unwrap_or_default()
                .to_ascii_lowercase()
                .contains("conditional access policy")
        },
    )
}

// ---------- Devices ----------

fn intune(t: &Tenant) -> bool {
    t.raw.list("skus").iter().any(|s| {
        s.a("servicePlans").iter().any(|p| {
            p.s("servicePlanName")
                .is_some_and(|n| n.starts_with("INTUNE"))
        })
    })
}

fn dev_006(t: &Tenant) -> CheckResult {
    let out = check("EN-DEV-006")
        .expected("Every managed device reports a compliance state")
        .evidence("Read from", read_from(t));
    if !intune(t) {
        return out
            .found("No Intune licence: compliance is not reported")
            .done();
    }
    let list: Vec<Affected> = t
        .raw
        .list("devices")
        .iter()
        .filter(|d| d.b("accountEnabled") != Some(false))
        .filter(|d| d.get("isCompliant").is_none_or(Value::is_null))
        .map(|d| {
            t.object(
                "device",
                d.s("displayName").unwrap_or_default(),
                d.s("operatingSystem").map(str::to_string),
                "No compliance state: Conditional Access that requires a compliant device cannot rely on it",
            )
        })
        .collect();
    out.found(plural(list.len(), "device", "devices") + " without a compliance state")
        .affected(list, "devices")
        .done()
}

fn dev_007(t: &Tenant) -> CheckResult {
    let devices = t.raw.list("devices");
    let hybrid: Vec<&Value> = devices
        .iter()
        .filter(|d| d.s("trustType") == Some("ServerAd"))
        .collect();
    let list: Vec<Affected> = hybrid
        .iter()
        .filter(|d| d.get("registrationDateTime").is_none_or(Value::is_null))
        .map(|d| {
            t.object(
                "device",
                d.s("displayName").unwrap_or_default(),
                None,
                "Hybrid join pending: synced from AD but never registered, so device-based Conditional Access does not apply",
            )
        })
        .collect();
    check("EN-DEV-007")
        .expected("Hybrid-joined devices complete registration")
        .found(format!(
            "{} hybrid joined; {} pending",
            hybrid.len(),
            list.len()
        ))
        .affected(list, "devices")
        .evidence("Read from", read_from(t))
        .done()
}

fn dev_011(t: &Tenant) -> CheckResult {
    let out = check("EN-DEV-011")
        .expected("Only selected users can register (workplace join) personal devices")
        .evidence("Read from", read_from(t));
    let Some(p) = t.raw.first("deviceregistration") else {
        return out
            .not_assessed("The device registration policy was not returned.")
            .done();
    };
    let kind = p
        .at(&["azureADRegistration", "allowedToRegister", "@odata.type"])
        .and_then(Value::as_str)
        .unwrap_or_default();
    let all = kind.ends_with("allDeviceRegistrationMembership");
    let list = if all {
        vec![tenant_item(
            t,
            "Every user can register personal devices, which then count as known devices",
        )]
    } else {
        Vec::new()
    };
    out.found(if all {
        "All users can register devices"
    } else {
        "Registration is limited"
    })
    .affected(list, "tenant")
    .done()
}

// ---------- Groups ----------

fn owners(g: &Value) -> Vec<&Value> {
    g.a("owners").iter().collect()
}

fn grp_002(t: &Tenant) -> CheckResult {
    let role_groups: Vec<&Value> = t
        .groups
        .values()
        .copied()
        .filter(|g| g.b("isAssignableToRole") == Some(true))
        .collect();
    let privileged: BTreeSet<String> = t
        .privileged_principals()
        .into_iter()
        .map(|(p, _)| p)
        .collect();
    let mut list = Vec::new();
    for g in &role_groups {
        let outsiders: Vec<String> = owners(g)
            .iter()
            .filter_map(|o| o.s("id"))
            .filter(|o| !privileged.contains(*o))
            .map(|o| t.name_of(o))
            .collect();
        if !outsiders.is_empty() {
            list.push(t.object(
                "group",
                g.s("displayName").unwrap_or_default(),
                None,
                format!(
                    "Owned by non-admins ({}), who can add members and so grant its roles",
                    outsiders.join(", ")
                ),
            ));
        }
    }
    check("EN-GRP-002")
        .expected("Role-assignable groups are owned only by privileged admins")
        .found(format!(
            "{}; {} with non-admin owners",
            plural(
                role_groups.len(),
                "role-assignable group",
                "role-assignable groups"
            ),
            list.len()
        ))
        .affected(list, "groups")
        .evidence("Read from", read_from(t))
        .done()
}

fn grp_005(t: &Tenant) -> CheckResult {
    let mut roles: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    for h in &t.holders {
        if h.kind == PrincipalKind::Group && t.is_privileged(&h.role) {
            roles
                .entry(h.principal.as_str())
                .or_default()
                .insert(t.role_name(&h.role));
        }
    }
    let list: Vec<Affected> = roles
        .into_iter()
        .filter(|(g, _)| t.groups.get(g).is_some_and(|g| owners(g).is_empty()))
        .map(|(g, r)| {
            t.affected(
                g,
                format!(
                    "Grants {} and has no owner: nobody is accountable for its membership",
                    r.into_iter().collect::<Vec<_>>().join(", ")
                ),
            )
        })
        .collect();
    check("EN-GRP-005")
        .expected("Groups that grant privileged roles have named owners")
        .found(plural(list.len(), "group", "groups") + " without owners")
        .affected(list, "groups")
        .evidence("Read from", read_from(t))
        .done()
}

const SENSITIVE_WORDS: [&str; 10] = [
    "hr",
    "human resources",
    "finance",
    "payroll",
    "legal",
    "executive",
    "board",
    "admin",
    "security",
    "confidential",
];

fn grp_007(t: &Tenant) -> CheckResult {
    let list: Vec<Affected> = t
        .groups
        .values()
        .filter(|g| g.strs("groupTypes").contains(&"Unified") && g.s("visibility") == Some("Public"))
        .filter(|g| {
            let name = g.s("displayName").unwrap_or_default().to_ascii_lowercase();
            SENSITIVE_WORDS.iter().any(|w| {
                name.split(|c: char| !c.is_alphanumeric()).any(|part| part == *w) || (w.contains(' ') && name.contains(w))
            })
        })
        .map(|g| {
            t.object(
                "group",
                g.s("displayName").unwrap_or_default(),
                None,
                "Public Microsoft 365 group with a sensitive name: anyone in the tenant can join and read its files and mail",
            )
        })
        .collect();
    check("EN-GRP-007")
        .expected("Microsoft 365 groups for sensitive teams are private")
        .found(plural(list.len(), "public group", "public groups") + " with sensitive names")
        .affected(list, "groups")
        .evidence("Read from", read_from(t))
        .done()
}

fn grp_009(t: &Tenant) -> CheckResult {
    let v = setting(t, "Group.Unified", "EnableMIPLabels");
    let on = v.is_some_and(|v| v.eq_ignore_ascii_case("true"));
    check("EN-GRP-009")
        .expected("Sensitivity labels can be applied to Microsoft 365 groups and Teams")
        .found(format!("EnableMIPLabels: {}", v.unwrap_or("not set")))
        .affected(
            if on { Vec::new() } else { vec![tenant_item(t, "Sensitivity labels for groups are off: privacy and guest access are not controlled by label")] },
            "tenant",
        )
        .evidence("Read from", read_from(t))
        .done()
}

// ---------- Identities ----------

fn id_005(t: &Tenant) -> CheckResult {
    let list: Vec<Affected> = t
        .users
        .iter()
        .filter(|(_, u)| {
            u.b("accountEnabled") != Some(false) && u.b("onPremisesSyncEnabled") != Some(true)
        })
        .filter(|(_, u)| {
            u.s("passwordPolicies")
                .is_some_and(|p| p.contains("DisablePasswordExpiration"))
        })
        .map(|(id, _)| {
            t.affected(
                id,
                "Cloud password set never to expire, outside the tenant's password policy",
            )
        })
        .collect();
    check("EN-ID-005")
        .expected("Cloud accounts follow the tenant password policy (no per-user DisablePasswordExpiration)")
        .found(plural(list.len(), "account", "accounts") + " with a password that never expires")
        .affected(list, "accounts")
        .evidence("Read from", read_from(t))
        .done()
}

fn id_009(t: &Tenant) -> CheckResult {
    let list: Vec<Affected> = t
        .raw
        .list("exomailboxes")
        .iter()
        .filter(|m| {
            matches!(
                m.s("RecipientTypeDetails"),
                Some("SharedMailbox" | "RoomMailbox" | "EquipmentMailbox" | "SchedulingMailbox")
            )
        })
        .filter_map(|m| {
            let id = m.s("ExternalDirectoryObjectId")?;
            let u = t.users.get(id)?;
            (u.b("accountEnabled") == Some(true)).then(|| {
                t.affected(
                    id,
                    format!(
                        "{} with sign-in enabled: its password can be used to sign in",
                        m.s("RecipientTypeDetails").unwrap_or_default()
                    ),
                )
            })
        })
        .collect();
    check("EN-ID-009")
        .expected("Shared, room and equipment mailboxes cannot sign in")
        .found(
            plural(list.len(), "resource mailbox", "resource mailboxes") + " with sign-in enabled",
        )
        .affected(list, "mailboxes")
        .evidence("Read from", format!("{} and Exchange Online", read_from(t)))
        .done()
}

fn id_010(t: &Tenant) -> CheckResult {
    let list: Vec<Affected> = t
        .users
        .iter()
        .filter(|(_, u)| u.b("onPremisesSyncEnabled") != Some(true))
        .filter(|(_, u)| u.s("onPremisesImmutableId").is_some_and(|v| !v.is_empty()))
        .map(|(id, _)| {
            t.affected(
                id,
                "Cloud account with an on-premises immutable ID: an on-premises account with the same anchor can take it over at the next sync (hard match)",
            )
        })
        .collect();
    check("EN-ID-010")
        .expected("Cloud-only accounts have no on-premises immutable ID")
        .found(plural(list.len(), "account", "accounts") + " open to a hard match")
        .affected(list, "accounts")
        .evidence("Read from", read_from(t))
        .done()
}

fn id_014(t: &Tenant) -> CheckResult {
    let mut list = Vec::new();
    for (id, u) in &t.users {
        for e in u.a("onPremisesProvisioningErrors") {
            let prop = e.s("propertyCausingError").unwrap_or_default();
            if prop.eq_ignore_ascii_case("ProxyAddresses")
                || prop.eq_ignore_ascii_case("UserPrincipalName")
            {
                list.push(t.affected(
                    id,
                    format!(
                        "Sync conflict on {prop}: {}",
                        e.s("value").unwrap_or_default()
                    ),
                ));
            }
        }
    }
    // Proxy addresses claimed by more than one user.
    let mut owners: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    for (id, u) in &t.users {
        for a in u.strs("proxyAddresses") {
            owners.entry(a.to_ascii_lowercase()).or_default().push(id);
        }
    }
    for (addr, ids) in owners.into_iter().filter(|(_, v)| v.len() > 1) {
        for id in ids {
            list.push(t.affected(id, format!("Shares {addr} with another account")));
        }
    }
    check("EN-ID-014")
        .expected("No duplicate UPNs or proxy addresses")
        .found(plural(list.len(), "conflict", "conflicts"))
        .affected(list, "accounts")
        .evidence("Read from", read_from(t))
        .done()
}

fn id_015(t: &Tenant) -> CheckResult {
    let users: Vec<(&&str, &&Value)> = t
        .users
        .iter()
        .filter(|(_, u)| !u.a("licenseAssignmentStates").is_empty())
        .collect();
    let direct: Vec<Affected> = users
        .iter()
        .filter(|(_, u)| {
            u.a("licenseAssignmentStates")
                .iter()
                .any(|s| s.get("assignedByGroup").is_none_or(Value::is_null))
        })
        .map(|(id, _)| t.affected(id, "Has a directly assigned licence"))
        .collect();
    check("EN-ID-015")
        .expected("Licences are assigned through groups")
        .found(format!(
            "{} of {} licensed users have direct assignments",
            direct.len(),
            plural(users.len(), "user", "users")
        ))
        .severity(crate::catalog::Severity::Info)
        .affected(direct, "users")
        .evidence("Read from", read_from(t))
        .done()
}

// ---------- Privileged access ----------

fn priv_010(t: &Tenant) -> CheckResult {
    let exchange_plan = |u: &Value| !u.a("assignedLicenses").is_empty() && u.s("mail").is_some();
    let list: Vec<Affected> = t
        .privileged_principals()
        .into_iter()
        .filter_map(|(p, roles)| {
            let u = t.users.get(p.as_str())?;
            (exchange_plan(u)).then(|| {
                t.affected(
                    &p,
                    format!("Holds {} and also has a licensed mailbox: the same account reads email and administers", t.roles_text(&roles)),
                )
            })
        })
        .collect();
    check("EN-PRIV-010")
        .expected("Admins use dedicated accounts without mailboxes")
        .found(plural(list.len(), "admin uses", "admins use") + " their daily account")
        .affected(list, "accounts")
        .evidence("Read from", read_from(t))
        .done()
}

struct AzAssignment<'a> {
    principal: &'a str,
    role: String,
    scope: &'a str,
}

fn az_assignments<'a>(t: &Tenant<'a>) -> Vec<AzAssignment<'a>> {
    let mut seen = BTreeSet::new();
    t.raw
        .list("azroleassignments")
        .iter()
        .filter(|a| seen.insert(a.s("id").unwrap_or_default().to_string()))
        .filter_map(|a| {
            let p = a.o("properties")?;
            Some(AzAssignment {
                principal: p.s("principalId")?,
                role: guid_of(p.s("roleDefinitionId")?),
                scope: p.s("scope")?,
            })
        })
        .collect()
}

fn priv_015(t: &Tenant) -> CheckResult {
    let entra_admins: BTreeMap<String, String> = t
        .privileged_principals()
        .into_iter()
        .map(|(p, r)| (p, t.roles_text(&r)))
        .collect();
    let list: Vec<Affected> = az_assignments(t)
        .into_iter()
        .filter(|a| a.role == AZ_OWNER || a.role == AZ_USER_ACCESS_ADMIN)
        .filter_map(|a| {
            let roles = entra_admins.get(a.principal)?;
            Some(t.affected(
                a.principal,
                format!(
                    "{} on {} and {} in Entra: one account controls both",
                    if a.role == AZ_OWNER {
                        "Owner"
                    } else {
                        "User Access Administrator"
                    },
                    a.scope,
                    roles
                ),
            ))
        })
        .collect();
    check("EN-PRIV-015")
        .expected("Entra admins do not also hold Owner or User Access Administrator in Azure")
        .found(plural(list.len(), "assignment", "assignments"))
        .affected(list, "assignments")
        .evidence(
            "Read from",
            format!("{} and Azure Resource Manager", read_from(t)),
        )
        .done()
}

fn priv_016(t: &Tenant) -> CheckResult {
    let list: Vec<Affected> = az_assignments(t)
        .into_iter()
        .filter(|a| a.scope == "/" && a.role == AZ_USER_ACCESS_ADMIN)
        .map(|a| {
            t.affected(
                a.principal,
                "User Access Administrator at the root scope: \"Access management for Azure resources\" was turned on and not turned off",
            )
        })
        .collect();
    check("EN-PRIV-016")
        .expected("No one keeps root-scope User Access Administrator from elevate access")
        .found(plural(list.len(), "elevated account", "elevated accounts"))
        .affected(list, "accounts")
        .evidence(
            "Read from",
            "Azure role assignments at the root scope, through Azure Resource Manager",
        )
        .done()
}

fn priv_019(t: &Tenant) -> CheckResult {
    let mut list = Vec::new();
    for (g, members) in &t.group_members {
        let nested: Vec<String> = members
            .iter()
            .filter(|m| m.s("@odata.type") == Some("#microsoft.graph.group"))
            .map(|m| m.s("displayName").unwrap_or_default().to_string())
            .collect();
        if !nested.is_empty() {
            list.push(t.affected(
                g,
                format!("Holds roles through nested groups ({})", nested.join(", ")),
            ));
        }
        if t.groups
            .get(*g)
            .is_some_and(|x| x.s("membershipRule").is_some())
        {
            list.push(t.affected(
                g,
                "Dynamic membership: anyone whose attributes match gets its roles",
            ));
        }
    }
    check("EN-PRIV-019")
        .expected("Privileged roles are not reachable through nested or dynamic groups")
        .found(plural(list.len(), "group", "groups"))
        .affected(list, "groups")
        .evidence("Read from", read_from(t))
        .done()
}

fn priv_020(t: &Tenant) -> CheckResult {
    let mut lines = Vec::new();
    for (role, name) in [
        (INTUNE_ADMIN, "Intune Administrator"),
        (EXCHANGE_ADMIN, "Exchange Administrator"),
        (SHAREPOINT_ADMIN, "SharePoint Administrator"),
    ] {
        let holders: BTreeSet<String> = t
            .holders_of(role)
            .map(|h| t.name_of(&h.principal))
            .collect();
        lines.push(format!(
            "{name}: {}",
            if holders.is_empty() {
                "none".to_string()
            } else {
                holders.into_iter().collect::<Vec<_>>().join(", ")
            }
        ));
    }
    check("EN-PRIV-020")
        .expected("An inventory of Intune, Exchange and SharePoint administrators")
        .found(lines.join("; "))
        .raw(lines.join("\n"))
        .evidence("Read from", read_from(t))
        .done()
}

// ---------- Tenant ----------

fn ten_010(t: &Tenant) -> CheckResult {
    let out = check("EN-TEN-010")
        .expected("B2B direct connect is closed by default and cross-tenant sync is limited to known partners")
        .evidence("Read from", read_from(t));
    let Some(d) = t.raw.first("crosstenant") else {
        return out
            .not_assessed("The cross-tenant access defaults were not returned.")
            .done();
    };
    let mut list = Vec::new();
    for dir in ["b2bDirectConnectInbound", "b2bDirectConnectOutbound"] {
        let access = d
            .at(&[dir, "usersAndGroups", "accessType"])
            .and_then(Value::as_str);
        if access == Some("allowed") {
            list.push(tenant_item(
                t,
                format!("{dir} is allowed for every external tenant by default"),
            ));
        }
    }
    // Cross-tenant sync needs inbound automatic redemption for the source
    // tenant, so partners with it on are the ones that can push users in.
    let mut synced = Vec::new();
    for p in t.raw.list("crosstenantpartners") {
        let tenant = p.s("tenantId").unwrap_or_default();
        if p.at(&["automaticUserConsentSettings", "inboundAllowed"])
            .and_then(Value::as_bool)
            == Some(true)
        {
            synced.push(tenant.to_string());
        }
        if p.at(&["b2bDirectConnectInbound", "usersAndGroups", "accessType"])
            .and_then(Value::as_str)
            == Some("allowed")
        {
            list.push(tenant_item(
                t,
                format!("B2B direct connect inbound is allowed for partner tenant {tenant}"),
            ));
        }
    }
    out.found(format!(
        "{} open settings; {} partners can sync users in (automatic redemption on)",
        list.len(),
        synced.len()
    ))
    .raw(synced.join("\n"))
    .affected(list, "settings")
    .done()
}

// ---------- Hunting in audit logs ----------

fn hunt_015(t: &Tenant) -> CheckResult {
    audit_check(
        t,
        "HUNT-EN-015",
        "partner",
        "Partner (delegated admin) relationships did not change in the last 30 days without a request",
        ("partner relationship change", "partner relationship changes"),
        |e| {
            let a = e.s("activityDisplayName").unwrap_or_default().to_ascii_lowercase();
            a.contains("partner") || a.contains("delegated admin")
        },
    )
}

fn hunt_016(t: &Tenant) -> CheckResult {
    let list: Vec<Affected> = az_assignments(t)
        .into_iter()
        .filter(|a| a.scope == "/")
        .map(|a| {
            t.affected(
                a.principal,
                format!("Role {} assigned at the root scope: it covers every subscription and management group", a.role),
            )
        })
        .collect();
    check("HUNT-EN-016")
        .expected("No role assignments at the Azure root scope")
        .found(plural(
            list.len(),
            "root-scope assignment",
            "root-scope assignments",
        ))
        .affected(list, "assignments")
        .evidence(
            "Read from",
            "Azure role assignments through Azure Resource Manager",
        )
        .done()
}

const GRAPH: &[&str] = &["users", "roleassignments"];

pub static RULES: &[Rule] = &[
    Rule {
        id: "EN-APP-018",
        needs: &["serviceprincipals", "approleassignments", "grants"],
        run: app_018,
    },
    Rule {
        id: "EN-APP-019",
        needs: &["audits", "serviceprincipals"],
        run: app_019,
    },
    Rule {
        id: "EN-APP-022",
        needs: &["applications"],
        run: app_022,
    },
    Rule {
        id: "EN-AUTH-005",
        needs: &["authmethods"],
        run: auth_005,
    },
    Rule {
        id: "EN-AUTH-009",
        needs: &["authmethods"],
        run: auth_009,
    },
    Rule {
        id: "EN-AUTH-010",
        needs: &["registration", "authorization"],
        run: auth_010,
    },
    Rule {
        id: "EN-AUTH-018",
        needs: &["signinsfailed"],
        run: auth_018,
    },
    Rule {
        id: "EN-AUTH-019",
        needs: &["authmethods"],
        run: auth_019,
    },
    Rule {
        id: "EN-CA-017",
        needs: &["capolicies", "roleassignments"],
        run: ca_017,
    },
    Rule {
        id: "EN-CA-018",
        needs: &["capolicies", "users"],
        run: ca_018,
    },
    Rule {
        id: "EN-CA-020",
        needs: &["capolicies"],
        run: ca_020,
    },
    Rule {
        id: "EN-CA-021",
        needs: &["capolicies", "serviceprincipals"],
        run: ca_021,
    },
    Rule {
        id: "EN-CA-023",
        needs: &["capolicies", "users"],
        run: ca_023,
    },
    Rule {
        id: "EN-CA-024",
        needs: &["audits"],
        run: ca_024,
    },
    Rule {
        id: "EN-DEV-006",
        needs: &["devices", "skus"],
        run: dev_006,
    },
    Rule {
        id: "EN-DEV-007",
        needs: &["devices"],
        run: dev_007,
    },
    Rule {
        id: "EN-DEV-011",
        needs: &["deviceregistration"],
        run: dev_011,
    },
    Rule {
        id: "EN-GRP-002",
        needs: &["groups", "groupowners", "roleassignments"],
        run: grp_002,
    },
    Rule {
        id: "EN-GRP-005",
        needs: &["groups", "groupowners", "roleassignments"],
        run: grp_005,
    },
    Rule {
        id: "EN-GRP-007",
        needs: &["groups"],
        run: grp_007,
    },
    Rule {
        id: "EN-GRP-009",
        needs: &["groupsettings"],
        run: grp_009,
    },
    Rule {
        id: "EN-ID-005",
        needs: &["users"],
        run: id_005,
    },
    Rule {
        id: "EN-ID-009",
        needs: &["users", "exomailboxes"],
        run: id_009,
    },
    Rule {
        id: "EN-ID-010",
        needs: &["users"],
        run: id_010,
    },
    Rule {
        id: "EN-ID-014",
        needs: &["users"],
        run: id_014,
    },
    Rule {
        id: "EN-ID-015",
        needs: &["users"],
        run: id_015,
    },
    Rule {
        id: "EN-PRIV-010",
        needs: GRAPH,
        run: priv_010,
    },
    Rule {
        id: "EN-PRIV-015",
        needs: &["users", "roleassignments", "azroleassignments"],
        run: priv_015,
    },
    Rule {
        id: "EN-PRIV-016",
        needs: &["azroleassignments"],
        run: priv_016,
    },
    Rule {
        id: "EN-PRIV-019",
        needs: &["groups", "roleassignments"],
        run: priv_019,
    },
    Rule {
        id: "EN-PRIV-020",
        needs: GRAPH,
        run: priv_020,
    },
    Rule {
        id: "EN-TEN-010",
        needs: &["crosstenant", "crosstenantpartners"],
        run: ten_010,
    },
    Rule {
        id: "HUNT-EN-015",
        needs: &["audits"],
        run: hunt_015,
    },
    Rule {
        id: "HUNT-EN-016",
        needs: &["azroleassignments"],
        run: hunt_016,
    },
];
