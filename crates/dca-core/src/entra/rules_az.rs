//! Azure resources, read from Azure Resource Manager: role assignments at
//! the root, management group and subscription scopes, custom roles,
//! Defender for Cloud, activity log export, Lighthouse delegations,
//! storage accounts and Key Vaults.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use super::model::{Tenant, J};
use super::Rule;
use crate::ad::rules::{check, plural, Out};
use crate::results::{Affected, CheckResult};

pub(crate) const OWNER: &str = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635";
pub(crate) const CONTRIBUTOR: &str = "b24988ac-6180-42a0-ab88-20f7382dd24c";
pub(crate) const USER_ACCESS_ADMIN: &str = "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9";
pub(crate) const RBAC_ADMIN: &str = "f58310d9-a9f6-439a-9e8d-f62e7b41a168";
pub(crate) const KV_ADMIN: &str = "00482a5a-887f-4fb3-b363-3b7fe8e74483";
pub(crate) const KV_SECRETS_OFFICER: &str = "b86a8fe4-44ce-4948-aee5-eccb2c155cd7";
pub(crate) const KV_SECRETS_USER: &str = "4633458b-17de-408a-b874-0445c86b69e6";
/// The Microsoft cloud security benchmark initiative.
const MCSB: &str = "1f3afdf9-d0c9-4c3d-847f-89da613e70a8";

/// Defender for Cloud plans every subscription with workloads should run.
const PLANS: [&str; 6] = [
    "VirtualMachines",
    "SqlServers",
    "StorageAccounts",
    "KeyVaults",
    "Arm",
    "Containers",
];

pub(crate) fn role_name(id: &str) -> &'static str {
    match id {
        OWNER => "Owner",
        CONTRIBUTOR => "Contributor",
        USER_ACCESS_ADMIN => "User Access Administrator",
        RBAC_ADMIN => "Role Based Access Control Administrator",
        KV_ADMIN => "Key Vault Administrator",
        KV_SECRETS_OFFICER => "Key Vault Secrets Officer",
        KV_SECRETS_USER => "Key Vault Secrets User",
        _ => "",
    }
}

/// Roles that can change who has access (or do everything).
pub(crate) fn controls_access(role: &str) -> bool {
    matches!(role, OWNER | USER_ACCESS_ADMIN | RBAC_ADMIN)
}

pub(crate) fn arm(t: &Tenant, id: &str) -> Out {
    check(id).evidence(
        "Read from",
        format!(
            "Azure Resource Manager, signed in as {}",
            t.raw.info.account
        ),
    )
}

/// One role assignment, flattened.
pub(crate) struct Assignment<'a> {
    pub principal: &'a str,
    pub kind: &'a str,
    pub role: String,
    pub scope: &'a str,
}

/// The role definition GUID at the end of a roleDefinitionId.
pub(crate) fn role_guid(id: &str) -> String {
    id.rsplit('/').next().unwrap_or(id).to_ascii_lowercase()
}

pub(crate) fn assignments<'a>(t: &'a Tenant, area: &str) -> Vec<Assignment<'a>> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for a in t.raw.list(area) {
        let Some(p) = a.o("properties") else { continue };
        let key = a.s("id").unwrap_or_default();
        if !key.is_empty() && !seen.insert(key) {
            continue;
        }
        let (Some(principal), Some(role), Some(scope)) =
            (p.s("principalId"), p.s("roleDefinitionId"), p.s("scope"))
        else {
            continue;
        };
        out.push(Assignment {
            principal,
            kind: p.s("principalType").unwrap_or("Unknown"),
            role: role_guid(role),
            scope,
        });
    }
    out
}

pub(crate) fn is_root(scope: &str) -> bool {
    scope == "/"
}

pub(crate) fn is_mg(scope: &str) -> bool {
    scope
        .to_ascii_lowercase()
        .starts_with("/providers/microsoft.management/managementgroups/")
}

/// Root, management group or a whole subscription.
pub(crate) fn is_broad(scope: &str) -> bool {
    is_root(scope)
        || is_mg(scope)
        || (scope.starts_with("/subscriptions/") && scope.matches('/').count() == 2)
}

pub(crate) fn scope_text(t: &Tenant, scope: &str) -> String {
    if is_root(scope) {
        return "root (/)".into();
    }
    if is_mg(scope) {
        let name = scope.rsplit('/').next().unwrap_or(scope);
        let display = t
            .raw
            .list("azmgmtgroups")
            .iter()
            .find(|g| g.s("name") == Some(name))
            .and_then(|g| g.at(&["properties", "displayName"]))
            .and_then(Value::as_str);
        return format!("management group {}", display.unwrap_or(name));
    }
    if let Some(rest) = scope.strip_prefix("/subscriptions/") {
        let sub = rest.split('/').next().unwrap_or(rest);
        let name = sub_name(t, sub);
        return if rest.contains('/') {
            format!(
                "{} in subscription {name}",
                rest.split_once('/').map_or("", |x| x.1)
            )
        } else {
            format!("subscription {name}")
        };
    }
    scope.to_string()
}

pub(crate) fn sub_name(t: &Tenant, id: &str) -> String {
    t.raw
        .list("azsubscriptions")
        .iter()
        .find(|s| s.s("subscriptionId") == Some(id))
        .and_then(|s| s.s("displayName"))
        .unwrap_or(id)
        .to_string()
}

fn custom_role_name(t: &Tenant, guid: &str) -> Option<String> {
    t.raw
        .list("azroledefinitions")
        .iter()
        .find(|d| d.s("name").is_some_and(|n| n.eq_ignore_ascii_case(guid)))
        .and_then(|d| d.at(&["properties", "roleName"]))
        .and_then(Value::as_str)
        .map(str::to_string)
}

pub(crate) fn role_label(t: &Tenant, guid: &str) -> String {
    let n = role_name(guid);
    if !n.is_empty() {
        return n.to_string();
    }
    custom_role_name(t, guid).unwrap_or_else(|| format!("role {guid}"))
}

pub(crate) fn principal_item(t: &Tenant, a: &Assignment, reason: String) -> Affected {
    if t.principal(a.principal).is_some() {
        t.affected(a.principal, reason)
    } else {
        t.object("account", a.principal, Some(a.kind.to_string()), reason)
    }
}

pub(crate) fn subscriptions<'a>(t: &'a Tenant) -> Vec<&'a Value> {
    t.raw
        .list("azsubscriptions")
        .iter()
        .filter(|s| s.s("state") == Some("Enabled"))
        .collect()
}

pub(crate) fn sub_item(t: &Tenant, s: &Value, reason: impl Into<String>) -> Affected {
    t.object(
        "subscription",
        s.s("displayName").unwrap_or("(subscription)"),
        s.s("subscriptionId").map(str::to_string),
        reason,
    )
}

/// Items of an area read per subscription, for one subscription.
pub(crate) fn for_sub<'a>(t: &'a Tenant, area: &str, sub: &str) -> Vec<&'a Value> {
    t.raw
        .list(area)
        .iter()
        .filter(|v| v.s("@dca.parent") == Some(sub))
        .collect()
}

pub(crate) fn prop<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    v.at(&["properties", key])
}

pub(crate) fn prop_b(v: &Value, key: &str) -> Option<bool> {
    prop(v, key).and_then(Value::as_bool)
}

pub(crate) fn prop_s<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    prop(v, key).and_then(Value::as_str)
}

// ---------- Role assignments ----------

fn rbac_001(t: &Tenant) -> CheckResult {
    let root_mg = format!("/providers/Microsoft.Management/managementGroups/{}", t.id);
    let affected: Vec<Affected> = assignments(t, "azroleassignments")
        .iter()
        .filter(|a| is_root(a.scope) || a.scope.eq_ignore_ascii_case(&root_mg))
        .map(|a| {
            principal_item(
                t,
                a,
                format!("{} at {}", role_label(t, &a.role), scope_text(t, a.scope)),
            )
        })
        .collect();
    let n = affected.len();
    arm(t, "AZ-RBAC-001")
        .expected("No standing role assignment at the root (/) or the tenant root management group")
        .affected(affected, "assignments")
        .found(plural(
            n,
            "assignment at the root",
            "assignments at the root",
        ))
        .evidence(
            "Management groups",
            t.raw.list("azmgmtgroups").len().to_string(),
        )
        .done()
}

fn rbac_002(t: &Tenant) -> CheckResult {
    let all = assignments(t, "azroleassignments");
    let privileged = |r: &str| matches!(r, OWNER | CONTRIBUTOR | USER_ACCESS_ADMIN | RBAC_ADMIN);
    let affected: Vec<Affected> = all
        .iter()
        .filter(|a| privileged(&a.role) && (is_root(a.scope) || is_mg(a.scope)))
        .map(|a| {
            principal_item(
                t,
                a,
                format!(
                    "{} at {}, inherited by every subscription below",
                    role_label(t, &a.role),
                    scope_text(t, a.scope)
                ),
            )
        })
        .collect();
    let mut per_sub: BTreeMap<String, usize> = BTreeMap::new();
    for a in all.iter().filter(|a| {
        privileged(&a.role) && is_broad(a.scope) && !is_root(a.scope) && !is_mg(a.scope)
    }) {
        *per_sub.entry(scope_text(t, a.scope)).or_default() += 1;
    }
    let n = affected.len();
    arm(t, "AZ-RBAC-002")
        .expected("Owner, Contributor and access administration roles are granted at subscription scope or below, not at management group or root scope")
        .affected(affected, "assignments")
        .found(plural(
            n,
            "privileged assignment at management group or root scope",
            "privileged assignments at management group or root scope",
        ))
        .evidence(
            "Privileged assignments per subscription",
            if per_sub.is_empty() {
                "None".to_string()
            } else {
                per_sub
                    .iter()
                    .map(|(s, c)| format!("{s}: {c}"))
                    .collect::<Vec<_>>()
                    .join("; ")
            },
        )
        .done()
}

fn rbac_003(t: &Tenant) -> CheckResult {
    let eligible = assignments(t, "azeligible").len();
    let mut seen = BTreeSet::new();
    let affected: Vec<Affected> = t
        .raw
        .list("azactive")
        .iter()
        .filter_map(|s| s.o("properties"))
        .filter(|p| {
            p.s("assignmentType") == Some("Assigned")
                && p.s("endDateTime").is_none_or(str::is_empty)
                && p.s("principalType") == Some("User")
        })
        .filter_map(|p| {
            let role = role_guid(p.s("roleDefinitionId")?);
            let scope = p.s("scope")?;
            let principal = p.s("principalId")?;
            (matches!(
                role.as_str(),
                OWNER | CONTRIBUTOR | USER_ACCESS_ADMIN | RBAC_ADMIN
            ) && is_broad(scope)
                && seen.insert((principal, role.clone(), scope)))
            .then(|| {
                t.affected(
                    principal,
                    format!(
                        "Permanent {} at {}",
                        role_label(t, &role),
                        scope_text(t, scope)
                    ),
                )
            })
        })
        .collect();
    let n = affected.len();
    arm(t, "AZ-RBAC-003")
        .expected("Users hold Owner, Contributor and access administration roles through PIM eligibility, not permanent assignments")
        .affected(affected, "assignments")
        .found(plural(
            n,
            "permanent privileged assignment to a user",
            "permanent privileged assignments to users",
        ))
        .evidence("PIM eligible assignments", eligible.to_string())
        .done()
}

fn rbac_004(t: &Tenant) -> CheckResult {
    let mut affected = Vec::new();
    for (area, how) in [("azroleassignments", "active"), ("azeligible", "eligible")] {
        for a in assignments(t, area)
            .iter()
            .filter(|a| t.is_guest(a.principal))
        {
            affected.push(t.affected(
                a.principal,
                format!(
                    "Guest with {} {} at {}",
                    how,
                    role_label(t, &a.role),
                    scope_text(t, a.scope)
                ),
            ));
        }
    }
    let n = affected.len();
    arm(t, "AZ-RBAC-004")
        .expected("Guests hold no Azure role assignments")
        .affected(affected, "assignments")
        .found(plural(n, "guest assignment", "guest assignments"))
        .done()
}

fn rbac_005(t: &Tenant) -> CheckResult {
    let affected: Vec<Affected> = assignments(t, "azroleassignments")
        .iter()
        .filter(|a| a.kind == "ServicePrincipal" && controls_access(&a.role) && is_broad(a.scope))
        .map(|a| {
            principal_item(
                t,
                a,
                format!("{} at {}", role_label(t, &a.role), scope_text(t, a.scope)),
            )
        })
        .collect();
    let n = affected.len();
    arm(t, "AZ-RBAC-005")
        .expected("No service principal or managed identity holds Owner or an access administration role on a subscription or above")
        .affected(affected, "assignments")
        .found(plural(
            n,
            "application or managed identity that can grant access",
            "applications or managed identities that can grant access",
        ))
        .done()
}

fn rbac_006(t: &Tenant) -> CheckResult {
    let risky = |action: &str| {
        let a = action.to_ascii_lowercase();
        a == "*"
            || a == "*/write"
            || a.starts_with("microsoft.authorization/*")
            || a == "microsoft.authorization/roleassignments/write"
            || a == "microsoft.authorization/roledefinitions/write"
    };
    let mut affected = Vec::new();
    for d in t.raw.list("azroledefinitions") {
        let name = prop_s(d, "roleName").unwrap_or("(custom role)");
        let mut found: Vec<String> = Vec::new();
        for p in prop(d, "permissions")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let not: Vec<&str> = p.strs("notActions");
            for a in p.strs("actions") {
                if risky(a) && !not.iter().any(|n| n.eq_ignore_ascii_case(a)) {
                    found.push(a.to_string());
                }
            }
        }
        found.sort();
        found.dedup();
        if !found.is_empty() {
            affected.push(t.object(
                "azrole",
                name,
                d.s("name").map(str::to_string),
                format!("Allows {}", found.join(", ")),
            ));
        }
    }
    let n = affected.len();
    arm(t, "AZ-RBAC-006")
        .expected("No custom role allows every action or writing role assignments and definitions")
        .affected(affected, "roles")
        .found(format!(
            "{} of {}",
            plural(n, "custom role", "custom roles"),
            t.raw.list("azroledefinitions").len()
        ))
        .done()
}

fn rbac_008(t: &Tenant) -> CheckResult {
    let known = |id: &str| t.principal(id).is_some();
    let affected: Vec<Affected> = assignments(t, "azroleassignments")
        .iter()
        .filter(|a| a.kind != "ForeignGroup" && !known(a.principal))
        .map(|a| {
            t.object(
                "account",
                a.principal,
                Some(a.kind.to_string()),
                format!(
                    "{} at {}: the principal no longer exists",
                    role_label(t, &a.role),
                    scope_text(t, a.scope)
                ),
            )
        })
        .collect();
    let n = affected.len();
    arm(t, "AZ-RBAC-008")
        .expected("Every role assignment points to an existing user, group or application")
        .affected(affected, "assignments")
        .found(plural(n, "orphaned assignment", "orphaned assignments"))
        .done()
}

fn rbac_009(t: &Tenant) -> CheckResult {
    let all = assignments(t, "azroleassignments");
    let subs = subscriptions(t);
    let mut affected = Vec::new();
    for s in &subs {
        let id = s.s("subscriptionId").unwrap_or_default();
        let path = format!("/subscriptions/{id}");
        let owners = all
            .iter()
            .filter(|a| {
                a.role == OWNER
                    && (a.scope.eq_ignore_ascii_case(&path) || is_root(a.scope) || is_mg(a.scope))
            })
            .count();
        let emails = for_sub(t, "azcontacts", id)
            .iter()
            .any(|c| prop_s(c, "emails").is_some_and(|e| !e.trim().is_empty()));
        let mut missing = Vec::new();
        if owners == 0 {
            missing.push("no Owner");
        }
        if !emails {
            missing.push("no security contact email");
        }
        if !missing.is_empty() {
            affected.push(sub_item(t, s, missing.join(", ")));
        }
    }
    let n = affected.len();
    arm(t, "AZ-RBAC-009")
        .expected("Every subscription has an Owner and a Defender for Cloud security contact")
        .affected(affected, "subscriptions")
        .found(format!(
            "{} of {} missing an owner or security contact",
            plural(n, "subscription", "subscriptions"),
            subs.len()
        ))
        .done()
}

fn rbac_011(t: &Tenant) -> CheckResult {
    let subs = subscriptions(t);
    let mut affected = Vec::new();
    let mut total = 0;
    for s in &subs {
        let id = s.s("subscriptionId").unwrap_or_default();
        let list = for_sub(t, "azpolicies", id);
        total += list.len();
        let mcsb = list.iter().any(|p| {
            prop_s(p, "policyDefinitionId").is_some_and(|d| d.to_ascii_lowercase().ends_with(MCSB))
        });
        if !mcsb {
            affected.push(sub_item(
                t,
                s,
                format!(
                    "Microsoft cloud security benchmark not assigned; {}",
                    plural(list.len(), "policy assignment", "policy assignments")
                ),
            ));
        }
    }
    let n = affected.len();
    arm(t, "AZ-RBAC-011")
        .expected("The Microsoft cloud security benchmark initiative applies to every subscription")
        .affected(affected, "subscriptions")
        .found(format!(
            "{} of {} without the benchmark",
            plural(n, "subscription", "subscriptions"),
            subs.len()
        ))
        .evidence("Policy assignments read", total.to_string())
        .done()
}

fn rbac_012(t: &Tenant) -> CheckResult {
    let subs = subscriptions(t);
    let mut affected = Vec::new();
    for s in &subs {
        let id = s.s("subscriptionId").unwrap_or_default();
        let pricings = for_sub(t, "azpricings", id);
        let free: Vec<&str> = PLANS
            .iter()
            .copied()
            .filter(|plan| {
                pricings
                    .iter()
                    .find(|p| p.s("name") == Some(*plan))
                    .and_then(|p| prop_s(p, "pricingTier"))
                    != Some("Standard")
            })
            .collect();
        if !free.is_empty() {
            affected.push(sub_item(t, s, format!("Plans off: {}", free.join(", "))));
        }
    }
    let n = affected.len();
    arm(t, "AZ-RBAC-012")
        .expected(format!(
            "Defender for Cloud plans on in every subscription: {}",
            PLANS.join(", ")
        ))
        .affected(affected, "subscriptions")
        .found(format!(
            "{} of {} with plans off",
            plural(n, "subscription", "subscriptions"),
            subs.len()
        ))
        .done()
}

fn rbac_013(t: &Tenant) -> CheckResult {
    let subs = subscriptions(t);
    let lines: Vec<String> = subs
        .iter()
        .filter_map(|s| {
            let id = s.s("subscriptionId")?;
            let score = for_sub(t, "azsecurescore", id).into_iter().next()?;
            let pct = prop(score, "score")
                .and_then(|x| x.get("percentage"))
                .and_then(Value::as_f64)?;
            Some(format!(
                "{}: {:.0}%",
                s.s("displayName").unwrap_or(id),
                pct * 100.0
            ))
        })
        .collect();
    let out = arm(t, "AZ-RBAC-013");
    if lines.is_empty() {
        return out
            .not_assessed("No subscription returned a Defender for Cloud secure score.")
            .done();
    }
    out.found(format!(
        "Secure score read for {}",
        plural(lines.len(), "subscription", "subscriptions")
    ))
    .evidence("Secure score", lines.join("; "))
    .done()
}

fn rbac_014(t: &Tenant) -> CheckResult {
    let subs = subscriptions(t);
    let mut affected = Vec::new();
    for s in &subs {
        let id = s.s("subscriptionId").unwrap_or_default();
        let exported = for_sub(t, "azdiagnostics", id).iter().any(|d| {
            let dest = [
                "workspaceId",
                "eventHubAuthorizationRuleId",
                "storageAccountId",
            ]
            .iter()
            .any(|k| prop_s(d, k).is_some_and(|v| !v.is_empty()));
            let admin = prop(d, "logs").and_then(Value::as_array).is_some_and(|l| {
                l.iter().any(|x| {
                    x.b("enabled") == Some(true)
                        && matches!(x.s("category"), Some("Administrative") | None)
                })
            });
            dest && admin
        });
        if !exported {
            affected.push(sub_item(t, s, "Activity log not exported"));
        }
    }
    let n = affected.len();
    arm(t, "AZ-RBAC-014")
        .expected(
            "Every subscription exports its activity log to Log Analytics, an event hub or storage",
        )
        .affected(affected, "subscriptions")
        .found(format!(
            "{} of {} without activity log export",
            plural(n, "subscription", "subscriptions"),
            subs.len()
        ))
        .done()
}

fn rbac_015(t: &Tenant) -> CheckResult {
    let mut affected = Vec::new();
    let mut lines = Vec::new();
    for r in t.raw.list("azlighthouse") {
        let Some(def) = r.at(&["properties", "registrationDefinition", "properties"]) else {
            continue;
        };
        let tenant = def
            .s("managedByTenantName")
            .or(def.s("managedByTenantId"))
            .unwrap_or("(tenant)");
        let roles: Vec<String> = def
            .a("authorizations")
            .iter()
            .filter_map(|a| a.s("roleDefinitionId"))
            .map(|r| role_label(t, &role_guid(r)))
            .collect();
        let sub = r
            .s("@dca.parent")
            .map(|s| sub_name(t, s))
            .unwrap_or_default();
        lines.push(format!("{tenant} on {sub}: {}", roles.join(", ")));
        let broad: Vec<&String> = roles
            .iter()
            .filter(|r| {
                matches!(
                    r.as_str(),
                    "Contributor"
                        | "User Access Administrator"
                        | "Role Based Access Control Administrator"
                )
            })
            .collect();
        if !broad.is_empty() {
            affected.push(t.object(
                "tenant",
                tenant,
                Some(sub.clone()),
                format!(
                    "Delegated {} on {sub}",
                    broad.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
                ),
            ));
        }
    }
    let n = affected.len();
    arm(t, "AZ-RBAC-015")
        .expected("Lighthouse delegations to other tenants grant only the roles the provider needs, without Contributor or access administration")
        .affected(affected, "delegations")
        .found(format!(
            "{} of {}",
            plural(n, "broad delegation", "broad delegations"),
            plural(lines.len(), "delegation", "delegations")
        ))
        .evidence(
            "Delegations",
            if lines.is_empty() {
                "None".to_string()
            } else {
                lines.join("; ")
            },
        )
        .done()
}

fn rbac_018(t: &Tenant) -> CheckResult {
    let accounts = t.raw.list("azstorage");
    let mut affected = Vec::new();
    for a in accounts {
        let mut issues = Vec::new();
        if prop_b(a, "allowBlobPublicAccess") == Some(true) {
            issues.push("anonymous blob access allowed");
        }
        if prop_b(a, "allowSharedKeyAccess") != Some(false) {
            issues.push("shared key access allowed");
        }
        if !issues.is_empty() {
            affected.push(t.object(
                "resource",
                a.s("name").unwrap_or("(storage account)"),
                a.s("@dca.parent").map(|s| sub_name(t, s)),
                issues.join(", "),
            ));
        }
    }
    let n = affected.len();
    arm(t, "AZ-RBAC-018")
        .expected("Storage accounts allow neither anonymous blob access nor shared key access")
        .affected(affected, "storage accounts")
        .found(format!(
            "{} of {}",
            plural(n, "storage account", "storage accounts"),
            accounts.len()
        ))
        .done()
}

// ---------- Key Vault ----------

pub(crate) fn vault_item(t: &Tenant, v: &Value, reason: impl Into<String>) -> Affected {
    t.object(
        "resource",
        v.s("name").unwrap_or("(key vault)"),
        v.s("@dca.parent").map(|s| sub_name(t, s)),
        reason,
    )
}

fn vault_check(
    t: &Tenant,
    id: &str,
    expected: &str,
    eval: impl Fn(&Value) -> Option<String>,
) -> CheckResult {
    let vaults = t.raw.list("azvaults");
    let affected: Vec<Affected> = vaults
        .iter()
        .filter_map(|v| eval(v).map(|r| vault_item(t, v, r)))
        .collect();
    let n = affected.len();
    arm(t, id)
        .expected(expected)
        .affected(affected, "key vaults")
        .found(format!(
            "{} of {}",
            plural(n, "key vault", "key vaults"),
            vaults.len()
        ))
        .done()
}

fn kv_001(t: &Tenant) -> CheckResult {
    vault_check(
        t,
        "AZ-KV-001",
        "Key Vaults use Azure RBAC for data access, not access policies",
        |v| {
            (prop_b(v, "enableRbacAuthorization") != Some(true))
                .then(|| "Uses access policies".into())
        },
    )
}

fn kv_002(t: &Tenant) -> CheckResult {
    let vaults = t.raw.list("azvaults");
    let mut affected = Vec::new();
    for v in vaults {
        if prop_b(v, "enableRbacAuthorization") == Some(true) {
            continue;
        }
        for p in prop(v, "accessPolicies")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let mut broad = Vec::new();
            for kind in ["secrets", "keys", "certificates"] {
                let perms: Vec<String> = p
                    .at(&["permissions", kind])
                    .and_then(Value::as_array)
                    .map(|l| {
                        l.iter()
                            .filter_map(Value::as_str)
                            .map(str::to_ascii_lowercase)
                            .collect()
                    })
                    .unwrap_or_default();
                if perms.iter().any(|x| x == "all") {
                    broad.push(format!("all {kind} permissions"));
                } else if perms.iter().any(|x| x == "purge") {
                    broad.push(format!("purge {kind}"));
                }
            }
            if !broad.is_empty() {
                let who = p.s("objectId").unwrap_or_default();
                affected.push(vault_item(
                    t,
                    v,
                    format!("{} has {}", t.name_of(who), broad.join(", ")),
                ));
            }
        }
    }
    for a in assignments(t, "azroleassignments").iter().filter(|a| {
        matches!(
            a.role.as_str(),
            KV_ADMIN | KV_SECRETS_OFFICER | KV_SECRETS_USER
        ) && is_broad(a.scope)
    }) {
        affected.push(principal_item(
            t,
            a,
            format!(
                "{} at {}: reaches every vault below",
                role_label(t, &a.role),
                scope_text(t, a.scope)
            ),
        ));
    }
    let n = affected.len();
    arm(t, "AZ-KV-002")
        .expected("No access policy grants all or purge permissions, and Key Vault data roles are granted per vault, not on whole subscriptions")
        .affected(affected, "grants")
        .found(plural(n, "broad grant", "broad grants"))
        .evidence("Key vaults", vaults.len().to_string())
        .done()
}

fn kv_003(t: &Tenant) -> CheckResult {
    vault_check(
        t,
        "AZ-KV-003",
        "Soft delete and purge protection are on for every Key Vault",
        |v| {
            let mut off = Vec::new();
            if prop_b(v, "enableSoftDelete") == Some(false) {
                off.push("soft delete");
            }
            if prop_b(v, "enablePurgeProtection") != Some(true) {
                off.push("purge protection");
            }
            (!off.is_empty()).then(|| format!("Off: {}", off.join(", ")))
        },
    )
}

fn private_endpoints(v: &Value) -> usize {
    prop(v, "privateEndpointConnections")
        .and_then(Value::as_array)
        .map_or(0, Vec::len)
}

fn kv_004(t: &Tenant) -> CheckResult {
    vault_check(
        t,
        "AZ-KV-004",
        "Public network access is disabled on Key Vaults",
        |v| {
            (prop_s(v, "publicNetworkAccess") != Some("Disabled"))
                .then(|| "Public network access enabled".into())
        },
    )
}

fn kv_007(t: &Tenant) -> CheckResult {
    let diags = t.raw.list("azvaultdiagnostics");
    vault_check(
        t,
        "AZ-KV-007",
        "Every Key Vault sends its audit logs to Log Analytics, an event hub or storage",
        |v| {
            let id = v.s("id").unwrap_or_default();
            let logged = diags
                .iter()
                .filter(|d| {
                    d.s("@dca.parent")
                        .is_some_and(|p| p.eq_ignore_ascii_case(id))
                })
                .any(|d| {
                    prop(d, "logs").and_then(Value::as_array).is_some_and(|l| {
                        l.iter().any(|x| {
                            x.b("enabled") == Some(true)
                                && (x.s("category") == Some("AuditEvent")
                                    || matches!(x.s("categoryGroup"), Some("audit" | "allLogs")))
                        })
                    })
                });
            (!logged).then(|| "No diagnostic setting sends audit events".into())
        },
    )
}

fn kv_010(t: &Tenant) -> CheckResult {
    vault_check(
        t,
        "AZ-KV-010",
        "Key Vault firewalls deny by default, or the vault is reached through a private endpoint",
        |v| {
            let open = prop(v, "networkAcls")
                .and_then(|n| n.s("defaultAction"))
                .is_none_or(|a| a != "Deny");
            (open && private_endpoints(v) == 0)
                .then(|| "Firewall allows all networks and no private endpoint".into())
        },
    )
}

pub static RULES: &[Rule] = &[
    Rule {
        id: "AZ-RBAC-001",
        needs: &["azroleassignments", "azmgmtgroups"],
        run: rbac_001,
    },
    Rule {
        id: "AZ-RBAC-002",
        needs: &["azroleassignments"],
        run: rbac_002,
    },
    Rule {
        id: "AZ-RBAC-003",
        needs: &["azactive", "azeligible"],
        run: rbac_003,
    },
    Rule {
        id: "AZ-RBAC-004",
        needs: &["azroleassignments", "azeligible", "users"],
        run: rbac_004,
    },
    Rule {
        id: "AZ-RBAC-005",
        needs: &["azroleassignments"],
        run: rbac_005,
    },
    Rule {
        id: "AZ-RBAC-006",
        needs: &["azroledefinitions"],
        run: rbac_006,
    },
    Rule {
        id: "AZ-RBAC-008",
        needs: &["azroleassignments", "users", "groups", "serviceprincipals"],
        run: rbac_008,
    },
    Rule {
        id: "AZ-RBAC-009",
        needs: &["azsubscriptions", "azroleassignments", "azcontacts"],
        run: rbac_009,
    },
    Rule {
        id: "AZ-RBAC-011",
        needs: &["azsubscriptions", "azpolicies"],
        run: rbac_011,
    },
    Rule {
        id: "AZ-RBAC-012",
        needs: &["azsubscriptions", "azpricings"],
        run: rbac_012,
    },
    Rule {
        id: "AZ-RBAC-013",
        needs: &["azsubscriptions", "azsecurescore"],
        run: rbac_013,
    },
    Rule {
        id: "AZ-RBAC-014",
        needs: &["azsubscriptions", "azdiagnostics"],
        run: rbac_014,
    },
    Rule {
        id: "AZ-RBAC-015",
        needs: &["azlighthouse"],
        run: rbac_015,
    },
    Rule {
        id: "AZ-RBAC-018",
        needs: &["azstorage"],
        run: rbac_018,
    },
    Rule {
        id: "AZ-KV-001",
        needs: &["azvaults"],
        run: kv_001,
    },
    Rule {
        id: "AZ-KV-002",
        needs: &["azvaults", "azroleassignments"],
        run: kv_002,
    },
    Rule {
        id: "AZ-KV-003",
        needs: &["azvaults"],
        run: kv_003,
    },
    Rule {
        id: "AZ-KV-004",
        needs: &["azvaults"],
        run: kv_004,
    },
    Rule {
        id: "AZ-KV-007",
        needs: &["azvaults", "azvaultdiagnostics"],
        run: kv_007,
    },
    Rule {
        id: "AZ-KV-010",
        needs: &["azvaults"],
        run: kv_010,
    },
];
