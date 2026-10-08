//! Directory roles, PIM and applications.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde_json::Value;

use super::model::{
    is_microsoft_tenant, PrincipalKind, Tenant, APP_ADMIN, AUTH_ADMIN, CLOUD_APP_ADMIN,
    DEVICE_LOCAL_ADMIN, DIR_SYNC, GLOBAL_ADMIN, HYBRID_ADMIN, J, PRIV_AUTH_ADMIN, PRIV_ROLE_ADMIN,
};
use super::rules::{read_from, tenant_item, STALE_DAYS};
use super::Rule;
use crate::ad::rules::{check, plural};
use crate::catalog::Severity;
use crate::results::{Affected, CheckResult};

/// One affected entry per principal holding a role matched by `role`.
fn holders_list(
    t: &Tenant,
    role: impl Fn(&str) -> bool,
    who: impl Fn(PrincipalKind, &str) -> bool,
) -> Vec<Affected> {
    let mut by: BTreeMap<String, Vec<&super::model::Holder>> = BTreeMap::new();
    for h in t
        .holders
        .iter()
        .filter(|h| h.kind != PrincipalKind::Group && role(&h.role) && who(h.kind, &h.principal))
    {
        by.entry(h.principal.clone()).or_default().push(h);
    }
    by.into_iter()
        .map(|(id, hs)| t.affected(&id, t.roles_text(&hs)))
        .collect()
}

// ---------- EN-PRIV ----------

fn priv_001(t: &Tenant) -> CheckResult {
    let list = holders_list(t, |r| r == GLOBAL_ADMIN, |_, _| true);
    let n = list.len();
    let mut out = check("EN-PRIV-001")
        .expected("Two to four Global Administrators, including emergency access accounts")
        .found(plural(n, "Global Administrator", "Global Administrators"))
        .evidence("Read from", read_from(t));
    if n < 2 {
        out = out.affected(list, "accounts").severity(Severity::Medium);
        out.0.status = crate::results::ResultStatus::Failed;
        out.0.found = Some(format!(
            "Only {}: no second account if it is lost",
            plural(n, "Global Administrator", "Global Administrators")
        ));
    } else if n > 4 {
        out = out.affected(list, "accounts");
    } else {
        out.0.affected = list;
        out.0.affected_count = Some(n as u64);
        out.0.affected_unit = Some("accounts".into());
    }
    out.done()
}

fn priv_002(t: &Tenant) -> CheckResult {
    let schedules = t.raw.read("roleschedules");
    let list = holders_list_filtered(t, |h| {
        h.permanent && t.is_privileged(&h.role) && h.role != DIR_SYNC
    });
    let mut out = check("EN-PRIV-002")
        .expected("Privileged roles held through PIM eligible or time-bound assignments, except emergency access accounts")
        .found(plural(list.len(), "account holds", "accounts hold") + " privileged roles permanently")
        .affected(list, "accounts")
        .evidence("Read from", read_from(t));
    if !schedules {
        out = out.evidence("Note", "PIM schedules were not readable (Entra ID P2 needed), so every active assignment counts as permanent");
    }
    out.done()
}

fn holders_list_filtered(
    t: &Tenant,
    keep: impl Fn(&super::model::Holder) -> bool,
) -> Vec<Affected> {
    let mut by: BTreeMap<String, Vec<&super::model::Holder>> = BTreeMap::new();
    for h in t
        .holders
        .iter()
        .filter(|h| h.kind != PrincipalKind::Group && keep(h))
    {
        by.entry(h.principal.clone()).or_default().push(h);
    }
    by.into_iter()
        .map(|(id, hs)| t.affected(&id, t.roles_text(&hs)))
        .collect()
}

/// ISO 8601 duration (PT8H, P1D, PT90M) in minutes.
fn minutes(d: &str) -> Option<i64> {
    let d = d.strip_prefix('P')?;
    let (days, time) = d.split_once('T').unwrap_or((d, ""));
    let mut total = 0;
    if let Some(n) = days.strip_suffix('D') {
        total += n.parse::<i64>().ok()? * 1440;
    }
    let mut num = String::new();
    for c in time.chars() {
        match c {
            'H' => total += num.parse::<i64>().ok()? * 60,
            'M' => total += num.parse::<i64>().ok()?,
            'S' => {}
            _ => {
                num.push(c);
                continue;
            }
        }
        num.clear();
    }
    Some(total)
}

fn priv_003(t: &Tenant) -> CheckResult {
    let mut list = Vec::new();
    for role in [GLOBAL_ADMIN, PRIV_ROLE_ADMIN, PRIV_AUTH_ADMIN] {
        let Some(p) = t
            .raw
            .list("pimpolicies")
            .iter()
            .find(|p| p.s("roleDefinitionId") == Some(role))
        else {
            continue;
        };
        let rules = p
            .at(&["policy", "rules"])
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let rule = |id: &str| rules.iter().find(|r| r.s("id") == Some(id));
        let mut why = Vec::new();
        let mfa = rule("Enablement_EndUser_Assignment").is_some_and(|r| {
            r.strs("enabledRules")
                .contains(&"MultiFactorAuthentication")
        }) || rule("AuthenticationContext_EndUser_Assignment")
            .is_some_and(|r| r.b("isEnabled") == Some(true));
        if !mfa {
            why.push("No MFA or authentication context on activation".to_string());
        }
        if role == GLOBAL_ADMIN
            && !rule("Approval_EndUser_Assignment")
                .and_then(|r| r.at(&["setting", "isApprovalRequired"]))
                .and_then(Value::as_bool)
                .unwrap_or(false)
        {
            why.push("Activation needs no approval".to_string());
        }
        if let Some(m) = rule("Expiration_EndUser_Assignment")
            .and_then(|r| r.s("maximumDuration"))
            .and_then(minutes)
        {
            if m > 480 {
                why.push(format!("Activation lasts up to {} hours", m / 60));
            }
        }
        if !why.is_empty() {
            list.push(t.object("role", t.role_name(role), None, why.join("; ")));
        }
    }
    check("EN-PRIV-003")
        .expected("Activation of the most privileged roles requires MFA, approval for Global Administrator, and lasts 8 hours or less")
        .found(plural(list.len(), "role has", "roles have") + " weak activation settings")
        .affected(list, "roles")
        .evidence("Read from", read_from(t))
        .done()
}

fn priv_004(t: &Tenant) -> CheckResult {
    let list = holders_list(
        t,
        |r| r == PRIV_ROLE_ADMIN || r == PRIV_AUTH_ADMIN,
        |_, _| true,
    );
    let n = list.len();
    let out = check("EN-PRIV-004")
        .expected("Three holders or fewer of Privileged Role Administrator and Privileged Authentication Administrator")
        .found(plural(n, "holder", "holders"))
        .evidence("Read from", read_from(t));
    if n > 3 {
        out.affected(list, "accounts").done()
    } else {
        out.done()
    }
}

fn priv_005(t: &Tenant) -> CheckResult {
    let mut list = Vec::new();
    for g in t
        .raw
        .list("groups")
        .iter()
        .filter(|g| g.b("isAssignableToRole") == Some(true))
    {
        let owners: Vec<&str> = g
            .a("owners")
            .iter()
            .map(|o| {
                o.s("userPrincipalName")
                    .or(o.s("displayName"))
                    .unwrap_or("owner")
            })
            .collect();
        if !owners.is_empty() {
            let id = g.s("id").unwrap_or_default();
            let roles: Vec<String> = t
                .holders
                .iter()
                .filter(|h| h.principal == id)
                .map(|h| t.role_name(&h.role))
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            let held = if roles.is_empty() {
                String::new()
            } else {
                format!(". Grants {}", roles.join(", "))
            };
            list.push(t.affected(id, format!("Owners: {}{held}", owners.join(", "))));
        }
    }
    check("EN-PRIV-005")
        .expected("Role-assignable groups have no owners; membership is managed through PIM by Privileged Role Administrators")
        .found(plural(list.len(), "role-assignable group has", "role-assignable groups have") + " owners")
        .affected(list, "groups")
        .evidence("Read from", read_from(t))
        .done()
}

fn priv_006(t: &Tenant) -> CheckResult {
    let list = holders_list(t, |_| true, |k, _| k == PrincipalKind::ServicePrincipal);
    check("EN-PRIV-006")
        .expected("Applications use Graph application permissions scoped to what they need, not directory roles")
        .found(plural(list.len(), "service principal holds", "service principals hold") + " directory roles")
        .affected(list, "applications")
        .evidence("Read from", read_from(t))
        .done()
}

fn priv_007(t: &Tenant) -> CheckResult {
    let list = holders_list(
        t,
        |_| true,
        |k, p| k == PrincipalKind::User && t.is_guest(p),
    );
    check("EN-PRIV-007")
        .expected("No guest holds a directory role")
        .found(plural(list.len(), "guest holds", "guests hold") + " directory roles")
        .affected(list, "guests")
        .evidence("Read from", read_from(t))
        .done()
}

fn id_003(t: &Tenant) -> CheckResult {
    let list = holders_list(
        t,
        |r| t.is_privileged(r),
        |k, p| k == PrincipalKind::User && t.is_guest(p),
    );
    check("EN-ID-003")
        .expected("No guest holds a privileged role")
        .found(plural(list.len(), "guest holds", "guests hold") + " privileged roles")
        .affected(list, "guests")
        .evidence("Read from", read_from(t))
        .done()
}

fn id_007(t: &Tenant) -> CheckResult {
    let list = holders_list(
        t,
        |r| t.is_privileged(r) && r != DIR_SYNC,
        |k, p| {
            k == PrincipalKind::User
                && t.users
                    .get(p)
                    .is_some_and(|u| u.b("onPremisesSyncEnabled") == Some(true))
        },
    );
    check("EN-ID-007")
        .expected("Privileged roles held only by cloud-only accounts")
        .found(
            plural(list.len(), "synced account holds", "synced accounts hold")
                + " privileged roles",
        )
        .affected(list, "accounts")
        .evidence("Read from", read_from(t))
        .done()
}

fn priv_008(t: &Tenant) -> CheckResult {
    let units = t.raw.list("adminunits");
    let restricted = units
        .iter()
        .filter(|u| u.b("isMemberManagementRestricted") == Some(true))
        .count();
    let mut out = check("EN-PRIV-008")
        .found(format!(
            "{}, {restricted} restricted management",
            plural(units.len(), "administrative unit", "administrative units")
        ))
        .evidence("Read from", read_from(t));
    for u in units.iter().take(50) {
        out = out.evidence(
            u.s("displayName").unwrap_or("Unit"),
            if u.b("isMemberManagementRestricted") == Some(true) {
                "Restricted management"
            } else {
                "Standard"
            },
        );
    }
    out.done()
}

const DANGEROUS_ACTIONS: [&str; 10] = [
    "microsoft.directory/applications/credentials/update",
    "microsoft.directory/servicePrincipals/credentials/update",
    "microsoft.directory/roleAssignments/",
    "microsoft.directory/users/password/update",
    "microsoft.directory/users/authenticationMethods/",
    "microsoft.directory/conditionalAccessPolicies/",
    "microsoft.directory/applications/owners/update",
    "microsoft.directory/servicePrincipals/owners/update",
    "microsoft.directory/groups/members/update",
    "microsoft.directory/servicePrincipals/appRoleAssignedTo/update",
];

fn priv_009(t: &Tenant) -> CheckResult {
    let mut list = Vec::new();
    for d in t
        .raw
        .list("roledefinitions")
        .iter()
        .filter(|d| d.b("isBuiltIn") == Some(false))
    {
        let actions: Vec<&str> = d
            .a("rolePermissions")
            .iter()
            .flat_map(|p| p.strs("allowedResourceActions"))
            .collect();
        let bad: BTreeSet<&str> = actions
            .iter()
            .copied()
            .filter(|a| {
                a.ends_with("/allTasks") && a.starts_with("microsoft.directory/")
                    || DANGEROUS_ACTIONS.iter().any(|d| a.starts_with(d))
            })
            .collect();
        if !bad.is_empty() {
            let holders = t
                .holders
                .iter()
                .filter(|h| Some(h.role.as_str()) == d.s("id"))
                .count();
            list.push(t.object(
                "role",
                d.s("displayName").unwrap_or("Custom role"),
                Some(plural(holders, "assignment", "assignments")),
                bad.into_iter().collect::<Vec<_>>().join(", "),
            ));
        }
    }
    check("EN-PRIV-009")
        .expected("Custom roles do not grant credential, role assignment, password, authentication method, Conditional Access or owner changes")
        .found(plural(list.len(), "custom role", "custom roles") + " with dangerous permissions")
        .affected(list, "roles")
        .evidence("Read from", read_from(t))
        .done()
}

fn priv_011(t: &Tenant) -> CheckResult {
    let mut list = Vec::new();
    for (id, hs) in t.privileged_principals() {
        let Some(u) = t.users.get(id.as_str()) else {
            continue;
        };
        let n = u.a("assignedLicenses").len();
        if n > 0 && hs.iter().any(|h| h.role != DIR_SYNC) {
            list.push(t.affected(
                &id,
                format!(
                    "{}; {}",
                    t.roles_text(&hs),
                    plural(n, "licence", "licences")
                ),
            ));
        }
    }
    check("EN-PRIV-011")
        .expected("Admin roles held by separate, unlicensed admin accounts")
        .found(
            plural(list.len(), "admin account is", "admin accounts are")
                + " licensed for productivity apps",
        )
        .affected(list, "accounts")
        .evidence("Read from", read_from(t))
        .done()
}

fn priv_014(t: &Tenant) -> CheckResult {
    let mut list = Vec::new();
    for (id, hs) in t.privileged_principals() {
        let Some(u) = t.users.get(id.as_str()) else {
            continue;
        };
        if u.b("accountEnabled") != Some(true) {
            continue;
        }
        let created = t.days_since(u.t("createdDateTime")).unwrap_or(0);
        let why = match t.days_since(t.last_signin(u)) {
            Some(d) if d > STALE_DAYS => format!("Last sign-in {d} days ago"),
            None if created > STALE_DAYS => "Never signed in".to_string(),
            _ => continue,
        };
        list.push(t.affected(&id, format!("{why}. {}", t.roles_text(&hs))));
    }
    check("EN-PRIV-014")
        .expected(format!(
            "Every admin signed in within {STALE_DAYS} days, or the role is removed"
        ))
        .found(plural(list.len(), "stale admin", "stale admins"))
        .affected(list, "accounts")
        .evidence("Read from", read_from(t))
        .done()
}

fn priv_017(t: &Tenant) -> CheckResult {
    let mut list = Vec::new();
    for h in t.holders_of(DIR_SYNC) {
        let name = t.name_of(&h.principal);
        let display = t
            .principal(&h.principal)
            .and_then(|p| p.s("displayName"))
            .unwrap_or_default();
        let sync = name.to_lowercase().starts_with("sync_")
            || display.starts_with("On-Premises Directory Synchronization Service Account");
        if !sync && h.kind != PrincipalKind::ServicePrincipal {
            list.push(t.affected(
                &h.principal,
                "Holds Directory Synchronization Accounts but is not a sync service account",
            ));
        }
    }
    check("EN-PRIV-017")
        .expected("Only the Entra Connect or Cloud Sync service accounts hold Directory Synchronization Accounts")
        .found(plural(list.len(), "other account holds", "other accounts hold") + " the role")
        .affected(list, "accounts")
        .evidence("Read from", read_from(t))
        .done()
}

fn priv_018(t: &Tenant) -> CheckResult {
    let list: Vec<Affected> = t
        .raw
        .list("contracts")
        .iter()
        .map(|c| {
            t.object(
                "tenant",
                c.s("displayName").unwrap_or("Partner"),
                c.s("defaultDomainName").map(str::to_string),
                format!("Contract type {}", c.s("contractType").unwrap_or("unknown")),
            )
        })
        .collect();
    check("EN-PRIV-018")
        .expected("No partner holds delegated admin privileges (DAP); partners use granular delegated admin (GDAP)")
        .found(plural(list.len(), "partner relationship", "partner relationships"))
        .affected(list, "partners")
        .evidence("Read from", read_from(t))
        .done()
}

fn priv_021(t: &Tenant) -> CheckResult {
    let list = holders_list(t, |r| r == DEVICE_LOCAL_ADMIN, |_, _| true);
    check("EN-PRIV-021")
        .expected("No standing holders; use Windows LAPS or scoped local admin groups")
        .found(plural(list.len(), "holder", "holders"))
        .affected(list, "accounts")
        .evidence("Read from", read_from(t))
        .done()
}

fn priv_022(t: &Tenant) -> CheckResult {
    let list = holders_list_filtered(t, |h| {
        h.permanent
            && !h.scoped
            && [APP_ADMIN, CLOUD_APP_ADMIN, HYBRID_ADMIN, AUTH_ADMIN].contains(&h.role.as_str())
    });
    check("EN-PRIV-022")
        .expected("Tier 0-equivalent roles held only through PIM")
        .found(plural(list.len(), "account holds", "accounts hold") + " them permanently")
        .affected(list, "accounts")
        .evidence("Read from", read_from(t))
        .done()
}

// ---------- EN-APP ----------

pub(crate) const RISKY_DELEGATED: [&str; 12] = [
    "Mail.ReadWrite",
    "Mail.Send",
    "Files.ReadWrite.All",
    "Sites.ReadWrite.All",
    "Directory.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All",
    "User.ReadWrite.All",
    "Group.ReadWrite.All",
    "full_access_as_user",
    "EWS.AccessAsUser.All",
];

pub(crate) const RISKY_APPLICATION: [&str; 13] = [
    "RoleManagement.ReadWrite.Directory",
    "AppRoleAssignment.ReadWrite.All",
    "Application.ReadWrite.All",
    "Directory.ReadWrite.All",
    "User.ReadWrite.All",
    "Group.ReadWrite.All",
    "Mail.ReadWrite",
    "Mail.Send",
    "Files.ReadWrite.All",
    "Sites.FullControl.All",
    "full_access_as_app",
    "UserAuthenticationMethod.ReadWrite.All",
    "Policy.ReadWrite.ConditionalAccess",
];

fn sp_name(t: &Tenant, id: &str) -> String {
    t.sps
        .get(id)
        .and_then(|s| s.s("displayName"))
        .unwrap_or(id)
        .to_string()
}

pub(crate) fn sp_item(t: &Tenant, id: &str, reason: impl Into<String>) -> Affected {
    let sp = t.sps.get(id);
    Affected {
        last_seen: None,
        name: sp_name(t, id),
        kind: "app".into(),
        location: sp.and_then(|s| s.s("appId")).map(|a| format!("App id {a}")),
        reason: Some(reason.into()),
        object: sp.map(|_| id.to_string()),
    }
}

/// Application permissions held, per client service principal id.
pub(crate) fn app_permissions(t: &Tenant) -> HashMap<String, Vec<String>> {
    let mut roles: HashMap<&str, &str> = HashMap::new();
    for r in t.raw.list("resources") {
        for role in r.a("appRoles") {
            if let (Some(id), Some(v)) = (role.s("id"), role.s("value")) {
                roles.insert(id, v);
            }
        }
    }
    let mut out: HashMap<String, Vec<String>> = HashMap::new();
    for a in t.raw.list("approleassignments") {
        if a.s("principalType") != Some("ServicePrincipal") {
            continue;
        }
        let (Some(p), Some(role)) = (a.s("principalId"), a.s("appRoleId")) else {
            continue;
        };
        if let Some(v) = roles.get(role) {
            out.entry(p.to_string()).or_default().push(v.to_string());
        }
    }
    out
}

pub(crate) fn risky_app_permissions(t: &Tenant) -> HashMap<String, Vec<String>> {
    app_permissions(t)
        .into_iter()
        .filter_map(|(sp, perms)| {
            let risky: Vec<String> = perms
                .into_iter()
                .filter(|p| RISKY_APPLICATION.contains(&p.as_str()))
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            (!risky.is_empty()).then_some((sp, risky))
        })
        .collect()
}

fn privileged_sps(t: &Tenant) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for h in t
        .holders
        .iter()
        .filter(|h| h.kind == PrincipalKind::ServicePrincipal && t.is_privileged(&h.role))
    {
        out.entry(h.principal.clone())
            .or_default()
            .push(t.role_name(&h.role));
    }
    for (sp, perms) in risky_app_permissions(t) {
        out.entry(sp).or_default().extend(perms);
    }
    out
}

fn app_001(t: &Tenant) -> CheckResult {
    let Some(assigned) = t
        .raw
        .first("authorization")
        .and_then(|a| {
            a.at(&[
                "defaultUserRolePermissions",
                "permissionGrantPoliciesAssigned",
            ])
        })
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect::<Vec<String>>()
        })
    else {
        return check("EN-APP-001")
            .not_assessed("The authorization policy does not include the user consent setting.")
            .done();
    };
    let legacy = assigned
        .iter()
        .any(|p| p.ends_with("microsoft-user-default-legacy"));
    let low = assigned
        .iter()
        .any(|p| p.ends_with("microsoft-user-default-low"));
    let found = if legacy {
        "Users can consent to any app for any permission that does not need admin consent"
    } else if low {
        "Users can consent to apps from verified publishers for low-impact permissions"
    } else if assigned.is_empty() {
        "Users cannot consent to apps"
    } else {
        "A custom consent policy applies"
    };
    let mut out = check("EN-APP-001")
        .expected("User consent off, or limited to verified publishers and low-impact permissions")
        .found(found)
        .evidence(
            "Policies assigned",
            if assigned.is_empty() {
                "None".to_string()
            } else {
                assigned.join(", ")
            },
        )
        .evidence("Read from", read_from(t));
    if legacy {
        out = out.affected(vec![tenant_item(t, found)], "tenant");
    }
    out.done()
}

fn app_002(t: &Tenant) -> CheckResult {
    let on = t
        .raw
        .first("adminconsent")
        .and_then(|a| a.b("isEnabled"))
        .unwrap_or(false);
    let mut out = check("EN-APP-002")
        .expected("The admin consent request workflow is on, so users can ask for apps they cannot consent to")
        .found(if on { "Admin consent requests are on" } else { "Admin consent requests are off" })
        .evidence("Read from", read_from(t));
    if !on {
        out = out.affected(
            vec![tenant_item(t, "Admin consent workflow is off")],
            "tenant",
        );
    }
    out.done()
}

fn app_003(t: &Tenant) -> CheckResult {
    let mut by: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for g in t
        .raw
        .list("grants")
        .iter()
        .filter(|g| g.s("consentType") == Some("AllPrincipals"))
    {
        let scopes = g.s("scope").unwrap_or_default();
        let risky: Vec<&str> = scopes
            .split_whitespace()
            .filter(|s| RISKY_DELEGATED.contains(s))
            .collect();
        if let (false, Some(client)) = (risky.is_empty(), g.s("clientId")) {
            by.entry(client.to_string())
                .or_default()
                .extend(risky.iter().map(|s| s.to_string()));
        }
    }
    let list: Vec<Affected> = by
        .into_iter()
        .map(|(sp, s)| {
            sp_item(
                t,
                &sp,
                format!(
                    "Granted for all users: {}",
                    s.into_iter().collect::<Vec<_>>().join(", ")
                ),
            )
        })
        .collect();
    check("EN-APP-003")
        .expected("No app holds high-risk delegated permissions for all users unless reviewed and required")
        .found(plural(list.len(), "app", "apps") + " with tenant-wide high-risk delegated permissions")
        .affected(list, "applications")
        .evidence("Read from", read_from(t))
        .done()
}

fn app_004(t: &Tenant) -> CheckResult {
    let list: Vec<Affected> = risky_app_permissions(t)
        .into_iter()
        .collect::<BTreeMap<_, _>>()
        .into_iter()
        .map(|(sp, perms)| sp_item(t, &sp, perms.join(", ")))
        .collect();
    check("EN-APP-004")
        .expected("No application holds tenant-wide write or role management application permissions unless reviewed and required")
        .found(plural(list.len(), "app", "apps") + " with high-risk application permissions")
        .affected(list, "applications")
        .evidence("Read from", read_from(t))
        .done()
}

fn app_005(t: &Tenant) -> CheckResult {
    let list = holders_list(
        t,
        |r| t.is_privileged(r),
        |k, _| k == PrincipalKind::ServicePrincipal,
    );
    check("EN-APP-005")
        .expected("No service principal holds a privileged directory role")
        .found(
            plural(
                list.len(),
                "service principal holds",
                "service principals hold",
            ) + " privileged roles",
        )
        .affected(list, "applications")
        .evidence("Read from", read_from(t))
        .done()
}

fn app_item(a: &Value, reason: impl Into<String>) -> Affected {
    Affected {
        last_seen: None,
        name: a.s("displayName").unwrap_or("Application").to_string(),
        kind: "app".into(),
        location: a.s("appId").map(|x| format!("App id {x}")),
        reason: Some(reason.into()),
        object: None,
    }
}

fn app_006(t: &Tenant) -> CheckResult {
    let mut list = Vec::new();
    for a in t.raw.list("applications") {
        let mut why = Vec::new();
        for (key, what) in [
            ("passwordCredentials", "Secret"),
            ("keyCredentials", "Certificate"),
        ] {
            for c in a.a(key) {
                let Some(end) = c.t("endDateTime") else {
                    continue;
                };
                let days = (end - t.now) / 86_400;
                let name = c.s("displayName").unwrap_or("unnamed");
                if days < 0 {
                    why.push(format!("{what} {name} expired {} days ago", -days));
                } else if days <= 30 {
                    why.push(format!("{what} {name} expires in {days} days"));
                }
            }
        }
        if !why.is_empty() {
            list.push(app_item(a, why.join("; ")));
        }
    }
    check("EN-APP-006")
        .expected("Expired credentials removed and expiring ones rotated ahead of time")
        .found(plural(list.len(), "app", "apps") + " with expired or expiring credentials")
        .affected(list, "applications")
        .evidence("Read from", read_from(t))
        .done()
}

fn app_007(t: &Tenant) -> CheckResult {
    let mut list = Vec::new();
    for a in t.raw.list("applications") {
        let long: Vec<String> = a
            .a("passwordCredentials")
            .iter()
            .filter(|c| c.t("endDateTime").is_none_or(|e| e > t.now))
            .filter_map(|c| {
                let days = (c.t("endDateTime")? - c.t("startDateTime")?) / 86_400;
                (days > 366).then(|| {
                    format!(
                        "{} valid for {} days",
                        c.s("displayName").unwrap_or("Secret"),
                        days
                    )
                })
            })
            .collect();
        if !long.is_empty() {
            list.push(app_item(a, long.join("; ")));
        }
    }
    check("EN-APP-007")
        .expected("Client secrets valid for one year or less")
        .found(plural(list.len(), "app", "apps") + " with long-lived secrets")
        .affected(list, "applications")
        .evidence("Read from", read_from(t))
        .done()
}

fn app_008(t: &Tenant) -> CheckResult {
    let list: Vec<Affected> = t
        .raw
        .list("applications")
        .iter()
        .filter_map(|a| {
            let n = a
                .a("passwordCredentials")
                .iter()
                .filter(|c| c.t("endDateTime").is_none_or(|e| e > t.now))
                .count();
            (n > 0).then(|| app_item(a, plural(n, "valid client secret", "valid client secrets")))
        })
        .collect();
    check("EN-APP-008")
        .expected(
            "Apps authenticate with certificates, managed identities or federated credentials",
        )
        .found(plural(list.len(), "app uses", "apps use") + " client secrets")
        .affected(list, "applications")
        .evidence("Read from", read_from(t))
        .done()
}

fn app_009(t: &Tenant) -> CheckResult {
    let apps: HashMap<&str, &Value> = t
        .raw
        .list("applications")
        .iter()
        .filter_map(|a| Some((a.s("appId")?, a)))
        .collect();
    let mut list = Vec::new();
    for (sp, grants) in privileged_sps(t) {
        let Some(s) = t.sps.get(sp.as_str()) else {
            continue;
        };
        let mut owners: Vec<&str> = s
            .a("owners")
            .iter()
            .filter_map(|o| o.s("userPrincipalName").or(o.s("displayName")))
            .collect();
        if let Some(a) = s.s("appId").and_then(|id| apps.get(id)) {
            owners.extend(
                a.a("owners")
                    .iter()
                    .filter_map(|o| o.s("userPrincipalName").or(o.s("displayName"))),
            );
        }
        owners.sort();
        owners.dedup();
        if !owners.is_empty() {
            let mut g = grants.clone();
            g.sort();
            g.dedup();
            list.push(sp_item(
                t,
                &sp,
                format!("Owners: {}. Holds {}", owners.join(", "), g.join(", ")),
            ));
        }
    }
    check("EN-APP-009")
        .expected("Privileged applications have no owners; admins manage them")
        .found(plural(list.len(), "privileged app has", "privileged apps have") + " owners")
        .affected(list, "applications")
        .evidence("Read from", read_from(t))
        .done()
}

fn app_010(t: &Tenant) -> CheckResult {
    let perms = app_permissions(t);
    let tenant_wide: BTreeSet<&str> = t
        .raw
        .list("grants")
        .iter()
        .filter(|g| g.s("consentType") == Some("AllPrincipals"))
        .filter_map(|g| g.s("clientId"))
        .collect();
    let mut list = Vec::new();
    for s in t.raw.list("serviceprincipals") {
        let Some(id) = s.s("id") else { continue };
        let owner = s.s("appOwnerOrganizationId").unwrap_or_default();
        if owner.is_empty() || owner == t.id || is_microsoft_tenant(owner) {
            continue;
        }
        let verified = s
            .o("verifiedPublisher")
            .and_then(|v| v.s("verifiedPublisherId"))
            .is_some_and(|v| !v.is_empty());
        if verified {
            continue;
        }
        let mut why = Vec::new();
        if tenant_wide.contains(id) {
            why.push("delegated permissions for all users".to_string());
        }
        if let Some(p) = perms.get(id) {
            why.push(format!("application permissions {}", p.join(", ")));
        }
        if !why.is_empty() {
            list.push(sp_item(
                t,
                id,
                format!("Unverified publisher; holds {}", why.join(" and ")),
            ));
        }
    }
    check("EN-APP-010")
        .expected(
            "Apps from other organizations with tenant-wide access come from verified publishers",
        )
        .found(plural(list.len(), "unverified app", "unverified apps"))
        .affected(list, "applications")
        .evidence("Read from", read_from(t))
        .done()
}

fn app_011(t: &Tenant) -> CheckResult {
    let mut list = Vec::new();
    for a in t.raw.list("applications") {
        let uris: Vec<&str> = ["web", "spa", "publicClient"]
            .iter()
            .flat_map(|k| a.o(k).map(|o| o.strs("redirectUris")).unwrap_or_default())
            .collect();
        let bad: Vec<&str> = uris
            .into_iter()
            .filter(|u| {
                let l = u.to_lowercase();
                l.contains('*')
                    || (l.starts_with("http://")
                        && !l.starts_with("http://localhost")
                        && !l.starts_with("http://127.0.0.1"))
            })
            .collect();
        if !bad.is_empty() {
            list.push(app_item(a, bad.join(", ")));
        }
    }
    check("EN-APP-011")
        .expected("Redirect URIs are exact https addresses the organization controls")
        .found(plural(list.len(), "app has", "apps have") + " wildcard or plain http redirect URIs")
        .affected(list, "applications")
        .evidence("Read from", read_from(t))
        .done()
}

fn app_013(t: &Tenant) -> CheckResult {
    let list: Vec<Affected> = t
        .raw
        .list("serviceprincipals")
        .iter()
        .filter(|s| {
            s.s("appOwnerOrganizationId")
                .is_some_and(is_microsoft_tenant)
        })
        .filter_map(|s| {
            let secrets = s.a("passwordCredentials").len();
            let certs = s
                .a("keyCredentials")
                .iter()
                .filter(|k| k.s("usage") == Some("Verify"))
                .count();
            (secrets + certs > 0).then(|| {
                sp_item(
                    t,
                    s.s("id").unwrap_or_default(),
                    format!(
                        "{} and {} added in this tenant",
                        plural(secrets, "secret", "secrets"),
                        plural(certs, "certificate", "certificates")
                    ),
                )
            })
        })
        .collect();
    check("EN-APP-013")
        .expected("No credentials on Microsoft first-party service principals")
        .found(
            plural(
                list.len(),
                "Microsoft service principal has",
                "Microsoft service principals have",
            ) + " credentials",
        )
        .affected(list, "applications")
        .evidence("Read from", read_from(t))
        .done()
}

fn app_015(t: &Tenant) -> CheckResult {
    let list: Vec<Affected> = privileged_sps(t)
        .into_iter()
        .filter(|(sp, _)| {
            t.sps
                .get(sp.as_str())
                .is_some_and(|s| s.s("servicePrincipalType") == Some("ManagedIdentity"))
        })
        .map(|(sp, mut g)| {
            g.sort();
            g.dedup();
            sp_item(t, &sp, g.join(", "))
        })
        .collect();
    check("EN-APP-015")
        .expected("Managed identities hold only the permissions their workload needs, not privileged roles or tenant-wide write permissions")
        .found(plural(list.len(), "managed identity", "managed identities") + " with privileged access")
        .affected(list, "identities")
        .evidence("Read from", read_from(t))
        .done()
}

fn app_016(t: &Tenant) -> CheckResult {
    let list: Vec<Affected> = t
        .raw
        .list("applications")
        .iter()
        .filter(|a| {
            a.o("servicePrincipalLockConfiguration")
                .and_then(|l| l.b("isEnabled"))
                != Some(true)
        })
        .map(|a| app_item(a, "App instance property lock is off"))
        .collect();
    check("EN-APP-016")
        .expected("App instance property lock on for every app registration")
        .found(plural(list.len(), "app", "apps") + " without the lock")
        .affected(list, "applications")
        .evidence("Read from", read_from(t))
        .done()
}

fn app_017(t: &Tenant) -> CheckResult {
    let list: Vec<Affected> = t
        .raw
        .list("applications")
        .iter()
        .filter(|a| {
            a.at(&["web", "implicitGrantSettings", "enableAccessTokenIssuance"])
                .and_then(Value::as_bool)
                == Some(true)
        })
        .map(|a| app_item(a, "Issues access tokens through the implicit grant"))
        .collect();
    check("EN-APP-017")
        .expected(
            "Implicit grant access tokens off; apps use the authorization code flow with PKCE",
        )
        .found(plural(list.len(), "app allows", "apps allow") + " the implicit grant")
        .affected(list, "applications")
        .evidence("Read from", read_from(t))
        .done()
}

fn app_020(t: &Tenant) -> CheckResult {
    let mut list = Vec::new();
    for s in t
        .raw
        .list("serviceprincipals")
        .iter()
        .filter(|s| s.s("preferredSingleSignOnMode") == Some("saml"))
    {
        let latest = s
            .a("keyCredentials")
            .iter()
            .filter(|k| k.s("usage") == Some("Sign"))
            .filter_map(|k| k.t("endDateTime"))
            .max();
        let Some(end) = latest else { continue };
        let days = (end - t.now) / 86_400;
        if days <= 60 {
            let why = if days < 0 {
                format!("Signing certificate expired {} days ago", -days)
            } else {
                format!("Signing certificate expires in {days} days")
            };
            list.push(sp_item(t, s.s("id").unwrap_or_default(), why));
        }
    }
    check("EN-APP-020")
        .expected("SAML signing certificates renewed at least 60 days before they expire")
        .found(plural(list.len(), "SAML app", "SAML apps") + " with expiring certificates")
        .affected(list, "applications")
        .evidence("Read from", read_from(t))
        .done()
}

const ADMIN_TOOLS: [(&str, &str); 3] = [
    (
        "14d82eec-204b-4c2f-b7e8-296a70dab67e",
        "Microsoft Graph Command Line Tools",
    ),
    (
        "1950a258-227b-4e31-a9cf-717495945fc2",
        "Microsoft Azure PowerShell",
    ),
    (
        "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
        "Microsoft Azure CLI",
    ),
];

fn app_024(t: &Tenant) -> CheckResult {
    let mut list = Vec::new();
    for (app, name) in ADMIN_TOOLS {
        let Some(sp) = t.sps_by_app.get(app) else {
            continue;
        };
        let Some(id) = sp.s("id") else { continue };
        let write: BTreeSet<&str> = t
            .raw
            .list("grants")
            .iter()
            .filter(|g| g.s("clientId") == Some(id) && g.s("consentType") == Some("AllPrincipals"))
            .flat_map(|g| g.s("scope").unwrap_or_default().split_whitespace())
            .filter(|s| s.contains("ReadWrite") || s.contains(".Write") || s.ends_with(".Send"))
            .collect();
        if !write.is_empty() {
            let mut a = sp_item(
                t,
                id,
                format!(
                    "Write scopes for all users: {}",
                    write.into_iter().collect::<Vec<_>>().join(", ")
                ),
            );
            a.name = name.to_string();
            list.push(a);
        }
    }
    check("EN-APP-024")
        .expected("Admin tools hold write scopes only per user, not consented for all users")
        .found(
            plural(list.len(), "admin tool has", "admin tools have") + " tenant-wide write scopes",
        )
        .affected(list, "applications")
        .evidence("Read from", read_from(t))
        .done()
}

pub static RULES: &[Rule] = &[
    Rule {
        id: "EN-ID-003",
        needs: &["users", "roleassignments"],
        run: id_003,
    },
    Rule {
        id: "EN-ID-007",
        needs: &["users", "roleassignments"],
        run: id_007,
    },
    Rule {
        id: "EN-PRIV-001",
        needs: &["roleassignments"],
        run: priv_001,
    },
    Rule {
        id: "EN-PRIV-002",
        needs: &["roleassignments"],
        run: priv_002,
    },
    Rule {
        id: "EN-PRIV-003",
        needs: &["pimpolicies"],
        run: priv_003,
    },
    Rule {
        id: "EN-PRIV-004",
        needs: &["roleassignments"],
        run: priv_004,
    },
    Rule {
        id: "EN-PRIV-005",
        needs: &["groups", "groupowners"],
        run: priv_005,
    },
    Rule {
        id: "EN-PRIV-006",
        needs: &["roleassignments", "serviceprincipals"],
        run: priv_006,
    },
    Rule {
        id: "EN-PRIV-007",
        needs: &["roleassignments", "users"],
        run: priv_007,
    },
    Rule {
        id: "EN-PRIV-008",
        needs: &["adminunits"],
        run: priv_008,
    },
    Rule {
        id: "EN-PRIV-009",
        needs: &["roledefinitions"],
        run: priv_009,
    },
    Rule {
        id: "EN-PRIV-011",
        needs: &["roleassignments", "users"],
        run: priv_011,
    },
    Rule {
        id: "EN-PRIV-014",
        needs: &["roleassignments", "users", "signinactivity"],
        run: priv_014,
    },
    Rule {
        id: "EN-PRIV-017",
        needs: &["roleassignments"],
        run: priv_017,
    },
    Rule {
        id: "EN-PRIV-018",
        needs: &["contracts"],
        run: priv_018,
    },
    Rule {
        id: "EN-PRIV-021",
        needs: &["roleassignments"],
        run: priv_021,
    },
    Rule {
        id: "EN-PRIV-022",
        needs: &["roleassignments"],
        run: priv_022,
    },
    Rule {
        id: "EN-APP-001",
        needs: &["authorization"],
        run: app_001,
    },
    Rule {
        id: "EN-APP-002",
        needs: &["adminconsent"],
        run: app_002,
    },
    Rule {
        id: "EN-APP-003",
        needs: &["grants", "serviceprincipals"],
        run: app_003,
    },
    Rule {
        id: "EN-APP-004",
        needs: &["resources", "approleassignments", "serviceprincipals"],
        run: app_004,
    },
    Rule {
        id: "EN-APP-005",
        needs: &["roleassignments", "serviceprincipals"],
        run: app_005,
    },
    Rule {
        id: "EN-APP-006",
        needs: &["applications"],
        run: app_006,
    },
    Rule {
        id: "EN-APP-007",
        needs: &["applications"],
        run: app_007,
    },
    Rule {
        id: "EN-APP-008",
        needs: &["applications"],
        run: app_008,
    },
    Rule {
        id: "EN-APP-009",
        needs: &[
            "roleassignments",
            "serviceprincipals",
            "applications",
            "approleassignments",
        ],
        run: app_009,
    },
    Rule {
        id: "EN-APP-010",
        needs: &["serviceprincipals", "grants", "approleassignments"],
        run: app_010,
    },
    Rule {
        id: "EN-APP-011",
        needs: &["applications"],
        run: app_011,
    },
    Rule {
        id: "EN-APP-013",
        needs: &["serviceprincipals"],
        run: app_013,
    },
    Rule {
        id: "EN-APP-015",
        needs: &["roleassignments", "serviceprincipals", "approleassignments"],
        run: app_015,
    },
    Rule {
        id: "EN-APP-016",
        needs: &["applications"],
        run: app_016,
    },
    Rule {
        id: "EN-APP-017",
        needs: &["applications"],
        run: app_017,
    },
    Rule {
        id: "EN-APP-020",
        needs: &["serviceprincipals"],
        run: app_020,
    },
    Rule {
        id: "EN-APP-024",
        needs: &["serviceprincipals", "grants"],
        run: app_024,
    },
];

#[cfg(test)]
mod tests {
    #[test]
    fn durations() {
        assert_eq!(super::minutes("PT8H"), Some(480));
        assert_eq!(super::minutes("PT1H30M"), Some(90));
        assert_eq!(super::minutes("P1D"), Some(1440));
    }
}
