//! Conditional Access, security defaults and authentication methods.

use std::collections::{BTreeSet, HashMap};

use serde_json::Value;

use super::model::{PrincipalKind, Tenant, GLOBAL_ADMIN, J};
use super::rules::{read_from, setting, tenant_item};
use super::Rule;
use crate::ad::rules::{check, plural};
use crate::catalog::Severity;
use crate::results::{Affected, CheckResult};

/// The built-in "Phishing-resistant MFA" authentication strength.
const PHISHING_RESISTANT: &str = "00000000-0000-0000-0000-000000000004";
/// Microsoft Azure Management (portal, ARM, PowerShell, CLI).
const AZURE_MANAGEMENT: &str = "797f4846-ba00-4fd7-ba43-dac1f8f63013";

/// One Conditional Access policy.
pub(crate) struct Ca<'a>(pub &'a Value);

impl<'a> Ca<'a> {
    pub fn name(&self) -> &'a str {
        self.0.s("displayName").unwrap_or("Unnamed policy")
    }
    pub fn enabled(&self) -> bool {
        self.0.s("state") == Some("enabled")
    }
    pub fn report_only(&self) -> bool {
        self.0.s("state") == Some("enabledForReportingButNotEnforced")
    }
    pub fn users(&self, key: &str) -> Vec<&'a str> {
        self.0
            .at(&["conditions", "users", key])
            .map(|v| {
                v.as_array()
                    .map(|a| a.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default()
            })
            .unwrap_or_default()
    }
    pub fn apps(&self, key: &str) -> Vec<&'a str> {
        self.0
            .at(&["conditions", "applications", key])
            .map(|v| {
                v.as_array()
                    .map(|a| a.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default()
            })
            .unwrap_or_default()
    }
    pub fn list(&self, path: &[&str]) -> Vec<&'a str> {
        self.0
            .at(path)
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default()
    }
    pub fn all_users(&self) -> bool {
        self.users("includeUsers").contains(&"All")
    }
    fn includes_guests(&self) -> bool {
        self.all_users()
            || self
                .users("includeUsers")
                .contains(&"GuestsOrExternalUsers")
            || self
                .0
                .at(&["conditions", "users", "includeGuestsOrExternalUsers"])
                .is_some()
    }
    fn admins(&self) -> bool {
        self.all_users() || self.users("includeRoles").contains(&GLOBAL_ADMIN)
    }
    pub fn all_apps(&self) -> bool {
        self.apps("includeApplications").contains(&"All")
    }
    pub fn all_clients(&self) -> bool {
        let types = self.list(&["conditions", "clientAppTypes"]);
        types.is_empty()
            || types.contains(&"all")
            || (types.contains(&"browser") && types.contains(&"mobileAppsAndDesktopClients"))
    }
    pub fn grants(&self) -> Vec<&'a str> {
        self.list(&["grantControls", "builtInControls"])
    }
    fn strength(&self) -> Option<&'a str> {
        self.0
            .at(&["grantControls", "authenticationStrength", "id"])
            .and_then(Value::as_str)
    }
    pub fn mfa(&self) -> bool {
        self.grants().contains(&"mfa") || self.strength().is_some()
    }
    pub fn blocks(&self) -> bool {
        self.grants().contains(&"block")
    }
    fn user_actions(&self) -> Vec<&'a str> {
        self.apps("includeUserActions")
    }
    fn risk(&self, key: &str) -> Vec<&'a str> {
        self.list(&["conditions", key])
    }
    /// MFA (or an authentication strength) for every user on every resource.
    fn mfa_for_all(&self) -> bool {
        self.enabled() && self.all_users() && self.all_apps() && self.all_clients() && self.mfa()
    }
    fn blocks_legacy(&self) -> bool {
        let types = self.list(&["conditions", "clientAppTypes"]);
        self.enabled()
            && self.all_users()
            && self.all_apps()
            && self.blocks()
            && types.contains(&"exchangeActiveSync")
            && types.contains(&"other")
    }
}

pub(crate) fn policies<'a>(t: &'a Tenant) -> Vec<Ca<'a>> {
    t.raw.list("capolicies").iter().map(Ca).collect()
}

fn names(list: &[&Ca]) -> String {
    list.iter().map(|p| p.name()).collect::<Vec<_>>().join(", ")
}

fn security_defaults(t: &Tenant) -> bool {
    t.raw
        .first("securitydefaults")
        .and_then(|s| s.b("isEnabled"))
        .unwrap_or(false)
}

/// Passes when an enabled policy satisfies `ok`, naming it; fails otherwise.
fn need_policy(
    t: &Tenant,
    id: &str,
    expected: &str,
    missing: &str,
    ok: impl Fn(&Ca) -> bool,
) -> CheckResult {
    let all = policies(t);
    let found: Vec<&Ca> = all.iter().filter(|p| p.enabled() && ok(p)).collect();
    let report_only: Vec<&Ca> = all
        .iter()
        .filter(|p| {
            p.report_only() && {
                // The same condition, if the policy were on.
                let on = Value::Object({
                    let mut m = p.0.as_object().cloned().unwrap_or_default();
                    m.insert("state".into(), Value::String("enabled".into()));
                    m
                });
                ok(&Ca(&on))
            }
        })
        .collect();
    let mut out = check(id)
        .expected(expected)
        .evidence("Read from", read_from(t));
    if !report_only.is_empty() {
        out = out.evidence("Report-only (not enforced)", names(&report_only));
    }
    if found.is_empty() {
        out.found(missing.to_string())
            .affected(vec![tenant_item(t, missing)], "tenant")
            .done()
    } else {
        out.found(format!("Enforced by {}", names(&found))).done()
    }
}

fn ten_002(t: &Tenant) -> CheckResult {
    let sd = security_defaults(t);
    let mfa: Vec<Ca> = policies(t)
        .into_iter()
        .filter(|p| p.enabled() && p.mfa())
        .collect();
    let out = check("EN-TEN-002")
        .expected("Security defaults on, or Conditional Access policies that require MFA")
        .evidence("Security defaults", if sd { "On" } else { "Off" })
        .evidence("Enabled policies requiring MFA", mfa.len().to_string())
        .evidence("Read from", read_from(t));
    if sd || !mfa.is_empty() {
        out.found(if sd {
            "Security defaults are on".to_string()
        } else {
            format!("{} require MFA", plural(mfa.len(), "policy", "policies"))
        })
        .done()
    } else {
        out.found("Security defaults are off and no enabled policy requires MFA")
            .affected(vec![tenant_item(t, "No MFA enforcement")], "tenant")
            .done()
    }
}

// ---------- EN-CA ----------

fn ca_001(t: &Tenant) -> CheckResult {
    let all = policies(t);
    let on = all.iter().filter(|p| p.enabled()).count();
    let ro = all.iter().filter(|p| p.report_only()).count();
    let off = all.len() - on - ro;
    let mut out = check("EN-CA-001")
        .found(format!(
            "{}: {on} on, {ro} report-only, {off} off",
            plural(all.len(), "policy", "policies")
        ))
        .evidence("Read from", read_from(t));
    for p in &all {
        let state = if p.enabled() {
            "On"
        } else if p.report_only() {
            "Report-only"
        } else {
            "Off"
        };
        out = out.evidence(p.name(), state);
    }
    out.done()
}

fn ca_002(t: &Tenant) -> CheckResult {
    if security_defaults(t) && policies(t).is_empty() {
        return check("EN-CA-002")
            .expected("MFA required for all users on all resources")
            .found("Security defaults are on (they require MFA registration and MFA when needed)")
            .evidence("Read from", read_from(t))
            .done();
    }
    need_policy(
        t,
        "EN-CA-002",
        "An enabled policy requires MFA for All users on All resources",
        "No enabled policy requires MFA for all users on all resources",
        |p| p.mfa_for_all(),
    )
}

fn ca_003(t: &Tenant) -> CheckResult {
    need_policy(
        t,
        "EN-CA-003",
        "An enabled policy requires phishing-resistant MFA for admin roles",
        "No enabled policy requires phishing-resistant MFA for admins",
        |p| p.admins() && p.all_apps() && p.strength() == Some(PHISHING_RESISTANT),
    )
}

fn ca_004(t: &Tenant) -> CheckResult {
    if security_defaults(t) && policies(t).is_empty() {
        return check("EN-CA-004")
            .expected("Legacy authentication blocked for all users")
            .found("Security defaults are on (they block legacy authentication)")
            .evidence("Read from", read_from(t))
            .done();
    }
    need_policy(
        t,
        "EN-CA-004",
        "An enabled policy blocks Exchange ActiveSync and other legacy clients for All users",
        "No enabled policy blocks legacy authentication for all users",
        |p| p.blocks_legacy(),
    )
}

fn ca_005(t: &Tenant) -> CheckResult {
    need_policy(
        t,
        "EN-CA-005",
        "An enabled policy blocks device code flow",
        "No enabled policy blocks device code flow",
        |p| {
            p.blocks()
                && p.0
                    .at(&["conditions", "authenticationFlows", "transferMethods"])
                    .and_then(Value::as_str)
                    .is_some_and(|m| m.contains("deviceCodeFlow"))
        },
    )
}

fn p2_only(t: &Tenant, id: &str) -> Option<CheckResult> {
    (t.licences_known && !t.p2).then(|| {
        check(id)
            .not_assessed(
                "Risk-based Conditional Access needs Entra ID P2, which the tenant does not have.",
            )
            .done()
    })
}

fn ca_006(t: &Tenant) -> CheckResult {
    p2_only(t, "EN-CA-006").unwrap_or_else(|| {
        need_policy(
            t,
            "EN-CA-006",
            "An enabled policy requires MFA or blocks on medium and high sign-in risk",
            "No enabled policy acts on sign-in risk",
            |p| !p.risk("signInRiskLevels").is_empty() && (p.mfa() || p.blocks()),
        )
    })
}

fn ca_007(t: &Tenant) -> CheckResult {
    p2_only(t, "EN-CA-007").unwrap_or_else(|| {
        need_policy(
            t,
            "EN-CA-007",
            "An enabled policy requires a secure password change or blocks on high user risk",
            "No enabled policy acts on user risk",
            |p| {
                !p.risk("userRiskLevels").is_empty()
                    && (p.grants().contains(&"passwordChange") || p.blocks() || p.mfa())
            },
        )
    })
}

fn ca_008(t: &Tenant) -> CheckResult {
    need_policy(
        t,
        "EN-CA-008",
        "An enabled policy protects registering security information",
        "No enabled policy protects the Register security information action",
        |p| p.user_actions().contains(&"urn:user:registersecurityinfo"),
    )
}

fn ca_009(t: &Tenant) -> CheckResult {
    need_policy(
        t,
        "EN-CA-009",
        "An enabled policy requires MFA for admin portals and Azure management",
        "No enabled policy requires MFA for admin portals or Azure management",
        |p| {
            let apps = p.apps("includeApplications");
            p.all_users()
                && p.mfa()
                && (p.all_apps()
                    || apps.contains(&"MicrosoftAdminPortals")
                    || apps.contains(&AZURE_MANAGEMENT))
        },
    )
}

fn ca_010(t: &Tenant) -> CheckResult {
    need_policy(
        t,
        "EN-CA-010",
        "An enabled policy requires a compliant or hybrid-joined device for admin roles",
        "No enabled policy requires a managed device for admins",
        |p| {
            p.admins()
                && (p.grants().contains(&"compliantDevice")
                    || p.grants().contains(&"domainJoinedDevice"))
        },
    )
}

fn ca_011(t: &Tenant) -> CheckResult {
    need_policy(
        t,
        "EN-CA-011",
        "An enabled policy requires MFA for guests and external users",
        "No enabled policy requires MFA for guests",
        |p| p.includes_guests() && p.all_apps() && p.mfa(),
    )
}

fn ca_012(t: &Tenant) -> CheckResult {
    need_policy(
        t,
        "EN-CA-012",
        "An enabled policy sets sign-in frequency or non-persistent browser sessions for admins",
        "No session limits for admins",
        |p| {
            p.admins()
                && (p
                    .0
                    .at(&["sessionControls", "signInFrequency", "isEnabled"])
                    .and_then(Value::as_bool)
                    == Some(true)
                    || p.0
                        .at(&["sessionControls", "persistentBrowser", "mode"])
                        .and_then(Value::as_str)
                        == Some("never"))
        },
    )
}

fn ca_013(t: &Tenant) -> CheckResult {
    let list: Vec<Affected> = policies(t)
        .iter()
        .filter(|p| {
            p.enabled()
                && p.0
                    .at(&["sessionControls", "continuousAccessEvaluation", "mode"])
                    .and_then(Value::as_str)
                    == Some("disabled")
        })
        .map(|p| {
            t.object(
                "policy",
                p.name(),
                None,
                "Disables continuous access evaluation",
            )
        })
        .collect();
    check("EN-CA-013")
        .expected("Continuous access evaluation left on")
        .found(
            plural(list.len(), "policy disables", "policies disable")
                + " continuous access evaluation",
        )
        .affected(list, "policies")
        .evidence("Read from", read_from(t))
        .done()
}

fn ca_014(t: &Tenant) -> CheckResult {
    let mut list = Vec::new();
    for l in t
        .raw
        .list("namedlocations")
        .iter()
        .filter(|l| l.b("isTrusted") == Some(true))
    {
        let broad: Vec<&str> = l
            .a("ipRanges")
            .iter()
            .filter_map(|r| r.s("cidrAddress"))
            .filter(|c| {
                let Some((addr, len)) = c.split_once('/') else {
                    return false;
                };
                let len: u32 = len.parse().unwrap_or(128);
                if addr.contains(':') {
                    len < 32
                } else {
                    len < 16
                }
            })
            .collect();
        if !broad.is_empty() {
            list.push(t.object(
                "location",
                l.s("displayName").unwrap_or("Named location"),
                None,
                format!("Trusted range {}", broad.join(", ")),
            ));
        }
    }
    check("EN-CA-014")
        .expected("Trusted locations list only the organization's own egress ranges")
        .found(plural(list.len(), "trusted location is", "trusted locations are") + " very broad")
        .affected(list, "locations")
        .evidence("Read from", read_from(t))
        .done()
}

fn ca_015(t: &Tenant) -> CheckResult {
    let all = policies(t);
    let critical: Vec<&Ca> = all
        .iter()
        .filter(|p| p.mfa_for_all() || p.blocks_legacy())
        .collect();
    if critical.is_empty() {
        return check("EN-CA-015").not_assessed("No enabled policy requires MFA for all users or blocks legacy authentication, so there are no exclusions to review (see EN-CA-002 and EN-CA-004).").done();
    }
    let mut users: BTreeSet<&str> = BTreeSet::new();
    let mut groups: BTreeSet<&str> = BTreeSet::new();
    for p in &critical {
        users.extend(
            p.users("excludeUsers")
                .into_iter()
                .filter(|u| *u != "GuestsOrExternalUsers"),
        );
        groups.extend(p.users("excludeGroups"));
    }
    let mut list: Vec<Affected> = users
        .iter()
        .map(|u| t.affected(u, "Excluded from a critical policy"))
        .collect();
    list.extend(
        groups
            .iter()
            .map(|g| t.affected(g, "Group excluded from a critical policy")),
    );
    let fail = users.len() > 2 || !groups.is_empty();
    let out = check("EN-CA-015")
        .expected("Only the emergency access accounts (two at most) are excluded")
        .found(format!(
            "{} and {} excluded from {}",
            plural(users.len(), "user", "users"),
            plural(groups.len(), "group", "groups"),
            names(&critical)
        ))
        .evidence("Read from", read_from(t));
    if fail {
        out.affected(list, "exclusions").done()
    } else {
        out.done()
    }
}

fn ca_016(t: &Tenant) -> CheckResult {
    let mut seen: HashMap<&str, Vec<&str>> = HashMap::new();
    let all = policies(t);
    for p in all.iter().filter(|p| p.enabled()) {
        for g in p.users("excludeGroups") {
            seen.entry(g).or_default().push(p.name());
        }
    }
    let mut list = Vec::new();
    for (g, pols) in seen {
        let Some(group) = t.groups.get(g) else {
            continue;
        };
        let why = if group.s("membershipRule").is_some() {
            "Dynamic: anyone who can change the attributes in its rule joins it"
        } else if group.b("isAssignableToRole") != Some(true) {
            "Not role-assignable: group owners and Groups or User administrators can add members"
        } else {
            continue;
        };
        list.push(t.affected(g, format!("{why}. Excluded from {}", pols.join(", "))));
    }
    list.sort_by(|a, b| a.name.cmp(&b.name));
    check("EN-CA-016")
        .expected("Excluded groups are role-assignable and not dynamic")
        .found(
            plural(list.len(), "excluded group", "excluded groups")
                + " can be changed outside Tier 0",
        )
        .affected(list, "groups")
        .evidence("Read from", read_from(t))
        .done()
}

fn ca_019(t: &Tenant) -> CheckResult {
    let mut list = Vec::new();
    for p in policies(t).iter().filter(|p| p.report_only()) {
        let changed = p.0.t("modifiedDateTime").or(p.0.t("createdDateTime"));
        if let Some(d) = t.days_since(changed).filter(|d| *d > 30) {
            list.push(t.object(
                "policy",
                p.name(),
                None,
                format!("Report-only, unchanged for {d} days"),
            ));
        }
    }
    check("EN-CA-019")
        .expected("Report-only policies are reviewed and turned on or removed within 30 days")
        .found(plural(list.len(), "policy", "policies") + " left in report-only")
        .affected(list, "policies")
        .evidence("Read from", read_from(t))
        .done()
}

fn ca_022(t: &Tenant) -> CheckResult {
    let list: Vec<Affected> = policies(t)
        .iter()
        .filter(|p| p.enabled() && p.grants().contains(&"approvedApplication"))
        .map(|p| {
            t.object(
                "policy",
                p.name(),
                None,
                "Uses the retired Require approved client app grant",
            )
        })
        .collect();
    check("EN-CA-022")
        .expected("Policies use Require app protection policy instead")
        .found(plural(list.len(), "policy uses", "policies use") + " the retired grant")
        .affected(list, "policies")
        .evidence("Read from", read_from(t))
        .done()
}

// ---------- Break-glass and risk (EN-ID) ----------

/// Whether policy `p` applies to user `id` (who holds `roles`).
fn applies(t: &Tenant, p: &Ca, id: &str, roles: &[String]) -> bool {
    let member_of = |g: &str| {
        t.group_members
            .get(g)
            .is_some_and(|m| m.iter().any(|x| x.s("id") == Some(id)))
    };
    if p.users("excludeUsers").contains(&id)
        || p.users("excludeGroups").iter().any(|g| member_of(g))
    {
        return false;
    }
    if p.users("excludeRoles")
        .iter()
        .any(|r| roles.iter().any(|x| x == r))
    {
        return false;
    }
    p.all_users()
        || p.users("includeUsers").contains(&id)
        || p.users("includeGroups").iter().any(|g| member_of(g))
        || p.users("includeRoles")
            .iter()
            .any(|r| roles.iter().any(|x| x == r))
}

fn id_008(t: &Tenant) -> CheckResult {
    let enabled: Vec<Ca> = policies(t).into_iter().filter(|p| p.enabled()).collect();
    if enabled.is_empty() {
        return check("EN-ID-008").not_assessed("The tenant has no enabled Conditional Access policy, so emergency access accounts cannot be told apart from other admins.").done();
    }
    let mut found = Vec::new();
    for id in super::rules::global_admins(t) {
        let Some(u) = t.users.get(id) else { continue };
        if u.b("onPremisesSyncEnabled") == Some(true) || u.b("accountEnabled") != Some(true) {
            continue;
        }
        let roles: Vec<String> = t
            .holders
            .iter()
            .filter(|h| h.principal == id && h.active)
            .map(|h| h.role.clone())
            .collect();
        if enabled.iter().all(|p| !applies(t, p, id, &roles)) {
            found.push(t.name_of(id));
        }
    }
    let out = check("EN-ID-008")
        .expected("At least one enabled, cloud-only Global Administrator excluded from all Conditional Access policies, kept for emergencies")
        .evidence("Read from", read_from(t));
    if found.is_empty() {
        out.found("No emergency access account found")
            .affected(
                vec![tenant_item(
                    t,
                    "No cloud-only Global Administrator is excluded from every enabled policy",
                )],
                "tenant",
            )
            .done()
    } else {
        out.found(format!("Emergency access accounts: {}", found.join(", ")))
            .done()
    }
}

fn id_013(t: &Tenant) -> CheckResult {
    let high: Vec<&Value> = t
        .raw
        .list("riskyusers")
        .iter()
        .filter(|r| r.s("riskState") == Some("atRisk") && r.s("riskLevel") == Some("high"))
        .collect();
    let covered: Vec<Ca> = policies(t)
        .into_iter()
        .filter(|p| p.enabled() && p.risk("userRiskLevels").contains(&"high"))
        .collect();
    let out = check("EN-ID-013")
        .expected("A user risk policy responds to high user risk")
        .evidence("Read from", read_from(t));
    if !covered.is_empty() {
        return out
            .found(format!(
                "High user risk handled by {}",
                names(&covered.iter().collect::<Vec<_>>())
            ))
            .done();
    }
    let list: Vec<Affected> = high
        .iter()
        .map(|r| {
            let id = r.s("id").unwrap_or_default();
            let mut a = t.affected(id, "High user risk with no policy response");
            if a.name == id {
                a.name = r.s("userPrincipalName").unwrap_or(id).to_string();
            }
            a
        })
        .collect();
    out.found(format!(
        "{} at high risk and no policy acts on user risk",
        plural(list.len(), "user", "users")
    ))
    .affected(list, "users")
    .done()
}

fn dev_002(t: &Tenant) -> CheckResult {
    let Some(p) = t.raw.first("deviceregistration") else {
        return check("EN-DEV-002")
            .not_assessed("The device registration policy was empty.")
            .done();
    };
    let required = p.s("multiFactorAuthConfiguration") == Some("required");
    let ca: Vec<Ca> = policies(t)
        .into_iter()
        .filter(|p| p.enabled() && p.user_actions().contains(&"urn:user:registerdevice"))
        .collect();
    let out = check("EN-DEV-002")
        .expected("MFA required to register or join devices (device setting or a Conditional Access user action policy)")
        .evidence("Device setting requires MFA", if required { "Yes" } else { "No" })
        .evidence("Read from", read_from(t));
    if required || !ca.is_empty() {
        out.found(if required {
            "Required by the device setting".to_string()
        } else {
            format!("Required by {}", names(&ca.iter().collect::<Vec<_>>()))
        })
        .done()
    } else {
        out.found("Devices can be registered and joined without MFA")
            .affected(
                vec![tenant_item(t, "No MFA for device registration")],
                "tenant",
            )
            .done()
    }
}

// ---------- EN-AUTH ----------

pub(crate) fn methods_policy<'a>(t: &'a Tenant) -> Option<&'a Value> {
    t.raw.first("authmethods")
}

pub(crate) fn method<'a>(t: &'a Tenant, id: &str) -> Option<&'a Value> {
    methods_policy(t)?
        .a("authenticationMethodConfigurations")
        .iter()
        .find(|m| m.s("id").is_some_and(|x| x.eq_ignore_ascii_case(id)))
}

fn method_enabled(t: &Tenant, id: &str) -> bool {
    method(t, id).and_then(|m| m.s("state")) == Some("enabled")
}

fn no_methods(id: &str) -> CheckResult {
    check(id)
        .not_assessed("The authentication methods policy did not include the method settings.")
        .done()
}

fn registration<'a>(t: &'a Tenant) -> HashMap<&'a str, &'a Value> {
    t.raw
        .list("registration")
        .iter()
        .filter_map(|r| Some((r.s("id")?, r)))
        .collect()
}

fn auth_001(t: &Tenant) -> CheckResult {
    let mut list = Vec::new();
    for r in t.raw.list("registration") {
        let id = r.s("id").unwrap_or_default();
        let user = t.users.get(id);
        let enabled = user.is_none_or(|u| u.b("accountEnabled") == Some(true));
        let member = r
            .s("userType")
            .is_none_or(|x| x.eq_ignore_ascii_case("member"));
        if enabled && member && r.b("isMfaRegistered") == Some(false) {
            let mut a = t.affected(id, "No MFA method registered");
            if a.name == id {
                a.name = r.s("userPrincipalName").unwrap_or(id).to_string();
            }
            list.push(a);
        }
    }
    let admins = list
        .iter()
        .filter(|a| {
            a.object.as_deref().is_some_and(|o| {
                t.holders
                    .iter()
                    .any(|h| h.principal == o && t.is_privileged(&h.role))
            })
        })
        .count();
    let mut out = check("EN-AUTH-001")
        .expected("Every enabled member user has an MFA method registered")
        .found(plural(list.len(), "user", "users") + " without MFA")
        .affected(list, "users")
        .evidence("Read from", read_from(t));
    if admins > 0 {
        out = out
            .severity(Severity::Critical)
            .evidence("Of them admins", admins.to_string());
    }
    out.done()
}

const PHISHING_RESISTANT_METHODS: [&str; 6] = [
    "fido2",
    "windowsHelloForBusiness",
    "passKeyDeviceBound",
    "passKeyDeviceBoundAuthenticator",
    "passKeyDeviceBoundWindowsHello",
    "x509CertificateMultiFactor",
];

fn auth_002(t: &Tenant) -> CheckResult {
    let reg = registration(t);
    let mut list = Vec::new();
    for (id, holds) in t.privileged_principals() {
        if holds[0].kind != PrincipalKind::User {
            continue;
        }
        let Some(r) = reg.get(id.as_str()) else {
            continue;
        };
        let methods = r.strs("methodsRegistered");
        if !methods.iter().any(|m| {
            PHISHING_RESISTANT_METHODS
                .iter()
                .any(|p| p.eq_ignore_ascii_case(m))
        }) {
            let shown = if methods.is_empty() {
                "none".to_string()
            } else {
                methods.join(", ")
            };
            list.push(t.affected(&id, format!("{}. Methods: {shown}", t.roles_text(&holds))));
        }
    }
    check("EN-AUTH-002")
        .expected("Every admin has a passkey (FIDO2), Windows Hello for Business or certificate-based authentication registered")
        .found(plural(list.len(), "admin", "admins") + " without a phishing-resistant method")
        .affected(list, "admins")
        .evidence("Read from", read_from(t))
        .done()
}

fn auth_003(t: &Tenant) -> CheckResult {
    if methods_policy(t).is_none_or(|m| m.a("authenticationMethodConfigurations").is_empty()) {
        return no_methods("EN-AUTH-003");
    }
    let mut list = Vec::new();
    for (id, name) in [("Sms", "SMS"), ("Voice", "Voice call")] {
        if method_enabled(t, id) {
            list.push(tenant_item(t, format!("{name} is enabled")));
        }
    }
    check("EN-AUTH-003")
        .expected("SMS and voice call disabled as sign-in methods")
        .found(if list.is_empty() {
            "SMS and voice disabled".to_string()
        } else {
            list.iter()
                .filter_map(|a| a.reason.clone())
                .collect::<Vec<_>>()
                .join("; ")
        })
        .affected(list, "methods")
        .evidence("Read from", read_from(t))
        .done()
}

fn auth_004(t: &Tenant) -> CheckResult {
    let Some(m) = method(t, "MicrosoftAuthenticator") else {
        return no_methods("EN-AUTH-004");
    };
    let state = m
        .at(&[
            "featureSettings",
            "displayAppInformationRequiredState",
            "state",
        ])
        .and_then(Value::as_str)
        .unwrap_or("default");
    let ok = state == "enabled";
    let mut out = check("EN-AUTH-004")
        .expected("Push notifications show the application name and location")
        .found(format!("Additional context: {state}"))
        .evidence("Read from", read_from(t));
    if !ok && m.s("state") == Some("enabled") {
        out = out.affected(
            vec![tenant_item(
                t,
                "Authenticator does not show application name and location",
            )],
            "tenant",
        );
    }
    out.done()
}

fn auth_006(t: &Tenant) -> CheckResult {
    let Some(p) = methods_policy(t) else {
        return no_methods("EN-AUTH-006");
    };
    let state = p.s("policyMigrationState").unwrap_or("unknown");
    let mut out = check("EN-AUTH-006")
        .expected("Migration complete: only the authentication methods policy applies")
        .found(format!("Migration state: {state}"))
        .evidence("Read from", read_from(t));
    if state != "migrationComplete" {
        out = out.affected(
            vec![tenant_item(t, format!("Migration state {state}"))],
            "tenant",
        );
    }
    out.done()
}

fn auth_007(t: &Tenant) -> CheckResult {
    let Some(m) = method(t, "TemporaryAccessPass") else {
        return no_methods("EN-AUTH-007");
    };
    let out = check("EN-AUTH-007")
        .expected("Temporary Access Pass is one-time use with a lifetime of 8 hours or less")
        .evidence("Read from", read_from(t));
    if m.s("state") != Some("enabled") {
        return out.found("Temporary Access Pass is disabled").done();
    }
    let once = m.b("isUsableOnce").unwrap_or(false);
    let max = m.n("maximumLifetimeInMinutes").unwrap_or(480);
    let mut why = Vec::new();
    if !once {
        why.push("Reusable within its lifetime".to_string());
    }
    if max > 480 {
        why.push(format!("Maximum lifetime {} hours", max / 60));
    }
    out.found(format!(
        "One-time use: {}; maximum lifetime {} minutes",
        if once { "Yes" } else { "No" },
        max
    ))
    .affected(
        why.into_iter().map(|w| tenant_item(t, w)).collect(),
        "settings",
    )
    .done()
}

fn auth_008(t: &Tenant) -> CheckResult {
    let Some(m) = method(t, "Fido2") else {
        return no_methods("EN-AUTH-008");
    };
    let on = m.s("state") == Some("enabled");
    let attest = m.b("isAttestationEnforced").unwrap_or(false);
    let mut out = check("EN-AUTH-008")
        .expected("Passkeys (FIDO2) enabled with attestation enforced")
        .found(format!(
            "Enabled: {}; attestation enforced: {}",
            if on { "Yes" } else { "No" },
            if attest { "Yes" } else { "No" }
        ))
        .evidence("Read from", read_from(t));
    if !on {
        out = out.affected(
            vec![tenant_item(t, "Passkeys (FIDO2) are disabled")],
            "tenant",
        );
    } else if !attest {
        out = out.affected(
            vec![tenant_item(t, "Attestation is not enforced")],
            "tenant",
        );
    }
    out.done()
}

fn auth_011(t: &Tenant) -> CheckResult {
    let check_on = setting(t, "Password Rule Settings", "EnableBannedPasswordCheck")
        .is_some_and(|v| v.eq_ignore_ascii_case("true"));
    let list = setting(t, "Password Rule Settings", "BannedPasswordList").unwrap_or_default();
    let words = list
        .split(['\t', ',', '\n'])
        .filter(|w| !w.trim().is_empty())
        .count();
    let mut out = check("EN-AUTH-011")
        .expected("A custom banned password list with the organization's own terms, enforced")
        .found(if check_on {
            format!("Custom list enforced, {}", plural(words, "term", "terms"))
        } else {
            "No custom banned password list enforced".to_string()
        })
        .evidence("Read from", read_from(t));
    if !check_on || words == 0 {
        out = out.affected(
            vec![tenant_item(t, "No custom banned password list")],
            "tenant",
        );
    }
    out.done()
}

fn auth_012(t: &Tenant) -> CheckResult {
    let threshold: i64 = setting(t, "Password Rule Settings", "LockoutThreshold")
        .and_then(|v| v.parse().ok())
        .unwrap_or(10);
    let duration: i64 = setting(t, "Password Rule Settings", "LockoutDurationInSeconds")
        .and_then(|v| v.parse().ok())
        .unwrap_or(60);
    let mut why = Vec::new();
    if threshold > 10 {
        why.push(format!("Lockout after {threshold} failed attempts"));
    }
    if duration < 60 {
        why.push(format!("Lockout lasts {duration} seconds"));
    }
    check("EN-AUTH-012")
        .expected("Lockout after 10 failed attempts or fewer, for at least 60 seconds")
        .found(format!(
            "Threshold {threshold}, duration {duration} seconds"
        ))
        .affected(
            why.into_iter().map(|w| tenant_item(t, w)).collect(),
            "settings",
        )
        .evidence("Read from", read_from(t))
        .done()
}

fn auth_014(t: &Tenant) -> CheckResult {
    let out = check("EN-AUTH-014")
        .expected(
            "Password hash sync on, for leaked credential detection and as a sign-in fallback",
        )
        .evidence("Read from", read_from(t));
    if !t.synced() {
        return out
            .not_assessed("The tenant does not sync from on-premises AD.")
            .done();
    }
    let on = t
        .raw
        .first("onpremsync")
        .and_then(|s| s.at(&["features", "passwordSyncEnabled"]))
        .and_then(Value::as_bool);
    match on {
        Some(true) => out.found("Password hash sync is on").done(),
        Some(false) => out
            .found("Password hash sync is off")
            .affected(vec![tenant_item(t, "Password hash sync is off")], "tenant")
            .done(),
        None => out
            .not_assessed("The directory synchronization features were empty.")
            .done(),
    }
}

fn state_switch(t: &Tenant, id: &str, path: &[&str], what: &str, expected: &str) -> CheckResult {
    let Some(p) = methods_policy(t) else {
        return no_methods(id);
    };
    let state = p.at(path).and_then(Value::as_str).unwrap_or("default");
    let mut out = check(id)
        .expected(expected)
        .found(format!("{what}: {state}"))
        .evidence("Read from", read_from(t));
    if state == "disabled" {
        out = out.affected(vec![tenant_item(t, format!("{what} disabled"))], "tenant");
    }
    out.done()
}

fn auth_015(t: &Tenant) -> CheckResult {
    state_switch(
        t,
        "EN-AUTH-015",
        &[
            "registrationEnforcement",
            "authenticationMethodsRegistrationCampaign",
            "state",
        ],
        "Registration campaign",
        "Registration campaign on (Microsoft managed or enabled)",
    )
}

fn auth_016(t: &Tenant) -> CheckResult {
    need_policy(
        t,
        "EN-AUTH-016",
        "At least one enabled policy uses an authentication strength",
        "No enabled policy uses an authentication strength",
        |p| p.strength().is_some(),
    )
}

fn auth_017(t: &Tenant) -> CheckResult {
    state_switch(
        t,
        "EN-AUTH-017",
        &["systemCredentialPreferences", "state"],
        "System-preferred MFA",
        "System-preferred MFA on (Microsoft managed or enabled)",
    )
}

fn auth_020(t: &Tenant) -> CheckResult {
    state_switch(
        t,
        "EN-AUTH-020",
        &["reportSuspiciousActivitySettings", "state"],
        "Report suspicious activity",
        "Report suspicious activity enabled",
    )
}

pub static RULES: &[Rule] = &[
    Rule {
        id: "EN-TEN-002",
        needs: &["securitydefaults", "capolicies"],
        run: ten_002,
    },
    Rule {
        id: "EN-ID-008",
        needs: &["capolicies", "users", "roleassignments"],
        run: id_008,
    },
    Rule {
        id: "EN-ID-013",
        needs: &["riskyusers", "capolicies"],
        run: id_013,
    },
    Rule {
        id: "EN-DEV-002",
        needs: &["deviceregistration", "capolicies"],
        run: dev_002,
    },
    Rule {
        id: "EN-CA-001",
        needs: &["capolicies"],
        run: ca_001,
    },
    Rule {
        id: "EN-CA-002",
        needs: &["capolicies", "securitydefaults"],
        run: ca_002,
    },
    Rule {
        id: "EN-CA-003",
        needs: &["capolicies"],
        run: ca_003,
    },
    Rule {
        id: "EN-CA-004",
        needs: &["capolicies", "securitydefaults"],
        run: ca_004,
    },
    Rule {
        id: "EN-CA-005",
        needs: &["capolicies"],
        run: ca_005,
    },
    Rule {
        id: "EN-CA-006",
        needs: &["capolicies", "skus"],
        run: ca_006,
    },
    Rule {
        id: "EN-CA-007",
        needs: &["capolicies", "skus"],
        run: ca_007,
    },
    Rule {
        id: "EN-CA-008",
        needs: &["capolicies"],
        run: ca_008,
    },
    Rule {
        id: "EN-CA-009",
        needs: &["capolicies"],
        run: ca_009,
    },
    Rule {
        id: "EN-CA-010",
        needs: &["capolicies"],
        run: ca_010,
    },
    Rule {
        id: "EN-CA-011",
        needs: &["capolicies"],
        run: ca_011,
    },
    Rule {
        id: "EN-CA-012",
        needs: &["capolicies"],
        run: ca_012,
    },
    Rule {
        id: "EN-CA-013",
        needs: &["capolicies"],
        run: ca_013,
    },
    Rule {
        id: "EN-CA-014",
        needs: &["namedlocations"],
        run: ca_014,
    },
    Rule {
        id: "EN-CA-015",
        needs: &["capolicies"],
        run: ca_015,
    },
    Rule {
        id: "EN-CA-016",
        needs: &["capolicies", "groups"],
        run: ca_016,
    },
    Rule {
        id: "EN-CA-019",
        needs: &["capolicies"],
        run: ca_019,
    },
    Rule {
        id: "EN-CA-022",
        needs: &["capolicies"],
        run: ca_022,
    },
    Rule {
        id: "EN-AUTH-001",
        needs: &["registration"],
        run: auth_001,
    },
    Rule {
        id: "EN-AUTH-002",
        needs: &["registration", "roleassignments"],
        run: auth_002,
    },
    Rule {
        id: "EN-AUTH-003",
        needs: &["authmethods"],
        run: auth_003,
    },
    Rule {
        id: "EN-AUTH-004",
        needs: &["authmethods"],
        run: auth_004,
    },
    Rule {
        id: "EN-AUTH-006",
        needs: &["authmethods"],
        run: auth_006,
    },
    Rule {
        id: "EN-AUTH-007",
        needs: &["authmethods"],
        run: auth_007,
    },
    Rule {
        id: "EN-AUTH-008",
        needs: &["authmethods"],
        run: auth_008,
    },
    Rule {
        id: "EN-AUTH-011",
        needs: &["groupsettings"],
        run: auth_011,
    },
    Rule {
        id: "EN-AUTH-012",
        needs: &["groupsettings"],
        run: auth_012,
    },
    Rule {
        id: "EN-AUTH-014",
        needs: &["organization", "onpremsync"],
        run: auth_014,
    },
    Rule {
        id: "EN-AUTH-015",
        needs: &["authmethods"],
        run: auth_015,
    },
    Rule {
        id: "EN-AUTH-016",
        needs: &["capolicies"],
        run: auth_016,
    },
    Rule {
        id: "EN-AUTH-017",
        needs: &["authmethods"],
        run: auth_017,
    },
    Rule {
        id: "EN-AUTH-020",
        needs: &["authmethods"],
        run: auth_020,
    },
];
