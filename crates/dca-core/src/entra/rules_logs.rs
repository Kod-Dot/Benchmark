//! Sign-in and audit logs of the last 30 days: legacy authentication, spray
//! and MFA fatigue patterns, device code sign-ins, and the audit events
//! worth a second look.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use super::model::{Tenant, J};
use super::rules::{read_from, tenant_item};
use super::Rule;
use crate::ad::rules::{check, plural, Out};
use crate::results::{Affected, CheckResult};
use crate::time;

const SPRAY_ACCOUNTS: usize = 10;
const SPRAY_ATTEMPTS_PER_ACCOUNT: f64 = 3.0;
const FATIGUE_PROMPTS: usize = 5;
const INVITES_PER_DAY: usize = 20;
/// Graph-only and Microsoft first-party callers that make role assignments
/// on behalf of Privileged Identity Management.
const PIM_CALLERS: [&str; 2] = ["MS-PIM", "MS-PIM-Fairfax"];

pub(crate) fn logs(t: &Tenant, id: &str, areas: &[&str]) -> Out {
    let mut out = check(id).evidence(
        "Read from",
        format!("{}; logs of the last 30 days", read_from(t)),
    );
    let cut: Vec<&str> = areas
        .iter()
        .copied()
        .filter(|a| t.raw.truncated.contains(*a))
        .collect();
    if !cut.is_empty() {
        out = out.evidence("Note", "The tenant has more log records than the collector reads; the newest ones were checked");
    }
    out
}

/// "2026-10-03 14:05" from an ISO timestamp.
pub(crate) fn when(s: Option<&str>) -> String {
    s.map(|s| s.get(..16).unwrap_or(s).replace('T', " "))
        .unwrap_or_default()
}

fn success(s: &Value) -> bool {
    s.at(&["status", "errorCode"]).and_then(Value::as_i64) == Some(0)
}

pub(crate) fn error_code(s: &Value) -> Option<i64> {
    s.at(&["status", "errorCode"]).and_then(Value::as_i64)
}

/// The user a sign-in or audit event names, as an affected entry.
pub(crate) fn user_item(
    t: &Tenant,
    id: Option<&str>,
    upn: Option<&str>,
    reason: impl Into<String>,
) -> Affected {
    match id.filter(|i| t.users.contains_key(i)) {
        Some(i) => t.affected(i, reason),
        None => t.object("user", upn.or(id).unwrap_or("Unknown user"), None, reason),
    }
}

/// Who made an audit change: a user, or an application.
pub(crate) fn by(e: &Value) -> String {
    e.at(&["initiatedBy", "user", "userPrincipalName"])
        .or_else(|| e.at(&["initiatedBy", "app", "displayName"]))
        .and_then(Value::as_str)
        .unwrap_or("an unknown caller")
        .to_string()
}

fn caller_app(e: &Value) -> Option<&str> {
    e.at(&["initiatedBy", "app", "displayName"])
        .and_then(Value::as_str)
}

pub(crate) fn target(e: &Value) -> String {
    e.a("targetResources")
        .first()
        .and_then(|r| r.s("displayName").or(r.s("userPrincipalName")))
        .unwrap_or("Unnamed object")
        .to_string()
}

/// A modified property's new value, without the JSON quoting Graph keeps.
fn new_value<'a>(e: &'a Value, name: &str) -> Option<&'a str> {
    e.a("targetResources")
        .iter()
        .flat_map(|r| r.a("modifiedProperties"))
        .find(|p| p.s("displayName") == Some(name))
        .and_then(|p| p.s("newValue"))
        .map(|v| v.trim_matches(|c| c == '"' || c == '[' || c == ']'))
}

pub(crate) fn activity(e: &Value) -> &str {
    e.s("activityDisplayName").unwrap_or_default().trim()
}

fn audits<'a>(
    t: &'a Tenant,
    keep: impl Fn(&str) -> bool + 'a,
) -> impl Iterator<Item = &'a Value> + 'a {
    t.raw
        .list("audits")
        .iter()
        .filter(move |e| keep(activity(e)))
}

/// One finding per audit event that `keep` matches, newest first.
pub(crate) fn audit_check(
    t: &Tenant,
    id: &str,
    kind: &str,
    expected: &str,
    noun: (&str, &str),
    keep: impl Fn(&Value) -> bool,
) -> CheckResult {
    let mut events: Vec<&Value> = t.raw.list("audits").iter().filter(|e| keep(e)).collect();
    events.sort_by(|a, b| b.s("activityDateTime").cmp(&a.s("activityDateTime")));
    let list: Vec<Affected> = events
        .iter()
        .map(|e| {
            t.object(
                kind,
                target(e),
                Some(when(e.s("activityDateTime"))),
                format!("{} by {}", activity(e), by(e)),
            )
            .seen_at(e.s("activityDateTime"))
        })
        .collect();
    let out = logs(t, id, &["audits"]);
    out.expected(expected)
        .found(plural(list.len(), noun.0, noun.1) + " in the last 30 days")
        .affected(list, "changes")
        .done()
}

// ---------- Legacy authentication ----------

fn id_011(t: &Tenant) -> CheckResult {
    let mut by_user: BTreeMap<String, (Option<&str>, BTreeSet<&str>, usize)> = BTreeMap::new();
    for s in t.raw.list("signinslegacy").iter().filter(|s| success(s)) {
        let upn = s
            .s("userPrincipalName")
            .unwrap_or("Unknown user")
            .to_lowercase();
        let e = by_user
            .entry(upn)
            .or_insert((s.s("userId"), BTreeSet::new(), 0));
        e.1.insert(s.s("clientAppUsed").unwrap_or("Other clients"));
        e.2 += 1;
    }
    let list: Vec<Affected> = by_user
        .iter()
        .map(|(upn, (uid, protocols, n))| {
            user_item(
                t,
                *uid,
                Some(upn),
                format!(
                    "{} over {}",
                    plural(*n, "sign-in", "sign-ins"),
                    protocols.iter().copied().collect::<Vec<_>>().join(", ")
                ),
            )
        })
        .collect();
    let out = logs(t, "EN-ID-011", &["signinslegacy"]);
    out.expected("No successful sign-ins over legacy authentication protocols")
        .found(plural(list.len(), "user signed", "users signed") + " in with legacy authentication")
        .affected(list, "users")
        .done()
}

fn mon_006(t: &Tenant) -> CheckResult {
    let mut by_protocol: BTreeMap<&str, (usize, usize, BTreeSet<&str>)> = BTreeMap::new();
    for s in t.raw.list("signinslegacy") {
        let e = by_protocol
            .entry(s.s("clientAppUsed").unwrap_or("Other clients"))
            .or_default();
        if success(s) {
            e.0 += 1;
        } else {
            e.1 += 1;
        }
        if let Some(app) = s.s("appDisplayName") {
            e.2.insert(app);
        }
    }
    let mut out = logs(t, "EN-MON-006", &["signinslegacy"]);
    for (p, (ok, failed, _)) in &by_protocol {
        out = out.evidence(p, format!("{ok} successful, {failed} failed"));
    }
    let list: Vec<Affected> = by_protocol
        .iter()
        .filter(|(_, (ok, _, _))| *ok > 0)
        .map(|(p, (ok, failed, apps))| {
            let apps: Vec<&str> = apps.iter().copied().take(3).collect();
            t.object(
                "protocol",
                *p,
                None,
                format!(
                    "{ok} successful and {failed} failed sign-ins{}",
                    if apps.is_empty() {
                        String::new()
                    } else {
                        format!("; apps: {}", apps.join(", "))
                    }
                ),
            )
        })
        .collect();
    let total: usize = by_protocol.values().map(|v| v.0 + v.1).sum();
    out.expected("Legacy protocols see no successful sign-ins, only blocked attempts")
        .found(format!(
            "{} with successful sign-ins; {} in total",
            plural(list.len(), "legacy protocol", "legacy protocols"),
            plural(total, "legacy sign-in", "legacy sign-ins")
        ))
        .affected(list, "protocols")
        .done()
}

// ---------- Patterns in failed sign-ins ----------

/// Wrong-password failures from one address.
#[derive(Default)]
struct Spray<'a> {
    users: BTreeSet<String>,
    attempts: usize,
    country: Option<&'a str>,
    first: Option<&'a str>,
    last: Option<&'a str>,
}

fn hunt_003(t: &Tenant) -> CheckResult {
    let mut by_ip: BTreeMap<&str, Spray> = BTreeMap::new();
    for s in t
        .raw
        .list("signinsfailed")
        .iter()
        .filter(|s| error_code(s) == Some(50126))
    {
        let Some(ip) = s.s("ipAddress") else { continue };
        let e = by_ip.entry(ip).or_default();
        e.users
            .insert(s.s("userPrincipalName").unwrap_or_default().to_lowercase());
        e.attempts += 1;
        let at = s.s("createdDateTime");
        if e.first.is_none_or(|first| at.is_some_and(|a| a < first)) {
            e.first = at;
        }
        if e.last.is_none_or(|last| at.is_some_and(|a| a > last)) {
            e.last = at;
        }
        if e.country.is_none() {
            e.country = s
                .at(&["location", "countryOrRegion"])
                .and_then(Value::as_str);
        }
    }
    let list: Vec<Affected> = by_ip
        .iter()
        .filter(|(_, e)| {
            e.users.len() >= SPRAY_ACCOUNTS
                && (e.attempts as f64 / e.users.len() as f64) <= SPRAY_ATTEMPTS_PER_ACCOUNT
        })
        .map(|(ip, e)| {
            t.object(
                "ip",
                *ip,
                e.country.map(str::to_string),
                format!(
                    "{} against {} between {} and {}",
                    plural(e.attempts, "wrong password", "wrong passwords"),
                    plural(e.users.len(), "account", "accounts"),
                    when(e.first),
                    when(e.last)
                ),
            )
            .seen_at(e.last)
        })
        .collect();
    let out = logs(t, "HUNT-EN-003", &["signinsfailed"]);
    out.expected(format!(
        "No address tries passwords against {SPRAY_ACCOUNTS} or more accounts with few attempts each"
    ))
    .found(plural(list.len(), "address shows", "addresses show") + " a password spray pattern")
    .affected(list, "addresses")
    .done()
}

/// The most events within `window` seconds, and when that run started.
fn busiest(times: &mut [i64], window: i64) -> (usize, i64) {
    times.sort_unstable();
    let mut best = (0, 0);
    let mut start = 0;
    for end in 0..times.len() {
        while times[end] - times[start] > window {
            start += 1;
        }
        if end - start + 1 > best.0 {
            best = (end - start + 1, times[start]);
        }
    }
    best
}

fn hunt_004(t: &Tenant) -> CheckResult {
    let mut by_user: BTreeMap<String, (Option<&str>, Vec<i64>)> = BTreeMap::new();
    for s in t
        .raw
        .list("signinsfailed")
        .iter()
        .filter(|s| error_code(s) == Some(500121))
    {
        let Some(at) = s.t("createdDateTime") else {
            continue;
        };
        let upn = s
            .s("userPrincipalName")
            .unwrap_or("Unknown user")
            .to_lowercase();
        let e = by_user.entry(upn).or_insert((s.s("userId"), Vec::new()));
        e.1.push(at);
    }
    let mut list = Vec::new();
    for (upn, (uid, mut times)) in by_user {
        let (n, start) = busiest(&mut times, 3600);
        if n >= FATIGUE_PROMPTS {
            list.push(
                user_item(
                    t,
                    uid,
                    Some(&upn),
                    format!(
                        "{n} failed MFA prompts within an hour from {}",
                        when(Some(&time::iso(start)))
                    ),
                )
                .seen_at(Some(&time::iso(start))),
            );
        }
    }
    let out = logs(t, "HUNT-EN-004", &["signinsfailed"]);
    out.expected(format!(
        "No account gets {FATIGUE_PROMPTS} or more failed MFA prompts within an hour"
    ))
    .found(plural(list.len(), "account shows", "accounts show") + " an MFA fatigue pattern")
    .affected(list, "users")
    .done()
}

fn hunt_012(t: &Tenant) -> CheckResult {
    let mut by_user: BTreeMap<String, (Option<&str>, BTreeSet<&str>, usize)> = BTreeMap::new();
    for s in t
        .raw
        .list("signinsdevicecode")
        .iter()
        .filter(|s| success(s))
    {
        let upn = s
            .s("userPrincipalName")
            .unwrap_or("Unknown user")
            .to_lowercase();
        let e = by_user
            .entry(upn)
            .or_insert((s.s("userId"), BTreeSet::new(), 0));
        e.1.insert(s.s("appDisplayName").unwrap_or("an unnamed app"));
        e.2 += 1;
    }
    let list: Vec<Affected> = by_user
        .iter()
        .map(|(upn, (uid, apps, n))| {
            user_item(
                t,
                *uid,
                Some(upn),
                format!(
                    "{} to {}",
                    plural(*n, "device code sign-in", "device code sign-ins"),
                    apps.iter().copied().collect::<Vec<_>>().join(", ")
                ),
            )
        })
        .collect();
    let out = logs(t, "HUNT-EN-012", &["signinsdevicecode"]);
    out.expected("No device code sign-ins, or only expected ones from known devices")
        .found(plural(list.len(), "user signed", "users signed") + " in with a device code")
        .affected(list, "users")
        .done()
}

fn hunt_014(t: &Tenant) -> CheckResult {
    let mut by_inviter: BTreeMap<String, Vec<i64>> = BTreeMap::new();
    for e in t.raw.list("invites") {
        let Some(at) = e.t("activityDateTime") else {
            continue;
        };
        by_inviter.entry(by(e)).or_default().push(at);
    }
    let mut list = Vec::new();
    let mut total = 0;
    for (who, mut times) in by_inviter {
        total += times.len();
        let (n, start) = busiest(&mut times, time::DAY);
        if n >= INVITES_PER_DAY {
            let id = t
                .users
                .values()
                .find(|u| {
                    u.s("userPrincipalName")
                        .is_some_and(|p| p.eq_ignore_ascii_case(&who))
                })
                .and_then(|u| u.s("id"));
            list.push(
                user_item(
                    t,
                    id,
                    Some(&who),
                    format!(
                        "{n} guests invited within 24 hours from {}",
                        when(Some(&time::iso(start)))
                    ),
                )
                .seen_at(Some(&time::iso(start))),
            );
        }
    }
    let out = logs(t, "HUNT-EN-014", &["invites"]);
    out.expected(format!(
        "No account invites {INVITES_PER_DAY} or more guests within a day"
    ))
    .found(plural(list.len(), "account invited", "accounts invited") + " guests at scale")
    .affected(list, "users")
    .evidence("Invitations in 30 days", total.to_string())
    .done()
}

// ---------- Audit events ----------

fn hunt_005(t: &Tenant) -> CheckResult {
    audit_check(
        t,
        "HUNT-EN-005",
        "app",
        "New secrets and certificates on applications are expected and owned",
        ("credential change", "credential changes"),
        |e| {
            let a = activity(e);
            a == "Add service principal credentials"
                || a.contains("Certificates and secrets management")
        },
    )
}

fn hunt_006(t: &Tenant) -> CheckResult {
    audit_check(
        t,
        "HUNT-EN-006",
        "domain",
        "No change to how a domain authenticates",
        (
            "domain authentication change",
            "domain authentication changes",
        ),
        |e| {
            matches!(
                activity(e),
                "Set domain authentication" | "Set federation settings on domain"
            )
        },
    )
}

fn hunt_007(t: &Tenant) -> CheckResult {
    let mut events: Vec<&Value> = audits(t, |a| a == "Consent to application").collect();
    events.sort_by(|a, b| b.s("activityDateTime").cmp(&a.s("activityDateTime")));
    let list: Vec<Affected> = events
        .iter()
        .map(|e| {
            let admin = new_value(e, "ConsentContext.IsAdminConsent")
                .is_some_and(|v| v.eq_ignore_ascii_case("true"));
            t.object(
                "app",
                target(e),
                Some(when(e.s("activityDateTime"))),
                format!(
                    "{} by {}",
                    if admin {
                        "Admin consent for all users"
                    } else {
                        "User consent"
                    },
                    by(e)
                ),
            )
            .seen_at(e.s("activityDateTime"))
        })
        .collect();
    let out = logs(t, "HUNT-EN-007", &["audits"]);
    out.expected("Consents go through the admin consent workflow and are for known apps")
        .found(plural(list.len(), "consent", "consents") + " in the last 30 days")
        .affected(list, "consents")
        .done()
}

fn hunt_008(t: &Tenant) -> CheckResult {
    let mut events: Vec<&Value> = audits(t, |a| a == "Add member to role")
        .filter(|e| !caller_app(e).is_some_and(|a| PIM_CALLERS.contains(&a)))
        .collect();
    events.sort_by(|a, b| b.s("activityDateTime").cmp(&a.s("activityDateTime")));
    let list: Vec<Affected> = events
        .iter()
        .map(|e| {
            let role = new_value(e, "Role.DisplayName").unwrap_or("a directory role");
            let r = e.a("targetResources").first();
            user_item(
                t,
                r.and_then(|r| r.s("id")),
                r.and_then(|r| r.s("userPrincipalName").or(r.s("displayName"))),
                format!(
                    "Given {role} by {} on {}",
                    by(e),
                    when(e.s("activityDateTime"))
                ),
            )
            .seen_at(e.s("activityDateTime"))
        })
        .collect();
    let out = logs(t, "HUNT-EN-008", &["audits"]);
    out.expected("Directory roles are given through PIM, not assigned directly")
        .found(
            plural(
                list.len(),
                "direct role assignment",
                "direct role assignments",
            ) + " in the last 30 days",
        )
        .affected(list, "assignments")
        .done()
}

fn hunt_009(t: &Tenant) -> CheckResult {
    audit_check(
        t,
        "HUNT-EN-009",
        "policy",
        "Conditional Access changes are planned, reviewed and made by known admins",
        ("Conditional Access change", "Conditional Access changes"),
        |e| {
            matches!(
                activity(e),
                "Update conditional access policy" | "Delete conditional access policy"
            )
        },
    )
}

fn hunt_020(t: &Tenant) -> CheckResult {
    let mut events: Vec<&Value> = audits(t, |a| {
        a == "Set DirSyncEnabled flag" || a == "Set directory feature on tenant"
    })
    .collect();
    events.sort_by(|a, b| b.s("activityDateTime").cmp(&a.s("activityDateTime")));
    let list: Vec<Affected> = events
        .iter()
        .map(|e| {
            let mut a = tenant_item(t, format!("{} by {}", activity(e), by(e)));
            a.location = Some(when(e.s("activityDateTime")));
            a.seen_at(e.s("activityDateTime"))
        })
        .collect();
    let out = logs(t, "HUNT-EN-020", &["audits"]);
    out.expected("Directory synchronization settings do not change outside planned work")
        .found(
            plural(list.len(), "sync setting change", "sync setting changes")
                + " in the last 30 days",
        )
        .affected(list, "changes")
        .done()
}

fn mon_010(t: &Tenant) -> CheckResult {
    let mut by_activity: BTreeMap<&str, usize> = BTreeMap::new();
    for e in t.raw.list("audits") {
        *by_activity.entry(activity(e)).or_default() += 1;
    }
    let mut top: Vec<(&str, usize)> = by_activity.into_iter().collect();
    top.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    let total: usize = top.iter().map(|x| x.1).sum();
    let mut out = logs(t, "EN-MON-010", &["audits"]);
    out = out
        .expected("Changes to roles, applications, policies and directory settings are reviewed")
        .found(format!(
            "{} to roles, applications, policies and directory settings in the last 30 days",
            plural(total, "change", "changes")
        ));
    for (a, n) in top.into_iter().take(15) {
        out = out.evidence(a, n.to_string());
    }
    out.done()
}

pub static RULES: &[Rule] = &[
    Rule {
        id: "EN-ID-011",
        needs: &["signinslegacy"],
        run: id_011,
    },
    Rule {
        id: "EN-MON-006",
        needs: &["signinslegacy"],
        run: mon_006,
    },
    Rule {
        id: "EN-MON-010",
        needs: &["audits"],
        run: mon_010,
    },
    Rule {
        id: "HUNT-EN-003",
        needs: &["signinsfailed"],
        run: hunt_003,
    },
    Rule {
        id: "HUNT-EN-004",
        needs: &["signinsfailed"],
        run: hunt_004,
    },
    Rule {
        id: "HUNT-EN-005",
        needs: &["audits"],
        run: hunt_005,
    },
    Rule {
        id: "HUNT-EN-006",
        needs: &["audits"],
        run: hunt_006,
    },
    Rule {
        id: "HUNT-EN-007",
        needs: &["audits"],
        run: hunt_007,
    },
    Rule {
        id: "HUNT-EN-008",
        needs: &["audits"],
        run: hunt_008,
    },
    Rule {
        id: "HUNT-EN-009",
        needs: &["audits"],
        run: hunt_009,
    },
    Rule {
        id: "HUNT-EN-012",
        needs: &["signinsdevicecode"],
        run: hunt_012,
    },
    Rule {
        id: "HUNT-EN-014",
        needs: &["invites", "users"],
        run: hunt_014,
    },
    Rule {
        id: "HUNT-EN-020",
        needs: &["audits"],
        run: hunt_020,
    },
];

#[cfg(test)]
mod tests {
    use super::busiest;

    #[test]
    fn busiest_window() {
        let mut t = vec![0, 100, 5000, 5100, 5200, 5300, 9000];
        assert_eq!(busiest(&mut t, 3600), (4, 5000));
    }
}
