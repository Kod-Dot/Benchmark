//! App Proxy pre-authentication, BitLocker key escrow, empty and looping
//! groups, guest invitation domain lists and the admin portal restriction.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use super::model::{Tenant, J};
use super::rules::{read_from, tenant_item};
use super::Rule;
use crate::ad::rules::{check, plural, Out};
use crate::results::{Affected, CheckResult};
use crate::time;

/// Devices that signed in within this many days are expected to have keys.
const ACTIVE_DAYS: i64 = 30;

fn out(t: &Tenant, id: &str) -> Out {
    check(id).evidence("Read from", read_from(t))
}

fn app_021(t: &Tenant) -> CheckResult {
    let apps = t.raw.list("appproxy");
    let found: Vec<Affected> = apps
        .iter()
        .filter(|a| {
            a.at(&["onPremisesPublishing", "externalAuthenticationType"])
                .and_then(Value::as_str)
                == Some("passthru")
        })
        .map(|a| {
            t.object(
                "app",
                a.s("displayName").unwrap_or_default(),
                a.at(&["onPremisesPublishing", "externalUrl"])
                    .and_then(Value::as_str)
                    .map(str::to_string),
                format!(
                    "Published without pre-authentication: anyone on the internet reaches {}",
                    a.at(&["onPremisesPublishing", "internalUrl"])
                        .and_then(Value::as_str)
                        .unwrap_or("the internal application")
                ),
            )
        })
        .collect();
    out(t, "EN-APP-021")
        .expected("App Proxy applications require Microsoft Entra pre-authentication")
        .found(format!(
            "{} of {} pass traffic through without sign-in",
            found.len(),
            plural(
                apps.len(),
                "App Proxy application",
                "App Proxy applications"
            )
        ))
        .affected(found, "apps")
        .done()
}

fn dev_008(t: &Tenant) -> CheckResult {
    let with_key: BTreeSet<String> = t
        .raw
        .list("bitlockerkeys")
        .iter()
        .filter(|k| {
            k.s("volumeType")
                .is_none_or(|v| v == "operatingSystemVolume")
        })
        .filter_map(|k| k.s("deviceId"))
        .map(str::to_lowercase)
        .collect();
    let windows: Vec<&Value> = t
        .raw
        .list("devices")
        .iter()
        .filter(|d| {
            d.s("operatingSystem")
                .is_some_and(|o| o.eq_ignore_ascii_case("Windows"))
                && d.b("accountEnabled") != Some(false)
        })
        .filter(|d| matches!(d.s("trustType"), Some("AzureAd" | "ServerAd")))
        .filter(|d| {
            t.days_since(
                d.s("approximateLastSignInDateTime")
                    .and_then(time::parse_iso),
            )
            .is_some_and(|x| x <= ACTIVE_DAYS)
        })
        .collect();
    let found: Vec<Affected> = windows
        .iter()
        .filter(|d| {
            !d.s("deviceId")
                .is_some_and(|id| with_key.contains(&id.to_lowercase()))
        })
        .map(|d| {
            t.object(
                "device",
                d.s("displayName").unwrap_or_default(),
                d.s("operatingSystemVersion").map(str::to_string),
                "No BitLocker recovery key for the system drive is stored in Entra ID",
            )
        })
        .collect();
    out(t, "EN-DEV-008")
        .expected("Every active Windows device escrows its BitLocker recovery key in Entra ID")
        .found(format!(
            "{} of {} without a key",
            found.len(),
            plural(
                windows.len(),
                "active Windows device",
                "active Windows devices"
            )
        ))
        .affected(found, "devices")
        .evidence("Note", "Only which devices have a key is read, never a key")
        .done()
}

fn grp_010(t: &Tenant) -> CheckResult {
    let groups = t.raw.list("groupmembers");
    let names: BTreeMap<&str, &str> = groups
        .iter()
        .filter_map(|g| Some((g.s("id")?, g.s("displayName").unwrap_or_default())))
        .collect();
    let mut edges: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    let mut found = Vec::new();
    for g in groups {
        let Some(id) = g.s("id") else { continue };
        let members = g.a("members");
        let dynamic = g.s("membershipRule").is_some_and(|r| !r.is_empty());
        if members.is_empty() && !dynamic {
            found.push(t.object("group", g.s("displayName").unwrap_or_default(), None, "Empty group: unused, or a placeholder someone could fill to gain whatever it grants"));
        }
        for m in members {
            if let Some(mid) = m.s("id").filter(|mid| names.contains_key(mid)) {
                edges.entry(id).or_default().push(mid);
            }
        }
    }
    // Loops in nesting, found from each group by depth-first search.
    let mut reported: BTreeSet<Vec<&str>> = BTreeSet::new();
    for &start in edges.keys() {
        let mut stack = vec![(start, vec![start])];
        while let Some((n, path)) = stack.pop() {
            for &next in edges.get(n).into_iter().flatten() {
                if next == start {
                    let mut key = path.clone();
                    key.sort_unstable();
                    if reported.insert(key) {
                        let text: Vec<&str> = path
                            .iter()
                            .chain([&start])
                            .map(|g| names.get(g).copied().unwrap_or(g))
                            .collect();
                        found.push(t.object(
                            "group",
                            names.get(start).copied().unwrap_or(start),
                            None,
                            format!("Nesting loop: {}", text.join(" → ")),
                        ));
                    }
                } else if !path.contains(&next) && path.len() < 10 {
                    let mut p = path.clone();
                    p.push(next);
                    stack.push((next, p));
                }
            }
        }
    }
    out(t, "EN-GRP-010")
        .expected("No empty groups and no loops in group nesting")
        .found(plural(found.len(), "finding", "findings"))
        .affected(found, "groups")
        .evidence("Note", "Graph returns the first 20 members of each group, which is enough to tell empty groups and nesting")
        .done()
}

fn ten_008(t: &Tenant) -> CheckResult {
    let mut allowed: Vec<String> = Vec::new();
    let mut blocked: Vec<String> = Vec::new();
    for p in t.raw.list("b2bmanagement") {
        for d in p.strs("definition") {
            let Ok(v) = serde_json::from_str::<Value>(d) else {
                continue;
            };
            let Some(i) = v.at(&[
                "B2BManagementPolicy",
                "InvitationsAllowedAndBlockedDomainsPolicy",
            ]) else {
                continue;
            };
            allowed.extend(i.strs("AllowedDomains").into_iter().map(str::to_string));
            blocked.extend(i.strs("BlockedDomains").into_iter().map(str::to_string));
        }
    }
    let who = t
        .raw
        .first("authorization")
        .and_then(|a| a.s("allowInvitesFrom"))
        .unwrap_or("everyone");
    let mut found = Vec::new();
    if allowed.is_empty() && blocked.is_empty() && who != "none" {
        found.push(tenant_item(
            t,
            "Guests can be invited from any domain: there is no allow or block list",
        ));
    }
    if who == "everyone" {
        found.push(tenant_item(
            t,
            "Everyone, including guests, can invite guests",
        ));
    }
    out(t, "EN-TEN-008")
        .expected("Guest invitations are limited to allowed partner domains (or block known-bad ones) and to designated inviters")
        .found(format!(
            "{}; invites from {who}",
            if !allowed.is_empty() {
                format!("Allowed domains: {}", allowed.join(", "))
            } else if !blocked.is_empty() {
                format!("Blocked domains: {}", blocked.join(", "))
            } else {
                "No domain list".to_string()
            }
        ))
        .affected(found, "settings")
        .done()
}

fn ten_012(t: &Tenant) -> CheckResult {
    let v = t
        .raw
        .first("uxsetting")
        .and_then(|u| u.s("restrictNonAdminAccess"))
        .unwrap_or("false");
    let on = v == "true";
    out(t, "EN-TEN-012")
        .expected("Non-admin users cannot open the Microsoft Entra admin center")
        .found(if on { "Restricted" } else { "Not restricted" })
        .affected(
            if on {
                Vec::new()
            } else {
                vec![tenant_item(
                    t,
                    "Any user can browse the directory, apps and settings in the admin center",
                )]
            },
            "tenant",
        )
        .done()
}

pub static RULES: &[Rule] = &[
    Rule {
        id: "EN-APP-021",
        needs: &["appproxy", "serviceprincipals"],
        run: app_021,
    },
    Rule {
        id: "EN-DEV-008",
        needs: &["devices", "bitlockerkeys"],
        run: dev_008,
    },
    Rule {
        id: "EN-GRP-010",
        needs: &["groupmembers"],
        run: grp_010,
    },
    Rule {
        id: "EN-TEN-008",
        needs: &["b2bmanagement", "authorization"],
        run: ten_008,
    },
    Rule {
        id: "EN-TEN-012",
        needs: &["uxsetting"],
        run: ten_012,
    },
];
