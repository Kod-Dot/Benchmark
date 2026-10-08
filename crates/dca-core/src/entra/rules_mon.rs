//! Entra checks on Identity Protection, service principal sign-ins,
//! federated credentials, access reviews, PIM alerts, branding and the
//! sign-in logs: monitoring, governance and hunting.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use super::model::{Tenant, J};
use super::rules::{read_from, tenant_item};
use super::rules_logs::{logs, user_item, when};
use super::rules_priv::sp_item;
use super::Rule;
use crate::ad::rules::{check, plural};
use crate::results::{Affected, CheckResult};
use crate::time;

/// Days without a sign-in after which a service principal counts as unused.
const UNUSED_DAYS: i64 = 90;

fn ts(v: Option<&str>) -> Option<i64> {
    v.and_then(time::parse_iso)
}

fn break_glass(u: &Value) -> bool {
    let text = format!(
        "{} {}",
        u.s("userPrincipalName").unwrap_or_default(),
        u.s("displayName").unwrap_or_default()
    )
    .to_ascii_lowercase()
    .replace(['-', '_', '.', ' '], "");
    text.contains("breakglass") || text.contains("emergency")
}

/// Break-glass accounts, as (id, user principal name).
pub(crate) fn break_glass_accounts<'a>(t: &Tenant<'a>) -> Vec<(&'a str, &'a str)> {
    t.users
        .iter()
        .filter(|(_, u)| break_glass(u))
        .map(|(id, u)| (*id, u.s("userPrincipalName").unwrap_or(id)))
        .collect()
}

// ---------- Applications ----------

fn app_012(t: &Tenant) -> CheckResult {
    let mut last: BTreeMap<&str, Option<i64>> = BTreeMap::new();
    for a in t.raw.list("spsignins") {
        if let Some(app) = a.s("appId") {
            last.insert(
                app,
                ts(a.at(&["lastSignInActivity", "lastSignInDateTime"])
                    .and_then(Value::as_str)),
            );
        }
    }
    let mut list: Vec<Affected> = t
        .sps
        .iter()
        .filter(|(_, s)| {
            s.s("appOwnerOrganizationId") == Some(t.id.as_str())
                && s.s("servicePrincipalType") == Some("Application")
                && s.b("accountEnabled") != Some(false)
                && t.days_since(ts(s.s("createdDateTime"))).is_none_or(|d| d > UNUSED_DAYS)
        })
        .filter_map(|(id, s)| {
            let seen = last.get(s.s("appId").unwrap_or_default()).copied().flatten();
            match t.days_since(seen) {
                Some(d) if d <= UNUSED_DAYS => None,
                Some(d) => Some(sp_item(t, id, format!("Last sign-in {d} days ago; its credentials and permissions are unused risk"))),
                None => Some(sp_item(t, id, "No sign-in recorded; its credentials and permissions are unused risk")),
            }
        })
        .collect();
    list.sort_by(|a, b| a.name.cmp(&b.name));
    check("EN-APP-012")
        .expected(format!("The tenant's own service principals have signed in within {UNUSED_DAYS} days, or are removed"))
        .found(plural(list.len(), "unused service principal", "unused service principals"))
        .affected(list, "apps")
        .evidence("Read from", format!("{}; service principal sign-in activity", read_from(t)))
        .done()
}

const KNOWN_ISSUERS: [&str; 6] = [
    "https://token.actions.githubusercontent.com",
    "https://login.microsoftonline.com/",
    "https://sts.windows.net/",
    "oidc.prod-aks.azure.com",
    "https://accounts.google.com",
    "https://vstoken.dev.azure.com/",
];

fn app_014(t: &Tenant) -> CheckResult {
    let mut total = 0;
    let mut list = Vec::new();
    for app in t.raw.list("fedcreds") {
        for c in app.a("federatedIdentityCredentials") {
            total += 1;
            let issuer = c.s("issuer").unwrap_or_default();
            let subject = c.s("subject").unwrap_or_default();
            let mut why = Vec::new();
            if subject.contains('*') {
                why.push("its subject has a wildcard");
            }
            if issuer.contains("githubusercontent") && subject.ends_with(":pull_request") {
                why.push("any pull request, including from a fork, can get a token");
            }
            if !KNOWN_ISSUERS.iter().any(|k| issuer.contains(k)) {
                why.push("its issuer is not a well-known identity provider");
            }
            if !why.is_empty() {
                list.push(t.object(
                    "app",
                    app.s("displayName").unwrap_or_default(),
                    Some(format!("{issuer} {subject}")),
                    format!(
                        "Federated credential {}: {}",
                        c.s("name").unwrap_or_default(),
                        why.join("; ")
                    ),
                ));
            }
        }
    }
    check("EN-APP-014")
        .expected("Federated identity credentials trust known issuers and narrow subjects")
        .found(format!(
            "{}; {} too broad",
            plural(total, "federated credential", "federated credentials"),
            list.len()
        ))
        .affected(list, "credentials")
        .evidence("Read from", read_from(t))
        .done()
}

fn app_023(t: &Tenant) -> CheckResult {
    let list: Vec<Affected> = t
        .raw
        .list("riskysps")
        .iter()
        .filter(|s| s.s("riskState") == Some("atRisk"))
        .map(|s| {
            let reason = format!(
                "At risk ({}), last updated {}",
                s.s("riskLevel").unwrap_or("unknown level"),
                when(s.s("riskLastUpdatedDateTime"))
            );
            match s.s("id").filter(|id| t.sps.contains_key(id)) {
                Some(id) => sp_item(t, id, reason),
                None => t.object(
                    "app",
                    s.s("displayName").unwrap_or_default(),
                    s.s("appId").map(str::to_string),
                    reason,
                ),
            }
        })
        .collect();
    check("EN-APP-023")
        .expected("No service principal is at risk in Identity Protection")
        .found(plural(
            list.len(),
            "risky service principal",
            "risky service principals",
        ))
        .affected(list, "apps")
        .evidence("Read from", read_from(t))
        .done()
}

// ---------- Devices ----------

fn dev_012(t: &Tenant) -> CheckResult {
    let mut per_device: BTreeMap<&str, (String, BTreeSet<String>, usize)> = BTreeMap::new();
    for s in t.raw.list("signins") {
        let Some(d) = s.o("deviceDetail") else {
            continue;
        };
        let id = d.s("deviceId").unwrap_or_default();
        if id.is_empty() || d.b("isCompliant") != Some(false) {
            continue;
        }
        let e = per_device.entry(id).or_insert_with(|| {
            (
                d.s("displayName").unwrap_or(id).to_string(),
                BTreeSet::new(),
                0,
            )
        });
        e.1.insert(s.s("appDisplayName").unwrap_or("an app").to_string());
        e.2 += 1;
    }
    let list: Vec<Affected> = per_device
        .into_values()
        .map(|(name, apps, n)| {
            t.object(
                "device",
                name,
                None,
                format!(
                    "{n} successful sign-ins while not compliant, to {}",
                    apps.into_iter().collect::<Vec<_>>().join(", ")
                ),
            )
        })
        .collect();
    logs(t, "EN-DEV-012", &["signins"])
        .expected("Registered devices that are not compliant cannot reach resources")
        .found(plural(list.len(), "non-compliant device", "non-compliant devices") + " signed in")
        .affected(list, "devices")
        .done()
}

// ---------- Governance ----------

fn review_scope(r: &Value) -> String {
    format!(
        "{} {}",
        r.get("scope").map(Value::to_string).unwrap_or_default(),
        r.get("instanceEnumerationScope")
            .map(Value::to_string)
            .unwrap_or_default()
    )
    .to_ascii_lowercase()
}

fn active_reviews<'a>(t: &Tenant<'a>) -> Vec<&'a Value> {
    t.raw
        .list("accessreviews")
        .iter()
        .filter(|r| !matches!(r.s("status"), Some("Completed")))
        .collect()
}

fn id_016(t: &Tenant) -> CheckResult {
    let guests = t
        .users
        .values()
        .filter(|u| u.s("userType") == Some("Guest"))
        .count();
    let found: Vec<&str> = active_reviews(t)
        .into_iter()
        .filter(|r| review_scope(r).contains("guest"))
        .filter_map(|r| r.s("displayName"))
        .collect();
    let list = if found.is_empty() && guests > 0 {
        vec![tenant_item(
            t,
            format!(
                "{} and no access review covers guests",
                plural(guests, "guest", "guests")
            ),
        )]
    } else {
        Vec::new()
    };
    check("EN-ID-016")
        .expected("A recurring access review covers guest accounts")
        .found(if found.is_empty() {
            "No guest access review".to_string()
        } else {
            format!("Reviewed by {}", found.join(", "))
        })
        .affected(list, "tenant")
        .evidence("Read from", read_from(t))
        .done()
}

fn priv_013(t: &Tenant) -> CheckResult {
    let found: Vec<&str> = active_reviews(t)
        .into_iter()
        .filter(|r| {
            let s = review_scope(r);
            s.contains("rolemanagement")
                || s.contains("roleassignmentscheduleinstances")
                || s.contains("roleeligibilityschedule")
        })
        .filter_map(|r| r.s("displayName"))
        .collect();
    let admins = t.privileged_principals().len();
    let list = if found.is_empty() && admins > 0 {
        vec![tenant_item(
            t,
            format!(
                "{} and no access review of privileged roles",
                plural(admins, "privileged principal", "privileged principals")
            ),
        )]
    } else {
        Vec::new()
    };
    check("EN-PRIV-013")
        .expected("Privileged role assignments are reviewed regularly")
        .found(if found.is_empty() {
            "No role access review".to_string()
        } else {
            format!("Reviewed by {}", found.join(", "))
        })
        .affected(list, "tenant")
        .evidence("Read from", read_from(t))
        .done()
}

fn priv_012(t: &Tenant) -> CheckResult {
    let list: Vec<Affected> = t
        .raw
        .list("pimalerts")
        .iter()
        .filter(|a| a.b("isActive") == Some(true))
        .map(|a| {
            let name = a
                .at(&["alertDefinition", "displayName"])
                .and_then(Value::as_str)
                .or(a.s("alertDefinitionId"))
                .unwrap_or("PIM alert");
            t.object(
                "alert",
                name,
                a.at(&["alertDefinition", "severityLevel"])
                    .and_then(Value::as_str)
                    .map(str::to_string),
                format!(
                    "{} open, last scanned {}",
                    plural(
                        a.n("incidentCount").unwrap_or(0) as usize,
                        "incident",
                        "incidents"
                    ),
                    when(a.s("lastScannedDateTime"))
                ),
            )
        })
        .collect();
    check("EN-PRIV-012")
        .expected("No PIM alert for directory roles is active")
        .found(plural(list.len(), "active alert", "active alerts"))
        .affected(list, "alerts")
        .evidence("Read from", read_from(t))
        .done()
}

// ---------- Tenant ----------

const BRANDING_LINKS: [&str; 5] = [
    "customAccountResetCredentialsUrl",
    "customCannotAccessYourAccountUrl",
    "customForgotMyPasswordText",
    "customPrivacyAndCookiesUrl",
    "customTermsOfUseUrl",
];

fn host(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    Some(
        rest.split(['/', '?', '#', ':'])
            .next()?
            .to_ascii_lowercase(),
    )
}

fn ten_016(t: &Tenant) -> CheckResult {
    let domains: Vec<String> = t
        .raw
        .list("domains")
        .iter()
        .filter_map(|d| d.s("id"))
        .map(str::to_ascii_lowercase)
        .collect();
    let ours = |h: &str| {
        domains
            .iter()
            .any(|d| h == d || h.ends_with(&format!(".{d}")))
            || h.ends_with("microsoft.com")
            || h.ends_with("microsoftonline.com")
    };
    let mut list = Vec::new();
    let mut set = Vec::new();
    for b in t.raw.list("branding") {
        for key in BRANDING_LINKS {
            let Some(v) = b.s(key).filter(|v| !v.is_empty()) else {
                continue;
            };
            set.push(key);
            if let Some(h) = host(v).filter(|h| !ours(h)) {
                list.push(tenant_item(
                    t,
                    format!("{key} points to {h}, outside the tenant's domains"),
                ));
            }
        }
        if let Some(text) = b.s("signInPageText").filter(|s| s.contains("http")) {
            list.push(tenant_item(
                t,
                format!("The sign-in page text contains a link: {text}"),
            ));
        }
    }
    check("EN-TEN-016")
        .expected("Sign-in page branding links only to the organization's own sites")
        .found(if set.is_empty() {
            "No custom links in the branding".to_string()
        } else {
            format!("Custom links: {}", set.join(", "))
        })
        .affected(list, "settings")
        .evidence("Read from", read_from(t))
        .done()
}

// ---------- Identity Protection ----------

fn detections<'a>(t: &Tenant<'a>, types: &[&str]) -> Vec<&'a Value> {
    let mut v: Vec<&Value> = t
        .raw
        .list("riskdetections")
        .iter()
        .filter(|d| types.is_empty() || d.s("riskEventType").is_some_and(|e| types.contains(&e)))
        .collect();
    v.sort_by(|a, b| b.s("detectedDateTime").cmp(&a.s("detectedDateTime")));
    v
}

fn detection_item(t: &Tenant, d: &Value) -> Affected {
    user_item(
        t,
        d.s("userId"),
        d.s("userPrincipalName"),
        format!(
            "{} ({} risk, {}) from {} {}",
            d.s("riskEventType").unwrap_or("detection"),
            d.s("riskLevel").unwrap_or("unknown"),
            d.s("riskState").unwrap_or("unknown state"),
            d.s("ipAddress").unwrap_or("an unknown address"),
            d.at(&["location", "countryOrRegion"])
                .and_then(Value::as_str)
                .unwrap_or_default()
        )
        .trim_end()
        .to_string(),
    )
    .seen_at(d.s("detectedDateTime"))
}

fn summary(list: &[&Value]) -> String {
    let mut by: BTreeMap<&str, usize> = BTreeMap::new();
    for d in list {
        *by.entry(d.s("riskEventType").unwrap_or("other"))
            .or_default() += 1;
    }
    by.into_iter()
        .map(|(k, n)| format!("{k}: {n}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn mon_003(t: &Tenant) -> CheckResult {
    let all = detections(t, &[]);
    let list: Vec<Affected> = all
        .iter()
        .filter(|d| d.s("riskLevel") == Some("high"))
        .map(|d| detection_item(t, d))
        .collect();
    check("EN-MON-003")
        .expected("No high-risk detections in the last 30 days")
        .found(format!(
            "{}; {} high risk",
            plural(all.len(), "detection", "detections"),
            list.len()
        ))
        .raw(summary(&all))
        .affected(list, "detections")
        .evidence(
            "Read from",
            format!("{}; Identity Protection, last 30 days", read_from(t)),
        )
        .done()
}

fn mon_004(t: &Tenant) -> CheckResult {
    let list: Vec<Affected> = detections(t, &[])
        .into_iter()
        .filter(|d| d.s("riskState") == Some("atRisk"))
        .map(|d| detection_item(t, d))
        .collect();
    check("EN-MON-004")
        .expected("Every risk detection is remediated or dismissed")
        .found(plural(
            list.len(),
            "unresolved detection",
            "unresolved detections",
        ))
        .affected(list, "detections")
        .evidence(
            "Read from",
            format!("{}; Identity Protection, last 30 days", read_from(t)),
        )
        .done()
}

fn hunt(t: &Tenant, id: &str, types: &[&str], expected: &str, noun: (&str, &str)) -> CheckResult {
    let list: Vec<Affected> = detections(t, types)
        .into_iter()
        .map(|d| detection_item(t, d))
        .collect();
    check(id)
        .expected(expected)
        .found(plural(list.len(), noun.0, noun.1) + " in the last 30 days")
        .affected(list, "detections")
        .evidence(
            "Read from",
            format!("{}; Identity Protection, last 30 days", read_from(t)),
        )
        .evidence("Detection types", types.join(", "))
        .done()
}

fn hunt_001(t: &Tenant) -> CheckResult {
    hunt(
        t,
        "HUNT-EN-001",
        &[
            "impossibleTravel",
            "unlikelyTravel",
            "newCountry",
            "unfamiliarFeatures",
            "anomalousUserActivity",
        ],
        "No impossible travel or anomalous sign-ins",
        ("anomalous sign-in", "anomalous sign-ins"),
    )
}

fn hunt_002(t: &Tenant) -> CheckResult {
    hunt(
        t,
        "HUNT-EN-002",
        &["anomalousToken", "tokenIssuerAnomaly", "attemptedPrtAccess"],
        "No token replay or forged token indicators",
        ("token anomaly", "token anomalies"),
    )
}

fn hunt_013(t: &Tenant) -> CheckResult {
    hunt(
        t,
        "HUNT-EN-013",
        &["anonymizedIPAddress", "maliciousIPAddress", "nationStateIP"],
        "No sign-ins from anonymizers or known malicious addresses",
        (
            "sign-in from a flagged address",
            "sign-ins from flagged addresses",
        ),
    )
}

// ---------- Sign-in logs ----------

fn mon_005(t: &Tenant) -> CheckResult {
    let mut by: BTreeMap<String, (usize, BTreeSet<&str>)> = BTreeMap::new();
    let signins = t.raw.list("signins");
    for s in signins {
        let c = s
            .at(&["location", "countryOrRegion"])
            .and_then(Value::as_str)
            .filter(|c| !c.is_empty())
            .unwrap_or("Unknown")
            .to_string();
        let e = by.entry(c).or_default();
        e.0 += 1;
        e.1.insert(s.s("userPrincipalName").unwrap_or_default());
    }
    let mut rows: Vec<(String, usize, usize)> =
        by.into_iter().map(|(c, (n, u))| (c, n, u.len())).collect();
    rows.sort_by_key(|a| std::cmp::Reverse(a.1));
    let total = signins.len().max(1);
    // Countries with under 1% of sign-ins are the unexpected ones to look at.
    let list: Vec<Affected> = rows
        .iter()
        .filter(|(_, n, _)| n * 100 < total)
        .map(|(c, n, u)| {
            t.object(
                "country",
                c,
                None,
                format!(
                    "{} by {}: rare for this tenant",
                    plural(*n, "sign-in", "sign-ins"),
                    plural(*u, "user", "users")
                ),
            )
        })
        .collect();
    logs(t, "EN-MON-005", &["signins"])
        .expected("Sign-ins come from the countries the organization works in")
        .found(format!(
            "{} from {}; {} rare",
            plural(signins.len(), "sign-in", "sign-ins"),
            plural(rows.len(), "country", "countries"),
            list.len()
        ))
        .raw(
            rows.iter()
                .map(|(c, n, u)| format!("{c}: {n} sign-ins, {u} users"))
                .collect::<Vec<_>>()
                .join("\n"),
        )
        .affected(list, "countries")
        .done()
}

fn mon_007(t: &Tenant) -> CheckResult {
    let mut weeks: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for s in t.raw.list("signinsfailed") {
        let code = s.at(&["status", "errorCode"]).and_then(Value::as_i64);
        let Some(at) = ts(s.s("createdDateTime")) else {
            continue;
        };
        let week = time::iso(at - at.rem_euclid(7 * time::DAY));
        let e = weeks
            .entry(week.get(..10).unwrap_or_default().to_string())
            .or_default();
        match code {
            Some(500121) => e.0 += 1,
            Some(53003) => e.1 += 1,
            _ => {}
        }
    }
    let rows: Vec<String> = weeks
        .iter()
        .map(|(w, (mfa, blocked))| {
            format!("Week of {w}: {mfa} failed MFA, {blocked} blocked by Conditional Access")
        })
        .collect();
    let (mfa, blocked) = weeks.values().fold((0, 0), |a, b| (a.0 + b.0, a.1 + b.1));
    logs(t, "EN-MON-007", &["signinsfailed"])
        .expected("Failed MFA and Conditional Access blocks are tracked week by week")
        .found(format!(
            "{mfa} failed MFA prompts and {blocked} blocked sign-ins in 30 days"
        ))
        .raw(rows.join("\n"))
        .done()
}

fn hunt_019(t: &Tenant) -> CheckResult {
    let mut per_sp: BTreeMap<&str, (String, BTreeMap<String, usize>)> = BTreeMap::new();
    for s in t.raw.list("signinssp") {
        let Some(id) = s.s("servicePrincipalId") else {
            continue;
        };
        let c = s
            .at(&["location", "countryOrRegion"])
            .and_then(Value::as_str)
            .filter(|c| !c.is_empty())
            .unwrap_or("Unknown")
            .to_string();
        let e = per_sp.entry(id).or_insert_with(|| {
            (
                s.s("servicePrincipalName").unwrap_or(id).to_string(),
                BTreeMap::new(),
            )
        });
        *e.1.entry(c).or_default() += 1;
    }
    let list: Vec<Affected> = per_sp
        .into_iter()
        .filter(|(_, (_, c))| c.len() > 1)
        .map(|(id, (name, countries))| {
            let text = countries
                .iter()
                .map(|(c, n)| format!("{c} ({n})"))
                .collect::<Vec<_>>()
                .join(", ");
            let reason = format!("Signed in from more than one country: {text}");
            if t.sps.contains_key(id) {
                sp_item(t, id, reason)
            } else {
                t.object("app", name, None, reason)
            }
        })
        .collect();
    logs(t, "HUNT-EN-019", &["signinssp"])
        .expected("Each service principal signs in from one place")
        .found(
            plural(list.len(), "service principal", "service principals")
                + " signing in from several countries",
        )
        .affected(list, "apps")
        .done()
}

// ---------- Licences ----------

const DEFENDER_PLANS: [(&str, &str); 6] = [
    ("ADALLOM_S", "Defender for Cloud Apps"),
    ("ATA", "Defender for Identity"),
    ("WINDEFATP", "Defender for Endpoint"),
    ("MDE_", "Defender for Endpoint"),
    ("ATP_ENTERPRISE", "Defender for Office 365"),
    ("MTP", "Defender XDR"),
];

fn mon_008(t: &Tenant) -> CheckResult {
    let mut found = BTreeSet::new();
    for s in t
        .raw
        .list("skus")
        .iter()
        .filter(|s| s.s("capabilityStatus") != Some("Suspended"))
    {
        for p in s.a("servicePlans") {
            let name = p.s("servicePlanName").unwrap_or_default();
            for (prefix, product) in DEFENDER_PLANS {
                if name.starts_with(prefix) {
                    found.insert(product);
                }
            }
        }
    }
    let list = if found.is_empty() {
        vec![tenant_item(t, "No Microsoft Defender product is licensed: Entra signals are not correlated with mail, endpoints or cloud apps")]
    } else {
        Vec::new()
    };
    check("EN-MON-008")
        .expected("Microsoft Defender XDR products are licensed and connected")
        .found(if found.is_empty() {
            "None licensed".to_string()
        } else {
            found.into_iter().collect::<Vec<_>>().join(", ")
        })
        .affected(list, "tenant")
        .evidence("Read from", read_from(t))
        .done()
}

pub static RULES: &[Rule] = &[
    Rule {
        id: "EN-APP-012",
        needs: &["serviceprincipals", "spsignins"],
        run: app_012,
    },
    Rule {
        id: "EN-APP-014",
        needs: &["fedcreds"],
        run: app_014,
    },
    Rule {
        id: "EN-APP-023",
        needs: &["riskysps"],
        run: app_023,
    },
    Rule {
        id: "EN-DEV-012",
        needs: &["signins"],
        run: dev_012,
    },
    Rule {
        id: "EN-ID-016",
        needs: &["users", "accessreviews"],
        run: id_016,
    },
    Rule {
        id: "EN-PRIV-012",
        needs: &["pimalerts"],
        run: priv_012,
    },
    Rule {
        id: "EN-PRIV-013",
        needs: &["roleassignments", "accessreviews"],
        run: priv_013,
    },
    Rule {
        id: "EN-TEN-016",
        needs: &["branding", "domains"],
        run: ten_016,
    },
    Rule {
        id: "EN-MON-003",
        needs: &["riskdetections"],
        run: mon_003,
    },
    Rule {
        id: "EN-MON-004",
        needs: &["riskdetections"],
        run: mon_004,
    },
    Rule {
        id: "EN-MON-005",
        needs: &["signins"],
        run: mon_005,
    },
    Rule {
        id: "EN-MON-007",
        needs: &["signinsfailed"],
        run: mon_007,
    },
    Rule {
        id: "EN-MON-008",
        needs: &["skus"],
        run: mon_008,
    },
    Rule {
        id: "HUNT-EN-001",
        needs: &["riskdetections"],
        run: hunt_001,
    },
    Rule {
        id: "HUNT-EN-002",
        needs: &["riskdetections"],
        run: hunt_002,
    },
    Rule {
        id: "HUNT-EN-013",
        needs: &["riskdetections"],
        run: hunt_013,
    },
    Rule {
        id: "HUNT-EN-019",
        needs: &["signinssp"],
        run: hunt_019,
    },
];
