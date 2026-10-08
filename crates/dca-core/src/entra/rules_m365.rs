//! SharePoint Online and OneDrive, Teams and Purview checks. Tenant
//! settings come from Microsoft Graph where Graph has them; the rest from
//! Microsoft's own modules (Get-SPO*, Get-Cs*, Security & Compliance
//! PowerShell), whose properties keep their PascalCase names.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use super::model::{Tenant, J};
use super::rules::{read_from, tenant_item};
use super::Rule;
use crate::ad::rules::{check, plural, Out};
use crate::results::{Affected, CheckResult};
use crate::time;

/// Days an "Anyone" link may live.
const ANYONE_LINK_DAYS: i64 = 30;
/// Days a departed user's OneDrive should be kept.
const ONEDRIVE_RETENTION_DAYS: i64 = 90;
/// Days a DLP policy may stay in test mode.
const DLP_TEST_DAYS: i64 = 30;

const TEAMS_ADMIN: &str = "69091246-20e8-4a56-aa4d-066075b2a7a8";
const TEAMS_COMMS_ADMIN: &str = "baf37b3a-610e-45da-9e62-d9d1e5e8914b";
const TEAMS_DEVICES_ADMIN: &str = "3d762c5a-1b6c-493f-843e-55a3b42923d4";

fn out(t: &Tenant, id: &str, source: &str) -> Out {
    check(id).evidence("Read from", format!("{}; {source}", read_from(t)))
}

/// A number written as a number or as text.
fn num(v: &Value, key: &str) -> Option<i64> {
    match v.get(key)? {
        Value::Number(n) => n.as_i64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// A boolean written as a boolean or as text.
fn flag(v: &Value, key: &str) -> Option<bool> {
    match v.get(key)? {
        Value::Bool(b) => Some(*b),
        Value::String(s) => s.parse::<bool>().ok().or(match s.as_str() {
            "True" => Some(true),
            "False" => Some(false),
            _ => None,
        }),
        _ => None,
    }
}

fn text<'a>(v: &'a Value, key: &str) -> &'a str {
    v.s(key).unwrap_or_default()
}

/// A list written as an array, or as text.
fn list_of(v: &Value, key: &str) -> Vec<String> {
    match v.get(key) {
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
        Some(Value::String(s)) if !s.is_empty() => vec![s.clone()],
        _ => Vec::new(),
    }
}

fn eq(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

fn items(t: &Tenant, missing: Vec<String>) -> Vec<Affected> {
    missing.into_iter().map(|m| tenant_item(t, m)).collect()
}

// ---------- SharePoint and OneDrive ----------

const SPO: &str = "SharePoint Online";

fn spo_settings<'a>(t: &Tenant<'a>) -> Option<&'a Value> {
    t.raw.first("sposettings")
}

fn spo_tenant<'a>(t: &Tenant<'a>) -> Option<&'a Value> {
    t.raw.first("spotenant")
}

fn site_item(t: &Tenant, s: &Value, reason: impl Into<String>) -> Affected {
    t.object(
        "site",
        text(s, "Url"),
        s.s("Title").map(str::to_string),
        reason,
    )
}

fn spo_001(t: &Tenant) -> CheckResult {
    let level = spo_settings(t)
        .and_then(|s| s.s("sharingCapability"))
        .unwrap_or("unknown");
    let mut list = Vec::new();
    if eq(level, "externalUserAndGuestSharing") {
        list.push(tenant_item(
            t,
            "Anyone links are allowed: files can be shared with people who never sign in",
        ));
    }
    for s in t.raw.list("sposites") {
        if eq(text(s, "SharingCapability"), "ExternalUserAndGuestSharing") {
            list.push(site_item(t, s, "Site allows Anyone links"));
        }
    }
    out(t, "M365-SPO-001", SPO)
        .expected("External sharing is limited to new and existing guests, and only sites that need it allow it")
        .found(format!("Tenant sharing level: {level}"))
        .affected(list, "sites")
        .done()
}

fn spo_002(t: &Tenant) -> CheckResult {
    let o = out(t, "M365-SPO-002", SPO).expected(format!(
        "Anyone links are off, or are not the default and expire within {ANYONE_LINK_DAYS} days"
    ));
    let Some(s) = spo_tenant(t) else {
        return o.not_assessed("Get-SPOTenant was not read.").done();
    };
    if !eq(text(s, "SharingCapability"), "ExternalUserAndGuestSharing") {
        return o.found("Anyone links are not allowed").done();
    }
    let mut missing = Vec::new();
    if eq(text(s, "DefaultSharingLinkType"), "AnonymousAccess") {
        missing.push("The default sharing link is an Anyone link".to_string());
    }
    let days = num(s, "RequireAnonymousLinksExpireInDays").unwrap_or(-1);
    if days <= 0 {
        missing.push("Anyone links never expire".to_string());
    } else if days > ANYONE_LINK_DAYS {
        missing.push(format!("Anyone links expire after {days} days"));
    }
    o.found(format!(
        "Anyone links allowed; default {}; expiry {}",
        text(s, "DefaultSharingLinkType"),
        if days > 0 {
            format!("{days} days")
        } else {
            "none".into()
        }
    ))
    .affected(items(t, missing), "settings")
    .done()
}

fn spo_003(t: &Tenant) -> CheckResult {
    let o = out(t, "M365-SPO-003", SPO)
        .expected("Guest access expires and guests re-authenticate with a verification code");
    let Some(s) = spo_tenant(t) else {
        return o.not_assessed("Get-SPOTenant was not read.").done();
    };
    let mut missing = Vec::new();
    if flag(s, "ExternalUserExpirationRequired") != Some(true) {
        missing.push("Guest access to sites never expires".to_string());
    }
    if flag(s, "EmailAttestationRequired") != Some(true) {
        missing.push("Guests are not asked to re-verify their email address".to_string());
    }
    o.found(format!(
        "Expiry {}, re-verification {}",
        flag(s, "ExternalUserExpirationRequired").unwrap_or(false),
        flag(s, "EmailAttestationRequired").unwrap_or(false)
    ))
    .affected(items(t, missing), "settings")
    .done()
}

fn spo_004(t: &Tenant) -> CheckResult {
    let s = spo_settings(t);
    let level = s
        .and_then(|s| s.s("sharingCapability"))
        .unwrap_or("unknown");
    let mode = s
        .and_then(|s| s.s("sharingDomainRestrictionMode"))
        .unwrap_or("none");
    let open = !eq(level, "disabled") && eq(mode, "none");
    out(t, "M365-SPO-004", SPO)
        .expected("External sharing is limited to allowed domains, or blocks known-bad ones")
        .found(format!("Domain restriction: {mode}"))
        .affected(
            if open {
                vec![tenant_item(
                    t,
                    "Files can be shared with any external domain",
                )]
            } else {
                Vec::new()
            },
            "tenant",
        )
        .done()
}

fn broad_sites(t: &Tenant) -> BTreeMap<String, BTreeSet<String>> {
    let mut by: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for u in t
        .raw
        .list("spositeusers")
        .iter()
        .filter(|u| flag(u, "Broad") == Some(true))
    {
        by.entry(text(u, "Site").to_string())
            .or_default()
            .insert(text(u, "DisplayName").to_string());
    }
    by
}

fn spo_005(t: &Tenant) -> CheckResult {
    let list: Vec<Affected> = broad_sites(t)
        .into_iter()
        .map(|(site, who)| {
            t.object(
                "site",
                site,
                None,
                format!(
                    "Granted to {}: everyone in the organization can open it",
                    who.into_iter().collect::<Vec<_>>().join(", ")
                ),
            )
        })
        .collect();
    out(t, "M365-SPO-005", SPO)
        .expected("No site grants access to Everyone or Everyone except external users")
        .found(plural(list.len(), "site grants", "sites grant") + " everyone access")
        .affected(list, "sites")
        .evidence("Note", "Up to 200 sites are read")
        .done()
}

fn spo_006(t: &Tenant) -> CheckResult {
    let on = spo_settings(t)
        .and_then(|s| s.b("isLegacyAuthProtocolsEnabled"))
        .unwrap_or(true);
    out(t, "M365-SPO-006", SPO)
        .expected("SharePoint does not accept legacy authentication")
        .found(if on {
            "Legacy authentication allowed"
        } else {
            "Blocked"
        })
        .affected(
            if on {
                vec![tenant_item(
                    t,
                    "Apps can sign in to SharePoint with legacy authentication, which skips MFA",
                )]
            } else {
                Vec::new()
            },
            "tenant",
        )
        .done()
}

fn spo_007(t: &Tenant) -> CheckResult {
    let o = out(t, "M365-SPO-007", SPO)
        .expected("Unmanaged devices get limited, web-only access or are blocked");
    let Some(s) = spo_tenant(t) else {
        return o.not_assessed("Get-SPOTenant was not read.").done();
    };
    let p = text(s, "ConditionalAccessPolicy");
    let full = p.is_empty() || eq(p, "AllowFullAccess");
    o.found(format!(
        "Unmanaged devices: {}",
        if p.is_empty() { "AllowFullAccess" } else { p }
    ))
    .affected(
        if full {
            vec![tenant_item(
                t,
                "Unmanaged devices can download and sync files",
            )]
        } else {
            Vec::new()
        },
        "tenant",
    )
    .done()
}

fn spo_008(t: &Tenant) -> CheckResult {
    let idle = spo_settings(t).and_then(|s| s.o("idleSessionSignOut"));
    let on = idle.and_then(|i| i.b("isEnabled")) == Some(true);
    out(t, "M365-SPO-008", SPO)
        .expected("Idle browser sessions on unmanaged devices are signed out")
        .found(if on {
            format!(
                "After {} minutes",
                idle.and_then(|i| i.n("signOutAfterInSeconds")).unwrap_or(0) / 60
            )
        } else {
            "Off".to_string()
        })
        .affected(
            if on {
                Vec::new()
            } else {
                vec![tenant_item(
                    t,
                    "Sessions on shared or public computers stay signed in",
                )]
            },
            "tenant",
        )
        .done()
}

fn spo_009(t: &Tenant) -> CheckResult {
    let on =
        spo_settings(t).and_then(|s| s.b("isUnmanagedSyncAppForTenantRestricted")) == Some(true);
    out(t, "M365-SPO-009", SPO)
        .expected("OneDrive sync is limited to computers joined to the organization's domains")
        .found(if on {
            "Restricted"
        } else {
            "Any computer can sync"
        })
        .affected(
            if on {
                Vec::new()
            } else {
                vec![tenant_item(t, "Personal computers can sync company files")]
            },
            "tenant",
        )
        .done()
}

fn spo_010(t: &Tenant) -> CheckResult {
    let o = out(t, "M365-SPO-010", SPO).expected(
        "The default sharing link is specific people or the organization, with view permission",
    );
    let Some(s) = spo_tenant(t) else {
        return o.not_assessed("Get-SPOTenant was not read.").done();
    };
    let mut missing = Vec::new();
    if eq(text(s, "DefaultLinkPermission"), "Edit") {
        missing.push("Links give edit permission by default".to_string());
    }
    if eq(text(s, "DefaultSharingLinkType"), "AnonymousAccess") {
        missing.push("The default link is an Anyone link".to_string());
    }
    o.found(format!(
        "{} link, {} permission",
        text(s, "DefaultSharingLinkType"),
        text(s, "DefaultLinkPermission")
    ))
    .affected(items(t, missing), "settings")
    .done()
}

/// The user principal name in a SharePoint claims login.
fn login_upn(login: &str) -> &str {
    login.rsplit('|').next().unwrap_or(login)
}

fn spo_011(t: &Tenant) -> CheckResult {
    let upns: BTreeSet<String> = t
        .users
        .values()
        .filter_map(|u| u.s("userPrincipalName"))
        .map(str::to_lowercase)
        .collect();
    let mut admins = 0;
    let mut list = Vec::new();
    for u in t
        .raw
        .list("spositeusers")
        .iter()
        .filter(|u| flag(u, "IsSiteAdmin") == Some(true))
    {
        admins += 1;
        let login = text(u, "LoginName");
        let upn = login_upn(login).to_lowercase();
        let reason = if upn.contains("#ext#") || eq(text(u, "UserType"), "Guest") {
            "External user is a site collection administrator"
        } else if flag(u, "IsGroup") != Some(true)
            && login.contains("membership")
            && !upns.contains(&upn)
        {
            "Site collection administrator no longer exists in Entra ID"
        } else {
            continue;
        };
        list.push(t.object(
            "account",
            text(u, "DisplayName"),
            Some(text(u, "Site").to_string()),
            reason,
        ));
    }
    out(t, "M365-SPO-011", SPO)
        .expected("Site collection administrators are current internal accounts")
        .found(format!(
            "{}; {} external or orphaned",
            plural(admins, "site admin entry", "site admin entries"),
            list.len()
        ))
        .affected(list, "admins")
        .done()
}

fn spo_012(t: &Tenant) -> CheckResult {
    let list: Vec<Affected> = t
        .raw
        .list("sposites")
        .iter()
        .filter(|s| {
            !text(s, "Template").starts_with("SPSPERS")
                && !text(s, "Template").starts_with("REDIRECT")
        })
        .filter(|s| {
            let group = text(s, "GroupId");
            if !group.is_empty() && group != "00000000-0000-0000-0000-000000000000" {
                t.groups
                    .get(group)
                    .is_some_and(|g| g.a("owners").is_empty())
            } else {
                text(s, "Owner").is_empty()
            }
        })
        .map(|s| site_item(t, s, "No owner: nobody reviews who has access"))
        .collect();
    out(t, "M365-SPO-012", SPO)
        .expected("Every site has an owner")
        .found(plural(list.len(), "site", "sites") + " without an owner")
        .affected(list, "sites")
        .done()
}

fn spo_013(t: &Tenant) -> CheckResult {
    let o =
        out(t, "M365-SPO-013", SPO).expected("Files detected as malicious cannot be downloaded");
    let Some(s) = spo_tenant(t) else {
        return o.not_assessed("Get-SPOTenant was not read.").done();
    };
    let on = flag(s, "DisallowInfectedFileDownload") == Some(true);
    o.found(if on { "Blocked" } else { "Allowed" })
        .affected(
            if on {
                Vec::new()
            } else {
                vec![tenant_item(
                    t,
                    "Users can download files Defender marked as malicious",
                )]
            },
            "tenant",
        )
        .done()
}

fn spo_014(t: &Tenant) -> CheckResult {
    let list: Vec<Affected> = t
        .raw
        .list("sposites")
        .iter()
        .filter(|s| eq(text(s, "DenyAddAndCustomizePages"), "Disabled"))
        .map(|s| {
            site_item(
                t,
                s,
                "Custom script is allowed: site owners can add script that runs for every visitor",
            )
        })
        .collect();
    out(t, "M365-SPO-014", SPO)
        .expected("Custom script is blocked on every site")
        .found(plural(list.len(), "site allows", "sites allow") + " custom script")
        .affected(list, "sites")
        .done()
}

fn spo_015(t: &Tenant) -> CheckResult {
    let on = spo_settings(t).and_then(|s| s.b("isSiteCreationEnabled")) == Some(true);
    out(t, "M365-SPO-015", SPO)
        .expected("Only admins or a request process create sites")
        .found(if on {
            "Users can create sites"
        } else {
            "Users cannot create sites"
        })
        .affected(
            if on {
                vec![tenant_item(
                    t,
                    "Any user can create SharePoint sites, which then go ungoverned",
                )]
            } else {
                Vec::new()
            },
            "tenant",
        )
        .done()
}

fn spo_016(t: &Tenant) -> CheckResult {
    let days = spo_settings(t)
        .and_then(|s| s.n("deletedUserPersonalSiteRetentionPeriodInDays"))
        .unwrap_or(30);
    out(t, "M365-SPO-016", SPO)
        .expected(format!(
            "A departed user's OneDrive is kept at least {ONEDRIVE_RETENTION_DAYS} days"
        ))
        .found(format!("{days} days"))
        .affected(
            if days < ONEDRIVE_RETENTION_DAYS {
                vec![tenant_item(
                    t,
                    format!("OneDrives are deleted {days} days after the user"),
                )]
            } else {
                Vec::new()
            },
            "tenant",
        )
        .done()
}

fn spo_017(t: &Tenant) -> CheckResult {
    let sites: Vec<&Value> = t
        .raw
        .list("sposites")
        .iter()
        .filter(|s| {
            !text(s, "Template").starts_with("SPSPERS")
                && !text(s, "Template").starts_with("REDIRECT")
        })
        .collect();
    let labelled = sites
        .iter()
        .filter(|s| {
            !text(s, "SensitivityLabel").is_empty()
                && text(s, "SensitivityLabel") != "00000000-0000-0000-0000-000000000000"
        })
        .count();
    let list = if labelled == 0 && !sites.is_empty() {
        vec![tenant_item(
            t,
            "No site has a sensitivity label: privacy and sharing are set site by site",
        )]
    } else {
        Vec::new()
    };
    out(t, "M365-SPO-017", SPO)
        .expected("Sensitivity labels are applied to sites")
        .found(format!(
            "{labelled} of {}",
            plural(sites.len(), "site", "sites")
        ))
        .affected(list, "tenant")
        .done()
}

fn spo_018(t: &Tenant) -> CheckResult {
    let mut score: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (site, who) in broad_sites(t) {
        score.entry(site).or_default().push(format!(
            "granted to {}",
            who.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }
    for s in t.raw.list("sposites") {
        if eq(text(s, "SharingCapability"), "ExternalUserAndGuestSharing") {
            score
                .entry(text(s, "Url").to_string())
                .or_default()
                .push("allows Anyone links".to_string());
        }
    }
    let mut rows: Vec<(String, Vec<String>)> = score.into_iter().collect();
    rows.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(a.0.cmp(&b.0)));
    let list: Vec<Affected> = rows
        .iter()
        .map(|(site, why)| t.object("site", site, None, why.join("; ")))
        .collect();
    out(t, "M365-SPO-018", SPO)
        .expected("No site is open to the whole organization or to anyone with a link")
        .found(plural(list.len(), "overshared site", "overshared sites"))
        .raw(
            rows.iter()
                .map(|(s, w)| format!("{s}: {}", w.join("; ")))
                .collect::<Vec<_>>()
                .join("\n"),
        )
        .affected(list, "sites")
        .done()
}

// ---------- Teams ----------

const TEAMS: &str = "Microsoft Teams";

fn global<'a>(t: &Tenant<'a>, area: &str) -> Option<&'a Value> {
    let all = t.raw.list(area);
    all.iter()
        .find(|p| eq(text(p, "Identity"), "Global"))
        .or(all.first())
}

fn tms_001(t: &Tenant) -> CheckResult {
    let f = t.raw.first("tmsfederation");
    let on = f.and_then(|f| flag(f, "AllowFederatedUsers")) == Some(true);
    let allowed = f
        .map(|f| list_of(f, "AllowedDomains").join(", "))
        .unwrap_or_default();
    let open = on && (allowed.is_empty() || allowed.contains("AllowAllKnownDomains"));
    out(t, "M365-TMS-001", TEAMS)
        .expected("Teams external access is limited to allowed domains")
        .found(if !on { "External access off".to_string() } else if open { "Open to all domains".to_string() } else { format!("Allowed: {allowed}") })
        .affected(if open { vec![tenant_item(t, "Users can chat and call with any external Teams organization, a common phishing route")] } else { Vec::new() }, "tenant")
        .done()
}

fn tms_002(t: &Tenant) -> CheckResult {
    let f = t.raw.first("tmsfederation");
    let mut missing = Vec::new();
    if f.and_then(|f| flag(f, "AllowTeamsConsumer")) == Some(true) {
        missing.push("Users can chat with personal (consumer) Teams accounts".to_string());
    }
    if f.and_then(|f| flag(f, "AllowTeamsConsumerInbound")) == Some(true) {
        missing.push("Personal Teams accounts can start chats with users".to_string());
    }
    out(t, "M365-TMS-002", TEAMS)
        .expected("Communication with unmanaged Teams accounts is off")
        .found(plural(missing.len(), "setting allows", "settings allow") + " consumer accounts")
        .affected(items(t, missing), "settings")
        .done()
}

fn tms_003(t: &Tenant) -> CheckResult {
    let guests = global(t, "tmsclient").and_then(|c| flag(c, "AllowGuestUser")) == Some(true);
    let mut missing = Vec::new();
    if guests {
        if let Some(m) = t.raw.first("tmsguestmessaging") {
            if flag(m, "AllowUserDeleteMessage") == Some(true) {
                missing.push("Guests can delete sent messages".to_string());
            }
        }
        if let Some(m) = t.raw.first("tmsguestmeeting") {
            if eq(text(m, "ScreenSharingMode"), "EntireScreen") {
                missing.push("Guests can share their entire screen".to_string());
            }
            if flag(m, "AllowMeetNow") == Some(true) {
                missing.push("Guests can start meetings (Meet now)".to_string());
            }
        }
    }
    out(t, "M365-TMS-003", TEAMS)
        .expected("Guest capabilities in Teams are limited")
        .found(if guests {
            format!(
                "Guest access on; {}",
                plural(missing.len(), "broad capability", "broad capabilities")
            )
        } else {
            "Guest access off".to_string()
        })
        .affected(items(t, missing), "settings")
        .done()
}

fn tms_004(t: &Tenant) -> CheckResult {
    let disabled = t
        .raw
        .first("tmsmeetingconfig")
        .and_then(|c| flag(c, "DisableAnonymousJoin"))
        == Some(true);
    let p = global(t, "tmsmeeting");
    let mut missing = Vec::new();
    if !disabled && p.and_then(|p| flag(p, "AllowAnonymousUsersToJoinMeeting")) != Some(false) {
        missing.push("Anonymous people can join meetings".to_string());
    }
    if p.and_then(|p| flag(p, "AllowAnonymousUsersToStartMeeting")) == Some(true) {
        missing.push("Anonymous people can start meetings".to_string());
    }
    out(t, "M365-TMS-004", TEAMS)
        .expected("Anonymous users cannot join or start meetings, or wait in the lobby")
        .found(plural(missing.len(), "finding", "findings"))
        .affected(items(t, missing), "settings")
        .done()
}

fn tms_005(t: &Tenant) -> CheckResult {
    let mut list = Vec::new();
    for p in t.raw.list("tmsmeeting") {
        let who = text(p, "AutoAdmittedUsers");
        if eq(who, "Everyone") || eq(who, "EveryoneInSameAndFederatedCompany") {
            list.push(t.object(
                "policy",
                text(p, "Identity"),
                None,
                format!("Lobby bypassed by {who}"),
            ));
        }
        if flag(p, "AllowPSTNUsersToBypassLobby") == Some(true) {
            list.push(t.object(
                "policy",
                text(p, "Identity"),
                None,
                "Dial-in callers bypass the lobby",
            ));
        }
    }
    out(t, "M365-TMS-005", TEAMS)
        .expected("Only people in the organization (and invited people) bypass the lobby")
        .found(plural(list.len(), "finding", "findings"))
        .affected(list, "policies")
        .done()
}

fn tms_006(t: &Tenant) -> CheckResult {
    let list: Vec<Affected> = t
        .raw
        .list("tmsappsetup")
        .iter()
        .filter(|p| flag(p, "AllowSideLoading") == Some(true))
        .map(|p| {
            t.object(
                "policy",
                text(p, "Identity"),
                None,
                "Users can upload custom apps",
            )
        })
        .collect();
    out(t, "M365-TMS-006", TEAMS)
        .expected("Only admins can upload custom apps")
        .found(plural(list.len(), "policy allows", "policies allow") + " custom app upload")
        .affected(list, "policies")
        .done()
}

fn tms_007(t: &Tenant) -> CheckResult {
    let mut missing = Vec::new();
    if let Some(p) = global(t, "tmsapppermission") {
        for (key, apps, what) in [
            (
                "GlobalCatalogAppsType",
                "GlobalCatalogApps",
                "third-party apps",
            ),
            (
                "PrivateCatalogAppsType",
                "PrivateCatalogApps",
                "custom apps",
            ),
        ] {
            if eq(text(p, key), "BlockedAppList") && list_of(p, apps).is_empty() {
                missing.push(format!("All {what} are allowed"));
            }
        }
    }
    out(t, "M365-TMS-007", TEAMS)
        .expected("Third-party and custom apps are allowed only from a reviewed list")
        .found(plural(missing.len(), "app category is", "app categories are") + " open")
        .affected(items(t, missing), "settings")
        .done()
}

fn teams<'a>(t: &Tenant<'a>) -> Vec<&'a Value> {
    t.groups
        .values()
        .copied()
        .filter(|g| g.strs("resourceProvisioningOptions").contains(&"Team"))
        .collect()
}

fn tms_008(t: &Tenant) -> CheckResult {
    let all = teams(t);
    let list: Vec<Affected> = all
        .iter()
        .filter(|g| g.a("owners").is_empty())
        .map(|g| {
            t.object(
                "team",
                g.s("displayName").unwrap_or_default(),
                None,
                "No owner: nobody manages its members, guests or channels",
            )
        })
        .collect();
    out(t, "M365-TMS-008", "Microsoft Graph")
        .expected("Every team has an owner")
        .found(format!(
            "{} of {} without an owner",
            list.len(),
            plural(all.len(), "team", "teams")
        ))
        .affected(list, "teams")
        .done()
}

const SENSITIVE: [&str; 9] = [
    "confidential",
    "secret",
    "restricted",
    "highly",
    "finance",
    "legal",
    "hr",
    "board",
    "payroll",
];

fn tms_009(t: &Tenant) -> CheckResult {
    let mut guests: BTreeMap<&str, i64> = BTreeMap::new();
    for p in t.raw.list("teamguests") {
        if let (Some(g), Some(n)) = (p.s("@dca.parent"), p.n("@odata.count")) {
            guests.insert(g, n);
        }
    }
    let list: Vec<Affected> = teams(t)
        .into_iter()
        .filter_map(|g| {
            let n = *guests.get(g.s("id")?)?;
            if n == 0 {
                return None;
            }
            let labels: Vec<&str> = g
                .a("assignedLabels")
                .iter()
                .filter_map(|l| l.s("displayName"))
                .collect();
            let name = g.s("displayName").unwrap_or_default().to_lowercase();
            let hit = labels
                .iter()
                .map(|l| l.to_lowercase())
                .chain(
                    name.split(|c: char| !c.is_alphanumeric())
                        .map(str::to_string),
                )
                .find(|w| SENSITIVE.iter().any(|s| w.contains(s)))?;
            Some(t.object(
                "team",
                g.s("displayName").unwrap_or_default(),
                None,
                format!(
                    "{} in a team marked sensitive ({hit})",
                    plural(n as usize, "guest", "guests")
                ),
            ))
        })
        .collect();
    out(t, "M365-TMS-009", "Microsoft Graph")
        .expected("Teams labelled or named as sensitive have no guests")
        .found(plural(list.len(), "sensitive team has", "sensitive teams have") + " guests")
        .affected(list, "teams")
        .done()
}

fn tms_010(t: &Tenant) -> CheckResult {
    let c = global(t, "tmsclient");
    let on = c.and_then(|c| flag(c, "AllowEmailIntoChannel")) == Some(true);
    let restricted = c.is_some_and(|c| !list_of(c, "RestrictedSenderList").is_empty());
    let open = on && !restricted;
    out(t, "M365-TMS-010", TEAMS)
        .expected("Email into channels is off or limited to allowed senders")
        .found(if !on {
            "Off"
        } else if restricted {
            "Limited to listed senders"
        } else {
            "Anyone can email channels"
        })
        .affected(
            if open {
                vec![tenant_item(
                    t,
                    "Anyone who learns a channel's address can post mail and files into it",
                )]
            } else {
                Vec::new()
            },
            "tenant",
        )
        .done()
}

fn tms_011(t: &Tenant) -> CheckResult {
    let c = global(t, "tmsclient");
    let missing: Vec<String> = [
        ("AllowDropBox", "Dropbox"),
        ("AllowBox", "Box"),
        ("AllowGoogleDrive", "Google Drive"),
        ("AllowShareFile", "Citrix ShareFile"),
        ("AllowEgnyte", "Egnyte"),
    ]
    .into_iter()
    .filter(|(k, _)| c.and_then(|c| flag(c, k)) == Some(true))
    .map(|(_, n)| format!("{n} can be added to Teams"))
    .collect();
    out(t, "M365-TMS-011", TEAMS)
        .expected("Third-party cloud storage is off in Teams")
        .found(plural(missing.len(), "provider", "providers") + " enabled")
        .affected(items(t, missing), "providers")
        .done()
}

fn tms_012(t: &Tenant) -> CheckResult {
    let p = global(t, "tmsmeeting");
    let recording = p.and_then(|p| flag(p, "AllowCloudRecording")) != Some(false);
    let days = p
        .and_then(|p| num(p, "NewMeetingRecordingExpirationDays"))
        .unwrap_or(-1);
    let never = recording && days < 0;
    out(t, "M365-TMS-012", TEAMS)
        .expected("Meeting recordings expire")
        .found(if !recording {
            "Recording off".to_string()
        } else if days < 0 {
            "Recordings never expire".to_string()
        } else {
            format!("Recordings expire after {days} days")
        })
        .affected(
            if never {
                vec![tenant_item(
                    t,
                    "Meeting recordings are kept forever in OneDrive and SharePoint",
                )]
            } else {
                Vec::new()
            },
            "tenant",
        )
        .done()
}

fn tms_013(t: &Tenant) -> CheckResult {
    let fed_open = t
        .raw
        .first("tmsfederation")
        .and_then(|f| flag(f, "AllowFederatedUsers"))
        == Some(true);
    let onedrive = spo_tenant(t)
        .map(|s| text(s, "OneDriveSharingCapability"))
        .unwrap_or_default();
    let open = fed_open && eq(onedrive, "ExternalUserAndGuestSharing");
    out(t, "M365-TMS-013", TEAMS)
        .expected("Files shared in external chats cannot become Anyone links")
        .found(format!("External chat {}; OneDrive sharing {}", if fed_open { "on" } else { "off" }, if onedrive.is_empty() { "unknown" } else { onedrive }))
        .affected(if open { vec![tenant_item(t, "Files shared in chats with external organizations can be shared through Anyone links from OneDrive")] } else { Vec::new() }, "tenant")
        .done()
}

fn tms_014(t: &Tenant) -> CheckResult {
    let mut rows = Vec::new();
    for (role, name) in [
        (TEAMS_ADMIN, "Teams Administrator"),
        (TEAMS_COMMS_ADMIN, "Teams Communications Administrator"),
        (TEAMS_DEVICES_ADMIN, "Teams Devices Administrator"),
    ] {
        let holders: BTreeSet<String> = t
            .holders_of(role)
            .map(|h| t.name_of(&h.principal))
            .collect();
        rows.push(format!(
            "{name}: {}",
            if holders.is_empty() {
                "none".to_string()
            } else {
                holders.into_iter().collect::<Vec<_>>().join(", ")
            }
        ));
    }
    out(t, "M365-TMS-014", "Microsoft Graph")
        .expected("An inventory of Teams administrators")
        .found(rows.join("; "))
        .raw(rows.join("\n"))
        .done()
}

// ---------- Purview ----------

const PURVIEW: &str = "Security & Compliance PowerShell";

fn role_groups<'a>(t: &Tenant<'a>, role: &str) -> Vec<&'a Value> {
    t.raw
        .list("purrolegroups")
        .iter()
        .filter(|g| list_of(g, "Roles").iter().any(|r| eq(r, role)))
        .collect()
}

fn members(g: &Value) -> Vec<String> {
    list_of(g, "Members")
}

fn pur_001(t: &Tenant) -> CheckResult {
    let on = t
        .raw
        .first("exoadminaudit")
        .and_then(|a| flag(a, "UnifiedAuditLogIngestionEnabled"))
        == Some(true);
    let premium = t.raw.list("skus").iter().any(|s| {
        s.a("servicePlans")
            .iter()
            .any(|p| p.s("servicePlanName") == Some("M365_ADVANCED_AUDITING"))
    });
    let longest = t
        .raw
        .list("purauditretention")
        .iter()
        .filter_map(|p| p.s("RetentionDuration"))
        .max_by_key(|d| d.len())
        .unwrap_or(if premium {
            "OneYear"
        } else {
            "180 days (Audit Standard)"
        });
    out(t, "M365-PUR-001", "Exchange Online and Purview")
        .expected("The unified audit log is on, with Audit Premium retention")
        .found(format!(
            "Audit log {}; {}; longest retention {longest}",
            if on { "on" } else { "off" },
            if premium {
                "Audit Premium"
            } else {
                "Audit Standard"
            }
        ))
        .affected(
            if on {
                Vec::new()
            } else {
                vec![tenant_item(
                    t,
                    "The unified audit log is off: user and admin activity is not recorded",
                )]
            },
            "tenant",
        )
        .done()
}

fn pur_002(t: &Tenant) -> CheckResult {
    let mut rows = Vec::new();
    let mut who = BTreeSet::new();
    for role in ["View-Only Audit Logs", "Audit Logs"] {
        for g in role_groups(t, role) {
            let m = members(g);
            who.extend(m.iter().cloned());
            rows.push(format!(
                "{} ({role}): {}",
                text(g, "Name"),
                if m.is_empty() {
                    "no members".into()
                } else {
                    m.join(", ")
                }
            ));
        }
    }
    rows.sort();
    rows.dedup();
    out(t, "M365-PUR-002", PURVIEW)
        .expected("Few, known people can search the audit log")
        .found(
            plural(who.len(), "person or group", "people or groups") + " can search the audit log",
        )
        .raw(rows.join("\n"))
        .done()
}

fn pur_003(t: &Tenant) -> CheckResult {
    let labels = t
        .raw
        .list("purlabels")
        .iter()
        .filter(|l| flag(l, "Disabled") != Some(true))
        .count();
    let policies: Vec<&Value> = t
        .raw
        .list("purlabelpolicies")
        .iter()
        .filter(|p| flag(p, "Enabled") != Some(false))
        .collect();
    let default = policies.iter().any(|p| {
        list_of(p, "Settings")
            .iter()
            .any(|s| s.to_lowercase().contains("defaultlabelid"))
    });
    let mut missing = Vec::new();
    if labels == 0 || policies.is_empty() {
        missing.push("No sensitivity labels are published".to_string());
    } else if !default {
        missing.push("No label policy sets a default label".to_string());
    }
    out(t, "M365-PUR-003", PURVIEW)
        .expected("Sensitivity labels are published with a default label")
        .found(format!(
            "{} in {}",
            plural(labels, "label", "labels"),
            plural(policies.len(), "policy", "policies")
        ))
        .affected(items(t, missing), "settings")
        .done()
}

fn pur_004(t: &Tenant) -> CheckResult {
    let all = t.raw.list("purautolabel");
    let on = all
        .iter()
        .filter(|p| eq(text(p, "Mode"), "Enable") && flag(p, "Enabled") != Some(false))
        .count();
    let list: Vec<Affected> = if all.is_empty() {
        vec![tenant_item(t, "No auto-labeling policy")]
    } else {
        all.iter()
            .filter(|p| !eq(text(p, "Mode"), "Enable"))
            .map(|p| {
                t.object(
                    "policy",
                    text(p, "Name"),
                    None,
                    format!("In {} mode: labels are not applied", text(p, "Mode")),
                )
            })
            .collect()
    };
    out(t, "M365-PUR-004", PURVIEW)
        .expected("Auto-labeling policies are on (not in simulation)")
        .found(format!(
            "{on} of {} enforced",
            plural(all.len(), "auto-labeling policy", "auto-labeling policies")
        ))
        .affected(list, "policies")
        .done()
}

fn pur_005(t: &Tenant) -> CheckResult {
    let workloads: String = t
        .raw
        .list("purdlp")
        .iter()
        .filter(|p| flag(p, "Enabled") != Some(false) && eq(text(p, "Mode"), "Enable"))
        .map(|p| list_of(p, "Workload").join(",").to_lowercase())
        .collect::<Vec<_>>()
        .join(",");
    let missing: Vec<String> = [
        ("exchange", "Exchange"),
        ("sharepoint", "SharePoint"),
        ("onedriveforbusiness", "OneDrive"),
        ("teams", "Teams"),
        ("endpointdevices", "endpoints"),
    ]
    .into_iter()
    .filter(|(k, _)| !workloads.contains(k))
    .map(|(_, n)| format!("No enforced DLP policy covers {n}"))
    .collect();
    out(t, "M365-PUR-005", PURVIEW)
        .expected("Enforced DLP policies cover Exchange, SharePoint, OneDrive, Teams and endpoints")
        .found(format!("{} of 5 workloads covered", 5 - missing.len()))
        .affected(items(t, missing), "workloads")
        .done()
}

fn pur_006(t: &Tenant) -> CheckResult {
    let list: Vec<Affected> = t
        .raw
        .list("purdlp")
        .iter()
        .filter(|p| text(p, "Mode").starts_with("Test"))
        .filter_map(|p| {
            let changed = time::parse_iso(text(p, "WhenChangedUTC"))
                .or(time::parse_iso(text(p, "WhenCreatedUTC")))?;
            let days = t.days_since(Some(changed))?;
            (days > DLP_TEST_DAYS).then(|| {
                t.object(
                    "policy",
                    text(p, "Name"),
                    None,
                    format!("In test mode for {days} days: nothing is blocked"),
                )
            })
        })
        .collect();
    out(t, "M365-PUR-006", PURVIEW)
        .expected(format!(
            "DLP policies leave test mode within {DLP_TEST_DAYS} days"
        ))
        .found(plural(list.len(), "policy", "policies") + " in test mode too long")
        .affected(list, "policies")
        .done()
}

fn pur_007(t: &Tenant) -> CheckResult {
    let enabled: Vec<&Value> = t
        .raw
        .list("purretention")
        .iter()
        .filter(|p| flag(p, "Enabled") != Some(false))
        .collect();
    let covers = |key: &str| enabled.iter().any(|p| !list_of(p, key).is_empty());
    let missing: Vec<String> = [
        ("ExchangeLocation", "Exchange mailboxes"),
        ("SharePointLocation", "SharePoint sites"),
        ("OneDriveLocation", "OneDrive accounts"),
        ("TeamsChannelLocation", "Teams channel messages"),
        ("TeamsChatLocation", "Teams chats"),
    ]
    .into_iter()
    .filter(|(k, _)| !covers(k))
    .map(|(_, n)| format!("No retention policy covers {n}"))
    .collect();
    out(t, "M365-PUR-007", PURVIEW)
        .expected("Retention policies cover mail, sites, OneDrive and Teams")
        .found(format!(
            "{}; {} workloads uncovered",
            plural(enabled.len(), "retention policy", "retention policies"),
            missing.len()
        ))
        .affected(items(t, missing), "workloads")
        .done()
}

fn pur_008(t: &Tenant) -> CheckResult {
    let mut list: Vec<Affected> = t
        .raw
        .list("purcaseadmins")
        .iter()
        .map(|a| {
            t.object(
                "account",
                text(a, "Name"),
                a.s("PrimarySmtpAddress").map(str::to_string),
                "eDiscovery Administrator: can open every case and its content",
            )
        })
        .collect();
    let managers: Vec<String> = t
        .raw
        .list("purrolegroups")
        .iter()
        .filter(|g| eq(text(g, "Name"), "eDiscoveryManager"))
        .flat_map(members)
        .collect();
    if managers.len() > 5 {
        list.push(tenant_item(
            t,
            format!(
                "{} eDiscovery Managers: each can search all mailboxes and sites",
                managers.len()
            ),
        ));
    }
    out(t, "M365-PUR-008", PURVIEW)
        .expected("eDiscovery administrators and managers are few and known")
        .found(format!(
            "{} administrators, {} managers",
            t.raw.list("purcaseadmins").len(),
            managers.len()
        ))
        .raw(managers.join("\n"))
        .affected(list, "accounts")
        .done()
}

fn info(t: &Tenant, id: &str, area: &str, expected: &str, noun: (&str, &str)) -> CheckResult {
    let all = t.raw.list(area);
    let on = all
        .iter()
        .filter(|p| flag(p, "Enabled") != Some(false) && !eq(text(p, "State"), "Inactive"))
        .count();
    out(t, id, PURVIEW)
        .expected(expected)
        .found(format!(
            "{on} of {} active",
            plural(all.len(), noun.0, noun.1)
        ))
        .raw(
            all.iter()
                .map(|p| text(p, "Name").to_string())
                .collect::<Vec<_>>()
                .join("\n"),
        )
        .done()
}

fn pur_009(t: &Tenant) -> CheckResult {
    info(
        t,
        "M365-PUR-009",
        "purinsider",
        "Insider risk management is configured",
        ("insider risk policy", "insider risk policies"),
    )
}

fn pur_010(t: &Tenant) -> CheckResult {
    info(
        t,
        "M365-PUR-010",
        "purcommunication",
        "Communication compliance is configured",
        (
            "communication compliance policy",
            "communication compliance policies",
        ),
    )
}

fn pur_011(t: &Tenant) -> CheckResult {
    let plans: BTreeSet<&str> = t
        .raw
        .list("skus")
        .iter()
        .flat_map(|s| s.a("servicePlans"))
        .filter_map(|p| p.s("servicePlanName"))
        .filter(|n| {
            n.contains("CUSTOMER_KEY")
                || n.contains("DOUBLE_KEY")
                || n.contains("INFORMATION_PROTECTION_PREMIUM")
                || n == &"RMS_S_PREMIUM2"
        })
        .collect();
    check("M365-PUR-011")
        .expected(
            "Customer Key or Double Key Encryption, where the data's sensitivity calls for it",
        )
        .found(if plans.is_empty() {
            "Not licensed".to_string()
        } else {
            format!(
                "Licensed: {}",
                plans.into_iter().collect::<Vec<_>>().join(", ")
            )
        })
        .evidence("Read from", read_from(t))
        .done()
}

fn pur_012(t: &Tenant) -> CheckResult {
    let list: Vec<Affected> = t
        .raw
        .list("puralerts")
        .iter()
        .filter(|a| {
            flag(a, "IsSystemRule") == Some(true)
                && flag(a, "Disabled") == Some(true)
                && eq(text(a, "Severity"), "High")
        })
        .map(|a| {
            t.object(
                "alert",
                text(a, "Name"),
                None,
                "Default high-severity alert policy is turned off",
            )
        })
        .collect();
    out(t, "M365-PUR-012", PURVIEW)
        .expected("Default high-severity alert policies are on")
        .found(plural(list.len(), "default alert", "default alerts") + " turned off")
        .affected(list, "alerts")
        .done()
}

fn pur_013(t: &Tenant) -> CheckResult {
    info(
        t,
        "M365-PUR-013",
        "purbarriers",
        "Information barriers are configured where regulation requires them",
        ("information barrier policy", "information barrier policies"),
    )
}

fn pur_014(t: &Tenant) -> CheckResult {
    let filters = t.raw.list("pursecurityfilters").len();
    let list: Vec<Affected> = role_groups(t, "Compliance Search")
        .into_iter()
        .filter(|g| !members(g).is_empty())
        .map(|g| {
            t.object(
                "role group",
                text(g, "Name"),
                None,
                format!(
                    "{} can search all content{}",
                    plural(members(g).len(), "member", "members"),
                    if filters == 0 {
                        ", with no search permissions filter"
                    } else {
                        ""
                    }
                ),
            )
        })
        .collect();
    let broad = if filters == 0 { list } else { Vec::new() };
    out(t, "M365-PUR-014", PURVIEW)
        .expected("Content search is limited by permission filters, or held by few people")
        .found(format!(
            "{}; {} permission filters",
            plural(
                role_groups(t, "Compliance Search").len(),
                "role group can",
                "role groups can"
            ) + " search content",
            filters
        ))
        .affected(broad, "role groups")
        .done()
}

pub static RULES: &[Rule] = &[
    Rule {
        id: "M365-SPO-001",
        needs: &["sposettings"],
        run: spo_001,
    },
    Rule {
        id: "M365-SPO-002",
        needs: &["spotenant"],
        run: spo_002,
    },
    Rule {
        id: "M365-SPO-003",
        needs: &["spotenant"],
        run: spo_003,
    },
    Rule {
        id: "M365-SPO-004",
        needs: &["sposettings"],
        run: spo_004,
    },
    Rule {
        id: "M365-SPO-005",
        needs: &["spositeusers"],
        run: spo_005,
    },
    Rule {
        id: "M365-SPO-006",
        needs: &["sposettings"],
        run: spo_006,
    },
    Rule {
        id: "M365-SPO-007",
        needs: &["spotenant"],
        run: spo_007,
    },
    Rule {
        id: "M365-SPO-008",
        needs: &["sposettings"],
        run: spo_008,
    },
    Rule {
        id: "M365-SPO-009",
        needs: &["sposettings"],
        run: spo_009,
    },
    Rule {
        id: "M365-SPO-010",
        needs: &["spotenant"],
        run: spo_010,
    },
    Rule {
        id: "M365-SPO-011",
        needs: &["spositeusers", "users"],
        run: spo_011,
    },
    Rule {
        id: "M365-SPO-012",
        needs: &["sposites", "groups"],
        run: spo_012,
    },
    Rule {
        id: "M365-SPO-013",
        needs: &["spotenant"],
        run: spo_013,
    },
    Rule {
        id: "M365-SPO-014",
        needs: &["sposites"],
        run: spo_014,
    },
    Rule {
        id: "M365-SPO-015",
        needs: &["sposettings"],
        run: spo_015,
    },
    Rule {
        id: "M365-SPO-016",
        needs: &["sposettings"],
        run: spo_016,
    },
    Rule {
        id: "M365-SPO-017",
        needs: &["sposites"],
        run: spo_017,
    },
    Rule {
        id: "M365-SPO-018",
        needs: &["sposites", "spositeusers"],
        run: spo_018,
    },
    Rule {
        id: "M365-TMS-001",
        needs: &["tmsfederation"],
        run: tms_001,
    },
    Rule {
        id: "M365-TMS-002",
        needs: &["tmsfederation"],
        run: tms_002,
    },
    Rule {
        id: "M365-TMS-003",
        needs: &["tmsclient", "tmsguestmessaging", "tmsguestmeeting"],
        run: tms_003,
    },
    Rule {
        id: "M365-TMS-004",
        needs: &["tmsmeetingconfig", "tmsmeeting"],
        run: tms_004,
    },
    Rule {
        id: "M365-TMS-005",
        needs: &["tmsmeeting"],
        run: tms_005,
    },
    Rule {
        id: "M365-TMS-006",
        needs: &["tmsappsetup"],
        run: tms_006,
    },
    Rule {
        id: "M365-TMS-007",
        needs: &["tmsapppermission"],
        run: tms_007,
    },
    Rule {
        id: "M365-TMS-008",
        needs: &["groups", "groupowners"],
        run: tms_008,
    },
    Rule {
        id: "M365-TMS-009",
        needs: &["groups", "teamguests"],
        run: tms_009,
    },
    Rule {
        id: "M365-TMS-010",
        needs: &["tmsclient"],
        run: tms_010,
    },
    Rule {
        id: "M365-TMS-011",
        needs: &["tmsclient"],
        run: tms_011,
    },
    Rule {
        id: "M365-TMS-012",
        needs: &["tmsmeeting"],
        run: tms_012,
    },
    Rule {
        id: "M365-TMS-013",
        needs: &["tmsfederation", "spotenant"],
        run: tms_013,
    },
    Rule {
        id: "M365-TMS-014",
        needs: &["roleassignments"],
        run: tms_014,
    },
    Rule {
        id: "M365-PUR-001",
        needs: &["exoadminaudit", "skus"],
        run: pur_001,
    },
    Rule {
        id: "M365-PUR-002",
        needs: &["purrolegroups"],
        run: pur_002,
    },
    Rule {
        id: "M365-PUR-003",
        needs: &["purlabels", "purlabelpolicies"],
        run: pur_003,
    },
    Rule {
        id: "M365-PUR-004",
        needs: &["purautolabel"],
        run: pur_004,
    },
    Rule {
        id: "M365-PUR-005",
        needs: &["purdlp"],
        run: pur_005,
    },
    Rule {
        id: "M365-PUR-006",
        needs: &["purdlp"],
        run: pur_006,
    },
    Rule {
        id: "M365-PUR-007",
        needs: &["purretention"],
        run: pur_007,
    },
    Rule {
        id: "M365-PUR-008",
        needs: &["purcaseadmins", "purrolegroups"],
        run: pur_008,
    },
    Rule {
        id: "M365-PUR-009",
        needs: &["purinsider"],
        run: pur_009,
    },
    Rule {
        id: "M365-PUR-010",
        needs: &["purcommunication"],
        run: pur_010,
    },
    Rule {
        id: "M365-PUR-011",
        needs: &["skus"],
        run: pur_011,
    },
    Rule {
        id: "M365-PUR-012",
        needs: &["puralerts"],
        run: pur_012,
    },
    Rule {
        id: "M365-PUR-013",
        needs: &["purbarriers"],
        run: pur_013,
    },
    Rule {
        id: "M365-PUR-014",
        needs: &["purrolegroups", "pursecurityfilters"],
        run: pur_014,
    },
];
