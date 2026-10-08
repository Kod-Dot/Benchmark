//! More Exchange Online checks: inbox rules that forward, delete or hide
//! mail, mailbox permissions, quarantine release, open security groups, and
//! hunts in the unified audit log.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use super::model::{Tenant, J};
use super::rules::read_from;
use super::Rule;
use crate::ad::rules::{check, plural, Out};
use crate::results::{Affected, CheckResult};
use crate::time;

/// Mailboxes one account may open before it counts as broad access.
const MANY_MAILBOXES: usize = 10;
/// File downloads by one user in one day that look like mass download.
const MASS_DOWNLOAD: i64 = 500;
/// Anonymous links created by one user in one day.
const MASS_SHARING: i64 = 20;
/// Hours after a risk detection in which a new inbox rule is suspicious.
const RULE_AFTER_RISK_HOURS: i64 = 24;

fn out(t: &Tenant, id: &str) -> Out {
    check(id).evidence("Read from", format!("{}; Exchange Online", read_from(t)))
}

fn list(v: &Value, key: &str) -> Vec<String> {
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

fn truthy(v: &Value, key: &str) -> bool {
    match v.get(key) {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => s.eq_ignore_ascii_case("true"),
        _ => false,
    }
}

fn text<'a>(v: &'a Value, key: &str) -> &'a str {
    v.s(key).unwrap_or_default()
}

fn accepted(t: &Tenant) -> BTreeSet<String> {
    let mut d: BTreeSet<String> = t
        .raw
        .list("exoaccepteddomains")
        .iter()
        .filter_map(|x| x.s("DomainName"))
        .map(str::to_lowercase)
        .collect();
    d.extend(
        t.raw
            .list("domains")
            .iter()
            .filter_map(|x| x.s("id"))
            .map(str::to_lowercase),
    );
    d
}

/// The SMTP address in a recipient as Exchange prints it: "Name" [SMTP:a@b].
fn smtp(r: &str) -> String {
    let l = r.to_lowercase();
    match l.find("smtp:") {
        Some(i) => l[i + 5..].trim_end_matches(']').trim().to_string(),
        None => l.trim().to_string(),
    }
}

const HIDING_FOLDERS: [&str; 6] = [
    "rss",
    "conversation history",
    "archive",
    "deleted items",
    "junk",
    "notes",
];

fn exo_006(t: &Tenant) -> CheckResult {
    let ours = accepted(t);
    let external = |a: &str| a.contains('@') && !ours.iter().any(|d| a.ends_with(&format!("@{d}")));
    let mut found = Vec::new();
    for r in t
        .raw
        .list("exoinboxrules")
        .iter()
        .filter(|r| truthy(r, "Enabled"))
    {
        let mut why = Vec::new();
        let targets: Vec<String> = ["ForwardTo", "ForwardAsAttachmentTo", "RedirectTo"]
            .iter()
            .flat_map(|k| list(r, k))
            .map(|x| smtp(&x))
            .filter(|a| external(a))
            .collect();
        if !targets.is_empty() {
            why.push(format!("forwards to {}", targets.join(", ")));
        }
        if truthy(r, "DeleteMessage") || truthy(r, "SoftDeleteMessage") {
            why.push("deletes messages".to_string());
        }
        let folder = text(r, "MoveToFolder").to_lowercase();
        if HIDING_FOLDERS.iter().any(|f| folder.contains(f))
            && (truthy(r, "MarkAsRead")
                || folder.contains("rss")
                || folder.contains("conversation"))
        {
            why.push(format!(
                "moves mail to {} out of sight",
                text(r, "MoveToFolder")
            ));
        }
        let name = text(r, "Name").trim();
        if !why.is_empty() && name.chars().all(|c| !c.is_alphanumeric()) {
            why.push("has a name made of symbols only".to_string());
        }
        if !why.is_empty() {
            found.push(t.object(
                "rule",
                if name.is_empty() { "(no name)" } else { name },
                Some(text(r, "MailboxOwnerId").to_string()),
                format!("Inbox rule {}", why.join("; ")),
            ));
        }
    }
    out(t, "M365-EXO-006")
        .expected("No inbox rule forwards mail outside, deletes it, or hides it")
        .found(plural(
            found.len(),
            "suspicious inbox rule",
            "suspicious inbox rules",
        ))
        .affected(found, "rules")
        .evidence("Note", "Up to 500 user and shared mailboxes are read")
        .done()
}

/// Privileged Entra users by user principal name and mail.
fn admin_mailboxes(t: &Tenant) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (p, roles) in t.privileged_principals() {
        if let Some(u) = t.users.get(p.as_str()) {
            for k in ["userPrincipalName", "mail"] {
                if let Some(v) = u.s(k) {
                    out.insert(v.to_lowercase(), t.roles_text(&roles));
                }
            }
            out.insert(p.to_lowercase(), t.roles_text(&roles));
        }
    }
    out
}

fn exo_009(t: &Tenant) -> CheckResult {
    let admins = admin_mailboxes(t);
    let full: Vec<&Value> = t
        .raw
        .list("exofullaccess")
        .iter()
        .filter(|p| {
            list(p, "AccessRights")
                .iter()
                .any(|r| r.contains("FullAccess"))
        })
        .collect();
    let mut per_trustee: BTreeMap<String, usize> = BTreeMap::new();
    for p in &full {
        *per_trustee
            .entry(text(p, "User").to_lowercase())
            .or_default() += 1;
    }
    let mut found = Vec::new();
    let mut flag = |kind: &str, who: &str, target: &str, extra: Option<String>| {
        let w = who.to_lowercase();
        let mut why = Vec::new();
        if w.contains("#ext#") {
            why.push("an external guest".to_string());
        }
        if let Some(roles) = admins.get(&target.to_lowercase()) {
            why.push(format!("on the mailbox of an admin ({roles})"));
        }
        if let Some(e) = extra {
            why.push(e);
        }
        if !why.is_empty() {
            found.push(t.object(
                "permission",
                format!("{who} → {target}"),
                Some(kind.to_string()),
                format!("{kind}: {}", why.join("; ")),
            ));
        }
    };
    for p in &full {
        let who = text(p, "User");
        let n = per_trustee.get(&who.to_lowercase()).copied().unwrap_or(0);
        flag(
            "Full Access",
            who,
            text(p, "Identity"),
            (n >= MANY_MAILBOXES).then(|| format!("one of {n} mailboxes it can open")),
        );
    }
    for p in t.raw.list("exosendas") {
        flag("Send As", text(p, "Trustee"), text(p, "Identity"), None);
    }
    for m in t.raw.list("exomailboxes") {
        for who in list(m, "GrantSendOnBehalfTo") {
            flag("Send on Behalf", &who, text(m, "UserPrincipalName"), None);
        }
    }
    out(t, "M365-EXO-009")
        .expected("Mailbox delegation goes only to internal accounts, not to admins' mailboxes, and no account can open many mailboxes")
        .found(plural(found.len(), "unexpected grant", "unexpected grants"))
        .affected(found, "permissions")
        .evidence("Note", "Full Access is read for up to 500 user and shared mailboxes")
        .done()
}

/// Built-in policies that let users release quarantined mail themselves.
const RELEASING: [&str; 2] = [
    "DefaultFullAccessPolicy",
    "DefaultFullAccessWithNotificationPolicy",
];

fn exo_027(t: &Tenant) -> CheckResult {
    let mut can_release: BTreeSet<String> = RELEASING.iter().map(|s| s.to_lowercase()).collect();
    for q in t.raw.list("exoquarantine") {
        if text(q, "EndUserQuarantinePermissions")
            .to_lowercase()
            .contains("permissiontorelease: true")
        {
            can_release.insert(text(q, "Name").to_lowercase());
        }
    }
    let mut found = Vec::new();
    let mut tags: Vec<(&str, &str, String)> = Vec::new();
    for p in t.raw.list("exocontentfilter") {
        tags.push((
            text(p, "Name"),
            "high-confidence phishing",
            text(p, "HighConfidencePhishQuarantineTag").to_string(),
        ));
    }
    for p in t.raw.list("exomalware") {
        tags.push((
            text(p, "Name"),
            "malware",
            text(p, "QuarantineTag").to_string(),
        ));
    }
    for (policy, what, tag) in tags {
        if !tag.is_empty() && can_release.contains(&tag.to_lowercase()) {
            found.push(t.object(
                "policy",
                policy,
                Some(tag.clone()),
                format!("Users can release {what} from quarantine themselves ({tag})"),
            ));
        }
    }
    out(t, "M365-EXO-027")
        .expected("Users cannot release malware or high-confidence phishing from quarantine")
        .found(plural(found.len(), "policy lets", "policies let") + " users release dangerous mail")
        .affected(found, "policies")
        .done()
}

fn grp_008(t: &Tenant) -> CheckResult {
    let found: Vec<Affected> = t
        .raw
        .list("exodistgroups")
        .iter()
        .filter(|g| {
            text(g, "MemberJoinRestriction").eq_ignore_ascii_case("Open")
                && text(g, "GroupType").contains("SecurityEnabled")
        })
        .map(|g| {
            t.object(
                "group",
                text(g, "Name"),
                g.s("PrimarySmtpAddress").map(str::to_string),
                "Mail-enabled security group anyone can join: joining grants its permissions",
            )
        })
        .collect();
    out(t, "EN-GRP-008")
        .expected("No security group lets members add themselves")
        .found(plural(
            found.len(),
            "open security group",
            "open security groups",
        ))
        .affected(found, "groups")
        .done()
}

fn hunt_010(t: &Tenant) -> CheckResult {
    // Risk detections per user, as times.
    let mut risk: BTreeMap<String, Vec<i64>> = BTreeMap::new();
    for d in t.raw.list("riskdetections") {
        if let (Some(u), Some(at)) = (
            d.s("userPrincipalName"),
            d.s("detectedDateTime").and_then(time::parse_iso),
        ) {
            risk.entry(u.to_lowercase()).or_default().push(at);
        }
    }
    let mut found = Vec::new();
    for r in t.raw.list("exoualinbox") {
        let user = text(r, "UserIds").to_lowercase();
        let Some(at) = time::parse_iso(text(r, "CreationDate"))
            .or_else(|| parse_exo_date(text(r, "CreationDate")))
        else {
            continue;
        };
        let Some(after) = risk.get(&user).and_then(|v| {
            v.iter()
                .filter(|&&x| x <= at && at - x <= RULE_AFTER_RISK_HOURS * 3600)
                .max()
                .copied()
        }) else {
            continue;
        };
        found.push(
            t.object(
                "user",
                text(r, "UserIds"),
                None,
                format!(
                    "{} {} hours after a risk detection",
                    text(r, "Operations"),
                    (at - after) / 3600
                ),
            )
            .seen_at(Some(&time::iso(at))),
        );
    }
    out(t, "HUNT-EN-010")
        .expected(format!("No inbox rule is created or changed within {RULE_AFTER_RISK_HOURS} hours of a risky sign-in"))
        .found(plural(found.len(), "inbox rule change follows", "inbox rule changes follow") + " a risk detection")
        .affected(found, "changes")
        .done()
}

/// Exchange writes dates as "10/03/2026 14:05:00" in some cultures.
fn parse_exo_date(s: &str) -> Option<i64> {
    let (d, rest) = s.split_once(' ')?;
    let p: Vec<&str> = d.split('/').collect();
    if p.len() != 3 {
        return None;
    }
    time::parse_iso(&format!(
        "{}-{:0>2}-{:0>2}T{}Z",
        p[2],
        p[0],
        p[1],
        rest.trim()
    ))
}

fn hunt_011(t: &Tenant) -> CheckResult {
    let mut found = Vec::new();
    for r in t.raw.list("exoualfiles") {
        let n = r.get("Count").and_then(Value::as_i64).unwrap_or(0);
        let op = text(r, "Operation");
        let (limit, what) = if op == "AnonymousLinkCreated" {
            (MASS_SHARING, "anonymous links created")
        } else {
            (MASS_DOWNLOAD, "files downloaded")
        };
        if n >= limit {
            found.push(t.object(
                "user",
                text(r, "UserIds"),
                Some(text(r, "Day").to_string()),
                format!("{n} {what} on {}", text(r, "Day")),
            ));
        }
    }
    out(t, "HUNT-EN-011")
        .expected(format!("No user downloads {MASS_DOWNLOAD} or more files, or creates {MASS_SHARING} or more anonymous links, in one day"))
        .found(plural(found.len(), "day of mass activity", "days of mass activity"))
        .affected(found, "user days")
        .done()
}

pub static RULES: &[Rule] = &[
    Rule {
        id: "M365-EXO-006",
        needs: &["exoinboxrules", "exoaccepteddomains"],
        run: exo_006,
    },
    Rule {
        id: "M365-EXO-009",
        needs: &["exofullaccess", "exosendas", "exomailboxes"],
        run: exo_009,
    },
    Rule {
        id: "M365-EXO-027",
        needs: &["exoquarantine", "exocontentfilter", "exomalware"],
        run: exo_027,
    },
    Rule {
        id: "EN-GRP-008",
        needs: &["exodistgroups"],
        run: grp_008,
    },
    Rule {
        id: "HUNT-EN-010",
        needs: &["exoualinbox", "riskdetections"],
        run: hunt_010,
    },
    Rule {
        id: "HUNT-EN-011",
        needs: &["exoualfiles"],
        run: hunt_011,
    },
];
