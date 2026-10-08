//! Threat hunting in the domain controllers' event logs (`dcevents`, the
//! `hunt_*` queries). Each query returns the distinct sources of matching
//! events as '|'-joined keys; these rules merge them across DCs and decide
//! what is worth a look. A hunt that finds nothing only means nothing was
//! logged: each rule says which audit setting its events need.

use std::collections::{BTreeMap, BTreeSet};

use super::dc::EventSummary;
use super::model::{rdn_value, Kind, Model};
use super::rules::{check, plural, Out, Rule};
use crate::results::{Affected, CheckResult};

/// Distinct services one account must request RC4 tickets for.
const ROAST_SERVICES: usize = 5;
/// Distinct accounts one source must fail to sign in as.
const SPRAY_ACCOUNTS: usize = 10;
/// Failed sign-ins for one account from one source.
const BRUTE_FAILURES: u64 = 25;
/// Lockouts across the domain that make a storm.
const LOCKOUT_STORM: u64 = 10;

/// One distinct source of events on one DC.
struct Row<'a> {
    f: Vec<&'a str>,
    count: u64,
    last: Option<&'a str>,
    dc: &'a str,
}

impl Row<'_> {
    fn get(&self, i: usize) -> &str {
        self.f.get(i).copied().unwrap_or_default()
    }
}

#[derive(Default)]
struct Hunt<'a> {
    rows: Vec<Row<'a>>,
    assessed: Vec<&'a str>,
    skipped: Vec<String>,
    total: u64,
    capped: Vec<&'a str>,
    days: i64,
}

fn short(name: &str) -> &str {
    name.split('.').next().unwrap_or(name)
}

fn hunt<'a>(m: &'a Model, query: &str) -> Hunt<'a> {
    let mut h = Hunt::default();
    for dc in &m.raw.dcevents {
        let q: &EventSummary = match (&dc.error, dc.queries.get(query)) {
            (Some(e), _) => {
                h.skipped.push(format!("{} ({e})", dc.name));
                continue;
            }
            (None, None) => {
                h.skipped.push(format!("{} (not queried)", dc.name));
                continue;
            }
            (None, Some(q)) => q,
        };
        if let Some(e) = &q.error {
            h.skipped.push(format!("{} ({e})", dc.name));
            continue;
        }
        h.assessed.push(&dc.name);
        h.total += q.count;
        h.days = h.days.max(dc.days);
        if q.capped {
            h.capped.push(&dc.name);
        }
        for s in &q.top {
            h.rows.push(Row {
                f: s.key.split('|').collect(),
                count: s.count,
                last: s.last.as_deref(),
                dc: short(&dc.name),
            });
        }
    }
    h
}

/// "dc01, dc02; last 2026-10-04"
fn seen(dcs: &BTreeSet<&str>, last: Option<&str>) -> String {
    let on = dcs.iter().copied().collect::<Vec<_>>().join(", ");
    match last.and_then(|l| l.get(..10)) {
        Some(d) => format!("on {on}; last {d}"),
        None => format!("on {on}"),
    }
}

/// The later of two optional ISO times.
fn later<'a>(a: Option<&'a str>, b: Option<&'a str>) -> Option<&'a str> {
    match (a, b) {
        (Some(x), Some(y)) => Some(if y > x { y } else { x }),
        (x, y) => x.or(y),
    }
}

/// Events from one source merged across rows and DCs.
#[derive(Default)]
struct Agg<'a> {
    n: u64,
    dcs: BTreeSet<&'a str>,
    last: Option<&'a str>,
    /// Distinct values of the rule's choosing: services, accounts, sources.
    a: BTreeSet<String>,
    b: BTreeSet<String>,
}

impl<'a> Agg<'a> {
    fn add(&mut self, r: &Row<'a>) -> &mut Self {
        self.n += r.count;
        self.dcs.insert(r.dc);
        self.last = later(self.last, r.last);
        self
    }
    fn seen(&self) -> String {
        seen(&self.dcs, self.last)
    }
}

/// A source value worth listing: not empty and not the "-" placeholder.
fn value(v: &str) -> Option<String> {
    (!v.is_empty() && v != "-").then(|| v.to_string())
}

fn joined(set: &BTreeSet<String>) -> String {
    set.iter().cloned().collect::<Vec<_>>().join(", ")
}

fn read_from(m: &Model) -> String {
    format!(
        "Event logs of each DC over remote event log access, collected from {} as {}",
        m.raw.info.computer, m.raw.info.account
    )
}

/// Not assessed when no DC answered the query; otherwise the result with
/// the coverage evidence every hunt carries.
fn finish(
    m: &Model,
    out: Out,
    hunts: &[&Hunt],
    audit: &str,
    list: Vec<Affected>,
    unit: &str,
) -> CheckResult {
    if let Some(h) = hunts.iter().find(|h| h.assessed.is_empty()) {
        let why = if h.skipped.is_empty() {
            "No domain controller's logs were read.".to_string()
        } else {
            format!(
                "No domain controller's logs could be assessed: {}.",
                h.skipped.join("; ")
            )
        };
        return out.not_assessed(why).done();
    }
    let h = hunts[0];
    let mut out = out
        .affected(list, unit)
        .evidence(
            "Searched",
            format!(
                "{} over the last {}",
                h.assessed
                    .iter()
                    .map(|d| short(d))
                    .collect::<Vec<_>>()
                    .join(", "),
                plural(h.days as usize, "day", "days")
            ),
        )
        .evidence("Needs", audit);
    let skipped: BTreeSet<&String> = hunts.iter().flat_map(|h| &h.skipped).collect();
    if !skipped.is_empty() {
        out = out.evidence(
            "Not assessed on",
            skipped.into_iter().cloned().collect::<Vec<_>>().join("; "),
        );
    }
    let capped: BTreeSet<&str> = hunts
        .iter()
        .flat_map(|h| h.capped.iter().map(|d| short(d)))
        .collect();
    if !capped.is_empty() {
        out = out.evidence(
            "Event limit",
            format!(
                "The newest 5,000 matching events were read on {}; older ones were not",
                capped.into_iter().collect::<Vec<_>>().join(", ")
            ),
        );
    }
    out.evidence("Read from", read_from(m)).done()
}

fn affected(
    name: impl Into<String>,
    kind: &str,
    location: Option<String>,
    reason: String,
    object: Option<String>,
) -> Affected {
    Affected {
        last_seen: None,
        name: name.into(),
        kind: kind.into(),
        location,
        reason: Some(reason),
        object,
    }
}

/// The model's node for a SID, if it is in this domain.
fn node<'m>(m: &'m Model, sid: &str) -> Option<&'m super::model::Node> {
    m.by_sid(sid).map(|i| &m.nodes[i])
}

fn node_id(m: &Model, sid: &str) -> Option<String> {
    node(m, sid).map(|n| n.id.clone())
}

/// Admins, Tier 0 accounts, SYSTEM and the DCs: expected to make changes.
fn trusted(m: &Model, sid: &str) -> bool {
    m.is_default_admin(sid) || node(m, sid).is_some_and(|n| n.tier0 || n.is_dc())
}

/// The Entra Connect connector account, which replicates and writes key
/// credentials by design.
fn sync_account(name: &str) -> bool {
    let account = name
        .rsplit('\\')
        .next()
        .unwrap_or(name)
        .to_ascii_uppercase();
    account.starts_with("MSOL_") || account.starts_with("AAD_") || account.starts_with("SYNC_")
}

// ---------- Credential theft ----------

fn hunt_001(m: &Model) -> CheckResult {
    let h = hunt(m, "hunt_dcsync");
    let mut by: BTreeMap<(&str, &str), Agg> = BTreeMap::new();
    let mut expected = BTreeSet::new();
    for r in &h.rows {
        let (who, sid) = (r.get(0), r.get(1));
        if sid == "S-1-5-18" || node(m, sid).is_some_and(|n| n.is_dc()) {
            continue;
        }
        if sync_account(who) {
            expected.insert(who.to_string());
            continue;
        }
        by.entry((who, sid)).or_default().add(r);
    }
    let list: Vec<Affected> = by
        .into_iter()
        .map(|((who, sid), e)| {
            let foreign = node(m, sid).is_none() && who.ends_with('$');
            affected(
                who,
                "account",
                None,
                format!(
                    "{} {}{}",
                    plural(e.n as usize, "replication request", "replication requests"),
                    e.seen(),
                    if foreign {
                        "; a computer outside this domain: confirm it is a DC of another domain"
                    } else {
                        ""
                    }
                ),
                node_id(m, sid),
            )
            .seen_at(e.last)
        })
        .collect();
    let mut out = check("HUNT-AD-001")
        .expected("Only domain controllers request directory replication")
        .found(
            plural(
                list.len(),
                "account that is not a DC",
                "accounts that are not DCs",
            ) + " requested replication",
        );
    if !expected.is_empty() {
        out = out.evidence(
            "Entra Connect (expected)",
            expected.into_iter().collect::<Vec<_>>().join(", "),
        );
    }
    finish(
        m,
        out,
        &[&h],
        "Audit Directory Service Access (success) with a SACL for replication rights on the domain head",
        list,
        "accounts",
    )
}

fn hunt_002(m: &Model) -> CheckResult {
    let h = hunt(m, "hunt_kerberoast");
    let mut by: BTreeMap<&str, Agg> = BTreeMap::new();
    for r in &h.rows {
        let e = by.entry(r.get(0)).or_default().add(r);
        e.a.insert(r.get(1).to_string());
        e.b.extend(value(r.get(2)));
    }
    let list: Vec<Affected> = by
        .into_iter()
        .filter(|(_, e)| e.a.len() >= ROAST_SERVICES)
        .map(|(who, e)| {
            let shown: Vec<&str> = e.a.iter().map(String::as_str).take(5).collect();
            affected(
                who,
                "account",
                (!e.b.is_empty()).then(|| format!("From {}", joined(&e.b))),
                format!(
                    "{} for {} ({}{}) {}",
                    plural(e.n as usize, "RC4 service ticket", "RC4 service tickets"),
                    plural(e.a.len(), "service", "services"),
                    shown.join(", "),
                    if e.a.len() > 5 { ", …" } else { "" },
                    e.seen()
                ),
                None,
            )
            .seen_at(e.last)
        })
        .collect();
    let out = check("HUNT-AD-002")
        .expected(format!(
            "No account requests RC4 service tickets for {ROAST_SERVICES} or more services"
        ))
        .found(
            plural(list.len(), "account requested", "accounts requested")
                + " RC4 tickets for many services",
        )
        .evidence("RC4 service tickets", h.total.to_string());
    finish(
        m,
        out,
        &[&h],
        "Audit Kerberos Service Ticket Operations (success)",
        list,
        "accounts",
    )
}

fn hunt_003(m: &Model) -> CheckResult {
    let h = hunt(m, "hunt_asrep");
    let mut by: BTreeMap<&str, Agg> = BTreeMap::new();
    for r in &h.rows {
        by.entry(r.get(0))
            .or_default()
            .add(r)
            .b
            .extend(value(r.get(1)));
    }
    let list: Vec<Affected> = by
        .into_iter()
        .map(|(who, e)| {
            let i = m
                .nodes
                .iter()
                .position(|x| x.kind == Kind::User && x.name.eq_ignore_ascii_case(who));
            affected(
                who,
                "account",
                (!e.b.is_empty()).then(|| format!("From {}", joined(&e.b))),
                format!(
                    "{} without pre-authentication {}",
                    plural(e.n as usize, "ticket issued", "tickets issued"),
                    e.seen()
                ),
                i.map(|i| m.nodes[i].id.clone()),
            )
            .seen_at(e.last)
        })
        .collect();
    let out = check("HUNT-AD-003")
        .expected("No ticket is issued without Kerberos pre-authentication")
        .found(
            plural(list.len(), "account was", "accounts were")
                + " issued tickets without pre-authentication",
        );
    finish(
        m,
        out,
        &[&h],
        "Audit Kerberos Authentication Service (success)",
        list,
        "accounts",
    )
}

fn source(ip: &str) -> &str {
    if ip.is_empty() || ip == "-" {
        "Unknown source"
    } else {
        ip
    }
}

fn hunt_004(m: &Model) -> CheckResult {
    let h = hunt(m, "hunt_failures");
    let mut by: BTreeMap<&str, Agg> = BTreeMap::new();
    for r in &h.rows {
        by.entry(source(r.get(0)))
            .or_default()
            .add(r)
            .a
            .insert(r.get(1).to_string());
    }
    let list: Vec<Affected> = by
        .into_iter()
        .filter(|(_, e)| e.a.len() >= SPRAY_ACCOUNTS)
        .map(|(ip, e)| {
            affected(
                ip,
                "client",
                None,
                format!(
                    "{} across {} {}",
                    plural(e.n as usize, "failed sign-in", "failed sign-ins"),
                    plural(e.a.len(), "account", "accounts"),
                    e.seen()
                ),
                None,
            )
            .seen_at(e.last)
        })
        .collect();
    let out = check("HUNT-AD-004")
        .expected(format!(
            "No source fails to sign in as {SPRAY_ACCOUNTS} or more different accounts"
        ))
        .found(plural(list.len(), "source tried", "sources tried") + " many accounts")
        .evidence("Failed sign-ins", h.total.to_string());
    finish(
        m,
        out,
        &[&h],
        "Audit Logon (failure) and Audit Kerberos Authentication Service (failure)",
        list,
        "sources",
    )
}

fn hunt_005(m: &Model) -> CheckResult {
    let fails = hunt(m, "hunt_failures");
    let locks = hunt(m, "hunt_lockouts");
    let mut list = Vec::new();
    let mut pairs: BTreeMap<(&str, &str), Agg> = BTreeMap::new();
    for r in &fails.rows {
        pairs
            .entry((r.get(1), source(r.get(0))))
            .or_default()
            .add(r);
    }
    for ((user, ip), e) in pairs.into_iter().filter(|(_, e)| e.n >= BRUTE_FAILURES) {
        list.push(
            affected(
                user,
                "account",
                Some(format!("From {ip}")),
                format!(
                    "{} {}",
                    plural(e.n as usize, "failed sign-in", "failed sign-ins"),
                    e.seen()
                ),
                None,
            )
            .seen_at(e.last),
        );
    }
    let lockouts: u64 = locks.rows.iter().map(|r| r.count).sum();
    if lockouts >= LOCKOUT_STORM {
        let mut by: BTreeMap<&str, Agg> = BTreeMap::new();
        for r in &locks.rows {
            by.entry(r.get(0))
                .or_default()
                .add(r)
                .b
                .extend(value(r.get(1)));
        }
        for (user, e) in by {
            list.push(
                affected(
                    user,
                    "account",
                    (!e.b.is_empty()).then(|| format!("Locked from {}", joined(&e.b))),
                    format!(
                        "Locked out {}{}",
                        plural(e.n as usize, "time", "times"),
                        e.last
                            .and_then(|l| l.get(..10))
                            .map(|d| format!("; last {d}"))
                            .unwrap_or_default()
                    ),
                    None,
                )
                .seen_at(e.last),
            );
        }
    }
    let out = check("HUNT-AD-005")
        .expected(format!(
            "No account fails {BRUTE_FAILURES} or more sign-ins from one source, and fewer than {LOCKOUT_STORM} lockouts in the window"
        ))
        .found(format!(
            "{}; {}",
            plural(
                list.iter().filter(|a| a.reason.as_deref().is_some_and(|r| !r.starts_with("Locked"))).count(),
                "account under repeated guessing",
                "accounts under repeated guessing"
            ),
            plural(lockouts as usize, "lockout", "lockouts")
        ))
        .evidence("Lockouts", lockouts.to_string());
    finish(
        m,
        out,
        &[&fails, &locks],
        "Audit Logon (failure) and Audit User Account Management (success)",
        list,
        "accounts",
    )
}

fn hunt_008(m: &Model) -> CheckResult {
    let h = hunt(m, "hunt_ntlm");
    let privileged = m.privileged_users();
    let mut by: BTreeMap<usize, Agg> = BTreeMap::new();
    for r in &h.rows {
        let Some(i) = m.by_sid(r.get(0)) else {
            continue;
        };
        if !(privileged.contains_key(&i) || (m.nodes[i].tier0 && m.nodes[i].kind == Kind::User)) {
            continue;
        }
        let from = match (r.get(2), r.get(3)) {
            ("" | "-", ip) => source(ip).to_string(),
            (ws, "" | "-") => ws.to_string(),
            (ws, ip) => format!("{ws} ({ip})"),
        };
        by.entry(i).or_default().add(r).b.insert(from);
    }
    let list: Vec<Affected> = by
        .into_iter()
        .map(|(i, e)| {
            super::rules::item(
                m,
                i,
                format!(
                    "{} from {} {}",
                    plural(e.n as usize, "NTLM network logon", "NTLM network logons"),
                    joined(&e.b),
                    e.seen()
                ),
            )
        })
        .collect();
    let out = check("HUNT-AD-008")
        .expected("Privileged accounts sign in to domain controllers with Kerberos, not NTLM")
        .found(
            plural(
                list.len(),
                "privileged account used",
                "privileged accounts used",
            ) + " NTLM",
        )
        .evidence("NTLM network logons (all accounts)", h.total.to_string());
    finish(m, out, &[&h], "Audit Logon (success)", list, "accounts")
}

// ---------- Directory changes ----------

fn hunt_009(m: &Model) -> CheckResult {
    let h = hunt(m, "hunt_dsobjects");
    let mut list = Vec::new();
    for r in &h.rows {
        let dn = r.get(1);
        let server = super::model::parent_dn(dn)
            .map(rdn_value)
            .unwrap_or_default();
        let known = m
            .nodes
            .iter()
            .any(|n| n.is_dc() && n.name.trim_end_matches('$').eq_ignore_ascii_case(&server));
        if !known {
            list.push(affected(
                server.clone(),
                "server",
                Some(dn.to_string()),
                format!(
                    "Domain controller settings created by {}, but {server} is not a domain controller of this domain{}",
                    r.get(0),
                    r.last.and_then(|l| l.get(..10)).map(|d| format!("; {d}")).unwrap_or_default()
                ),
                None,
            ).seen_at(r.last));
        }
    }
    let out = check("HUNT-AD-009")
        .expected("New domain controller (nTDSDSA) objects belong to domain controllers")
        .found(plural(
            list.len(),
            "unexpected domain controller object",
            "unexpected domain controller objects",
        ))
        .evidence("nTDSDSA objects created", h.total.to_string());
    finish(
        m,
        out,
        &[&h],
        "Audit Directory Service Changes (success)",
        list,
        "objects",
    )
}

/// 5136 rows for one attribute: (object DN, subject, subject SID, count, last, DCs).
fn changes<'h>(h: &'h Hunt, attr: &str) -> Vec<&'h Row<'h>> {
    h.rows
        .iter()
        .filter(|r| r.get(0).eq_ignore_ascii_case(attr))
        .collect()
}

fn change_item(m: &Model, r: &Row, reason: &str) -> Affected {
    let dn = r.get(1);
    let target = m.by_dn.get(&dn.to_ascii_lowercase()).copied();
    Affected {
        last_seen: r.last.map(str::to_string),
        name: target
            .map(|i| m.nodes[i].name.clone())
            .unwrap_or_else(|| rdn_value(dn)),
        kind: target
            .map(|i| m.nodes[i].kind.ui().to_string())
            .unwrap_or_else(|| "object".into()),
        location: Some(dn.to_string()),
        reason: Some(format!(
            "{reason} by {} ({}){}",
            r.get(2),
            plural(r.count as usize, "change", "changes"),
            r.last
                .and_then(|l| l.get(..10))
                .map(|d| format!("; last {d} on {}", r.dc))
                .unwrap_or_default()
        )),
        object: target.map(|i| m.nodes[i].id.clone()),
    }
}

fn hunt_010(m: &Model) -> CheckResult {
    let h = hunt(m, "hunt_dschanges");
    let list: Vec<Affected> = changes(&h, "nTSecurityDescriptor")
        .into_iter()
        .map(|r| change_item(m, r, "Permissions changed"))
        .collect();
    let out = check("HUNT-AD-010")
        .expected("No permission changes on AdminSDHolder or the domain head")
        .found(
            plural(list.len(), "permission change", "permission changes")
                + " on AdminSDHolder or the domain head",
        );
    finish(
        m,
        out,
        &[&h],
        "Audit Directory Service Changes (success) with the default SACLs on AdminSDHolder and the domain head",
        list,
        "changes",
    )
}

fn hunt_016(m: &Model) -> CheckResult {
    let h = hunt(m, "hunt_dschanges");
    let list: Vec<Affected> = changes(&h, "msDS-KeyCredentialLink")
        .into_iter()
        .filter(|r| {
            let sid = r.get(3);
            let own = m.by_dn.get(&r.get(1).to_ascii_lowercase()).copied() == m.by_sid(sid)
                && m.by_sid(sid).is_some();
            !(sid == "S-1-5-18"
                || node(m, sid).is_some_and(|n| n.is_dc())
                || sync_account(r.get(2))
                || own)
        })
        .map(|r| change_item(m, r, "Key credential added"))
        .collect();
    let out = check("HUNT-AD-016")
        .expected("Key credentials (msDS-KeyCredentialLink) are written only by the account itself, DCs or Entra Connect")
        .found(plural(list.len(), "unexpected key credential write", "unexpected key credential writes"));
    finish(
        m,
        out,
        &[&h],
        "Audit Directory Service Changes (success)",
        list,
        "changes",
    )
}

fn hunt_022(m: &Model) -> CheckResult {
    let h = hunt(m, "hunt_dschanges");
    let roast = hunt(m, "hunt_kerberoast");
    let list: Vec<Affected> = changes(&h, "servicePrincipalName")
        .into_iter()
        .filter(|r| !trusted(m, r.get(3)))
        .map(|r| {
            let mut a = change_item(m, r, "SPN added");
            let requested = roast
                .rows
                .iter()
                .any(|t| t.get(1).eq_ignore_ascii_case(&a.name));
            if requested {
                if let Some(reason) = &mut a.reason {
                    reason.push_str("; an RC4 service ticket was then requested for it");
                }
            }
            a
        })
        .collect();
    let out = check("HUNT-AD-022")
        .expected("SPNs are added to user accounts only by admins")
        .found(
            plural(list.len(), "SPN addition", "SPN additions") + " to user accounts by non-admins",
        );
    finish(
        m,
        out,
        &[&h],
        "Audit Directory Service Changes (success)",
        list,
        "changes",
    )
}

fn hunt_011(m: &Model) -> CheckResult {
    let h = hunt(m, "hunt_groupadds");
    let tier0: BTreeSet<&str> = m
        .tier0_groups()
        .into_iter()
        .filter_map(|g| m.nodes[g].sid.as_deref())
        .collect();
    let list: Vec<Affected> = h
        .rows
        .iter()
        .filter(|r| tier0.contains(r.get(0)))
        .map(|r| {
            let member = m.by_sid(r.get(2));
            let name = member
                .map(|i| m.nodes[i].name.clone())
                .unwrap_or_else(|| match r.get(3) {
                    "" | "-" => r.get(2).to_string(),
                    dn => rdn_value(dn),
                });
            Affected {
                last_seen: r.last.map(str::to_string),
                name,
                kind: member
                    .map(|i| m.nodes[i].kind.ui().to_string())
                    .unwrap_or_else(|| "account".into()),
                location: None,
                reason: Some(format!(
                    "Added to {} by {}{}",
                    r.get(1),
                    r.get(4),
                    r.last
                        .and_then(|l| l.get(..10))
                        .map(|d| format!(" on {d} ({})", r.dc))
                        .unwrap_or_default()
                )),
                object: member.map(|i| m.nodes[i].id.clone()),
            }
        })
        .collect();
    let out = check("HUNT-AD-011")
        .expected("Every addition to a Tier 0 group in the window is a known, approved change")
        .found(plural(list.len(), "addition", "additions") + " to Tier 0 groups")
        .evidence(
            "Group membership additions (all groups)",
            h.total.to_string(),
        );
    finish(
        m,
        out,
        &[&h],
        "Audit Security Group Management (success)",
        list,
        "additions",
    )
}

// ---------- Persistence and tampering on DCs ----------

/// Service names and programs of well-known remote execution and credential
/// theft tools.
const TOOL_SERVICES: &[(&str, &str)] = &[
    ("psexesvc", "PsExec"),
    ("paexec", "PAExec"),
    ("remcomsvc", "RemCom"),
    ("csexecsvc", "CSExec"),
    ("winexesvc", "winexe"),
    ("mimidrv", "Mimikatz driver"),
    ("mimikatz", "Mimikatz"),
    ("mimilib", "Mimikatz"),
    ("btobto", "Impacket smbexec"),
    ("gsecdump", "gsecdump"),
    ("wceservice", "Windows Credential Editor"),
    ("pwdump", "pwdump"),
    ("fgexec", "fgdump"),
];

/// A service whose program is a shell runs a command line, not a service:
/// how Impacket's and Metasploit's PsExec variants run commands.
fn shell(program: &str) -> bool {
    let p = program.to_ascii_lowercase();
    p.contains("%comspec%")
        || p.ends_with("cmd.exe")
        || p.ends_with("cmd")
        || p.contains("powershell")
}

fn tool(service: &str, program: &str) -> Option<String> {
    let (s, p) = (service.to_ascii_lowercase(), program.to_ascii_lowercase());
    if let Some((_, t)) = TOOL_SERVICES
        .iter()
        .find(|(n, _)| s.contains(n) || p.contains(n))
    {
        return Some(format!("Matches {t}"));
    }
    shell(program).then(|| {
        "The service program is a command shell, as remote execution tools install it".to_string()
    })
}

/// atexec names its task with 8 random letters in the root folder.
fn random_task(name: &str) -> bool {
    let n = name.trim_start_matches('\\');
    n.len() == 8
        && !name.trim_start_matches('\\').contains('\\')
        && n.chars().all(|c| c.is_ascii_alphabetic())
}

fn standard_path(program: &str) -> bool {
    let p = program.to_ascii_lowercase().replace('/', "\\");
    [
        "c:\\windows\\",
        "%systemroot%\\",
        "\\systemroot\\",
        "system32\\",
        "c:\\program files\\",
        "c:\\program files (x86)\\",
        "c:\\programdata\\microsoft\\windows defender\\",
    ]
    .iter()
    .any(|s| p.starts_with(s))
}

fn hunt_013(m: &Model) -> CheckResult {
    let services = hunt(m, "hunt_services");
    let tasks = hunt(m, "hunt_tasks");
    let mut list = Vec::new();
    for r in &services.rows {
        let (name, program, account) = (r.get(0), r.get(1), r.get(2));
        if standard_path(program) && tool(name, program).is_none() {
            continue;
        }
        list.push(
            affected(
                name,
                "service",
                Some(r.dc.to_string()),
                format!(
                    "Installed{} running {program} as {account}{}",
                    r.last
                        .and_then(|l| l.get(..10))
                        .map(|d| format!(" {d}"))
                        .unwrap_or_default(),
                    if standard_path(program) {
                        ""
                    } else {
                        "; outside the Windows and Program Files folders"
                    }
                ),
                None,
            )
            .seen_at(r.last),
        );
    }
    for r in &tasks.rows {
        let (name, by) = (r.get(0), r.get(1));
        let machine = by.ends_with('$');
        if machine && !random_task(name) {
            continue;
        }
        list.push(
            affected(
                name,
                "task",
                Some(r.dc.to_string()),
                format!(
                    "Scheduled task created by {by}{}",
                    r.last
                        .and_then(|l| l.get(..10))
                        .map(|d| format!(" on {d}"))
                        .unwrap_or_default()
                ),
                None,
            )
            .seen_at(r.last),
        );
    }
    let out = check("HUNT-AD-013")
        .expected("No services outside the Windows and Program Files folders, and no scheduled tasks created by people, on DCs")
        .found(plural(list.len(), "service or task needs", "services and tasks need") + " review")
        .evidence("Services installed", services.total.to_string())
        .evidence("Scheduled tasks created", tasks.total.to_string());
    finish(
        m,
        out,
        &[&services, &tasks],
        "The System log (event 7045) and Audit Other Object Access Events (success) for 4698",
        list,
        "items",
    )
}

fn hunt_024(m: &Model) -> CheckResult {
    let services = hunt(m, "hunt_services");
    let tasks = hunt(m, "hunt_tasks");
    let mut list = Vec::new();
    for r in &services.rows {
        if let Some(why) = tool(r.get(0), r.get(1)) {
            list.push(
                affected(
                    r.get(0),
                    "service",
                    Some(r.dc.to_string()),
                    format!(
                        "{why}; program {}{}",
                        r.get(1),
                        r.last
                            .and_then(|l| l.get(..10))
                            .map(|d| format!("; installed {d}"))
                            .unwrap_or_default()
                    ),
                    None,
                )
                .seen_at(r.last),
            );
        }
    }
    for r in tasks.rows.iter().filter(|r| random_task(r.get(0))) {
        list.push(
            affected(
                r.get(0),
                "task",
                Some(r.dc.to_string()),
                format!(
                    "An 8-letter random task name, as atexec creates; created by {}",
                    r.get(1)
                ),
                None,
            )
            .seen_at(r.last),
        );
    }
    let out = check("HUNT-AD-024")
        .expected("No services or tasks that match known attack tools on DCs")
        .found(plural(list.len(), "artifact matches", "artifacts match") + " known attack tools");
    finish(
        m,
        out,
        &[&services, &tasks],
        "The System log (event 7045) and Audit Other Object Access Events (success) for 4698",
        list,
        "artifacts",
    )
}

fn hunt_014(m: &Model) -> CheckResult {
    let clears = hunt(m, "hunt_clears");
    let policy = hunt(m, "hunt_auditpolicy");
    let mut list = Vec::new();
    for r in &clears.rows {
        list.push(
            affected(
                r.get(0),
                "account",
                Some(r.dc.to_string()),
                format!(
                    "Cleared the Security log {}{}",
                    plural(r.count as usize, "time", "times"),
                    r.last
                        .and_then(|l| l.get(..10))
                        .map(|d| format!("; last {d}"))
                        .unwrap_or_default()
                ),
                None,
            )
            .seen_at(r.last),
        );
    }
    for r in &policy.rows {
        let (who, sid) = (r.get(0), r.get(1));
        // Group Policy applies audit settings as the DC itself.
        if who.ends_with('$') || sid == "S-1-5-18" || node(m, sid).is_some_and(|n| n.is_dc()) {
            continue;
        }
        list.push(
            affected(
                who,
                "account",
                Some(r.dc.to_string()),
                format!(
                    "Changed the audit policy directly {}{}",
                    plural(r.count as usize, "time", "times"),
                    r.last
                        .and_then(|l| l.get(..10))
                        .map(|d| format!("; last {d}"))
                        .unwrap_or_default()
                ),
                node_id(m, sid),
            )
            .seen_at(r.last),
        );
    }
    let out = check("HUNT-AD-014")
        .expected(
            "Security logs are not cleared and the audit policy changes only through Group Policy",
        )
        .found(format!(
            "{}; {}",
            plural(clears.total as usize, "log clear", "log clears"),
            plural(
                list.len() - clears.rows.len(),
                "direct audit policy change",
                "direct audit policy changes"
            )
        ));
    finish(
        m,
        out,
        &[&clears, &policy],
        "Audit Audit Policy Change (success); 1102 is always logged",
        list,
        "events",
    )
}

fn hunt_015(m: &Model) -> CheckResult {
    let h = hunt(m, "hunt_sidhistory");
    let list: Vec<Affected> = h
        .rows
        .iter()
        .map(|r| {
            let added = r.get(0) == "4765";
            affected(
                r.get(1),
                "account",
                Some(r.dc.to_string()),
                format!(
                    "{} {} by {}{}",
                    if added {
                        "SID history added:"
                    } else {
                        "SID history add failed:"
                    },
                    r.get(2),
                    r.get(3),
                    r.last
                        .and_then(|l| l.get(..10))
                        .map(|d| format!(" on {d}"))
                        .unwrap_or_default()
                ),
                None,
            )
            .seen_at(r.last)
        })
        .collect();
    let out = check("HUNT-AD-015")
        .expected("No SID history is added outside a planned migration")
        .found(plural(
            list.len(),
            "SID history event",
            "SID history events",
        ));
    finish(
        m,
        out,
        &[&h],
        "Audit User Account Management (success and failure)",
        list,
        "events",
    )
}

fn hunt_020(m: &Model) -> CheckResult {
    let h = hunt(m, "hunt_coercion");
    let mut by: BTreeMap<(&str, &str), Agg> = BTreeMap::new();
    for r in &h.rows {
        by.entry((source(r.get(1)), r.get(0)))
            .or_default()
            .add(r)
            .a
            .insert(r.get(2).to_string());
    }
    let list: Vec<Affected> = by
        .into_iter()
        .map(|((ip, pipe), e)| {
            let what = match pipe.to_ascii_lowercase().as_str() {
                "efsrpc" => "EFS RPC (PetitPotam)",
                "spoolss" => "the print spooler (PrinterBug)",
                "netdfs" => "DFS RPC (DFSCoerce)",
                _ => pipe,
            };
            affected(
                ip,
                "client",
                None,
                format!(
                    "{} to {what} as {} {}",
                    plural(e.n as usize, "connection", "connections"),
                    joined(&e.a),
                    e.seen()
                ),
                None,
            )
            .seen_at(e.last)
        })
        .collect();
    let out = check("HUNT-AD-020")
        .expected("No client opens the EFS, print spooler or DFS RPC pipes on a domain controller")
        .found(plural(list.len(), "source opened", "sources opened") + " pipes used for authentication coercion")
        .evidence(
            "Note",
            "Print clients use the spooler pipe legitimately when a DC shares printers; the EFS pipe has no routine use on a DC.",
        );
    finish(
        m,
        out,
        &[&h],
        "Audit Detailed File Share (success)",
        list,
        "sources",
    )
}

const DCEVENTS: &[&str] = &["dcevents"];
const WITH_GROUPS: &[&str] = &["dcevents", "users", "computers", "groups"];

// ---------- Added hunts: forged tickets, NTDS access, LSASS, admin sign-ins ----------

/// One affected row per distinct key, merged across DCs.
fn by_key<'a>(h: &Hunt<'a>, key: impl Fn(&Row<'a>) -> Option<String>) -> BTreeMap<String, Agg<'a>> {
    let mut by: BTreeMap<String, Agg> = BTreeMap::new();
    for r in &h.rows {
        if let Some(k) = key(r) {
            by.entry(k).or_default().add(r);
        }
    }
    by
}

fn hunt_006(m: &Model) -> CheckResult {
    let h = hunt(m, "hunt_golden");
    let list: Vec<Affected> = by_key(&h, |r| Some(format!("{}|{}", r.get(1), r.get(0))))
        .into_iter()
        .map(|(k, e)| {
            let (user, domain) = k.split_once('|').unwrap_or((&k, ""));
            affected(
                user,
                "account",
                value(domain).map(|d| format!("Account domain written as {d}")),
                format!(
                    "{} with a lower-case account domain, which real tickets do not carry; {}",
                    plural(e.n as usize, "service ticket", "service tickets"),
                    e.seen()
                ),
                None,
            )
            .seen_at(e.last)
        })
        .collect();
    let out = check("HUNT-AD-006")
        .expected("No service tickets carry signs of a forged (golden) ticket")
        .found(plural(list.len(), "account", "accounts") + " with suspicious tickets");
    finish(
        m,
        out,
        &[&h],
        "Audit Kerberos Service Ticket Operations (success)",
        list,
        "accounts",
    )
}

fn hunt_007(m: &Model) -> CheckResult {
    let h = hunt(m, "hunt_pac");
    let list: Vec<Affected> = by_key(&h, |r| Some(format!("{}|{}", r.get(0), r.get(1))))
        .into_iter()
        .map(|(k, e)| {
            let (id, who) = k.split_once('|').unwrap_or((&k, ""));
            affected(
                value(who).unwrap_or_else(|| format!("KDC event {id}")),
                "event",
                None,
                format!(
                    "KDC event {id}: a ticket without the PAC fields current DCs add, as forged or very old tickets lack; {}",
                    e.seen()
                ),
                None,
            )
            .seen_at(e.last)
        })
        .collect();
    let out = check("HUNT-AD-007")
        .expected("The KDC logs no tickets with missing or unexpected PAC data")
        .found(plural(
            list.len(),
            "PAC warning source",
            "PAC warning sources",
        ));
    finish(
        m,
        out,
        &[&h],
        "The System log on each DC (always on)",
        list,
        "sources",
    )
}

/// Weekday hours, in UTC, that count as the change window.
const WINDOW_HOURS: std::ops::Range<u32> = 6..19;

fn hunt_012(m: &Model) -> CheckResult {
    let h = hunt(m, "hunt_gpochanges");
    let list: Vec<Affected> = h
        .rows
        .iter()
        .filter(|r| {
            let hour: u32 = r.get(0).parse().unwrap_or(12);
            let day: u32 = r.get(1).parse().unwrap_or(1);
            day == 0 || day == 6 || !WINDOW_HOURS.contains(&hour)
        })
        .map(|r| {
            let gpo = rdn_value(r.get(2));
            affected(
                m.nodes
                    .iter()
                    .find(|n| n.kind == Kind::Gpo && rdn_value(&n.dn).eq_ignore_ascii_case(&gpo))
                    .map(|n| n.name.clone())
                    .unwrap_or(gpo),
                "gpo",
                Some(r.get(2).to_string()),
                format!(
                    "Changed by {} at {}:00 UTC on a {}; {}",
                    r.get(3),
                    r.get(0),
                    if matches!(r.get(1), "0" | "6") {
                        "weekend"
                    } else {
                        "weekday"
                    },
                    plural(r.count as usize, "change", "changes")
                ),
                None,
            )
            .seen_at(r.last)
        })
        .collect();
    let out = check("HUNT-AD-012")
        .expected(format!(
            "GPOs change only on weekdays between {}:00 and {}:00 UTC",
            WINDOW_HOURS.start, WINDOW_HOURS.end
        ))
        .found(plural(list.len(), "GPO change", "GPO changes") + " outside the window");
    finish(
        m,
        out,
        &[&h],
        "Audit Directory Service Changes (success) with a SACL on Group Policy objects",
        list,
        "changes",
    )
}

fn hunt_018(m: &Model) -> CheckResult {
    let h = hunt(m, "hunt_ntds");
    let list: Vec<Affected> = by_key(&h, |r| Some(format!("{}|{}", r.get(0), r.get(1))))
        .into_iter()
        .map(|(k, e)| {
            let (tool, who) = k.split_once('|').unwrap_or((&k, ""));
            affected(
                who,
                "account",
                None,
                format!(
                    "Ran {tool}, a tool used to copy the AD database or make shadow copies; {} {}",
                    plural(e.n as usize, "time", "times"),
                    e.seen()
                ),
                None,
            )
            .seen_at(e.last)
        })
        .collect();
    let out = check("HUNT-AD-018")
        .expected("No one ran ntdsutil, vssadmin, esentutl, diskshadow or wbadmin on a DC outside planned backups")
        .found(plural(list.len(), "account ran", "accounts ran") + " database or shadow copy tools");
    finish(
        m,
        out,
        &[&h],
        "Audit Process Creation (success)",
        list,
        "accounts",
    )
}

/// Processes that open LSASS as part of normal operation.
const LSASS_READERS: [&str; 12] = [
    "msmpeng.exe",
    "mssense.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "svchost.exe",
    "lsm.exe",
    "wmiprvse.exe",
    "taskmgr.exe",
    "sysmon64.exe",
    "sysmon.exe",
    "csfalconservice.exe",
];

fn hunt_019(m: &Model) -> CheckResult {
    let h = hunt(m, "hunt_lsass");
    let list: Vec<Affected> = by_key(&h, |r| {
        let exe = r
            .get(0)
            .rsplit('\\')
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        (!LSASS_READERS.contains(&exe.as_str())).then(|| r.get(0).to_string())
    })
    .into_iter()
    .map(|(image, e)| {
        affected(
            image.rsplit('\\').next().unwrap_or(&image),
            "process",
            Some(image.clone()),
            format!(
                "Opened LSASS memory {}; {}",
                plural(e.n as usize, "time", "times"),
                e.seen()
            ),
            None,
        )
        .seen_at(e.last)
    })
    .collect();
    let out = check("HUNT-AD-019")
        .expected("Only expected system and security processes open LSASS on DCs")
        .found(plural(
            list.len(),
            "unexpected process",
            "unexpected processes",
        ));
    finish(
        m,
        out,
        &[&h],
        "Sysmon with process access events (event 10) for lsass.exe",
        list,
        "processes",
    )
}

/// Privileged accounts whose service tickets were for computers in `targets`.
fn admin_ticket_rows<'a>(
    m: &'a Model,
    h: &Hunt<'a>,
    targets: impl Fn(&super::model::Node) -> bool,
) -> BTreeMap<String, Agg<'a>> {
    let privileged = m.privileged_users();
    let admin = |name: &str| {
        privileged
            .keys()
            .any(|&u| m.nodes[u].name.eq_ignore_ascii_case(name))
    };
    by_key(h, |r| {
        let user = r.get(0);
        let svc = r.get(1);
        if !admin(user) {
            return None;
        }
        let computer = m
            .nodes
            .iter()
            .find(|n| n.kind == Kind::Computer && n.name.eq_ignore_ascii_case(svc))?;
        (!computer.tier0 && !computer.is_dc() && targets(computer)).then(|| format!("{user}|{svc}"))
    })
}

fn admin_logons(m: &Model, id: &str, expected: &str, workstations_only: bool) -> CheckResult {
    let h = hunt(m, "hunt_ticketuse");
    let rows = admin_ticket_rows(m, &h, |c| {
        !workstations_only
            || c.attrs
                .str("operatingsystem")
                .is_some_and(|os| !os.to_ascii_lowercase().contains("server"))
    });
    let mut by_user: BTreeMap<String, (Vec<String>, Agg)> = BTreeMap::new();
    for (k, e) in rows {
        let (user, svc) = k.split_once('|').unwrap_or((&k, ""));
        let entry = by_user.entry(user.to_string()).or_default();
        entry.0.push(svc.trim_end_matches('$').to_string());
        entry.1.n += e.n;
        entry.1.dcs.extend(e.dcs.iter().copied());
        entry.1.last = later(entry.1.last, e.last);
    }
    let list: Vec<Affected> = by_user
        .into_iter()
        .map(|(user, (hosts, e))| {
            affected(
                user.clone(),
                "account",
                None,
                format!(
                    "Privileged account used on {}: its credentials are exposed there; {}",
                    hosts.join(", "),
                    e.seen()
                ),
                m.nodes
                    .iter()
                    .find(|n| n.name.eq_ignore_ascii_case(&user))
                    .map(|n| n.id.clone()),
            )
            .seen_at(e.last)
        })
        .collect();
    let out = check(id).expected(expected).found(
        plural(list.len(), "privileged account", "privileged accounts") + " used outside Tier 0",
    );
    finish(
        m,
        out,
        &[&h],
        "Audit Kerberos Service Ticket Operations (success)",
        list,
        "accounts",
    )
}

fn hunt_021(m: &Model) -> CheckResult {
    admin_logons(
        m,
        "HUNT-AD-021",
        "Privileged accounts get service tickets only for Tier 0 computers",
        false,
    )
}

fn priv_029(m: &Model) -> CheckResult {
    admin_logons(
        m,
        "AD-PRIV-029",
        "Privileged accounts are not used on workstations",
        true,
    )
}

fn aud_012(m: &Model) -> CheckResult {
    let fails = hunt(m, "hunt_failures");
    let locks = hunt(m, "hunt_lockouts");
    let changes = hunt(m, "hunt_computerchanges");
    let lockouts: u64 = locks.rows.iter().map(|r| r.count).sum();
    let failures: u64 = fails.rows.iter().map(|r| r.count).sum();
    let days = fails.days.max(1) as u64;
    let mut list = Vec::new();
    if lockouts >= LOCKOUT_STORM {
        list.push(affected(
            "Lockouts",
            "summary",
            None,
            format!("{lockouts} account lockouts in {days} days"),
            None,
        ));
    }
    if failures / days > 1000 {
        list.push(affected(
            "Failed sign-ins",
            "summary",
            None,
            format!("{failures} failed sign-ins in {days} days"),
            None,
        ));
    }
    for r in &changes.rows {
        let target = r.get(0);
        let by = r.get(1);
        let dc = m
            .nodes
            .iter()
            .any(|n| n.is_dc() && n.name.eq_ignore_ascii_case(target));
        let by_dc = by.ends_with('$');
        if dc && !by_dc {
            list.push(
                affected(
                    target,
                    "computer",
                    None,
                    format!(
                        "Domain controller account changed by {by} ({})",
                        plural(r.count as usize, "time", "times")
                    ),
                    None,
                )
                .seen_at(r.last),
            );
        }
    }
    let out = check("AD-AUD-012")
        .expected(
            "No lockout storms, no spike of failed sign-ins and no DC account changes by users",
        )
        .found(format!(
            "{lockouts} lockouts, {failures} failed sign-ins, {} DC account changes",
            changes.rows.iter().map(|r| r.count).sum::<u64>()
        ))
        .evidence("Lockouts", lockouts.to_string())
        .evidence("Failed sign-ins", failures.to_string());
    // Each part is assessed on its own: an older collector may not have run
    // all three queries.
    let all = [&fails, &locks, &changes];
    let read: Vec<&Hunt> = all
        .iter()
        .copied()
        .filter(|h| !h.assessed.is_empty())
        .collect();
    finish(
        m,
        out,
        if read.is_empty() { &all } else { &read },
        "Audit Logon (failure), Audit User Account Management and Audit Computer Account Management (success)",
        list,
        "findings",
    )
}

fn app_005(m: &Model) -> CheckResult {
    let h = hunt(m, "ldap_simple");
    let list: Vec<Affected> = by_key(&h, |r| Some(r.get(0).to_string()))
        .into_iter()
        .map(|(client, e)| {
            affected(
                client.clone(),
                "client",
                None,
                format!(
                    "Simple LDAP bind: the password crosses the network in clear text unless the connection is TLS; {} {}",
                    plural(e.n as usize, "bind", "binds"),
                    e.seen()
                ),
                None,
            )
            .seen_at(e.last)
        })
        .collect();
    let out = check("AD-APP-005")
        .expected("No application signs in to LDAP with a simple bind")
        .found(plural(list.len(), "client uses", "clients use") + " simple binds");
    finish(
        m,
        out,
        &[&h],
        "Directory Service event 2889 (LDAP Interface Events diagnostics level 2)",
        list,
        "clients",
    )
}

fn bkp_004(m: &Model) -> CheckResult {
    let h = hunt(m, "hunt_dsrm");
    let sets = by_key(&h, |r| Some(r.get(0).to_string()));
    let mut list = Vec::new();
    if h.rows.is_empty() && !h.assessed.is_empty() {
        list.push(affected(
            m.dns.clone(),
            "domain",
            None,
            format!(
                "No DSRM password change recorded in the {} of Security log kept: the password may be as old as the DC",
                plural(h.days as usize, "day", "days")
            ),
            None,
        ));
    }
    let found = if sets.is_empty() {
        "No DSRM password change found".to_string()
    } else {
        sets.iter()
            .map(|(who, e)| format!("set by {who} {}", e.seen()))
            .collect::<Vec<_>>()
            .join("; ")
    };
    let out = check("AD-BKP-004")
        .expected("The DSRM administrator password of every DC is set and changed at least yearly (event 4794)")
        .found(found);
    finish(
        m,
        out,
        &[&h],
        "Audit User Account Management (success)",
        list,
        "domains",
    )
}

pub static RULES: &[Rule] = &[
    Rule {
        id: "AD-BKP-004",
        needs: &[],
        run: bkp_004,
    },
    Rule {
        id: "HUNT-AD-006",
        needs: DCEVENTS,
        run: hunt_006,
    },
    Rule {
        id: "HUNT-AD-007",
        needs: DCEVENTS,
        run: hunt_007,
    },
    Rule {
        id: "HUNT-AD-012",
        needs: WITH_GROUPS,
        run: hunt_012,
    },
    Rule {
        id: "HUNT-AD-018",
        needs: DCEVENTS,
        run: hunt_018,
    },
    Rule {
        id: "HUNT-AD-019",
        needs: DCEVENTS,
        run: hunt_019,
    },
    Rule {
        id: "HUNT-AD-021",
        needs: WITH_GROUPS,
        run: hunt_021,
    },
    Rule {
        id: "AD-PRIV-029",
        needs: WITH_GROUPS,
        run: priv_029,
    },
    Rule {
        id: "AD-AUD-012",
        needs: WITH_GROUPS,
        run: aud_012,
    },
    Rule {
        id: "AD-APP-005",
        needs: DCEVENTS,
        run: app_005,
    },
    Rule {
        id: "HUNT-AD-001",
        needs: WITH_GROUPS,
        run: hunt_001,
    },
    Rule {
        id: "HUNT-AD-002",
        needs: DCEVENTS,
        run: hunt_002,
    },
    Rule {
        id: "HUNT-AD-003",
        needs: DCEVENTS,
        run: hunt_003,
    },
    Rule {
        id: "HUNT-AD-004",
        needs: DCEVENTS,
        run: hunt_004,
    },
    Rule {
        id: "HUNT-AD-005",
        needs: DCEVENTS,
        run: hunt_005,
    },
    Rule {
        id: "HUNT-AD-008",
        needs: WITH_GROUPS,
        run: hunt_008,
    },
    Rule {
        id: "HUNT-AD-009",
        needs: WITH_GROUPS,
        run: hunt_009,
    },
    Rule {
        id: "HUNT-AD-010",
        needs: DCEVENTS,
        run: hunt_010,
    },
    Rule {
        id: "HUNT-AD-011",
        needs: WITH_GROUPS,
        run: hunt_011,
    },
    Rule {
        id: "HUNT-AD-013",
        needs: DCEVENTS,
        run: hunt_013,
    },
    Rule {
        id: "HUNT-AD-014",
        needs: WITH_GROUPS,
        run: hunt_014,
    },
    Rule {
        id: "HUNT-AD-015",
        needs: DCEVENTS,
        run: hunt_015,
    },
    Rule {
        id: "HUNT-AD-016",
        needs: WITH_GROUPS,
        run: hunt_016,
    },
    Rule {
        id: "HUNT-AD-020",
        needs: DCEVENTS,
        run: hunt_020,
    },
    Rule {
        id: "HUNT-AD-022",
        needs: WITH_GROUPS,
        run: hunt_022,
    },
    Rule {
        id: "HUNT-AD-024",
        needs: DCEVENTS,
        run: hunt_024,
    },
];
