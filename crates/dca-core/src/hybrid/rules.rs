//! The hybrid rules. On-prem accounts are matched to Entra objects by the
//! on-premises SID that Entra Connect and Cloud Sync write to the cloud
//! object (`onPremisesSecurityIdentifier`).

use std::collections::{BTreeMap, HashMap, HashSet};

use serde_json::Value;

use super::{Ctx, Rule};
use crate::ad::model::{uac, Kind, Model};
use crate::ad::rules::{check, days_text, describe, item, plural};
use crate::entra::model::{PrincipalKind, Tenant, DIR_SYNC, J};
use crate::results::{Affected, CheckResult};

const PASSWORD_DAYS: i64 = 365;
const SSO_KEY_DAYS: i64 = 30;
const SYNC_SIGNIN_DAYS: i64 = 30;

/// Rights over an object that let a principal take it over.
const CONTROL: [&str; 9] = [
    "GenericAll",
    "GenericWrite",
    "WriteDacl",
    "WriteOwner",
    "Owns",
    "AllExtendedRights",
    "AddMember",
    "ForceChangePassword",
    "AddKeyCredentialLink",
];

fn read_from(ctx: &Ctx) -> String {
    let mut parts: Vec<String> = ctx
        .domains
        .iter()
        .map(|m| format!("LDAP on {} as {}", m.raw.info.server, m.raw.info.account))
        .collect();
    if let Some(t) = ctx.tenant {
        parts.push(format!(
            "Microsoft Graph, signed in as {}",
            t.raw.info.account
        ));
    }
    parts.join("; ")
}

fn tenant<'s, 'r>(ctx: &Ctx<'s, 'r>) -> &'s Tenant<'r> {
    ctx.tenant
        .expect("rules that read Entra data only run with a tenant")
}

fn names(m: &Model, list: &[usize]) -> String {
    let mut v: Vec<&str> = list.iter().map(|&i| m.nodes[i].name.as_str()).collect();
    v.sort_unstable();
    v.dedup();
    v.join(", ")
}

/// Up to `max` entries, then "and N more".
fn short(mut list: Vec<String>, max: usize) -> String {
    list.sort();
    list.dedup();
    let extra = list.len().saturating_sub(max);
    list.truncate(max);
    let mut s = list.join("; ");
    if extra > 0 {
        s.push_str(&format!("; and {extra} more"));
    }
    s
}

/// The AD account with this SID, in whichever collected domain has it.
fn onprem<'s, 'r>(ctx: &Ctx<'s, 'r>, sid: &str) -> Option<(&'s Model<'r>, usize)> {
    ctx.domains
        .iter()
        .find_map(|m| m.by_sid(sid).map(|i| (m, i)))
}

/// Entra users and groups synchronized from AD, by on-premises SID.
fn synced<'r>(t: &Tenant<'r>) -> HashMap<&'r str, &'r Value> {
    t.users
        .values()
        .chain(t.groups.values())
        .filter_map(|v| Some((v.s("onPremisesSecurityIdentifier")?, *v)))
        .collect()
}

fn cloud_name(v: &Value) -> &str {
    v.s("userPrincipalName")
        .or(v.s("displayName"))
        .unwrap_or("?")
}

/// Microsoft Entra Connect AD DS connector accounts: the MSOL_ account an
/// express install creates, or a custom account its description names.
fn connector_accounts(m: &Model) -> Vec<usize> {
    (0..m.nodes.len())
        .filter(|&i| {
            let n = &m.nodes[i];
            if n.kind != Kind::User {
                return false;
            }
            let desc = n
                .attrs
                .str("description")
                .unwrap_or_default()
                .to_lowercase();
            n.name.to_uppercase().starts_with("MSOL_")
                || desc.contains("azure active directory connect")
                || desc.contains("azure ad connect")
                || desc.contains("entra connect")
        })
        .collect()
}

fn admins_by_domain<'s>(ctx: &Ctx<'s, '_>) -> Vec<BTreeMap<usize, Vec<usize>>> {
    ctx.domains.iter().map(|m| m.privileged_users()).collect()
}

fn domain_index(ctx: &Ctx, m: &Model) -> usize {
    ctx.domains
        .iter()
        .position(|d| std::ptr::eq(d, m))
        .unwrap_or(0)
}

// ---------- HY-SYNC ----------

fn sync_004(ctx: &Ctx) -> CheckResult {
    let mut list = Vec::new();
    let mut accounts = Vec::new();
    let mut dcsync = Vec::new();
    for m in ctx.domains {
        let admins = m.privileged_users();
        for a in connector_accounts(m) {
            accounts.push(format!("{} ({})", m.nodes[a].name, m.dns));
            if m.replication.contains_key(&a) {
                dcsync.push(m.nodes[a].name.clone());
            }
            let mut reasons = Vec::new();
            if let Some(groups) = admins.get(&a) {
                reasons.push(format!("Member of {}", names(m, groups)));
            }
            let rights: Vec<String> = m
                .edges
                .iter()
                .filter(|e| e.from == a && CONTROL.contains(&e.kind) && m.nodes[e.to].tier0)
                .map(|e| format!("{} on {}", describe(e.kind), m.nodes[e.to].name))
                .collect();
            if !rights.is_empty() {
                reasons.push(short(rights, 3));
            }
            if !reasons.is_empty() {
                list.push(item(m, a, reasons.join("; ")));
            }
        }
    }
    let out = check("HY-SYNC-004")
        .expected("The connector account holds only the rights sync needs: no admin group membership and no control over Tier 0 objects")
        .evidence("Read from", read_from(ctx));
    if accounts.is_empty() {
        return out
            .found("No Microsoft Entra Connect connector account was found")
            .done();
    }
    out.found(
        plural(
            list.len(),
            "connector account has",
            "connector accounts have",
        ) + " more rights than sync needs",
    )
    .affected(list, "accounts")
    .evidence("Connector accounts", accounts.join(", "))
    .evidence(
        "DCSync rights",
        if dcsync.is_empty() {
            "None".to_string()
        } else {
            format!(
                "{} (expected for password hash sync; it makes the sync server Tier 0)",
                dcsync.join(", ")
            )
        },
    )
    .done()
}

fn sync_005(ctx: &Ctx) -> CheckResult {
    let mut list = Vec::new();
    let mut accounts = 0;
    for m in ctx.domains {
        for a in connector_accounts(m) {
            accounts += 1;
            let age = m.days_since(m.nodes[a].pwd_last_set);
            if age.is_none_or(|d| d > PASSWORD_DAYS) {
                list.push(item(m, a, format!("Password set {} ago", days_text(age))));
            }
        }
    }
    let out = check("HY-SYNC-005")
        .expected(format!(
            "The connector account's password is changed at least every {PASSWORD_DAYS} days"
        ))
        .evidence("Read from", read_from(ctx));
    if accounts == 0 {
        return out
            .found("No Microsoft Entra Connect connector account was found")
            .done();
    }
    out.found(
        plural(
            list.len(),
            "connector account has",
            "connector accounts have",
        ) + &format!(" a password older than {PASSWORD_DAYS} days"),
    )
    .affected(list, "accounts")
    .done()
}

fn sync_006(ctx: &Ctx) -> CheckResult {
    let t = tenant(ctx);
    let mut list = Vec::new();
    let mut holders: Vec<&str> = t
        .holders_of(DIR_SYNC)
        .filter(|h| h.kind == PrincipalKind::User)
        .map(|h| h.principal.as_str())
        .collect();
    holders.sort_unstable();
    holders.dedup();
    for id in &holders {
        let Some(u) = t.users.get(id) else { continue };
        let last = t.days_since(t.last_signin(u));
        let created = t.days_since(u.t("createdDateTime")).unwrap_or(0);
        let reason = match last {
            Some(d) if d > SYNC_SIGNIN_DAYS => format!("Last sign-in {d} days ago"),
            None if created > SYNC_SIGNIN_DAYS => {
                format!("Never signed in; created {created} days ago")
            }
            _ => continue,
        };
        list.push(t.affected(id, reason));
    }
    check("HY-SYNC-006")
        .expected(format!(
            "Only the sync account of a running sync server holds the Directory Synchronization Accounts role; it signs in on every sync cycle, so none is idle for {SYNC_SIGNIN_DAYS} days"
        ))
        .found(plural(list.len(), "sync account is", "sync accounts are") + " idle")
        .affected(list, "accounts")
        .evidence("Role holders", holders.len().to_string())
        .evidence("Read from", read_from(ctx))
        .done()
}

fn sync_007(ctx: &Ctx) -> CheckResult {
    let t = tenant(ctx);
    let cloud = synced(t);
    let mut list = Vec::new();
    for m in ctx.domains {
        for (u, groups) in m.privileged_users() {
            let Some(sid) = m.nodes[u].sid.as_deref() else {
                continue;
            };
            if let Some(v) = cloud.get(sid) {
                list.push(item(
                    m,
                    u,
                    format!(
                        "Member of {}; synchronized as {}",
                        names(m, &groups),
                        cloud_name(v)
                    ),
                ));
            }
        }
    }
    check("HY-SYNC-007")
        .expected(
            "On-premises admin accounts are not synchronized; cloud admins use cloud-only accounts",
        )
        .found(
            plural(list.len(), "on-premises admin is", "on-premises admins are")
                + " synchronized to Entra ID",
        )
        .affected(list, "accounts")
        .evidence("Read from", read_from(ctx))
        .done()
}

fn sync_008(ctx: &Ctx) -> CheckResult {
    let t = tenant(ctx);
    let cloud = synced(t);
    let mut list = Vec::new();
    for m in ctx.domains {
        for g in m.tier0_groups() {
            let Some(sid) = m.nodes[g].sid.as_deref() else {
                continue;
            };
            if let Some(v) = cloud.get(sid) {
                list.push(item(m, g, format!("Synchronized as {}", cloud_name(v))));
            }
        }
    }
    check("HY-SYNC-008")
        .expected("Tier 0 groups are left out of the sync scope")
        .found(
            plural(list.len(), "Tier 0 group is", "Tier 0 groups are")
                + " synchronized to Entra ID",
        )
        .affected(list, "groups")
        .evidence("Read from", read_from(ctx))
        .done()
}

fn sync_009(ctx: &Ctx) -> CheckResult {
    let t = tenant(ctx);
    let out = check("HY-SYNC-009")
        .expected("If password writeback is on, the connector account cannot reset passwords of Tier 0 accounts")
        .evidence("Read from", read_from(ctx));
    let writeback = t
        .raw
        .first("onpremsync")
        .and_then(|s| s.o("features"))
        .and_then(|f| f.b("passwordWritebackEnabled"));
    match writeback {
        None if !t.synced() => {
            return out
                .found("Directory synchronization is not enabled (cloud-only tenant)")
                .done()
        }
        None => {
            return out
                .not_assessed(
                    "The directory synchronization features do not include password writeback.",
                )
                .done()
        }
        Some(false) => return out.found("Password writeback is off").done(),
        Some(true) => {}
    }
    let mut list = Vec::new();
    for m in ctx.domains {
        for a in connector_accounts(m) {
            let targets: Vec<String> = m
                .edges
                .iter()
                .filter(|e| {
                    e.from == a
                        && matches!(
                            e.kind,
                            "ForceChangePassword" | "GenericAll" | "AllExtendedRights"
                        )
                        && m.nodes[e.to].tier0
                        && m.nodes[e.to].kind == Kind::User
                })
                .map(|e| m.nodes[e.to].name.clone())
                .collect();
            if !targets.is_empty() {
                list.push(item(
                    m,
                    a,
                    format!("Can reset the password of {}", short(targets, 5)),
                ));
            }
        }
    }
    out.found(if list.is_empty() {
        "Password writeback is on; the connector account cannot reset Tier 0 passwords".to_string()
    } else {
        "Password writeback is on and the connector account can reset Tier 0 passwords".to_string()
    })
    .affected(list, "accounts")
    .done()
}

fn sync_014(ctx: &Ctx) -> CheckResult {
    sso_key(ctx, "HY-SYNC-014")
}

/// The Seamless SSO computer account's Kerberos key age. HY-SYNC-014 and
/// EN-AUTH-013 are the same check, listed under sync and under Entra
/// authentication.
fn sso_key(ctx: &Ctx, id: &str) -> CheckResult {
    let mut list = Vec::new();
    let mut found = Vec::new();
    for m in ctx.domains {
        for i in (0..m.nodes.len()).filter(|&i| {
            m.nodes[i].kind == Kind::Computer
                && m.nodes[i]
                    .name
                    .trim_end_matches('$')
                    .eq_ignore_ascii_case("AZUREADSSOACC")
        }) {
            found.push(m.dns.clone());
            let age = m.days_since(m.nodes[i].pwd_last_set);
            if age.is_none_or(|d| d > SSO_KEY_DAYS) {
                list.push(item(
                    m,
                    i,
                    format!("Kerberos key last rolled over {} ago", days_text(age)),
                ));
            }
        }
    }
    let out = check(id)
        .expected(format!(
            "The Seamless SSO key is rolled over at least every {SSO_KEY_DAYS} days"
        ))
        .evidence("Read from", read_from(ctx));
    if found.is_empty() {
        return out
            .found("Seamless SSO is not set up (no AZUREADSSOACC account)")
            .done();
    }
    out.found(
        plural(list.len(), "domain has", "domains have") + " a Seamless SSO key older than 30 days",
    )
    .affected(list, "accounts")
    .evidence("Seamless SSO set up in", found.join(", "))
    .done()
}

fn sync_016(ctx: &Ctx) -> CheckResult {
    let t = tenant(ctx);
    let mut list = Vec::new();
    for v in t.users.values().chain(t.groups.values()) {
        let errors = v.a("onPremisesProvisioningErrors");
        if errors.is_empty() {
            continue;
        }
        let text: Vec<String> = errors
            .iter()
            .map(|e| {
                let what = e.s("propertyCausingError").unwrap_or("a property");
                match e.s("value") {
                    Some(val) => format!(
                        "{} conflict on {what}: {val}",
                        e.s("category").unwrap_or("Provisioning")
                    ),
                    None => format!(
                        "{} conflict on {what}",
                        e.s("category").unwrap_or("Provisioning")
                    ),
                }
            })
            .collect();
        list.push(t.affected(v.s("id").unwrap_or_default(), short(text, 3)));
    }
    list.sort_by(|a, b| a.name.cmp(&b.name));
    check("HY-SYNC-016")
        .expected("No synchronized object has provisioning errors")
        .found(plural(list.len(), "object has", "objects have") + " provisioning errors")
        .affected(list, "objects")
        .evidence("Read from", read_from(ctx))
        .done()
}

// ---------- HY-PATH ----------

/// Privileged Entra users that are synchronized, with their AD account.
fn privileged_synced<'s, 'r>(ctx: &Ctx<'s, 'r>) -> Vec<(String, String, &'s Model<'r>, usize)> {
    let t = tenant(ctx);
    let mut out = Vec::new();
    for (id, holds) in t.privileged_principals() {
        if holds[0].kind != PrincipalKind::User {
            continue;
        }
        let Some(sid) = t
            .users
            .get(id.as_str())
            .and_then(|u| u.s("onPremisesSecurityIdentifier"))
        else {
            continue;
        };
        if let Some((m, i)) = onprem(ctx, sid) {
            out.push((id.clone(), t.roles_text(&holds), m, i));
        }
    }
    out
}

fn path_001(ctx: &Ctx) -> CheckResult {
    let t = tenant(ctx);
    let admins = admins_by_domain(ctx);
    let mut list = Vec::new();
    for (id, roles, m, i) in privileged_synced(ctx) {
        if let Some(groups) = admins[domain_index(ctx, m)].get(&i) {
            let mut a = t.affected(
                &id,
                format!("{roles} in Entra ID; {} in {}", names(m, groups), m.dns),
            );
            a.location = Some(format!("{} in {}", m.nodes[i].name, m.dns));
            list.push(a);
        }
    }
    check("HY-PATH-001")
        .expected("Separate accounts for on-premises and cloud administration; no identity is an admin on both sides")
        .found(plural(list.len(), "identity is", "identities are") + " admins in both directories")
        .affected(list, "accounts")
        .evidence("Read from", read_from(ctx))
        .done()
}

fn path_004(ctx: &Ctx) -> CheckResult {
    let t = tenant(ctx);
    let mut protected: Vec<HashSet<usize>> = Vec::new();
    for m in ctx.domains {
        protected.push(
            m.group_by_rid(525)
                .map(|g| m.recursive_members(g).into_iter().collect())
                .unwrap_or_default(),
        );
    }
    let mut list = Vec::new();
    for (id, roles, m, i) in privileged_synced(ctx) {
        let n = &m.nodes[i];
        if !n.enabled() {
            continue;
        }
        let mut weak = Vec::new();
        if n.flag(uac::DONT_EXPIRE_PASSWORD) {
            weak.push("password never expires".to_string());
        }
        let age = m.days_since(n.pwd_last_set);
        if age.is_none_or(|d| d > PASSWORD_DAYS) {
            weak.push(format!("password set {} ago", days_text(age)));
        }
        if !n.spns().is_empty() {
            weak.push("has a servicePrincipalName (Kerberoastable)".to_string());
        }
        if n.flag(uac::DONT_REQ_PREAUTH) {
            weak.push("Kerberos pre-authentication not required".to_string());
        }
        if !n.flag(uac::NOT_DELEGATED) && !protected[domain_index(ctx, m)].contains(&i) {
            weak.push("can be delegated".to_string());
        }
        if !weak.is_empty() {
            let mut a = t.affected(&id, format!("{roles}. On-premises: {}", weak.join(", ")));
            a.location = Some(format!("{} in {}", n.name, m.dns));
            list.push(a);
        }
    }
    check("HY-PATH-004")
        .expected("Cloud admins' on-premises accounts are protected like Tier 0: expiring, recent passwords, no SPN, pre-authentication required, not delegable")
        .found(plural(list.len(), "cloud admin has", "cloud admins have") + " a weakly protected on-premises account")
        .affected(list, "accounts")
        .evidence("Read from", read_from(ctx))
        .done()
}

fn path_005(ctx: &Ctx) -> CheckResult {
    let t = tenant(ctx);
    let mut owned: HashMap<&str, Vec<&str>> = HashMap::new();
    for v in t
        .raw
        .list("applications")
        .iter()
        .chain(t.raw.list("serviceprincipals"))
    {
        for o in v.a("owners") {
            if let Some(id) = o.s("id") {
                owned
                    .entry(id)
                    .or_default()
                    .push(v.s("displayName").unwrap_or("Unnamed application"));
            }
        }
    }
    let mut list: Vec<Affected> = Vec::new();
    for u in t.users.values() {
        let (Some(id), Some(sid)) = (u.s("id"), u.s("onPremisesSecurityIdentifier")) else {
            continue;
        };
        let Some((m, i)) = onprem(ctx, sid) else {
            continue;
        };
        let n = &m.nodes[i];
        let service = !n.spns().is_empty() || n.name.to_lowercase().starts_with("svc");
        if !service {
            continue;
        }
        let holds: Vec<_> = t.holders.iter().filter(|h| h.principal == id).collect();
        let mut reasons = Vec::new();
        if !holds.is_empty() {
            reasons.push(t.roles_text(&holds));
        }
        if let Some(apps) = owned.get(id) {
            reasons.push(format!(
                "Owner of {}",
                short(apps.iter().map(|s| s.to_string()).collect(), 3)
            ));
        }
        if !reasons.is_empty() {
            let mut a = t.affected(id, reasons.join("; "));
            a.location = Some(format!("{} in {}", n.name, m.dns));
            list.push(a);
        }
    }
    list.sort_by(|a, b| a.name.cmp(&b.name));
    check("HY-PATH-005")
        .expected("Synchronized service accounts hold no Entra role and own no application")
        .found(
            plural(list.len(), "service account has", "service accounts have")
                + " cloud permissions",
        )
        .affected(list, "accounts")
        .evidence("Read from", read_from(ctx))
        .done()
}

// ---------- HY-FED ----------

fn fed_008(ctx: &Ctx) -> CheckResult {
    let t = tenant(ctx);
    let phs = t
        .raw
        .first("onpremsync")
        .and_then(|s| s.o("features"))
        .and_then(|f| f.b("passwordSyncEnabled"))
        .unwrap_or(false);
    let reason = if phs {
        "Password hash sync is on, so the domain can move to managed authentication with a staged rollout"
    } else {
        "Turn on password hash sync first, then move the domain to managed authentication"
    };
    let list: Vec<Affected> = t
        .raw
        .list("domains")
        .iter()
        .filter(|d| d.s("authenticationType") == Some("Federated"))
        .filter_map(|d| d.s("id"))
        .map(|d| t.object("domain", d, None, reason))
        .collect();
    check("HY-FED-008")
        .expected("Every domain uses managed authentication (password hash sync or pass-through), so no federation server is Tier 0")
        .found(plural(list.len(), "domain is", "domains are") + " still federated")
        .affected(list, "domains")
        .evidence("Password hash sync", if phs { "On" } else { "Off" })
        .evidence("Read from", read_from(ctx))
        .done()
}

fn auth_013(ctx: &Ctx) -> CheckResult {
    sso_key(ctx, "EN-AUTH-013")
}

// ---------- Cloud management of Tier 0 ----------

/// Domain controllers and Tier 0 computers, by lower-case host name.
pub(crate) fn tier0_hosts<'s, 'r>(ctx: &Ctx<'s, 'r>) -> BTreeMap<String, (&'s Model<'r>, usize)> {
    let mut out = BTreeMap::new();
    for m in ctx.domains {
        for (i, n) in m.nodes.iter().enumerate() {
            if n.kind == Kind::Computer && (n.is_dc() || n.tier0) {
                out.insert(n.name.trim_end_matches('$').to_lowercase(), (m, i));
            }
        }
    }
    out
}

fn tier0_cloud_managed(ctx: &Ctx, id: &str, expected: &str) -> CheckResult {
    let t = tenant(ctx);
    let hosts = tier0_hosts(ctx);
    let mut list = Vec::new();
    for d in t.raw.list("intunedevices") {
        let name = d.s("deviceName").unwrap_or_default().to_lowercase();
        if let Some((m, i)) = hosts.get(&name) {
            let what = if m.nodes[*i].is_dc() {
                "Domain controller"
            } else {
                "Tier 0 server"
            };
            list.push(item(
                m,
                *i,
                format!(
                    "{what} enrolled in Intune ({}): Intune admins can run scripts and apps on it as SYSTEM",
                    d.s("managementAgent").unwrap_or("mdm")
                ),
            ));
        }
    }
    check(id)
        .expected(expected)
        .found(
            plural(list.len(), "Tier 0 computer is", "Tier 0 computers are")
                + " managed from Intune",
        )
        .affected(list, "computers")
        .evidence("Read from", read_from(ctx))
        .evidence("Tier 0 computers compared", hosts.len().to_string())
        .done()
}

fn int_020(ctx: &Ctx) -> CheckResult {
    tier0_cloud_managed(
        ctx,
        "M365-INT-020",
        "Domain controllers and Tier 0 servers are not enrolled in Intune or co-management",
    )
}

fn path_007(ctx: &Ctx) -> CheckResult {
    tier0_cloud_managed(
        ctx,
        "HY-PATH-007",
        "No cloud endpoint management reaches domain controllers or Tier 0 servers",
    )
}

const HYBRID_IDENTITY_ADMIN: &str = "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2";
/// Roles that can reset the passwords of some or all users.
const RESET_ROLES: [&str; 5] = [
    "729827e3-9c14-49f7-bb1b-9608f156bbb8",
    "fe930be7-5e62-47db-91af-98c3a49a38b1",
    "966707d0-3269-4727-9be2-8c3a10f19b9d",
    "c4e39bd9-1100-46d3-8c65-fb160da0071f",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",
];

fn path_002(ctx: &Ctx) -> CheckResult {
    let t = tenant(ctx);
    let writeback = t
        .raw
        .first("onpremsync")
        .and_then(|s| s.o("features"))
        .and_then(|f| f.b("passwordWritebackEnabled"))
        .unwrap_or(false);
    // On-prem admins with a synchronized cloud account: the targets.
    let admins = admins_by_domain(ctx);
    let targets: Vec<String> = synced(t)
        .into_iter()
        .filter_map(|(sid, v)| {
            let (m, i) = onprem(ctx, sid)?;
            admins[domain_index(ctx, m)]
                .contains_key(&i)
                .then(|| cloud_name(v).to_string())
        })
        .collect();
    let mut list: Vec<Affected> = Vec::new();
    let mut seen = HashSet::new();
    for h in t.holders_of(HYBRID_IDENTITY_ADMIN) {
        if seen.insert(h.principal.clone()) {
            list.push(t.affected(&h.principal, "Hybrid Identity Administrator: can change sync and federation settings that decide which on-premises identities the cloud trusts"));
        }
    }
    if writeback && !targets.is_empty() {
        for role in RESET_ROLES {
            for h in t.holders_of(role) {
                if seen.insert(h.principal.clone()) {
                    list.push(t.affected(
                        &h.principal,
                        format!(
                            "{} with password writeback on: can reset synced on-premises admins ({}) and the new password is written to AD",
                            t.role_name(role),
                            short(targets.clone(), 3)
                        ),
                    ));
                }
            }
        }
    }
    check("HY-PATH-002")
        .expected("No Entra role short of Tier 0 can change on-premises identities through sync or password writeback")
        .found(plural(list.len(), "cloud principal", "cloud principals") + " with a path into on-premises AD")
        .affected(list, "principals")
        .evidence("Password writeback", if writeback { "On" } else { "Off" })
        .evidence("Synchronized on-premises admins", targets.len().to_string())
        .evidence("Read from", read_from(ctx))
        .done()
}

const AZ_CONTROL: [(&str, &str); 3] = [
    ("8e3af657-a8ff-443c-a75c-2fe8c4bcb635", "Owner"),
    (
        "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",
        "User Access Administrator",
    ),
    ("b24988ac-6180-42a0-ab88-20f7382dd24c", "Contributor"),
];

fn path_003(ctx: &Ctx) -> CheckResult {
    let t = tenant(ctx);
    let synced_groups: HashMap<&str, &Value> = t
        .groups
        .iter()
        .filter(|(_, g)| g.b("onPremisesSyncEnabled") == Some(true))
        .map(|(id, g)| (*id, *g))
        .collect();
    let mut grants: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for h in t.holders.iter().filter(|h| h.kind == PrincipalKind::Group) {
        if synced_groups.contains_key(h.principal.as_str()) {
            grants
                .entry(h.principal.as_str())
                .or_default()
                .push(format!("Entra role {}", t.role_name(&h.role)));
        }
    }
    for a in t.raw.list("azroleassignments") {
        let Some(p) = a.o("properties") else { continue };
        let Some(g) = p.s("principalId").filter(|g| synced_groups.contains_key(g)) else {
            continue;
        };
        let role = p
            .s("roleDefinitionId")
            .unwrap_or_default()
            .rsplit('/')
            .next()
            .unwrap_or_default()
            .to_lowercase();
        if let Some((_, name)) = AZ_CONTROL.iter().find(|(id, _)| *id == role) {
            grants
                .entry(g)
                .or_default()
                .push(format!("Azure {name} on {}", p.s("scope").unwrap_or("/")));
        }
    }
    let list: Vec<Affected> = grants
        .into_iter()
        .map(|(g, mut what)| {
            what.sort();
            what.dedup();
            let mut a = t.affected(g, format!("Synchronized from AD and holds {}: whoever can change its on-premises membership gets them", what.join(", ")));
            if let Some((m, i)) = synced_groups[g].s("onPremisesSecurityIdentifier").and_then(|sid| onprem(ctx, sid)) {
                a.location = Some(format!("{} in {}", m.nodes[i].name, m.dns));
            }
            a
        })
        .collect();
    check("HY-PATH-003")
        .expected("Cloud roles are granted only through cloud-only groups")
        .found(
            plural(
                list.len(),
                "synchronized group grants",
                "synchronized groups grant",
            ) + " cloud roles",
        )
        .affected(list, "groups")
        .evidence("Read from", read_from(ctx))
        .done()
}

fn def_006(ctx: &Ctx) -> CheckResult {
    let t = tenant(ctx);
    let sensors: HashMap<String, &Value> = t
        .raw
        .list("mdisensors")
        .iter()
        .filter_map(|s| {
            let n = s.s("displayName")?;
            Some((n.split('.').next().unwrap_or(n).to_lowercase(), s))
        })
        .collect();
    let mut list = Vec::new();
    let mut dcs = 0;
    for m in ctx.domains {
        for (i, n) in m
            .nodes
            .iter()
            .enumerate()
            .filter(|(_, n)| n.kind == Kind::Computer && n.is_dc() && n.enabled())
        {
            dcs += 1;
            match sensors.get(&n.name.trim_end_matches('$').to_lowercase()) {
                None => list.push(item(m, i, "No Defender for Identity sensor: attacks against this domain controller are not detected")),
                Some(s) if s.s("healthStatus").is_some_and(|h| h != "healthy") => {
                    list.push(item(m, i, format!("Sensor health: {}", s.s("healthStatus").unwrap_or_default())))
                }
                _ => {}
            }
        }
    }
    for h in t.raw.list("mdihealth") {
        list.push(t.object(
            "health issue",
            h.s("displayName").unwrap_or("Health issue"),
            h.s("severity").map(str::to_string),
            "Open Defender for Identity health issue",
        ));
    }
    check("M365-DEF-006")
        .expected("Every domain controller has a healthy Defender for Identity sensor and no health issue is open")
        .found(format!("{} sensors for {dcs} domain controllers; {}", sensors.len(), plural(list.len(), "finding", "findings")))
        .affected(list, "items")
        .evidence("Read from", read_from(ctx))
        .done()
}

fn path_006(ctx: &Ctx) -> CheckResult {
    let t = tenant(ctx);
    let mut list = Vec::new();
    for (id, roles, m, i) in privileged_synced(ctx) {
        let starts = [
            m.group_by_rid(513),
            m.by_sid(crate::ad::model::AUTHENTICATED_USERS),
            m.by_sid(crate::ad::model::EVERYONE),
        ];
        let Some(chain) = starts
            .into_iter()
            .flatten()
            .find_map(|s| crate::ad::paths::chain(m, s, i))
        else {
            continue;
        };
        let mut a = t.affected(&id, format!("On-premises: {chain}; in Entra ID: {roles}"));
        a.location = Some(format!("{} in {}", m.nodes[i].name, m.dns));
        list.push(a);
    }
    check("HY-PATH-006")
        .expected("No chain of on-premises permissions lets ordinary users take over an account that administers the cloud")
        .found(plural(list.len(), "cloud admin is", "cloud admins are") + " reachable from ordinary users on-premises")
        .affected(list, "accounts")
        .evidence("Read from", read_from(ctx))
        .done()
}

/// Exchange Server Subscription Edition: 15.2 build 2562 and later.
fn exchange_supported(serial: &str) -> Option<bool> {
    let v = serial.split("Version ").nth(1)?;
    let (ver, rest) = v.split_once(' ')?;
    let build: u32 = rest
        .trim_start_matches("(Build ")
        .split('.')
        .next()?
        .parse()
        .ok()?;
    Some(ver == "15.2" && build >= 2562)
}

fn exo_029(ctx: &Ctx) -> CheckResult {
    let t = tenant(ctx);
    let onprem: Vec<String> = t
        .raw
        .list("exoinbound")
        .iter()
        .chain(t.raw.list("exooutbound"))
        .filter(|c| {
            c.s("ConnectorType") == Some("OnPremises")
                && c.b("Enabled") != Some(false)
                && c.s("Enabled") != Some("False")
        })
        .filter_map(|c| c.s("Name").map(str::to_string))
        .collect();
    let mut list = Vec::new();
    let mut servers = 0;
    for m in ctx.domains {
        for o in m.raw.objects("exchservers") {
            servers += 1;
            let serial = o.str("serialnumber").unwrap_or_default();
            if exchange_supported(serial) != Some(true) {
                list.push(crate::ad::rules_forest::obj_item(
                    o,
                    "server",
                    format!(
                        "{} is out of support{}",
                        if serial.is_empty() {
                            "Unknown version"
                        } else {
                            serial
                        },
                        if onprem.is_empty() {
                            ""
                        } else {
                            ", and Exchange Online exchanges mail with on-premises servers"
                        }
                    ),
                ));
            }
        }
    }
    check("M365-EXO-029")
        .expected("Hybrid mail flow goes only to supported Exchange servers (Exchange Server SE)")
        .found(format!(
            "{}; {} out of support; {}",
            plural(servers, "Exchange server", "Exchange servers"),
            list.len(),
            plural(
                onprem.len(),
                "on-premises connector",
                "on-premises connectors"
            )
        ))
        .affected(list, "servers")
        .evidence("Read from", read_from(ctx))
        .done()
}

pub static RULES: &[Rule] = &[
    Rule {
        id: "HY-PATH-006",
        ad: &["users", "groups", "acls"],
        entra: &["users", "roleassignments"],
        run: path_006,
    },
    Rule {
        id: "M365-EXO-029",
        ad: &["exchservers"],
        entra: &["exoinbound", "exooutbound"],
        run: exo_029,
    },
    Rule {
        id: "M365-DEF-006",
        ad: &["computers"],
        entra: &["mdisensors", "mdihealth"],
        run: def_006,
    },
    Rule {
        id: "EN-AUTH-013",
        ad: &["computers"],
        entra: &[],
        run: auth_013,
    },
    Rule {
        id: "M365-INT-020",
        ad: &["computers", "groups"],
        entra: &["intunedevices"],
        run: int_020,
    },
    Rule {
        id: "HY-PATH-007",
        ad: &["computers", "groups"],
        entra: &["intunedevices"],
        run: path_007,
    },
    Rule {
        id: "HY-PATH-002",
        ad: &["users", "groups"],
        entra: &["users", "roleassignments", "onpremsync"],
        run: path_002,
    },
    Rule {
        id: "HY-PATH-003",
        ad: &[],
        entra: &["groups", "roleassignments"],
        run: path_003,
    },
    Rule {
        id: "HY-SYNC-004",
        ad: &["users", "groups", "acls"],
        entra: &[],
        run: sync_004,
    },
    Rule {
        id: "HY-SYNC-005",
        ad: &["users"],
        entra: &[],
        run: sync_005,
    },
    Rule {
        id: "HY-SYNC-006",
        ad: &[],
        entra: &["users", "signinactivity", "roleassignments"],
        run: sync_006,
    },
    Rule {
        id: "HY-SYNC-007",
        ad: &["users", "groups"],
        entra: &["users"],
        run: sync_007,
    },
    Rule {
        id: "HY-SYNC-008",
        ad: &["groups"],
        entra: &["groups"],
        run: sync_008,
    },
    Rule {
        id: "HY-SYNC-009",
        ad: &["users", "acls"],
        entra: &["onpremsync", "organization"],
        run: sync_009,
    },
    Rule {
        id: "HY-SYNC-014",
        ad: &["computers"],
        entra: &[],
        run: sync_014,
    },
    Rule {
        id: "HY-SYNC-016",
        ad: &[],
        entra: &["users", "groups"],
        run: sync_016,
    },
    Rule {
        id: "HY-PATH-001",
        ad: &["users", "groups"],
        entra: &["users", "roleassignments"],
        run: path_001,
    },
    Rule {
        id: "HY-PATH-004",
        ad: &["users", "groups"],
        entra: &["users", "roleassignments"],
        run: path_004,
    },
    Rule {
        id: "HY-PATH-005",
        ad: &["users"],
        entra: &["users", "roleassignments"],
        run: path_005,
    },
    Rule {
        id: "HY-FED-008",
        ad: &[],
        entra: &["domains", "onpremsync"],
        run: fed_008,
    },
];
