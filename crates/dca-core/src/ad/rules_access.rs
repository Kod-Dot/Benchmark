//! Who can change or read sensitive attributes and containers, how
//! privileged access is structured (nesting, mailboxes, break-glass and
//! decoy accounts, RODC password replication), Kerberos exposure on
//! accounts, and recent changes recorded in replication metadata.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use super::model::{uac, Kind, Model};
use super::raw::LdapObject;
use super::rules::{check, item, plural, Rule};
use super::rules_forest::{
    crossrefs, dcs, decode_sd, describe, non_default_writers, obj_item, who,
};
use super::sd::{right, AceType};
use crate::results::{Affected, CheckResult};
use crate::time;

const RECENT_DAYS: i64 = 30;
const BROAD_GROUP: usize = 50;
const DEEP_NESTING: usize = 3;

const GUID_UAC: &str = "bf967a68-0de6-11d0-a285-00aa003049e2";
const GUID_ALT_SEC_IDS: &str = "00fbf30c-91fe-11d1-aebc-0000f80367c1";
const GUID_ACCOUNT_RESTRICTIONS: &str = "4c164200-20c0-11d0-a768-00aa006e0529";
const CLASS_USER: &str = "bf967aba-0de6-11d0-a285-00aa003049e2";
const CLASS_GROUP: &str = "bf967a9c-0de6-11d0-a285-00aa003049e2";
const CLASS_COMPUTER: &str = "bf967a86-0de6-11d0-a285-00aa003049e2";
const SELF_SID: &str = "S-1-5-10";

fn read_from(m: &Model, what: &str) -> String {
    format!(
        "{what} via LDAP on {} as {}",
        m.raw.info.server, m.raw.info.account
    )
}

fn broad(m: &Model, sid: &str) -> bool {
    matches!(sid, "S-1-1-0" | "S-1-5-11" | "S-1-5-7")
        || sid
            .strip_prefix(&m.domain_sid)
            .is_some_and(|r| r == "-513" || r == "-515")
}

/// A principal that should not hold rights on Tier 0 objects.
fn outsider(m: &Model, sid: &str) -> bool {
    sid != SELF_SID && !m.is_default_admin(sid) && !m.by_sid(sid).is_some_and(|i| m.nodes[i].tier0)
}

fn between<'a>(s: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let a = s.find(start)? + start.len();
    let b = s[a..].find(end)? + a;
    Some(s[a..b].trim())
}

fn has_word(text: &str, words: &[&str]) -> bool {
    let l = text.to_ascii_lowercase();
    words.iter().any(|w| l.contains(w))
}

fn label(m: &Model, i: usize) -> String {
    let n = &m.nodes[i];
    format!(
        "{} {}",
        n.name,
        n.attrs.str("description").unwrap_or_default()
    )
}

// ---------- Permissions on sensitive attributes and containers ----------

fn acl_012(m: &Model) -> CheckResult {
    let mut list = Vec::new();
    let mut targets: Vec<usize> = m.sds.keys().copied().collect();
    targets.sort_unstable();
    for t in targets {
        let n = &m.nodes[t];
        if !n.tier0 || !matches!(n.kind, Kind::User | Kind::Computer) {
            continue;
        }
        let mut found: BTreeMap<String, BTreeSet<&str>> = BTreeMap::new();
        for a in &m.sds[&t].dacl {
            if a.kind != AceType::Allow || a.inherit_only() || !outsider(m, &a.sid) {
                continue;
            }
            if a.mask & right::WRITE_PROP == 0 {
                continue;
            }
            let what = match a.object_type.as_deref() {
                Some(GUID_UAC) => "userAccountControl",
                Some(GUID_ALT_SEC_IDS) => "altSecurityIdentities",
                Some(GUID_ACCOUNT_RESTRICTIONS) => {
                    "account restrictions (includes userAccountControl)"
                }
                _ => continue,
            };
            found.entry(who(m, &a.sid)).or_default().insert(what);
        }
        for (p, what) in found {
            list.push(item(
                m,
                t,
                format!(
                    "{p} can write {}",
                    what.into_iter().collect::<Vec<_>>().join(" and ")
                ),
            ));
        }
    }
    check("AD-ACL-012")
        .expected("Nobody outside Tier 0 can write userAccountControl or altSecurityIdentities on Tier 0 accounts")
        .found(plural(list.len(), "risky write right", "risky write rights"))
        .affected(list, "rights")
        .evidence("Read from", read_from(m, "DACLs of Tier 0 accounts"))
        .done()
}

fn laps_guids(m: &Model) -> Vec<String> {
    m.raw
        .schema
        .iter()
        .filter(|s| {
            s.str("ldapdisplayname").is_some_and(|n| {
                matches!(
                    n.to_ascii_lowercase().as_str(),
                    "ms-mcs-admpwd" | "mslaps-password" | "mslaps-encryptedpassword"
                )
            })
        })
        .filter_map(|s| s.str("schemaidguid"))
        .map(str::to_ascii_lowercase)
        .collect()
}

fn acl_013(m: &Model) -> CheckResult {
    let guids = laps_guids(m);
    let mut inventory = BTreeSet::new();
    let mut list = Vec::new();
    let mut targets: Vec<usize> = m
        .sds
        .keys()
        .copied()
        .filter(|&i| matches!(m.nodes[i].kind, Kind::Ou | Kind::Domain))
        .collect();
    targets.sort_unstable();
    for t in targets {
        let mut wide = BTreeSet::new();
        for a in &m.sds[&t].dacl {
            if a.kind != AceType::Allow || m.is_default_admin(&a.sid) {
                continue;
            }
            if a.inherited_object_type
                .as_deref()
                .is_some_and(|c| c != CLASS_COMPUTER)
            {
                continue;
            }
            let ot = a.object_type.as_deref().map(str::to_ascii_lowercase);
            let how = match ot {
                Some(g) if guids.contains(&g) && a.mask & (right::CONTROL_ACCESS | 0x10) != 0 => {
                    "reads the LAPS password"
                }
                None if a.mask & right::CONTROL_ACCESS != 0 => {
                    "has all extended rights, which include reading LAPS passwords"
                }
                _ => continue,
            };
            let name = who(m, &a.sid);
            inventory.insert(format!("{}: {name} {how}", m.nodes[t].name));
            let big = m
                .by_sid(&a.sid)
                .filter(|&g| m.nodes[g].kind == Kind::Group)
                .is_some_and(|g| m.recursive_members(g).len() > BROAD_GROUP);
            if broad(m, &a.sid) || big {
                wide.insert(name);
            }
        }
        if !wide.is_empty() {
            list.push(item(
                m,
                t,
                format!(
                    "LAPS passwords of computers here are readable by {}",
                    wide.into_iter().collect::<Vec<_>>().join(", ")
                ),
            ));
        }
    }
    check("AD-ACL-013")
        .expected(format!(
            "Only small admin groups can read LAPS passwords (no broad groups, none over {BROAD_GROUP} members)"
        ))
        .found(format!(
            "{}; {} readable too broadly",
            plural(inventory.len(), "LAPS read delegation", "LAPS read delegations"),
            plural(list.len(), "OU", "OUs")
        ))
        .affected(list, "OUs")
        .raw(inventory.into_iter().collect::<Vec<_>>().join("\n"))
        .evidence("Read from", read_from(m, "OU DACLs and LAPS schemaIDGUIDs"))
        .done()
}

/// Takeover rights only: create-child is how DNS records and PKI objects
/// are normally added, and is covered by other checks.
fn takeover(writers: Vec<(String, Vec<&'static str>)>) -> Vec<(String, Vec<&'static str>)> {
    writers
        .into_iter()
        .filter_map(|(n, r)| {
            let r: Vec<&str> = r
                .into_iter()
                .filter(|x| *x != "create child objects")
                .collect();
            (!r.is_empty()).then_some((n, r))
        })
        .collect()
}

fn acl_020(m: &Model) -> CheckResult {
    let expected_holder = |n: &str| {
        let l = n.to_ascii_lowercase();
        l == "dnsadmins" || l == "dnsupdateproxy"
    };
    let mut zones = 0;
    let list: Vec<Affected> = m
        .raw
        .dnszones
        .iter()
        .filter_map(|z| {
            zones += 1;
            let sd = decode_sd(z)?;
            let w: Vec<_> = takeover(non_default_writers(m, &sd))
                .into_iter()
                .filter(|(n, _)| !expected_holder(n))
                .collect();
            (!w.is_empty()).then(|| {
                obj_item(
                    z,
                    "dnsZone",
                    format!("Can take over the zone: {}", describe(&w)),
                )
            })
        })
        .collect();
    check("AD-ACL-020")
        .expected("Only DnsAdmins and the built-in admin groups control AD-integrated DNS zones")
        .found(format!(
            "{} of {} have extra controllers",
            list.len(),
            plural(zones, "zone", "zones")
        ))
        .affected(list, "zones")
        .evidence(
            "Read from",
            read_from(m, "nTSecurityDescriptor of dnsZone objects"),
        )
        .done()
}

fn acl_021(m: &Model) -> CheckResult {
    let is_container = |o: &LdapObject| {
        o.strs("objectclass").iter().any(|c| {
            c.eq_ignore_ascii_case("container") || c.eq_ignore_ascii_case("certificationAuthority")
        })
    };
    let cert_publishers = format!("{}-517", m.domain_sid);
    let containers: Vec<&LdapObject> = m.raw.pki.iter().filter(|o| is_container(o)).collect();
    let list: Vec<Affected> = containers
        .iter()
        .filter_map(|o| {
            let sd = decode_sd(o)?;
            let cp = who(m, &cert_publishers);
            let w: Vec<_> = takeover(non_default_writers(m, &sd))
                .into_iter()
                .filter(|(n, _)| *n != cp)
                .collect();
            (!w.is_empty()).then(|| {
                obj_item(
                    o,
                    "container",
                    format!("Can change AD CS configuration: {}", describe(&w)),
                )
            })
        })
        .collect();
    check("AD-ACL-021")
        .expected("Only Enterprise Admins and the built-in admin groups control the PKI containers (ESC5)")
        .found(format!(
            "{} of {} have extra controllers",
            list.len(),
            plural(containers.len(), "PKI container", "PKI containers")
        ))
        .affected(list, "containers")
        .evidence("Read from", read_from(m, "nTSecurityDescriptor of CN=Public Key Services containers"))
        .done()
}

fn acl_023(m: &Model) -> CheckResult {
    let holders: BTreeSet<usize> = (0..m.nodes.len())
        .filter(|&i| {
            m.nodes[i].tier0 && matches!(m.nodes[i].kind, Kind::User | Kind::Group | Kind::Computer)
        })
        .filter_map(|i| m.nodes[i].parent)
        .filter(|&p| m.nodes[p].kind == Kind::Ou)
        .collect();
    let mut list = Vec::new();
    for ou in holders {
        let Some(sd) = m.sds.get(&ou) else { continue };
        let who_can: BTreeSet<String> = sd
            .dacl
            .iter()
            .filter(|a| a.kind == AceType::Allow && !a.inherit_only() && outsider(m, &a.sid))
            .filter(|a| {
                a.mask & (right::CREATE_CHILD | right::GENERIC_ALL) != 0
                    && a.object_type
                        .as_deref()
                        .is_none_or(|c| matches!(c, CLASS_USER | CLASS_GROUP | CLASS_COMPUTER))
            })
            .map(|a| who(m, &a.sid))
            .collect();
        if !who_can.is_empty() {
            list.push(item(
                m,
                ou,
                format!(
                    "Holds Tier 0 objects; {} can create users, groups or computers here",
                    who_can.into_iter().collect::<Vec<_>>().join(", ")
                ),
            ));
        }
    }
    check("AD-ACL-023")
        .expected("Nobody outside Tier 0 can create objects in OUs that hold Tier 0 objects")
        .found(plural(list.len(), "OU", "OUs") + " with create rights for non-Tier 0 principals")
        .affected(list, "OUs")
        .evidence(
            "Read from",
            read_from(m, "DACLs of OUs holding Tier 0 objects"),
        )
        .done()
}

fn priv_023(m: &Model) -> CheckResult {
    // Read and limited rights Windows grants on AdminSDHolder by default.
    let default_extra = |sid: &str| {
        matches!(
            sid,
            "S-1-1-0"
                | "S-1-5-11"
                | "S-1-5-10"
                | "S-1-5-32-554"
                | "S-1-5-32-560"
                | "S-1-5-32-561"
                | "S-1-5-32-553"
        ) || sid == format!("{}-517", m.domain_sid)
    };
    let holder = (0..m.nodes.len()).find(|&i| {
        m.nodes[i].kind == Kind::Container && m.nodes[i].name.eq_ignore_ascii_case("AdminSDHolder")
    });
    let out = check("AD-PRIV-023").expected("AdminSDHolder has only its default permissions");
    let Some(sd) = holder.and_then(|h| m.sds.get(&h)) else {
        return out
            .not_assessed("The permissions of AdminSDHolder were not returned.")
            .done();
    };
    let h = holder.unwrap_or_default();
    let list: Vec<Affected> = sd
        .dacl
        .iter()
        .filter(|a| a.kind == AceType::Allow && !m.is_default_admin(&a.sid) && !default_extra(&a.sid))
        .map(|a| {
            item(
                m,
                h,
                format!(
                    "{} has rights {:#x}{}: copied to every protected account and group within an hour",
                    who(m, &a.sid),
                    a.mask,
                    a.object_type
                        .as_deref()
                        .map(|o| format!(" on {o}"))
                        .unwrap_or_default()
                ),
            )
        })
        .collect();
    out.found(plural(
        list.len(),
        "non-default entry",
        "non-default entries",
    ))
    .affected(list, "entries")
    .evidence(
        "Read from",
        read_from(m, "nTSecurityDescriptor of CN=AdminSDHolder"),
    )
    .done()
}

// ---------- Applications and service accounts ----------

fn app_004(m: &Model) -> CheckResult {
    let list: Vec<Affected> = m
        .privileged_users()
        .into_iter()
        .filter(|(u, _)| {
            m.nodes[*u].enabled()
                && m.nodes[*u]
                    .spns()
                    .iter()
                    .any(|s| s.to_ascii_lowercase().starts_with("mssqlsvc/"))
        })
        .map(|(u, groups)| {
            item(
                m,
                u,
                format!(
                    "Runs SQL Server and is in {}",
                    groups
                        .iter()
                        .map(|&g| m.nodes[g].name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            )
        })
        .collect();
    check("AD-APP-004")
        .expected("No SQL Server service account is a member of a privileged group")
        .found(
            plural(
                list.len(),
                "SQL service account is",
                "SQL service accounts are",
            ) + " privileged",
        )
        .affected(list, "accounts")
        .evidence(
            "Read from",
            read_from(m, "MSSQLSvc SPNs and group membership"),
        )
        .done()
}

const IDENTITY_TOOLS: [&str; 18] = [
    "varonis",
    "sailpoint",
    "quest",
    "oneidentity",
    "one identity",
    "okta",
    "ping",
    "cyberark",
    "netwrix",
    "semperis",
    "specops",
    "manageengine",
    "adaudit",
    "stealthbits",
    "tenable",
    "silverfort",
    "crowdstrike",
    "attivo",
];

fn app_007(m: &Model) -> CheckResult {
    let list: Vec<Affected> = m
        .replication
        .iter()
        .filter(|(_, rights)| {
            rights.contains(&"AllExtendedRights")
                || (rights.contains(&"GetChanges")
                    && (rights.contains(&"GetChangesAll")
                        || rights.contains(&"GetChangesInFilteredSet")))
        })
        .filter(|(&p, _)| has_word(&label(m, p), &IDENTITY_TOOLS))
        .map(|(&p, rights)| {
            item(
                m,
                p,
                format!(
                    "Identity tool account with {}: can read every password hash in the domain",
                    rights.join(", ")
                ),
            )
        })
        .collect();
    check("AD-APP-007")
        .expected("Third-party identity tools do not hold DCSync rights, or hold them on a documented, protected account")
        .found(plural(list.len(), "identity tool account has", "identity tool accounts have") + " DCSync rights")
        .affected(list, "accounts")
        .evidence("Read from", read_from(m, "replication rights on the domain head"))
        .done()
}

// ---------- Audit, backup and recovery ----------

fn aud_007(m: &Model) -> CheckResult {
    let decoys: Vec<String> = (0..m.nodes.len())
        .filter(|&i| m.nodes[i].kind == Kind::User && m.nodes[i].enabled())
        .filter(|&i| has_word(&label(m, i), &["honey", "decoy", "canary", "bait"]))
        .map(|i| m.nodes[i].name.clone())
        .collect();
    check("AD-AUD-007")
        .failed(decoys.is_empty())
        .expected("Decoy (honeytoken) accounts exist and their use raises an alert")
        .found(if decoys.is_empty() {
            "No account is named or described as a decoy".to_string()
        } else {
            plural(decoys.len(), "decoy account", "decoy accounts")
        })
        .raw(decoys.join("\n"))
        .evidence("Read from", read_from(m, "user names and descriptions"))
        .done()
}

fn bkp_003(m: &Model) -> CheckResult {
    let Some(g) = m.by_sid("S-1-5-32-551") else {
        return check("AD-BKP-003")
            .not_assessed("The Backup Operators group was not collected.")
            .done();
    };
    let list: Vec<Affected> = m
        .recursive_members(g)
        .into_iter()
        .filter(|&u| m.nodes[u].kind != Kind::Group)
        .map(|u| {
            item(
                m,
                u,
                "Backup Operators can back up the AD database and registry hives from a DC and extract every password hash",
            )
        })
        .collect();
    check("AD-BKP-003")
        .expected("Backup Operators is empty; backup software uses a dedicated, protected account")
        .found(plural(list.len(), "member", "members"))
        .affected(list, "members")
        .evidence("Read from", read_from(m, "Backup Operators membership"))
        .done()
}

fn bkp_006(m: &Model) -> CheckResult {
    let on = super::rules_forest::crossref_container(m)
        .map(|c| c.strs("msds-enabledfeature"))
        .unwrap_or_default()
        .iter()
        .any(|f| f.to_ascii_lowercase().starts_with("cn=recycle bin feature"));
    check("AD-BKP-006")
        .failed(!on)
        .expected("The AD Recycle Bin is enabled, so deleted objects can be restored with their attributes")
        .found(if on { "Enabled" } else { "Not enabled" })
        .evidence("Read from", "msDS-EnabledFeature on CN=Partitions")
        .done()
}

// ---------- Kerberos ----------

fn krb_013(m: &Model) -> CheckResult {
    let mut known: BTreeSet<String> = BTreeSet::new();
    known.insert(m.dns.to_ascii_lowercase());
    for c in crossrefs(m) {
        for a in ["dnsroot", "netbiosname"] {
            if let Some(v) = c.str(a) {
                known.insert(v.to_ascii_lowercase());
            }
        }
    }
    for n in m.nodes.iter().filter(|n| n.kind == Kind::Computer) {
        if let Some(h) = n.attrs.str("dnshostname") {
            known.insert(h.to_ascii_lowercase());
        }
        let short = n.name.trim_end_matches('$').to_ascii_lowercase();
        known.insert(format!("{short}.{}", m.dns.to_ascii_lowercase()));
        known.insert(short);
    }
    let mut list = Vec::new();
    for i in (0..m.nodes.len()).filter(|&i| m.nodes[i].kind == Kind::User) {
        if super::rules::is_krbtgt(m, i) {
            continue;
        }
        let missing: BTreeSet<String> = m.nodes[i]
            .spns()
            .iter()
            .filter_map(|s| {
                let host = s.split('/').nth(1)?;
                let host = host.split(':').next()?.to_ascii_lowercase();
                (!host.is_empty() && !known.contains(&host)).then_some(host)
            })
            .collect();
        if !missing.is_empty() {
            list.push(item(
                m,
                i,
                format!(
                    "SPN for {}, which is not a computer in the domain",
                    missing.into_iter().collect::<Vec<_>>().join(", ")
                ),
            ));
        }
    }
    check("AD-KRB-013")
        .expected("Every SPN on a user account names a computer that exists")
        .found(plural(list.len(), "account has", "accounts have") + " SPNs for unknown hosts")
        .affected(list, "accounts")
        .evidence(
            "Read from",
            read_from(m, "servicePrincipalName and computer host names"),
        )
        .done()
}

fn krb_018(m: &Model) -> CheckResult {
    let list: Vec<Affected> = (0..m.nodes.len())
        .filter(|&i| {
            let n = &m.nodes[i];
            n.kind == Kind::Computer
                && n.enabled()
                && !n.is_dc()
                && n.flag(uac::TRUSTED_TO_AUTH_FOR_DELEGATION)
        })
        .map(|i| {
            item(
                m,
                i,
                "Trusted to authenticate for delegation: whoever controls this computer can get a ticket as any user (S4U2Self) to its delegated services",
            )
        })
        .collect();
    check("AD-KRB-018")
        .expected("No computer other than a DC can use protocol transition (S4U2Self to any user)")
        .found(plural(list.len(), "computer", "computers") + " with protocol transition")
        .affected(list, "computers")
        .evidence("Read from", read_from(m, "userAccountControl of computers"))
        .done()
}

// ---------- Privileged access structure ----------

fn ou_005(m: &Model) -> CheckResult {
    let tiers: Vec<String> = (0..m.nodes.len())
        .filter(|&i| m.nodes[i].kind == Kind::Ou)
        .filter(|&i| {
            let l = m.nodes[i]
                .name
                .to_ascii_lowercase()
                .replace([' ', '-', '_'], "");
            l.starts_with("tier") || matches!(l.as_str(), "t0" | "t1" | "t2") || l.contains("admin")
        })
        .map(|i| m.nodes[i].dn.clone())
        .collect();
    check("AD-OU-005")
        .failed(tiers.is_empty())
        .expected("A tiered administration structure: separate OUs for Tier 0, Tier 1 and Tier 2 admin accounts and assets")
        .found(if tiers.is_empty() {
            "No tier or admin OUs found".to_string()
        } else {
            plural(tiers.len(), "tier or admin OU", "tier or admin OUs")
        })
        .raw(tiers.join("\n"))
        .evidence("Read from", read_from(m, "OU names"))
        .done()
}

fn ou_006(m: &Model) -> CheckResult {
    let list: Vec<Affected> = m
        .privileged_users()
        .into_keys()
        .filter(|&u| m.nodes[u].enabled() && !super::rules::is_krbtgt(m, u))
        .filter(|&u| {
            let a = &m.nodes[u].attrs;
            a.str("userworkstations").is_none_or(str::is_empty)
                && !a.has("msds-assignedauthnpolicysilo")
                && !a.has("msds-assignedauthnpolicy")
        })
        .map(|u| {
            item(
                m,
                u,
                "Not restricted to privileged access workstations (no workstation list and no authentication policy or silo)",
            )
        })
        .collect();
    check("AD-OU-006")
        .expected("Privileged accounts can sign in only from privileged access workstations")
        .found(
            plural(
                list.len(),
                "privileged account is",
                "privileged accounts are",
            ) + " not restricted",
        )
        .affected(list, "accounts")
        .evidence(
            "Read from",
            read_from(m, "userWorkstations and authentication policy assignments"),
        )
        .done()
}

fn priv_010(m: &Model) -> CheckResult {
    let roots = m.admin_groups();
    let mut deepest: BTreeMap<usize, (usize, usize)> = BTreeMap::new();
    for &root in &roots {
        let mut seen = BTreeSet::from([root]);
        let mut queue = VecDeque::from([(root, 0usize)]);
        while let Some((g, d)) = queue.pop_front() {
            for &c in &m.members[g] {
                // Built-in nesting (Domain Admins in Administrators) starts
                // its own count.
                if m.nodes[c].kind == Kind::Group && !roots.contains(&c) && seen.insert(c) {
                    let e = deepest.entry(c).or_insert((0, root));
                    if d + 1 > e.0 {
                        *e = (d + 1, root);
                    }
                    queue.push_back((c, d + 1));
                }
            }
        }
    }
    let list: Vec<Affected> = deepest
        .into_iter()
        .filter(|(_, (d, _))| *d >= DEEP_NESTING)
        .map(|(g, (d, root))| {
            item(
                m,
                g,
                format!(
                    "Nested {d} levels deep into {}: its members are privileged without appearing in the group",
                    m.nodes[root].name
                ),
            )
        })
        .collect();
    check("AD-PRIV-010")
        .expected(format!(
            "Groups are nested less than {DEEP_NESTING} levels deep into privileged groups"
        ))
        .found(plural(
            list.len(),
            "deeply nested group",
            "deeply nested groups",
        ))
        .affected(list, "groups")
        .evidence("Read from", read_from(m, "group membership"))
        .done()
}

fn priv_018(m: &Model) -> CheckResult {
    let list: Vec<Affected> = m
        .privileged_users()
        .into_keys()
        .filter(|&u| m.nodes[u].enabled())
        .filter_map(|u| {
            let a = &m.nodes[u].attrs;
            let mail = a.str("mail").map(str::to_string).or_else(|| {
                a.strs("proxyaddresses")
                    .iter()
                    .find(|p| p.to_ascii_lowercase().starts_with("smtp:"))
                    .map(|p| p[5..].to_string())
            });
            let mailbox = a.has("msexchmailboxguid");
            (mail.is_some() || mailbox).then(|| {
                item(
                    m,
                    u,
                    match mail {
                        Some(addr) => {
                            format!("Has email ({addr}): phishing reaches a privileged account")
                        }
                        None => {
                            "Has an Exchange mailbox: phishing reaches a privileged account".into()
                        }
                    },
                )
            })
        })
        .collect();
    check("AD-PRIV-018")
        .expected("Privileged accounts have no mailbox or email address")
        .found(
            plural(
                list.len(),
                "privileged account has",
                "privileged accounts have",
            ) + " email",
        )
        .affected(list, "accounts")
        .evidence(
            "Read from",
            read_from(m, "mail, proxyAddresses and msExchMailboxGuid"),
        )
        .done()
}

fn priv_028(m: &Model) -> CheckResult {
    let mut lines = Vec::new();
    for i in dcs(m) {
        let n = &m.nodes[i];
        lines.push(format!(
            "Domain controller: {}",
            n.attrs.str("dnshostname").unwrap_or(&n.name)
        ));
    }
    for o in &m.raw.pki {
        if o.strs("objectclass")
            .iter()
            .any(|c| c.eq_ignore_ascii_case("pKIEnrollmentService"))
        {
            lines.push(format!(
                "Certification authority: {}",
                o.str("dnshostname").unwrap_or_default()
            ));
        }
    }
    for i in (0..m.nodes.len()).filter(|&i| m.nodes[i].kind == Kind::User) {
        let n = &m.nodes[i];
        let lower = n.name.to_ascii_lowercase();
        if lower.starts_with("msol_") || lower.starts_with("sync_") {
            lines.push(format!(
                "Entra Connect server (from {}): {}",
                n.name,
                n.attrs.str("description").unwrap_or_default()
            ));
        }
        if n.spns()
            .iter()
            .any(|s| s.to_ascii_lowercase().contains("adfs"))
        {
            lines.push(format!("AD FS service account: {}", n.name));
        }
    }
    check("AD-PRIV-028")
        .expected("An inventory of Tier 0 assets: DCs, certification authorities, Entra Connect and AD FS servers")
        .found(plural(lines.len(), "Tier 0 asset", "Tier 0 assets"))
        .raw(lines.join("\n"))
        .evidence("Read from", read_from(m, "computers, AD CS enrollment services and service accounts"))
        .done()
}

fn priv_030(m: &Model) -> CheckResult {
    let found: Vec<String> = m
        .privileged_users()
        .into_keys()
        .filter(|&u| m.nodes[u].enabled())
        .filter(|&u| {
            has_word(
                &label(m, u).replace([' ', '-', '_'], ""),
                &["breakglass", "emergency"],
            )
        })
        .map(|u| m.nodes[u].name.clone())
        .collect();
    check("AD-PRIV-030")
        .failed(found.is_empty())
        .expected("A documented break-glass account exists, is privileged and its use is monitored")
        .found(if found.is_empty() {
            "No privileged account is named or described as break-glass or emergency".to_string()
        } else {
            plural(found.len(), "break-glass account", "break-glass accounts")
        })
        .raw(found.join("\n"))
        .evidence(
            "Read from",
            read_from(m, "privileged account names and descriptions"),
        )
        .done()
}

fn dc_032(m: &Model) -> CheckResult {
    let rodcs: Vec<usize> = (0..m.nodes.len())
        .filter(|&i| {
            m.nodes[i].kind == Kind::Computer && m.nodes[i].flag(uac::PARTIAL_SECRETS_ACCOUNT)
        })
        .collect();
    let by_dn = |dn: &str| m.by_dn.get(&dn.to_ascii_lowercase()).copied();
    let mut list = Vec::new();
    for &r in &rodcs {
        let a = &m.nodes[r].attrs;
        let mut why = Vec::new();
        for dn in a.strs("msds-revealondemandgroup") {
            if let Some(i) = by_dn(dn) {
                let n = &m.nodes[i];
                let wide = broad(m, n.sid.as_deref().unwrap_or_default())
                    || n.tier0
                    || (n.kind == Kind::Group
                        && m.recursive_members(i).iter().any(|&x| m.nodes[x].tier0));
                if wide {
                    why.push(format!("allowed to cache {}", n.name));
                }
            }
        }
        for v in a.strs("msds-revealedusers") {
            let dn = v.rsplit_once(':').map(|(_, d)| d).unwrap_or(v);
            if let Some(i) = by_dn(dn).filter(|&i| m.nodes[i].tier0) {
                why.push(format!("has cached the password of {}", m.nodes[i].name));
            }
        }
        if !why.is_empty() {
            list.push(item(m, r, why.join("; ")));
        }
    }
    check("AD-DC-032")
        .expected("Read-only DCs cannot cache, and have not cached, Tier 0 passwords")
        .found(if rodcs.is_empty() {
            "No read-only domain controllers".to_string()
        } else {
            format!(
                "{} of {} allow or hold Tier 0 passwords",
                list.len(),
                plural(rodcs.len(), "RODC", "RODCs")
            )
        })
        .affected(list, "RODCs")
        .evidence(
            "Read from",
            read_from(m, "msDS-RevealOnDemandGroup and msDS-RevealedUsers"),
        )
        .done()
}

// ---------- Replication metadata ----------

/// (attribute, value DN, created, deleted, last change) from msDS-Repl*MetaData XML.
type MetaEntry = (String, String, Option<i64>, Option<i64>, Option<i64>);

fn meta_entries(o: &LdapObject, attr: &str) -> Vec<MetaEntry> {
    o.strs(attr)
        .iter()
        .filter_map(|x| {
            let name = between(x, "<pszAttributeName>", "</pszAttributeName>")?.to_string();
            let value = between(x, "<pszObjectDn>", "</pszObjectDn>")
                .unwrap_or_default()
                .to_string();
            let t = |tag: &str| {
                between(x, &format!("<{tag}>"), &format!("</{tag}>"))
                    .and_then(time::parse_iso)
                    .filter(|&t| t > 0)
            };
            Some((
                name,
                value,
                t("ftimeCreated"),
                t("ftimeDeleted"),
                t("ftimeLastOriginatingChange"),
            ))
        })
        .collect()
}

fn recent(m: &Model, t: Option<i64>) -> bool {
    t.is_some_and(|t| m.now - t <= RECENT_DAYS * time::DAY && t <= m.now + time::DAY)
}

fn no_metadata(m: &Model, area: &str, attr: &str) -> bool {
    !m.raw.objects(area).iter().any(|o| o.has(attr))
}

fn priv_027(m: &Model) -> CheckResult {
    let out = check("AD-PRIV-027").expected(format!(
        "Privileged group membership changes in the last {RECENT_DAYS} days are all known"
    ));
    let groups = m.raw.objects("privmeta");
    if no_metadata(m, "privmeta", "msds-replvaluemetadata") {
        return out
            .not_assessed("The server did not return msDS-ReplValueMetaData for privileged groups.")
            .done();
    }
    let mut list = Vec::new();
    for g in groups {
        let gname = super::model::rdn_value(g.dn());
        for (attr, value, created, deleted, changed) in meta_entries(g, "msds-replvaluemetadata") {
            if !attr.eq_ignore_ascii_case("member") {
                continue;
            }
            let member = super::model::rdn_value(&value);
            let what = if recent(m, deleted) {
                Some(format!("{member} removed from {gname}"))
            } else if recent(m, created) || (deleted.is_none() && recent(m, changed)) {
                Some(format!("{member} added to {gname}"))
            } else {
                None
            };
            if let Some(w) = what {
                let when = deleted
                    .or(created)
                    .or(changed)
                    .map(time::iso)
                    .unwrap_or_default();
                list.push(obj_item(g, "group", format!("{w} on {when}")));
            }
        }
    }
    out.found(plural(
        list.len(),
        "membership change",
        "membership changes",
    ))
    .affected(list, "changes")
    .evidence(
        "Read from",
        read_from(m, "msDS-ReplValueMetaData of protected groups"),
    )
    .done()
}

fn ioc_003(m: &Model) -> CheckResult {
    let out = check("AD-IOC-003")
        .expected(format!("No unexplained SPN or key credential changes on user accounts in the last {RECENT_DAYS} days"));
    if no_metadata(m, "attrmeta", "msds-replattributemetadata") {
        return out
            .not_assessed("The server did not return msDS-ReplAttributeMetaData for accounts with SPNs or key credentials.")
            .done();
    }
    let mut list = Vec::new();
    for o in m.raw.objects("attrmeta") {
        let created = o.str("whencreated").and_then(time::parse_iso);
        for (attr, _, _, _, changed) in meta_entries(o, "msds-replattributemetadata") {
            let l = attr.to_ascii_lowercase();
            if l != "serviceprincipalname" && l != "msds-keycredentiallink" {
                continue;
            }
            let after_creation =
                matches!((changed, created), (Some(c), Some(w)) if c - w > time::DAY);
            if recent(m, changed) && after_creation {
                list.push(obj_item(
                    o,
                    "user",
                    format!(
                        "{attr} changed on {}: check it was not a Kerberoasting or shadow credentials setup",
                        changed.map(time::iso).unwrap_or_default()
                    ),
                ));
            }
        }
    }
    out.found(plural(list.len(), "recent change", "recent changes"))
        .affected(list, "accounts")
        .evidence("Read from", read_from(m, "msDS-ReplAttributeMetaData"))
        .done()
}

fn ioc_012(m: &Model) -> CheckResult {
    let out =
        check("AD-IOC-012").expected("No DCSync rights were granted outside the defaults recently");
    let Some(d) = m
        .raw
        .domain
        .first()
        .filter(|d| d.has("msds-replattributemetadata"))
    else {
        return out
            .not_assessed("The domain head did not return msDS-ReplAttributeMetaData.")
            .done();
    };
    let changed = meta_entries(d, "msds-replattributemetadata")
        .into_iter()
        .find(|e| e.0.eq_ignore_ascii_case("nTSecurityDescriptor"))
        .and_then(|e| e.4);
    let holders: Vec<usize> = m
        .replication
        .iter()
        .filter(|(_, r)| {
            r.contains(&"GetChanges")
                && (r.contains(&"GetChangesAll") || r.contains(&"GetChangesInFilteredSet"))
        })
        .map(|(&p, _)| p)
        .collect();
    let list: Vec<Affected> = if recent(m, changed) {
        holders
            .iter()
            .map(|&p| {
                item(
                    m,
                    p,
                    format!(
                        "Holds DCSync rights; the domain head's permissions changed on {}",
                        changed.map(time::iso).unwrap_or_default()
                    ),
                )
            })
            .collect()
    } else {
        Vec::new()
    };
    out.found(match changed {
        Some(t) => format!(
            "Domain head permissions last changed {}; {}",
            time::iso(t),
            plural(
                holders.len(),
                "non-default DCSync holder",
                "non-default DCSync holders"
            )
        ),
        None => "No change time recorded for the domain head's permissions".into(),
    })
    .affected(list, "principals")
    .evidence(
        "Read from",
        read_from(m, "msDS-ReplAttributeMetaData of the domain head"),
    )
    .done()
}

const LDAP: &[&str] = &["domain", "users", "computers", "groups"];
const ACLS: &[&str] = &[
    "domain",
    "users",
    "computers",
    "groups",
    "containers",
    "acls",
];

/// Changes recorded in replication metadata: (object, attribute, when,
/// originating DSA).
fn meta_changes(m: &Model) -> Vec<(String, String, i64, String)> {
    let mut out = Vec::new();
    for (area, attr) in [
        ("attrmeta", "msds-replattributemetadata"),
        ("privmeta", "msds-replvaluemetadata"),
    ] {
        for o in m.raw.objects(area) {
            for x in o.strs(attr) {
                let (Some(name), Some(when), Some(dsa)) = (
                    between(x, "<pszAttributeName>", "</pszAttributeName>"),
                    between(
                        x,
                        "<ftimeLastOriginatingChange>",
                        "</ftimeLastOriginatingChange>",
                    )
                    .and_then(time::parse_iso),
                    between(x, "<pszLastOriginatingDsaDN>", "</pszLastOriginatingDsaDN>"),
                ) else {
                    continue;
                };
                out.push((
                    super::model::rdn_value(o.dn()),
                    name.to_string(),
                    when,
                    dsa.to_string(),
                ));
            }
        }
    }
    out
}

fn hunt_023(m: &Model) -> CheckResult {
    let out = check("HUNT-AD-023")
        .expected("Recent changes to sensitive objects originate on current domain controllers, in working hours");
    if no_metadata(m, "attrmeta", "msds-replattributemetadata")
        && no_metadata(m, "privmeta", "msds-replvaluemetadata")
    {
        return out
            .not_assessed("The server did not return replication metadata.")
            .done();
    }
    let dcs: BTreeSet<String> = m
        .nodes
        .iter()
        .filter(|n| n.kind == Kind::Computer && n.is_dc())
        .map(|n| n.name.trim_end_matches('$').to_lowercase())
        .collect();
    let mut list = Vec::new();
    for (object, attr, when, dsa) in meta_changes(m).into_iter().filter(|c| recent(m, Some(c.2))) {
        // CN=NTDS Settings,CN=<server>,CN=Servers,...
        let server = dsa
            .split(',')
            .nth(1)
            .map(|p| p.trim_start_matches("CN=").to_lowercase())
            .unwrap_or_default();
        let at = time::iso(when);
        let hour: u32 = at.get(11..13).and_then(|h| h.parse().ok()).unwrap_or(12);
        let reason = if dsa.contains("\0ADEL:") || dsa.contains("\0aDEL:") || !dcs.contains(&server)
        {
            format!("{attr} changed on {at} from {server}, which is not a current domain controller (a removed DC, or a rogue one as in DCShadow)")
        } else if hour < 5 {
            format!("{attr} changed at {at} (UTC) on {server}, outside working hours")
        } else {
            continue;
        };
        list.push(Affected {
            last_seen: Some(at.clone()),
            name: object,
            kind: "object".into(),
            location: None,
            reason: Some(reason),
            object: None,
        });
    }
    out.found(
        plural(list.len(), "unexpected change", "unexpected changes")
            + format!(" in the last {RECENT_DAYS} days").as_str(),
    )
    .affected(list, "changes")
    .evidence(
        "Read from",
        format!("Replication metadata via LDAP on {}", m.raw.info.server),
    )
    .done()
}

pub static RULES: &[Rule] = &[
    Rule {
        id: "HUNT-AD-023",
        needs: &["attrmeta", "privmeta", "computers"],
        run: hunt_023,
    },
    Rule {
        id: "AD-ACL-012",
        needs: ACLS,
        run: acl_012,
    },
    Rule {
        id: "AD-ACL-013",
        needs: &[
            "domain",
            "users",
            "computers",
            "groups",
            "containers",
            "acls",
            "schema",
        ],
        run: acl_013,
    },
    Rule {
        id: "AD-ACL-020",
        needs: &["domain", "groups", "dnszones"],
        run: acl_020,
    },
    Rule {
        id: "AD-ACL-021",
        needs: &["domain", "groups", "pki"],
        run: acl_021,
    },
    Rule {
        id: "AD-ACL-023",
        needs: ACLS,
        run: acl_023,
    },
    Rule {
        id: "AD-PRIV-023",
        needs: ACLS,
        run: priv_023,
    },
    Rule {
        id: "AD-APP-004",
        needs: LDAP,
        run: app_004,
    },
    Rule {
        id: "AD-APP-007",
        needs: ACLS,
        run: app_007,
    },
    Rule {
        id: "AD-AUD-007",
        needs: &["users"],
        run: aud_007,
    },
    Rule {
        id: "AD-BKP-003",
        needs: LDAP,
        run: bkp_003,
    },
    Rule {
        id: "AD-BKP-006",
        needs: &["partitions"],
        run: bkp_006,
    },
    Rule {
        id: "AD-KRB-013",
        needs: &["domain", "users", "computers", "partitions"],
        run: krb_013,
    },
    Rule {
        id: "AD-KRB-018",
        needs: &["computers"],
        run: krb_018,
    },
    Rule {
        id: "AD-OU-005",
        needs: &["containers"],
        run: ou_005,
    },
    Rule {
        id: "AD-OU-006",
        needs: LDAP,
        run: ou_006,
    },
    Rule {
        id: "AD-PRIV-010",
        needs: LDAP,
        run: priv_010,
    },
    Rule {
        id: "AD-PRIV-018",
        needs: LDAP,
        run: priv_018,
    },
    Rule {
        id: "AD-PRIV-028",
        needs: &["domain", "users", "computers", "pki"],
        run: priv_028,
    },
    Rule {
        id: "AD-PRIV-030",
        needs: LDAP,
        run: priv_030,
    },
    Rule {
        id: "AD-DC-032",
        needs: LDAP,
        run: dc_032,
    },
    Rule {
        id: "AD-PRIV-027",
        needs: &["privmeta"],
        run: priv_027,
    },
    Rule {
        id: "AD-IOC-003",
        needs: &["attrmeta"],
        run: ioc_003,
    },
    Rule {
        id: "AD-IOC-012",
        needs: ACLS,
        run: ioc_012,
    },
];
