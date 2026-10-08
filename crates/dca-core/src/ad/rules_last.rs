//! Computer owners, delegated admin groups, audit entries on sensitive
//! objects, orphaned service connection points, Configuration Manager in
//! AD, and management ports open on Tier 0 servers.

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine;
use serde_json::Value;

use super::model::{rdn_value, Kind, Model};
use super::paths::CONTROL;
use super::raw::LdapObject;
use super::rules::{check, item, plural, Rule};
use super::rules_forest::{decode_sd, describe, non_default_writers, obj_item, who};
use super::sd;
use crate::results::{Affected, CheckResult};

fn read_from(m: &Model, what: &str) -> String {
    format!(
        "{what} via LDAP on {} as {}",
        m.raw.info.server, m.raw.info.account
    )
}

/// The computer node for a host name or FQDN.
fn computer(m: &Model, host: &str) -> Option<usize> {
    let short = host.split('.').next().unwrap_or(host).to_lowercase();
    (0..m.nodes.len()).find(|&i| {
        m.nodes[i].kind == Kind::Computer
            && m.nodes[i]
                .name
                .trim_end_matches('$')
                .eq_ignore_ascii_case(&short)
    })
}

// ---------- Computers ----------

fn cmp_010(m: &Model) -> CheckResult {
    let objs = m.raw.objects("computerowners");
    let mut list = Vec::new();
    for o in objs {
        let Some(owner) = decode_sd(o).and_then(|s| s.owner) else {
            continue;
        };
        if m.is_default_admin(&owner) {
            continue;
        }
        let name = o
            .str("samaccountname")
            .map(str::to_string)
            .unwrap_or_else(|| rdn_value(o.dn()));
        let tier0 = m
            .by_dn
            .get(&o.dn().to_lowercase())
            .is_some_and(|&i| m.nodes[i].tier0);
        let reason = format!(
            "Owned by {}, who can grant themselves full control of it (resource-based delegation, LAPS password){}",
            who(m, &owner),
            if tier0 { "; this is a Tier 0 computer" } else { "" }
        );
        let mut a = obj_item(o, "computer", reason);
        a.name = name;
        list.push(a);
    }
    check("AD-CMP-010")
        .expected("Computer objects are owned by Domain Admins (or another built-in admin group)")
        .found(format!(
            "{} of {} with a non-standard owner",
            list.len(),
            plural(objs.len(), "computer", "computers")
        ))
        .affected(list, "computers")
        .evidence(
            "Read from",
            read_from(m, "The owner of each computer object"),
        )
        .done()
}

// ---------- OUs ----------

/// The first OU under the domain root that contains `dn`, lower case.
fn top_ou(dn: &str) -> Option<String> {
    let parts: Vec<&str> = dn.split(',').collect();
    let ous: Vec<usize> = (0..parts.len())
        .filter(|&i| parts[i].trim().to_lowercase().starts_with("ou="))
        .collect();
    ous.last().map(|&i| parts[i].trim().to_lowercase())
}

fn ou_008(m: &Model) -> CheckResult {
    let mut delegated: BTreeMap<usize, BTreeSet<String>> = BTreeMap::new();
    for e in &m.edges {
        if m.nodes[e.to].kind == Kind::Ou
            && m.nodes[e.from].kind == Kind::Group
            && CONTROL.contains(&e.kind)
            && !matches!(e.kind, "Contains" | "GPLink")
            && !m.nodes[e.from]
                .sid
                .as_deref()
                .is_some_and(|s| m.is_default_admin(s))
        {
            delegated
                .entry(e.from)
                .or_default()
                .insert(m.nodes[e.to].name.clone());
        }
    }
    let mut list = Vec::new();
    for (g, ous) in &delegated {
        let home = top_ou(&m.nodes[*g].dn);
        for &u in &m.members[*g] {
            let n = &m.nodes[u];
            if n.kind != Kind::User || !n.enabled() {
                continue;
            }
            if top_ou(&n.dn) != home {
                list.push(item(
                    m,
                    u,
                    format!(
                        "Member of {}, which administers {}, but the account lives outside {}",
                        m.nodes[*g].name,
                        ous.iter().cloned().collect::<Vec<_>>().join(", "),
                        home.clone().unwrap_or_else(|| "an OU".into())
                    ),
                ));
            }
        }
    }
    check("AD-OU-008")
        .expected("Members of delegated admin groups are admin accounts kept in the same OU structure as the group")
        .found(format!("{}; {} members outside", plural(delegated.len(), "delegated group", "delegated groups"), list.len()))
        .affected(list, "accounts")
        .evidence("Read from", read_from(m, "OU permissions and group membership"))
        .done()
}

// ---------- Auditing ----------

const WRITES: u32 = sd::right::WRITE_PROP
    | sd::right::GENERIC_WRITE
    | sd::right::GENERIC_ALL
    | sd::right::WRITE_DACL
    | sd::right::WRITE_OWNER;

fn sacl_of(o: &LdapObject) -> Option<Vec<sd::AuditAce>> {
    let b = base64::engine::general_purpose::STANDARD
        .decode(o.str("ntsecuritydescriptor")?)
        .ok()?;
    sd::parse_sacl(&b)
}

fn aud_003(m: &Model) -> CheckResult {
    let objs = m.raw.objects("sacls");
    let out = check("AD-AUD-003")
        .expected(
            "The domain head, AdminSDHolder and privileged groups audit every change (success)",
        )
        .evidence("Read from", read_from(m, "The SACL of sensitive objects"));
    if !objs.iter().any(|o| o.has("ntsecuritydescriptor")) {
        return out
            .not_assessed("No SACL was returned: reading audit entries needs the \"Manage auditing and security log\" right, which the collecting account does not hold.")
            .done();
    }
    let mut list = Vec::new();
    for o in objs.iter().filter(|o| o.has("ntsecuritydescriptor")) {
        let audited = sacl_of(o)
            .unwrap_or_default()
            .iter()
            .any(|a| a.success && a.mask & WRITES != 0);
        if !audited {
            list.push(obj_item(
                o,
                "object",
                "No audit entry for changes: edits to it raise no 5136 event",
            ));
        }
    }
    out.found(format!(
        "{} of {} without change auditing",
        list.len(),
        plural(objs.len(), "object", "objects")
    ))
    .affected(list, "objects")
    .done()
}

// ---------- Applications ----------

fn app_008(m: &Model) -> CheckResult {
    let scps = m.raw.objects("scps");
    let mut list = Vec::new();
    for s in scps {
        // The computer the SCP lives under, or the host it points to.
        let parent_dn = s
            .dn()
            .split_once(',')
            .map(|x| x.1.to_lowercase())
            .unwrap_or_default();
        let parent = m
            .by_dn
            .get(&parent_dn)
            .copied()
            .filter(|&i| m.nodes[i].kind == Kind::Computer);
        let host = s.str("servicednsname");
        let reason = match (parent, host) {
            (Some(p), _) if !m.nodes[p].enabled() => {
                format!("Published under {}, which is disabled", m.nodes[p].name)
            }
            (None, Some(h)) if !h.is_empty() && computer(m, h).is_none() => {
                format!("Points to {h}, which is no longer a computer in the domain")
            }
            _ => continue,
        };
        list.push(obj_item(
            s,
            "service connection point",
            format!(
                "{} ({})",
                reason,
                s.str("serviceclassname").unwrap_or("unknown service")
            ),
        ));
    }
    check("AD-APP-008")
        .expected("Service connection points belong to servers that still exist")
        .found(format!(
            "{} of {} orphaned",
            list.len(),
            plural(
                scps.len(),
                "service connection point",
                "service connection points"
            )
        ))
        .affected(list, "objects")
        .evidence("Read from", read_from(m, "serviceConnectionPoint objects"))
        .done()
}

const SCCM_WORDS: [&str; 6] = ["sccm", "configmgr", "naa", "cmpush", "clientpush", "mecm"];

fn app_003(m: &Model) -> CheckResult {
    let objs = m.raw.objects("sccm");
    let mut list = Vec::new();
    let container = objs
        .iter()
        .find(|o| rdn_value(o.dn()).eq_ignore_ascii_case("System Management"));
    let sites: Vec<String> = objs
        .iter()
        .filter(|o| {
            o.strs("objectclass")
                .iter()
                .any(|c| c.eq_ignore_ascii_case("mSSMSSite"))
        })
        .map(|o| o.str("mssmssitecode").unwrap_or_default().to_string())
        .collect();
    if let Some(sd) = container.and_then(decode_sd) {
        for (name, rights) in non_default_writers(m, &sd) {
            let is_computer = m
                .nodes
                .iter()
                .any(|n| n.kind == Kind::Computer && n.name == name);
            if !is_computer {
                list.push(Affected {
                    last_seen: None,
                    name: name.clone(),
                    kind: "principal".into(),
                    location: container.map(|c| c.dn().to_string()),
                    reason: Some(format!("Can change System Management ({}): it can publish a rogue management point", describe(&[(name, rights)]))),
                    object: None,
                });
            }
        }
    }
    // Accounts named for Configuration Manager that hold admin rights.
    let admins = m.privileged_users();
    for (i, n) in m
        .nodes
        .iter()
        .enumerate()
        .filter(|(_, n)| n.kind == Kind::User && n.enabled())
    {
        let l = n.name.to_lowercase();
        if SCCM_WORDS.iter().any(|w| l.contains(w)) && admins.contains_key(&i) {
            list.push(item(
                m,
                i,
                "Configuration Manager account with domain admin rights: network access and client push accounts are readable from clients",
            ));
        }
    }
    let out = check("AD-APP-003")
        .expected("Configuration Manager accounts hold no domain admin rights and only site servers can change System Management")
        .evidence("Read from", read_from(m, "the System Management container and account names"));
    if container.is_none() && list.is_empty() {
        return out
            .found("Configuration Manager is not published in this domain")
            .done();
    }
    out.found(format!(
        "{}; {}",
        plural(sites.len(), "site", "sites"),
        plural(list.len(), "finding", "findings")
    ))
    .affected(list, "accounts")
    .done()
}

// ---------- Network exposure ----------

fn any_remote(rule: &Value) -> bool {
    let r: Vec<&str> = rule
        .get("remote")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    r.is_empty() || r.iter().any(|x| x.eq_ignore_ascii_case("Any") || *x == "*")
}

fn t0_009(m: &Model) -> CheckResult {
    let dcs = m
        .raw
        .dcconfig
        .iter()
        .filter_map(|d| Some((d.name.as_str(), d.data.as_ref()?.mgmtrules.as_ref()?)));
    let eps = m.raw.endpoints.iter().filter_map(|e| {
        let rules = e.part("mgmtrules")?.as_array()?;
        computer(m, &e.name)
            .filter(|&i| m.nodes[i].tier0)
            .map(|_| (e.name.as_str(), rules))
    });
    let mut read = 0;
    let mut list = Vec::new();
    for (host, rules) in dcs.chain(eps) {
        read += 1;
        let open: Vec<String> = rules
            .iter()
            .filter(|r| any_remote(r))
            .map(|r| {
                let ports: Vec<&str> = r
                    .get("ports")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                format!(
                    "{} ({})",
                    r.get("name").and_then(Value::as_str).unwrap_or("rule"),
                    ports.join(", ")
                )
            })
            .collect();
        if !open.is_empty() {
            list.push(Affected {
                last_seen: None,
                name: host.to_string(),
                kind: "computer".into(),
                location: None,
                reason: Some(format!(
                    "Management ports open to any address: {}",
                    open.join("; ")
                )),
                object: computer(m, host).map(|i| m.nodes[i].id.clone()),
            });
        }
    }
    let out = check("EP-T0-009")
        .expected("Tier 0 servers accept management traffic (RDP, WinRM, SMB, RPC, SSH) only from admin networks")
        .evidence("Read from", "Windows Firewall inbound rules on domain controllers and Tier 0 servers")
        .evidence("Note", "Only the host firewall is read; network firewalls between VLANs are not visible");
    if read == 0 {
        return out
            .not_assessed("No domain controller or Tier 0 server reported its firewall rules.")
            .done();
    }
    out.found(format!(
        "{} of {} open to any address",
        list.len(),
        plural(read, "Tier 0 server", "Tier 0 servers")
    ))
    .affected(list, "computers")
    .done()
}

pub static RULES: &[Rule] = &[
    Rule {
        id: "AD-CMP-010",
        needs: &["computers", "computerowners"],
        run: cmp_010,
    },
    Rule {
        id: "AD-OU-008",
        needs: &["groups", "containers", "acls"],
        run: ou_008,
    },
    Rule {
        id: "AD-AUD-003",
        needs: &["sacls"],
        run: aud_003,
    },
    Rule {
        id: "AD-APP-008",
        needs: &["computers", "scps"],
        run: app_008,
    },
    Rule {
        id: "AD-APP-003",
        needs: &["users", "groups", "sccm"],
        run: app_003,
    },
    Rule {
        id: "EP-T0-009",
        needs: &["computers"],
        run: t0_009,
    },
];
