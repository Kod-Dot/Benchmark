//! Indicators of compromise that the directory itself records: objects and
//! settings an attacker leaves behind for persistence, read from LDAP and,
//! for LSA packages, from each DC's registry.

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;

use super::model::{rdn_value, uac, well_known_name, Kind, Model};
use super::raw::LdapObject;
use super::rules::{check, days_text, item, plural, Rule};
use super::sd::{self, right, AceType};
use crate::results::{Affected, CheckResult};
use crate::time;

/// How far back "recently" reaches.
const RECENT_DAYS: i64 = 30;

const READ_PROP: u32 = 0x0000_0010;
const LIST_CHILDREN: u32 = 0x0000_0004;
const LIST_OBJECT: u32 = 0x0000_0080;
const READ_CONTROL: u32 = 0x0002_0000;
const GENERIC_READ: u32 = 0x8000_0000;

fn read_from(m: &Model) -> String {
    format!("LDAP on {} as {}", m.raw.info.server, m.raw.info.account)
}

fn decode_sd(o: &LdapObject, attr: &str) -> Option<sd::SecurityDescriptor> {
    let b = base64::engine::general_purpose::STANDARD
        .decode(o.str(attr)?)
        .ok()?;
    sd::parse(&b)
}

fn who(m: &Model, sid: &str) -> String {
    m.by_sid(sid)
        .map(|i| m.nodes[i].name.clone())
        .or_else(|| well_known_name(sid).map(str::to_string))
        .unwrap_or_else(|| sid.to_string())
}

fn privileged(m: &Model, sid: &str) -> bool {
    m.is_default_admin(sid) || m.by_sid(sid).is_some_and(|i| m.nodes[i].tier0)
}

fn days_ago(m: &Model, t: i64) -> i64 {
    (m.now - t).div_euclid(time::DAY)
}

// ---------- Persistence in the directory ----------

fn ioc_001(m: &Model) -> CheckResult {
    let out = check("AD-IOC-001").expected(format!(
        "AdminSDHolder unchanged in the last {RECENT_DAYS} days"
    ));
    let Some(o) = m.raw.acls.iter().find(|o| {
        o.dn()
            .to_ascii_lowercase()
            .starts_with("cn=adminsdholder,cn=system,")
    }) else {
        return out
            .not_assessed("The AdminSDHolder object was not returned.")
            .done();
    };
    let Some(t) = o.str("whenchanged").and_then(time::parse_iso) else {
        return out
            .not_assessed(
                "whenChanged was not collected for AdminSDHolder; collect again with this version.",
            )
            .done();
    };
    let d = days_ago(m, t);
    let list = if d <= RECENT_DAYS {
        let node = m.by_dn.get(&o.dn().to_ascii_lowercase()).copied();
        vec![Affected {
            last_seen: None,
            name: "AdminSDHolder".into(),
            kind: "container".into(),
            location: Some(o.dn().to_string()),
            reason: Some(format!(
                "Changed {} ago ({}); its permissions are copied to every protected account and group",
                days_text(Some(d)),
                &time::iso(t)[..10]
            )),
            object: node.map(|i| m.nodes[i].id.clone()),
        }]
    } else {
        Vec::new()
    };
    out.found(format!("Last changed {} ago", days_text(Some(d))))
        .affected(list, "objects")
        .evidence("Note", "whenChanged is kept per DC and moves with any attribute change; AD-ACL checks what the permissions are")
        .evidence("Read from", format!("whenChanged via {}", read_from(m)))
        .done()
}

/// The role a SID in SID history would grant, if it is a privileged one.
fn privileged_sid(sid: &str) -> Option<&'static str> {
    if let Some(name) = match sid {
        "S-1-5-32-544" => Some("Administrators"),
        "S-1-5-32-548" => Some("Account Operators"),
        "S-1-5-32-549" => Some("Server Operators"),
        "S-1-5-32-550" => Some("Print Operators"),
        "S-1-5-32-551" => Some("Backup Operators"),
        _ => None,
    } {
        return Some(name);
    }
    if !sid.starts_with("S-1-5-21-") {
        return None;
    }
    Some(match sid.rsplit('-').next()? {
        "500" => "the built-in Administrator",
        "502" => "krbtgt",
        "512" => "Domain Admins",
        "516" => "Domain Controllers",
        "518" => "Schema Admins",
        "519" => "Enterprise Admins",
        "520" => "Group Policy Creator Owners",
        "526" => "Key Admins",
        "527" => "Enterprise Key Admins",
        _ => return None,
    })
}

fn ioc_002(m: &Model) -> CheckResult {
    let mut list = Vec::new();
    for i in (0..m.nodes.len())
        .filter(|&i| matches!(m.nodes[i].kind, Kind::User | Kind::Computer | Kind::Group))
    {
        let hits: Vec<String> = m.nodes[i]
            .attrs
            .strs("sidhistory")
            .into_iter()
            .filter_map(|s| privileged_sid(s).map(|r| format!("{s} ({r})")))
            .collect();
        if !hits.is_empty() {
            list.push(item(m, i, format!("SID history holds {}", hits.join(", "))));
        }
    }
    check("AD-IOC-002")
        .expected("No SID history holds the SID of an admin account or group")
        .found(
            plural(list.len(), "object has", "objects have") + " a privileged SID in SID history",
        )
        .affected(list, "objects")
        .evidence("Read from", format!("sIDHistory via {}", read_from(m)))
        .done()
}

/// Server objects in the sites, by DN, with the nTDSDSA objects under them.
struct Sites<'a> {
    servers: Vec<&'a LdapObject>,
    dsas: Vec<&'a LdapObject>,
}

fn sites<'a>(m: &Model<'a>) -> Sites<'a> {
    let raw = m.raw;
    let class = |o: &LdapObject, c: &str| {
        o.strs("objectclass")
            .iter()
            .any(|x| x.eq_ignore_ascii_case(c))
    };
    Sites {
        servers: raw.sites.iter().filter(|o| class(o, "server")).collect(),
        dsas: raw.sites.iter().filter(|o| class(o, "nTDSDSA")).collect(),
    }
}

fn parent_of(dn: &str) -> String {
    super::model::parent_dn(dn)
        .unwrap_or_default()
        .to_ascii_lowercase()
}

fn ioc_004(m: &Model) -> CheckResult {
    let s = sites(m);
    let domain_dn = m
        .domain
        .map(|d| m.nodes[d].dn.to_ascii_lowercase())
        .unwrap_or_default();
    let mut list = Vec::new();
    let mut other_domains = 0;
    for dsa in &s.dsas {
        let server_dn = parent_of(dsa.dn());
        let server = s
            .servers
            .iter()
            .find(|o| o.dn().eq_ignore_ascii_case(&server_dn));
        let name = server
            .map(|o| rdn_value(o.dn()))
            .unwrap_or_else(|| rdn_value(&server_dn));
        let reference = server.and_then(|o| o.str("serverreference"));
        let reason = match reference {
            None => Some("No computer account is linked to this server object".to_string()),
            Some(r) if !r.to_ascii_lowercase().ends_with(&domain_dn) => {
                other_domains += 1;
                None
            }
            Some(r) => match m.by_dn.get(&r.to_ascii_lowercase()) {
                Some(&i) if m.nodes[i].is_dc() || m.nodes[i].flag(uac::PARTIAL_SECRETS_ACCOUNT) => {
                    None
                }
                Some(_) => Some(format!("Linked to {r}, which is not a domain controller")),
                None => Some(format!("Linked to {r}, which does not exist")),
            },
        };
        if let Some(reason) = reason {
            let when = dsa
                .str("whencreated")
                .and_then(time::parse_iso)
                .map(|t| format!("; created {}", &time::iso(t)[..10]));
            list.push(Affected {
                last_seen: None,
                name,
                kind: "server".into(),
                location: Some(dsa.dn().to_string()),
                reason: Some(format!("{reason}{}", when.unwrap_or_default())),
                object: None,
            });
        }
    }
    let mut out = check("AD-IOC-004")
        .expected("Every directory service agent (nTDSDSA) belongs to a domain controller")
        .found(
            plural(
                list.len(),
                "directory service agent does not",
                "directory service agents do not",
            ) + " match a domain controller",
        )
        .affected(list, "servers")
        .evidence("Directory service agents", s.dsas.len().to_string());
    if other_domains > 0 {
        out = out.evidence("Other domains", format!("{other_domains} belong to DCs of other domains in the forest and are not checked here"));
    }
    out.evidence(
        "Read from",
        format!(
            "CN=Sites in the configuration partition via {}",
            read_from(m)
        ),
    )
    .done()
}

fn ioc_014(m: &Model) -> CheckResult {
    let s = sites(m);
    let with_dsa: BTreeSet<String> = s
        .servers
        .iter()
        .filter(|srv| {
            s.dsas
                .iter()
                .any(|d| parent_of(d.dn()) == srv.dn().to_ascii_lowercase())
        })
        .filter_map(|srv| srv.str("serverreference").map(str::to_ascii_lowercase))
        .collect();
    let list: Vec<Affected> = (0..m.nodes.len())
        .filter(|&i| m.nodes[i].is_dc())
        .filter(|&i| !with_dsa.contains(&m.nodes[i].dn.to_ascii_lowercase()))
        .map(|i| {
            item(
                m,
                i,
                "SERVER_TRUST_ACCOUNT is set, but no directory service agent (nTDSDSA) belongs to this computer",
            )
        })
        .collect();
    check("AD-IOC-014")
        .expected("Only real domain controllers carry SERVER_TRUST_ACCOUNT")
        .found(
            plural(list.len(), "computer is", "computers are")
                + " marked as a DC without being one",
        )
        .affected(list, "computers")
        .evidence(
            "Read from",
            format!("userAccountControl and CN=Sites via {}", read_from(m)),
        )
        .done()
}

fn ioc_005(m: &Model) -> CheckResult {
    let dc_ou = (0..m.nodes.len()).find(|&i| {
        m.nodes[i].kind == Kind::Ou
            && m.nodes[i]
                .dn
                .to_ascii_lowercase()
                .starts_with("ou=domain controllers,")
    });
    let mut list = Vec::new();
    for (&g, holders) in &m.gpo_links {
        let applies: Vec<&str> = holders
            .iter()
            .filter(|&&h| Some(h) == dc_ou || Some(h) == m.domain)
            .map(|&h| m.nodes[h].name.as_str())
            .collect();
        if applies.is_empty() {
            continue;
        }
        let Some(t) = m.nodes[g]
            .attrs
            .str("whenchanged")
            .and_then(time::parse_iso)
        else {
            continue;
        };
        let d = days_ago(m, t);
        if d <= RECENT_DAYS {
            let name = m.nodes[g]
                .attrs
                .str("displayname")
                .map(str::to_string)
                .unwrap_or_else(|| m.nodes[g].name.clone());
            let mut a = item(
                m,
                g,
                format!(
                    "Changed {} ago ({}); linked to {}",
                    days_text(Some(d)),
                    &time::iso(t)[..10],
                    applies.join(" and ")
                ),
            );
            a.name = name;
            list.push(a);
        }
    }
    check("AD-IOC-005")
        .expected(format!("Changes to GPOs that apply to DCs in the last {RECENT_DAYS} days are known and approved"))
        .found(plural(list.len(), "GPO applying to DCs was", "GPOs applying to DCs were") + " changed recently")
        .affected(list, "GPOs")
        .evidence("Read from", format!("whenChanged and gPLink via {}", read_from(m)))
        .done()
}

// ---------- LSA packages on DCs ----------

const LSA_DEFAULTS: &[(&str, &str, &[&str])] = &[
    (
        "lsa.securitypackages",
        "security package",
        &[
            "kerberos", "msv1_0", "schannel", "wdigest", "tspkg", "pku2u", "cloudap", "negoexts",
            "livessp",
        ],
    ),
    (
        "lsa.authenticationpackages",
        "authentication package",
        &["msv1_0"],
    ),
    (
        "lsa.notificationpackages",
        "password notification package",
        &["scecli", "rassfm"],
    ),
];

fn ioc_006(m: &Model) -> CheckResult {
    let out = check("AD-IOC-006")
        .expected("LSA loads only the Windows security, authentication and notification packages");
    let mut list = Vec::new();
    let mut read = Vec::new();
    let mut skipped = Vec::new();
    for dc in &m.raw.dcconfig {
        let Some(d) = dc.data.as_ref().filter(|_| dc.error.is_none()) else {
            skipped.push(format!(
                "{} ({})",
                dc.name,
                dc.error.as_deref().unwrap_or("no data")
            ));
            continue;
        };
        if LSA_DEFAULTS
            .iter()
            .all(|(k, _, _)| d.registry.as_ref().is_none_or(|r| !r.contains_key(*k)))
        {
            skipped.push(format!("{} (LSA package lists not collected)", dc.name));
            continue;
        }
        read.push(dc.name.as_str());
        for (key, what, known) in LSA_DEFAULTS {
            let Some(v) = d.reg_str(key) else { continue };
            for p in v
                .split(',')
                .map(|p| p.trim().trim_matches('"').trim())
                .filter(|p| !p.is_empty())
            {
                if !known.iter().any(|k| k.eq_ignore_ascii_case(p)) {
                    list.push(Affected {
                        last_seen: None,
                        name: dc.name.clone(),
                        kind: "dc".into(),
                        location: None,
                        reason: Some(format!(
                            "Unexpected {what}: {p}; confirm which product installed it"
                        )),
                        object: None,
                    });
                }
            }
        }
    }
    if read.is_empty() {
        let why = if skipped.is_empty() {
            "No domain controller configuration was read.".to_string()
        } else {
            skipped.join("; ")
        };
        return out.not_assessed(why).done();
    }
    let mut out = out
        .found(plural(
            list.len(),
            "unexpected LSA package",
            "unexpected LSA packages",
        ))
        .affected(list, "packages")
        .evidence("Checked", read.join(", "));
    if !skipped.is_empty() {
        out = out.evidence("Not assessed on", skipped.join("; "));
    }
    out.evidence(
        "Read from",
        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa on each DC over PowerShell remoting",
    )
    .done()
}

// ---------- Hidden and new privileged accounts ----------

fn ioc_008(m: &Model) -> CheckResult {
    let broad = |sid: &str| {
        matches!(sid, "S-1-1-0" | "S-1-5-11" | "S-1-5-7")
            || sid
                .strip_prefix(&m.domain_sid)
                .is_some_and(|r| r == "-513" || r == "-515")
    };
    let mut list = Vec::new();
    for (&i, sd) in &m.sds {
        let n = &m.nodes[i];
        if !matches!(n.kind, Kind::User | Kind::Group | Kind::Computer)
            || !(n.tier0 || n.attrs.int("admincount") == Some(1))
        {
            continue;
        }
        let denied: BTreeSet<String> = sd
            .dacl
            .iter()
            .filter(|a| a.kind == AceType::Deny && !a.inherit_only() && broad(&a.sid))
            .filter(|a| {
                a.mask & (READ_PROP | LIST_CHILDREN | LIST_OBJECT | READ_CONTROL | GENERIC_READ)
                    != 0
            })
            .map(|a| who(m, &a.sid))
            .collect();
        if !denied.is_empty() {
            list.push(item(
                m,
                i,
                format!(
                    "Read access denied to {}: hidden from normal directory queries",
                    denied.into_iter().collect::<Vec<_>>().join(", ")
                ),
            ));
        }
    }
    check("AD-IOC-008")
        .expected("No privileged object hides itself with deny-read permissions")
        .found(plural(list.len(), "privileged object is", "privileged objects are") + " hidden")
        .affected(list, "objects")
        .evidence("Note", "An object that denies read to the collecting account is not returned at all; collect as a Domain Admin")
        .evidence("Read from", format!("nTSecurityDescriptor via {}", read_from(m)))
        .done()
}

fn ioc_010(m: &Model) -> CheckResult {
    let privileged = m.privileged_users();
    let mut list = Vec::new();
    for (&i, groups) in &privileged {
        let Some(t) = m.nodes[i].created else {
            continue;
        };
        let d = days_ago(m, t);
        if d <= RECENT_DAYS {
            let names: BTreeSet<&str> = groups.iter().map(|&g| m.nodes[g].name.as_str()).collect();
            list.push(item(
                m,
                i,
                format!(
                    "Created {} ago ({}); in {}",
                    days_text(Some(d)),
                    &time::iso(t)[..10],
                    names.into_iter().collect::<Vec<_>>().join(", ")
                ),
            ));
        }
    }
    check("AD-IOC-010")
        .expected(format!(
            "Every privileged account created in the last {RECENT_DAYS} days is known and approved"
        ))
        .found(
            plural(
                list.len(),
                "privileged account was",
                "privileged accounts were",
            ) + " created recently",
        )
        .affected(list, "accounts")
        .evidence(
            "Read from",
            format!("whenCreated and group membership via {}", read_from(m)),
        )
        .done()
}

fn ioc_011(m: &Model) -> CheckResult {
    let mut list = Vec::new();
    for i in (0..m.nodes.len()).filter(|&i| matches!(m.nodes[i].kind, Kind::User | Kind::Computer))
    {
        let n = &m.nodes[i];
        if n.rid() == Some(502) && n.attrs.has("msds-allowedtoactonbehalfofotheridentity") {
            list.push(item(
                m,
                i,
                "Resource-based constrained delegation is set on krbtgt",
            ));
        }
        let to: Vec<&str> = n
            .attrs
            .strs("msds-allowedtodelegateto")
            .into_iter()
            .filter(|s| s.to_ascii_lowercase().starts_with("krbtgt/"))
            .collect();
        if !to.is_empty() {
            list.push(item(
                m,
                i,
                format!("Allowed to delegate to {}", to.join(", ")),
            ));
        }
    }
    check("AD-IOC-011")
        .expected("No account can delegate to krbtgt")
        .found(plural(
            list.len(),
            "delegation to krbtgt",
            "delegations to krbtgt",
        ))
        .affected(list, "accounts")
        .evidence(
            "Read from",
            format!(
                "msDS-AllowedToDelegateTo and msDS-AllowedToActOnBehalfOfOtherIdentity via {}",
                read_from(m)
            ),
        )
        .done()
}

fn ioc_013(m: &Model) -> CheckResult {
    let out =
        check("AD-IOC-013").expected("Only admins and domain controllers can read KDS root keys");
    if m.raw.kds.is_empty() {
        return out
            .found("No KDS root key exists")
            .evidence(
                "Read from",
                format!("CN=Master Root Keys via {}", read_from(m)),
            )
            .done();
    }
    let mut readers: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for o in &m.raw.kds {
        let Some(sd) = decode_sd(o, "ntsecuritydescriptor") else {
            continue;
        };
        for a in sd
            .dacl
            .iter()
            .filter(|a| a.kind == AceType::Allow && !a.inherit_only() && !privileged(m, &a.sid))
        {
            let all = a.mask & right::GENERIC_ALL != 0 || a.mask & GENERIC_READ != 0;
            let props = a.mask & READ_PROP != 0 && a.object_type.is_none();
            if all || props {
                readers
                    .entry(who(m, &a.sid))
                    .or_default()
                    .insert(rdn_value(o.dn()));
            }
        }
    }
    let list: Vec<Affected> = readers
        .into_iter()
        .map(|(p, keys)| Affected {
            last_seen: None,
            name: p,
            kind: "principal".into(),
            location: None,
            reason: Some(format!(
                "Can read {}: enough to compute every gMSA password (Golden gMSA)",
                plural(keys.len(), "KDS root key", "KDS root keys")
            )),
            object: None,
        })
        .collect();
    out.found(
        plural(
            list.len(),
            "non-admin principal can",
            "non-admin principals can",
        ) + " read KDS root keys",
    )
    .affected(list, "principals")
    .evidence("KDS root keys", m.raw.kds.len().to_string())
    .evidence(
        "Read from",
        format!(
            "nTSecurityDescriptor of CN=Master Root Keys objects via {}",
            read_from(m)
        ),
    )
    .done()
}

pub static RULES: &[Rule] = &[
    Rule {
        id: "AD-IOC-001",
        needs: &["acls"],
        run: ioc_001,
    },
    Rule {
        id: "AD-IOC-002",
        needs: &["users", "computers", "groups"],
        run: ioc_002,
    },
    Rule {
        id: "AD-IOC-004",
        needs: &["sites", "computers"],
        run: ioc_004,
    },
    Rule {
        id: "AD-IOC-005",
        needs: &["domain", "containers", "gpos"],
        run: ioc_005,
    },
    Rule {
        id: "AD-IOC-006",
        needs: &["dcconfig"],
        run: ioc_006,
    },
    Rule {
        id: "AD-IOC-008",
        needs: &["users", "groups", "acls"],
        run: ioc_008,
    },
    Rule {
        id: "AD-IOC-010",
        needs: &["users", "groups"],
        run: ioc_010,
    },
    Rule {
        id: "AD-IOC-011",
        needs: &["users", "computers"],
        run: ioc_011,
    },
    Rule {
        id: "AD-IOC-013",
        needs: &["kds", "groups"],
        run: ioc_013,
    },
    Rule {
        id: "AD-IOC-014",
        needs: &["sites", "computers"],
        run: ioc_014,
    },
];
