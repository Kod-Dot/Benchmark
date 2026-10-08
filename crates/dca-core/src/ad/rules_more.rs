//! Account, group and OU checks that read only the directory objects the
//! collector already gathers: account flags, privileged group membership,
//! LAPS coverage and OU structure.

use super::model::{rdn_value, uac, well_known_name, Kind, Model};
use super::rules::{active_members, check, days_text, item, plural, Rule};
use crate::results::Affected;

const LARGE_GROUP: usize = 500;
const OLD_PASSWORD_DAYS: i64 = 365;
const OLD_KRBTGT_DAYS: i64 = 180;
const MAX_OU_DEPTH: usize = 10;

fn read_from(m: &Model) -> String {
    format!("LDAP on {} as {}", m.raw.info.server, m.raw.info.account)
}

fn users<'a>(m: &'a Model<'a>) -> impl Iterator<Item = usize> + 'a {
    (0..m.nodes.len()).filter(move |&i| m.nodes[i].kind == Kind::User)
}

fn is_krbtgt_account(m: &Model, i: usize) -> bool {
    m.nodes[i].rid() == Some(502) || m.nodes[i].name.to_ascii_lowercase().starts_with("krbtgt")
}

// ---------- Accounts ----------

fn acc_009(m: &Model) -> CheckResult {
    let flags: [(u32, &str); 5] = [
        (uac::DONT_EXPIRE_PASSWORD, "password never expires"),
        (
            uac::TRUSTED_FOR_DELEGATION,
            "trusted for unconstrained delegation",
        ),
        (
            uac::TRUSTED_TO_AUTH_FOR_DELEGATION,
            "trusted to authenticate for delegation (protocol transition)",
        ),
        (
            uac::USE_DES_KEY_ONLY,
            "restricted to weak DES Kerberos keys",
        ),
        (
            uac::ENCRYPTED_TEXT_PWD_ALLOWED,
            "password stored with reversible encryption",
        ),
    ];
    let list: Vec<Affected> = users(m)
        .filter(|&i| m.nodes[i].enabled() && !is_krbtgt_account(m, i))
        .filter_map(|i| {
            let why: Vec<&str> = flags
                .iter()
                .filter(|(f, _)| m.nodes[i].flag(*f))
                .map(|(_, t)| *t)
                .collect();
            (!why.is_empty()).then(|| item(m, i, why.join("; ")))
        })
        .collect();
    check("AD-ACC-009")
        .expected("No enabled user has a risky userAccountControl flag")
        .found(plural(list.len(), "user has", "users have") + " a risky flag")
        .affected(list, "users")
        .evidence(
            "Read from",
            format!("userAccountControl via {}", read_from(m)),
        )
        .done()
}

fn acc_014(m: &Model) -> CheckResult {
    let mut inventory = Vec::new();
    for i in 0..m.nodes.len() {
        let n = &m.nodes[i];
        if !matches!(n.kind, Kind::User | Kind::Computer) {
            continue;
        }
        let ws = n.attrs.str("userworkstations").unwrap_or_default();
        let hours = n.attrs.has("logonhours");
        if ws.is_empty() && !hours {
            continue;
        }
        let mut parts = Vec::new();
        if !ws.is_empty() {
            parts.push(format!("can only sign in to {ws}"));
        }
        if hours {
            parts.push("has logon hours set".to_string());
        }
        inventory.push(format!("{}: {}", n.name, parts.join(", ")));
    }
    let privileged = m.privileged_users();
    let list: Vec<Affected> = privileged
        .keys()
        .copied()
        .filter(|&u| m.nodes[u].enabled() && !is_krbtgt_account(m, u))
        .filter(|&u| {
            m.nodes[u]
                .attrs
                .str("userworkstations")
                .is_none_or(str::is_empty)
        })
        .map(|u| {
            item(
                m,
                u,
                "No sign-in workstation restriction (userWorkstations)",
            )
        })
        .collect();
    check("AD-ACC-014")
        .expected("Privileged accounts can sign in only to the workstations they are meant to use")
        .found(format!(
            "{} with logon restrictions; {} without a workstation restriction",
            plural(inventory.len(), "account", "accounts"),
            plural(list.len(), "privileged account", "privileged accounts")
        ))
        .affected(list, "accounts")
        .raw(inventory.join("\n"))
        .evidence(
            "Read from",
            format!("userWorkstations and logonHours via {}", read_from(m)),
        )
        .done()
}

fn acc_015(m: &Model) -> CheckResult {
    let list: Vec<Affected> = (0..m.nodes.len())
        .filter(|&i| m.nodes[i].kind == Kind::Principal)
        .filter(|&i| {
            let sid = m.nodes[i].sid.as_deref().unwrap_or_default();
            well_known_name(sid).is_none() && sid.starts_with("S-1-5-21-")
        })
        .filter(|&i| {
            // Foreign principals the domain's trusts no longer cover.
            let sid = m.nodes[i].sid.as_deref().unwrap_or_default();
            !m.raw.trusts.iter().any(|t| {
                t.str("securityidentifier")
                    .is_some_and(|s| sid.starts_with(s))
            })
        })
        .map(|i| {
            let groups: Vec<String> = (0..m.nodes.len())
                .filter(|&g| m.members[g].contains(&i))
                .map(|g| m.nodes[g].name.clone())
                .collect();
            Affected {
                last_seen: None,
                name: m.nodes[i].name.clone(),
                kind: "group".into(),
                location: None,
                reason: Some(format!(
                    "{}; member of {}",
                    if m.nodes[i]
                        .sid
                        .as_deref()
                        .is_some_and(|s| s.starts_with(&m.domain_sid))
                    {
                        "A SID from this domain that no longer matches an account"
                    } else {
                        "A foreign security principal whose domain is not trusted"
                    },
                    if groups.is_empty() {
                        "no group".into()
                    } else {
                        groups.join(", ")
                    }
                )),
                object: Some(m.nodes[i].id.clone()),
            }
        })
        .collect();
    check("AD-ACC-015")
        .expected("Every foreign security principal belongs to a trusted domain")
        .found(plural(
            list.len(),
            "orphaned principal",
            "orphaned principals",
        ))
        .affected(list, "principals")
        .evidence(
            "Read from",
            format!("group membership and trusts via {}", read_from(m)),
        )
        .done()
}

fn acc_018(m: &Model) -> CheckResult {
    let list: Vec<Affected> = (0..m.nodes.len())
        .filter(|&g| m.nodes[g].kind == Kind::Group)
        .filter(|&g| !matches!(m.nodes[g].rid(), Some(513..=516)))
        .filter_map(|g| {
            let n = m.nodes[g].attrs.strs("member").len();
            (n > LARGE_GROUP).then(|| {
                item(
                    m,
                    g,
                    format!(
                        "{} directly: any access given to this group reaches all of them",
                        plural(n, "member", "members")
                    ),
                )
            })
        })
        .collect();
    check("AD-ACC-018")
        .expected(format!(
            "No group with more than {LARGE_GROUP} members is used to grant access"
        ))
        .found(plural(list.len(), "large group", "large groups"))
        .affected(list, "groups")
        .evidence("Read from", format!("member via {}", read_from(m)))
        .done()
}

// ---------- Computers ----------

fn cmp_003(m: &Model) -> CheckResult {
    let list: Vec<Affected> = (0..m.nodes.len())
        .filter(|&i| m.nodes[i].kind == Kind::Computer)
        .filter(|&i| {
            let n = &m.nodes[i];
            n.enabled() && n.flag(uac::TRUSTED_FOR_DELEGATION) && !n.is_dc()
        })
        .map(|i| {
            item(
                m,
                i,
                "Trusted for unconstrained delegation: any account that signs in to it can be impersonated",
            )
        })
        .collect();
    check("AD-CMP-003")
        .expected("No computer other than a domain controller has unconstrained delegation")
        .found(plural(list.len(), "computer has", "computers have") + " unconstrained delegation")
        .affected(list, "computers")
        .evidence(
            "Read from",
            format!("userAccountControl via {}", read_from(m)),
        )
        .done()
}

// ---------- Privileged groups ----------

fn member_items(
    m: &Model,
    group: usize,
    skip: impl Fn(usize) -> bool,
    reason: &str,
) -> Vec<Affected> {
    m.members[group]
        .iter()
        .copied()
        .filter(|&i| !skip(i))
        .map(|i| item(m, i, format!("{reason} ({})", m.nodes[group].name)))
        .collect()
}

fn priv_004(m: &Model) -> CheckResult {
    let Some(admins) = m.by_sid("S-1-5-32-544") else {
        return check("AD-PRIV-004")
            .not_assessed("The Administrators group was not collected.")
            .done();
    };
    let list = member_items(
        m,
        admins,
        |i| {
            matches!(m.nodes[i].rid(), Some(500 | 512 | 519))
                && m.nodes[i]
                    .sid
                    .as_deref()
                    .is_some_and(|s| s.starts_with(&m.domain_sid) || s.ends_with("-519"))
        },
        "Direct member of the built-in Administrators group, which is not a default member",
    );
    check("AD-PRIV-004")
        .expected("Only Administrator, Domain Admins and Enterprise Admins are members of the built-in Administrators group")
        .found(plural(list.len(), "extra member", "extra members"))
        .affected(list, "members")
        .evidence("Read from", format!("member via {}", read_from(m)))
        .done()
}

fn priv_007(m: &Model) -> CheckResult {
    let Some(g) = m.group_by_rid(520) else {
        return check("AD-PRIV-007")
            .expected("Group Policy Creator Owners has no members besides Administrator")
            .found("The group does not exist")
            .evidence("Read from", format!("groups via {}", read_from(m)))
            .done();
    };
    let list = member_items(
        m,
        g,
        |i| m.nodes[i].rid() == Some(500),
        "Can create GPOs and edit the ones they create",
    );
    check("AD-PRIV-007")
        .expected("Group Policy Creator Owners has no members besides Administrator")
        .found(plural(list.len(), "extra member", "extra members"))
        .affected(list, "members")
        .evidence("Read from", format!("member via {}", read_from(m)))
        .done()
}

fn priv_008(m: &Model) -> CheckResult {
    let mut list = Vec::new();
    for rid in [517u32, 526, 527] {
        let Some(g) = m.group_by_rid(rid) else {
            continue;
        };
        list.extend(member_items(
            m,
            g,
            // Certification authority computers belong in Cert Publishers.
            |i| rid == 517 && m.nodes[i].kind == Kind::Computer,
            "Holds certificate publishing or key administration rights",
        ));
    }
    check("AD-PRIV-008")
        .expected(
            "Cert Publishers, Key Admins and Enterprise Key Admins have only the members they need",
        )
        .found(plural(list.len(), "member", "members"))
        .affected(list, "members")
        .evidence("Read from", format!("member via {}", read_from(m)))
        .done()
}

fn priv_012(m: &Model) -> CheckResult {
    let list: Vec<Affected> = m
        .privileged_users()
        .into_iter()
        .filter(|&(u, _)| {
            m.nodes[u].enabled()
                && !is_krbtgt_account(m, u)
                && !m.nodes[u].attrs.strs("serviceprincipalname").is_empty()
        })
        .map(|(u, groups)| {
            let names: Vec<&str> = groups.iter().map(|&g| m.nodes[g].name.as_str()).collect();
            item(
                m,
                u,
                format!(
                    "Has an SPN and is in {}: its password can be cracked offline by any user",
                    names.join(", ")
                ),
            )
        })
        .collect();
    check("AD-PRIV-012")
        .expected("No service account is a member of a privileged group")
        .found(plural(list.len(), "service account is", "service accounts are") + " privileged")
        .affected(list, "accounts")
        .evidence(
            "Read from",
            format!(
                "serviceprincipalname and group membership via {}",
                read_from(m)
            ),
        )
        .done()
}

fn priv_019(m: &Model) -> CheckResult {
    let Some(a) = m.by_sid(&format!("{}-500", m.domain_sid)) else {
        return check("AD-PRIV-019")
            .not_assessed("The built-in Administrator account was not found.")
            .done();
    };
    let n = &m.nodes[a];
    let mut why = Vec::new();
    if n.enabled() {
        if n.name.eq_ignore_ascii_case("Administrator") {
            why.push("Still named Administrator".to_string());
        }
        let age = m.days_since(n.pwd_last_set);
        if age.is_none_or(|d| d > OLD_PASSWORD_DAYS) {
            why.push(format!("Password last set {} ago", days_text(age)));
        }
        if let Some(d) = m.days_since(n.last_logon).filter(|&d| d <= 30) {
            why.push(format!(
                "Signed in {} ago: it should be a break-glass account",
                days_text(Some(d))
            ));
        }
    }
    let list = if why.is_empty() {
        Vec::new()
    } else {
        vec![item(m, a, why.join("; "))]
    };
    check("AD-PRIV-019")
        .expected("The built-in Administrator is renamed, has a recent password and is not used day to day")
        .found(if list.is_empty() {
            "The account is disabled or well managed".to_string()
        } else {
            plural(why.len(), "problem", "problems")
        })
        .affected(list, "accounts")
        .evidence(
            "Read from",
            format!("name, pwdLastSet and lastLogonTimestamp via {}", read_from(m)),
        )
        .done()
}

fn priv_022(m: &Model) -> CheckResult {
    let list: Vec<Affected> = users(m)
        .filter(|&i| m.nodes[i].name.to_ascii_lowercase().starts_with("krbtgt_"))
        .filter_map(|i| {
            let age = m.days_since(m.nodes[i].pwd_last_set);
            age.is_none_or(|d| d > OLD_KRBTGT_DAYS).then(|| {
                item(
                    m,
                    i,
                    format!(
                        "Read-only DC krbtgt password last set {} ago",
                        days_text(age)
                    ),
                )
            })
        })
        .collect();
    check("AD-PRIV-022")
        .expected(format!(
            "Read-only DC krbtgt passwords are changed at least every {OLD_KRBTGT_DAYS} days"
        ))
        .found(plural(
            list.len(),
            "old krbtgt account",
            "old krbtgt accounts",
        ))
        .affected(list, "accounts")
        .evidence("Read from", format!("pwdLastSet via {}", read_from(m)))
        .done()
}

fn priv_026(m: &Model) -> CheckResult {
    let mut list = Vec::new();
    for g in m.admin_groups() {
        for &i in &m.members[g] {
            let n = &m.nodes[i];
            let sid = n.sid.as_deref().unwrap_or_default();
            if n.kind == Kind::Principal && well_known_name(sid).is_none() {
                list.push(item(
                    m,
                    i,
                    format!(
                        "A principal from another domain or a deleted account is in {}",
                        m.nodes[g].name
                    ),
                ));
            }
        }
    }
    check("AD-PRIV-026")
        .expected("No foreign security principal is a member of a privileged group")
        .found(plural(
            list.len(),
            "foreign principal",
            "foreign principals",
        ))
        .affected(list, "principals")
        .evidence("Read from", format!("member via {}", read_from(m)))
        .done()
}

fn ioc_009(m: &Model) -> CheckResult {
    let list: Vec<Affected> = (0..m.nodes.len())
        .filter(|&i| matches!(m.nodes[i].kind, Kind::User | Kind::Computer))
        .filter(|&i| !m.nodes[i].is_dc())
        .filter_map(|i| {
            let pg = m.nodes[i].attrs.int("primarygroupid")?;
            matches!(pg, 512 | 518 | 519).then(|| {
                item(
                    m,
                    i,
                    format!(
                        "Primary group is {}: the membership does not appear in the group's member list",
                        match pg {
                            512 => "Domain Admins",
                            518 => "Schema Admins",
                            _ => "Enterprise Admins",
                        }
                    ),
                )
            })
        })
        .collect();
    check("AD-IOC-009")
        .expected("No account has a privileged group as its primary group")
        .found(plural(list.len(), "account", "accounts") + " hide privileged membership")
        .affected(list, "accounts")
        .evidence("Read from", format!("primaryGroupID via {}", read_from(m)))
        .done()
}

fn krb_017(m: &Model) -> CheckResult {
    let protected = m.group_by_rid(525);
    let covered: Vec<usize> = protected
        .map(|g| m.recursive_members(g))
        .unwrap_or_default();
    let list: Vec<Affected> = m
        .privileged_users()
        .into_keys()
        .filter(|&u| m.nodes[u].enabled() && !is_krbtgt_account(m, u))
        .filter(|u| !covered.contains(u))
        .map(|u| {
            item(
                m,
                u,
                "Privileged but not in Protected Users: NTLM, delegation and long-lived tickets are still allowed",
            )
        })
        .collect();
    check("AD-KRB-017")
        .expected("Every enabled privileged account is a member of Protected Users")
        .found(if protected.is_none() {
            format!(
                "The Protected Users group does not exist; {} unprotected",
                plural(list.len(), "privileged account", "privileged accounts")
            )
        } else {
            plural(list.len(), "privileged account", "privileged accounts") + " unprotected"
        })
        .affected(list, "accounts")
        .evidence(
            "Read from",
            format!("Protected Users and privileged groups via {}", read_from(m)),
        )
        .done()
}

// ---------- LAPS and OUs ----------

fn laps_002(m: &Model) -> CheckResult {
    let active: Vec<usize> = active_members(m).collect();
    let missing: Vec<Affected> = active
        .iter()
        .copied()
        .filter(|&c| {
            let a = &m.nodes[c].attrs;
            !a.has("mslaps-passwordexpirationtime") && !a.has("ms-mcs-admpwdexpirationtime")
        })
        .map(|c| {
            item(
                m,
                c,
                "No managed local administrator password in the directory",
            )
        })
        .collect();
    let covered = active.len() - missing.len();
    let pct = if active.is_empty() {
        100
    } else {
        covered * 100 / active.len()
    };
    check("AD-LAPS-002")
        .expected("Every active member computer has a managed LAPS password")
        .found(format!(
            "{pct}% covered ({covered} of {})",
            plural(active.len(), "active computer", "active computers")
        ))
        .affected(missing, "computers")
        .evidence(
            "Read from",
            format!("LAPS expiry attributes via {}", read_from(m)),
        )
        .done()
}

fn ou_001(m: &Model) -> CheckResult {
    let mut inventory = Vec::new();
    let mut deep = Vec::new();
    for i in (0..m.nodes.len()).filter(|&i| m.nodes[i].kind == Kind::Ou) {
        let dn = &m.nodes[i].dn;
        let depth = dn
            .split(',')
            .filter(|p| p.trim().to_ascii_uppercase().starts_with("OU="))
            .count();
        inventory.push(format!("{depth}\t{}", rdn_value(dn)));
        if depth > MAX_OU_DEPTH {
            deep.push(item(
                m,
                i,
                format!("{depth} levels deep: policy processing and delegation get hard to follow"),
            ));
        }
    }
    check("AD-OU-001")
        .expected(format!("OUs are no more than {MAX_OU_DEPTH} levels deep"))
        .found(format!(
            "{}; {} too deep",
            plural(inventory.len(), "OU", "OUs"),
            deep.len()
        ))
        .affected(deep, "OUs")
        .raw(inventory.join("\n"))
        .evidence(
            "Read from",
            format!("organizationalUnit objects via {}", read_from(m)),
        )
        .done()
}

use crate::results::CheckResult;

const LDAP: &[&str] = &["domain", "users", "computers", "groups"];
const GROUPS: &[&str] = &["domain", "groups"];

pub static RULES: &[Rule] = &[
    Rule {
        id: "AD-ACC-009",
        needs: &["users"],
        run: acc_009,
    },
    Rule {
        id: "AD-ACC-014",
        needs: &["domain", "users", "groups"],
        run: acc_014,
    },
    Rule {
        id: "AD-ACC-015",
        needs: &["domain", "groups", "trusts"],
        run: acc_015,
    },
    Rule {
        id: "AD-ACC-018",
        needs: GROUPS,
        run: acc_018,
    },
    Rule {
        id: "AD-CMP-003",
        needs: &["computers"],
        run: cmp_003,
    },
    Rule {
        id: "AD-KRB-017",
        needs: LDAP,
        run: krb_017,
    },
    Rule {
        id: "AD-PRIV-004",
        needs: GROUPS,
        run: priv_004,
    },
    Rule {
        id: "AD-PRIV-007",
        needs: GROUPS,
        run: priv_007,
    },
    Rule {
        id: "AD-PRIV-008",
        needs: GROUPS,
        run: priv_008,
    },
    Rule {
        id: "AD-PRIV-012",
        needs: LDAP,
        run: priv_012,
    },
    Rule {
        id: "AD-PRIV-019",
        needs: &["domain", "users"],
        run: priv_019,
    },
    Rule {
        id: "AD-PRIV-022",
        needs: &["users"],
        run: priv_022,
    },
    Rule {
        id: "AD-PRIV-026",
        needs: LDAP,
        run: priv_026,
    },
    Rule {
        id: "AD-IOC-009",
        needs: &["users", "computers"],
        run: ioc_009,
    },
    Rule {
        id: "AD-LAPS-002",
        needs: &["domain", "computers"],
        run: laps_002,
    },
    Rule {
        id: "AD-OU-001",
        needs: &["containers"],
        run: ou_001,
    },
];
