//! Service accounts (regular, standalone, group and delegated managed) and
//! the OU structure: where accounts live and how OUs are protected.

use std::collections::BTreeSet;

use base64::Engine as _;

use super::model::{rdn_value, uac, well_known_name, Kind, Model};
use super::raw::LdapObject;
use super::rules::{check, days_text, item, plural, Rule};
use super::sd::{self, right, AceType};
use crate::results::{Affected, CheckResult};
use crate::time;

/// A group with more members than this is too broad to retrieve a gMSA password.
const BROAD_GROUP: usize = 50;
const OLD_PASSWORD_DAYS: i64 = 365;

/// msDS-DelegatedManagedServiceAccount, the class BadSuccessor creates.
const DMSA_CLASS: &str = "0feb936f-47b3-49f2-9386-1dedc2c23765";
const DELETE: u32 = 0x0001_0000;
const DELETE_TREE: u32 = 0x0000_0040;

const ENC_RC4: i64 = 0x4;
const ENC_AES: i64 = 0x18;

fn read_from(m: &Model) -> String {
    format!("LDAP on {} as {}", m.raw.info.server, m.raw.info.account)
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

/// Enabled user accounts that run services: they have an SPN. krbtgt aside.
fn service_accounts<'a>(m: &'a Model<'a>) -> impl Iterator<Item = usize> + 'a {
    (0..m.nodes.len()).filter(move |&i| {
        let n = &m.nodes[i];
        n.kind == Kind::User
            && n.enabled()
            && n.rid() != Some(502)
            && !n.attrs.strs("serviceprincipalname").is_empty()
    })
}

fn has_class(o: &LdapObject, class: &str) -> bool {
    o.strs("objectclass")
        .iter()
        .any(|c| c.eq_ignore_ascii_case(class))
}

fn gmsas<'a>(m: &Model<'a>) -> impl Iterator<Item = &'a LdapObject> + 'a {
    let raw = m.raw;
    raw.msas
        .iter()
        .filter(|o| has_class(o, "msDS-GroupManagedServiceAccount"))
}

fn msa_item(o: &LdapObject, reason: impl Into<String>) -> Affected {
    Affected {
        last_seen: None,
        name: o
            .str("samaccountname")
            .map(str::to_string)
            .unwrap_or_else(|| rdn_value(o.dn())),
        kind: "msa".into(),
        location: Some(o.dn().to_string()),
        reason: Some(reason.into()),
        object: None,
    }
}

// ---------- Service accounts ----------

fn svc_001(m: &Model) -> CheckResult {
    let list: Vec<Affected> = service_accounts(m)
        .map(|i| {
            let spns = m.nodes[i].attrs.strs("serviceprincipalname");
            item(
                m,
                i,
                format!(
                    "A user account with {}: a candidate for a gMSA",
                    plural(spns.len(), "SPN", "SPNs")
                ),
            )
        })
        .collect();
    let g = gmsas(m).count();
    check("AD-SVC-001")
        .expected(
            "Services run as group managed service accounts, not user accounts with passwords",
        )
        .found(format!(
            "{}; {}",
            plural(list.len(), "user service account", "user service accounts"),
            plural(g, "gMSA", "gMSAs")
        ))
        .affected(list, "accounts")
        .evidence("gMSAs", g.to_string())
        .evidence(
            "Read from",
            format!(
                "servicePrincipalName and managed service accounts via {}",
                read_from(m)
            ),
        )
        .done()
}

fn svc_002(m: &Model) -> CheckResult {
    let broad_sid = |sid: &str| {
        matches!(sid, "S-1-1-0" | "S-1-5-11" | "S-1-5-7")
            || sid
                .strip_prefix(&m.domain_sid)
                .is_some_and(|r| r == "-513" || r == "-515")
    };
    let mut list = Vec::new();
    for o in gmsas(m) {
        let Some(sd) = o
            .str("msds-groupmsamembership")
            .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())
            .and_then(|b| sd::parse(&b))
        else {
            continue;
        };
        let mut wide = Vec::new();
        for a in sd.dacl.iter().filter(|a| a.kind == AceType::Allow) {
            if broad_sid(&a.sid) {
                wide.push(who(m, &a.sid));
            } else if let Some(g) = m.by_sid(&a.sid).filter(|&g| m.nodes[g].kind == Kind::Group) {
                let n = m.recursive_members(g).len();
                if n > BROAD_GROUP {
                    wide.push(format!("{} ({n} members)", m.nodes[g].name));
                }
            }
        }
        if !wide.is_empty() {
            list.push(msa_item(
                o,
                format!("Password retrievable by {}", wide.join(", ")),
            ));
        }
    }
    check("AD-SVC-002")
        .expected(format!(
            "gMSA passwords are retrievable only by the servers that run them (no broad groups, none over {BROAD_GROUP} members)"
        ))
        .found(plural(list.len(), "gMSA is", "gMSAs are") + " retrievable by broad groups")
        .affected(list, "gMSAs")
        .evidence("gMSAs", gmsas(m).count().to_string())
        .evidence("Read from", format!("msDS-GroupMSAMembership via {}", read_from(m)))
        .done()
}

fn svc_003(m: &Model) -> CheckResult {
    let out = check("AD-SVC-003").expected("A KDS root key exists, so services can use gMSAs");
    let created: Vec<i64> = m
        .raw
        .kds
        .iter()
        .filter_map(|o| o.str("whencreated").and_then(time::parse_iso))
        .collect();
    if m.raw.kds.is_empty() {
        return out
            .failed(true)
            .found("No KDS root key: gMSAs cannot be created")
            .evidence(
                "Read from",
                format!("CN=Master Root Keys via {}", read_from(m)),
            )
            .done();
    }
    let newest = created
        .iter()
        .max()
        .map(|t| time::iso(*t)[..10].to_string())
        .unwrap_or_else(|| "unknown".into());
    out.found(format!(
        "{}; newest created {newest}",
        plural(m.raw.kds.len(), "KDS root key", "KDS root keys")
    ))
    .evidence(
        "Read from",
        format!("CN=Master Root Keys via {}", read_from(m)),
    )
    .done()
}

/// Rights on an OU that let a principal create a dMSA in it.
fn dmsa_rights(m: &Model, sd: &sd::SecurityDescriptor) -> Vec<(String, &'static str)> {
    let mut out = Vec::new();
    if let Some(owner) = sd.owner.as_deref().filter(|o| !privileged(m, o)) {
        out.push((who(m, owner), "Owner"));
    }
    for a in sd
        .dacl
        .iter()
        .filter(|a| a.kind == AceType::Allow && !a.inherit_only() && !privileged(m, &a.sid))
    {
        let ot = a.object_type.as_deref();
        let r = if a.mask & right::GENERIC_ALL != 0
            || a.mask & right::FULL_CONTROL == right::FULL_CONTROL
        {
            "Full control"
        } else if a.mask & right::WRITE_DACL != 0 {
            "Modify permissions"
        } else if a.mask & right::WRITE_OWNER != 0 {
            "Take ownership"
        } else if a.mask & right::CREATE_CHILD != 0 && matches!(ot, None | Some(DMSA_CLASS)) {
            if ot.is_none() {
                "Create all child objects"
            } else {
                "Create dMSA objects"
            }
        } else {
            continue;
        };
        out.push((who(m, &a.sid), r));
    }
    out
}

fn svc_004(m: &Model) -> CheckResult {
    let mut list = Vec::new();
    for (&i, sd) in &m.sds {
        if !matches!(m.nodes[i].kind, Kind::Ou | Kind::Container | Kind::Domain) {
            continue;
        }
        let rights = dmsa_rights(m, sd);
        if !rights.is_empty() {
            let text: BTreeSet<String> = rights
                .into_iter()
                .map(|(p, r)| format!("{p}: {r}"))
                .collect();
            list.push(item(m, i, text.into_iter().collect::<Vec<_>>().join("; ")));
        }
    }
    let dc2025: Vec<&str> = (0..m.nodes.len())
        .filter(|&i| {
            m.nodes[i].is_dc()
                && m.nodes[i]
                    .attrs
                    .str("operatingsystem")
                    .is_some_and(|o| o.contains("2025"))
        })
        .map(|i| m.nodes[i].name.as_str())
        .collect();
    let out = check("AD-SVC-004")
        .expected("No non-admin can create delegated managed service accounts (BadSuccessor)");
    if dc2025.is_empty() {
        let exposed: Vec<String> = list.iter().map(|a| a.name.clone()).collect();
        let mut out = out
            .found(format!(
                "No Windows Server 2025 domain controller, so dMSAs cannot be used yet; {} would be exposed once one is added",
                plural(exposed.len(), "OU or container", "OUs and containers")
            ))
            .evidence("Read from", format!("nTSecurityDescriptor of OUs and operatingSystem via {}", read_from(m)));
        if !exposed.is_empty() {
            out = out.evidence("OUs to fix before adding a 2025 DC", exposed.join(", "));
        }
        return out.done();
    }
    out.found(
        plural(list.len(), "OU or container lets", "OUs and containers let")
            + " non-admins create dMSAs",
    )
    .affected(list, "OUs and containers")
    .evidence("Windows Server 2025 DCs", dc2025.join(", "))
    .evidence(
        "Read from",
        format!(
            "nTSecurityDescriptor of OUs and operatingSystem via {}",
            read_from(m)
        ),
    )
    .done()
}

fn svc_006(m: &Model) -> CheckResult {
    let list: Vec<Affected> = service_accounts(m)
        .filter(|&i| m.nodes[i].flag(uac::DONT_EXPIRE_PASSWORD))
        .filter_map(|i| {
            let age = m.nodes[i]
                .pwd_last_set
                .map(|t| (m.now - t).div_euclid(time::DAY));
            (age.is_none_or(|d| d > OLD_PASSWORD_DAYS)).then(|| {
                item(
                    m,
                    i,
                    format!("Password never expires; last set {} ago", days_text(age)),
                )
            })
        })
        .collect();
    check("AD-SVC-006")
        .expected(format!(
            "Service account passwords are changed at least every {OLD_PASSWORD_DAYS} days"
        ))
        .found(
            plural(list.len(), "service account has", "service accounts have")
                + " an old password that never expires",
        )
        .affected(list, "accounts")
        .evidence(
            "Read from",
            format!("userAccountControl and pwdLastSet via {}", read_from(m)),
        )
        .done()
}

fn svc_007(m: &Model) -> CheckResult {
    let list: Vec<Affected> = service_accounts(m)
        .filter_map(|i| {
            let enc = m.nodes[i]
                .attrs
                .int("msds-supportedencryptiontypes")
                .unwrap_or(0);
            let reason = if enc == 0 {
                "No encryption types set: tickets default to RC4"
            } else if enc & ENC_RC4 != 0 && enc & ENC_AES == 0 {
                "RC4 only"
            } else if enc & ENC_RC4 != 0 {
                "RC4 allowed alongside AES"
            } else {
                return None;
            };
            Some(item(m, i, reason))
        })
        .collect();
    check("AD-SVC-007")
        .expected("Service accounts with SPNs allow only AES Kerberos encryption")
        .found(
            plural(
                list.len(),
                "service account allows",
                "service accounts allow",
            ) + " RC4",
        )
        .affected(list, "accounts")
        .evidence(
            "Read from",
            format!("msDS-SupportedEncryptionTypes via {}", read_from(m)),
        )
        .done()
}

fn svc_008(m: &Model) -> CheckResult {
    let privileged = m.privileged_users();
    let list: Vec<Affected> = service_accounts(m)
        .filter(|i| privileged.contains_key(i))
        .map(|i| {
            let mut groups: Vec<&str> = privileged[&i]
                .iter()
                .map(|&g| m.nodes[g].name.as_str())
                .collect();
            groups.sort();
            groups.dedup();
            item(
                m,
                i,
                format!(
                    "Has an SPN and is in {}: its ticket can be cracked offline for admin rights",
                    groups.join(", ")
                ),
            )
        })
        .collect();
    check("AD-SVC-008")
        .expected("No service account is in an admin group")
        .found(plural(list.len(), "service account is", "service accounts are") + " privileged")
        .affected(list, "accounts")
        .evidence(
            "Read from",
            format!(
                "servicePrincipalName and group membership via {}",
                read_from(m)
            ),
        )
        .done()
}

fn svc_009(m: &Model) -> CheckResult {
    let smsas: Vec<&LdapObject> = m
        .raw
        .msas
        .iter()
        .filter(|o| has_class(o, "msDS-ManagedServiceAccount"))
        .collect();
    let list: Vec<Affected> = smsas
        .iter()
        .filter(|o| o.strs("msds-hostserviceaccountbl").is_empty())
        .map(|o| {
            msa_item(
                o,
                "Not linked to any computer: unused, or its host was removed",
            )
        })
        .collect();
    check("AD-SVC-009")
        .expected("Every standalone managed service account is linked to the computer that uses it")
        .found(format!(
            "{}; {} unlinked",
            plural(smsas.len(), "sMSA", "sMSAs"),
            list.len()
        ))
        .affected(list, "sMSAs")
        .evidence(
            "Read from",
            format!("msDS-HostServiceAccountBL via {}", read_from(m)),
        )
        .done()
}

fn svc_010(m: &Model) -> CheckResult {
    let list: Vec<Affected> = service_accounts(m)
        .filter(|&i| {
            let a = &m.nodes[i].attrs;
            a.str("description").is_none_or(|d| d.trim().is_empty()) && !a.has("manager")
        })
        .map(|i| item(m, i, "No description and no manager"))
        .collect();
    check("AD-SVC-010")
        .expected("Every service account has a description and a manager")
        .found(
            plural(list.len(), "service account has", "service accounts have")
                + " no owner recorded",
        )
        .affected(list, "accounts")
        .evidence(
            "Read from",
            format!("description and manager via {}", read_from(m)),
        )
        .done()
}

// ---------- OUs ----------

fn ou_002(m: &Model) -> CheckResult {
    let domain = m
        .domain
        .map(|d| m.nodes[d].dn.to_ascii_lowercase())
        .unwrap_or_default();
    let users = format!("cn=users,{domain}");
    let computers = format!("cn=computers,{domain}");
    let list: Vec<Affected> = (0..m.nodes.len())
        .filter(|&i| matches!(m.nodes[i].kind, Kind::User | Kind::Computer))
        .filter(|&i| m.nodes[i].rid().is_none_or(|r| r >= 1000))
        .filter_map(|i| {
            let parent = super::model::parent_dn(&m.nodes[i].dn)?.to_ascii_lowercase();
            let c = if parent == users {
                "Users"
            } else if parent == computers {
                "Computers"
            } else {
                return None;
            };
            Some(item(
                m,
                i,
                format!("In the default {c} container, where OU Group Policy cannot be linked"),
            ))
        })
        .collect();
    check("AD-OU-002")
        .expected("Accounts live in OUs, not the default Users and Computers containers")
        .found(plural(list.len(), "account is", "accounts are") + " in a default container")
        .affected(list, "accounts")
        .evidence(
            "Read from",
            format!("distinguishedName via {}", read_from(m)),
        )
        .done()
}

fn ou_003(m: &Model) -> CheckResult {
    let out = check("AD-OU-003")
        .expected("New users and computers are created in OUs (redirusr and redircmp)");
    let Some(d) = m.domain else {
        return out.not_assessed("The domain head was not read.").done();
    };
    let wko = m.nodes[d].attrs.strs("wellknownobjects");
    if wko.is_empty() {
        return out
            .not_assessed("wellKnownObjects was not collected; collect again with this version.")
            .done();
    }
    let target = |guid: &str| {
        wko.iter()
            .find(|v| v.to_ascii_uppercase().contains(guid))
            .and_then(|v| v.splitn(4, ':').nth(3))
            .map(str::to_string)
    };
    let mut list = Vec::new();
    for (guid, what, default) in [
        ("A9D1CA15768811D1ADED00C04FD8D5CD", "users", "CN=Users,"),
        (
            "AA312825768811D1ADED00C04FD8D5CD",
            "computers",
            "CN=Computers,",
        ),
    ] {
        let Some(dn) = target(guid) else { continue };
        if dn
            .to_ascii_lowercase()
            .starts_with(&default.to_ascii_lowercase())
        {
            list.push(Affected {
                last_seen: None,
                name: rdn_value(&dn),
                kind: "container".into(),
                location: Some(dn.clone()),
                reason: Some(format!(
                    "New {what} are still created in the default container"
                )),
                object: m
                    .by_dn
                    .get(&dn.to_ascii_lowercase())
                    .map(|&i| m.nodes[i].id.clone()),
            });
        }
    }
    out.found(
        plural(list.len(), "default container is", "default containers are") + " not redirected",
    )
    .affected(list, "containers")
    .evidence(
        "Read from",
        format!("wellKnownObjects on the domain head via {}", read_from(m)),
    )
    .done()
}

fn ou_004(m: &Model) -> CheckResult {
    let ous: Vec<usize> = (0..m.nodes.len())
        .filter(|&i| m.nodes[i].kind == Kind::Ou)
        .collect();
    let read: Vec<usize> = ous
        .iter()
        .copied()
        .filter(|i| m.sds.contains_key(i))
        .collect();
    let list: Vec<Affected> = read
        .iter()
        .filter(|i| {
            !m.sds[i].dacl.iter().any(|a| {
                a.kind == AceType::Deny
                    && a.sid == "S-1-1-0"
                    && a.mask & DELETE != 0
                    && a.mask & DELETE_TREE != 0
            })
        })
        .map(|&i| item(m, i, "Not protected from accidental deletion"))
        .collect();
    let out = check("AD-OU-004").expected("Every OU is protected from accidental deletion");
    if read.is_empty() && !ous.is_empty() {
        return out
            .not_assessed("No OU security descriptor was read.")
            .done();
    }
    out.found(format!(
        "{} of {} unprotected",
        list.len(),
        plural(read.len(), "OU", "OUs")
    ))
    .affected(list, "OUs")
    .evidence(
        "Read from",
        format!("nTSecurityDescriptor of OUs via {}", read_from(m)),
    )
    .done()
}

fn ou_007(m: &Model) -> CheckResult {
    let privileged = m.privileged_users();
    let list: Vec<Affected> = privileged
        .keys()
        .copied()
        .filter(|&i| m.nodes[i].enabled() && m.nodes[i].rid() != Some(500))
        .filter_map(|i| {
            let mail = m.nodes[i].attrs.str("mail")?;
            Some(item(
                m,
                i,
                format!("Has a mail address ({mail}): likely also used for email and browsing"),
            ))
        })
        .collect();
    check("AD-OU-007")
        .expected("Admins use separate accounts for administration, without mailboxes")
        .found(
            plural(list.len(), "admin account looks", "admin accounts look")
                + " like a daily-use account",
        )
        .affected(list, "accounts")
        .evidence(
            "Read from",
            format!("mail and group membership via {}", read_from(m)),
        )
        .done()
}

pub static RULES: &[Rule] = &[
    Rule {
        id: "AD-SVC-001",
        needs: &["users", "msas"],
        run: svc_001,
    },
    Rule {
        id: "AD-SVC-002",
        needs: &["msas", "groups"],
        run: svc_002,
    },
    Rule {
        id: "AD-SVC-003",
        needs: &["kds"],
        run: svc_003,
    },
    Rule {
        id: "AD-SVC-004",
        needs: &["acls", "containers", "computers", "groups"],
        run: svc_004,
    },
    Rule {
        id: "AD-SVC-006",
        needs: &["users"],
        run: svc_006,
    },
    Rule {
        id: "AD-SVC-007",
        needs: &["users"],
        run: svc_007,
    },
    Rule {
        id: "AD-SVC-008",
        needs: &["users", "groups"],
        run: svc_008,
    },
    Rule {
        id: "AD-SVC-009",
        needs: &["msas"],
        run: svc_009,
    },
    Rule {
        id: "AD-SVC-010",
        needs: &["users"],
        run: svc_010,
    },
    Rule {
        id: "AD-OU-002",
        needs: &["users", "computers", "domain"],
        run: ou_002,
    },
    Rule {
        id: "AD-OU-003",
        needs: &["domain"],
        run: ou_003,
    },
    Rule {
        id: "AD-OU-004",
        needs: &["containers", "acls"],
        run: ou_004,
    },
    Rule {
        id: "AD-OU-007",
        needs: &["users", "groups"],
        run: ou_007,
    },
];
