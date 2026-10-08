//! Schema, trusts, audit coverage and applications that hold rights in the
//! directory (Exchange, Entra Connect).

use std::collections::BTreeSet;

use base64::Engine;

use super::model::{rdn_value, Kind, Model};
use super::raw::LdapObject;
use super::rules::{check, days_text, item, plural, Rule};
use super::rules_dc::{each_dc, Eval};
use super::rules_gpo::rights_check;
use super::sd::{self, right, AceType};
use crate::results::{Affected, CheckResult};
use crate::time;

const CONFIDENTIAL: i64 = 0x80;
const BASE_SCHEMA: i64 = 0x10;

fn ldap_from(m: &Model, what: &str) -> String {
    format!(
        "{what} via LDAP on {} as {}",
        m.raw.info.server, m.raw.info.account
    )
}

fn is_class(o: &LdapObject, c: &str) -> bool {
    o.strs("objectclass")
        .iter()
        .any(|x| x.eq_ignore_ascii_case(c))
}

fn definitions<'a>(m: &Model<'a>) -> impl Iterator<Item = &'a LdapObject> {
    let raw = m.raw;
    raw.schema
        .iter()
        .filter(|o| is_class(o, "attributeSchema") || is_class(o, "classSchema"))
}

/// True when the schema was read by a collector that returns flags and
/// dates for every definition.
fn full_schema(m: &Model) -> bool {
    definitions(m).any(|o| o.has("searchflags") || o.has("whencreated"))
}

const OLD_SCHEMA: &str =
    "Schema definitions were not collected in full; collect LDAP again with this version.";

// ---------- Schema ----------

const SECRET_ATTRIBUTES: &[&str] = &[
    "ms-Mcs-AdmPwd",
    "msLAPS-Password",
    "msLAPS-EncryptedPassword",
    "msLAPS-EncryptedDSRMPassword",
    "msFVE-RecoveryPassword",
    "msFVE-KeyPackage",
];

fn schema_item(o: &LdapObject, reason: impl Into<String>) -> Affected {
    Affected {
        last_seen: None,
        name: o
            .str("ldapdisplayname")
            .map(str::to_string)
            .unwrap_or_else(|| rdn_value(o.dn())),
        kind: o.class().unwrap_or("attributeSchema").into(),
        location: Some(o.dn().to_string()),
        reason: Some(reason.into()),
        object: None,
    }
}

fn sch_001(m: &Model) -> CheckResult {
    let out = check("AD-SCH-001")
        .expected("LAPS and BitLocker secret attributes are marked confidential");
    if !full_schema(m) {
        return out.not_assessed(OLD_SCHEMA).done();
    }
    let mut present = 0;
    let list: Vec<Affected> = definitions(m)
        .filter(|o| {
            o.str("ldapdisplayname")
                .is_some_and(|n| SECRET_ATTRIBUTES.iter().any(|s| s.eq_ignore_ascii_case(n)))
        })
        .filter_map(|o| {
            present += 1;
            let flags = o.int("searchflags").unwrap_or(0);
            (flags & CONFIDENTIAL == 0).then(|| {
                schema_item(
                    o,
                    format!("searchFlags {flags}: not confidential, so anyone with read access to the object can read it"),
                )
            })
        })
        .collect();
    out.found(format!(
        "{} of {} not confidential",
        list.len(),
        plural(present, "secret attribute", "secret attributes")
    ))
    .affected(list, "attributes")
    .evidence(
        "Read from",
        ldap_from(m, "searchFlags of attributeSchema objects"),
    )
    .done()
}

fn sch_002(m: &Model) -> CheckResult {
    let out = check("AD-SCH-002").expected(
        "Custom attributes named like passwords or secrets are confidential, or do not exist",
    );
    if !full_schema(m) {
        return out.not_assessed(OLD_SCHEMA).done();
    }
    let looks_secret = |n: &str| {
        let n = n.to_ascii_lowercase();
        ["pass", "pwd", "secret", "credential", "apikey", "token"]
            .iter()
            .any(|k| n.contains(k))
    };
    let list: Vec<Affected> = definitions(m)
        .filter(|o| is_class(o, "attributeSchema"))
        .filter(|o| o.int("systemflags").unwrap_or(0) & BASE_SCHEMA == 0)
        .filter(|o| {
            o.str("ldapdisplayname").is_some_and(|n| {
                looks_secret(n) && !SECRET_ATTRIBUTES.iter().any(|s| s.eq_ignore_ascii_case(n))
            })
        })
        .filter(|o| o.int("searchflags").unwrap_or(0) & CONFIDENTIAL == 0)
        .map(|o| {
            schema_item(
                o,
                "Custom attribute named like a secret and readable by default: check whether an application stores credentials in it",
            )
        })
        .collect();
    out.affected(list, "attributes")
        .evidence(
            "Read from",
            ldap_from(
                m,
                "ldapDisplayName, systemFlags and searchFlags of attributeSchema",
            ),
        )
        .done()
}

fn sch_006(m: &Model) -> CheckResult {
    let out =
        check("AD-SCH-006").expected("Schema changes in the last 90 days are known and approved");
    if !full_schema(m) {
        return out.not_assessed(OLD_SCHEMA).done();
    }
    let age = |o: &LdapObject, a: &str| {
        o.str(a)
            .and_then(time::parse_iso)
            .map(|t| (m.now - t).div_euclid(time::DAY))
    };
    let mut list: Vec<(i64, Affected)> = definitions(m)
        .filter_map(|o| {
            let created = age(o, "whencreated");
            let changed = age(o, "whenchanged");
            let why = match (created, changed) {
                (Some(c), _) if c <= 90 => format!("Added {} ago", days_text(Some(c))),
                (_, Some(c)) if c <= 90 => format!("Changed {} ago", days_text(Some(c))),
                _ => return None,
            };
            Some((created.min(changed).unwrap_or(0), schema_item(o, why)))
        })
        .collect();
    list.sort_by_key(|(d, _)| *d);
    out.affected(list.into_iter().map(|(_, a)| a).collect(), "definitions")
        .evidence(
            "Read from",
            ldap_from(m, "whenCreated and whenChanged of schema definitions"),
        )
        .done()
}

// ---------- Trusts ----------

const WITHIN_FOREST: i64 = 0x20;
const FOREST_TRANSITIVE: i64 = 0x8;

fn trust_item(t: &LdapObject, reason: impl Into<String>) -> Affected {
    Affected {
        last_seen: None,
        name: t
            .str("trustpartner")
            .map(str::to_string)
            .unwrap_or_else(|| rdn_value(t.dn())),
        kind: "trustedDomain".into(),
        location: Some(t.dn().to_string()),
        reason: Some(reason.into()),
        object: None,
    }
}

fn tru_005(m: &Model) -> CheckResult {
    let list: Vec<Affected> = m
        .raw
        .trusts
        .iter()
        .filter_map(|t| {
            let why = match t.int("msds-supportedencryptiontypes") {
                None | Some(0) => {
                    "No encryption types set: referral tickets across the trust use RC4".to_string()
                }
                Some(v) if v & 0x18 == 0 => {
                    format!("Encryption types {v} have no AES: referral tickets use RC4 or DES")
                }
                _ => return None,
            };
            Some(trust_item(t, why))
        })
        .collect();
    check("AD-TRU-005")
        .expected("Every trust uses AES for Kerberos referrals")
        .found(format!(
            "{} of {} without AES",
            list.len(),
            plural(m.raw.trusts.len(), "trust", "trusts")
        ))
        .affected(list, "trusts")
        .evidence(
            "Read from",
            ldap_from(m, "msDS-SupportedEncryptionTypes of trustedDomain objects"),
        )
        .done()
}

fn tru_008(m: &Model) -> CheckResult {
    let list: Vec<Affected> = m
        .raw
        .trusts
        .iter()
        .filter(|t| t.int("trustdirection") == Some(3))
        .filter(|t| t.int("trustattributes").unwrap_or(0) & WITHIN_FOREST == 0)
        .filter(|t| t.int("trusttype") != Some(3))
        .map(|t| {
            let kind = if t.int("trustattributes").unwrap_or(0) & FOREST_TRANSITIVE != 0 {
                "Two-way forest trust"
            } else {
                "Two-way external trust"
            };
            trust_item(
                t,
                format!("{kind}: users of the other side can reach resources here, and a compromise there opens a path here"),
            )
        })
        .collect();
    check("AD-TRU-008")
        .expected("Trusts to other forests are one-way unless both directions are needed")
        .affected(list, "trusts")
        .evidence(
            "Read from",
            ldap_from(m, "trustDirection and trustAttributes"),
        )
        .done()
}

fn tru_010(m: &Model) -> CheckResult {
    let mit: Vec<String> = m
        .raw
        .trusts
        .iter()
        .filter(|t| t.int("trusttype") == Some(3))
        .map(|t| {
            format!(
                "{} (direction {}, encryption types {})",
                t.str("trustpartner").unwrap_or_default(),
                t.int("trustdirection").unwrap_or(0),
                t.int("msds-supportedencryptiontypes")
                    .map_or("not set".into(), |v| v.to_string())
            )
        })
        .collect();
    check("AD-TRU-010")
        .expected("An inventory of Kerberos realm (MIT) trusts")
        .found(plural(mit.len(), "realm trust", "realm trusts"))
        .failed(false)
        .raw(mit.join("\n"))
        .evidence(
            "Read from",
            ldap_from(m, "trustType of trustedDomain objects"),
        )
        .done()
}

fn tru_012(m: &Model) -> CheckResult {
    let trusts: Vec<(String, String)> = m
        .raw
        .trusts
        .iter()
        .filter_map(|t| {
            Some((
                t.str("securityidentifier")?.to_string(),
                t.str("trustpartner").unwrap_or_default().to_string(),
            ))
        })
        .collect();
    let mut seen = BTreeSet::new();
    let mut list = Vec::new();
    for g in m.tier0_groups() {
        for p in m.recursive_members(g) {
            let n = &m.nodes[p];
            let Some(sid) = n.sid.as_deref() else {
                continue;
            };
            if n.kind != Kind::Principal
                || !sid.starts_with("S-1-5-21-")
                || sid.starts_with(&format!("{}-", m.domain_sid))
                || !seen.insert(p)
            {
                continue;
            }
            let from = trusts
                .iter()
                .find(|(d, _)| sid.starts_with(&format!("{d}-")))
                .map(|(_, name)| format!(" from {name}"))
                .unwrap_or_else(|| " from an unknown or removed domain".into());
            list.push(Affected {
                last_seen: None,
                name: sid.to_string(),
                kind: "foreignSecurityPrincipal".into(),
                location: None,
                reason: Some(format!(
                    "Account{from} in {}: whoever controls that domain controls this one",
                    m.nodes[g].name
                )),
                object: None,
            });
        }
    }
    check("AD-TRU-012")
        .expected("No account from another domain is in a Tier 0 group")
        .affected(list, "principals")
        .evidence(
            "Read from",
            ldap_from(
                m,
                "member of Tier 0 groups and securityIdentifier of trusts",
            ),
        )
        .done()
}

// ---------- Audit ----------

const LOG_AGENTS: &[&str] = &[
    "splunk",
    "nxlog",
    "winlogbeat",
    "elastic agent",
    "wazuh",
    "ossec",
    "wincollect",
    "azure monitor agent",
    "microsoft monitoring agent",
    "sumo logic",
    "arcsight",
    "rapid7",
    "datadog",
    "graylog",
    "cribl",
    "fluent",
    "snare",
    "logrhythm",
    "qradar",
    "sentinel",
];

fn aud_005(m: &Model) -> CheckResult {
    each_dc(
        m,
        "AD-AUD-005",
        "Every DC forwards its events: a log agent is installed or Windows Event Forwarding is configured",
        "domain controllers",
        |_, d| {
            if d.software.is_none() && d.registry.is_none() {
                return Eval::Unknown(d.why_missing("software"));
            }
            let mut found: Vec<String> = d
                .software
                .iter()
                .flatten()
                .filter(|s| {
                    let n = s.name.to_ascii_lowercase();
                    LOG_AGENTS.iter().any(|a| n.contains(a))
                })
                .map(|s| s.name.clone())
                .collect();
            if let Some(wef) = d.reg_str("wef.subscriptionmanager").filter(|s| !s.is_empty()) {
                found.push(format!("Windows Event Forwarding to {wef}"));
            }
            if found.is_empty() {
                Eval::Bad("No log agent or event forwarding found: events stay on the DC, where an attacker can clear them".into())
            } else {
                Eval::Ok(found.join(", "))
            }
        },
    )
    .done()
}

fn aud_008(m: &Model) -> CheckResult {
    each_dc(
        m,
        "AD-AUD-008",
        "Sysmon runs on every DC",
        "domain controllers",
        |_, d| {
            let Some(services) = &d.services else {
                return Eval::Unknown(d.why_missing("services"));
            };
            match services
                .iter()
                .find(|s| s.name.to_ascii_lowercase().starts_with("sysmon"))
            {
                Some(s) if s.state.eq_ignore_ascii_case("Running") => {
                    Eval::Ok(format!("{} running", s.name))
                }
                Some(s) => Eval::Bad(format!("{} installed but {}", s.name, s.state.to_ascii_lowercase())),
                None => Eval::Bad("Sysmon is not installed: no process, network or registry telemetry beyond the Security log".into()),
            }
        },
    )
    .done()
}

fn aud_010(m: &Model) -> CheckResult {
    rights_check(
        m,
        "AD-AUD-010",
        "Only admins hold \"Manage auditing and security log\" on DCs",
        &[("SeSecurityPrivilege", "Manage auditing and security log")],
        (
            "audit right is granted to non-admins",
            "audit rights are granted to non-admins",
        ),
    )
}

// ---------- Applications ----------

fn group_named(m: &Model, name: &str) -> Option<usize> {
    (0..m.nodes.len())
        .find(|&i| m.nodes[i].kind == Kind::Group && m.nodes[i].name.eq_ignore_ascii_case(name))
}

fn app_001(m: &Model) -> CheckResult {
    let out = check("AD-APP-001")
        .expected("Exchange Windows Permissions cannot change permissions on the domain head (PrivExchange fix applied)");
    let Some(ewp) = group_named(m, "Exchange Windows Permissions") else {
        return out.found("No Exchange groups in this domain").done();
    };
    let sid = m.nodes[ewp].sid.clone().unwrap_or_default();
    let head = m.raw.acls.iter().find(|o| is_class(o, "domainDNS"));
    let Some(sd) = head
        .and_then(|o| o.str("ntsecuritydescriptor"))
        .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())
        .and_then(|b| sd::parse(&b))
    else {
        return out
            .not_assessed("The security descriptor of the domain head was not returned.")
            .done();
    };
    let bad = sd.dacl.iter().any(|a| {
        a.kind == AceType::Allow
            && a.sid == sid
            && !a.inherit_only()
            && a.mask & (right::WRITE_DACL | right::GENERIC_ALL) != 0
    });
    let list = if bad {
        vec![item(
            m,
            ewp,
            "Can modify permissions on the domain head: any Exchange server, or anyone who relays its authentication, can grant itself DCSync",
        )]
    } else {
        Vec::new()
    };
    out.found(if bad {
        "WriteDACL on the domain head"
    } else {
        "No WriteDACL on the domain head"
    })
    .affected(list, "groups")
    .evidence(
        "Read from",
        ldap_from(m, "nTSecurityDescriptor of the domain head"),
    )
    .done()
}

fn app_002(m: &Model) -> CheckResult {
    let groups: Vec<usize> = ["Exchange Windows Permissions", "Exchange Trusted Subsystem"]
        .iter()
        .filter_map(|n| group_named(m, n))
        .collect();
    let mut list = Vec::new();
    for &g in &groups {
        for &u in m.members.get(g).into_iter().flatten() {
            if m.nodes[u].kind == Kind::User {
                list.push(item(
                    m,
                    u,
                    format!(
                        "User in {}: holds the rights Exchange servers have over every account",
                        m.nodes[g].name
                    ),
                ));
            }
        }
    }
    let mut out = check("AD-APP-002")
        .expected("Exchange Windows Permissions and Exchange Trusted Subsystem contain only Exchange servers and groups")
        .affected(list, "accounts");
    if groups.is_empty() {
        out = out.found("No Exchange groups in this domain");
    }
    out.evidence("Read from", ldap_from(m, "member of Exchange groups"))
        .done()
}

fn app_006(m: &Model) -> CheckResult {
    let privileged = m.privileged_users();
    let mut inventory = Vec::new();
    let mut list = Vec::new();
    for u in (0..m.nodes.len()).filter(|&u| m.nodes[u].kind == Kind::User) {
        let n = &m.nodes[u];
        let name = n.name.to_ascii_lowercase();
        let desc = n
            .attrs
            .str("description")
            .unwrap_or_default()
            .to_ascii_lowercase();
        let connect = name.starts_with("msol_")
            || name.starts_with("sync_")
            || name.starts_with("aad_")
            || desc.contains("azure ad connect")
            || desc.contains("azure active directory connect")
            || desc.contains("entra connect");
        if !connect {
            continue;
        }
        inventory.push(n.name.clone());
        let mut why = Vec::new();
        if privileged.contains_key(&u) {
            why.push("member of a privileged group, which Entra Connect does not need".to_string());
        }
        let idle = m.days_since(n.last_logon);
        if n.enabled() && idle.is_none_or(|d| d > 90) {
            why.push(format!(
                "no sign-in for {}: the sync server may be gone while the account keeps its replication rights",
                days_text(idle)
            ));
        }
        if !why.is_empty() {
            list.push(item(m, u, why.join("; ")));
        }
    }
    check("AD-APP-006")
        .expected("Entra Connect accounts are in use and hold only the rights sync needs")
        .found(format!(
            "{} of {} need attention",
            list.len(),
            plural(
                inventory.len(),
                "Entra Connect account",
                "Entra Connect accounts"
            )
        ))
        .affected(list, "accounts")
        .raw(inventory.join("\n"))
        .evidence(
            "Read from",
            ldap_from(m, "users named or described as Entra Connect accounts"),
        )
        .done()
}

pub static RULES: &[Rule] = &[
    Rule {
        id: "AD-SCH-001",
        needs: &["schema"],
        run: sch_001,
    },
    Rule {
        id: "AD-SCH-002",
        needs: &["schema"],
        run: sch_002,
    },
    Rule {
        id: "AD-SCH-006",
        needs: &["schema"],
        run: sch_006,
    },
    Rule {
        id: "AD-TRU-005",
        needs: &["trusts"],
        run: tru_005,
    },
    Rule {
        id: "AD-TRU-008",
        needs: &["trusts"],
        run: tru_008,
    },
    Rule {
        id: "AD-TRU-010",
        needs: &["trusts"],
        run: tru_010,
    },
    Rule {
        id: "AD-TRU-012",
        needs: &["groups", "trusts"],
        run: tru_012,
    },
    Rule {
        id: "AD-AUD-005",
        needs: &["dcconfig"],
        run: aud_005,
    },
    Rule {
        id: "AD-AUD-008",
        needs: &["dcconfig"],
        run: aud_008,
    },
    Rule {
        id: "AD-AUD-010",
        needs: &["sysvol", "gpos", "containers", "groups"],
        run: aud_010,
    },
    Rule {
        id: "AD-APP-001",
        needs: &["groups", "acls"],
        run: app_001,
    },
    Rule {
        id: "AD-APP-002",
        needs: &["groups", "users"],
        run: app_002,
    },
    Rule {
        id: "AD-APP-006",
        needs: &["users", "groups"],
        run: app_006,
    },
];
