//! Account, computer and LAPS hygiene: leftovers, duplicates, weak
//! certificate mappings, key credentials, BitLocker escrow and how LAPS is
//! configured and who can read it.

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine;

use super::model::{guid, rdn_value, uac, well_known_name, Kind, Model};
use super::raw::SysvolPolicy;
use super::rules::{check, days_text, is_krbtgt, item, laps_schema, plural, Rule};
use super::rules_gpo::{
    applies_to_dcs, gpo_name, not_read, read_from as sysvol_from, read_policies,
};
use super::sd::{self, right, AceType};
use crate::results::{Affected, CheckResult};

const INHERIT_CONTAINER: u8 = 0x02;

fn ldap_from(m: &Model, what: &str) -> String {
    format!(
        "{what} via LDAP on {} as {}",
        m.raw.info.server, m.raw.info.account
    )
}

fn of_kind<'a>(m: &'a Model<'a>, kind: Kind) -> impl Iterator<Item = usize> + 'a {
    (0..m.nodes.len()).filter(move |&i| m.nodes[i].kind == kind)
}

/// Groups that list `u` as a direct member.
fn groups_of(m: &Model, u: usize) -> Vec<usize> {
    (0..m.nodes.len())
        .filter(|&g| {
            m.nodes[g].kind == Kind::Group && m.members.get(g).is_some_and(|x| x.contains(&u))
        })
        .collect()
}

// ---------- Accounts ----------

fn acc_003(m: &Model) -> CheckResult {
    let list: Vec<Affected> = of_kind(m, Kind::User)
        .filter(|&u| {
            let n = &m.nodes[u];
            !n.enabled() && !is_krbtgt(m, u) && n.rid() != Some(501)
        })
        .filter_map(|u| {
            let n = &m.nodes[u];
            let last = m.days_since(n.last_logon.or(n.created))?;
            if last <= 365 {
                return None;
            }
            let groups: Vec<String> = groups_of(m, u)
                .into_iter()
                .filter(|&g| m.nodes[g].rid() != Some(513))
                .map(|g| m.nodes[g].name.clone())
                .collect();
            let mut why = format!("Disabled, last sign-in {} ago", days_text(Some(last)));
            if !groups.is_empty() {
                why.push_str(&format!(
                    "; still in {}: re-enabling it restores that access",
                    groups.join(", ")
                ));
            }
            Some(item(m, u, why))
        })
        .collect();
    check("AD-ACC-003")
        .expected(
            "Accounts disabled for over a year are deleted, or at least removed from their groups",
        )
        .affected(list, "accounts")
        .evidence(
            "Read from",
            ldap_from(
                m,
                "userAccountControl, lastLogonTimestamp and group membership",
            ),
        )
        .done()
}

fn acc_008(m: &Model) -> CheckResult {
    let mut by_name: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for u in of_kind(m, Kind::User).filter(|&u| m.nodes[u].enabled()) {
        if let Some(d) = m.nodes[u]
            .attrs
            .str("displayname")
            .filter(|d| !d.trim().is_empty())
        {
            by_name.entry(d.trim().to_lowercase()).or_default().push(u);
        }
    }
    let list: Vec<Affected> = by_name
        .values()
        .filter(|v| v.len() > 1)
        .flat_map(|v| {
            v.iter().map(|&u| {
                let others: Vec<&str> = v
                    .iter()
                    .filter(|&&o| o != u)
                    .map(|&o| m.nodes[o].name.as_str())
                    .collect();
                item(
                    m,
                    u,
                    format!(
                        "Same display name as {}: one person with several enabled accounts, or a leftover",
                        others.join(", ")
                    ),
                )
            })
        })
        .collect();
    check("AD-ACC-008")
        .expected("Each enabled user has a distinct display name")
        .affected(list, "accounts")
        .evidence("Read from", ldap_from(m, "displayName of enabled users"))
        .done()
}

fn acc_011(m: &Model) -> CheckResult {
    let list: Vec<Affected> = of_kind(m, Kind::Computer)
        .filter(|&c| {
            let n = &m.nodes[c];
            n.enabled() && n.flag(uac::PASSWD_NOTREQD) && n.last_logon.is_none() && !n.is_dc()
        })
        .map(|c| {
            item(
                m,
                c,
                "Enabled, never signed in, password not required: created as a pre-Windows 2000 computer, its password is likely the lowercase computer name",
            )
        })
        .collect();
    check("AD-ACC-011")
        .expected("No enabled computer account was pre-created without a password and never used")
        .affected(list, "computers")
        .evidence(
            "Read from",
            ldap_from(m, "userAccountControl and lastLogonTimestamp of computers"),
        )
        .done()
}

/// The mapping type of an altSecurityIdentities value and whether
/// KB5014754 counts it as strong.
fn mapping(v: &str) -> (&'static str, bool) {
    let u = v.to_ascii_uppercase();
    if !u.starts_with("X509:") {
        return ("Kerberos name", false);
    }
    if u.contains("<SKI>") {
        ("SubjectKeyIdentifier", true)
    } else if u.contains("<SHA1-PUKEY>") {
        ("SHA1 public key", true)
    } else if u.contains("<I>") && u.contains("<SR>") {
        ("Issuer and serial number", true)
    } else if u.contains("<I>") && u.contains("<S>") {
        ("Issuer and subject", false)
    } else if u.contains("<RFC822>") {
        ("RFC822 email", false)
    } else if u.contains("<S>") {
        ("Subject only", false)
    } else {
        ("Unknown X509 form", false)
    }
}

fn acc_012(m: &Model) -> CheckResult {
    let mut strong = 0;
    let mut list = Vec::new();
    for i in (0..m.nodes.len()).filter(|&i| matches!(m.nodes[i].kind, Kind::User | Kind::Computer))
    {
        let values = m.nodes[i].attrs.strs("altsecurityidentities");
        let weak: BTreeSet<&str> = values
            .iter()
            .map(|v| mapping(v))
            .filter(|(kind, ok)| {
                if *ok {
                    strong += 1;
                }
                !ok && *kind != "Kerberos name"
            })
            .map(|(kind, _)| kind)
            .collect();
        if !weak.is_empty() {
            list.push(item(
                m,
                i,
                format!(
                    "Weak certificate mapping ({}): anyone who gets a certificate with a matching name signs in as this account",
                    weak.into_iter().collect::<Vec<_>>().join(", ")
                ),
            ));
        }
    }
    check("AD-ACC-012")
        .expected("Explicit certificate mappings use strong forms (issuer and serial, SKI or SHA1 public key)")
        .affected(list, "accounts")
        .evidence("Strong mappings", strong.to_string())
        .evidence("Read from", ldap_from(m, "altSecurityIdentities"))
        .done()
}

fn acc_013(m: &Model) -> CheckResult {
    let privileged = m.privileged_users();
    let mut list = Vec::new();
    let mut others = 0;
    for o in &m.raw.keycreds {
        let Some(&i) = m.by_dn.get(&o.dn().to_ascii_lowercase()) else {
            others += 1;
            continue;
        };
        let n = &m.nodes[i];
        let sensitive = privileged.contains_key(&i) || (n.tier0 && !n.is_dc());
        if sensitive {
            list.push(item(
                m,
                i,
                "Has key credentials: if they were not added by Windows Hello for Business, someone can sign in as this account with their own key (Shadow Credentials)",
            ));
        } else {
            others += 1;
        }
    }
    check("AD-ACC-013")
        .expected("No admin or Tier 0 account has key credentials it does not use")
        .affected(list, "accounts")
        .evidence("Other accounts with key credentials", others.to_string())
        .evidence(
            "Note",
            "Only which accounts have msDS-KeyCredentialLink was collected, never the keys",
        )
        .evidence("Read from", ldap_from(m, "(msDS-KeyCredentialLink=*)"))
        .done()
}

fn acc_016(m: &Model) -> CheckResult {
    let list: Vec<Affected> = of_kind(m, Kind::Group)
        .filter(|&g| {
            let n = &m.nodes[g];
            n.rid().is_some_and(|r| r >= 1000)
                && n.sid
                    .as_deref()
                    .is_some_and(|s| s.starts_with(&m.domain_sid))
                && m.members.get(g).is_none_or(Vec::is_empty)
                && n.attrs.int("admincount") != Some(1)
        })
        .map(|g| item(m, g, "No members: remove it, or record why it exists"))
        .collect();
    check("AD-ACC-016")
        .expected("Custom groups have members or a documented purpose")
        .affected(list, "groups")
        .evidence("Read from", ldap_from(m, "member of groups"))
        .done()
}

// ---------- Computers ----------

fn cmp_002(m: &Model) -> CheckResult {
    let mut by_os: BTreeMap<String, usize> = BTreeMap::new();
    let mut total = 0;
    for c in of_kind(m, Kind::Computer).filter(|&c| m.nodes[c].enabled()) {
        total += 1;
        let os = m.nodes[c]
            .attrs
            .str("operatingsystem")
            .unwrap_or("Unknown")
            .to_string();
        *by_os.entry(os).or_default() += 1;
    }
    let mut rows: Vec<(String, usize)> = by_os.into_iter().collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let raw: Vec<String> = rows.iter().map(|(os, n)| format!("{n}  {os}")).collect();
    check("AD-CMP-002")
        .expected("An inventory of operating systems on enabled computers")
        .found(format!(
            "{} across {}",
            plural(rows.len(), "operating system", "operating systems"),
            plural(total, "enabled computer", "enabled computers")
        ))
        .failed(false)
        .raw(raw.join("\n"))
        .evidence("Read from", ldap_from(m, "operatingSystem of computers"))
        .done()
}

fn cmp_006(m: &Model) -> CheckResult {
    let escrowed: BTreeSet<String> = m
        .raw
        .bitlocker
        .iter()
        .filter_map(|o| super::model::parent_dn(o.dn()))
        .map(str::to_ascii_lowercase)
        .collect();
    let workstations: Vec<usize> = of_kind(m, Kind::Computer)
        .filter(|&c| {
            let n = &m.nodes[c];
            n.enabled()
                && !n.is_dc()
                && n.attrs
                    .str("operatingsystem")
                    .is_some_and(|o| o.contains("Windows") && !o.contains("Server"))
        })
        .collect();
    let list: Vec<Affected> = workstations
        .iter()
        .filter(|&&c| !escrowed.contains(&m.nodes[c].dn.to_ascii_lowercase()))
        .map(|&c| item(m, c, "No BitLocker recovery key stored in AD"))
        .collect();
    let mut out = check("AD-CMP-006")
        .expected("Every Windows workstation has a BitLocker recovery key stored in AD")
        .found(format!(
            "{} of {} without a recovery key",
            list.len(),
            plural(workstations.len(), "workstation", "workstations")
        ))
        .affected(list, "computers");
    if m.raw.bitlocker.is_empty() {
        out = out.evidence(
            "Note",
            "No recovery object was visible at all; the collecting account may not be allowed to read them, or keys are stored in Entra ID or Intune instead",
        );
    }
    out.evidence(
        "Read from",
        ldap_from(m, "msFVE-RecoveryInformation objects (location only)"),
    )
    .done()
}

// ---------- LAPS ----------

const WINDOWS_LAPS: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\LAPS";
const LEGACY_LAPS: &str = "Software\\Policies\\Microsoft Services\\AdmPwd";

fn laps_value(p: &SysvolPolicy, key: &str, value: &str) -> Option<i64> {
    p.policy("Machine", key, value).and_then(|v| v.int())
}

/// GPOs that back up Windows LAPS passwords to AD (BackupDirectory = 2).
fn laps_to_ad<'a>(policies: &[&'a SysvolPolicy]) -> Vec<&'a SysvolPolicy> {
    policies
        .iter()
        .filter(|p| laps_value(p, WINDOWS_LAPS, "BackupDirectory") == Some(2))
        .copied()
        .collect()
}

fn laps_004(m: &Model) -> CheckResult {
    let expected = "Windows LAPS GPOs that back up to AD keep password encryption on";
    let policies = read_policies(m);
    if let Some(r) = not_read(check("AD-LAPS-004").expected(expected), &policies) {
        return r;
    }
    let to_ad = laps_to_ad(&policies);
    if to_ad.is_empty() {
        return check("AD-LAPS-004")
            .expected(expected)
            .not_assessed("No GPO backs up Windows LAPS passwords to AD; they may be managed by Intune or not used.")
            .done();
    }
    let list: Vec<Affected> = to_ad
        .iter()
        .filter(|p| laps_value(p, WINDOWS_LAPS, "ADPasswordEncryptionEnabled") == Some(0))
        .map(|p| Affected {
            last_seen: None,
            name: gpo_name(m, p),
            kind: "gpo".into(),
            location: None,
            reason: Some(
                "Password encryption turned off: the password is stored in clear text in msLAPS-Password".into(),
            ),
            object: None,
        })
        .collect();
    check("AD-LAPS-004")
        .expected(expected)
        .found(format!(
            "{} of {} turn encryption off",
            list.len(),
            plural(to_ad.len(), "LAPS GPO", "LAPS GPOs")
        ))
        .affected(list, "GPOs")
        .evidence("Read from", format!("Registry.pol in {}", sysvol_from(m)))
        .done()
}

fn laps_005(m: &Model) -> CheckResult {
    let expected =
        "LAPS GPOs use passwords of 14+ characters, full complexity and rotation within 30 days";
    let policies = read_policies(m);
    if let Some(r) = not_read(check("AD-LAPS-005").expected(expected), &policies) {
        return r;
    }
    let mut seen = 0;
    let mut list = Vec::new();
    for p in &policies {
        for (key, label) in [(WINDOWS_LAPS, "Windows LAPS"), (LEGACY_LAPS, "Legacy LAPS")] {
            let length = laps_value(p, key, "PasswordLength");
            let complexity = laps_value(p, key, "PasswordComplexity");
            let age = laps_value(p, key, "PasswordAgeDays");
            if length.is_none() && complexity.is_none() && age.is_none() {
                continue;
            }
            seen += 1;
            let mut why = Vec::new();
            if let Some(l) = length.filter(|l| *l < 14) {
                why.push(format!("length {l}"));
            }
            if let Some(c) = complexity.filter(|c| *c < 4) {
                why.push(format!("complexity {c} of 4"));
            }
            if let Some(a) = age.filter(|a| *a > 30) {
                why.push(format!("rotation every {a} days"));
            }
            if !why.is_empty() {
                list.push(Affected {
                    last_seen: None,
                    name: gpo_name(m, p),
                    kind: "gpo".into(),
                    location: None,
                    reason: Some(format!("{label}: {}", why.join(", "))),
                    object: None,
                });
            }
        }
    }
    if seen == 0 {
        return check("AD-LAPS-005")
            .expected(expected)
            .not_assessed("No GPO sets LAPS password length, complexity or age; the built-in defaults apply, or LAPS is managed elsewhere.")
            .done();
    }
    check("AD-LAPS-005")
        .expected(expected)
        .found(
            plural(list.len(), "LAPS policy is", "LAPS policies are") + " weaker than recommended",
        )
        .affected(list, "GPOs")
        .evidence("Read from", format!("Registry.pol in {}", sysvol_from(m)))
        .done()
}

fn laps_006(m: &Model) -> CheckResult {
    let expected = "A Windows LAPS GPO that applies to DCs backs up the DSRM password to AD";
    let policies = read_policies(m);
    if let Some(r) = not_read(check("AD-LAPS-006").expected(expected), &policies) {
        return r;
    }
    let by: Vec<String> = laps_to_ad(&policies)
        .into_iter()
        .filter(|p| applies_to_dcs(m, p))
        .map(|p| gpo_name(m, p))
        .collect();
    let list = if by.is_empty() {
        vec![Affected {
            last_seen: None,
            name: "DSRM password".into(),
            kind: "setting".into(),
            location: None,
            reason: Some(
                "Not managed by Windows LAPS: the DSRM password is set by hand and rarely changed, and it opens every DC it is shared with".into(),
            ),
            object: None,
        }]
    } else {
        Vec::new()
    };
    let mut out = check("AD-LAPS-006")
        .expected(expected)
        .found(if by.is_empty() {
            "Not managed"
        } else {
            "Managed"
        })
        .affected(list, "settings");
    if !by.is_empty() {
        out = out.evidence("Set by", by.join(", "));
    }
    out.evidence("Read from", format!("Registry.pol in {}", sysvol_from(m)))
        .done()
}

fn laps_007(m: &Model) -> CheckResult {
    let expected = "Only admins and designated groups can read LAPS passwords";
    let (legacy, windows) = laps_schema(m);
    if !legacy && !windows {
        return check("AD-LAPS-007")
            .expected(expected)
            .found("LAPS is not in the schema")
            .done();
    }
    let laps_guids: BTreeSet<String> = m
        .raw
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
        .collect();
    let computer = guid::class("computer").unwrap_or_default();
    let mut readers: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for o in m.raw.acls.iter().filter(|o| {
        o.strs("objectclass").iter().any(|c| {
            c.eq_ignore_ascii_case("organizationalUnit") || c.eq_ignore_ascii_case("domainDNS")
        })
    }) {
        let Some(sd) = o
            .str("ntsecuritydescriptor")
            .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())
            .and_then(|b| sd::parse(&b))
        else {
            continue;
        };
        for a in sd.dacl.iter().filter(|a| {
            a.kind == AceType::Allow
                && a.flags & INHERIT_CONTAINER != 0
                && a.inherited_object_type
                    .as_deref()
                    .is_none_or(|t| t.eq_ignore_ascii_case(computer))
        }) {
            if m.is_default_admin(&a.sid)
                || m.by_sid(&a.sid).is_some_and(|i| m.nodes[i].tier0)
                || a.sid == "S-1-5-10"
            {
                continue;
            }
            let on_laps = a
                .object_type
                .as_deref()
                .is_some_and(|t| laps_guids.contains(&t.to_ascii_lowercase()));
            let reads = a.mask & right::GENERIC_ALL != 0
                || (a.mask & right::CONTROL_ACCESS != 0 && (a.object_type.is_none() || on_laps))
                || (a.mask & 0x10 != 0 && on_laps);
            if !reads {
                continue;
            }
            let who = m
                .by_sid(&a.sid)
                .map(|i| m.nodes[i].name.clone())
                .or_else(|| well_known_name(&a.sid).map(str::to_string))
                .unwrap_or_else(|| a.sid.clone());
            readers.entry(who).or_default().insert(rdn_value(o.dn()));
        }
    }
    let list: Vec<Affected> = readers
        .into_iter()
        .map(|(who, ous)| Affected {
            last_seen: None,
            name: who,
            kind: "principal".into(),
            location: None,
            reason: Some(format!(
                "Can read LAPS passwords of computers in {}",
                ous.into_iter().collect::<Vec<_>>().join(", ")
            )),
            object: None,
        })
        .collect();
    check("AD-LAPS-007")
        .expected(expected)
        .found(
            plural(
                list.len(),
                "non-admin principal can",
                "non-admin principals can",
            ) + " read LAPS passwords",
        )
        .affected(list, "principals")
        .evidence(
            "Note",
            "Review that each principal is meant to read local admin passwords there",
        )
        .evidence(
            "Read from",
            ldap_from(m, "inheritable ACEs on OUs and the domain head"),
        )
        .done()
}

pub static RULES: &[Rule] = &[
    Rule {
        id: "AD-ACC-003",
        needs: &["users", "groups"],
        run: acc_003,
    },
    Rule {
        id: "AD-ACC-008",
        needs: &["users"],
        run: acc_008,
    },
    Rule {
        id: "AD-ACC-011",
        needs: &["computers"],
        run: acc_011,
    },
    Rule {
        id: "AD-ACC-012",
        needs: &["users", "computers"],
        run: acc_012,
    },
    Rule {
        id: "AD-ACC-013",
        needs: &["keycreds", "users", "groups"],
        run: acc_013,
    },
    Rule {
        id: "AD-ACC-016",
        needs: &["groups"],
        run: acc_016,
    },
    Rule {
        id: "AD-CMP-002",
        needs: &["computers"],
        run: cmp_002,
    },
    Rule {
        id: "AD-CMP-006",
        needs: &["computers", "bitlocker"],
        run: cmp_006,
    },
    Rule {
        id: "AD-LAPS-004",
        needs: &["sysvol"],
        run: laps_004,
    },
    Rule {
        id: "AD-LAPS-005",
        needs: &["sysvol"],
        run: laps_005,
    },
    Rule {
        id: "AD-LAPS-006",
        needs: &["sysvol", "gpos", "containers"],
        run: laps_006,
    },
    Rule {
        id: "AD-LAPS-007",
        needs: &["schema", "acls", "groups"],
        run: laps_007,
    },
];
