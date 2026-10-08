//! On-premises checks that run on what LDAP and SYSVOL return. Each rule
//! names the collector areas it reads; when one of them was not collected
//! the check is reported as not assessed, with the reason.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use super::model::{self, uac, Kind, Model};
use crate::catalog::Severity;
use crate::results::{Affected, CheckResult, Evidence, ResultStatus};
use crate::time;

pub struct Rule {
    pub id: &'static str,
    /// Collector areas the rule reads (see `raw::LDAP_AREAS` and `sysvol`).
    pub needs: &'static [&'static str],
    pub run: fn(&Model) -> CheckResult,
}

/// At most this many affected objects are listed; the count is always exact.
const MAX_LISTED: usize = 1000;
const STALE_DAYS: i64 = 90;

pub(crate) struct Out(pub(crate) CheckResult);

pub(crate) fn check(id: &str) -> Out {
    Out(CheckResult {
        id: id.to_string(),
        status: ResultStatus::Passed,
        severity: None,
        affected_count: None,
        affected_unit: None,
        affected: Vec::new(),
        expected: None,
        found: None,
        evidence: Vec::new(),
        raw: None,
        note: None,
    })
}

impl Out {
    pub(crate) fn failed(mut self, failed: bool) -> Self {
        self.0.status = if failed {
            ResultStatus::Failed
        } else {
            ResultStatus::Passed
        };
        self
    }

    pub(crate) fn not_assessed(mut self, note: impl Into<String>) -> Self {
        self.0.status = ResultStatus::NotAssessed;
        self.0.note = Some(note.into());
        self
    }

    pub(crate) fn expected(mut self, s: impl Into<String>) -> Self {
        self.0.expected = Some(s.into());
        self
    }

    pub(crate) fn found(mut self, s: impl Into<String>) -> Self {
        self.0.found = Some(s.into());
        self
    }

    pub(crate) fn severity(mut self, s: Severity) -> Self {
        self.0.severity = Some(s);
        self
    }

    pub(crate) fn evidence(mut self, label: &str, value: impl Into<String>) -> Self {
        self.0.evidence.push(Evidence {
            label: label.to_string(),
            value: value.into(),
        });
        self
    }

    pub(crate) fn raw(mut self, s: impl Into<String>) -> Self {
        self.0.raw = Some(s.into());
        self
    }

    /// Fails when `list` is not empty, and records it.
    pub(crate) fn affected(mut self, mut list: Vec<Affected>, unit: &str) -> Self {
        self.0.status = if list.is_empty() {
            ResultStatus::Passed
        } else {
            ResultStatus::Failed
        };
        self.0.affected_count = Some(list.len() as u64);
        self.0.affected_unit = Some(unit.to_string());
        list.truncate(MAX_LISTED);
        self.0.affected = list;
        self
    }

    pub(crate) fn done(self) -> CheckResult {
        self.0
    }
}

pub(crate) fn item(m: &Model, i: usize, reason: impl Into<String>) -> Affected {
    let n = &m.nodes[i];
    Affected {
        last_seen: None,
        name: n.name.clone(),
        kind: n.kind.ui().to_string(),
        location: (!n.dn.is_empty()).then(|| n.dn.clone()),
        reason: Some(reason.into()),
        object: Some(n.id.clone()),
    }
}

pub(crate) fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

pub(crate) fn days_text(d: Option<i64>) -> String {
    match d {
        Some(d) => plural(d.max(0) as usize, "day", "days"),
        None => "never".into(),
    }
}

fn of_kind<'a>(m: &'a Model<'a>, kind: Kind) -> impl Iterator<Item = usize> + 'a {
    (0..m.nodes.len()).filter(move |&i| m.nodes[i].kind == kind)
}

fn enabled_users<'a>(m: &'a Model<'a>) -> impl Iterator<Item = usize> + 'a {
    of_kind(m, Kind::User).filter(move |&i| m.nodes[i].enabled())
}

pub(super) fn is_krbtgt(m: &Model, i: usize) -> bool {
    m.nodes[i].rid() == Some(502) || m.nodes[i].name.to_ascii_lowercase().starts_with("krbtgt")
}

fn read_from(m: &Model) -> String {
    format!("LDAP on {} as {}", m.raw.info.server, m.raw.info.account)
}

fn group_names(m: &Model, groups: &[usize]) -> String {
    let mut names: Vec<&str> = groups.iter().map(|&g| m.nodes[g].name.as_str()).collect();
    names.sort();
    names.dedup();
    names.join(", ")
}

// ---------- Forest and domain ----------

fn level_name(level: i64) -> &'static str {
    match level {
        0 => "Windows 2000",
        1 => "Windows Server 2003 interim",
        2 => "Windows Server 2003",
        3 => "Windows Server 2008",
        4 => "Windows Server 2008 R2",
        5 => "Windows Server 2012",
        6 => "Windows Server 2012 R2",
        7 => "Windows Server 2016",
        10 => "Windows Server 2025",
        _ => "unknown",
    }
}

fn functional_level(m: &Model, id: &str, attr: &str, what: &str) -> CheckResult {
    let out = check(id).expected(format!(
        "{what} functional level Windows Server 2016 or later"
    ));
    let Some(level) = m
        .raw
        .info
        .rootdse
        .get(attr)
        .and_then(|v| v.parse::<i64>().ok())
    else {
        return out
            .not_assessed(format!("RootDSE did not return {attr}."))
            .done();
    };
    out.failed(level < 7)
        .found(format!("{} ({level})", level_name(level)))
        .evidence("Read from", format!("RootDSE of {}", m.raw.info.server))
        .raw(format!("{attr}: {level}"))
        .done()
}

fn fnd_001(m: &Model) -> CheckResult {
    functional_level(m, "AD-FND-001", "forestfunctionality", "Forest")
}

fn fnd_002(m: &Model) -> CheckResult {
    functional_level(m, "AD-FND-002", "domainfunctionality", "Domain")
}

fn fnd_007(m: &Model) -> CheckResult {
    let ds = m.raw.dirservice.first();
    let set = ds.and_then(|d| d.int("tombstonelifetime"));
    // Unset means the 60-day default of forests created before Windows Server 2003 SP1.
    let days = set.unwrap_or(60);
    check("AD-FND-007")
        .failed(days < 180)
        .expected("180 days or more")
        .found(match set {
            Some(d) => plural(d as usize, "day", "days"),
            None => "Not set, so the 60-day default applies".into(),
        })
        .evidence(
            "Read from",
            "tombstoneLifetime on CN=Directory Service,CN=Windows NT,CN=Services",
        )
        .raw(format!(
            "tombstoneLifetime: {}",
            set.map(|d| d.to_string())
                .unwrap_or_else(|| "<not set>".into())
        ))
        .done()
}

fn fnd_008(m: &Model) -> CheckResult {
    let container = m.raw.partitions.iter().find(|p| {
        p.values("objectclass")
            .iter()
            .any(|v| v == "crossRefContainer")
    });
    let features = container
        .map(|c| c.strs("msds-enabledfeature"))
        .unwrap_or_default();
    let on = features
        .iter()
        .any(|f| f.to_ascii_lowercase().starts_with("cn=recycle bin feature"));
    check("AD-FND-008")
        .failed(!on)
        .expected("Recycle Bin optional feature enabled")
        .found(if on { "Enabled" } else { "Not enabled" })
        .evidence("Read from", "msDS-EnabledFeature on CN=Partitions")
        .raw(if features.is_empty() {
            "msDS-EnabledFeature: <empty>".into()
        } else {
            features.join("\n")
        })
        .done()
}

fn fnd_011(m: &Model) -> CheckResult {
    let value = m
        .raw
        .dirservice
        .first()
        .and_then(|d| d.str("dsheuristics"))
        .unwrap_or_default()
        .to_string();
    let at = |pos: usize| value.chars().nth(pos - 1);
    let mut problems = Vec::new();
    if at(7) == Some('2') {
        problems.push("Anonymous LDAP operations are allowed (7th character is 2)".to_string());
    }
    if let Some(c) = at(16).filter(|c| *c != '0') {
        problems.push(format!(
            "Operator groups are excluded from AdminSDHolder protection (16th character is {c})"
        ));
    }
    if at(3) == Some('1') {
        problems.push(
            "List Object mode is on (3rd character is 1); review that it is intended".to_string(),
        );
    }
    check("AD-FND-011")
        .failed(!problems.is_empty())
        .expected("No anonymous access and no AdminSDHolder exclusions in dSHeuristics")
        .found(if problems.is_empty() {
            "No risky flags set".to_string()
        } else {
            problems.join(". ")
        })
        .evidence(
            "Read from",
            "dSHeuristics on CN=Directory Service,CN=Windows NT,CN=Services",
        )
        .raw(format!(
            "dSHeuristics: {}",
            if value.is_empty() {
                "<not set>"
            } else {
                &value
            }
        ))
        .done()
}

fn fnd_012(m: &Model) -> CheckResult {
    let quota = m
        .raw
        .domain
        .first()
        .and_then(|d| d.int("ms-ds-machineaccountquota"));
    let out = check("AD-FND-012").expected("0, so only delegated accounts can join computers");
    match quota {
        None => out
            .not_assessed("ms-DS-MachineAccountQuota was not returned for the domain head.")
            .done(),
        Some(q) => out
            .failed(q > 0)
            .found(format!(
                "{q}: any user can join {q} computers to the domain"
            ))
            .evidence("Read from", read_from(m))
            .raw(format!("ms-DS-MachineAccountQuota: {q}"))
            .done(),
    }
}

// ---------- Privileged groups ----------

fn group_should_be_empty(
    m: &Model,
    id: &str,
    rids: &[u32],
    builtin: &[&str],
    names: &[&str],
    why: &str,
) -> CheckResult {
    let mut groups: Vec<usize> = rids.iter().filter_map(|&r| m.group_by_rid(r)).collect();
    groups.extend(builtin.iter().filter_map(|s| m.by_sid(s)));
    groups.extend(names.iter().filter_map(|n| m.group_by_name(n)));
    if groups.is_empty() {
        return check(id)
            .not_assessed("The group is not in this domain. Enterprise Admins and Schema Admins exist only in the forest root domain.")
            .done();
    }
    let mut list = Vec::new();
    for &g in &groups {
        for mbr in m.recursive_members(g) {
            if m.nodes[mbr].kind == Kind::Group {
                continue;
            }
            let direct = m.members[g].contains(&mbr);
            let how = if direct {
                "Direct member"
            } else {
                "Member through a nested group"
            };
            list.push(item(m, mbr, format!("{how} of {}", m.nodes[g].name)));
        }
    }
    let total = list.len();
    check(id)
        .affected(list, "members")
        .expected(format!("Empty: {why}"))
        .found(format!(
            "{} in {}",
            plural(total, "member", "members"),
            group_names(m, &groups)
        ))
        .evidence("Read from", read_from(m))
        .done()
}

fn priv_001(m: &Model) -> CheckResult {
    group_should_be_empty(
        m,
        "AD-PRIV-001",
        &[519],
        &[],
        &[],
        "add members only for forest-level changes, then remove them",
    )
}

fn priv_002(m: &Model) -> CheckResult {
    group_should_be_empty(
        m,
        "AD-PRIV-002",
        &[518],
        &[],
        &[],
        "add members only while changing the schema",
    )
}

fn priv_003(m: &Model) -> CheckResult {
    const THRESHOLD: usize = 5;
    let Some(da) = m.group_by_rid(512) else {
        return check("AD-PRIV-003")
            .not_assessed("Domain Admins was not found.")
            .done();
    };
    let users: Vec<usize> = m
        .recursive_members(da)
        .into_iter()
        .filter(|&u| m.nodes[u].kind == Kind::User && m.nodes[u].enabled())
        .collect();
    let n = users.len();
    let list = if n > THRESHOLD {
        users
            .iter()
            .map(|&u| {
                item(
                    m,
                    u,
                    if m.members[da].contains(&u) {
                        "Direct member"
                    } else {
                        "Member through a nested group"
                    },
                )
            })
            .collect()
    } else {
        Vec::new()
    };
    let mut out = check("AD-PRIV-003")
        .affected(list, "accounts")
        .expected(format!("{THRESHOLD} or fewer enabled accounts"))
        .found(plural(n, "enabled account", "enabled accounts"))
        .evidence("Read from", read_from(m));
    if n > 2 * THRESHOLD {
        out = out.severity(Severity::High);
    }
    out.done()
}

fn priv_005(m: &Model) -> CheckResult {
    group_should_be_empty(
        m,
        "AD-PRIV-005",
        &[],
        &[
            "S-1-5-32-548",
            "S-1-5-32-549",
            "S-1-5-32-550",
            "S-1-5-32-551",
        ],
        &[],
        "these groups can log on to domain controllers and reach Tier 0",
    )
}

fn priv_006(m: &Model) -> CheckResult {
    group_should_be_empty(
        m,
        "AD-PRIV-006",
        &[],
        &[],
        &["DnsAdmins"],
        "members can load a DLL into the DNS service on domain controllers",
    )
}

/// Privileged users filtered by `test`, each with a reason.
pub(super) fn privileged_where(m: &Model, test: impl Fn(usize) -> Option<String>) -> Vec<Affected> {
    m.privileged_users()
        .into_iter()
        .filter_map(|(u, groups)| {
            test(u).map(|why| item(m, u, format!("{why} · {}", group_names(m, &groups))))
        })
        .collect()
}

fn priv_011(m: &Model) -> CheckResult {
    let list = privileged_where(m, |u| {
        let n = &m.nodes[u];
        if !n.enabled() {
            return Some("Disabled".into());
        }
        match m.days_since(n.last_logon) {
            Some(d) if d > STALE_DAYS => Some(format!("Last logon {d} days ago")),
            None => Some("Never logged on".into()),
            _ => None,
        }
    });
    check("AD-PRIV-011")
        .affected(list, "accounts")
        .expected(format!(
            "Every admin account enabled and used within {STALE_DAYS} days"
        ))
        .evidence(
            "Last logon",
            "lastLogonTimestamp, which replicates every 9 to 14 days",
        )
        .evidence("Read from", read_from(m))
        .done()
}

fn priv_013(m: &Model) -> CheckResult {
    let list = privileged_where(m, |u| {
        let n = &m.nodes[u];
        (n.enabled() && n.flag(uac::DONT_EXPIRE_PASSWORD))
            .then(|| "Password never expires".to_string())
    });
    check("AD-PRIV-013")
        .affected(list, "accounts")
        .expected("Admin passwords expire, or are managed by a PAM tool")
        .evidence(
            "Read from",
            format!(
                "userAccountControl (DONT_EXPIRE_PASSWORD) via {}",
                read_from(m)
            ),
        )
        .done()
}

fn priv_014(m: &Model) -> CheckResult {
    let list = privileged_where(m, |u| {
        let n = &m.nodes[u];
        if !n.enabled() {
            return None;
        }
        match m.days_since(n.pwd_last_set) {
            Some(d) if d > 365 => Some(format!("Password set {d} days ago")),
            None => Some("Password never set".into()),
            _ => None,
        }
    });
    check("AD-PRIV-014")
        .affected(list, "accounts")
        .expected("Admin passwords changed within the last year")
        .evidence("Read from", format!("pwdLastSet via {}", read_from(m)))
        .done()
}

fn protected_users(m: &Model) -> HashSet<usize> {
    m.group_by_rid(525)
        .map(|g| m.recursive_members(g).into_iter().collect())
        .unwrap_or_default()
}

fn priv_015(m: &Model) -> CheckResult {
    let protected = protected_users(m);
    let exists = m.group_by_rid(525).is_some();
    let list = privileged_where(m, |u| {
        (m.nodes[u].enabled() && !protected.contains(&u) && !is_krbtgt(m, u))
            .then(|| "Not in Protected Users".to_string())
    });
    let mut out = check("AD-PRIV-015")
        .affected(list, "accounts")
        .expected("Every admin account in Protected Users")
        .evidence("Read from", read_from(m));
    if !exists {
        out = out.evidence(
            "Protected Users",
            "The group does not exist; it needs a Windows Server 2012 R2 PDC emulator",
        );
    }
    out.done()
}

fn priv_016(m: &Model) -> CheckResult {
    let protected = protected_users(m);
    let list = privileged_where(m, |u| {
        let n = &m.nodes[u];
        (n.enabled() && !n.flag(uac::NOT_DELEGATED) && !protected.contains(&u))
            .then(|| "Can be delegated (no NOT_DELEGATED flag, not in Protected Users)".to_string())
    });
    check("AD-PRIV-016")
        .affected(list, "accounts")
        .expected("\"Account is sensitive and cannot be delegated\" set on every admin account")
        .evidence(
            "Read from",
            format!("userAccountControl (NOT_DELEGATED) via {}", read_from(m)),
        )
        .done()
}

fn priv_017(m: &Model) -> CheckResult {
    let list = privileged_where(m, |u| {
        let n = &m.nodes[u];
        let spns = n.spns();
        (n.enabled() && !spns.is_empty() && !is_krbtgt(m, u))
            .then(|| format!("SPN {}", spns.join(", ")))
    });
    check("AD-PRIV-017")
        .affected(list, "accounts")
        .expected("No admin account has a service principal name")
        .evidence(
            "Read from",
            format!("servicePrincipalName via {}", read_from(m)),
        )
        .done()
}

fn priv_020(m: &Model) -> CheckResult {
    let Some(guest) = m.by_sid(&format!("{}-501", m.domain_sid)) else {
        return check("AD-PRIV-020")
            .not_assessed("The Guest account (RID 501) was not found.")
            .done();
    };
    let on = m.nodes[guest].enabled();
    check("AD-PRIV-020")
        .affected(
            if on {
                vec![item(m, guest, "Enabled")]
            } else {
                Vec::new()
            },
            "accounts",
        )
        .expected("Guest disabled")
        .found(if on { "Enabled" } else { "Disabled" })
        .evidence("Read from", read_from(m))
        .done()
}

fn priv_021(m: &Model) -> CheckResult {
    let Some(k) = m.by_sid(&format!("{}-502", m.domain_sid)) else {
        return check("AD-PRIV-021")
            .not_assessed("The krbtgt account (RID 502) was not found.")
            .done();
    };
    let age = m.days_since(m.nodes[k].pwd_last_set);
    let failed = age.is_none_or(|d| d > 180);
    let mut out = check("AD-PRIV-021")
        .failed(failed)
        .expected("Changed within 180 days")
        .found(match age {
            Some(d) => format!("Last changed {d} days ago"),
            None => "Never changed".into(),
        })
        .evidence(
            "Read from",
            format!("pwdLastSet on krbtgt via {}", read_from(m)),
        )
        .raw(format!(
            "pwdLastSet: {}",
            m.nodes[k]
                .pwd_last_set
                .map(time::iso)
                .unwrap_or_else(|| "<never>".into())
        ));
    if failed {
        out = out.affected(
            vec![item(m, k, format!("Password age {}", days_text(age)))],
            "accounts",
        );
    }
    if age.is_some_and(|d| d > 3 * 365) {
        out = out.severity(Severity::Critical);
    }
    out.done()
}

fn priv_024(m: &Model) -> CheckResult {
    let privileged: HashSet<usize> = m
        .tier0_groups()
        .into_iter()
        .flat_map(|g| m.recursive_members(g))
        .collect();
    let list: Vec<Affected> = of_kind(m, Kind::User)
        .filter(|&u| {
            m.nodes[u].attrs.int("admincount") == Some(1)
                && !privileged.contains(&u)
                && !is_krbtgt(m, u)
        })
        .map(|u| {
            item(
                m,
                u,
                "adminCount=1 but no longer in a protected group; inheritance stays blocked",
            )
        })
        .collect();
    check("AD-PRIV-024")
        .affected(list, "accounts")
        .expected("adminCount cleared and inheritance restored when an account leaves the protected groups")
        .evidence("Read from", read_from(m))
        .done()
}

fn priv_025(m: &Model) -> CheckResult {
    let hidden: [(u32, &str); 3] = [
        (512, "Domain Admins"),
        (518, "Schema Admins"),
        (519, "Enterprise Admins"),
    ];
    let mut list = Vec::new();
    for kind in [Kind::User, Kind::Computer] {
        for i in of_kind(m, kind) {
            let Some(pg) = m.nodes[i].attrs.int("primarygroupid") else {
                continue;
            };
            if let Some((_, name)) = hidden.iter().find(|(r, _)| i64::from(*r) == pg) {
                list.push(item(m, i, format!("primaryGroupID {pg} ({name}): membership not shown in the group's member list")));
            }
            if pg == 516 && kind == Kind::Computer && !m.nodes[i].is_dc() {
                list.push(item(m, i, "primaryGroupID 516 (Domain Controllers) on a computer that is not a domain controller"));
            }
        }
    }
    check("AD-PRIV-025")
        .affected(list, "accounts")
        .expected("Privileged membership only through the member attribute")
        .evidence("Read from", format!("primaryGroupID via {}", read_from(m)))
        .done()
}

// ---------- Kerberos ----------

fn krb_001(m: &Model) -> CheckResult {
    let privileged = m.privileged_users();
    let mut any_admin = false;
    let list: Vec<Affected> = enabled_users(m)
        .filter(|&u| !m.nodes[u].spns().is_empty() && !is_krbtgt(m, u))
        .map(|u| {
            let admin = privileged.contains_key(&u);
            any_admin |= admin;
            let age = days_text(m.days_since(m.nodes[u].pwd_last_set));
            item(
                m,
                u,
                format!(
                    "{} SPN · password age {age}{}",
                    m.nodes[u].spns().len(),
                    if admin { " · privileged" } else { "" }
                ),
            )
        })
        .collect();
    let mut out = check("AD-KRB-001")
        .affected(list, "accounts")
        .expected("No user accounts with SPNs, or gMSAs instead")
        .evidence(
            "Read from",
            format!("servicePrincipalName via {}", read_from(m)),
        );
    if any_admin {
        out = out.severity(Severity::High);
    }
    out.done()
}

fn uac_users(m: &Model, id: &str, flag: u32, reason: &str, expected: &str) -> CheckResult {
    let list = enabled_users(m)
        .filter(|&u| m.nodes[u].flag(flag))
        .map(|u| item(m, u, reason))
        .collect();
    check(id)
        .affected(list, "accounts")
        .expected(expected)
        .evidence(
            "Read from",
            format!("userAccountControl via {}", read_from(m)),
        )
        .done()
}

fn krb_002(m: &Model) -> CheckResult {
    uac_users(
        m,
        "AD-KRB-002",
        uac::DONT_REQ_PREAUTH,
        "Kerberos preauthentication not required",
        "Preauthentication required for every account",
    )
}

fn krb_003(m: &Model) -> CheckResult {
    let list = of_kind(m, Kind::Computer)
        .filter(|&c| {
            let n = &m.nodes[c];
            n.enabled() && n.flag(uac::TRUSTED_FOR_DELEGATION) && !n.is_dc()
        })
        .map(|c| {
            item(
                m,
                c,
                "Trusted for delegation to any service (unconstrained)",
            )
        })
        .collect();
    check("AD-KRB-003")
        .affected(list, "computers")
        .expected("Unconstrained delegation only on domain controllers")
        .evidence(
            "Read from",
            format!(
                "userAccountControl (TRUSTED_FOR_DELEGATION) via {}",
                read_from(m)
            ),
        )
        .done()
}

fn krb_004(m: &Model) -> CheckResult {
    uac_users(
        m,
        "AD-KRB-004",
        uac::TRUSTED_FOR_DELEGATION,
        "Trusted for delegation to any service (unconstrained)",
        "No user account trusted for unconstrained delegation",
    )
}

fn krb_005(m: &Model) -> CheckResult {
    let list = (0..m.nodes.len())
        .filter(|&i| matches!(m.nodes[i].kind, Kind::User | Kind::Computer))
        .filter(|&i| m.nodes[i].enabled() && m.nodes[i].flag(uac::TRUSTED_TO_AUTH_FOR_DELEGATION))
        .map(|i| {
            let to = m.nodes[i].attrs.strs("msds-allowedtodelegateto");
            item(
                m,
                i,
                format!(
                    "Protocol transition to {}",
                    if to.is_empty() {
                        "no listed service".into()
                    } else {
                        to.join(", ")
                    }
                ),
            )
        })
        .collect();
    check("AD-KRB-005")
        .affected(list, "accounts")
        .expected("Protocol transition only where documented and needed")
        .evidence(
            "Read from",
            format!(
                "userAccountControl (TRUSTED_TO_AUTH_FOR_DELEGATION) via {}",
                read_from(m)
            ),
        )
        .done()
}

fn krb_006(m: &Model) -> CheckResult {
    let dc_hosts: HashSet<String> = of_kind(m, Kind::Computer)
        .filter(|&c| m.nodes[c].is_dc())
        .flat_map(|c| {
            let n = &m.nodes[c];
            let mut names = vec![n.name.trim_end_matches('$').to_ascii_lowercase()];
            names.extend(n.attrs.str("dnshostname").map(str::to_ascii_lowercase));
            names
        })
        .collect();
    let list = (0..m.nodes.len())
        .filter(|&i| {
            matches!(m.nodes[i].kind, Kind::User | Kind::Computer)
                && m.nodes[i].enabled()
                && !m.nodes[i].is_dc()
        })
        .filter_map(|i| {
            let sensitive: Vec<&str> = m.nodes[i]
                .attrs
                .strs("msds-allowedtodelegateto")
                .into_iter()
                .filter(|spn| {
                    let lower = spn.to_ascii_lowercase();
                    let (svc, rest) = lower.split_once('/').unwrap_or((&lower, ""));
                    let host = rest.split([':', '/']).next().unwrap_or_default();
                    svc == "krbtgt" || dc_hosts.contains(host)
                })
                .collect();
            (!sensitive.is_empty())
                .then(|| item(m, i, format!("Can delegate to {}", sensitive.join(", "))))
        })
        .collect();
    check("AD-KRB-006")
        .affected(list, "accounts")
        .expected("No constrained delegation to services on domain controllers or krbtgt")
        .evidence(
            "Read from",
            format!("msDS-AllowedToDelegateTo via {}", read_from(m)),
        )
        .done()
}

fn krb_007(m: &Model) -> CheckResult {
    let list = of_kind(m, Kind::Computer)
        .filter(|&c| {
            m.nodes[c].tier0
                && m.nodes[c]
                    .attrs
                    .has("msds-allowedtoactonbehalfofotheridentity")
        })
        .map(|c| {
            item(
                m,
                c,
                "Resource-based constrained delegation configured on a Tier 0 computer",
            )
        })
        .collect();
    check("AD-KRB-007")
        .affected(list, "computers")
        .expected("msDS-AllowedToActOnBehalfOfOtherIdentity empty on domain controllers and Tier 0 servers")
        .evidence("Read from", read_from(m))
        .done()
}

fn krb_012(m: &Model) -> CheckResult {
    let mut owners: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for i in 0..m.nodes.len() {
        if matches!(m.nodes[i].kind, Kind::User | Kind::Computer) {
            for spn in m.nodes[i].spns() {
                owners.entry(spn.to_ascii_lowercase()).or_default().push(i);
            }
        }
    }
    let mut list = Vec::new();
    for (spn, holders) in owners.iter().filter(|(_, h)| h.len() > 1) {
        for &h in holders {
            list.push(item(
                m,
                h,
                format!(
                    "{spn} is also on {}",
                    holders
                        .iter()
                        .filter(|&&o| o != h)
                        .map(|&o| m.nodes[o].name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ));
        }
    }
    check("AD-KRB-012")
        .affected(list, "accounts")
        .expected("Every SPN registered on exactly one account")
        .evidence(
            "Read from",
            format!("servicePrincipalName via {}", read_from(m)),
        )
        .done()
}

fn krb_014(m: &Model) -> CheckResult {
    let list = (0..m.nodes.len())
        .filter(|&i| matches!(m.nodes[i].kind, Kind::User | Kind::Computer))
        .filter(|&i| m.nodes[i].enabled() && m.nodes[i].flag(uac::USE_DES_KEY_ONLY))
        .map(|i| item(m, i, "Use only Kerberos DES encryption types"))
        .collect();
    check("AD-KRB-014")
        .affected(list, "accounts")
        .expected("No account restricted to DES")
        .evidence(
            "Read from",
            format!("userAccountControl (USE_DES_KEY_ONLY) via {}", read_from(m)),
        )
        .done()
}

// ---------- Password policy ----------

fn policy_raw(m: &Model) -> String {
    let p = m.password_policy();
    let v = |x: Option<i64>| {
        x.map(|v| v.to_string())
            .unwrap_or_else(|| "<not read>".into())
    };
    format!(
        "minPwdLength: {}\npwdHistoryLength: {}\ncomplexity: {}\nreversible encryption: {}\nmaxPwdAge (days): {}\nlockoutThreshold: {}\nlockoutDuration (minutes): {}",
        v(p.min_length),
        v(p.history),
        p.complexity.map(|b| b.to_string()).unwrap_or_default(),
        p.reversible.map(|b| b.to_string()).unwrap_or_default(),
        p.max_age_days.map(|d| d.to_string()).unwrap_or_else(|| "never".into()),
        v(p.lockout_threshold),
        p.lockout_minutes.map(|d| d.to_string()).unwrap_or_else(|| "until an admin unlocks".into()),
    )
}

fn policy_check(
    m: &Model,
    id: &str,
    expected: &str,
    eval: impl Fn(&model::PasswordPolicy) -> Option<(bool, String)>,
) -> CheckResult {
    let p = m.password_policy();
    let out = check(id).expected(expected);
    match eval(&p) {
        None => out
            .not_assessed("The default domain password policy was not returned.")
            .done(),
        Some((failed, found)) => out
            .failed(failed)
            .found(found)
            .evidence(
                "Read from",
                format!(
                    "Default domain policy on the domain head via {}",
                    read_from(m)
                ),
            )
            .raw(policy_raw(m))
            .done(),
    }
}

fn pwd_001(m: &Model) -> CheckResult {
    policy_check(m, "AD-PWD-001", "14 characters or more", |p| {
        p.min_length
            .map(|l| (l < 14, plural(l as usize, "character", "characters")))
    })
}

fn pwd_002(m: &Model) -> CheckResult {
    policy_check(m, "AD-PWD-002", "Complexity enabled", |p| {
        p.complexity.map(|c| {
            (
                !c,
                if c {
                    "Enabled".into()
                } else {
                    "Disabled".into()
                },
            )
        })
    })
}

fn pwd_004(m: &Model) -> CheckResult {
    policy_check(m, "AD-PWD-004", "24 remembered passwords", |p| {
        p.history.map(|h| {
            (
                h < 24,
                plural(h as usize, "remembered password", "remembered passwords"),
            )
        })
    })
}

fn pwd_005(m: &Model) -> CheckResult {
    let policy = m.password_policy().reversible;
    let accounts: Vec<Affected> = enabled_users(m)
        .filter(|&u| m.nodes[u].flag(uac::ENCRYPTED_TEXT_PWD_ALLOWED))
        .map(|u| item(m, u, "Store password using reversible encryption"))
        .collect();
    let n = accounts.len();
    let mut out = check("AD-PWD-005").affected(accounts, "accounts");
    if policy == Some(true) {
        out = out.failed(true);
    }
    out.expected("Reversible encryption off in the domain policy and on every account")
        .found(format!(
            "Domain policy: {}. Accounts with the flag: {n}",
            match policy {
                Some(true) => "on",
                Some(false) => "off",
                None => "not read",
            }
        ))
        .evidence("Read from", read_from(m))
        .done()
}

fn pwd_006(m: &Model) -> CheckResult {
    policy_check(
        m,
        "AD-PWD-006",
        "Lockout after 1 to 10 failed attempts",
        |p| {
            p.lockout_threshold.map(|t| match t {
                0 => (true, "Never locks out".into()),
                t if t > 10 => (true, format!("Locks out after {t} attempts")),
                t => (false, format!("Locks out after {t} attempts")),
            })
        },
    )
}

fn pwd_011(m: &Model) -> CheckResult {
    uac_users(
        m,
        "AD-PWD-011",
        uac::PASSWD_NOTREQD,
        "PASSWD_NOTREQD: may have an empty password",
        "No account with PASSWD_NOTREQD",
    )
}

fn pwd_012(m: &Model) -> CheckResult {
    let list = enabled_users(m)
        .filter(|&u| m.nodes[u].flag(uac::DONT_EXPIRE_PASSWORD))
        .map(|u| {
            item(
                m,
                u,
                format!(
                    "Password never expires · password age {}",
                    days_text(m.days_since(m.nodes[u].pwd_last_set))
                ),
            )
        })
        .collect();
    check("AD-PWD-012")
        .affected(list, "accounts")
        .expected("Only documented service and break-glass accounts never expire")
        .evidence(
            "Read from",
            format!(
                "userAccountControl (DONT_EXPIRE_PASSWORD) via {}",
                read_from(m)
            ),
        )
        .done()
}

fn pwd_013(m: &Model) -> CheckResult {
    let list = enabled_users(m)
        .filter(|&u| {
            m.nodes[u].flag(uac::PASSWD_NOTREQD)
                && m.nodes[u].attrs.int("pwdlastset").unwrap_or(0) == 0
        })
        .map(|u| item(m, u, "PASSWD_NOTREQD and no password ever set"))
        .collect();
    check("AD-PWD-013")
        .affected(list, "accounts")
        .expected("No enabled account that may have a blank password")
        .evidence("Read from", read_from(m))
        .done()
}

fn created_days(m: &Model, i: usize) -> i64 {
    m.days_since(m.nodes[i].created).unwrap_or(i64::MAX)
}

fn pwd_014(m: &Model) -> CheckResult {
    let list = enabled_users(m)
        .filter(|&u| m.nodes[u].last_logon.is_none() && created_days(m, u) > 30)
        .map(|u| {
            item(
                m,
                u,
                format!("Never logged on · created {} days ago", created_days(m, u)),
            )
        })
        .collect();
    check("AD-PWD-014")
        .affected(list, "accounts")
        .expected("Accounts that were never used are disabled or removed after 30 days")
        .evidence(
            "Read from",
            format!("lastLogonTimestamp and whenCreated via {}", read_from(m)),
        )
        .done()
}

fn pwd_015(m: &Model) -> CheckResult {
    let list = enabled_users(m)
        .filter(|&u| !is_krbtgt(m, u))
        .filter_map(|u| {
            let d = m.days_since(m.nodes[u].pwd_last_set)?;
            (d > 365).then(|| item(m, u, format!("Password set {d} days ago")))
        })
        .collect();
    check("AD-PWD-015")
        .affected(list, "accounts")
        .expected("Every enabled account's password changed within a year")
        .evidence("Read from", format!("pwdLastSet via {}", read_from(m)))
        .done()
}

fn pwd_016(m: &Model) -> CheckResult {
    let list = enabled_users(m)
        .filter(|&u| {
            m.nodes[u].attrs.int("pwdlastset") == Some(0)
                && !m.nodes[u].flag(uac::PASSWD_NOTREQD)
                && created_days(m, u) > 30
        })
        .map(|u| {
            item(
                m,
                u,
                "Must change password at next logon, still unchanged after 30 days",
            )
        })
        .collect();
    check("AD-PWD-016")
        .affected(list, "accounts")
        .expected("Initial passwords changed soon after the account is created")
        .evidence("Read from", format!("pwdLastSet via {}", read_from(m)))
        .done()
}

fn pwd_019(m: &Model) -> CheckResult {
    const WORDS: [&str; 9] = [
        "password",
        "passwort",
        "passwd",
        "pwd",
        "pw:",
        "pw=",
        "kennwort",
        "mot de passe",
        "contrase",
    ];
    let list = (0..m.nodes.len())
        .filter(|&i| matches!(m.nodes[i].kind, Kind::User | Kind::Computer))
        .filter_map(|i| {
            let desc = m.nodes[i].attrs.str("description")?.to_lowercase();
            let word = WORDS.iter().find(|w| desc.contains(*w))?;
            // The value is never copied into results: it may be a password.
            Some(item(m, i, format!("description contains \"{word}\"")))
        })
        .collect();
    check("AD-PWD-019")
        .affected(list, "accounts")
        .expected("No password-like text in descriptions")
        .evidence("Note", "Descriptions are readable by every domain user. Values are not copied into this report.")
        .evidence("Read from", read_from(m))
        .done()
}

// ---------- Account hygiene ----------

fn stale(m: &Model, id: &str, kind: Kind, unit: &str) -> CheckResult {
    let list = of_kind(m, kind)
        .filter(|&i| m.nodes[i].enabled() && !is_krbtgt(m, i))
        .filter_map(|i| {
            let n = &m.nodes[i];
            match m.days_since(n.last_logon) {
                Some(d) if d > STALE_DAYS => Some(item(m, i, format!("Last logon {d} days ago"))),
                None if created_days(m, i) > STALE_DAYS => Some(item(m, i, "Never logged on")),
                _ => None,
            }
        })
        .collect();
    check(id)
        .affected(list, unit)
        .expected(format!("Enabled {unit} used within {STALE_DAYS} days"))
        .evidence(
            "Last logon",
            "lastLogonTimestamp, which replicates every 9 to 14 days",
        )
        .evidence("Read from", read_from(m))
        .done()
}

fn acc_001(m: &Model) -> CheckResult {
    stale(m, "AD-ACC-001", Kind::User, "accounts")
}

fn acc_002(m: &Model) -> CheckResult {
    stale(m, "AD-ACC-002", Kind::Computer, "computers")
}

fn acc_004(m: &Model) -> CheckResult {
    let list = (0..m.nodes.len())
        .filter(|&i| m.nodes[i].kind == Kind::User && m.nodes[i].enabled())
        .filter_map(|i| {
            let exp = m.nodes[i]
                .attrs
                .int("accountexpires")
                .and_then(time::from_filetime)?;
            (exp < m.now).then(|| item(m, i, format!("Expired {}", &time::iso(exp)[..10])))
        })
        .collect();
    check("AD-ACC-004")
        .affected(list, "accounts")
        .expected("Expired accounts disabled")
        .evidence("Read from", format!("accountExpires via {}", read_from(m)))
        .done()
}

fn acc_005(m: &Model) -> CheckResult {
    let list = of_kind(m, Kind::Computer)
        .filter(|&c| m.nodes[c].enabled())
        .filter_map(|c| {
            let logon = m.days_since(m.nodes[c].last_logon)?;
            let pwd = m.days_since(m.nodes[c].pwd_last_set)?;
            (logon <= STALE_DAYS && pwd > STALE_DAYS).then(|| {
                item(
                    m,
                    c,
                    format!("In use, but machine password set {pwd} days ago"),
                )
            })
        })
        .collect();
    check("AD-ACC-005")
        .affected(list, "computers")
        .expected("Machine passwords rotate (every 30 days by default)")
        .evidence(
            "Read from",
            format!("pwdLastSet and lastLogonTimestamp via {}", read_from(m)),
        )
        .done()
}

fn acc_006(m: &Model) -> CheckResult {
    let mut same_domain = false;
    let list = (0..m.nodes.len())
        .filter(|&i| matches!(m.nodes[i].kind, Kind::User | Kind::Computer | Kind::Group))
        .filter_map(|i| {
            let history = m.nodes[i].attrs.strs("sidhistory");
            if history.is_empty() {
                return None;
            }
            let own = history
                .iter()
                .filter(|s| s.starts_with(&format!("{}-", m.domain_sid)))
                .count();
            same_domain |= own > 0;
            Some(item(
                m,
                i,
                format!(
                    "{}{}",
                    plural(history.len(), "SID in SID history", "SIDs in SID history"),
                    if own > 0 {
                        ", from this same domain"
                    } else {
                        ""
                    }
                ),
            ))
        })
        .collect();
    let mut out = check("AD-ACC-006")
        .affected(list, "objects")
        .expected("SID history cleared after migrations")
        .evidence("Read from", format!("sIDHistory via {}", read_from(m)));
    if same_domain {
        out = out.severity(Severity::Critical);
    }
    out.done()
}

fn acc_007(m: &Model) -> CheckResult {
    let mut list = Vec::new();
    for i in 0..m.nodes.len() {
        let n = &m.nodes[i];
        let Some(pg) = n.attrs.int("primarygroupid") else {
            continue;
        };
        let normal: &[i64] = match n.kind {
            Kind::User => &[513, 514],
            Kind::Computer if n.is_dc() => &[516],
            Kind::Computer if n.flag(uac::PARTIAL_SECRETS_ACCOUNT) => &[521],
            Kind::Computer => &[515],
            _ => continue,
        };
        if !normal.contains(&pg) {
            let group = m
                .group_by_rid(pg as u32)
                .map(|g| m.nodes[g].name.clone())
                .unwrap_or_else(|| format!("RID {pg}"));
            list.push(item(m, i, format!("Primary group is {group}")));
        }
    }
    check("AD-ACC-007")
        .affected(list, "accounts")
        .expected(
            "Domain Users for users, Domain Computers for computers, Domain Controllers for DCs",
        )
        .evidence("Read from", format!("primaryGroupID via {}", read_from(m)))
        .done()
}

fn acc_010(m: &Model) -> CheckResult {
    let Some(g) = m.by_sid("S-1-5-32-554") else {
        return check("AD-ACC-010")
            .not_assessed("Pre-Windows 2000 Compatible Access was not found.")
            .done();
    };
    let list: Vec<Affected> = m.members[g]
        .iter()
        .filter(|&&i| {
            matches!(
                m.nodes[i].sid.as_deref(),
                Some(model::EVERYONE | model::ANONYMOUS | model::AUTHENTICATED_USERS)
            )
        })
        .map(|&i| item(m, i, "Grants read access to the whole directory"))
        .collect();
    let anonymous = list
        .iter()
        .any(|a| a.name == "Everyone" || a.name == "Anonymous Logon");
    let mut out = check("AD-ACC-010")
        .affected(list, "members")
        .expected("Pre-Windows 2000 Compatible Access without Everyone, Anonymous Logon or Authenticated Users")
        .evidence("Read from", read_from(m));
    if anonymous {
        out = out.severity(Severity::High);
    }
    out.done()
}

fn acc_017(m: &Model) -> CheckResult {
    // Groups that can reach themselves through membership.
    let groups: Vec<usize> = of_kind(m, Kind::Group).collect();
    let list = groups
        .into_iter()
        .filter(|&g| {
            m.recursive_members(g)
                .iter()
                .any(|&x| m.members[x].contains(&g))
        })
        .map(|g| item(m, g, "Member of itself through nested groups"))
        .collect();
    check("AD-ACC-017")
        .affected(list, "groups")
        .expected("No circular group nesting")
        .evidence("Read from", format!("member via {}", read_from(m)))
        .done()
}

// ---------- LAPS and computers ----------

pub(super) fn laps_schema(m: &Model) -> (bool, bool) {
    let names: Vec<String> = m
        .raw
        .schema
        .iter()
        .filter_map(|s| s.str("ldapdisplayname"))
        .map(str::to_ascii_lowercase)
        .collect();
    (
        names.iter().any(|n| n == "ms-mcs-admpwd"),
        names
            .iter()
            .any(|n| n == "mslaps-password" || n == "mslaps-encryptedpassword"),
    )
}

fn laps_001(m: &Model) -> CheckResult {
    let (legacy, windows) = laps_schema(m);
    check("AD-LAPS-001")
        .failed(!legacy && !windows)
        .expected("Windows LAPS schema attributes present")
        .found(match (legacy, windows) {
            (_, true) if legacy => "Windows LAPS and legacy LAPS attributes present".to_string(),
            (_, true) => "Windows LAPS attributes present".to_string(),
            (true, false) => "Only legacy LAPS (ms-Mcs-AdmPwd) present".to_string(),
            _ => "No LAPS attributes in the schema".to_string(),
        })
        .evidence("Read from", "Schema partition")
        .done()
}

fn laps_expiry(m: &Model, c: usize) -> Option<i64> {
    let a = &m.nodes[c].attrs;
    a.int("mslaps-passwordexpirationtime")
        .and_then(time::from_filetime)
        .or_else(|| {
            a.int("ms-mcs-admpwdexpirationtime")
                .and_then(time::from_filetime)
        })
}

pub(super) fn active_members<'a>(m: &'a Model<'a>) -> impl Iterator<Item = usize> + 'a {
    of_kind(m, Kind::Computer).filter(move |&c| {
        let n = &m.nodes[c];
        n.enabled() && !n.is_dc() && m.days_since(n.last_logon).is_some_and(|d| d <= STALE_DAYS)
    })
}

fn laps_003(m: &Model) -> CheckResult {
    let list = active_members(m)
        .filter_map(|c| {
            let exp = laps_expiry(m, c)?;
            let late = time::days_between(exp, m.now);
            (late > 7).then(|| item(m, c, format!("LAPS password expired {late} days ago")))
        })
        .collect();
    check("AD-LAPS-003")
        .affected(list, "computers")
        .expected("LAPS passwords rotate on schedule on every active computer")
        .evidence(
            "Read from",
            format!(
                "msLAPS-PasswordExpirationTime and ms-Mcs-AdmPwdExpirationTime via {}",
                read_from(m)
            ),
        )
        .done()
}

fn laps_008(m: &Model) -> CheckResult {
    let (legacy, windows) = laps_schema(m);
    let list: Vec<Affected> = if legacy && windows {
        active_members(m)
            .filter(|&c| {
                m.nodes[c].attrs.has("ms-mcs-admpwdexpirationtime")
                    && !m.nodes[c].attrs.has("mslaps-passwordexpirationtime")
            })
            .map(|c| item(m, c, "Still managed by legacy LAPS"))
            .collect()
    } else {
        Vec::new()
    };
    check("AD-LAPS-008")
        .affected(list, "computers")
        .expected("All computers moved to Windows LAPS")
        .evidence("Read from", read_from(m))
        .done()
}

fn cmp_001(m: &Model) -> CheckResult {
    let unsupported = |os: &str| -> Option<&'static str> {
        let os = os.to_ascii_lowercase();
        let rules: [(&str, &str); 9] = [
            ("windows xp", "Windows XP"),
            ("vista", "Windows Vista"),
            ("windows 7", "Windows 7"),
            ("windows 8", "Windows 8 or 8.1"),
            ("2000", "Windows 2000"),
            ("2003", "Windows Server 2003"),
            ("2008", "Windows Server 2008 or 2008 R2"),
            ("2012", "Windows Server 2012 or 2012 R2"),
            ("windows 10", "Windows 10"),
        ];
        let hit = rules.iter().find(|(k, _)| os.contains(k))?;
        // Windows 10 LTSC editions are still supported.
        if hit.0 == "windows 10" && (os.contains("ltsc") || os.contains("ltsb")) {
            return None;
        }
        Some(hit.1)
    };
    let list = of_kind(m, Kind::Computer)
        .filter(|&c| m.nodes[c].enabled())
        .filter_map(|c| {
            let os = m.nodes[c].attrs.str("operatingsystem")?;
            let name = unsupported(os)?;
            Some(item(
                m,
                c,
                format!("{name} ({os}) is out of Microsoft support"),
            ))
        })
        .collect();
    check("AD-CMP-001")
        .affected(list, "computers")
        .expected("Only supported Windows versions (Windows 10 only with Extended Security Updates or LTSC)")
        .evidence("Read from", format!("operatingSystem via {}", read_from(m)))
        .done()
}

fn cmp_004(m: &Model) -> CheckResult {
    let list = of_kind(m, Kind::Computer)
        .filter(|&c| m.nodes[c].enabled())
        .filter_map(|c| {
            let a = &m.nodes[c].attrs;
            let mut why = Vec::new();
            if a.has("sidhistory") {
                why.push("SID history");
            }
            if a.has("msds-allowedtoactonbehalfofotheridentity") {
                why.push("resource-based constrained delegation");
            }
            (!why.is_empty()).then(|| item(m, c, why.join(" and ")))
        })
        .collect();
    check("AD-CMP-004")
        .affected(list, "computers")
        .expected("No SID history or RBCD on computer accounts unless documented")
        .evidence("Read from", read_from(m))
        .done()
}

fn cmp_007(m: &Model) -> CheckResult {
    let (legacy, windows) = laps_schema(m);
    let list = active_members(m)
        .filter(|&c| laps_expiry(m, c).is_none())
        .map(|c| item(m, c, "No LAPS-managed local administrator password"))
        .collect();
    check("AD-CMP-007")
        .affected(list, "computers")
        .expected("Every active member computer has a LAPS-managed password")
        .found(if legacy || windows {
            String::new()
        } else {
            "LAPS is not in the schema".into()
        })
        .evidence(
            "Read from",
            format!("LAPS expiration time attributes via {}", read_from(m)),
        )
        .done()
}

fn cmp_008(m: &Model) -> CheckResult {
    let list = of_kind(m, Kind::Computer)
        .filter_map(|c| {
            let creator = m.nodes[c].attrs.str("ms-ds-creatorsid")?;
            let who = m
                .by_sid(creator)
                .map(|i| m.nodes[i].name.clone())
                .unwrap_or_else(|| creator.to_string());
            Some(item(
                m,
                c,
                format!("Joined to the domain by {who} using the machine account quota"),
            ))
        })
        .collect();
    check("AD-CMP-008")
        .affected(list, "computers")
        .expected("Computers joined only by delegated accounts")
        .evidence(
            "Read from",
            format!("ms-DS-CreatorSID via {}", read_from(m)),
        )
        .done()
}

// ---------- Trusts ----------

mod trust {
    pub const NON_TRANSITIVE: i64 = 0x1;
    pub const QUARANTINED_DOMAIN: i64 = 0x4;
    pub const FOREST_TRANSITIVE: i64 = 0x8;
    pub const CROSS_ORGANIZATION: i64 = 0x10;
    pub const WITHIN_FOREST: i64 = 0x20;
    pub const TREAT_AS_EXTERNAL: i64 = 0x40;
    pub const ENABLE_TGT_DELEGATION: i64 = 0x800;
    pub const OUTBOUND: i64 = 0x2;
}

fn trusts<'a>(m: &'a Model<'a>) -> impl Iterator<Item = (usize, i64, i64, i64)> + 'a {
    of_kind(m, Kind::Trust).map(move |t| {
        let a = &m.nodes[t].attrs;
        (
            t,
            a.int("trustattributes").unwrap_or(0),
            a.int("trustdirection").unwrap_or(0),
            a.int("trusttype").unwrap_or(0),
        )
    })
}

fn direction(d: i64) -> &'static str {
    match d {
        1 => "Inbound",
        2 => "Outbound",
        3 => "Bidirectional",
        _ => "Disabled",
    }
}

fn trust_kind(attrs: i64, ty: i64) -> &'static str {
    if attrs & trust::WITHIN_FOREST != 0 {
        "Parent-child or tree-root (same forest)"
    } else if attrs & trust::FOREST_TRANSITIVE != 0 {
        "Forest"
    } else if ty == 3 {
        "Realm (MIT Kerberos)"
    } else {
        "External"
    }
}

fn tru_001(m: &Model) -> CheckResult {
    let rows: Vec<String> = trusts(m)
        .map(|(t, a, d, ty)| {
            format!(
                "{}  {}  {}{}",
                m.nodes[t].name,
                trust_kind(a, ty),
                direction(d),
                if a & trust::NON_TRANSITIVE != 0 {
                    ", non-transitive"
                } else {
                    ""
                }
            )
        })
        .collect();
    check("AD-TRU-001")
        .found(plural(rows.len(), "trust", "trusts"))
        .expected("Every trust documented with an owner and a reason")
        .evidence(
            "Read from",
            format!("trustedDomain objects in CN=System via {}", read_from(m)),
        )
        .raw(if rows.is_empty() {
            "No trusts".into()
        } else {
            rows.join("\n")
        })
        .done()
}

fn external_outbound(a: i64, d: i64) -> bool {
    d & trust::OUTBOUND != 0 && a & trust::WITHIN_FOREST == 0
}

fn tru_002(m: &Model) -> CheckResult {
    let list = trusts(m)
        .filter(|&(_, a, d, ty)| {
            external_outbound(a, d)
                && a & trust::FOREST_TRANSITIVE == 0
                && ty == 2
                && a & trust::QUARANTINED_DOMAIN == 0
        })
        .map(|(t, ..)| item(m, t, "External trust without SID filtering (quarantine)"))
        .collect();
    check("AD-TRU-002")
        .affected(list, "trusts")
        .expected("SID filtering on every external trust")
        .evidence("Read from", format!("trustAttributes via {}", read_from(m)))
        .done()
}

fn tru_003(m: &Model) -> CheckResult {
    let list = trusts(m)
        .filter(|&(_, a, d, _)| {
            external_outbound(a, d)
                && a & trust::FOREST_TRANSITIVE != 0
                && a & trust::TREAT_AS_EXTERNAL != 0
        })
        .map(|(t, ..)| item(m, t, "Forest trust accepts SID history (TREAT_AS_EXTERNAL)"))
        .collect();
    check("AD-TRU-003")
        .affected(list, "trusts")
        .expected("SID history not accepted across forest trusts")
        .evidence("Read from", format!("trustAttributes via {}", read_from(m)))
        .done()
}

fn tru_004(m: &Model) -> CheckResult {
    let list = trusts(m)
        .filter(|&(_, a, d, ty)| {
            external_outbound(a, d) && ty == 2 && a & trust::CROSS_ORGANIZATION == 0
        })
        .map(|(t, a, d, ty)| {
            item(
                m,
                t,
                format!(
                    "{} trust, {}, forest-wide authentication",
                    trust_kind(a, ty),
                    direction(d).to_lowercase()
                ),
            )
        })
        .collect();
    check("AD-TRU-004")
        .affected(list, "trusts")
        .expected("Selective authentication on trusts to other forests")
        .evidence("Read from", format!("trustAttributes via {}", read_from(m)))
        .done()
}

fn tru_006(m: &Model) -> CheckResult {
    let list = trusts(m)
        .filter_map(|(t, ..)| {
            let changed = m.nodes[t].attrs.str("whenchanged").and_then(time::parse_iso)?;
            let d = time::days_between(changed, m.now);
            (d > 90).then(|| item(m, t, format!("Trust object unchanged for {d} days; the trust password rotates every 30 days")))
        })
        .collect();
    check("AD-TRU-006")
        .affected(list, "trusts")
        .expected("Trust passwords rotating (object changed within 90 days)")
        .evidence(
            "Read from",
            format!("whenChanged on trustedDomain objects via {}", read_from(m)),
        )
        .done()
}

fn tru_009(m: &Model) -> CheckResult {
    let list = trusts(m)
        .filter(|&(_, a, d, _)| external_outbound(a, d) && a & trust::ENABLE_TGT_DELEGATION != 0)
        .map(|(t, ..)| item(m, t, "TGT delegation enabled across the trust"))
        .collect();
    check("AD-TRU-009")
        .affected(list, "trusts")
        .expected("TGT delegation disabled across forest trusts")
        .evidence("Read from", format!("trustAttributes via {}", read_from(m)))
        .done()
}

// ---------- ACLs ----------

const TAKEOVER: [&str; 6] = [
    "GenericAll",
    "GenericWrite",
    "WriteDacl",
    "WriteOwner",
    "Owns",
    "AllExtendedRights",
];

pub(crate) fn describe(kind: &str) -> &'static str {
    match kind {
        "GenericAll" => "Full control",
        "GenericWrite" => "Write all properties",
        "WriteDacl" => "Modify permissions",
        "WriteOwner" => "Take ownership",
        "Owns" => "Owner",
        "AllExtendedRights" => "All extended rights",
        "AddMember" => "Add members",
        "AddSelf" => "Add self as member",
        "ForceChangePassword" => "Reset password",
        "AddKeyCredentialLink" => "Write msDS-KeyCredentialLink",
        "WriteSPN" => "Write servicePrincipalName",
        "WriteAccountRestrictions" => "Write account restrictions (RBCD)",
        "WriteGPLink" => "Link GPOs",
        "DCSync" => "Replicate directory changes (DCSync)",
        _ => "Control",
    }
}

/// Non-default principals holding rights in `kinds` over targets that pass `target`.
fn acl_findings(m: &Model, kinds: &[&str], target: impl Fn(usize) -> bool) -> Vec<Affected> {
    let mut by_principal: BTreeMap<usize, Vec<String>> = BTreeMap::new();
    for e in &m.edges {
        if kinds.contains(&e.kind) && target(e.to) && !m.nodes[e.from].tier0 {
            by_principal.entry(e.from).or_default().push(format!(
                "{} on {}",
                describe(e.kind),
                m.nodes[e.to].name
            ));
        }
    }
    by_principal
        .into_iter()
        .map(|(p, mut rights)| {
            rights.sort();
            rights.dedup();
            let extra = rights.len().saturating_sub(3);
            rights.truncate(3);
            let mut reason = rights.join("; ");
            if extra > 0 {
                reason.push_str(&format!("; and {extra} more"));
            }
            item(m, p, reason)
        })
        .collect()
}

fn acl_raw(m: &Model, kinds: &[&str], target: impl Fn(usize) -> bool) -> String {
    let mut lines: Vec<String> = m
        .edges
        .iter()
        .filter(|e| kinds.contains(&e.kind) && target(e.to) && !m.nodes[e.from].tier0)
        .map(|e| {
            format!(
                "{}  {}  {}",
                m.nodes[e.to].name,
                e.kind,
                m.nodes[e.from]
                    .sid
                    .as_deref()
                    .unwrap_or(&m.nodes[e.from].name)
            )
        })
        .collect();
    lines.sort();
    lines.dedup();
    lines.truncate(200);
    lines.join("\n")
}

fn acl_check(
    m: &Model,
    id: &str,
    kinds: &[&str],
    target: impl Fn(usize) -> bool + Copy,
    expected: &str,
) -> CheckResult {
    let list = acl_findings(m, kinds, target);
    let raw = acl_raw(m, kinds, target);
    let mut out = check(id)
        .affected(list, "principals")
        .expected(expected)
        .evidence(
            "Read from",
            format!("nTSecurityDescriptor (owner and DACL) via {}", read_from(m)),
        );
    if !raw.is_empty() {
        out = out.raw(raw);
    }
    out.done()
}

fn acl_001(m: &Model) -> CheckResult {
    let domain = m.domain;
    acl_check(
        m,
        "AD-ACL-001",
        &[
            "GenericAll",
            "GenericWrite",
            "WriteDacl",
            "WriteOwner",
            "Owns",
        ],
        |t| Some(t) == domain,
        "Only built-in admin groups hold write, permission or ownership rights on the domain head",
    )
}

fn acl_002(m: &Model) -> CheckResult {
    let domain = m.domain;
    let list: Vec<Affected> = m
        .edges
        .iter()
        .filter(|e| e.kind == "DCSync" && Some(e.to) == domain && !m.nodes[e.from].tier0)
        .map(|e| {
            let rights = m
                .replication
                .get(&e.from)
                .map(|r| r.join(", "))
                .unwrap_or_default();
            item(m, e.from, format!("Holds {rights} on the domain head"))
        })
        .collect();
    let raw: Vec<String> = m
        .replication
        .iter()
        .map(|(&p, r)| {
            format!(
                "{}  {}",
                m.nodes[p].sid.as_deref().unwrap_or(&m.nodes[p].name),
                r.join(", ")
            )
        })
        .collect();
    let mut out = check("AD-ACL-002")
        .affected(list, "principals")
        .expected("Only domain controllers and built-in admin groups can replicate secrets")
        .evidence(
            "Read from",
            format!(
                "nTSecurityDescriptor of the domain head via {}",
                read_from(m)
            ),
        );
    if !raw.is_empty() {
        out = out.raw(raw.join("\n"));
    }
    out.done()
}

fn acl_003(m: &Model) -> CheckResult {
    acl_check(
        m,
        "AD-ACL-003",
        &TAKEOVER,
        |t| m.nodes[t].name.eq_ignore_ascii_case("AdminSDHolder"),
        "Default permissions on AdminSDHolder",
    )
}

fn acl_004(m: &Model) -> CheckResult {
    acl_check(
        m,
        "AD-ACL-004",
        &[
            "GenericAll",
            "GenericWrite",
            "WriteDacl",
            "WriteOwner",
            "Owns",
            "AllExtendedRights",
            "AddKeyCredentialLink",
            "WriteAccountRestrictions",
        ],
        |t| m.nodes[t].is_dc() || (m.nodes[t].kind == Kind::Ou && m.nodes[t].tier0),
        "Only Tier 0 admins can change the Domain Controllers OU and DC computer objects",
    )
}

fn acl_005(m: &Model) -> CheckResult {
    acl_check(
        m,
        "AD-ACL-005",
        &[
            "GenericAll",
            "GenericWrite",
            "WriteDacl",
            "WriteOwner",
            "Owns",
            "AddMember",
            "AddSelf",
        ],
        |t| m.nodes[t].kind == Kind::Group && m.nodes[t].tier0,
        "Only Tier 0 admins can change privileged group membership",
    )
}

fn acl_006(m: &Model) -> CheckResult {
    acl_check(
        m,
        "AD-ACL-006",
        &[
            "GenericAll",
            "GenericWrite",
            "WriteDacl",
            "WriteOwner",
            "Owns",
        ],
        |t| m.nodes[t].kind == Kind::Gpo && m.nodes[t].tier0,
        "Only Tier 0 admins can edit GPOs linked to the domain or to domain controllers",
    )
}

fn tier0_user(m: &Model, t: usize) -> bool {
    m.nodes[t].kind == Kind::User && m.nodes[t].tier0
}

fn acl_008(m: &Model) -> CheckResult {
    acl_check(
        m,
        "AD-ACL-008",
        &["ForceChangePassword", "AllExtendedRights"],
        |t| tier0_user(m, t),
        "Nobody outside Tier 0 can reset Tier 0 passwords",
    )
}

fn acl_009(m: &Model) -> CheckResult {
    acl_check(
        m,
        "AD-ACL-009",
        &["WriteSPN"],
        |t| m.nodes[t].kind == Kind::User,
        "Nobody outside Tier 0 can write SPNs on sensitive accounts",
    )
}

fn acl_010(m: &Model) -> CheckResult {
    acl_check(
        m,
        "AD-ACL-010",
        &["AddKeyCredentialLink"],
        |t| matches!(m.nodes[t].kind, Kind::User | Kind::Computer),
        "Only Key Admins and the accounts themselves write msDS-KeyCredentialLink",
    )
}

fn acl_011(m: &Model) -> CheckResult {
    acl_check(
        m,
        "AD-ACL-011",
        &["WriteAccountRestrictions"],
        |t| m.nodes[t].kind == Kind::Computer,
        "Nobody outside Tier 0 can configure RBCD on sensitive computers",
    )
}

fn broad(m: &Model, i: usize) -> bool {
    let sid = m.nodes[i].sid.as_deref().unwrap_or_default();
    matches!(
        sid,
        model::EVERYONE | model::AUTHENTICATED_USERS | model::ANONYMOUS | "S-1-5-32-545"
    ) || m.nodes[i]
        .rid()
        .is_some_and(|r| (r == 513 || r == 515) && sid.starts_with(&m.domain_sid))
}

fn acl_015(m: &Model) -> CheckResult {
    let list: Vec<Affected> = acl_findings(m, &super::paths::CONTROL, |t| m.nodes[t].tier0)
        .into_iter()
        .filter(|a| {
            a.object
                .as_deref()
                .and_then(|id| m.by_sid(id))
                .is_some_and(|i| broad(m, i))
        })
        .collect();
    check("AD-ACL-015")
        .affected(list, "groups")
        .expected("Everyone, Authenticated Users, Domain Users and Domain Computers have no write rights on Tier 0 objects")
        .evidence("Read from", format!("nTSecurityDescriptor via {}", read_from(m)))
        .done()
}

fn acl_016(m: &Model) -> CheckResult {
    acl_check(
        m,
        "AD-ACL-016",
        &["Owns"],
        |t| m.nodes[t].tier0,
        "Tier 0 objects owned by Domain Admins, Enterprise Admins, Administrators or SYSTEM",
    )
}

fn acl_025(m: &Model) -> CheckResult {
    acl_check(
        m,
        "AD-ACL-025",
        &["WriteGPLink", "GenericAll", "GenericWrite"],
        |t| matches!(m.nodes[t].kind, Kind::Ou | Kind::Domain) && m.nodes[t].tier0,
        "Only Tier 0 admins can link GPOs to the domain and the Domain Controllers OU",
    )
}

fn acl_027(m: &Model) -> CheckResult {
    let prefix = format!("{}-", m.domain_sid);
    let mut targets: HashMap<usize, BTreeSet<String>> = HashMap::new();
    for e in &m.edges {
        let n = &m.nodes[e.from];
        if n.kind == Kind::Principal && n.sid.as_deref().is_some_and(|s| s.starts_with(&prefix)) {
            targets
                .entry(e.from)
                .or_default()
                .insert(m.nodes[e.to].name.clone());
        }
    }
    let mut list: Vec<Affected> = targets
        .into_iter()
        .map(|(p, on)| {
            item(
                m,
                p,
                format!(
                    "Deleted or unknown principal with rights on {}",
                    on.into_iter().take(3).collect::<Vec<_>>().join(", ")
                ),
            )
        })
        .collect();
    list.sort_by(|a, b| a.name.cmp(&b.name));
    check("AD-ACL-027")
        .affected(list, "SIDs")
        .expected("No permissions granted to SIDs that no longer resolve")
        .evidence(
            "Read from",
            format!("nTSecurityDescriptor via {}", read_from(m)),
        )
        .done()
}

// ---------- Group Policy ----------

fn gpo_002(m: &Model) -> CheckResult {
    let mut list = Vec::new();
    for i in 0..m.nodes.len() {
        if !matches!(m.nodes[i].kind, Kind::Domain | Kind::Ou) {
            continue;
        }
        let Some(link) = m.nodes[i].attrs.str("gplink") else {
            continue;
        };
        for part in link.split('[').filter(|p| !p.is_empty()) {
            let dn = part
                .trim_end_matches(']')
                .rsplit_once(';')
                .map(|(d, _)| d)
                .unwrap_or(part);
            let dn = dn
                .trim_start_matches("LDAP://")
                .trim_start_matches("ldap://");
            if !m.by_dn.contains_key(&dn.to_ascii_lowercase()) {
                list.push(item(
                    m,
                    i,
                    format!("Links to {}, which does not exist", model::rdn_value(dn)),
                ));
            }
        }
    }
    check("AD-GPO-002")
        .affected(list, "links")
        .expected("Every GPO link points to an existing GPO")
        .evidence("Read from", format!("gPLink via {}", read_from(m)))
        .done()
}

fn gpo_003(m: &Model) -> CheckResult {
    let folders: HashSet<String> = m
        .raw
        .sysvol
        .iter()
        .map(|p| p.folder.to_ascii_lowercase())
        .collect();
    let gpos: Vec<usize> = of_kind(m, Kind::Gpo).collect();
    let names: HashSet<String> = gpos
        .iter()
        .map(|&g| model::rdn_value(&m.nodes[g].dn).to_ascii_lowercase())
        .collect();
    let mut list: Vec<Affected> = gpos
        .iter()
        .filter(|&&g| !folders.contains(&model::rdn_value(&m.nodes[g].dn).to_ascii_lowercase()))
        .map(|&g| item(m, g, "In AD, but its SYSVOL folder is missing"))
        .collect();
    for f in
        m.raw.sysvol.iter().filter(|p| {
            p.folder.starts_with('{') && !names.contains(&p.folder.to_ascii_lowercase())
        })
    {
        list.push(Affected {
            last_seen: None,
            name: f.folder.clone(),
            kind: "gpo".into(),
            location: Some(format!(
                "\\\\{}\\SYSVOL\\{}\\Policies\\{}",
                m.dns, m.dns, f.folder
            )),
            reason: Some("Folder in SYSVOL with no GPO in AD".into()),
            object: None,
        });
    }
    check("AD-GPO-003")
        .affected(list, "GPOs")
        .expected("Every GPO has both its AD object and its SYSVOL folder")
        .evidence(
            "Read from",
            format!("CN=Policies and \\\\{}\\SYSVOL", m.dns),
        )
        .done()
}

fn gpo_004(m: &Model) -> CheckResult {
    let by_folder: HashMap<String, usize> = of_kind(m, Kind::Gpo)
        .map(|g| (model::rdn_value(&m.nodes[g].dn).to_ascii_lowercase(), g))
        .collect();
    let mut list = Vec::new();
    for p in &m.raw.sysvol {
        for c in &p.cpasswords {
            let user = c
                .user
                .as_deref()
                .filter(|u| !u.is_empty())
                .map(|u| format!(" for {u}"))
                .unwrap_or_default();
            let reason = format!("cpassword in {} ({}){user}", c.file, c.element);
            match by_folder.get(&p.folder.to_ascii_lowercase()) {
                Some(&g) => list.push(item(m, g, reason)),
                None => list.push(Affected {
                    last_seen: None,
                    name: p.folder.clone(),
                    kind: "gpo".into(),
                    location: None,
                    reason: Some(reason),
                    object: None,
                }),
            }
        }
    }
    check("AD-GPO-004")
        .affected(list, "files")
        .expected("No Group Policy Preferences file holds a cpassword")
        .evidence("Note", "The cpassword values were detected but not copied")
        .evidence(
            "Read from",
            format!("\\\\{}\\SYSVOL\\{}\\Policies", m.dns, m.dns),
        )
        .done()
}

fn acl_028(m: &Model) -> CheckResult {
    let paths = super::paths::find(m);
    let broad_paths: Vec<_> = paths
        .iter()
        .filter(|p| p.severity == Severity::Critical)
        .collect();
    let list = broad_paths
        .iter()
        .map(|p| Affected {
            last_seen: None,
            name: p.title.clone(),
            kind: "path".into(),
            location: None,
            reason: Some(
                p.steps
                    .iter()
                    .map(|s| s.name.as_str())
                    .collect::<Vec<_>>()
                    .join(" → "),
            ),
            object: None,
        })
        .collect();
    check("AD-ACL-028")
        .affected(list, "paths")
        .expected("No path from Everyone, Authenticated Users, Domain Users or Domain Computers to Tier 0")
        .found(format!("{} from broad groups, {} from easily compromised accounts", broad_paths.len(), paths.len() - broad_paths.len()))
        .evidence("Graph", "Group membership, ACLs on Tier 0 objects, GPO links and DCSync rights")
        .done()
}

const LDAP: &[&str] = &["domain", "users", "computers", "groups"];
const DOMAIN: &[&str] = &["domain"];
const USERS: &[&str] = &["domain", "users", "groups"];
const COMPUTERS: &[&str] = &["domain", "computers"];
const ACLS: &[&str] = &[
    "domain",
    "users",
    "computers",
    "groups",
    "containers",
    "gpos",
    "acls",
];

pub const RULES: &[Rule] = &[
    Rule {
        id: "AD-FND-001",
        needs: &[],
        run: fnd_001,
    },
    Rule {
        id: "AD-FND-002",
        needs: &[],
        run: fnd_002,
    },
    Rule {
        id: "AD-FND-007",
        needs: &["dirservice"],
        run: fnd_007,
    },
    Rule {
        id: "AD-FND-008",
        needs: &["partitions"],
        run: fnd_008,
    },
    Rule {
        id: "AD-FND-011",
        needs: &["dirservice"],
        run: fnd_011,
    },
    Rule {
        id: "AD-FND-012",
        needs: DOMAIN,
        run: fnd_012,
    },
    Rule {
        id: "AD-PRIV-001",
        needs: LDAP,
        run: priv_001,
    },
    Rule {
        id: "AD-PRIV-002",
        needs: LDAP,
        run: priv_002,
    },
    Rule {
        id: "AD-PRIV-003",
        needs: LDAP,
        run: priv_003,
    },
    Rule {
        id: "AD-PRIV-005",
        needs: LDAP,
        run: priv_005,
    },
    Rule {
        id: "AD-PRIV-006",
        needs: LDAP,
        run: priv_006,
    },
    Rule {
        id: "AD-PRIV-011",
        needs: LDAP,
        run: priv_011,
    },
    Rule {
        id: "AD-PRIV-013",
        needs: LDAP,
        run: priv_013,
    },
    Rule {
        id: "AD-PRIV-014",
        needs: LDAP,
        run: priv_014,
    },
    Rule {
        id: "AD-PRIV-015",
        needs: LDAP,
        run: priv_015,
    },
    Rule {
        id: "AD-PRIV-016",
        needs: LDAP,
        run: priv_016,
    },
    Rule {
        id: "AD-PRIV-017",
        needs: LDAP,
        run: priv_017,
    },
    Rule {
        id: "AD-PRIV-020",
        needs: USERS,
        run: priv_020,
    },
    Rule {
        id: "AD-PRIV-021",
        needs: USERS,
        run: priv_021,
    },
    Rule {
        id: "AD-PRIV-024",
        needs: LDAP,
        run: priv_024,
    },
    Rule {
        id: "AD-PRIV-025",
        needs: LDAP,
        run: priv_025,
    },
    Rule {
        id: "AD-KRB-001",
        needs: LDAP,
        run: krb_001,
    },
    Rule {
        id: "AD-KRB-002",
        needs: USERS,
        run: krb_002,
    },
    Rule {
        id: "AD-KRB-003",
        needs: COMPUTERS,
        run: krb_003,
    },
    Rule {
        id: "AD-KRB-004",
        needs: USERS,
        run: krb_004,
    },
    Rule {
        id: "AD-KRB-005",
        needs: LDAP,
        run: krb_005,
    },
    Rule {
        id: "AD-KRB-006",
        needs: LDAP,
        run: krb_006,
    },
    Rule {
        id: "AD-KRB-007",
        needs: LDAP,
        run: krb_007,
    },
    Rule {
        id: "AD-KRB-012",
        needs: LDAP,
        run: krb_012,
    },
    Rule {
        id: "AD-KRB-014",
        needs: LDAP,
        run: krb_014,
    },
    Rule {
        id: "AD-PWD-001",
        needs: DOMAIN,
        run: pwd_001,
    },
    Rule {
        id: "AD-PWD-002",
        needs: DOMAIN,
        run: pwd_002,
    },
    Rule {
        id: "AD-PWD-004",
        needs: DOMAIN,
        run: pwd_004,
    },
    Rule {
        id: "AD-PWD-005",
        needs: USERS,
        run: pwd_005,
    },
    Rule {
        id: "AD-PWD-006",
        needs: DOMAIN,
        run: pwd_006,
    },
    Rule {
        id: "AD-PWD-011",
        needs: USERS,
        run: pwd_011,
    },
    Rule {
        id: "AD-PWD-012",
        needs: USERS,
        run: pwd_012,
    },
    Rule {
        id: "AD-PWD-013",
        needs: USERS,
        run: pwd_013,
    },
    Rule {
        id: "AD-PWD-014",
        needs: USERS,
        run: pwd_014,
    },
    Rule {
        id: "AD-PWD-015",
        needs: USERS,
        run: pwd_015,
    },
    Rule {
        id: "AD-PWD-016",
        needs: USERS,
        run: pwd_016,
    },
    Rule {
        id: "AD-PWD-019",
        needs: LDAP,
        run: pwd_019,
    },
    Rule {
        id: "AD-ACC-001",
        needs: USERS,
        run: acc_001,
    },
    Rule {
        id: "AD-ACC-002",
        needs: COMPUTERS,
        run: acc_002,
    },
    Rule {
        id: "AD-ACC-004",
        needs: USERS,
        run: acc_004,
    },
    Rule {
        id: "AD-ACC-005",
        needs: COMPUTERS,
        run: acc_005,
    },
    Rule {
        id: "AD-ACC-006",
        needs: LDAP,
        run: acc_006,
    },
    Rule {
        id: "AD-ACC-007",
        needs: LDAP,
        run: acc_007,
    },
    Rule {
        id: "AD-ACC-010",
        needs: LDAP,
        run: acc_010,
    },
    Rule {
        id: "AD-ACC-017",
        needs: LDAP,
        run: acc_017,
    },
    Rule {
        id: "AD-LAPS-001",
        needs: &["schema"],
        run: laps_001,
    },
    Rule {
        id: "AD-LAPS-003",
        needs: COMPUTERS,
        run: laps_003,
    },
    Rule {
        id: "AD-LAPS-008",
        needs: &["schema", "computers"],
        run: laps_008,
    },
    Rule {
        id: "AD-CMP-001",
        needs: COMPUTERS,
        run: cmp_001,
    },
    Rule {
        id: "AD-CMP-004",
        needs: COMPUTERS,
        run: cmp_004,
    },
    Rule {
        id: "AD-CMP-007",
        needs: &["schema", "computers"],
        run: cmp_007,
    },
    Rule {
        id: "AD-CMP-008",
        needs: LDAP,
        run: cmp_008,
    },
    Rule {
        id: "AD-TRU-001",
        needs: &["trusts"],
        run: tru_001,
    },
    Rule {
        id: "AD-TRU-002",
        needs: &["trusts"],
        run: tru_002,
    },
    Rule {
        id: "AD-TRU-003",
        needs: &["trusts"],
        run: tru_003,
    },
    Rule {
        id: "AD-TRU-004",
        needs: &["trusts"],
        run: tru_004,
    },
    Rule {
        id: "AD-TRU-006",
        needs: &["trusts"],
        run: tru_006,
    },
    Rule {
        id: "AD-TRU-009",
        needs: &["trusts"],
        run: tru_009,
    },
    Rule {
        id: "AD-ACL-001",
        needs: ACLS,
        run: acl_001,
    },
    Rule {
        id: "AD-ACL-002",
        needs: ACLS,
        run: acl_002,
    },
    Rule {
        id: "AD-ACL-003",
        needs: ACLS,
        run: acl_003,
    },
    Rule {
        id: "AD-ACL-004",
        needs: ACLS,
        run: acl_004,
    },
    Rule {
        id: "AD-ACL-005",
        needs: ACLS,
        run: acl_005,
    },
    Rule {
        id: "AD-ACL-006",
        needs: ACLS,
        run: acl_006,
    },
    Rule {
        id: "AD-ACL-008",
        needs: ACLS,
        run: acl_008,
    },
    Rule {
        id: "AD-ACL-009",
        needs: ACLS,
        run: acl_009,
    },
    Rule {
        id: "AD-ACL-010",
        needs: ACLS,
        run: acl_010,
    },
    Rule {
        id: "AD-ACL-011",
        needs: ACLS,
        run: acl_011,
    },
    Rule {
        id: "AD-ACL-015",
        needs: ACLS,
        run: acl_015,
    },
    Rule {
        id: "AD-ACL-016",
        needs: ACLS,
        run: acl_016,
    },
    Rule {
        id: "AD-ACL-025",
        needs: ACLS,
        run: acl_025,
    },
    Rule {
        id: "AD-ACL-027",
        needs: ACLS,
        run: acl_027,
    },
    Rule {
        id: "AD-ACL-028",
        needs: ACLS,
        run: acl_028,
    },
    Rule {
        id: "AD-GPO-002",
        needs: &["domain", "containers", "gpos"],
        run: gpo_002,
    },
    Rule {
        id: "AD-GPO-003",
        needs: &["gpos", "sysvol"],
        run: gpo_003,
    },
    Rule {
        id: "AD-GPO-004",
        needs: &["gpos", "sysvol"],
        run: gpo_004,
    },
];
