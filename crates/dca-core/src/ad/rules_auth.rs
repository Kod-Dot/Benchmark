//! Kerberos and password policy: encryption types, ticket policy, armoring,
//! authentication silos, fine-grained password policies and where
//! passwords can leak.

use std::collections::{BTreeMap, HashMap};

use super::model::{Kind, Model, Node};
use super::raw::{LdapObject, SysvolPolicy};
use super::rules::{check, days_text, is_krbtgt, item, plural, privileged_where, Rule};
use super::rules_dc::{each_dc, Eval};
use super::rules_gpo::{
    applies_to_dcs, gpo_name, not_read, read_from as sysvol_from, read_policies,
};
use crate::results::{Affected, CheckResult};
use crate::time;

const SMARTCARD_REQUIRED: u32 = 0x0004_0000;

const DES: i64 = 0x1 | 0x2;
const RC4: i64 = 0x4;
const AES: i64 = 0x8 | 0x10;

fn ldap_from(m: &Model, what: &str) -> String {
    format!(
        "{what} via LDAP on {} as {}",
        m.raw.info.server, m.raw.info.account
    )
}

fn etypes(n: &Node) -> Option<i64> {
    n.attrs.int("msds-supportedencryptiontypes")
}

fn etype_names(v: i64) -> String {
    let mut out = Vec::new();
    for (bit, name) in [
        (0x1, "DES-CBC-CRC"),
        (0x2, "DES-CBC-MD5"),
        (0x4, "RC4"),
        (0x8, "AES128"),
        (0x10, "AES256"),
    ] {
        if v & bit != 0 {
            out.push(name);
        }
    }
    if out.is_empty() {
        "none".into()
    } else {
        out.join(", ")
    }
}

fn accounts<'a>(m: &'a Model<'a>) -> impl Iterator<Item = usize> + 'a {
    (0..m.nodes.len()).filter(move |&i| {
        let n = &m.nodes[i];
        matches!(n.kind, Kind::User | Kind::Computer) && n.enabled()
    })
}

// ---------- Kerberos encryption ----------

fn krb_008(m: &Model) -> CheckResult {
    let list: Vec<Affected> = accounts(m)
        .filter_map(|i| {
            let v = etypes(&m.nodes[i]).filter(|v| v & DES != 0)?;
            Some(item(
                m,
                i,
                format!(
                    "Allows {} ({v}): DES keys can be cracked in hours",
                    etype_names(v)
                ),
            ))
        })
        .collect();
    check("AD-KRB-008")
        .expected("No account allows DES encryption types")
        .affected(list, "accounts")
        .evidence(
            "Read from",
            ldap_from(m, "msDS-SupportedEncryptionTypes on users and computers"),
        )
        .done()
}

fn krb_009(m: &Model) -> CheckResult {
    let list: Vec<Affected> = accounts(m)
        .filter(|&i| !is_krbtgt(m, i))
        .filter_map(|i| {
            let n = &m.nodes[i];
            let why = match etypes(n) {
                Some(v) if v & RC4 != 0 && v & AES == 0 => format!(
                    "Only {} allowed ({v}): tickets for it use RC4, which is fast to crack",
                    etype_names(v)
                ),
                Some(v) if v & RC4 != 0 => format!("Allows RC4 next to AES ({})", etype_names(v)),
                None | Some(0) if n.kind == Kind::User && !n.spns().is_empty() => {
                    "Has an SPN and no encryption types set: service tickets default to RC4".into()
                }
                _ => return None,
            };
            Some(item(m, i, why))
        })
        .collect();
    check("AD-KRB-009")
        .expected("No account allows RC4, and every service account has AES set explicitly")
        .affected(list, "accounts")
        .evidence(
            "Read from",
            ldap_from(m, "msDS-SupportedEncryptionTypes and servicePrincipalName"),
        )
        .done()
}

/// A security setting a GPO that applies to DCs sets, from GptTmpl.inf
/// [Registry Values] or Registry.pol: (GPO name, value).
fn dc_policy_values(
    m: &Model,
    policies: &[&SysvolPolicy],
    key: &str,
    value: &str,
) -> Vec<(String, i64)> {
    let inf_key = format!("MACHINE\\{key}\\{value}");
    policies
        .iter()
        .filter(|p| applies_to_dcs(m, p))
        .filter_map(|p| {
            let from_inf = p
                .inf_values("Registry Values", &inf_key)
                .and_then(|v| v.get(1))
                .and_then(|v| v.trim().trim_matches('"').parse().ok());
            let from_pol = p.policy("Machine", key, value).and_then(|v| v.int());
            from_inf.or(from_pol).map(|v| (gpo_name(m, p), v))
        })
        .collect()
}

fn krb_010(m: &Model) -> CheckResult {
    let expected =
        "A GPO that applies to DCs limits Kerberos encryption types to AES (no DES or RC4)";
    let policies = read_policies(m);
    if let Some(r) = not_read(check("AD-KRB-010").expected(expected), &policies) {
        return r;
    }
    let set = dc_policy_values(
        m,
        &policies,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters",
        "SupportedEncryptionTypes",
    );
    let mut list = Vec::new();
    if set.is_empty() {
        list.push(Affected {
            last_seen: None,
            name: "Network security: Configure encryption types allowed for Kerberos".into(),
            kind: "setting".into(),
            location: None,
            reason: Some(
                "Not set by any GPO that applies to DCs: they accept RC4 by default".into(),
            ),
            object: None,
        });
    }
    for (gpo, v) in &set {
        if v & (DES | RC4) != 0 {
            list.push(Affected {
                last_seen: None,
                name: gpo.clone(),
                kind: "gpo".into(),
                location: None,
                reason: Some(format!("Allows {} ({v})", etype_names(*v))),
                object: None,
            });
        }
    }
    let shown: Vec<String> = set
        .iter()
        .map(|(g, v)| format!("{g}: {}", etype_names(*v)))
        .collect();
    let mut out = check("AD-KRB-010")
        .expected(expected)
        .found(if set.is_empty() {
            "Not configured".to_string()
        } else if list.is_empty() {
            "AES only".to_string()
        } else {
            "Weak types allowed".to_string()
        })
        .affected(list, "settings");
    if !shown.is_empty() {
        out = out.evidence("Set by", shown.join("; "));
    }
    out.evidence(
        "Read from",
        format!(
            "GptTmpl.inf [Registry Values] and Registry.pol in {}",
            sysvol_from(m)
        ),
    )
    .done()
}

/// GPOs linked to the domain head (where account policies apply).
fn domain_policies<'a>(m: &Model, policies: &[&'a SysvolPolicy]) -> Vec<&'a SysvolPolicy> {
    let gpos: HashMap<String, usize> = (0..m.nodes.len())
        .filter(|&i| m.nodes[i].kind == Kind::Gpo)
        .map(|i| {
            (
                super::model::rdn_value(&m.nodes[i].dn).to_ascii_lowercase(),
                i,
            )
        })
        .collect();
    policies
        .iter()
        .filter(|p| {
            gpos.get(&p.folder.to_ascii_lowercase())
                .and_then(|g| m.gpo_links.get(g))
                .is_some_and(|l| l.iter().any(|&h| Some(h) == m.domain))
        })
        .copied()
        .collect()
}

fn krb_011(m: &Model) -> CheckResult {
    let expected = "Kerberos policy at or below the defaults: user tickets 10 hours, renewal 7 days, service tickets 600 minutes, clock skew 5 minutes";
    let policies = read_policies(m);
    if let Some(r) = not_read(check("AD-KRB-011").expected(expected), &policies) {
        return r;
    }
    let limits = [
        (
            "MaxTicketAge",
            10,
            "hours",
            "Maximum lifetime for user ticket",
        ),
        (
            "MaxRenewAge",
            7,
            "days",
            "Maximum lifetime for user ticket renewal",
        ),
        (
            "MaxServiceAge",
            600,
            "minutes",
            "Maximum lifetime for service ticket",
        ),
        (
            "MaxClockSkew",
            5,
            "minutes",
            "Maximum tolerance for computer clock synchronization",
        ),
    ];
    let mut list = Vec::new();
    let mut set = Vec::new();
    for p in domain_policies(m, &policies) {
        for (key, max, unit, label) in limits {
            let Some(v) = p
                .inf_values("Kerberos Policy", key)
                .and_then(|v| v.first())
                .and_then(|v| v.trim().parse::<i64>().ok())
            else {
                continue;
            };
            set.push(format!("{}: {key} {v}", gpo_name(m, p)));
            if v > max || v == 0 {
                list.push(Affected {
                    last_seen: None,
                    name: label.into(),
                    kind: "setting".into(),
                    location: Some(gpo_name(m, p)),
                    reason: Some(if v == 0 {
                        format!("{key} = 0: no limit; stolen tickets stay valid")
                    } else {
                        format!(
                            "{v} {unit}, above the default {max}: stolen tickets stay valid longer"
                        )
                    }),
                    object: None,
                });
            }
        }
    }
    let mut out = check("AD-KRB-011")
        .expected(expected)
        .found(
            plural(list.len(), "Kerberos limit is", "Kerberos limits are") + " above the default",
        )
        .affected(list, "settings");
    if !set.is_empty() {
        out = out.evidence("Set by", set.join("; "));
    }
    out.evidence(
        "Read from",
        format!(
            "GptTmpl.inf [Kerberos Policy] of GPOs linked to the domain in {}",
            sysvol_from(m)
        ),
    )
    .done()
}

fn krb_015(m: &Model) -> CheckResult {
    let expected = "A GPO that applies to DCs turns on Kerberos armoring (FAST) support";
    let policies = read_policies(m);
    if let Some(r) = not_read(check("AD-KRB-015").expected(expected), &policies) {
        return r;
    }
    let set = dc_policy_values(
        m,
        &policies,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\KDC\\Parameters",
        "EnableCbacAndArmor",
    );
    let on: Vec<String> = set
        .iter()
        .filter(|(_, v)| *v == 1)
        .map(|(g, _)| g.clone())
        .collect();
    let list = if on.is_empty() {
        vec![Affected {
            last_seen: None,
            name: "KDC support for claims, compound authentication and Kerberos armoring".into(),
            kind: "setting".into(),
            location: None,
            reason: Some(
                "Not turned on: AS requests are not armored, so offline guessing of pre-authentication is possible".into(),
            ),
            object: None,
        }]
    } else {
        Vec::new()
    };
    let mut out = check("AD-KRB-015")
        .expected(expected)
        .found(if on.is_empty() { "Off" } else { "On" })
        .affected(list, "settings");
    if !on.is_empty() {
        out = out.evidence("Set by", on.join(", "));
    }
    out.evidence("Read from", format!("Registry.pol in {}", sysvol_from(m)))
        .done()
}

fn krb_016(m: &Model) -> CheckResult {
    let class = |o: &LdapObject, c: &str| {
        o.strs("objectclass")
            .iter()
            .any(|x| x.eq_ignore_ascii_case(c))
    };
    let silos: Vec<&LdapObject> = m
        .raw
        .authn
        .iter()
        .filter(|o| class(o, "msDS-AuthNPolicySilo"))
        .collect();
    let policies = m
        .raw
        .authn
        .iter()
        .filter(|o| class(o, "msDS-AuthNPolicy"))
        .count();
    let enforced: Vec<String> = silos
        .iter()
        .filter(|s| s.int("msds-authnpolicysiloenforced") == Some(1))
        .map(|s| super::model::rdn_value(s.dn()))
        .collect();
    let list = privileged_where(m, |u| {
        let n = &m.nodes[u];
        if !n.enabled() || is_krbtgt(m, u) {
            return None;
        }
        let silo = n.attrs.str("msds-assignedauthnpolicysilo");
        let policy = n.attrs.str("msds-assignedauthnpolicy");
        match (silo, policy) {
            (None, None) => Some(
                "No authentication policy or silo: its credentials work from any computer".into(),
            ),
            (Some(s), _)
                if !enforced
                    .iter()
                    .any(|e| e.eq_ignore_ascii_case(&super::model::rdn_value(s))) =>
            {
                Some(format!(
                    "In silo {} which is only audited, not enforced",
                    super::model::rdn_value(s)
                ))
            }
            _ => None,
        }
    });
    check("AD-KRB-016")
        .expected("Every admin account is in an enforced authentication policy silo that limits where it can sign in")
        .affected(list, "accounts")
        .evidence(
            "Defined",
            format!(
                "{}, {} ({} enforced)",
                plural(policies, "policy", "policies"),
                plural(silos.len(), "silo", "silos"),
                enforced.len()
            ),
        )
        .evidence(
            "Read from",
            ldap_from(
                m,
                "CN=AuthN Policy Configuration and msDS-AssignedAuthNPolicySilo on users",
            ),
        )
        .done()
}

fn krb_019(m: &Model) -> CheckResult {
    let out = check("AD-KRB-019")
        .expected("krbtgt has been rotated since the domain was built, and its keys are AES only");
    let Some(k) = m.by_sid(&format!("{}-502", m.domain_sid)) else {
        return out
            .not_assessed("The krbtgt account (RID 502) was not found.")
            .done();
    };
    let n = &m.nodes[k];
    let mut why = Vec::new();
    if let (Some(set), Some(created)) = (n.pwd_last_set, n.created) {
        if (set - created).abs() < time::DAY {
            why.push(format!(
                "Password never changed since the account was created ({} ago): any krbtgt hash taken since then still forges tickets",
                days_text(m.days_since(Some(created)))
            ));
        }
    }
    match etypes(n) {
        Some(v) if v & (DES | RC4) != 0 => why.push(format!(
            "Allows {} ({v}): forged tickets can use RC4, which looks like normal traffic",
            etype_names(v)
        )),
        _ => {}
    }
    let list = if why.is_empty() {
        Vec::new()
    } else {
        vec![item(m, k, why.join("; "))]
    };
    out.found(match m.days_since(n.pwd_last_set) {
        Some(d) => format!("Last changed {d} days ago"),
        None => "Never changed".into(),
    })
    .affected(list, "accounts")
    .evidence(
        "Read from",
        ldap_from(
            m,
            "pwdLastSet, whenCreated and msDS-SupportedEncryptionTypes on krbtgt",
        ),
    )
    .done()
}

fn krb_020(m: &Model) -> CheckResult {
    let wanted = [
        ("0CCE9242", "Kerberos Authentication Service (4768, 4771)"),
        ("0CCE9240", "Kerberos Service Ticket Operations (4769)"),
    ];
    each_dc(
        m,
        "AD-KRB-020",
        "Kerberos authentication and service ticket events audited for success and failure",
        "domain controllers",
        |_, d| {
            let Some(audit) = &d.audit else {
                return Eval::Unknown(d.why_missing("audit"));
            };
            let gaps: Vec<String> = wanted
                .iter()
                .filter_map(|(g, name)| {
                    let v = audit
                        .iter()
                        .find(|(k, _)| k.starts_with(g))
                        .map(|(_, v)| v.to_ascii_lowercase())
                        .unwrap_or_default();
                    let missing: Vec<&str> = [("success", "success"), ("failure", "failure")]
                        .into_iter()
                        .filter(|(k, _)| !v.contains(k))
                        .map(|(_, l)| l)
                        .collect();
                    (!missing.is_empty()).then(|| format!("{name}: no {}", missing.join(" or ")))
                })
                .collect();
            if gaps.is_empty() {
                Eval::Ok("both audited".into())
            } else {
                Eval::Bad(gaps.join("; "))
            }
        },
    )
    .done()
}

// ---------- Password policy ----------

fn pwd_003(m: &Model) -> CheckResult {
    let p = m.password_policy();
    let raw = m.raw.domain.first().and_then(|d| d.int("maxpwdage"));
    let never = raw.is_none_or(|v| v == 0 || v == i64::MIN) || p.max_age_days == Some(0);
    let long = p.min_length.unwrap_or(0) >= 14;
    let (failed, found) = if never {
        (
            !long,
            if long {
                "Never expires, with a 14+ character minimum".to_string()
            } else {
                format!(
                    "Never expires, with only a {}-character minimum",
                    p.min_length.unwrap_or(0)
                )
            },
        )
    } else {
        let d = p.max_age_days.unwrap_or(0);
        (d > 365, format!("{d} days"))
    };
    check("AD-PWD-003")
        .expected(
            "Passwords expire within 365 days, or never expire only with a 14+ character minimum",
        )
        .found(found)
        .failed(failed)
        .evidence(
            "Read from",
            ldap_from(m, "maxPwdAge and minPwdLength on the domain head"),
        )
        .done()
}

fn pwd_007(m: &Model) -> CheckResult {
    let p = m.password_policy();
    let out = check("AD-PWD-007")
        .expected(
            "Lockout lasts at least 15 minutes and failures are counted over at least 15 minutes",
        )
        .evidence(
            "Read from",
            ldap_from(
                m,
                "lockoutDuration and lockOutObservationWindow on the domain head",
            ),
        );
    if p.lockout_threshold.unwrap_or(0) == 0 {
        return out
            .found("Lockout is off, so duration does not apply (see AD-PWD-006)")
            .done();
    }
    let mut why = Vec::new();
    match p.lockout_minutes {
        Some(0) | None => {}
        Some(x) if x < 15 => why.push(format!("Accounts unlock after {x} minutes")),
        _ => {}
    }
    match p.window_minutes {
        Some(x) if x < 15 => why.push(format!("Failures reset after {x} minutes")),
        _ => {}
    }
    let found = format!(
        "Duration {}, window {}",
        p.lockout_minutes
            .map(|x| if x == 0 {
                "until an admin unlocks".into()
            } else {
                format!("{x} minutes")
            })
            .unwrap_or_else(|| "not set".into()),
        p.window_minutes
            .map(|x| format!("{x} minutes"))
            .unwrap_or_else(|| "not set".into())
    );
    out.found(if why.is_empty() {
        found
    } else {
        format!("{found}: {}", why.join("; "))
    })
    .failed(!why.is_empty())
    .done()
}

/// A fine-grained password policy, read from its PSO.
struct Pso<'a> {
    obj: &'a LdapObject,
    name: String,
    precedence: i64,
    min_length: i64,
    history: i64,
    complexity: bool,
    reversible: bool,
    lockout: i64,
}

fn flag(o: &LdapObject, attr: &str) -> bool {
    match o.values(attr).first() {
        Some(serde_json::Value::Bool(b)) => *b,
        Some(serde_json::Value::String(s)) => s.eq_ignore_ascii_case("true"),
        Some(serde_json::Value::Number(n)) => n.as_i64() == Some(1),
        _ => false,
    }
}

fn psos<'a>(m: &Model<'a>) -> Vec<Pso<'a>> {
    let raw = m.raw;
    let mut out: Vec<Pso> = raw
        .psos
        .iter()
        .map(|o| Pso {
            obj: o,
            name: o
                .str("name")
                .map(str::to_string)
                .unwrap_or_else(|| super::model::rdn_value(o.dn())),
            precedence: o.int("msds-passwordsettingsprecedence").unwrap_or(i64::MAX),
            min_length: o.int("msds-minimumpasswordlength").unwrap_or(0),
            history: o.int("msds-passwordhistorylength").unwrap_or(0),
            complexity: flag(o, "msds-passwordcomplexityenabled"),
            reversible: flag(o, "msds-passwordreversibleencryptionenabled"),
            lockout: o.int("msds-lockoutthreshold").unwrap_or(0),
        })
        .collect();
    out.sort_by_key(|p| p.precedence);
    out
}

fn pso_item(p: &Pso, reason: impl Into<String>) -> Affected {
    Affected {
        last_seen: None,
        name: p.name.clone(),
        kind: "msDS-PasswordSettings".into(),
        location: Some(p.obj.dn().to_string()),
        reason: Some(reason.into()),
        object: None,
    }
}

const PSO_NOTE: &str = "Reading password settings objects needs delegated rights; a standard account sees none even when they exist";

fn psos_from(m: &Model) -> String {
    ldap_from(m, "CN=Password Settings Container")
}

fn pwd_008(m: &Model) -> CheckResult {
    let all = psos(m);
    let out = check("AD-PWD-008").expected(
        "Every fine-grained password policy applies to someone and has its own precedence",
    );
    if all.is_empty() {
        return out
            .found("No fine-grained password policy is visible")
            .evidence("Note", PSO_NOTE)
            .evidence("Read from", psos_from(m))
            .done();
    }
    let mut by_prec: BTreeMap<i64, Vec<&str>> = BTreeMap::new();
    for p in &all {
        by_prec.entry(p.precedence).or_default().push(&p.name);
    }
    let mut list = Vec::new();
    for p in &all {
        let targets = p.obj.strs("msds-psoappliesto");
        let mut why = Vec::new();
        if targets.is_empty() {
            why.push("Applies to no one".to_string());
        } else {
            let missing: Vec<String> = targets
                .iter()
                .filter(|t| !m.by_dn.contains_key(&t.to_ascii_lowercase()))
                .map(|t| super::model::rdn_value(t))
                .collect();
            if !missing.is_empty() && missing.len() == targets.len() {
                why.push(format!(
                    "Applies only to objects that were not found: {}",
                    missing.join(", ")
                ));
            }
        }
        let same = &by_prec[&p.precedence];
        if same.len() > 1 {
            why.push(format!(
                "Shares precedence {} with {}: which one wins depends on GUID order",
                p.precedence,
                same.iter()
                    .filter(|n| **n != p.name)
                    .copied()
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if !why.is_empty() {
            list.push(pso_item(p, why.join("; ")));
        }
    }
    let raw: Vec<String> = all
        .iter()
        .map(|p| {
            format!(
                "{} (precedence {}): length {}, history {}, complexity {}, lockout {}, applies to {}",
                p.name,
                p.precedence,
                p.min_length,
                p.history,
                if p.complexity { "on" } else { "off" },
                p.lockout,
                p.obj
                    .strs("msds-psoappliesto")
                    .iter()
                    .map(|t| super::model::rdn_value(t))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })
        .collect();
    out.found(format!(
        "{} of {} need attention",
        list.len(),
        plural(all.len(), "policy", "policies")
    ))
    .affected(list, "policies")
    .raw(raw.join("\n"))
    .evidence("Read from", psos_from(m))
    .done()
}

fn pwd_009(m: &Model) -> CheckResult {
    let all = psos(m);
    let d = m.password_policy();
    let out = check("AD-PWD-009")
        .expected("No fine-grained password policy is weaker than the domain policy");
    if all.is_empty() {
        return out
            .found("No fine-grained password policy is visible")
            .evidence("Note", PSO_NOTE)
            .evidence("Read from", psos_from(m))
            .done();
    }
    let list: Vec<Affected> = all
        .iter()
        .filter_map(|p| {
            let mut why = Vec::new();
            if let Some(l) = d.min_length.filter(|l| p.min_length < *l) {
                why.push(format!("minimum length {} (domain {l})", p.min_length));
            }
            if let Some(h) = d.history.filter(|h| p.history < *h) {
                why.push(format!("history {} (domain {h})", p.history));
            }
            if !p.complexity && d.complexity == Some(true) {
                why.push("complexity off".into());
            }
            if p.reversible {
                why.push("reversible encryption on".into());
            }
            if p.lockout == 0 && d.lockout_threshold.unwrap_or(0) > 0 {
                why.push("no lockout".into());
            }
            (!why.is_empty()).then(|| {
                pso_item(
                    p,
                    format!("Weaker than the domain policy: {}", why.join(", ")),
                )
            })
        })
        .collect();
    out.found(plural(list.len(), "policy is", "policies are") + " weaker than the domain policy")
        .affected(list, "policies")
        .evidence("Read from", psos_from(m))
        .done()
}

fn pwd_010(m: &Model) -> CheckResult {
    let all = psos(m);
    let domain = m.password_policy().min_length.unwrap_or(0);
    // Account to (policy that applies directly, policy that applies through a group).
    let mut direct: HashMap<usize, &Pso> = HashMap::new();
    let mut via_group: HashMap<usize, &Pso> = HashMap::new();
    for p in &all {
        for t in p.obj.strs("msds-psoappliesto") {
            let Some(&i) = m.by_dn.get(&t.to_ascii_lowercase()) else {
                continue;
            };
            if m.nodes[i].kind == Kind::Group {
                for u in m.recursive_members(i) {
                    via_group.entry(u).or_insert(p);
                }
            } else {
                direct.entry(i).or_insert(p);
            }
        }
    }
    let list = privileged_where(m, |u| {
        if !m.nodes[u].enabled() || is_krbtgt(m, u) {
            return None;
        }
        let (len, from) = match direct.get(&u).or_else(|| via_group.get(&u)) {
            Some(p) => (p.min_length, p.name.clone()),
            None => (domain, "the domain policy".into()),
        };
        (len < 14).then(|| format!("Minimum password length {len} from {from}"))
    });
    let mut out = check("AD-PWD-010")
        .expected("Every admin account gets a 14+ character minimum, from a fine-grained policy or the domain policy")
        .affected(list, "accounts");
    if all.is_empty() {
        out = out.evidence("Note", PSO_NOTE);
    }
    out.evidence("Read from", psos_from(m)).done()
}

fn pwd_020(m: &Model) -> CheckResult {
    let list: Vec<Affected> = m
        .raw
        .pwdattrs
        .iter()
        .map(|o| {
            let name = o
                .str("samaccountname")
                .map(str::to_string)
                .unwrap_or_else(|| super::model::rdn_value(o.dn()));
            match m.by_dn.get(&o.dn().to_ascii_lowercase()) {
                Some(&i) => item(
                    m,
                    i,
                    "Has a value in userPassword, unixUserPassword, msSFU30Password or os400Password, which LDAP can return",
                ),
                None => Affected {
                    last_seen: None,
                    name,
                    kind: o.class().unwrap_or("object").into(),
                    location: Some(o.dn().to_string()),
                    reason: Some(
                        "Has a value in a readable password attribute".into(),
                    ),
                    object: None,
                },
            }
        })
        .collect();
    check("AD-PWD-020")
        .expected("No account stores a password in userPassword or a similar readable attribute")
        .affected(list, "accounts")
        .evidence(
            "Note",
            "Only which accounts have a value was collected, never the value",
        )
        .evidence(
            "Read from",
            ldap_from(m, "(userPassword=*) and similar presence filters"),
        )
        .done()
}

fn pwd_021(m: &Model) -> CheckResult {
    each_dc(
        m,
        "AD-PWD-021",
        "The Entra Password Protection DC agent runs on every DC",
        "domain controllers",
        |_, d| {
            let installed = d.software.as_ref().map(|s| {
                s.iter().any(|x| {
                    let n = x.name.to_ascii_lowercase();
                    n.contains("password protection") && n.contains("dc agent")
                })
            });
            let service = d
                .services
                .as_ref()
                .map(|_| d.running("AzureADPasswordProtectionDCAgent"));
            match (installed, service) {
                (_, Some(true)) => Eval::Ok("DC agent running".into()),
                (Some(true), _) => {
                    Eval::Bad("DC agent installed but its service is not running".into())
                }
                (None, None) => Eval::Unknown(d.why_missing("software")),
                _ => Eval::Bad("Not installed: banned and breached passwords are accepted".into()),
            }
        },
    )
    .done()
}

fn pwd_022(m: &Model) -> CheckResult {
    let rotation = m
        .raw
        .domain
        .first()
        .is_some_and(|d| flag(d, "msds-expirepasswordsonsmartcardonlyaccounts"));
    let list: Vec<Affected> = if rotation {
        Vec::new()
    } else {
        (0..m.nodes.len())
            .filter(|&i| {
                let n = &m.nodes[i];
                n.kind == Kind::User && n.enabled() && n.flag(SMARTCARD_REQUIRED)
            })
            .filter_map(|i| {
                let age = m.days_since(m.nodes[i].pwd_last_set);
                age.is_none_or(|d| d > 365).then(|| {
                    item(
                        m,
                        i,
                        format!(
                            "Smart card required, password hash {} old: a stolen NT hash keeps working",
                            days_text(age)
                        ),
                    )
                })
            })
            .collect()
    };
    check("AD-PWD-022")
        .expected("Smart-card-only accounts have their hidden password rotated, by the domain setting or within a year")
        .affected(list, "accounts")
        .evidence(
            "Domain rotation",
            if rotation { "On" } else { "Off" },
        )
        .evidence(
            "Read from",
            ldap_from(
                m,
                "msDS-ExpirePasswordsOnSmartCardOnlyAccounts and pwdLastSet",
            ),
        )
        .done()
}

pub static RULES: &[Rule] = &[
    Rule {
        id: "AD-KRB-008",
        needs: &["users", "computers"],
        run: krb_008,
    },
    Rule {
        id: "AD-KRB-009",
        needs: &["users", "computers"],
        run: krb_009,
    },
    Rule {
        id: "AD-KRB-010",
        needs: &["sysvol", "gpos", "containers"],
        run: krb_010,
    },
    Rule {
        id: "AD-KRB-011",
        needs: &["sysvol", "gpos", "domain"],
        run: krb_011,
    },
    Rule {
        id: "AD-KRB-015",
        needs: &["sysvol", "gpos", "containers"],
        run: krb_015,
    },
    Rule {
        id: "AD-KRB-016",
        needs: &["users", "groups", "authn"],
        run: krb_016,
    },
    Rule {
        id: "AD-KRB-019",
        needs: &["users"],
        run: krb_019,
    },
    Rule {
        id: "AD-KRB-020",
        needs: &["dcconfig"],
        run: krb_020,
    },
    Rule {
        id: "AD-PWD-003",
        needs: &["domain"],
        run: pwd_003,
    },
    Rule {
        id: "AD-PWD-007",
        needs: &["domain"],
        run: pwd_007,
    },
    Rule {
        id: "AD-PWD-008",
        needs: &["psos"],
        run: pwd_008,
    },
    Rule {
        id: "AD-PWD-009",
        needs: &["psos", "domain"],
        run: pwd_009,
    },
    Rule {
        id: "AD-PWD-010",
        needs: &["psos", "domain", "users", "groups"],
        run: pwd_010,
    },
    Rule {
        id: "AD-PWD-020",
        needs: &["pwdattrs"],
        run: pwd_020,
    },
    Rule {
        id: "AD-PWD-021",
        needs: &["dcconfig"],
        run: pwd_021,
    },
    Rule {
        id: "AD-PWD-022",
        needs: &["users", "domain"],
        run: pwd_022,
    },
];
