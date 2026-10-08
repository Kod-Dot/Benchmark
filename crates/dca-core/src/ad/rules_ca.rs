//! Certification authority configuration read on the CA servers themselves
//! (the `certsvc` part, on DCs or member servers): ESC6, ESC7, ESC8, ESC11
//! and ESC16, key protection, auditing and templates that are published but
//! not used.

use std::collections::BTreeSet;

use serde_json::Value;

use super::model::Model;
use super::rules::{check, plural, Rule};
use crate::results::{Affected, CheckResult};

const EDITF_ATTRIBUTESUBJECTALTNAME2: i64 = 0x0004_0000;
const IF_ENFORCEENCRYPTICERTREQUEST: i64 = 0x0000_0200;
const CA_ACCESS_ADMIN: i64 = 0x1;
const CA_ACCESS_OFFICER: i64 = 0x2;
/// Every CA audit category (start/stop, backup, requests, revocation,
/// security, key archival, configuration).
const AUDIT_ALL: i64 = 0x7f;
const SECURITY_EXTENSION: &str = "1.3.6.1.4.1.311.25.2";

struct Ca<'a> {
    host: &'a str,
    data: &'a Value,
}

/// Every machine that reported a CA, from the DC and endpoint reads.
fn cas<'a>(m: &Model<'a>) -> (Vec<Ca<'a>>, usize) {
    let mut out = Vec::new();
    let mut read = 0;
    let dcs = m
        .raw
        .dcconfig
        .iter()
        .filter_map(|d| Some((d.name.as_str(), d.data.as_ref()?.certsvc.as_ref()?)));
    let eps = m
        .raw
        .endpoints
        .iter()
        .filter_map(|e| Some((e.name.as_str(), e.part("certsvc")?)));
    for (host, data) in dcs.chain(eps) {
        read += 1;
        if data.get("installed").and_then(Value::as_bool) == Some(true) {
            out.push(Ca { host, data });
        }
    }
    (out, read)
}

fn int(v: &Value, key: &str) -> Option<i64> {
    v.get(key).and_then(Value::as_i64)
}

fn ca_item(ca: &Ca, reason: String) -> Affected {
    Affected {
        last_seen: None,
        name: ca
            .data
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or(ca.host)
            .to_string(),
        kind: "ca".into(),
        location: Some(ca.host.to_string()),
        reason: Some(reason),
        object: None,
    }
}

fn per_ca(
    m: &Model,
    id: &str,
    expected: &str,
    eval: impl Fn(&Ca) -> Result<Option<String>, String>,
) -> CheckResult {
    let out = check(id).expected(expected);
    let (list, read) = cas(m);
    if list.is_empty() {
        return if read == 0 {
            out.not_assessed(
                "No CA server was read: the CA settings come from the DC and member server reads.",
            )
            .done()
        } else {
            out.found("No machine that was read runs Certificate Services")
                .evidence(
                    "Read from",
                    "Certificate Services registry on the machines read over PowerShell remoting",
                )
                .done()
        };
    }
    let mut bad = Vec::new();
    let mut lines = Vec::new();
    let mut unknown = Vec::new();
    for ca in &list {
        match eval(ca) {
            Ok(None) => lines.push(format!("{}: as expected", ca.host)),
            Ok(Some(why)) => {
                lines.push(format!("{}: {why}", ca.host));
                bad.push(ca_item(ca, why));
            }
            Err(why) => unknown.push(format!("{} ({why})", ca.host)),
        }
    }
    if bad.is_empty() && lines.is_empty() {
        return out
            .not_assessed(format!("No CA could be assessed: {}", unknown.join("; ")))
            .done();
    }
    let mut out = out
        .found(format!(
            "{} of {}",
            bad.len(),
            plural(list.len(), "CA", "CAs")
        ))
        .affected(bad, "CAs")
        .raw(lines.join("\n"))
        .evidence(
            "Read from",
            "Certificate Services registry on the CA servers over PowerShell remoting",
        );
    if !unknown.is_empty() {
        out = out.evidence("Not assessed on", unknown.join("; "));
    }
    out.done()
}

fn pki_007(m: &Model) -> CheckResult {
    per_ca(m, "AD-PKI-007", "No CA honours subject alternative names in request attributes (EDITF_ATTRIBUTESUBJECTALTNAME2 off)", |ca| {
        let flags = int(ca.data, "edit_flags").ok_or("the policy module's EditFlags were not returned")?;
        Ok((flags & EDITF_ATTRIBUTESUBJECTALTNAME2 != 0).then(|| {
            "EDITF_ATTRIBUTESUBJECTALTNAME2 is on: any template that issues client authentication certificates lets the requester name any user (ESC6)".to_string()
        }))
    })
}

fn pki_008(m: &Model) -> CheckResult {
    per_ca(
        m,
        "AD-PKI-008",
        "Only Tier 0 admins hold ManageCA or ManageCertificates on a CA",
        |ca| {
            let aces = ca
                .data
                .get("aces")
                .and_then(Value::as_array)
                .ok_or("the CA's permissions were not returned")?;
            let holders: BTreeSet<String> = aces
                .iter()
                .filter(|a| a.get("allow").and_then(Value::as_bool) != Some(false))
                .filter(|a| {
                    int(a, "mask").is_some_and(|x| x & (CA_ACCESS_ADMIN | CA_ACCESS_OFFICER) != 0)
                })
                .filter_map(|a| a.get("sid").and_then(Value::as_str))
                .filter(|sid| {
                    !m.is_default_admin(sid) && !m.by_sid(sid).is_some_and(|i| m.nodes[i].tier0)
                })
                .map(|sid| {
                    m.by_sid(sid)
                        .map(|i| m.nodes[i].name.clone())
                        .unwrap_or_else(|| sid.to_string())
                })
                .collect();
            Ok((!holders.is_empty()).then(|| {
            format!(
                "ManageCA or ManageCertificates held by {}: they can turn on ESC6 or approve any request (ESC7)",
                holders.into_iter().collect::<Vec<_>>().join(", ")
            )
        }))
        },
    )
}

fn pki_009(m: &Model) -> CheckResult {
    per_ca(
        m,
        "AD-PKI-009",
        "Web enrollment is off, or served only over HTTPS with Extended Protection",
        |ca| {
            let web = ca
                .data
                .get("web")
                .ok_or("web enrollment state was not returned")?;
            if web.get("installed").and_then(Value::as_bool) != Some(true) {
                return Ok(None);
            }
            if let Some(e) = web.get("error").and_then(Value::as_str) {
                return Err(format!("IIS settings could not be read: {e}"));
            }
            let http = web.get("http").and_then(Value::as_bool) == Some(true);
            let epa = web.get("epa").and_then(Value::as_str).unwrap_or_default();
            let mut why = Vec::new();
            if http {
                why.push("served over HTTP");
            }
            if !epa.eq_ignore_ascii_case("Require") {
                why.push("Extended Protection for Authentication is not required");
            }
            Ok((!why.is_empty()).then(|| {
            format!("Web enrollment is {}: NTLM can be relayed to it to get a certificate as the victim (ESC8)", why.join(" and "))
        }))
        },
    )
}

fn pki_011(m: &Model) -> CheckResult {
    per_ca(
        m,
        "AD-PKI-011",
        "Every CA requires encrypted RPC requests (IF_ENFORCEENCRYPTICERTREQUEST)",
        |ca| {
            let flags =
                int(ca.data, "interface_flags").ok_or("InterfaceFlags were not returned")?;
            Ok((flags & IF_ENFORCEENCRYPTICERTREQUEST == 0).then(|| {
            "IF_ENFORCEENCRYPTICERTREQUEST is off: NTLM can be relayed to the CA's RPC interface (ESC11)".to_string()
        }))
        },
    )
}

fn pki_015(m: &Model) -> CheckResult {
    per_ca(
        m,
        "AD-PKI-015",
        "No CA disables the szOID_NTDS_CA_SECURITY_EXT security extension",
        |ca| {
            let list = ca
                .data
                .get("disabled_extensions")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            Ok(list
            .iter()
            .any(|v| v.as_str() == Some(SECURITY_EXTENSION))
            .then(|| "The SID security extension is disabled CA-wide: certificates no longer bind strongly to the account (ESC16)".to_string()))
        },
    )
}

fn pki_022(m: &Model) -> CheckResult {
    per_ca(
        m,
        "AD-PKI-022",
        "CA private keys are protected by a hardware security module",
        |ca| {
            let provider = ca
                .data
                .get("provider")
                .and_then(Value::as_str)
                .ok_or("the key storage provider was not returned")?;
            let software = provider.starts_with("Microsoft")
                && !provider.to_ascii_lowercase().contains("platform crypto");
            Ok(software.then(|| {
            format!("The CA key is in {provider}, a software provider: an admin of the server can export it and forge any certificate")
        }))
        },
    )
}

fn pki_023(m: &Model) -> CheckResult {
    per_ca(
        m,
        "AD-PKI-023",
        "Every CA audits all event categories (AuditFilter 127)",
        |ca| {
            let filter = int(ca.data, "audit_filter").unwrap_or(0);
            Ok((filter & AUDIT_ALL != AUDIT_ALL).then(|| {
            format!("AuditFilter is {filter}: certificate requests, approvals and configuration changes are not all logged")
        }))
        },
    )
}

fn pki_024(m: &Model) -> CheckResult {
    // Published template names per CA, from the enrollment service objects.
    let published = |ca: &Ca| -> Vec<String> {
        let name = ca
            .data
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        m.raw
            .pki
            .iter()
            .filter(|o| {
                o.strs("objectclass")
                    .iter()
                    .any(|c| c.eq_ignore_ascii_case("pKIEnrollmentService"))
            })
            .filter(|o| super::model::rdn_value(o.dn()).eq_ignore_ascii_case(name))
            .flat_map(|o| {
                o.strs("certificatetemplates")
                    .into_iter()
                    .map(str::to_string)
            })
            .collect()
    };
    let oid_of = |template: &str| -> Option<String> {
        m.raw
            .pki
            .iter()
            .find(|o| super::model::rdn_value(o.dn()).eq_ignore_ascii_case(template))
            .and_then(|o| o.str("mspki-cert-template-oid"))
            .map(str::to_string)
    };
    per_ca(
        m,
        "AD-PKI-024",
        "Every template a CA publishes was used in the last 90 days",
        |ca| {
            let issued: BTreeSet<String> = ca
                .data
                .get("issued_templates")
                .and_then(Value::as_array)
                .ok_or("issued certificates could not be read from the CA database")?
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_ascii_lowercase)
                .collect();
            let unused: Vec<String> = published(ca)
                .into_iter()
                .filter(|t| {
                    !issued.contains(&t.to_ascii_lowercase())
                        && !oid_of(t).is_some_and(|o| issued.contains(&o.to_ascii_lowercase()))
                })
                .collect();
            Ok((!unused.is_empty()).then(|| {
                format!(
                "Published but not used in 90 days: {}. Each published template is attack surface",
                unused.join(", ")
            )
            }))
        },
    )
}

fn hunt_017(m: &Model) -> CheckResult {
    let (list_cas, read) = cas(m);
    let out = check("HUNT-AD-017")
        .expected("No certificate in the last 90 days was requested by one account for a privileged user's name")
        .evidence("Read from", "The CA database (requests that named another user), on each CA");
    let with_data: Vec<&Ca> = list_cas
        .iter()
        .filter(|c| c.data.get("san_requests").is_some_and(Value::is_array))
        .collect();
    if with_data.is_empty() {
        return out
            .not_assessed(if read == 0 || list_cas.is_empty() {
                "No certification authority was read.".to_string()
            } else {
                "The CA database could not be read for requests (needs a collector that reads san_requests, run as a CA administrator or auditor).".to_string()
            })
            .done();
    }
    // Privileged users by user principal name and by account name.
    let admins = m.privileged_users();
    let mut by_name: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for &i in admins.keys() {
        let n = &m.nodes[i];
        by_name.insert(n.name.to_lowercase(), i);
        if let Some(u) = n.attrs.str("userprincipalname") {
            by_name.insert(u.to_lowercase(), i);
        }
    }
    let mut list = Vec::new();
    for ca in &with_data {
        for r in ca
            .data
            .get("san_requests")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let upn = r
                .get("upn")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_lowercase();
            let short = upn.split('@').next().unwrap_or_default().to_string();
            let Some(&i) = by_name.get(&upn).or_else(|| by_name.get(&short)) else {
                continue;
            };
            let requester = r
                .get("requester")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if requester
                .rsplit('\\')
                .next()
                .unwrap_or_default()
                .eq_ignore_ascii_case(&m.nodes[i].name)
            {
                continue;
            }
            let issued = r.get("issued").and_then(Value::as_str);
            list.push(
                ca_item(
                    ca,
                    format!(
                        "{requester} obtained a certificate for {} (privileged) with template {}{}",
                        m.nodes[i].name,
                        r.get("template")
                            .and_then(Value::as_str)
                            .unwrap_or("unknown"),
                        if r.get("from_attributes").and_then(Value::as_bool) == Some(true) {
                            ", the name given in request attributes (ESC6)"
                        } else {
                            ""
                        }
                    ),
                )
                .seen_at(issued),
            );
        }
    }
    out.found(
        plural(list.len(), "request", "requests") + " for a privileged user's name by someone else",
    )
    .affected(list, "requests")
    .done()
}

pub static RULES: &[Rule] = &[
    Rule {
        id: "HUNT-AD-017",
        needs: &["users", "groups"],
        run: hunt_017,
    },
    Rule {
        id: "AD-PKI-007",
        needs: &[],
        run: pki_007,
    },
    Rule {
        id: "AD-PKI-008",
        needs: &["domain", "groups"],
        run: pki_008,
    },
    Rule {
        id: "AD-PKI-009",
        needs: &[],
        run: pki_009,
    },
    Rule {
        id: "AD-PKI-011",
        needs: &[],
        run: pki_011,
    },
    Rule {
        id: "AD-PKI-015",
        needs: &[],
        run: pki_015,
    },
    Rule {
        id: "AD-PKI-022",
        needs: &[],
        run: pki_022,
    },
    Rule {
        id: "AD-PKI-023",
        needs: &[],
        run: pki_023,
    },
    Rule {
        id: "AD-PKI-024",
        needs: &["pki"],
        run: pki_024,
    },
];
