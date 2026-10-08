//! Active Directory Certificate Services, as published in the forest's
//! configuration partition: templates, enterprise CAs, the NTAuth store and
//! the PKI containers, with their permissions. Settings that live only in a
//! CA's registry (ESC6, ESC7, ESC11, ESC16) need the CA itself and are not
//! read here.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use base64::Engine as _;

use super::model::{well_known_name, Kind, Model};
use super::raw::LdapObject;
use super::rules::{check, days_text, plural, Rule};
use super::sd::{self, right, AceType};
use super::x509::{self, Cert};
use crate::results::{Affected, CheckResult};
use crate::time;

const ENROLL: &str = "0e10c968-78fb-11d2-90d4-00c04f79dc55";
const AUTO_ENROLL: &str = "a05b8cc2-17bc-4802-a710-e7c15ab866a2";

const CLIENT_AUTH: &str = "1.3.6.1.5.5.7.3.2";
const PKINIT: &str = "1.3.6.1.5.2.3.4";
const SMARTCARD_LOGON: &str = "1.3.6.1.4.1.311.20.2.2";
const ANY_PURPOSE: &str = "2.5.29.37.0";
const REQUEST_AGENT: &str = "1.3.6.1.4.1.311.20.2.1";

const ENROLLEE_SUPPLIES_SUBJECT: i64 = 0x1;
const PEND_ALL_REQUESTS: i64 = 0x2;
const NO_SECURITY_EXTENSION: i64 = 0x8_0000;

const LONG_VALIDITY_DAYS: i64 = 2 * 365 + 1;
const CA_EXPIRY_DAYS: i64 = 180;

fn b64(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

fn read_from(m: &Model) -> String {
    format!(
        "CN=Public Key Services in the configuration partition, via LDAP on {} as {}",
        m.raw.info.server, m.raw.info.account
    )
}

fn has_class(o: &LdapObject, class: &str) -> bool {
    o.strs("objectclass")
        .iter()
        .any(|c| c.eq_ignore_ascii_case(class))
}

fn obj_name(o: &LdapObject) -> String {
    o.str("name")
        .map(str::to_string)
        .unwrap_or_else(|| super::model::rdn_value(o.dn()))
}

/// A principal's display name: its account name, a well-known name, or the SID.
fn who(m: &Model, sid: &str) -> String {
    m.by_sid(sid)
        .map(|i| m.nodes[i].name.clone())
        .or_else(|| well_known_name(sid).map(str::to_string))
        .unwrap_or_else(|| sid.to_string())
}

/// Admins and Tier 0 principals, whose rights on PKI objects are expected.
fn privileged(m: &Model, sid: &str) -> bool {
    m.is_default_admin(sid) || m.by_sid(sid).is_some_and(|i| m.nodes[i].tier0)
}

#[derive(Default)]
struct Rights {
    enroll: BTreeSet<String>,
    write: BTreeMap<String, BTreeSet<&'static str>>,
}

/// Who, other than admins, can enroll in or change an object.
fn rights(m: &Model, o: &LdapObject) -> Rights {
    let mut out = Rights::default();
    let Some(sd) = o
        .str("ntsecuritydescriptor")
        .and_then(b64)
        .and_then(|b| sd::parse(&b))
    else {
        return out;
    };
    if let Some(owner) = sd.owner.as_deref().filter(|s| !privileged(m, s)) {
        out.write.entry(who(m, owner)).or_default().insert("Owner");
    }
    for ace in sd
        .dacl
        .iter()
        .filter(|a| a.kind == AceType::Allow && !a.inherit_only() && !privileged(m, &a.sid))
    {
        let name = who(m, &ace.sid);
        let ot = ace.object_type.as_deref();
        let all = ace.mask & right::GENERIC_ALL != 0
            || ace.mask & right::FULL_CONTROL == right::FULL_CONTROL;
        if all
            || (ace.mask & right::CONTROL_ACCESS != 0
                && matches!(ot, None | Some(ENROLL) | Some(AUTO_ENROLL)))
        {
            out.enroll.insert(name.clone());
        }
        let mut kinds = Vec::new();
        if all {
            kinds.push("Full control");
        } else {
            if ace.mask & right::WRITE_DACL != 0 {
                kinds.push("Modify permissions");
            }
            if ace.mask & right::WRITE_OWNER != 0 {
                kinds.push("Take ownership");
            }
            if ace.mask & right::GENERIC_WRITE != 0
                || (ace.mask & right::WRITE_PROP != 0 && ot.is_none())
            {
                kinds.push("Write all properties");
            } else if ace.mask & right::WRITE_PROP != 0 {
                kinds.push("Write a property");
            }
        }
        for k in kinds {
            out.write.entry(name.clone()).or_default().insert(k);
        }
    }
    out
}

struct Template<'a> {
    o: &'a LdapObject,
    name: String,
    published_on: Vec<String>,
    rights: Rights,
}

impl Template<'_> {
    fn flag(&self, attr: &str, bit: i64) -> bool {
        self.o.int(attr).is_some_and(|v| v & bit != 0)
    }
    /// The usages a certificate gets: application policies on schema v2+
    /// templates, the EKUs otherwise.
    fn ekus(&self) -> Vec<&str> {
        let app = self.o.strs("mspki-certificate-application-policy");
        let schema = self.o.int("mspki-template-schema-version").unwrap_or(1);
        if schema >= 2 && !app.is_empty() {
            app
        } else {
            self.o.strs("pkiextendedkeyusage")
        }
    }
    fn any_purpose(&self) -> bool {
        let e = self.ekus();
        e.is_empty() || e.contains(&ANY_PURPOSE)
    }
    fn authenticates(&self) -> bool {
        self.any_purpose()
            || self
                .ekus()
                .iter()
                .any(|e| [CLIENT_AUTH, PKINIT, SMARTCARD_LOGON].contains(e))
    }
    fn supplies_subject(&self) -> bool {
        self.flag("mspki-certificate-name-flag", ENROLLEE_SUPPLIES_SUBJECT)
    }
    /// Issued without a CA manager's approval or an authorized signature.
    fn unattended(&self) -> bool {
        !self.flag("mspki-enrollment-flag", PEND_ALL_REQUESTS)
            && self.o.int("mspki-ra-signature").unwrap_or(0) == 0
    }
    fn published(&self) -> bool {
        !self.published_on.is_empty()
    }
    fn enrollers(&self) -> String {
        self.rights
            .enroll
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(", ")
    }
    fn item(&self, reason: impl Into<String>) -> Affected {
        Affected {
            last_seen: None,
            name: self.name.clone(),
            kind: "template".into(),
            location: (!self.published_on.is_empty())
                .then(|| format!("Published on {}", self.published_on.join(", "))),
            reason: Some(reason.into()),
            object: None,
        }
    }
}

pub(super) fn cas<'a>(m: &Model<'a>) -> impl Iterator<Item = &'a LdapObject> + 'a {
    let raw = m.raw;
    raw.pki
        .iter()
        .filter(|o| has_class(o, "pKIEnrollmentService"))
}

fn templates<'a>(m: &'a Model) -> Vec<Template<'a>> {
    let mut published: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for ca in cas(m) {
        for t in ca.strs("certificatetemplates") {
            published
                .entry(t.to_lowercase())
                .or_default()
                .push(obj_name(ca));
        }
    }
    m.raw
        .pki
        .iter()
        .filter(|o| has_class(o, "pKICertificateTemplate"))
        .map(|o| {
            let name = obj_name(o);
            Template {
                o,
                published_on: published
                    .get(&name.to_lowercase())
                    .cloned()
                    .unwrap_or_default(),
                name,
                rights: rights(m, o),
            }
        })
        .collect()
}

fn template_check(
    m: &Model,
    id: &str,
    expected: &str,
    noun: (&str, &str),
    test: impl Fn(&Template) -> Option<String>,
) -> CheckResult {
    let all = templates(m);
    let list: Vec<Affected> = all
        .iter()
        .filter_map(|t| test(t).map(|r| t.item(r)))
        .collect();
    check(id)
        .expected(expected)
        .found(plural(list.len(), noun.0, noun.1))
        .affected(list, "templates")
        .evidence("Templates read", all.len().to_string())
        .evidence("Read from", read_from(m))
        .done()
}

// ---------- Templates (ESC1-4, 9, 13, 15) ----------

fn pki_002(m: &Model) -> CheckResult {
    template_check(
        m,
        "AD-PKI-002",
        "No published template lets non-admins choose the subject of an authentication certificate",
        ("template allows ESC1", "templates allow ESC1"),
        |t| {
            (t.published()
                && t.supplies_subject()
                && t.authenticates()
                && t.unattended()
                && !t.rights.enroll.is_empty())
            .then(|| {
                format!(
                    "Enrollee supplies the subject; authentication usage; enrollable by {}",
                    t.enrollers()
                )
            })
        },
    )
}

fn pki_003(m: &Model) -> CheckResult {
    template_check(
        m,
        "AD-PKI-003",
        "No published template with Any Purpose or no usage restriction is enrollable by non-admins",
        ("template allows ESC2", "templates allow ESC2"),
        |t| {
            (t.published() && t.any_purpose() && t.unattended() && !t.rights.enroll.is_empty()).then(|| {
                format!(
                    "{}; enrollable by {}",
                    if t.ekus().is_empty() { "No usage restriction" } else { "Any Purpose" },
                    t.enrollers()
                )
            })
        },
    )
}

fn pki_004(m: &Model) -> CheckResult {
    template_check(
        m,
        "AD-PKI-004",
        "Enrollment agent templates are limited to named enrollment agents and require approval",
        (
            "enrollment agent template is",
            "enrollment agent templates are",
        ),
        |t| {
            (t.published()
                && t.ekus().contains(&REQUEST_AGENT)
                && t.unattended()
                && !t.rights.enroll.is_empty())
            .then(|| format!("Certificate Request Agent; enrollable by {}", t.enrollers()))
        },
    )
    .with_found_suffix(" open to non-admins")
}

fn pki_005(m: &Model) -> CheckResult {
    template_check(
        m,
        "AD-PKI-005",
        "Only PKI admins can change certificate templates",
        ("template is", "templates are"),
        |t| {
            (!t.rights.write.is_empty()).then(|| {
                t.rights
                    .write
                    .iter()
                    .map(|(p, k)| {
                        format!("{p}: {}", k.iter().copied().collect::<Vec<_>>().join(", "))
                    })
                    .collect::<Vec<_>>()
                    .join("; ")
            })
        },
    )
    .with_found_suffix(" writable by non-admins")
}

fn pki_010(m: &Model) -> CheckResult {
    template_check(
        m,
        "AD-PKI-010",
        "No published authentication template drops the SID security extension",
        ("template drops", "templates drop"),
        |t| {
            (t.published()
                && t.authenticates()
                && t.flag("mspki-enrollment-flag", NO_SECURITY_EXTENSION)
                && !t.rights.enroll.is_empty())
            .then(|| {
                format!(
                    "CT_FLAG_NO_SECURITY_EXTENSION set; enrollable by {}",
                    t.enrollers()
                )
            })
        },
    )
    .with_found_suffix(" the SID security extension (ESC9)")
}

fn pki_012(m: &Model) -> CheckResult {
    // Issuance policy OIDs that put a group into the certificate holder's token.
    let linked: BTreeMap<&str, Vec<&str>> = m
        .raw
        .pki
        .iter()
        .filter_map(|o| {
            Some((
                o.str("mspki-cert-template-oid")?,
                o.strs("msds-oidtogrouplink"),
            ))
        })
        .filter(|(_, g)| !g.is_empty())
        .collect();
    template_check(
        m,
        "AD-PKI-012",
        "No template enrollable by non-admins carries an issuance policy linked to a group",
        ("template grants", "templates grant"),
        |t| {
            if !t.published() || t.rights.enroll.is_empty() {
                return None;
            }
            let groups: Vec<String> =
                t.o.strs("mspki-certificate-policy")
                    .iter()
                    .filter_map(|p| linked.get(p))
                    .flatten()
                    .map(|dn| super::model::rdn_value(dn))
                    .collect();
            (!groups.is_empty()).then(|| {
                format!(
                    "Linked to {}; enrollable by {}",
                    groups.join(", "),
                    t.enrollers()
                )
            })
        },
    )
    .with_found_suffix(" group membership through an issuance policy (ESC13)")
}

fn pki_014(m: &Model) -> CheckResult {
    template_check(
        m,
        "AD-PKI-014",
        "No published schema version 1 template lets non-admins supply the subject",
        ("template allows", "templates allow"),
        |t| {
            (t.published()
                && t.o.int("mspki-template-schema-version").unwrap_or(1) == 1
                && t.supplies_subject()
                && !t.rights.enroll.is_empty())
            .then(|| {
                format!(
                    "Schema version 1 with enrollee-supplied subject; enrollable by {}",
                    t.enrollers()
                )
            })
        },
    )
    .with_found_suffix(" ESC15 (application policies in the request)")
}

fn pki_018(m: &Model) -> CheckResult {
    template_check(
        m,
        "AD-PKI-018",
        "Templates with authentication or enrollment agent usage require CA manager approval or an authorized signature when the subject is supplied in the request",
        ("sensitive template issues", "sensitive templates issue"),
        |t| {
            (t.published() && (t.authenticates() || t.ekus().contains(&REQUEST_AGENT)) && t.supplies_subject() && t.unattended())
                .then(|| "Enrollee supplies the subject and no approval is needed".to_string())
        },
    )
    .with_found_suffix(" without approval")
}

/// pKIExpirationPeriod: a negative 100-nanosecond interval, little-endian.
fn validity_days(t: &Template) -> Option<i64> {
    let b = b64(t.o.str("pkiexpirationperiod")?)?;
    let v = i64::from_le_bytes(b.get(..8)?.try_into().ok()?);
    Some(v.unsigned_abs() as i64 / 10_000_000 / time::DAY)
}

fn pki_019(m: &Model) -> CheckResult {
    template_check(
        m,
        "AD-PKI-019",
        "Published templates issue certificates valid for two years or less",
        ("template issues", "templates issue"),
        |t| {
            let d = validity_days(t)?;
            (t.published() && d > LONG_VALIDITY_DAYS)
                .then(|| format!("Valid for {}", days_text(Some(d))))
        },
    )
    .with_found_suffix(" long-lived certificates")
}

// ---------- CAs and PKI objects ----------

fn ca_certs(o: &LdapObject) -> Vec<(Vec<u8>, Option<Cert>)> {
    o.strs("cacertificate")
        .iter()
        .filter_map(|s| b64(s))
        .map(|der| {
            let c = x509::parse(&der);
            (der, c)
        })
        .collect()
}

fn ca_item(o: &LdapObject, reason: impl Into<String>) -> Affected {
    Affected {
        last_seen: None,
        name: obj_name(o),
        kind: "ca".into(),
        location: o.str("dnshostname").map(str::to_string),
        reason: Some(reason.into()),
        object: None,
    }
}

fn pki_001(m: &Model) -> CheckResult {
    let mut list = Vec::new();
    let mut out =
        check("AD-PKI-001").expected("Enterprise CAs run on a supported Windows Server version");
    let mut n = 0;
    for ca in cas(m) {
        n += 1;
        let host = ca.str("dnshostname").unwrap_or_default();
        let os = (0..m.nodes.len())
            .find(|&i| {
                m.nodes[i].kind == Kind::Computer
                    && m.nodes[i]
                        .attrs
                        .str("dnshostname")
                        .is_some_and(|h| h.eq_ignore_ascii_case(host))
            })
            .and_then(|i| m.nodes[i].attrs.str("operatingsystem"));
        let cert = ca_certs(ca).into_iter().find_map(|(_, c)| c);
        out = out.evidence(
            &obj_name(ca),
            format!(
                "{host}; {}; {}",
                os.unwrap_or("operating system not read"),
                cert.as_ref()
                    .and_then(|c| c.not_after)
                    .map(|t| format!("CA certificate valid until {}", &time::iso(t)[..10]))
                    .unwrap_or_else(|| "CA certificate not read".into())
            ),
        );
        if let Some(os) = os.filter(|o| ["2003", "2008", "2012"].iter().any(|v| o.contains(v))) {
            list.push(ca_item(ca, format!("Runs {os}, which is out of support")));
        }
    }
    if n == 0 {
        return out
            .found("No enterprise CA is published in this forest")
            .evidence("Read from", read_from(m))
            .done();
    }
    out.found(format!(
        "{}; {} on an unsupported OS",
        plural(n, "enterprise CA", "enterprise CAs"),
        list.len()
    ))
    .affected(list, "CAs")
    .evidence("Read from", read_from(m))
    .done()
}

fn pki_006(m: &Model) -> CheckResult {
    let mut list = Vec::new();
    for o in m.raw.pki.iter().filter(|o| {
        !has_class(o, "pKICertificateTemplate") && !has_class(o, "msPKI-Enterprise-Oid")
    }) {
        let r = rights(m, o);
        if r.write.is_empty() {
            continue;
        }
        let reason = r
            .write
            .iter()
            .map(|(p, k)| format!("{p}: {}", k.iter().copied().collect::<Vec<_>>().join(", ")))
            .collect::<Vec<_>>()
            .join("; ");
        list.push(Affected {
            last_seen: None,
            name: obj_name(o),
            kind: if has_class(o, "pKIEnrollmentService") {
                "ca"
            } else {
                "container"
            }
            .into(),
            location: Some(o.dn().to_string()),
            reason: Some(reason),
            object: None,
        });
    }
    check("AD-PKI-006")
        .expected("Only PKI admins can change the PKI containers, CA objects and the NTAuth store")
        .found(plural(list.len(), "PKI object is", "PKI objects are") + " writable by non-admins")
        .affected(list, "objects")
        .evidence("Read from", read_from(m))
        .done()
}

fn pki_016(m: &Model) -> CheckResult {
    let mut list = Vec::new();
    for ca in cas(m) {
        for c in ca_certs(ca).into_iter().filter_map(|(_, c)| c) {
            let mut weak = Vec::new();
            if c.key == "RSA" && c.key_bits.is_some_and(|b| b < 2048) {
                weak.push(format!("RSA {}-bit key", c.key_bits.unwrap_or_default()));
            }
            if c.weak_hash() {
                weak.push(format!("{} signature", c.signature));
            }
            if !weak.is_empty() {
                list.push(ca_item(ca, format!("{}: {}", c.subject, weak.join(", "))));
            }
        }
    }
    check("AD-PKI-016")
        .expected("CA certificates use RSA 2048-bit or larger (or ECC) keys and SHA-256 or stronger signatures")
        .found(plural(list.len(), "CA certificate is", "CA certificates are") + " weak")
        .affected(list, "CAs")
        .evidence("Read from", read_from(m))
        .done()
}

fn pki_017(m: &Model) -> CheckResult {
    let mut list = Vec::new();
    for ca in cas(m) {
        for c in ca_certs(ca).into_iter().filter_map(|(_, c)| c) {
            let Some(end) = c.not_after else { continue };
            let left = (end - m.now) / time::DAY;
            if left < 0 {
                list.push(ca_item(
                    ca,
                    format!("{} expired {} ago", c.subject, days_text(Some(-left))),
                ));
            } else if left <= CA_EXPIRY_DAYS {
                list.push(ca_item(
                    ca,
                    format!("{} expires in {}", c.subject, days_text(Some(left))),
                ));
            }
        }
    }
    check("AD-PKI-017")
        .expected(format!(
            "CA certificates are valid for more than {CA_EXPIRY_DAYS} days"
        ))
        .found(
            plural(
                list.len(),
                "CA certificate expires",
                "CA certificates expire",
            ) + " soon or has expired",
        )
        .affected(list, "CAs")
        .evidence(
            "Not checked",
            "CRL publication needs the CA or its CDP locations and is not read",
        )
        .evidence("Read from", read_from(m))
        .done()
}

fn pki_020(m: &Model) -> CheckResult {
    let enterprise: HashSet<Vec<u8>> = cas(m)
        .flat_map(|ca| ca_certs(ca).into_iter().map(|(d, _)| d))
        .collect();
    let roots: HashSet<Vec<u8>> = m
        .raw
        .pki
        .iter()
        .filter(|o| {
            o.dn()
                .to_lowercase()
                .contains("cn=certification authorities,")
        })
        .flat_map(|o| ca_certs(o).into_iter().map(|(d, _)| d))
        .collect();
    let Some(store) = m
        .raw
        .pki
        .iter()
        .find(|o| obj_name(o).eq_ignore_ascii_case("NTAuthCertificates"))
    else {
        return check("AD-PKI-020")
            .expected("The NTAuth store holds only this forest's issuing CAs")
            .found("No NTAuth store is published")
            .evidence("Read from", read_from(m))
            .done();
    };
    let certs = ca_certs(store);
    let list: Vec<Affected> = certs
        .iter()
        .filter(|(d, _)| !enterprise.contains(d))
        .map(|(_, c)| Affected {
            last_seen: None,
            name: c.as_ref().map(|c| c.subject.clone()).unwrap_or_else(|| "Unreadable certificate".into()),
            kind: "certificate".into(),
            location: Some("NTAuthCertificates".into()),
            reason: Some(
                if certs.iter().any(|(d, _)| roots.contains(d)) && c.as_ref().is_some_and(|c| c.self_signed) {
                    "A root CA, not an issuing CA of this forest, is trusted to issue logon certificates"
                } else {
                    "Not an enterprise CA of this forest, yet trusted to issue logon certificates"
                }
                .to_string(),
            ),
            object: None,
        })
        .collect();
    check("AD-PKI-020")
        .expected("The NTAuth store holds only this forest's issuing CAs")
        .found(plural(list.len(), "unexpected CA is", "unexpected CAs are") + " trusted for logon")
        .affected(list, "certificates")
        .evidence("Certificates in NTAuth", certs.len().to_string())
        .evidence("Read from", read_from(m))
        .done()
}

fn pki_021(m: &Model) -> CheckResult {
    let list: Vec<Affected> = cas(m)
        .filter_map(|ca| {
            let c = ca_certs(ca)
                .into_iter()
                .filter_map(|(_, c)| c)
                .find(|c| c.self_signed)?;
            Some(ca_item(
                ca,
                format!(
                    "{} is a self-signed root, online as an enterprise CA",
                    c.subject
                ),
            ))
        })
        .collect();
    check("AD-PKI-021")
        .expected("The root CA is offline; online enterprise CAs are subordinate issuing CAs")
        .found(plural(list.len(), "root CA is", "root CAs are") + " online")
        .affected(list, "CAs")
        .evidence("Read from", read_from(m))
        .done()
}

// ---------- ESC14: explicit certificate mappings ----------

fn pki_013(m: &Model) -> CheckResult {
    let mut list = Vec::new();
    for i in (0..m.nodes.len()).filter(|&i| matches!(m.nodes[i].kind, Kind::User | Kind::Computer))
    {
        let weak: Vec<&str> = m.nodes[i]
            .attrs
            .strs("altsecurityidentities")
            .into_iter()
            .filter(|v| {
                let v = v.to_uppercase();
                v.starts_with("X509:")
                    && !(v.contains("<SR>") || v.contains("<SKI>") || v.contains("<SHA1-PUKEY>"))
            })
            .collect();
        if !weak.is_empty() {
            let kinds: BTreeSet<&str> = weak
                .iter()
                .map(|v| {
                    let u = v.to_uppercase();
                    if u.contains("<RFC822>") {
                        "e-mail (RFC822)"
                    } else if u.contains("<I>") && u.contains("<S>") {
                        "issuer and subject"
                    } else if u.contains("<S>") {
                        "subject only"
                    } else {
                        "issuer only"
                    }
                })
                .collect();
            list.push(super::rules::item(
                m,
                i,
                format!(
                    "Weak explicit mapping by {}",
                    kinds.into_iter().collect::<Vec<_>>().join(", ")
                ),
            ));
        }
    }
    check("AD-PKI-013")
        .expected(
            "Explicit certificate mappings use issuer and serial number, SKI or public key hash",
        )
        .found(plural(list.len(), "account has", "accounts have") + " weak explicit mappings")
        .affected(list, "accounts")
        .evidence(
            "Read from",
            format!("altSecurityIdentities via LDAP on {}", m.raw.info.server),
        )
        .done()
}

trait FoundSuffix {
    fn with_found_suffix(self, s: &str) -> CheckResult;
}

impl FoundSuffix for CheckResult {
    fn with_found_suffix(mut self, s: &str) -> CheckResult {
        if let Some(f) = &mut self.found {
            f.push_str(s);
        }
        self
    }
}

pub static RULES: &[Rule] = &[
    Rule {
        id: "AD-PKI-001",
        needs: &["pki", "computers"],
        run: pki_001,
    },
    Rule {
        id: "AD-PKI-002",
        needs: &["pki", "groups"],
        run: pki_002,
    },
    Rule {
        id: "AD-PKI-003",
        needs: &["pki", "groups"],
        run: pki_003,
    },
    Rule {
        id: "AD-PKI-004",
        needs: &["pki", "groups"],
        run: pki_004,
    },
    Rule {
        id: "AD-PKI-005",
        needs: &["pki", "groups"],
        run: pki_005,
    },
    Rule {
        id: "AD-PKI-006",
        needs: &["pki", "groups"],
        run: pki_006,
    },
    Rule {
        id: "AD-PKI-010",
        needs: &["pki", "groups"],
        run: pki_010,
    },
    Rule {
        id: "AD-PKI-012",
        needs: &["pki", "groups"],
        run: pki_012,
    },
    Rule {
        id: "AD-PKI-013",
        needs: &["users", "computers"],
        run: pki_013,
    },
    Rule {
        id: "AD-PKI-014",
        needs: &["pki", "groups"],
        run: pki_014,
    },
    Rule {
        id: "AD-PKI-016",
        needs: &["pki"],
        run: pki_016,
    },
    Rule {
        id: "AD-PKI-017",
        needs: &["pki"],
        run: pki_017,
    },
    Rule {
        id: "AD-PKI-018",
        needs: &["pki"],
        run: pki_018,
    },
    Rule {
        id: "AD-PKI-019",
        needs: &["pki"],
        run: pki_019,
    },
    Rule {
        id: "AD-PKI-020",
        needs: &["pki"],
        run: pki_020,
    },
    Rule {
        id: "AD-PKI-021",
        needs: &["pki"],
        run: pki_021,
    },
];
