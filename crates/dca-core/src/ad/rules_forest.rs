//! Forest configuration (operations masters, partitions, schema, query
//! policy, display specifiers, extended rights) and permissions on objects
//! outside the main privilege paths: the configuration and schema partition
//! heads, OUs, tier 0 computers and the Password Settings Container.

use std::collections::BTreeSet;

use base64::Engine as _;

use super::model::{parent_dn, rdn_value, uac, well_known_name, Kind, Model};
use super::raw::LdapObject;
use super::rules::{check, item, plural, Rule};
use super::sd::{self, right, AceType, SecurityDescriptor};
use crate::results::{Affected, CheckResult};
use crate::time;

const LIST_CHILDREN: u32 = 0x0000_0004;
const READ_PROP: u32 = 0x0000_0010;
const LIST_OBJECT: u32 = 0x0000_0080;
const READ_CONTROL: u32 = 0x0002_0000;
const GENERIC_READ: u32 = 0x8000_0000;
const DELETED_OBJECT_DAYS: i64 = 180;

fn read_from(m: &Model, what: &str) -> String {
    format!(
        "{what} via LDAP on {} as {}",
        m.raw.info.server, m.raw.info.account
    )
}

pub(super) fn decode_sd(o: &LdapObject) -> Option<SecurityDescriptor> {
    let b = base64::engine::general_purpose::STANDARD
        .decode(o.str("ntsecuritydescriptor")?)
        .ok()?;
    sd::parse(&b)
}

pub(super) fn who(m: &Model, sid: &str) -> String {
    m.by_sid(sid)
        .map(|i| m.nodes[i].name.clone())
        .or_else(|| well_known_name(sid).map(str::to_string))
        .unwrap_or_else(|| sid.to_string())
}

pub(crate) fn obj_item(o: &LdapObject, kind: &str, reason: impl Into<String>) -> Affected {
    Affected {
        last_seen: None,
        name: rdn_value(o.dn()),
        kind: kind.into(),
        location: Some(o.dn().to_string()),
        reason: Some(reason.into()),
        object: None,
    }
}

/// Write-type rights an allow ACE grants, by name.
pub(super) fn write_rights(mask: u32, object_type: Option<&str>) -> Vec<&'static str> {
    let mut out = Vec::new();
    if mask & right::GENERIC_ALL != 0
        || (object_type.is_none() && mask & right::FULL_CONTROL == right::FULL_CONTROL)
    {
        return vec!["full control"];
    }
    if mask & right::WRITE_DACL != 0 {
        out.push("change permissions");
    }
    if mask & right::WRITE_OWNER != 0 {
        out.push("take ownership");
    }
    if mask & right::GENERIC_WRITE != 0 || (object_type.is_none() && mask & right::WRITE_PROP != 0)
    {
        out.push("write all properties");
    }
    if mask & right::CREATE_CHILD != 0 {
        out.push("create child objects");
    }
    out
}

/// Principals other than the built-in admin set that hold write-type rights
/// in `sd`, with the rights each holds.
pub(super) fn non_default_writers(
    m: &Model,
    sd: &SecurityDescriptor,
) -> Vec<(String, Vec<&'static str>)> {
    let mut out: Vec<(String, Vec<&'static str>)> = Vec::new();
    for ace in &sd.dacl {
        if ace.kind != AceType::Allow || ace.inherit_only() || m.is_default_admin(&ace.sid) {
            continue;
        }
        let rights = write_rights(ace.mask, ace.object_type.as_deref());
        if rights.is_empty() {
            continue;
        }
        let name = who(m, &ace.sid);
        match out.iter_mut().find(|(n, _)| *n == name) {
            Some((_, r)) => {
                for x in rights {
                    if !r.contains(&x) {
                        r.push(x);
                    }
                }
            }
            None => out.push((name, rights)),
        }
    }
    if let Some(owner) = &sd.owner {
        if !m.is_default_admin(owner) {
            out.push((who(m, owner), vec!["owner"]));
        }
    }
    out
}

pub(super) fn describe(writers: &[(String, Vec<&'static str>)]) -> String {
    writers
        .iter()
        .map(|(n, r)| format!("{n} ({})", r.join(", ")))
        .collect::<Vec<_>>()
        .join("; ")
}

pub(super) fn crossref_container<'a>(m: &Model<'a>) -> Option<&'a LdapObject> {
    m.raw.partitions.iter().find(|p| {
        p.values("objectclass")
            .iter()
            .any(|v| v == "crossRefContainer")
    })
}

pub(super) fn crossrefs<'a>(m: &Model<'a>) -> impl Iterator<Item = &'a LdapObject> + 'a {
    m.raw
        .partitions
        .iter()
        .filter(|p| p.values("objectclass").iter().any(|v| v == "crossRef"))
}

fn schema_head<'a>(m: &Model<'a>) -> Option<&'a LdapObject> {
    m.raw
        .schema
        .iter()
        .find(|s| s.values("objectclass").iter().any(|v| v == "dMD"))
}

/// When the forest was created: the schema head's creation time.
fn forest_created(m: &Model) -> Option<i64> {
    schema_head(m)
        .and_then(|s| s.str("whencreated"))
        .and_then(time::parse_iso)
}

pub(super) fn dcs<'a>(m: &'a Model<'a>) -> impl Iterator<Item = usize> + 'a {
    (0..m.nodes.len()).filter(move |&i| {
        let n = &m.nodes[i];
        n.kind == Kind::Computer && (n.is_dc() || n.flag(uac::PARTIAL_SECRETS_ACCOUNT))
    })
}

// ---------- Forest fundamentals ----------

fn fnd_003(m: &Model) -> CheckResult {
    let old = ["2000", "2003", "2008", "2012"];
    let list: Vec<Affected> = dcs(m)
        .filter_map(|i| {
            let os = m.nodes[i].attrs.str("operatingsystem")?;
            old.iter().any(|v| os.contains(v)).then(|| {
                item(
                    m,
                    i,
                    format!("Runs {os}, which no longer gets security updates"),
                )
            })
        })
        .collect();
    check("AD-FND-003")
        .expected("Every domain controller runs a supported Windows Server version (2016 or later)")
        .found(
            plural(
                list.len(),
                "domain controller runs",
                "domain controllers run",
            ) + " an unsupported version",
        )
        .affected(list, "domain controllers")
        .evidence(
            "Read from",
            read_from(m, "operatingSystem of domain controllers"),
        )
        .done()
}

fn schema_version_name(v: i64) -> &'static str {
    match v {
        13 => "Windows 2000 Server",
        30 => "Windows Server 2003",
        31 => "Windows Server 2003 R2",
        44 => "Windows Server 2008",
        47 => "Windows Server 2008 R2",
        56 => "Windows Server 2012",
        69 => "Windows Server 2012 R2",
        87 => "Windows Server 2016",
        88 => "Windows Server 2019 or 2022",
        91 => "Windows Server 2025",
        _ => "an unrecognized version",
    }
}

fn fnd_004(m: &Model) -> CheckResult {
    let version = schema_head(m).and_then(|s| s.int("objectversion"));
    let names: Vec<&str> = m
        .raw
        .schema
        .iter()
        .filter_map(|s| s.str("ldapdisplayname"))
        .collect();
    let count = |p: &str| {
        names
            .iter()
            .filter(|n| n.to_ascii_lowercase().starts_with(p))
            .count()
    };
    let products: [(&str, &str); 6] = [
        ("ms-exch", "Exchange"),
        ("ms-mcs-admpwd", "Legacy LAPS"),
        ("mslaps-", "Windows LAPS"),
        ("ms-sms", "Configuration Manager"),
        ("msrtcsip-", "Skype for Business / Lync"),
        ("msds-cloudextension", "Entra Connect cloud extensions"),
    ];
    let mut found: Vec<String> = products
        .iter()
        .filter_map(|(p, name)| {
            let n = count(p);
            (n > 0).then(|| {
                format!(
                    "{name}: {}",
                    plural(n, "attribute or class", "attributes and classes")
                )
            })
        })
        .collect();
    // Attributes and classes outside the base schema (systemFlags 0x10)
    // and without a Microsoft prefix: third-party or in-house extensions.
    let custom = m
        .raw
        .schema
        .iter()
        .filter(|s| s.int("systemflags").unwrap_or(0) & 0x10 == 0)
        .filter_map(|s| s.str("ldapdisplayname"))
        .filter(|n| !n.to_ascii_lowercase().starts_with("ms"))
        .count();
    if custom > 0 {
        found.push(format!("Other extensions: {custom}"));
    }
    check("AD-FND-004")
        .expected("An inventory of the schema version and the products that extended it")
        .found(match version {
            Some(v) => format!("Schema version {v} ({})", schema_version_name(v)),
            None => "The schema version was not returned".into(),
        })
        .raw(found.join("\n"))
        .evidence("Read from", read_from(m, "the schema partition"))
        .done()
}

/// Role name, the object that holds the role, and its fsmoRoleOwner.
fn role_holders(m: &Model) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    let owner = |o: &LdapObject| o.str("fsmoroleowner").unwrap_or_default().to_string();
    if let Some(d) = m.raw.domain.first() {
        out.push(("PDC emulator", owner(d)));
    }
    for o in m.raw.objects("roles") {
        let classes = o.strs("objectclass");
        if classes.iter().any(|c| c.eq_ignore_ascii_case("rIDManager")) {
            out.push(("RID master", owner(o)));
        } else if parent_dn(o.dn()).is_some_and(|p| {
            m.raw
                .domain
                .first()
                .is_some_and(|d| d.dn().eq_ignore_ascii_case(p))
        }) {
            out.push(("Infrastructure master", owner(o)));
        }
    }
    if let Some(s) = schema_head(m) {
        out.push(("Schema master", owner(s)));
    }
    if let Some(p) = crossref_container(m) {
        out.push(("Domain naming master", owner(p)));
    }
    out
}

/// The server name in an NTDS Settings DN: CN=NTDS Settings,CN=DC01,CN=Servers,...
fn server_of(owner: &str) -> String {
    parent_dn(owner).map(rdn_value).unwrap_or_default()
}

fn fnd_005(m: &Model) -> CheckResult {
    let roles = role_holders(m);
    let lines: Vec<String> = roles
        .iter()
        .map(|(r, o)| {
            if o.is_empty() {
                format!("{r}: not returned")
            } else {
                format!("{r}: {}", server_of(o))
            }
        })
        .collect();
    let holders: BTreeSet<String> = roles
        .iter()
        .filter(|(_, o)| !o.is_empty())
        .map(|(_, o)| server_of(o))
        .collect();
    let missing: Vec<&str> = roles
        .iter()
        .filter(|(_, o)| o.is_empty())
        .map(|(r, _)| *r)
        .collect();
    check("AD-FND-005")
        .failed(!missing.is_empty())
        .expected("Every operations master role has a holder")
        .found(if missing.is_empty() {
            format!(
                "{} held by {}",
                plural(roles.len(), "role", "roles"),
                holders.into_iter().collect::<Vec<_>>().join(", ")
            )
        } else {
            format!("No holder returned for {}", missing.join(", "))
        })
        .raw(lines.join("\n"))
        .evidence(
            "Read from",
            read_from(m, "fsmoRoleOwner on the role objects"),
        )
        .done()
}

fn fnd_006(m: &Model) -> CheckResult {
    let dsas: BTreeSet<String> = m
        .raw
        .sites
        .iter()
        .filter(|o| {
            o.values("objectclass").iter().any(|v| {
                v.as_str()
                    .is_some_and(|c| c.eq_ignore_ascii_case("nTDSDSA"))
            })
        })
        .map(|o| o.dn().to_ascii_lowercase())
        .collect();
    let list: Vec<Affected> = role_holders(m)
        .into_iter()
        .filter(|(_, o)| !o.is_empty())
        .filter(|(_, o)| {
            o.contains("\\0ADEL:") || o.contains("DEL:") || !dsas.contains(&o.to_ascii_lowercase())
        })
        .map(|(role, o)| Affected {
            last_seen: None,
            name: role.to_string(),
            kind: "role".into(),
            location: Some(o.clone()),
            reason: Some(format!(
                "Held by {}, which is not a current domain controller in the forest's sites",
                server_of(&o)
            )),
            object: None,
        })
        .collect();
    check("AD-FND-006")
        .expected("Every operations master role is held by a domain controller that still exists")
        .found(plural(list.len(), "role is", "roles are") + " held by a missing domain controller")
        .affected(list, "roles")
        .evidence(
            "Read from",
            read_from(m, "fsmoRoleOwner and nTDSDSA objects"),
        )
        .done()
}

fn fnd_009(m: &Model) -> CheckResult {
    let ds = m.raw.dirservice.first();
    let tombstone = ds.and_then(|d| d.int("tombstonelifetime")).unwrap_or(60);
    let set = ds.and_then(|d| d.int("msds-deletedobjectlifetime"));
    let days = set.unwrap_or(tombstone);
    check("AD-FND-009")
        .failed(days < DELETED_OBJECT_DAYS)
        .expected(format!(
            "Deleted objects can be restored for at least {DELETED_OBJECT_DAYS} days"
        ))
        .found(match set {
            Some(d) => format!("msDS-DeletedObjectLifetime is {d} days"),
            None => format!("Not set, so the tombstone lifetime applies: {tombstone} days"),
        })
        .raw(format!(
            "msDS-DeletedObjectLifetime: {}\ntombstoneLifetime: {tombstone}",
            set.map(|d| d.to_string())
                .unwrap_or_else(|| "<not set>".into())
        ))
        .evidence(
            "Read from",
            "CN=Directory Service,CN=Windows NT,CN=Services",
        )
        .done()
}

fn fnd_010(m: &Model) -> CheckResult {
    let features: Vec<String> = crossref_container(m)
        .map(|c| c.strs("msds-enabledfeature"))
        .unwrap_or_default()
        .iter()
        .map(|f| rdn_value(f))
        .collect();
    let pam = features.iter().any(|f| {
        f.to_ascii_lowercase()
            .starts_with("privileged access management")
    });
    check("AD-FND-010")
        .expected("An inventory of the forest's optional features")
        .found(format!(
            "{}; Privileged Access Management feature {}",
            if features.is_empty() {
                "No optional features enabled".to_string()
            } else {
                features.join(", ")
            },
            if pam { "enabled" } else { "not enabled" }
        ))
        .raw(features.join("\n"))
        .evidence("Read from", "msDS-EnabledFeature on CN=Partitions")
        .done()
}

fn fnd_013(m: &Model) -> CheckResult {
    let dns = m.dns.to_ascii_lowercase();
    let mut list = Vec::new();
    if !dns.contains('.') {
        list.push(Affected {
            last_seen: None,
            name: m.dns.clone(),
            kind: "domain".into(),
            location: None,
            reason: Some(
                "A single-label DNS name: unsupported by many products and by Entra Connect".into(),
            ),
            object: None,
        });
    }
    for i in dcs(m) {
        if let Some(host) = m.nodes[i].attrs.str("dnshostname") {
            let h = host.to_ascii_lowercase();
            if !h.ends_with(&format!(".{dns}")) {
                list.push(item(
                    m,
                    i,
                    format!(
                        "Host name {host} is outside {}: a disjoint namespace",
                        m.dns
                    ),
                ));
            }
        }
    }
    check("AD-FND-013")
        .expected("The domain has a multi-label DNS name and its DCs use it as their DNS suffix")
        .found(plural(list.len(), "naming problem", "naming problems"))
        .affected(list, "objects")
        .evidence(
            "Read from",
            read_from(m, "the domain name and DC host names"),
        )
        .done()
}

fn fnd_014(m: &Model) -> CheckResult {
    let mut known: BTreeSet<String> = crossref_container(m)
        .map(|c| c.strs("upnsuffixes"))
        .unwrap_or_default()
        .iter()
        .map(|s| s.to_ascii_lowercase())
        .collect();
    let alternates = known.clone();
    known.insert(m.dns.to_ascii_lowercase());
    for c in crossrefs(m) {
        if let Some(d) = c.str("dnsroot") {
            known.insert(d.to_ascii_lowercase());
        }
    }
    let list: Vec<Affected> = (0..m.nodes.len())
        .filter(|&i| m.nodes[i].kind == Kind::User && m.nodes[i].enabled())
        .filter_map(|i| {
            let upn = m.nodes[i].attrs.str("userprincipalname")?;
            let suffix = upn.rsplit_once('@')?.1.to_ascii_lowercase();
            (!known.contains(&suffix)).then(|| {
                item(
                    m,
                    i,
                    format!("UPN suffix {suffix} is not a domain or registered UPN suffix of the forest"),
                )
            })
        })
        .collect();
    check("AD-FND-014")
        .expected("Users sign in with UPN suffixes the forest knows")
        .found(format!(
            "{}; {} with an unregistered suffix",
            plural(
                alternates.len(),
                "alternate UPN suffix",
                "alternate UPN suffixes"
            ),
            plural(list.len(), "user", "users")
        ))
        .affected(list, "users")
        .raw(alternates.into_iter().collect::<Vec<_>>().join("\n"))
        .evidence(
            "Read from",
            read_from(m, "uPNSuffixes on CN=Partitions and userPrincipalName"),
        )
        .done()
}

fn fnd_015(m: &Model) -> CheckResult {
    let count = |k: Kind| m.nodes.iter().filter(|n| n.kind == k).count();
    let sites = m
        .raw
        .sites
        .iter()
        .filter(|o| o.class().is_some_and(|c| c.eq_ignore_ascii_case("site")))
        .count();
    let domains = crossrefs(m).filter(|c| c.has("netbiosname")).count();
    let lines = [
        format!("Domains in the forest: {domains}"),
        format!("Sites: {sites}"),
        format!("Domain controllers: {}", dcs(m).count()),
        format!("Users: {}", count(Kind::User)),
        format!("Computers: {}", count(Kind::Computer)),
        format!("Groups: {}", count(Kind::Group)),
        format!(
            "OUs and containers: {}",
            count(Kind::Ou) + count(Kind::Container)
        ),
    ];
    check("AD-FND-015")
        .expected("Sizing context for the rest of the assessment")
        .found(format!(
            "{} users, {} computers, {} groups, {} DCs",
            count(Kind::User),
            count(Kind::Computer),
            count(Kind::Group),
            dcs(m).count()
        ))
        .raw(lines.join("\n"))
        .evidence("Read from", read_from(m, "object counts"))
        .done()
}

fn fnd_016(m: &Model) -> CheckResult {
    let list: Vec<Affected> = crossrefs(m)
        .filter(|c| {
            c.values("enabled")
                .first()
                .is_some_and(|v| v.as_bool() == Some(false) || v.as_str().is_some_and(|s| s.eq_ignore_ascii_case("false")))
        })
        .map(|c| {
            obj_item(
                c,
                "crossRef",
                format!(
                    "Disabled cross-reference for {}: a partition that was pre-created or not fully removed",
                    c.str("dnsroot").or(c.str("ncname")).unwrap_or_default()
                ),
            )
        })
        .collect();
    check("AD-FND-016")
        .expected("Every cross-reference in CN=Partitions is enabled and in use")
        .found(plural(
            list.len(),
            "stale cross-reference",
            "stale cross-references",
        ))
        .affected(list, "cross-references")
        .evidence(
            "Read from",
            read_from(m, "crossRef objects in CN=Partitions"),
        )
        .done()
}

fn fnd_017(m: &Model) -> CheckResult {
    const NTDS_NC: i64 = 0x1;
    const NTDS_DOMAIN: i64 = 0x2;
    let mut inventory = Vec::new();
    let mut list = Vec::new();
    for c in crossrefs(m) {
        let flags = c.int("systemflags").unwrap_or(0);
        let nc = c.str("ncname").unwrap_or_default();
        let lower = nc.to_ascii_lowercase();
        if flags & NTDS_NC == 0
            || flags & NTDS_DOMAIN != 0
            || lower.starts_with("cn=configuration,")
            || lower.starts_with("cn=schema,")
        {
            continue;
        }
        let replicas = c.strs("msds-nc-replica-locations");
        inventory.push(format!(
            "{nc}: {}",
            plural(replicas.len(), "replica", "replicas")
        ));
        if replicas.is_empty() {
            list.push(obj_item(
                c,
                "crossRef",
                format!("Application partition {nc} has no replica: no DC holds it any more"),
            ));
        }
    }
    check("AD-FND-017")
        .expected("Every application partition is held by at least one domain controller")
        .found(format!(
            "{}; {} orphaned",
            plural(
                inventory.len(),
                "application partition",
                "application partitions"
            ),
            list.len()
        ))
        .affected(list, "partitions")
        .raw(inventory.join("\n"))
        .evidence(
            "Read from",
            read_from(m, "msDS-NC-Replica-Locations on crossRef objects"),
        )
        .done()
}

fn fnd_018(m: &Model) -> CheckResult {
    const DEFAULTS: [(&str, i64); 6] = [
        ("MaxPageSize", 1000),
        ("MaxQueryDuration", 120),
        ("MaxValRange", 1500),
        ("MaxResultSetSize", 262_144),
        ("MaxConnections", 5000),
        ("MaxConnIdleTime", 900),
    ];
    let policies = m.raw.objects("querypolicy");
    let mut changed = Vec::new();
    let mut lines = Vec::new();
    for p in policies {
        for v in p.strs("ldapadminlimits") {
            lines.push(format!("{}: {v}", rdn_value(p.dn())));
            let Some((k, val)) = v.split_once('=') else {
                continue;
            };
            let Ok(val) = val.trim().parse::<i64>() else {
                continue;
            };
            if let Some((_, d)) = DEFAULTS
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(k.trim()))
            {
                if val != *d {
                    changed.push(obj_item(
                        p,
                        "queryPolicy",
                        format!("{} is {val} (default {d})", k.trim()),
                    ));
                }
            }
        }
    }
    check("AD-FND-018")
        .expected("LDAP query limits are left at their defaults")
        .found(if policies.is_empty() {
            "No query policy object: defaults apply".to_string()
        } else {
            plural(changed.len(), "limit changed", "limits changed")
        })
        .affected(changed, "settings")
        .raw(lines.join("\n"))
        .evidence(
            "Read from",
            read_from(m, "lDAPAdminLimits in CN=Query-Policies"),
        )
        .done()
}

// ---------- Schema ----------

fn sch_003(m: &Model) -> CheckResult {
    const CONFIDENTIAL: i64 = 0x80;
    const RODC_FILTERED: i64 = 0x200;
    let created = forest_created(m);
    let mut inventory = Vec::new();
    let mut list = Vec::new();
    for a in &m.raw.schema {
        let flags = a.int("searchflags").unwrap_or(0);
        if flags & (CONFIDENTIAL | RODC_FILTERED) == 0 {
            continue;
        }
        let name = a.str("ldapdisplayname").unwrap_or_default();
        let mut what = Vec::new();
        if flags & CONFIDENTIAL != 0 {
            what.push("confidential");
        }
        if flags & RODC_FILTERED != 0 {
            what.push("RODC filtered");
        }
        inventory.push(format!("{name}: {}", what.join(", ")));
        let changed = a.str("whenchanged").and_then(time::parse_iso);
        if let (Some(c), Some(f)) = (changed, created) {
            if c - f > time::DAY {
                list.push(obj_item(
                    a,
                    "attributeSchema",
                    format!(
                        "{name} is {} and was changed after the forest was created",
                        what.join(" and ")
                    ),
                ));
            }
        }
    }
    check("AD-SCH-003")
        .expected("Confidential and RODC-filtered attributes are reviewed after every change")
        .found(format!(
            "{}; {} changed since the forest was created",
            plural(inventory.len(), "flagged attribute", "flagged attributes"),
            list.len()
        ))
        .affected(list, "attributes")
        .raw(inventory.join("\n"))
        .evidence(
            "Read from",
            read_from(m, "searchFlags and whenChanged of attributeSchema"),
        )
        .done()
}

fn sch_004(m: &Model) -> CheckResult {
    let suspicious = |v: &str| {
        let l = v.to_ascii_lowercase();
        l.contains('\\')
            || l.contains('/')
            || [
                ".exe", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".dll", "http:", "https:",
            ]
            .iter()
            .any(|x| l.contains(x))
    };
    let list: Vec<Affected> = m
        .raw
        .objects("dispspec")
        .iter()
        .filter_map(|o| {
            let hits: Vec<&str> = o
                .strs("admincontextmenu")
                .into_iter()
                .chain(o.strs("shellcontextmenu"))
                .filter(|v| suspicious(v))
                .collect();
            (!hits.is_empty()).then(|| {
                obj_item(
                    o,
                    "displaySpecifier",
                    format!("Context menu runs a program: {}", hits.join("; ")),
                )
            })
        })
        .collect();
    check("AD-SCH-004")
        .expected("No display specifier adds a context menu entry that runs a program")
        .found(
            plural(list.len(), "display specifier", "display specifiers")
                + " with a program in a context menu",
        )
        .affected(list, "display specifiers")
        .evidence(
            "Read from",
            read_from(
                m,
                "adminContextMenu and shellContextMenu in CN=DisplaySpecifiers",
            ),
        )
        .done()
}

fn sch_005(m: &Model) -> CheckResult {
    let created = forest_created(m);
    let rights = m.raw.objects("extrights");
    let list: Vec<Affected> = rights
        .iter()
        .filter(|o| {
            let c = o.str("whencreated").and_then(time::parse_iso);
            matches!((c, created), (Some(c), Some(f)) if c - f > time::DAY)
        })
        .map(|o| {
            obj_item(
                o,
                "controlAccessRight",
                format!(
                    "Added on {}, after the forest was created",
                    o.str("whencreated").unwrap_or_default()
                ),
            )
        })
        .collect();
    check("AD-SCH-005")
        .expected("Extended rights added after the forest was created come from known products")
        .found(format!(
            "{}; {} added later",
            plural(rights.len(), "extended right", "extended rights"),
            list.len()
        ))
        .affected(list, "extended rights")
        .evidence(
            "Read from",
            read_from(m, "controlAccessRight objects in CN=Extended-Rights"),
        )
        .done()
}

// ---------- Trusts ----------

fn tru_011(m: &Model) -> CheckResult {
    const WITHIN_FOREST: i64 = 0x20;
    let dns = m.dns.to_ascii_lowercase();
    let lines: Vec<String> = m
        .raw
        .trusts
        .iter()
        .filter(|t| t.int("trustattributes").unwrap_or(0) & WITHIN_FOREST != 0)
        .filter_map(|t| {
            let p = t.str("trustpartner")?.to_ascii_lowercase();
            let parent_child = p.ends_with(&format!(".{dns}")) || dns.ends_with(&format!(".{p}"));
            (!parent_child).then(|| format!("Shortcut trust to {p}"))
        })
        .collect();
    check("AD-TRU-011")
        .expected("An inventory of shortcut trusts inside the forest")
        .found(plural(lines.len(), "shortcut trust", "shortcut trusts"))
        .raw(lines.join("\n"))
        .evidence("Read from", read_from(m, "trustedDomain objects"))
        .done()
}

// ---------- Permissions ----------

fn acl_007(m: &Model) -> CheckResult {
    let heads = m.raw.objects("ncheads");
    let list: Vec<Affected> = heads
        .iter()
        .filter_map(|o| {
            let sd = decode_sd(o)?;
            let w = non_default_writers(m, &sd);
            (!w.is_empty()).then(|| {
                obj_item(
                    o,
                    "partition",
                    format!("Non-default rights: {}", describe(&w)),
                )
            })
        })
        .collect();
    check("AD-ACL-007")
        .expected("Only the forest's built-in admin groups can change the configuration and schema partitions")
        .found(format!(
            "{} of {} have extra rights",
            list.len(),
            plural(heads.len(), "partition head", "partition heads")
        ))
        .affected(list, "partitions")
        .evidence("Read from", read_from(m, "nTSecurityDescriptor of CN=Configuration and CN=Schema"))
        .done()
}

fn ou_sds<'a>(m: &'a Model) -> impl Iterator<Item = (usize, &'a SecurityDescriptor)> + 'a {
    m.sds
        .iter()
        .filter(|(&i, _)| m.nodes[i].kind == Kind::Ou)
        .map(|(&i, sd)| (i, sd))
}

fn acl_017(m: &Model) -> CheckResult {
    let mut inventory = Vec::new();
    let mut list = Vec::new();
    for (i, sd) in ou_sds(m) {
        if !sd.protected {
            continue;
        }
        inventory.push(m.nodes[i].dn.clone());
        if m.nodes[i].tier0 {
            list.push(item(
                m,
                i,
                "A Tier 0 OU that does not inherit permissions from the domain: changes made at the top do not reach it",
            ));
        }
    }
    check("AD-ACL-017")
        .expected(
            "Inheritance is blocked only on OUs where it is documented, and not on Tier 0 OUs",
        )
        .found(format!(
            "{} with inheritance disabled; {} of them Tier 0",
            plural(inventory.len(), "OU", "OUs"),
            list.len()
        ))
        .affected(list, "OUs")
        .raw(inventory.join("\n"))
        .evidence("Read from", read_from(m, "the DACL protection flag of OUs"))
        .done()
}

fn acl_018(m: &Model) -> CheckResult {
    let hide = LIST_CHILDREN | READ_PROP | LIST_OBJECT | READ_CONTROL | GENERIC_READ;
    let mut inventory = Vec::new();
    let mut list = Vec::new();
    let mut targets: Vec<(&usize, &SecurityDescriptor)> = m.sds.iter().collect();
    targets.sort_by_key(|(i, _)| **i);
    for (&i, sd) in targets {
        let denies: Vec<&sd::Ace> = sd
            .dacl
            .iter()
            .filter(|a| a.kind == AceType::Deny && a.flags & sd::ACE_INHERITED == 0)
            .collect();
        if denies.is_empty() {
            continue;
        }
        for a in &denies {
            inventory.push(format!(
                "{}: deny {:#x} to {}",
                m.nodes[i].name,
                a.mask,
                who(m, &a.sid)
            ));
        }
        let hiding: Vec<String> = denies
            .iter()
            .filter(|a| a.mask & hide != 0 && a.object_type.is_none())
            .map(|a| who(m, &a.sid))
            .collect();
        if !hiding.is_empty() {
            list.push(item(
                m,
                i,
                format!(
                    "Read or list access denied to {}: hides the object from audits",
                    hiding.join(", ")
                ),
            ));
        }
    }
    check("AD-ACL-018")
        .expected("No explicit deny entries hide objects from reading or listing")
        .found(format!(
            "{}; {} hide objects",
            plural(
                inventory.len(),
                "explicit deny entry",
                "explicit deny entries"
            ),
            list.len()
        ))
        .affected(list, "objects")
        .raw(inventory.join("\n"))
        .evidence("Read from", read_from(m, "explicit deny ACEs"))
        .done()
}

fn acl_019(m: &Model) -> CheckResult {
    let exchange = |name: &str| {
        let l = name.to_ascii_lowercase();
        l == "exchange windows permissions" || l == "exchange trusted subsystem"
    };
    let list: Vec<Affected> = m
        .edges
        .iter()
        .filter(|e| Some(e.to) == m.domain)
        .filter(|e| matches!(e.kind, "WriteDacl" | "GenericAll" | "WriteOwner"))
        .filter(|e| exchange(&m.nodes[e.from].name))
        .map(|e| {
            item(
                m,
                e.from,
                format!(
                    "Has {} on the domain: any Exchange server or admin can grant itself DCSync",
                    e.kind
                ),
            )
        })
        .collect();
    check("AD-ACL-019")
        .expected("Exchange groups do not hold WriteDACL on the domain (split permissions or the 2019 fix applied)")
        .found(plural(list.len(), "Exchange group has", "Exchange groups have") + " WriteDACL on the domain")
        .affected(list, "groups")
        .evidence("Read from", read_from(m, "the domain head's DACL"))
        .done()
}

fn acl_022(m: &Model) -> CheckResult {
    let mut lines: BTreeSet<String> = BTreeSet::new();
    for e in &m.edges {
        if m.nodes[e.to].kind != Kind::Ou || e.kind == "Contains" || e.kind == "GPLink" {
            continue;
        }
        lines.insert(format!(
            "{}\t{}\t{}",
            m.nodes[e.to].name, m.nodes[e.from].name, e.kind
        ));
    }
    check("AD-ACL-022")
        .expected("An inventory of who has been delegated control of each OU")
        .found(plural(lines.len(), "delegation", "delegations"))
        .raw(lines.into_iter().collect::<Vec<_>>().join("\n"))
        .evidence("Read from", read_from(m, "OU DACLs"))
        .done()
}

fn acl_024(m: &Model) -> CheckResult {
    let list: Vec<Affected> = m
        .edges
        .iter()
        .filter(|e| m.nodes[e.to].kind == Kind::Computer && m.nodes[e.to].tier0)
        .filter(|e| e.kind != "Contains" && e.from != e.to)
        .filter(|e| !m.nodes[e.from].tier0)
        .map(|e| {
            item(
                m,
                e.from,
                format!(
                    "Has {} on {}, a Tier 0 computer",
                    e.kind, m.nodes[e.to].name
                ),
            )
        })
        .collect();
    check("AD-ACL-024")
        .expected("Only Tier 0 principals control Tier 0 computer objects")
        .found(plural(list.len(), "right", "rights") + " held by non-Tier 0 principals")
        .affected(list, "rights")
        .evidence(
            "Read from",
            read_from(m, "DACLs of domain controller computer objects"),
        )
        .done()
}

fn acl_026(m: &Model) -> CheckResult {
    let container = m.raw.acls.iter().find(|o| {
        o.dn()
            .to_ascii_lowercase()
            .starts_with("cn=password settings container,")
    });
    let out = check("AD-ACL-026")
        .expected("Only domain admins can create or change fine-grained password policies");
    let Some(o) = container else {
        return out
            .not_assessed("The Password Settings Container's permissions were not returned.")
            .done();
    };
    let list = match decode_sd(o) {
        Some(sd) => {
            let w = non_default_writers(m, &sd);
            if w.is_empty() {
                Vec::new()
            } else {
                vec![obj_item(
                    o,
                    "container",
                    format!("Non-default rights: {}", describe(&w)),
                )]
            }
        }
        None => Vec::new(),
    };
    out.found(if list.is_empty() {
        "Default permissions".to_string()
    } else {
        "Extra principals can manage password policies".to_string()
    })
    .affected(list, "containers")
    .evidence(
        "Read from",
        read_from(m, "nTSecurityDescriptor of CN=Password Settings Container"),
    )
    .done()
}

fn acl_014(m: &Model) -> CheckResult {
    let broad = |sid: &str| {
        matches!(sid, "S-1-1-0" | "S-1-5-11" | "S-1-5-7")
            || sid
                .strip_prefix(&m.domain_sid)
                .is_some_and(|r| r == "-513" || r == "-515")
    };
    let mut inventory = Vec::new();
    let mut list = Vec::new();
    for o in m
        .raw
        .msas
        .iter()
        .filter(|o| o.has("msds-groupmsamembership"))
    {
        let Some(sd) = o
            .str("msds-groupmsamembership")
            .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())
            .and_then(|b| sd::parse(&b))
        else {
            continue;
        };
        let readers: Vec<&sd::Ace> = sd
            .dacl
            .iter()
            .filter(|a| a.kind == AceType::Allow)
            .collect();
        let name = o.str("samaccountname").unwrap_or_default();
        inventory.push(format!(
            "{name}: {}",
            readers
                .iter()
                .map(|a| who(m, &a.sid))
                .collect::<Vec<_>>()
                .join(", ")
        ));
        let wide: Vec<String> = readers
            .iter()
            .filter(|a| broad(&a.sid))
            .map(|a| who(m, &a.sid))
            .collect();
        if !wide.is_empty() {
            list.push(obj_item(
                o,
                "msa",
                format!("Password readable by {}", wide.join(", ")),
            ));
        }
    }
    check("AD-ACL-014")
        .expected("gMSA passwords are readable only by the computers that run the service")
        .found(format!(
            "{}; {} readable by broad groups",
            plural(inventory.len(), "gMSA", "gMSAs"),
            list.len()
        ))
        .affected(list, "gMSAs")
        .raw(inventory.join("\n"))
        .evidence("Read from", read_from(m, "msDS-GroupMSAMembership"))
        .done()
}

const LDAP: &[&str] = &["domain", "users", "computers", "groups"];
const ACLS: &[&str] = &[
    "domain",
    "users",
    "computers",
    "groups",
    "containers",
    "acls",
];

pub static RULES: &[Rule] = &[
    Rule {
        id: "AD-FND-003",
        needs: &["computers"],
        run: fnd_003,
    },
    Rule {
        id: "AD-FND-004",
        needs: &["schema"],
        run: fnd_004,
    },
    Rule {
        id: "AD-FND-005",
        needs: &["domain", "schema", "partitions", "roles"],
        run: fnd_005,
    },
    Rule {
        id: "AD-FND-006",
        needs: &["domain", "schema", "partitions", "roles", "sites"],
        run: fnd_006,
    },
    Rule {
        id: "AD-FND-009",
        needs: &["dirservice"],
        run: fnd_009,
    },
    Rule {
        id: "AD-FND-010",
        needs: &["partitions"],
        run: fnd_010,
    },
    Rule {
        id: "AD-FND-013",
        needs: &["domain", "computers"],
        run: fnd_013,
    },
    Rule {
        id: "AD-FND-014",
        needs: &["partitions", "users"],
        run: fnd_014,
    },
    Rule {
        id: "AD-FND-015",
        needs: LDAP,
        run: fnd_015,
    },
    Rule {
        id: "AD-FND-016",
        needs: &["partitions"],
        run: fnd_016,
    },
    Rule {
        id: "AD-FND-017",
        needs: &["partitions"],
        run: fnd_017,
    },
    Rule {
        id: "AD-FND-018",
        needs: &["querypolicy"],
        run: fnd_018,
    },
    Rule {
        id: "AD-SCH-003",
        needs: &["schema"],
        run: sch_003,
    },
    Rule {
        id: "AD-SCH-004",
        needs: &["dispspec"],
        run: sch_004,
    },
    Rule {
        id: "AD-SCH-005",
        needs: &["schema", "extrights"],
        run: sch_005,
    },
    Rule {
        id: "AD-TRU-011",
        needs: &["trusts"],
        run: tru_011,
    },
    Rule {
        id: "AD-ACL-007",
        needs: &["ncheads"],
        run: acl_007,
    },
    Rule {
        id: "AD-ACL-014",
        needs: &["msas"],
        run: acl_014,
    },
    Rule {
        id: "AD-ACL-017",
        needs: ACLS,
        run: acl_017,
    },
    Rule {
        id: "AD-ACL-018",
        needs: ACLS,
        run: acl_018,
    },
    Rule {
        id: "AD-ACL-019",
        needs: ACLS,
        run: acl_019,
    },
    Rule {
        id: "AD-ACL-022",
        needs: ACLS,
        run: acl_022,
    },
    Rule {
        id: "AD-ACL-024",
        needs: ACLS,
        run: acl_024,
    },
    Rule {
        id: "AD-ACL-026",
        needs: &["acls"],
        run: acl_026,
    },
];
