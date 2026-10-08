//! DNS, replication and site topology: what each DC's DNS server and
//! replication engine report, and how sites, subnets and site links are
//! laid out in the configuration partition.

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine;

use super::dc::{DcData, DnsServer};
use super::model::{parent_dn, rdn_value, well_known_name, Model};
use super::raw::{LdapObject, SysvolPolicy};
use super::rules::{check, item, plural, Rule};
use super::rules_dc::{age_days, dc_item, dc_nodes, each_dc, registry_ready, short, Eval};
use super::sd::{self, right, AceType};
use crate::results::{Affected, CheckResult};

/// The dnsNode class: an ACE for it lets the holder create DNS records.
const DNS_NODE: &str = "e0fa1e8c-9b45-11d0-afdd-00c04fd930c9";

fn ldap_from(m: &Model, what: &str) -> String {
    format!(
        "{what} via LDAP on {} as {}",
        m.raw.info.server, m.raw.info.account
    )
}

fn remoting(m: &Model, what: &str) -> String {
    format!(
        "{what} over PowerShell remoting, collected from {} as {}",
        m.raw.info.computer, m.raw.info.account
    )
}

/// The DC's DNS server data, or the result for a DC that has none.
fn dns(d: &DcData) -> Result<&DnsServer, Eval> {
    match &d.dns {
        None => Err(Eval::Unknown(d.why_missing("dns"))),
        Some(s) if !s.installed => Err(Eval::Ok("does not run the DNS server".into())),
        Some(s) => Ok(s),
    }
}

/// DNS servers that were read, by DC name.
fn dns_servers<'a>(m: &'a Model) -> Vec<(&'a str, &'a DnsServer)> {
    m.raw
        .dcconfig
        .iter()
        .filter_map(|c| {
            let s = c.data.as_ref()?.dns.as_ref()?;
            s.installed.then_some((c.name.as_str(), s))
        })
        .collect()
}

fn not_dns(m: &Model, id: &str, expected: &str) -> Option<CheckResult> {
    if !dns_servers(m).is_empty() {
        return None;
    }
    let why = if m.raw.dcconfig.iter().any(|c| c.data.is_some()) {
        "No domain controller that was read runs the DNS server, or the DNS part could not be read."
    } else {
        "No domain controller was read."
    };
    Some(check(id).expected(expected).not_assessed(why).done())
}

// ---------- DNS ----------

fn dns_001(m: &Model) -> CheckResult {
    each_dc(
        m,
        "AD-DNS-001",
        "Every zone accepts secure dynamic updates only",
        "domain controllers",
        |_, d| {
            let s = match dns(d) {
                Ok(s) => s,
                Err(e) => return e,
            };
            let open: Vec<&str> = s
                .zones
                .iter()
                .filter(|z| z.dynamic.eq_ignore_ascii_case("NonsecureAndSecure"))
                .map(|z| z.name.as_str())
                .collect();
            if open.is_empty() {
                Eval::Ok(format!(
                    "{} without nonsecure updates",
                    plural(s.zones.len(), "zone", "zones")
                ))
            } else {
                Eval::Bad(format!(
                    "Nonsecure dynamic updates on {}: anyone on the network can add or overwrite records",
                    open.join(", ")
                ))
            }
        },
    )
    .done()
}

fn dns_002(m: &Model) -> CheckResult {
    each_dc(
        m,
        "AD-DNS-002",
        "No zone allows transfers to any server",
        "domain controllers",
        |_, d| {
            let s = match dns(d) {
                Ok(s) => s,
                Err(e) => return e,
            };
            let open: Vec<&str> = s
                .zones
                .iter()
                .filter(|z| z.transfer.eq_ignore_ascii_case("TransferAnyServer"))
                .map(|z| z.name.as_str())
                .collect();
            if open.is_empty() {
                Eval::Ok("no zone transfers to any server".into())
            } else {
                Eval::Bad(format!(
                    "Transfers to any server allowed for {}: anyone can download every record",
                    open.join(", ")
                ))
            }
        },
    )
    .done()
}

fn dns_003(m: &Model) -> CheckResult {
    each_dc(
        m,
        "AD-DNS-003",
        "No wildcard records, and the global query block list blocks wpad and isatap",
        "domain controllers",
        |_, d| {
            let s = match dns(d) {
                Ok(s) => s,
                Err(e) => return e,
            };
            let mut why = Vec::new();
            let wild: BTreeSet<&str> = s
                .records
                .iter()
                .filter(|r| r.name == "*")
                .map(|r| r.zone.as_str())
                .collect();
            if !wild.is_empty() {
                why.push(format!(
                    "Wildcard record in {}: every unknown name resolves",
                    wild.into_iter().collect::<Vec<_>>().join(", ")
                ));
            }
            let blocked = |n: &str| {
                s.block_list.enabled
                    && s.block_list.names.iter().any(|x| x.eq_ignore_ascii_case(n))
            };
            let open: Vec<&str> = ["wpad", "isatap"]
                .into_iter()
                .filter(|n| !blocked(n))
                .collect();
            if !open.is_empty() {
                let has_record = |n: &str| s.records.iter().any(|r| r.name.eq_ignore_ascii_case(n));
                let names: Vec<String> = open
                    .iter()
                    .map(|n| {
                        if has_record(n) {
                            format!("{n} (a record exists)")
                        } else {
                            n.to_string()
                        }
                    })
                    .collect();
                why.push(format!(
                    "Global query block list does not block {}: a user who registers the name can intercept web proxy or IPv6 traffic",
                    names.join(", ")
                ));
            }
            if why.is_empty() {
                Eval::Ok("no wildcard records; wpad and isatap blocked".into())
            } else {
                Eval::Bad(why.join("; "))
            }
        },
    )
    .done()
}

/// Principals any user is part of.
fn broad(m: &Model, sid: &str) -> bool {
    matches!(sid, "S-1-1-0" | "S-1-5-11" | "S-1-5-7" | "S-1-5-32-545")
        || sid
            .strip_prefix(&m.domain_sid)
            .is_some_and(|r| r == "-513" || r == "-515")
}

fn dns_004(m: &Model) -> CheckResult {
    let mut list = Vec::new();
    let mut zones = 0;
    for z in &m.raw.dnszones {
        let name = rdn_value(z.dn());
        if name.eq_ignore_ascii_case("RootDNSServers") || name.starts_with("..") {
            continue;
        }
        zones += 1;
        let Some(sd) = z
            .str("ntsecuritydescriptor")
            .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())
            .and_then(|b| sd::parse(&b))
        else {
            continue;
        };
        let who: BTreeSet<String> = sd
            .dacl
            .iter()
            .filter(|a| a.kind == AceType::Allow && !a.inherit_only() && broad(m, &a.sid))
            .filter(|a| {
                a.mask & (right::CREATE_CHILD | right::GENERIC_ALL) != 0
                    && a.object_type
                        .as_deref()
                        .is_none_or(|t| t.eq_ignore_ascii_case(DNS_NODE))
            })
            .map(|a| {
                well_known_name(&a.sid)
                    .map(str::to_string)
                    .or_else(|| m.by_sid(&a.sid).map(|i| m.nodes[i].name.clone()))
                    .unwrap_or_else(|| a.sid.clone())
            })
            .collect();
        if !who.is_empty() {
            list.push(Affected {
                last_seen: None,
                name,
                kind: "dnsZone".into(),
                location: Some(z.dn().to_string()),
                reason: Some(format!(
                    "{} can create records: any user can register names that are not taken yet, such as wpad or a mistyped server name",
                    who.into_iter().collect::<Vec<_>>().join(", ")
                )),
                object: None,
            });
        }
    }
    check("AD-DNS-004")
        .expected("Only admins and DNS servers can create records in AD-integrated zones")
        .found(format!(
            "{} of {} let any user create records",
            list.len(),
            plural(zones, "zone", "zones")
        ))
        .affected(list, "zones")
        .evidence(
            "Read from",
            ldap_from(
                m,
                "nTSecurityDescriptor of dnsZone objects in DomainDnsZones and ForestDnsZones",
            ),
        )
        .done()
}

fn dns_005(m: &Model) -> CheckResult {
    let expected =
        "At least one DNS server scavenges stale records, and AD-integrated zones have aging on";
    if let Some(r) = not_dns(m, "AD-DNS-005", expected) {
        return r;
    }
    let servers = dns_servers(m);
    let scavengers: Vec<String> = servers
        .iter()
        .filter(|(_, s)| s.scavenging)
        .map(|(n, s)| {
            format!(
                "{} (every {})",
                short(n),
                plural(s.scavenging_days.max(0) as usize, "day", "days")
            )
        })
        .collect();
    let mut no_aging: BTreeMap<&str, ()> = BTreeMap::new();
    for (_, s) in &servers {
        for z in s.zones.iter().filter(|z| {
            z.ds && !z.reverse
                && z.kind.eq_ignore_ascii_case("Primary")
                && !z.name.starts_with("_msdcs.")
        }) {
            if z.aging == Some(false) {
                no_aging.insert(z.name.as_str(), ());
            }
        }
    }
    let mut list: Vec<Affected> = no_aging
        .keys()
        .map(|z| Affected {
            last_seen: None,
            name: (*z).to_string(),
            kind: "dnsZone".into(),
            location: None,
            reason: Some("Aging is off: records of retired computers stay in the zone".into()),
            object: None,
        })
        .collect();
    if scavengers.is_empty() {
        list.insert(
            0,
            Affected {
                last_seen: None,
                name: "Scavenging".into(),
                kind: "setting".into(),
                location: None,
                reason: Some(format!(
                    "Off on all {}: stale records are never removed",
                    plural(servers.len(), "DNS server", "DNS servers")
                )),
                object: None,
            },
        );
    }
    let mut out = check("AD-DNS-005")
        .expected(expected)
        .found(if list.is_empty() {
            "Scavenging and aging are on".to_string()
        } else {
            plural(list.len(), "scavenging gap", "scavenging gaps")
        })
        .affected(list, "settings");
    if !scavengers.is_empty() {
        out = out.evidence("Scavenging on", scavengers.join(", "));
    }
    out.evidence(
        "Read from",
        remoting(m, "Get-DnsServerScavenging and Get-DnsServerZoneAging"),
    )
    .done()
}

fn dns_006(m: &Model) -> CheckResult {
    let expected = "Every DNS server DC forwards to the same resolvers";
    if let Some(r) = not_dns(m, "AD-DNS-006", expected) {
        return r;
    }
    let servers = dns_servers(m);
    let key = |s: &DnsServer| {
        let mut f = s.forwarders.clone();
        f.sort();
        f.join(", ")
    };
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for (_, s) in &servers {
        *counts.entry(key(s)).or_default() += 1;
    }
    let common = counts
        .iter()
        .max_by_key(|(k, n)| (**n, !k.is_empty()))
        .map(|(k, _)| k.clone())
        .unwrap_or_default();
    let shown = |k: &str| {
        if k.is_empty() {
            "no forwarders (root hints only)".to_string()
        } else {
            k.to_string()
        }
    };
    let list: Vec<Affected> = servers
        .iter()
        .filter(|(_, s)| key(s) != common)
        .map(|(n, s)| {
            dc_item(
                m,
                n,
                format!(
                    "Forwards to {}, while most DNS servers use {}",
                    shown(&key(s)),
                    shown(&common)
                ),
            )
        })
        .collect();
    let inventory: Vec<String> = servers
        .iter()
        .map(|(n, s)| format!("{}: {}", short(n), shown(&key(s))))
        .collect();
    check("AD-DNS-006")
        .expected(expected)
        .found(if list.is_empty() {
            format!(
                "All {} forward to {}",
                plural(servers.len(), "DNS server", "DNS servers"),
                shown(&common)
            )
        } else {
            plural(list.len(), "DNS server differs", "DNS servers differ")
        })
        .affected(list, "domain controllers")
        .raw(inventory.join("\n"))
        .evidence("Read from", remoting(m, "Get-DnsServerForwarder"))
        .done()
}

fn dns_009(m: &Model) -> CheckResult {
    each_dc(
        m,
        "AD-DNS-009",
        "The DNS server audit log is on, so zone and record changes are recorded",
        "domain controllers",
        |_, d| {
            let s = match dns(d) {
                Ok(s) => s,
                Err(e) => return e,
            };
            match s.audit_log {
                Some(true) => Eval::Ok("DNS audit log on".into()),
                Some(false) => Eval::Bad(
                    "Microsoft-Windows-DNSServer/Audit is off: record and zone changes leave no trace"
                        .into(),
                ),
                None => Eval::Unknown("the DNS server has no audit log channel".into()),
            }
        },
    )
    .done()
}

fn dns_010(m: &Model) -> CheckResult {
    let expected =
        "Every DC has an _ldap._tcp.dc._msdcs SRV record, and every record points at a DC";
    if let Some(r) = not_dns(m, "AD-DNS-010", expected) {
        return r;
    }
    let servers = dns_servers(m);
    let targets: BTreeSet<String> = servers
        .iter()
        .flat_map(|(_, s)| s.dc_srv.iter())
        .map(|t| t.trim_end_matches('.').to_ascii_lowercase())
        .collect();
    if targets.is_empty() {
        return check("AD-DNS-010")
            .expected(expected)
            .not_assessed("No DNS server returned the _ldap._tcp.dc._msdcs SRV records; the zone may be hosted elsewhere.")
            .done();
    }
    let mut list = Vec::new();
    let mut hosts = BTreeSet::new();
    for i in dc_nodes(m) {
        let Some(host) = m.nodes[i].attrs.str("dnshostname") else {
            continue;
        };
        let host = host.to_ascii_lowercase();
        if !targets.contains(&host) {
            list.push(item(
                m,
                i,
                format!("No SRV record points at {host}: clients cannot find this DC"),
            ));
        }
        hosts.insert(host);
    }
    for t in targets.iter().filter(|t| !hosts.contains(*t)) {
        list.push(Affected {
            last_seen: None,
            name: t.clone(),
            kind: "dnsRecord".into(),
            location: Some("_ldap._tcp.dc._msdcs".into()),
            reason: Some(
                "SRV record for a host that is not a DC: clients try it and wait, or whoever controls that name receives sign-ins"
                    .into(),
            ),
            object: None,
        });
    }
    check("AD-DNS-010")
        .expected(expected)
        .found(plural(list.len(), "SRV mismatch", "SRV mismatches"))
        .affected(list, "records")
        .raw(targets.into_iter().collect::<Vec<_>>().join("\n"))
        .evidence(
            "Read from",
            remoting(m, "Get-DnsServerResourceRecord for _ldap._tcp.dc._msdcs"),
        )
        .done()
}

fn dns_012(m: &Model) -> CheckResult {
    let expected = "Zones on DCs are AD-integrated and stored in the DomainDnsZones or ForestDnsZones partition";
    if let Some(r) = not_dns(m, "AD-DNS-012", expected) {
        return r;
    }
    let mut bad: BTreeMap<String, String> = BTreeMap::new();
    for (dc, s) in dns_servers(m) {
        for z in s
            .zones
            .iter()
            .filter(|z| z.kind.eq_ignore_ascii_case("Primary"))
        {
            if !z.ds {
                bad.entry(z.name.clone()).or_insert_with(|| {
                    format!(
                        "File-backed on {}: not replicated by AD and not protected by AD permissions",
                        short(dc)
                    )
                });
            } else if z.scope.eq_ignore_ascii_case("Legacy") {
                bad.entry(z.name.clone()).or_insert_with(|| {
                    "Stored in the domain partition (Windows 2000 mode): replicated to every DC, DNS server or not".into()
                });
            }
        }
    }
    let list: Vec<Affected> = bad
        .into_iter()
        .map(|(name, why)| Affected {
            last_seen: None,
            name,
            kind: "dnsZone".into(),
            location: None,
            reason: Some(why),
            object: None,
        })
        .collect();
    check("AD-DNS-012")
        .expected(expected)
        .found(plural(list.len(), "zone is", "zones are") + " stored in the wrong place")
        .affected(list, "zones")
        .evidence("Read from", remoting(m, "Get-DnsServerZone"))
        .done()
}

// ---------- Replication on each DC ----------

/// "CN=NTDS Settings,CN=DC02,CN=Servers,..." to "DC02".
fn partner_name(dn: &str) -> String {
    parent_dn(dn)
        .map(rdn_value)
        .unwrap_or_else(|| dn.to_string())
}

fn rep_001(m: &Model) -> CheckResult {
    each_dc(
        m,
        "AD-REP-001",
        "The last inbound replication from every partner succeeded",
        "domain controllers",
        |_, d| {
            let Some(links) = &d.replication else {
                return Eval::Unknown(d.why_missing("replication"));
            };
            let failing: Vec<String> = links
                .iter()
                .filter(|l| l.last_result != 0 || l.failures > 0)
                .map(|l| {
                    format!(
                        "{} / {}: error {}, {}",
                        partner_name(&l.partner),
                        rdn_value(&l.partition),
                        l.last_result,
                        plural(l.failures.max(0) as usize, "failure", "failures") + " in a row"
                    )
                })
                .collect();
            if failing.is_empty() {
                Eval::Ok(format!(
                    "{} replicating",
                    plural(links.len(), "partner link", "partner links")
                ))
            } else {
                Eval::Bad(format!("Failing: {}", failing.join("; ")))
            }
        },
    )
    .done()
}

fn rep_002(m: &Model) -> CheckResult {
    each_dc(
        m,
        "AD-REP-002",
        "Every partner replicated in successfully within the last 24 hours",
        "domain controllers",
        |_, d| {
            let Some(links) = &d.replication else {
                return Eval::Unknown(d.why_missing("replication"));
            };
            let stale: Vec<String> = links
                .iter()
                .filter_map(|l| {
                    let label =
                        format!("{} / {}", partner_name(&l.partner), rdn_value(&l.partition));
                    match age_days(m, l.last_success.as_deref()) {
                        None => Some(format!("{label}: never")),
                        Some(days) if days >= 1 => Some(format!(
                            "{label}: {} ago",
                            plural(days as usize, "day", "days")
                        )),
                        Some(_) => None,
                    }
                })
                .collect();
            if stale.is_empty() {
                Eval::Ok("all partners within 24 hours".into())
            } else {
                Eval::Bad(format!("Last success: {}", stale.join("; ")))
            }
        },
    )
    .done()
}

fn rep_003(m: &Model) -> CheckResult {
    each_dc(
        m,
        "AD-REP-003",
        "No DC has stopped replication after a USN rollback",
        "domain controllers",
        |_, d| {
            if let Some(e) = registry_ready(d) {
                return e;
            }
            match d.reg_int("ntds.dsanotwritable") {
                None | Some(0) => Eval::Ok("Dsa Not Writable not set".into()),
                Some(4) => Eval::Bad(
                    "Dsa Not Writable = 4: USN rollback detected; this DC no longer replicates and must be demoted or restored correctly"
                        .into(),
                ),
                Some(v) => Eval::Bad(format!(
                    "Dsa Not Writable = {v}: the directory database is in read-only quarantine"
                )),
            }
        },
    )
    .done()
}

fn rep_008(m: &Model) -> CheckResult {
    each_dc(
        m,
        "AD-REP-008",
        "Every client signs in from a subnet mapped to a site",
        "domain controllers",
        |_, d| {
            let Some(clients) = &d.no_client_site else {
                return Eval::Unknown(d.why_missing("no_client_site"));
            };
            if clients.is_empty() {
                return Eval::Ok("no NO_CLIENT_SITE entries in netlogon.log".into());
            }
            let total: u64 = clients.iter().map(|c| c.times).sum();
            let top: Vec<String> = clients
                .iter()
                .take(5)
                .map(|c| format!("{} {} ({})", c.client, c.ip, c.times))
                .collect();
            Eval::Bad(format!(
                "{} from {} with no site, such as {}: they may authenticate against distant DCs",
                plural(total as usize, "sign-in", "sign-ins"),
                plural(clients.len(), "address", "addresses"),
                top.join(", ")
            ))
        },
    )
    .done()
}

fn rep_011(m: &Model) -> CheckResult {
    each_dc(
        m,
        "AD-REP-011",
        "SYSVOL replicates with DFSR, and FRS is gone",
        "domain controllers",
        |_, d| {
            if let Some(e) = registry_ready(d) {
                return e;
            }
            if d.services.is_none() {
                return Eval::Unknown(d.why_missing("services"));
            }
            match d.reg_int("dfsr.sysvolstate") {
                Some(3) => return Eval::Ok("DFSR (migration eliminated)".into()),
                Some(v) => {
                    return Eval::Bad(format!(
                        "SYSVOL migration to DFSR not finished (state {v} of 3): FRS still replicates SYSVOL"
                    ))
                }
                None => {}
            }
            if d.running("NtFrs") {
                Eval::Bad("SYSVOL replicates with FRS, which is deprecated and blocks Windows Server 2019 and later DCs".into())
            } else if d.running("DFSR") {
                Eval::Ok("DFSR".into())
            } else {
                Eval::Bad("Neither DFSR nor FRS is running: SYSVOL does not replicate".into())
            }
        },
    )
    .done()
}

fn dfsr_state(s: i64) -> &'static str {
    match s {
        0 => "uninitialized",
        1 => "initialized",
        2 => "initial sync",
        3 => "auto recovery",
        4 => "normal",
        5 => "in error",
        _ => "unknown",
    }
}

fn rep_012(m: &Model) -> CheckResult {
    each_dc(
        m,
        "AD-REP-012",
        "The SYSVOL replicated folder is in the Normal state on every DC",
        "domain controllers",
        |_, d| {
            let Some(folders) = &d.dfsr else {
                return Eval::Unknown(d.why_missing("dfsr"));
            };
            let Some(f) = folders
                .iter()
                .find(|f| f.folder.eq_ignore_ascii_case("SYSVOL Share"))
            else {
                return Eval::Unknown("SYSVOL is not replicated by DFSR on this DC".into());
            };
            if f.state == 4 {
                Eval::Ok("SYSVOL Share normal".into())
            } else {
                Eval::Bad(format!(
                    "SYSVOL Share is {} (state {}): policy and script changes do not reach or leave this DC",
                    dfsr_state(f.state),
                    f.state
                ))
            }
        },
    )
    .done()
}

// ---------- Site topology ----------

struct Topology<'a> {
    sites: Vec<&'a LdapObject>,
    servers: Vec<&'a LdapObject>,
    dsas: Vec<&'a LdapObject>,
    settings: Vec<&'a LdapObject>,
    subnets: Vec<&'a LdapObject>,
    links: Vec<&'a LdapObject>,
    bridges: Vec<&'a LdapObject>,
    transports: Vec<&'a LdapObject>,
}

fn topology<'a>(m: &Model<'a>) -> Topology<'a> {
    let raw = m.raw;
    let of = |c: &str| -> Vec<&'a LdapObject> {
        raw.sites
            .iter()
            .filter(|o| {
                o.strs("objectclass")
                    .iter()
                    .any(|x| x.eq_ignore_ascii_case(c))
            })
            .collect()
    };
    Topology {
        sites: of("site"),
        servers: of("server"),
        dsas: of("nTDSDSA"),
        settings: of("nTDSSiteSettings"),
        subnets: of("subnet"),
        links: of("siteLink"),
        bridges: of("siteLinkBridge"),
        transports: of("interSiteTransport"),
    }
}

fn lower_parent(dn: &str) -> String {
    parent_dn(dn).unwrap_or_default().to_ascii_lowercase()
}

impl Topology<'_> {
    /// DSAs in a site (by site DN, lower case).
    fn dsas_in(&self, site: &str) -> Vec<&LdapObject> {
        self.dsas
            .iter()
            .filter(|d| lower_parent(&lower_parent(&lower_parent(d.dn()))) == site)
            .copied()
            .collect()
    }
}

fn site_item(o: &LdapObject, kind: &str, reason: impl Into<String>) -> Affected {
    Affected {
        last_seen: None,
        name: rdn_value(o.dn()),
        kind: kind.into(),
        location: Some(o.dn().to_string()),
        reason: Some(reason.into()),
        object: None,
    }
}

fn sites_from(m: &Model) -> String {
    ldap_from(m, "CN=Sites in the configuration partition")
}

fn rep_005(m: &Model) -> CheckResult {
    let t = topology(m);
    let dsas: BTreeSet<String> = t.dsas.iter().map(|d| d.dn().to_ascii_lowercase()).collect();
    let mut list = Vec::new();
    let mut with_dcs = 0;
    for site in &t.sites {
        let site_dn = site.dn().to_ascii_lowercase();
        if t.dsas_in(&site_dn).is_empty() {
            continue;
        }
        with_dcs += 1;
        let settings = t.settings.iter().find(|s| lower_parent(s.dn()) == site_dn);
        let mut why = Vec::new();
        match settings.and_then(|s| s.str("intersitetopologygenerator")) {
            None => why.push("No inter-site topology generator (ISTG) is set".to_string()),
            Some(istg) if istg.contains("\\0ADEL:") || istg.contains("\nDEL:") => {
                why.push("The ISTG is a deleted DC".into())
            }
            Some(istg) if !dsas.contains(&istg.to_ascii_lowercase()) => {
                why.push(format!("The ISTG {} no longer exists", partner_name(istg)))
            }
            Some(istg) if lower_parent(&lower_parent(&lower_parent(istg))) != site_dn => why.push(
                format!("The ISTG {} is in another site", partner_name(istg)),
            ),
            Some(_) => {}
        }
        let options = settings.and_then(|s| s.int("options")).unwrap_or(0);
        if options & 0x1 != 0 {
            why.push("Automatic intra-site topology is off".into());
        }
        if options & 0x10 != 0 {
            why.push("Automatic inter-site topology is off".into());
        }
        if !why.is_empty() {
            list.push(site_item(site, "site", why.join("; ")));
        }
    }
    check("AD-REP-005")
        .expected("Every site with DCs has a live ISTG and automatic topology on")
        .found(format!(
            "{} of {} with topology issues",
            list.len(),
            plural(with_dcs, "site with DCs", "sites with DCs")
        ))
        .affected(list, "sites")
        .evidence("Read from", sites_from(m))
        .done()
}

fn rep_006(m: &Model) -> CheckResult {
    let t = topology(m);
    let list: Vec<Affected> = t
        .sites
        .iter()
        .filter(|s| t.dsas_in(&s.dn().to_ascii_lowercase()).is_empty())
        .map(|s| {
            let subnets = t
                .subnets
                .iter()
                .filter(|n| {
                    n.str("siteobject")
                        .is_some_and(|x| x.eq_ignore_ascii_case(s.dn()))
                })
                .count();
            site_item(
                s,
                "site",
                format!(
                    "No DC; clients in its {} sign in at whichever DC covers it",
                    plural(subnets, "subnet", "subnets")
                ),
            )
        })
        .collect();
    check("AD-REP-006")
        .expected("Every site has a DC, or is knowingly covered by one in another site")
        .found(format!(
            "{} of {} without a DC",
            list.len(),
            plural(t.sites.len(), "site", "sites")
        ))
        .affected(list, "sites")
        .evidence("Read from", sites_from(m))
        .done()
}

fn rep_007(m: &Model) -> CheckResult {
    let t = topology(m);
    let list: Vec<Affected> = t
        .subnets
        .iter()
        .filter(|n| n.str("siteobject").is_none_or(str::is_empty))
        .map(|n| {
            site_item(
                n,
                "subnet",
                "Not assigned to a site: clients in it get no site and may use any DC",
            )
        })
        .collect();
    let mut out = check("AD-REP-007")
        .expected("Every subnet is assigned to a site")
        .found(format!(
            "{} of {} not assigned",
            list.len(),
            plural(t.subnets.len(), "subnet", "subnets")
        ))
        .affected(list, "subnets");
    if t.subnets.is_empty() && t.sites.len() > 1 {
        out = out.evidence(
            "Note",
            "No subnet is defined at all, so no client is mapped to a site",
        );
    }
    out.evidence("Read from", sites_from(m)).done()
}

fn rep_009(m: &Model) -> CheckResult {
    let t = topology(m);
    let mut list = Vec::new();
    for l in &t.links {
        let mut why = Vec::new();
        let sites = l.strs("sitelist").len();
        if sites < 2 {
            why.push(format!("Links {}", plural(sites, "site", "sites")));
        }
        if let Some(i) = l.int("replinterval").filter(|i| *i > 180) {
            why.push(format!(
                "Replicates every {i} minutes: changes take hours to reach other sites"
            ));
        }
        if !why.is_empty() {
            list.push(site_item(l, "siteLink", why.join("; ")));
        }
    }
    let raw: Vec<String> = t
        .links
        .iter()
        .map(|l| {
            format!(
                "{}: cost {}, every {} min, {}",
                rdn_value(l.dn()),
                l.int("cost").map_or("?".into(), |c| c.to_string()),
                l.int("replinterval").map_or("?".into(), |c| c.to_string()),
                l.strs("sitelist")
                    .iter()
                    .map(|s| rdn_value(s))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })
        .collect();
    check("AD-REP-009")
        .expected("Site links join two or more sites and replicate at least every 3 hours")
        .found(format!(
            "{} of {} need review",
            list.len(),
            plural(t.links.len(), "site link", "site links")
        ))
        .affected(list, "site links")
        .raw(raw.join("\n"))
        .evidence("Read from", sites_from(m))
        .done()
}

fn rep_010(m: &Model) -> CheckResult {
    let t = topology(m);
    let out = check("AD-REP-010").expected(
        "Bridge all site links is on, or site link bridges cover the sites that need transitive replication",
    );
    let Some(ip) = t
        .transports
        .iter()
        .find(|x| rdn_value(x.dn()).eq_ignore_ascii_case("IP"))
    else {
        return out
            .not_assessed("The IP inter-site transport object was not returned.")
            .done();
    };
    let bridging = ip.int("options").unwrap_or(0) & 0x2 == 0;
    let mut list = Vec::new();
    if !bridging && t.bridges.is_empty() && t.sites.len() > 2 {
        list.push(site_item(
            ip,
            "interSiteTransport",
            "Bridge all site links is off and no site link bridge exists: sites without a direct link do not replicate with each other",
        ));
    }
    out.found(if bridging {
        "Bridge all site links is on".to_string()
    } else {
        format!(
            "Bridge all site links is off, {}",
            plural(t.bridges.len(), "site link bridge", "site link bridges")
        )
    })
    .affected(list, "settings")
    .evidence("Read from", sites_from(m))
    .done()
}

fn rep_015(m: &Model) -> CheckResult {
    let t = topology(m);
    let domain = m
        .domain
        .map(|d| m.nodes[d].dn.to_ascii_lowercase())
        .unwrap_or_default();
    let mut list = Vec::new();
    for s in &t.servers {
        let dn = s.dn().to_ascii_lowercase();
        if !t.dsas.iter().any(|d| lower_parent(d.dn()) == dn) {
            continue;
        }
        let why = match s.str("serverreference") {
            None => "Has NTDS Settings but no computer account: left behind by a DC that was removed without cleanup".to_string(),
            Some(r) if r.to_ascii_lowercase().ends_with(&domain) && !m.by_dn.contains_key(&r.to_ascii_lowercase()) => format!(
                "Its computer account {} no longer exists: metadata of a removed DC",
                rdn_value(r)
            ),
            _ => continue,
        };
        list.push(site_item(s, "server", why));
    }
    check("AD-REP-015")
        .expected("Every server with NTDS Settings belongs to an existing DC")
        .found(plural(
            list.len(),
            "orphaned DC entry",
            "orphaned DC entries",
        ))
        .affected(list, "servers")
        .evidence("Read from", sites_from(m))
        .done()
}

fn rep_016(m: &Model) -> CheckResult {
    let t = topology(m);
    let mut list = Vec::new();
    let mut with_dcs = 0;
    for site in &t.sites {
        let dsas = t.dsas_in(&site.dn().to_ascii_lowercase());
        if dsas.is_empty() {
            continue;
        }
        with_dcs += 1;
        if !dsas
            .iter()
            .any(|d| d.int("options").unwrap_or(0) & 0x1 != 0)
        {
            list.push(site_item(
                site,
                "site",
                format!(
                    "None of its {} is a global catalog: sign-ins there query a GC in another site",
                    plural(dsas.len(), "DC", "DCs")
                ),
            ));
        }
    }
    check("AD-REP-016")
        .expected("Every site with DCs has a global catalog")
        .found(format!(
            "{} of {} without a GC",
            list.len(),
            plural(with_dcs, "site with DCs", "sites with DCs")
        ))
        .affected(list, "sites")
        .evidence("Read from", sites_from(m))
        .done()
}

// ---------- Group Policy versions ----------

fn split_version(v: i64) -> String {
    format!("user {}, computer {}", v >> 16, v & 0xFFFF)
}

fn rep_014(m: &Model) -> CheckResult {
    let out = check("AD-REP-014").expected("Every GPO has the same version in AD and in SYSVOL");
    let read: Vec<&SysvolPolicy> = m
        .raw
        .sysvol
        .iter()
        .filter(|p| p.version.is_some())
        .collect();
    if read.is_empty() {
        return out
            .not_assessed(
                "GPT.INI versions were not collected; collect SYSVOL again with this version.",
            )
            .done();
    }
    let mut list = Vec::new();
    for p in read {
        let Some(g) = m.nodes.iter().position(|n| {
            n.kind == super::model::Kind::Gpo && rdn_value(&n.dn).eq_ignore_ascii_case(&p.folder)
        }) else {
            continue;
        };
        let (Some(ad), Some(fs)) = (m.nodes[g].attrs.int("versionnumber"), p.version) else {
            continue;
        };
        if ad != fs {
            list.push(item(
                m,
                g,
                format!(
                    "AD version {ad} ({}), SYSVOL version {fs} ({}): computers may apply old settings or skip the GPO",
                    split_version(ad),
                    split_version(fs)
                ),
            ));
        }
    }
    out.found(plural(list.len(), "GPO differs", "GPOs differ") + " between AD and SYSVOL")
        .affected(list, "GPOs")
        .evidence(
            "Read from",
            format!(
                "versionNumber via LDAP on {} and GPT.INI in \\\\{}\\SYSVOL",
                m.raw.info.server, m.dns
            ),
        )
        .done()
}

pub static RULES: &[Rule] = &[
    Rule {
        id: "AD-DNS-001",
        needs: &["dcconfig"],
        run: dns_001,
    },
    Rule {
        id: "AD-DNS-002",
        needs: &["dcconfig"],
        run: dns_002,
    },
    Rule {
        id: "AD-DNS-003",
        needs: &["dcconfig"],
        run: dns_003,
    },
    Rule {
        id: "AD-DNS-004",
        needs: &["dnszones", "groups"],
        run: dns_004,
    },
    Rule {
        id: "AD-DNS-005",
        needs: &["dcconfig"],
        run: dns_005,
    },
    Rule {
        id: "AD-DNS-006",
        needs: &["dcconfig"],
        run: dns_006,
    },
    Rule {
        id: "AD-DNS-009",
        needs: &["dcconfig"],
        run: dns_009,
    },
    Rule {
        id: "AD-DNS-010",
        needs: &["dcconfig", "computers"],
        run: dns_010,
    },
    Rule {
        id: "AD-DNS-012",
        needs: &["dcconfig"],
        run: dns_012,
    },
    Rule {
        id: "AD-REP-001",
        needs: &["dcconfig"],
        run: rep_001,
    },
    Rule {
        id: "AD-REP-002",
        needs: &["dcconfig"],
        run: rep_002,
    },
    Rule {
        id: "AD-REP-003",
        needs: &["dcconfig"],
        run: rep_003,
    },
    Rule {
        id: "AD-REP-005",
        needs: &["sites"],
        run: rep_005,
    },
    Rule {
        id: "AD-REP-006",
        needs: &["sites"],
        run: rep_006,
    },
    Rule {
        id: "AD-REP-007",
        needs: &["sites"],
        run: rep_007,
    },
    Rule {
        id: "AD-REP-008",
        needs: &["dcconfig"],
        run: rep_008,
    },
    Rule {
        id: "AD-REP-009",
        needs: &["sites"],
        run: rep_009,
    },
    Rule {
        id: "AD-REP-010",
        needs: &["sites"],
        run: rep_010,
    },
    Rule {
        id: "AD-REP-011",
        needs: &["dcconfig"],
        run: rep_011,
    },
    Rule {
        id: "AD-REP-012",
        needs: &["dcconfig"],
        run: rep_012,
    },
    Rule {
        id: "AD-REP-014",
        needs: &["sysvol", "gpos"],
        run: rep_014,
    },
    Rule {
        id: "AD-REP-015",
        needs: &["sites", "computers"],
        run: rep_015,
    },
    Rule {
        id: "AD-REP-016",
        needs: &["sites"],
        run: rep_016,
    },
];
