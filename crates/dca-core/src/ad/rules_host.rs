//! Domain controller host checks read over PowerShell remoting
//! (`dcconfig`): installed software and protection, cached logons, the
//! NTDS volume, DSRM sign-in, cipher suites, DNS recursion and records,
//! PowerShell transcripts, backup software accounts, virtualization safety
//! and whether trusted domains still resolve. Plus who administers
//! virtualization, from LDAP.

use serde_json::Value;

use super::dc::DcData;
use super::model::{Kind, Model};
use super::rules::{check, item, plural, Rule};
use super::rules_dc::{each_dc, registry_ready, Eval};
use super::rules_ep::EDR_SERVICES;
use crate::results::{Affected, CheckResult};

const CACHED_LOGONS: i64 = 4;
/// Builds before Windows Server 2016, where RC4 and 3DES suites are on by default.
const SERVER_2016: i64 = 14393;

fn text(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn microsoft(publisher: &str) -> bool {
    let p = publisher.to_ascii_lowercase();
    p.is_empty() || p.contains("microsoft")
}

/// Backup products, by words in their service or package names.
const BACKUP_PRODUCTS: [&str; 12] = [
    "veeam",
    "commvault",
    "veritas",
    "netbackup",
    "backup exec",
    "rubrik",
    "cohesity",
    "acronis",
    "arcserve",
    "networker",
    "avamar",
    "data protection manager",
];

fn is_backup(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    BACKUP_PRODUCTS.iter().any(|p| l.contains(p))
}

/// The directory account a service runs as ("CORP\name" or "name@dns").
fn account_node(m: &Model, account: &str) -> Option<usize> {
    let name = account
        .rsplit('\\')
        .next()
        .unwrap_or(account)
        .split('@')
        .next()
        .unwrap_or(account);
    (0..m.nodes.len()).find(|&i| {
        matches!(m.nodes[i].kind, Kind::User | Kind::Computer)
            && m.nodes[i].name.eq_ignore_ascii_case(name)
    })
}

fn private_ipv4(ip: &str) -> bool {
    let o: Vec<u8> = ip.split('.').filter_map(|x| x.parse().ok()).collect();
    match o.as_slice() {
        [10, ..] | [127, ..] => true,
        [172, b, ..] => (16..=31).contains(b),
        [192, 168, ..] => true,
        [100, b, ..] => (64..=127).contains(b),
        [169, 254, ..] => true,
        _ => false,
    }
}

fn dc_008(m: &Model) -> CheckResult {
    each_dc(
        m,
        "AD-DC-008",
        "An inventory of third-party software installed on DCs",
        "domain controllers",
        |_, d| {
            let Some(sw) = &d.software else {
                return Eval::Unknown(d.why_missing("software"));
            };
            let mut third: Vec<String> = sw
                .iter()
                .filter(|s| !microsoft(&s.publisher))
                .map(|s| format!("{} {} ({})", s.name, s.version, s.publisher))
                .collect();
            third.sort();
            third.dedup();
            Eval::Ok(if third.is_empty() {
                "no third-party software".into()
            } else {
                format!(
                    "{}: {}",
                    plural(third.len(), "package", "packages"),
                    third.join("; ")
                )
            })
        },
    )
    .done()
}

fn dc_026(m: &Model) -> CheckResult {
    each_dc(
        m,
        "AD-DC-026",
        &format!("DCs cache at most {CACHED_LOGONS} logons"),
        "domain controllers",
        |_, d| {
            if let Some(e) = registry_ready(d) {
                return e;
            }
            let n = d.reg_int("winlogon.cachedlogonscount").unwrap_or(10);
            if n > CACHED_LOGONS {
                Eval::Bad(format!("CachedLogonsCount {n}: credentials of the last {n} accounts that signed in stay on disk"))
            } else {
                Eval::Ok(format!("CachedLogonsCount {n}"))
            }
        },
    )
    .done()
}

fn broad_exclusion(x: &str) -> bool {
    let l = x
        .trim()
        .to_ascii_lowercase()
        .trim_end_matches('\\')
        .to_string();
    l.len() <= 3 // a drive root such as "c:"
        || ["c:\\windows", "c:\\windows\\temp", "c:\\users", "c:\\programdata", "%temp%", "%windir%", "%systemroot%"]
            .contains(&l.as_str())
        || [".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", "exe", "dll", "ps1"].contains(&l.as_str())
        || l.ends_with("\\powershell.exe")
        || l.ends_with("\\cmd.exe")
        || l == "powershell.exe"
        || l == "cmd.exe"
        || l.contains("\\temp")
}

fn dc_027(m: &Model) -> CheckResult {
    each_dc(
        m,
        "AD-DC-027",
        "Every DC runs antivirus or EDR, without broad exclusions",
        "domain controllers",
        |_, d| {
            let edr: Vec<&str> = EDR_SERVICES
                .iter()
                .filter(|(svc, _)| d.running(svc))
                .map(|(_, name)| *name)
                .collect();
            let def = d.defender.as_ref();
            let defender_on = def.is_some_and(|v| {
                v.get("enabled").and_then(Value::as_bool) == Some(true)
                    && v.get("realtime").and_then(Value::as_bool) == Some(true)
            });
            if d.services.is_none() && def.is_none() {
                return Eval::Unknown(d.why_missing("services"));
            }
            let exclusions: Vec<String> = def
                .and_then(|v| v.get("exclusions"))
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            let wide: Vec<&String> = exclusions.iter().filter(|x| broad_exclusion(x)).collect();
            let mut running: Vec<&str> = edr.clone();
            if defender_on {
                running.push("Microsoft Defender Antivirus");
            }
            if running.is_empty() {
                return Eval::Bad("No antivirus or EDR agent is running".into());
            }
            if !wide.is_empty() {
                return Eval::Bad(format!(
                    "{} running, but exclusions are broad: {}",
                    running.join(", "),
                    wide.iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            Eval::Ok(format!(
                "{} running; {}",
                running.join(", "),
                plural(exclusions.len(), "exclusion", "exclusions")
            ))
        },
    )
    .done()
}

fn drive(path: &str) -> String {
    path.trim()
        .chars()
        .take(2)
        .collect::<String>()
        .to_ascii_uppercase()
}

fn dc_031(m: &Model) -> CheckResult {
    each_dc(
        m,
        "AD-DC-031",
        "The AD database and logs are on a volume other than the system volume",
        "domain controllers",
        |_, d| {
            if let Some(e) = registry_ready(d) {
                return e;
            }
            let (Some(db), logs) = (d.reg_str("ntds.database"), d.reg_str("ntds.logs")) else {
                return Eval::Unknown(
                    "No NTDS database path in the registry: not a domain controller".into(),
                );
            };
            let system = "C:";
            let mut why = Vec::new();
            if drive(&db) == system {
                why.push(format!("NTDS.dit is on the system volume ({db})"));
            }
            if let Some(l) = &logs {
                if drive(l) == system {
                    why.push(format!("logs are on the system volume ({l})"));
                }
            }
            if why.is_empty() {
                Eval::Ok(format!("database {db}; logs {}", logs.unwrap_or_default()))
            } else {
                Eval::Bad(why.join("; "))
            }
        },
    )
    .done()
}

fn ioc_007(m: &Model) -> CheckResult {
    each_dc(m, "AD-IOC-007", "The DSRM account cannot sign in over the network (DsrmAdminLogonBehavior is not 2)", "domain controllers", |_, d| {
        if let Some(e) = registry_ready(d) {
            return e;
        }
        match d.reg_int("lsa.dsrmadminlogonbehavior") {
            Some(2) => Eval::Bad("DsrmAdminLogonBehavior 2: the DSRM password works over the network, a known persistence technique".into()),
            v => Eval::Ok(format!("DsrmAdminLogonBehavior {}", v.map(|v| v.to_string()).unwrap_or_else(|| "not set".into()))),
        }
    })
    .done()
}

fn weak_cipher(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.starts_with("rc4")
        || l.starts_with("des")
        || l.starts_with("triple des")
        || l.starts_with("null")
        || l.starts_with("rc2")
}

fn leg_010(m: &Model) -> CheckResult {
    each_dc(
        m,
        "AD-LEG-010",
        "RC4, DES, 3DES and NULL cipher suites are off on DCs",
        "domain controllers",
        |_, d| {
            let Some(c) = &d.ciphers else {
                return Eval::Unknown(d.why_missing("ciphers"));
            };
            let enabled = c.get("enabled").and_then(Value::as_object);
            let on: Vec<String> = enabled
                .into_iter()
                .flatten()
                .filter(|(n, v)| weak_cipher(n) && v.as_i64().is_some_and(|x| x != 0))
                .map(|(n, _)| n.clone())
                .collect();
            let policy = text(c, "suite_policy");
            let weak_suites: Vec<&str> = policy
                .split(',')
                .map(str::trim)
                .filter(|s| {
                    let u = s.to_ascii_uppercase();
                    u.contains("_RC4_")
                        || u.contains("_3DES_")
                        || u.contains("_DES_")
                        || u.contains("_NULL_")
                        || u.contains("EXPORT")
                })
                .collect();
            let build = d.os.as_ref().map(|o| o.build).unwrap_or(0);
            let disabled = |prefix: &str| {
                enabled.is_some_and(|e| {
                    e.iter().any(|(n, v)| {
                        n.to_ascii_lowercase().starts_with(prefix) && v.as_i64() == Some(0)
                    })
                })
            };
            let mut why = Vec::new();
            if !on.is_empty() {
                why.push(format!("explicitly enabled: {}", on.join(", ")));
            }
            if !weak_suites.is_empty() {
                why.push(format!(
                    "in the cipher suite order policy: {}",
                    weak_suites.join(", ")
                ));
            }
            if build > 0 && build < SERVER_2016 && (!disabled("rc4") || !disabled("triple des")) {
                why.push(
                    "RC4 and 3DES are on by default on this Windows version and not turned off"
                        .into(),
                );
            }
            if why.is_empty() {
                Eval::Ok("no weak ciphers enabled".into())
            } else {
                Eval::Bad(why.join("; "))
            }
        },
    )
    .done()
}

fn dns_ready(d: &DcData) -> Result<&super::dc::DnsServer, Eval> {
    match &d.dns {
        Some(s) => Ok(s),
        None => Err(Eval::Unknown(d.why_missing("dns"))),
    }
}

fn dns_007(m: &Model) -> CheckResult {
    each_dc(m, "AD-DNS-007", "DNS servers on DCs that answer recursive queries are not reachable on public addresses", "domain controllers", |_, d| {
        let s = match dns_ready(d) {
            Ok(s) => s,
            Err(e) => return e,
        };
        if !s.installed {
            return Eval::Ok("DNS server not installed".into());
        }
        let Some(addrs) = &d.addresses else {
            return Eval::Unknown(d.why_missing("addresses"));
        };
        let public: Vec<&String> = addrs.iter().filter(|a| !private_ipv4(a)).collect();
        if s.recursion && !public.is_empty() {
            Eval::Bad(format!(
                "Recursion is on and the DC has public addresses ({}): it can be used as an open resolver",
                public.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
            ))
        } else {
            Eval::Ok(format!(
                "recursion {}; {}",
                if s.recursion { "on" } else { "off" },
                if public.is_empty() { "private addresses only" } else { "public addresses" }
            ))
        }
    })
    .done()
}

fn dns_008(m: &Model) -> CheckResult {
    each_dc(
        m,
        "AD-DNS-008",
        "An inventory of DNSSEC-signed zones",
        "domain controllers",
        |_, d| {
            let s = match dns_ready(d) {
                Ok(s) => s,
                Err(e) => return e,
            };
            if !s.installed {
                return Eval::Ok("DNS server not installed".into());
            }
            let signed: Vec<&str> = s
                .zones
                .iter()
                .filter(|z| z.signed)
                .map(|z| z.name.as_str())
                .collect();
            Eval::Ok(format!(
                "{} of {} signed{}",
                signed.len(),
                plural(s.zones.len(), "zone", "zones"),
                if signed.is_empty() {
                    String::new()
                } else {
                    format!(": {}", signed.join(", "))
                }
            ))
        },
    )
    .done()
}

fn dns_013(m: &Model) -> CheckResult {
    each_dc(m, "AD-DNS-013", "Each DC's A records point only at its own addresses", "domain controllers", |_, d| {
        let s = match dns_ready(d) {
            Ok(s) => s,
            Err(e) => return e,
        };
        if !s.installed {
            return Eval::Ok("DNS server not installed".into());
        }
        let Some(addrs) = &d.addresses else {
            return Eval::Unknown(d.why_missing("addresses"));
        };
        let stale: Vec<&String> = s.own_a.iter().filter(|a| !addrs.contains(a)).collect();
        if stale.is_empty() {
            Eval::Ok(format!("{} matching the DC's addresses", plural(s.own_a.len(), "A record", "A records")))
        } else {
            Eval::Bad(format!(
                "A records for addresses the DC does not have: {}. Clients sent there fail or reach another host",
                stale.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
            ))
        }
    })
    .done()
}

fn dns_014(m: &Model) -> CheckResult {
    each_dc(
        m,
        "AD-DNS-014",
        "An inventory of forwarders and root hints on DC DNS servers",
        "domain controllers",
        |_, d| {
            let s = match dns_ready(d) {
                Ok(s) => s,
                Err(e) => return e,
            };
            if !s.installed {
                return Eval::Ok("DNS server not installed".into());
            }
            Eval::Ok(format!(
                "forwarders: {}; {}",
                if s.forwarders.is_empty() {
                    "none".to_string()
                } else {
                    s.forwarders.join(", ")
                },
                s.root_hints
                    .map(|n| plural(n.max(0) as usize, "root hint", "root hints"))
                    .unwrap_or_else(|| "root hints not returned".into())
            ))
        },
    )
    .done()
}

fn aud_009(m: &Model) -> CheckResult {
    each_dc(m, "AD-AUD-009", "PowerShell transcripts from DCs are written to a central share users cannot change", "domain controllers", |_, d| {
        if let Some(e) = registry_ready(d) {
            return e;
        }
        if d.reg_int("powershell.enabletranscripting") != Some(1) {
            return Eval::Ok("Transcription is off".into());
        }
        let dir = d.reg_str("powershell.outputdirectory").unwrap_or_default();
        if dir.trim().is_empty() {
            Eval::Bad("Transcripts go to each user's Documents folder, where the user can delete them".into())
        } else if dir.starts_with("\\\\") {
            Eval::Ok(format!("Written to {dir}; confirm users can only add files there"))
        } else {
            Eval::Bad(format!("Written to {dir} on the DC itself: anyone with admin rights there can remove them"))
        }
    })
    .done()
}

fn bkp_007(m: &Model) -> CheckResult {
    each_dc(
        m,
        "AD-BKP-007",
        "Backup software on DCs runs as an account that is not a domain admin",
        "domain controllers",
        |_, d| {
            let Some(svcs) = &d.service_accounts else {
                return Eval::Unknown(d.why_missing("service_accounts"));
            };
            let mut bad = Vec::new();
            let mut seen = 0;
            for s in svcs {
                let label = format!("{} {}", text(s, "name"), text(s, "display"));
                if !is_backup(&label) {
                    continue;
                }
                seen += 1;
                let account = text(s, "account");
                if account_node(m, &account).is_some_and(|i| m.nodes[i].tier0) {
                    bad.push(format!(
                        "{} runs as {account}, a Tier 0 account",
                        text(s, "display")
                    ));
                }
            }
            if bad.is_empty() {
                Eval::Ok(format!(
                    "{} under a domain account checked",
                    plural(seen, "backup service", "backup services")
                ))
            } else {
                Eval::Bad(bad.join("; "))
            }
        },
    )
    .done()
}

fn bkp_008(m: &Model) -> CheckResult {
    each_dc(m, "AD-BKP-008", "Virtual DCs run on a hypervisor that provides VM-GenerationID", "domain controllers", |_, d| {
        let Some(h) = &d.hardware else {
            return Eval::Unknown(d.why_missing("hardware"));
        };
        let model = format!("{} {}", text(h, "manufacturer"), text(h, "model")).to_ascii_lowercase();
        let virtual_machine = ["virtual", "vmware", "kvm", "xen", "qemu", "hvm", "openstack", "parallels"]
            .iter()
            .any(|w| model.contains(w));
        if !virtual_machine {
            return Eval::Ok("physical".into());
        }
        if h.get("vm_generation_id").and_then(Value::as_bool) == Some(true) {
            Eval::Ok(format!("virtual ({}); VM-GenerationID present", model.trim()))
        } else {
            Eval::Bad(format!(
                "virtual ({}) without VM-GenerationID: restoring a snapshot rolls back the DC's USN and breaks replication",
                model.trim()
            ))
        }
    })
    .done()
}

fn tru_007(m: &Model) -> CheckResult {
    each_dc(
        m,
        "AD-TRU-007",
        "Every trusted domain's DCs can be found in DNS",
        "domain controllers",
        |_, d| {
            let Some(t) = &d.trust_dns else {
                return Eval::Unknown(d.why_missing("trust_dns"));
            };
            let gone: Vec<String> = t
                .iter()
                .filter(|x| x.get("resolves").and_then(Value::as_bool) == Some(false))
                .map(|x| text(x, "partner"))
                .collect();
            if gone.is_empty() {
                Eval::Ok(format!(
                    "{} resolve",
                    plural(t.len(), "trusted domain", "trusted domains")
                ))
            } else {
                Eval::Bad(format!(
                "No DC found in DNS for {}: the trust may point at a domain that no longer exists",
                gone.join(", ")
            ))
            }
        },
    )
    .done()
}

fn priv_009(m: &Model) -> CheckResult {
    let virt = |n: &str| {
        let l = n.to_ascii_lowercase();
        l.contains("hyper-v admin")
            || l.contains("vmware")
            || l.contains("vcenter")
            || l.contains("esx admin")
            || l.contains("virtualization admin")
    };
    let mut groups: Vec<usize> = m.by_sid("S-1-5-32-578").into_iter().collect();
    groups.extend(
        (0..m.nodes.len()).filter(|&i| m.nodes[i].kind == Kind::Group && virt(&m.nodes[i].name)),
    );
    groups.sort_unstable();
    groups.dedup();
    let mut list: Vec<Affected> = Vec::new();
    for g in &groups {
        for u in m.recursive_members(*g) {
            if m.nodes[u].kind == Kind::User && !m.nodes[u].tier0 {
                list.push(item(
                    m,
                    u,
                    format!(
                        "Member of {}: administers the hypervisor that can host virtual DCs",
                        m.nodes[*g].name
                    ),
                ));
            }
        }
    }
    check("AD-PRIV-009")
        .expected("Only Tier 0 admins administer the virtualization platform that runs DCs")
        .found(format!(
            "{}; {} outside Tier 0",
            plural(
                groups.len(),
                "virtualization admin group",
                "virtualization admin groups"
            ),
            plural(list.len(), "member", "members")
        ))
        .affected(list, "members")
        .evidence(
            "Read from",
            format!(
                "Hyper-V Administrators and groups named for VMware or Hyper-V via LDAP on {}",
                m.raw.info.server
            ),
        )
        .done()
}

pub static RULES: &[Rule] = &[
    Rule {
        id: "AD-DC-008",
        needs: &["dcconfig"],
        run: dc_008,
    },
    Rule {
        id: "AD-DC-026",
        needs: &["dcconfig"],
        run: dc_026,
    },
    Rule {
        id: "AD-DC-027",
        needs: &["dcconfig"],
        run: dc_027,
    },
    Rule {
        id: "AD-DC-031",
        needs: &["dcconfig"],
        run: dc_031,
    },
    Rule {
        id: "AD-IOC-007",
        needs: &["dcconfig"],
        run: ioc_007,
    },
    Rule {
        id: "AD-LEG-010",
        needs: &["dcconfig"],
        run: leg_010,
    },
    Rule {
        id: "AD-DNS-007",
        needs: &["dcconfig"],
        run: dns_007,
    },
    Rule {
        id: "AD-DNS-008",
        needs: &["dcconfig"],
        run: dns_008,
    },
    Rule {
        id: "AD-DNS-013",
        needs: &["dcconfig"],
        run: dns_013,
    },
    Rule {
        id: "AD-DNS-014",
        needs: &["dcconfig"],
        run: dns_014,
    },
    Rule {
        id: "AD-AUD-009",
        needs: &["dcconfig"],
        run: aud_009,
    },
    Rule {
        id: "AD-BKP-007",
        needs: &["dcconfig", "users", "groups"],
        run: bkp_007,
    },
    Rule {
        id: "AD-BKP-008",
        needs: &["dcconfig"],
        run: bkp_008,
    },
    Rule {
        id: "AD-TRU-007",
        needs: &["dcconfig"],
        run: tru_007,
    },
    Rule {
        id: "AD-PRIV-009",
        needs: &["domain", "users", "groups"],
        run: priv_009,
    },
];
