//! AD FS, Microsoft Entra Connect Sync, Cloud Sync and pass-through
//! authentication servers, read on the servers themselves (the `identity`
//! part, on DCs or endpoints), matched to AD and to the tenant.

use std::collections::BTreeSet;

use serde_json::Value;

use super::{Ctx, Rule};
use crate::ad::model::Model;
use crate::ad::rules::{check, plural, Out};
use crate::entra::model::J;
use crate::results::{Affected, CheckResult};
use crate::time;

/// Days since the last update after which a server counts as unpatched.
const PATCH_DAYS: i64 = 60;
/// Days a token-signing certificate may stay in use.
const CERT_DAYS: i64 = 365;
/// The oldest Entra Connect Sync version this check accepts.
const MIN_SYNC: (u32, u32) = (2, 4);

/// One server that reported the identity part.
struct Server<'a> {
    host: &'a str,
    model: &'a Model<'a>,
    identity: &'a Value,
    os_build: Option<i64>,
    last_patch: Option<i64>,
    /// Endpoint parts (local admins, sessions, audit), when read as an endpoint.
    endpoint: Option<&'a crate::ad::ep::Endpoint>,
}

fn servers<'a>(ctx: &'a Ctx) -> Vec<Server<'a>> {
    let mut out = Vec::new();
    for m in ctx.domains {
        for d in &m.raw.dcconfig {
            let Some(data) = d.data.as_ref() else {
                continue;
            };
            let Some(identity) = data.identity.as_ref() else {
                continue;
            };
            out.push(Server {
                host: &d.name,
                model: m,
                identity,
                os_build: data.os.as_ref().map(|o| o.build),
                last_patch: data
                    .hotfixes
                    .as_ref()
                    .and_then(|h| h.last.as_deref())
                    .and_then(time::parse_iso),
                endpoint: None,
            });
        }
        for e in &m.raw.endpoints {
            let Some(identity) = e.part("identity") else {
                continue;
            };
            out.push(Server {
                host: &e.name,
                model: m,
                identity,
                os_build: e
                    .part("os")
                    .and_then(|o| o.get("build"))
                    .and_then(Value::as_i64),
                last_patch: e
                    .part("hotfixes")
                    .and_then(|h| h.s("last"))
                    .and_then(time::parse_iso),
                endpoint: Some(e),
            });
        }
    }
    out
}

impl Server<'_> {
    fn has(&self, service: &str) -> bool {
        self.identity.at(&["services", service]).is_some()
    }
    fn service(&self, name: &str, key: &str) -> Option<&str> {
        self.identity
            .at(&["services", name, key])
            .and_then(Value::as_str)
    }
    fn adfs(&self) -> Option<&Value> {
        self.identity.get("adfs").filter(|_| self.has("adfssrv"))
    }
    fn sync(&self) -> Option<&Value> {
        self.identity.get("sync").filter(|_| self.has("ADSync"))
    }
    fn item(&self, reason: impl Into<String>) -> Affected {
        Affected {
            last_seen: None,
            name: self.host.to_string(),
            kind: "computer".into(),
            location: None,
            reason: Some(reason.into()),
            object: self.node().map(|i| self.model.nodes[i].id.clone()),
        }
    }
    /// The computer's AD node.
    fn node(&self) -> Option<usize> {
        let short = self
            .host
            .split('.')
            .next()
            .unwrap_or(self.host)
            .to_lowercase();
        self.model.nodes.iter().position(|n| {
            n.kind == crate::ad::model::Kind::Computer
                && n.name.trim_end_matches('$').eq_ignore_ascii_case(&short)
        })
    }
    fn tier0(&self) -> bool {
        self.node()
            .is_some_and(|i| self.model.nodes[i].tier0 || self.model.nodes[i].is_dc())
    }
}

fn read_from(ctx: &Ctx) -> String {
    let hosts: BTreeSet<&str> = servers(ctx).iter().map(|s| s.host).collect();
    format!(
        "The identity part read on {}",
        if hosts.is_empty() {
            "no server".to_string()
        } else {
            hosts.into_iter().collect::<Vec<_>>().join(", ")
        }
    )
}

/// Runs `eval` over the servers that run `what`; not assessed when none did.
fn per_server(
    ctx: &Ctx,
    what: &str,
    has: impl Fn(&Server) -> bool,
    eval: impl Fn(&Server) -> Vec<String>,
    out: Out,
) -> CheckResult {
    let all = servers(ctx);
    let hits: Vec<&Server> = all.iter().filter(|s| has(s)).collect();
    if hits.is_empty() {
        return out
            .not_assessed(format!(
                "No {what} server was read: add the {what} servers to the endpoint targets (or run the DC read where they are installed)."
            ))
            .done();
    }
    let list: Vec<Affected> = hits
        .iter()
        .flat_map(|s| eval(s).into_iter().map(|r| s.item(r)))
        .collect();
    out.found(format!(
        "{}; {}",
        plural(
            hits.len(),
            &format!("{what} server"),
            &format!("{what} servers")
        ),
        plural(list.len(), "finding", "findings")
    ))
    .affected(list, "findings")
    .evidence("Read from", read_from(ctx))
    .done()
}

fn days_ago(ctx: &Ctx, t: Option<i64>) -> Option<i64> {
    let now = ctx.domains.first()?.now;
    t.map(|t| (now - t) / time::DAY)
}

// ---------- AD FS ----------

fn fed_001(ctx: &Ctx) -> CheckResult {
    per_server(
        ctx,
        "AD FS",
        |s| s.adfs().is_some(),
        |s| {
            let mut why = Vec::new();
            let fbl = s
                .adfs()
                .and_then(|a| a.get("farm_behavior"))
                .and_then(Value::as_i64);
            if fbl.is_some_and(|f| f < 3) {
                why.push(format!(
                    "AD FS farm behavior level {} (Windows Server 2012 R2), out of support",
                    fbl.unwrap_or_default()
                ));
            }
            if s.os_build.is_some_and(|b| b < 14393) {
                why.push(format!(
                    "Windows build {} is out of support",
                    s.os_build.unwrap_or_default()
                ));
            }
            match days_ago(ctx, s.last_patch) {
                Some(d) if d > PATCH_DAYS => {
                    why.push(format!("last update installed {d} days ago"))
                }
                None => why.push("no installed update date was returned".to_string()),
                _ => {}
            }
            why
        },
        check("HY-FED-001").expected(format!(
            "AD FS servers run a supported version and were patched in the last {PATCH_DAYS} days"
        )),
    )
}

/// Key storage providers that keep the key in hardware.
fn hardware(provider: &str) -> bool {
    let p = provider.to_lowercase();
    [
        "hsm", "ncipher", "safenet", "luna", "thales", "entrust", "utimaco", "yubihsm",
    ]
    .iter()
    .any(|w| p.contains(w))
}

fn fed_002(ctx: &Ctx) -> CheckResult {
    per_server(
        ctx,
        "AD FS",
        |s| s.adfs().is_some(),
        |s| {
            let mut why = Vec::new();
            for c in s.adfs().map(|a| a.a("certificates")).unwrap_or_default().iter().filter(|c| c.s("type") == Some("Token-Signing")) {
                let age = days_ago(ctx, c.s("not_before").and_then(time::parse_iso));
                if age.is_some_and(|d| d > CERT_DAYS) {
                    why.push(format!("token-signing certificate {} in use for {} days", c.s("thumbprint").unwrap_or_default(), age.unwrap_or_default()));
                }
                if !hardware(c.s("provider").unwrap_or_default()) {
                    why.push(format!(
                        "token-signing key {} is not in an HSM ({}): server admins and the DKM key in AD can extract it (Golden SAML)",
                        c.s("thumbprint").unwrap_or_default(),
                        c.s("provider").filter(|p| !p.is_empty()).unwrap_or("software or AD FS-managed")
                    ));
                }
            }
            why
        },
        check("HY-FED-002").expected(format!("Token-signing certificates are younger than {CERT_DAYS} days and their keys are in an HSM")),
    )
}

fn fed_003(ctx: &Ctx) -> CheckResult {
    per_server(
        ctx,
        "AD FS",
        |s| s.adfs().is_some(),
        |s| {
            let account = s.service("adfssrv", "account").unwrap_or_default();
            let sam = account.rsplit('\\').next().unwrap_or(account);
            let mut why = Vec::new();
            if !sam.ends_with('$') {
                why.push(format!(
                    "AD FS runs as {account}, not a group managed service account"
                ));
            }
            let m = s.model;
            if let Some(i) = m
                .nodes
                .iter()
                .position(|n| n.name.eq_ignore_ascii_case(sam))
            {
                if let Some(groups) = m.privileged_users().get(&i) {
                    let names: Vec<&str> =
                        groups.iter().map(|&g| m.nodes[g].name.as_str()).collect();
                    why.push(format!(
                        "its service account {sam} is in {}",
                        names.join(", ")
                    ));
                }
            }
            why
        },
        check("HY-FED-003").expected("The AD FS service runs as a gMSA with no admin rights in AD"),
    )
}

fn fed_004(ctx: &Ctx) -> CheckResult {
    per_server(
        ctx,
        "AD FS",
        |s| s.adfs().is_some(),
        |s| {
            let p = s.adfs().and_then(|a| a.get("properties"));
            let on = p.and_then(|p| p.b("lockout_enabled")) == Some(true);
            let mode = p.and_then(|p| p.s("lockout_mode")).unwrap_or_default();
            if !on {
                vec!["Extranet lockout is off: password spraying through the proxy can lock out or guess AD accounts".to_string()]
            } else if !mode.contains("Enforce") && mode.contains("Smart") {
                vec![format!(
                    "Extranet smart lockout is in {mode} mode: it only logs"
                )]
            } else if !mode.contains("Smart") {
                vec!["Extranet lockout is on but not smart lockout: attackers can lock out real users from outside".to_string()]
            } else {
                Vec::new()
            }
        },
        check("HY-FED-004").expected("Extranet smart lockout is on, in enforce mode"),
    )
}

const RISKY_ENDPOINTS: [&str; 4] = [
    "/adfs/services/trust/2005/usernamemixed",
    "/adfs/services/trust/13/usernamemixed",
    "/adfs/services/trust/2005/windowstransport",
    "/adfs/services/trust/13/windowstransport",
];

fn fed_005(ctx: &Ctx) -> CheckResult {
    per_server(
        ctx,
        "AD FS",
        |s| s.adfs().is_some(),
        |s| {
            s.adfs()
                .map(|a| a.a("endpoints"))
                .unwrap_or_default()
                .iter()
                .filter(|e| e.b("proxy") == Some(true))
                .filter_map(|e| e.s("path"))
                .filter(|p| RISKY_ENDPOINTS.iter().any(|r| p.eq_ignore_ascii_case(r)))
                .map(|p| format!("{p} is published to the internet: it accepts passwords without MFA (legacy WS-Trust)"))
                .collect()
        },
        check("HY-FED-005").expected("Legacy WS-Trust username and Windows transport endpoints are not published through the proxy"),
    )
}

fn fed_007(ctx: &Ctx) -> CheckResult {
    let out = check("HY-FED-007").expected("Every federated domain trusts only certificates and issuers of the organization's own AD FS farms");
    let Some(t) = ctx.tenant else {
        return out
            .not_assessed("This check needs Microsoft Entra ID.")
            .done();
    };
    let feds = t.raw.list("federation");
    if feds.is_empty() {
        return out
            .found("No federated domain")
            .evidence("Read from", "Microsoft Graph")
            .done();
    }
    let all = servers(ctx);
    let farms: Vec<&Value> = all.iter().filter_map(|s| s.adfs()).collect();
    if farms.is_empty() {
        return out
            .not_assessed("No AD FS server was read, so the tenant's federation certificates cannot be compared with the farm's.")
            .done();
    }
    let certs: BTreeSet<String> = farms
        .iter()
        .flat_map(|a| a.a("certificates"))
        .filter(|c| c.s("type") == Some("Token-Signing"))
        .filter_map(|c| c.s("raw"))
        .map(|r| r.replace(['\r', '\n', ' '], ""))
        .collect();
    let issuers: BTreeSet<String> = farms
        .iter()
        .filter_map(|a| a.at(&["properties", "identifier"]).and_then(Value::as_str))
        .map(str::to_lowercase)
        .collect();
    let mut list = Vec::new();
    for f in feds {
        let domain = f.s("@dca.parent").unwrap_or("domain");
        for key in ["signingCertificate", "nextSigningCertificate"] {
            if let Some(c) = f.s(key).filter(|c| !c.is_empty()) {
                if !certs.contains(&c.replace(['\r', '\n', ' '], "")) {
                    list.push(t.object("domain", domain, None, format!("Trusts a {key} that is not a token-signing certificate of any AD FS server read: a possible federation backdoor")));
                }
            }
        }
        if let Some(i) = f.s("issuerUri") {
            if !issuers.contains(&i.to_lowercase()) {
                list.push(t.object(
                    "domain",
                    domain,
                    None,
                    format!("Trusts issuer {i}, which is not an AD FS farm read"),
                ));
            }
        }
    }
    out.found(format!(
        "{}; {}",
        plural(feds.len(), "federated domain", "federated domains"),
        plural(list.len(), "mismatch", "mismatches")
    ))
    .affected(list, "domains")
    .evidence("Read from", format!("Microsoft Graph; {}", read_from(ctx)))
    .done()
}

/// auditpol's Application Generated subcategory.
const APPLICATION_GENERATED: &str = "0CCE9222-69AE-11D9-BED3-505054503030";

fn fed_009(ctx: &Ctx) -> CheckResult {
    per_server(
        ctx,
        "AD FS",
        |s| s.adfs().is_some(),
        |s| {
            let mut why = Vec::new();
            let p = s.adfs().and_then(|a| a.get("properties"));
            let level = p.and_then(|p| p.s("audit_level")).unwrap_or("None");
            if level.eq_ignore_ascii_case("None") {
                why.push("AD FS auditing is off (AuditLevel None)".to_string());
            }
            let logs: Vec<&str> = p.map(|p| p.strs("log_level")).unwrap_or_default();
            for need in ["SuccessAudits", "FailureAudits"] {
                if !logs.contains(&need) {
                    why.push(format!("LogLevel lacks {need}"));
                }
            }
            if let Some(setting) = s
                .endpoint
                .and_then(|e| e.part("audit"))
                .and_then(|a| a.get(APPLICATION_GENERATED))
                .and_then(Value::as_str)
            {
                if !(setting.contains("Success") && setting.contains("Failure")) {
                    why.push(format!(
                        "Audit Application Generated is \"{setting}\", not Success and Failure"
                    ));
                }
            }
            why
        },
        check("HY-FED-009").expected(
            "AD FS audits successes and failures, and Windows records them (Application Generated)",
        ),
    )
}

fn fed_010(ctx: &Ctx) -> CheckResult {
    per_server(
        ctx,
        "AD FS",
        |s| s.adfs().is_some(),
        |s| {
            let mut why = Vec::new();
            for rp in s
                .adfs()
                .map(|a| a.a("relying_parties"))
                .unwrap_or_default()
                .iter()
                .filter(|r| r.b("enabled") != Some(false))
            {
                let name = rp.s("name").unwrap_or("relying party");
                let auth = rp.s("authorization").unwrap_or_default().to_lowercase();
                let policy = rp.s("access_policy").unwrap_or_default();
                if policy.is_empty()
                    && (auth.is_empty()
                        || auth.contains("authorization/claims/permit")
                            && auth.contains("\"true\"")
                            && !auth.contains("c:["))
                {
                    why.push(format!(
                        "{name}: permits every authenticated user, with no access control policy"
                    ));
                }
                if rp
                    .s("signature")
                    .is_some_and(|a| a.to_lowercase().contains("sha1"))
                {
                    why.push(format!("{name}: signs tokens with SHA-1"));
                }
            }
            why
        },
        check("HY-FED-010")
            .expected("Relying party trusts restrict who gets a token and sign with SHA-256"),
    )
}

// ---------- Sync servers and agents ----------

fn version(v: &str) -> Option<(u32, u32)> {
    let mut p = v.split('.');
    Some((
        p.next()?.trim().parse().ok()?,
        p.next()?.trim().parse().ok()?,
    ))
}

fn sync_001(ctx: &Ctx) -> CheckResult {
    per_server(
        ctx,
        "Entra Connect Sync",
        |s| s.sync().is_some(),
        |s| {
            let v = s.service("ADSync", "version").unwrap_or_default();
            match version(v) {
                Some(x) if x >= MIN_SYNC => Vec::new(),
                Some((1, _)) => vec![format!(
                    "Entra Connect Sync {v}: version 1 is retired and no longer syncs reliably"
                )],
                Some(_) => vec![format!(
                    "Entra Connect Sync {v} is older than {}.{}",
                    MIN_SYNC.0, MIN_SYNC.1
                )],
                None => vec!["The Entra Connect Sync version was not returned".to_string()],
            }
        },
        check("HY-SYNC-001").expected(format!(
            "Entra Connect Sync is version {}.{} or later",
            MIN_SYNC.0, MIN_SYNC.1
        )),
    )
}

fn sync_003(ctx: &Ctx) -> CheckResult {
    per_server(
        ctx,
        "Entra Connect Sync",
        |s| s.sync().is_some(),
        |s| {
            let m = s.model;
            let mut why = Vec::new();
            if !s.tier0() {
                why.push(
                    "the sync server is not treated as Tier 0 in AD (not in a Tier 0 OU or group)"
                        .to_string(),
                );
            }
            let not_tier0 = |sid: &str| {
                m.by_sid(sid).is_some_and(|i| !m.nodes[i].tier0) && !m.is_default_admin(sid)
            };
            if let Some(admins) = s
                .endpoint
                .and_then(|e| e.part("local_admins"))
                .and_then(Value::as_array)
            {
                for a in admins {
                    if a.s("sid").is_some_and(not_tier0) {
                        why.push(format!(
                            "{} is a local administrator but not Tier 0",
                            a.s("name").unwrap_or_default()
                        ));
                    }
                }
            }
            if let Some(sessions) = s
                .endpoint
                .and_then(|e| e.part("sessions"))
                .and_then(Value::as_array)
            {
                for who in sessions.iter().filter_map(Value::as_str) {
                    let sam = who.rsplit('\\').next().unwrap_or(who);
                    if m.nodes
                        .iter()
                        .any(|n| n.name.eq_ignore_ascii_case(sam) && !n.tier0)
                    {
                        why.push(format!(
                            "{who} is signed in interactively but is not Tier 0"
                        ));
                    }
                }
            }
            why
        },
        check("HY-SYNC-003").expected(
            "The sync server is Tier 0: only Tier 0 admins are local admins or sign in to it",
        ),
    )
}

fn sync_010(ctx: &Ctx) -> CheckResult {
    per_server(
        ctx,
        "Entra Connect Sync",
        |s| s.sync().is_some(),
        |s| {
            let mut why = Vec::new();
            let features = s.sync().and_then(|x| x.get("features")).and_then(Value::as_object);
            for (k, v) in features.into_iter().flatten() {
                let l = k.to_lowercase();
                if v.as_bool() == Some(true) && l.contains("writeback") && !l.contains("password") {
                    let reason = if l.contains("group") {
                        format!("{k} is on: cloud group owners and admins decide memberships of groups written into AD")
                    } else if l.contains("device") {
                        format!("{k} is on: devices registered in Entra ID are written into AD")
                    } else {
                        format!("{k} is on")
                    };
                    why.push(reason);
                }
            }
            why
        },
        check("HY-SYNC-010").expected("Group and device writeback are off, or scoped to OUs that no Tier 0 permission depends on"),
    )
}

fn sync_012(ctx: &Ctx) -> CheckResult {
    let all = servers(ctx);
    let syncs: Vec<&Server> = all.iter().filter(|s| s.sync().is_some()).collect();
    let out = check("HY-SYNC-012").expected(
        "Exactly one active sync server, with any staging server on the same version and features",
    );
    if syncs.is_empty() {
        return out.not_assessed("No Entra Connect Sync server was read: add the sync servers to the endpoint targets.").done();
    }
    let active: Vec<&&Server> = syncs
        .iter()
        .filter(|s| s.sync().and_then(|x| x.b("staging")) != Some(true))
        .collect();
    let mut list = Vec::new();
    if active.len() > 1 {
        for s in &active {
            list.push(s.item("More than one sync server is active (not in staging mode)"));
        }
    }
    if active.is_empty() {
        for s in &syncs {
            list.push(s.item("Every sync server is in staging mode: nothing is synchronized"));
        }
    }
    let versions: BTreeSet<&str> = syncs
        .iter()
        .filter_map(|s| s.service("ADSync", "version"))
        .collect();
    let features: BTreeSet<String> = syncs
        .iter()
        .map(|s| {
            s.sync()
                .and_then(|x| x.get("features"))
                .map(Value::to_string)
                .unwrap_or_default()
        })
        .collect();
    if syncs.len() > 1 && versions.len() > 1 {
        list.extend(syncs.iter().map(|s| {
            s.item(format!(
                "Version {} differs from the other sync servers",
                s.service("ADSync", "version").unwrap_or("unknown")
            ))
        }));
    }
    if syncs.len() > 1 && features.len() > 1 {
        list.extend(syncs.iter().map(|s| {
            s.item("Its features (hash sync, writeback...) differ from the other sync servers")
        }));
    }
    out.found(format!(
        "{}; {} active",
        plural(syncs.len(), "sync server", "sync servers"),
        active.len()
    ))
    .affected(list, "servers")
    .evidence("Read from", read_from(ctx))
    .done()
}

fn agents(
    ctx: &Ctx,
    id: &str,
    service: &str,
    what: &str,
    expected: &str,
    eval: impl Fn(&Server) -> Vec<String>,
) -> CheckResult {
    per_server(
        ctx,
        what,
        |s| s.has(service),
        eval,
        check(id).expected(expected),
    )
}

fn sync_013(ctx: &Ctx) -> CheckResult {
    agents(
        ctx,
        "HY-SYNC-013",
        "AADConnectProvisioningAgent",
        "Cloud Sync agent",
        "Cloud Sync agents run as a gMSA on Tier 0 servers",
        |s| {
            let account = s
                .service("AADConnectProvisioningAgent", "account")
                .unwrap_or_default();
            let mut why = Vec::new();
            if !account.ends_with('$') {
                why.push(format!("Cloud Sync agent runs as {account}, not a gMSA"));
            }
            if !s.tier0() {
                why.push(format!(
                    "Cloud Sync agent {} on a server that is not Tier 0",
                    s.service("AADConnectProvisioningAgent", "version")
                        .unwrap_or_default()
                ));
            }
            why
        },
    )
}

fn sync_015(ctx: &Ctx) -> CheckResult {
    agents(
        ctx,
        "HY-SYNC-015",
        "AzureADConnectAuthenticationAgent",
        "pass-through authentication agent",
        "Pass-through authentication agents run only on Tier 0 servers, at least three of them",
        |s| {
            if s.tier0() {
                Vec::new()
            } else {
                vec![format!(
                    "Pass-through agent {} on a server that is not Tier 0: it sees every cloud sign-in password",
                    s.service("AzureADConnectAuthenticationAgent", "version").unwrap_or_default()
                )]
            }
        },
    )
}

pub static RULES: &[Rule] = &[
    Rule {
        id: "HY-FED-001",
        ad: &["computers"],
        entra: &[],
        run: fed_001,
    },
    Rule {
        id: "HY-FED-002",
        ad: &["computers"],
        entra: &[],
        run: fed_002,
    },
    Rule {
        id: "HY-FED-003",
        ad: &["users", "groups"],
        entra: &[],
        run: fed_003,
    },
    Rule {
        id: "HY-FED-004",
        ad: &["computers"],
        entra: &[],
        run: fed_004,
    },
    Rule {
        id: "HY-FED-005",
        ad: &["computers"],
        entra: &[],
        run: fed_005,
    },
    Rule {
        id: "HY-FED-007",
        ad: &["computers"],
        entra: &["domains"],
        run: fed_007,
    },
    Rule {
        id: "HY-FED-009",
        ad: &["computers"],
        entra: &[],
        run: fed_009,
    },
    Rule {
        id: "HY-FED-010",
        ad: &["computers"],
        entra: &[],
        run: fed_010,
    },
    Rule {
        id: "HY-SYNC-001",
        ad: &["computers"],
        entra: &[],
        run: sync_001,
    },
    Rule {
        id: "HY-SYNC-003",
        ad: &["computers", "groups"],
        entra: &[],
        run: sync_003,
    },
    Rule {
        id: "HY-SYNC-010",
        ad: &["computers"],
        entra: &[],
        run: sync_010,
    },
    Rule {
        id: "HY-SYNC-012",
        ad: &["computers"],
        entra: &[],
        run: sync_012,
    },
    Rule {
        id: "HY-SYNC-013",
        ad: &["computers"],
        entra: &[],
        run: sync_013,
    },
    Rule {
        id: "HY-SYNC-015",
        ad: &["computers"],
        entra: &[],
        run: sync_015,
    },
];
