//! Entra monitoring read through Azure Resource Manager: where Entra sends
//! its logs, log alert rules for break-glass accounts, and VM command
//! execution in the activity log.

use serde_json::Value;

use super::model::{Tenant, J};
use super::rules::tenant_item;
use super::rules_logs::when;
use super::rules_mon::break_glass_accounts;
use super::Rule;
use crate::ad::rules::{check, plural};
use crate::results::{Affected, CheckResult};

/// Days logs should be kept outside Entra.
const RETENTION_DAYS: i64 = 90;
const ARM: &str = "Azure Resource Manager";

/// Where a diagnostic setting sends logs, as text.
fn destinations(p: &Value) -> Vec<&'static str> {
    let mut d = Vec::new();
    if p.s("workspaceId").is_some_and(|v| !v.is_empty()) {
        d.push("Log Analytics");
    }
    if p.s("eventHubAuthorizationRuleId")
        .is_some_and(|v| !v.is_empty())
    {
        d.push("Event Hub");
    }
    if p.s("storageAccountId").is_some_and(|v| !v.is_empty()) {
        d.push("storage account");
    }
    d
}

fn enabled_logs(p: &Value) -> Vec<&str> {
    p.a("logs")
        .iter()
        .filter(|l| l.b("enabled") == Some(true))
        .filter_map(|l| l.s("category"))
        .collect()
}

/// Settings that export both sign-in and audit logs somewhere.
fn exporting<'a>(t: &Tenant<'a>) -> Vec<&'a Value> {
    t.raw
        .list("aaddiagnostics")
        .iter()
        .filter(|s| {
            let Some(p) = s.o("properties") else {
                return false;
            };
            let logs = enabled_logs(p);
            !destinations(p).is_empty()
                && logs.contains(&"SignInLogs")
                && logs.contains(&"AuditLogs")
        })
        .collect()
}

fn mon_001(t: &Tenant) -> CheckResult {
    let all = t.raw.list("aaddiagnostics");
    let good = exporting(t);
    let rows: Vec<String> = all
        .iter()
        .map(|s| {
            let p = s.o("properties");
            format!(
                "{}: {} to {}",
                s.s("name").unwrap_or("setting"),
                p.map(enabled_logs).unwrap_or_default().join(", "),
                p.map(destinations).unwrap_or_default().join(", ")
            )
        })
        .collect();
    let list = if good.is_empty() {
        vec![tenant_item(t, "Sign-in and audit logs are not exported: they are kept only as long as Entra keeps them and are not in the SIEM")]
    } else {
        Vec::new()
    };
    check("EN-MON-001")
        .expected("A diagnostic setting sends Entra sign-in and audit logs to Log Analytics, a SIEM or storage")
        .found(format!("{}; {} export sign-in and audit logs", plural(all.len(), "diagnostic setting", "diagnostic settings"), good.len()))
        .raw(rows.join("\n"))
        .affected(list, "tenant")
        .evidence("Read from", ARM)
        .done()
}

fn mon_002(t: &Tenant) -> CheckResult {
    let good = exporting(t);
    let mut list = Vec::new();
    if good.is_empty() {
        list.push(tenant_item(
            t,
            "Logs are only in Entra, which keeps them 30 days (7 without Entra ID P1)",
        ));
    }
    for s in &good {
        let Some(p) = s.o("properties") else { continue };
        // A storage account retention policy of 0 days means keep forever.
        let only_storage = destinations(p) == ["storage account"];
        let short = p
            .a("logs")
            .iter()
            .filter(|l| l.b("enabled") == Some(true))
            .filter_map(|l| l.o("retentionPolicy"))
            .filter(|r| r.b("enabled") == Some(true))
            .filter_map(|r| r.n("days"))
            .find(|d| *d > 0 && *d < RETENTION_DAYS);
        if let (true, Some(d)) = (only_storage, short) {
            list.push(t.object(
                "setting",
                s.s("name").unwrap_or("setting"),
                None,
                format!("Keeps logs {d} days in storage, under {RETENTION_DAYS}"),
            ));
        }
    }
    check("EN-MON-002")
        .expected(format!(
            "Entra logs are kept at least {RETENTION_DAYS} days outside Entra"
        ))
        .found(if list.is_empty() {
            format!("Exported by {}", plural(good.len(), "setting", "settings"))
        } else {
            plural(list.len(), "retention gap", "retention gaps")
        })
        .affected(list, "settings")
        .evidence("Read from", ARM)
        .evidence(
            "Note",
            "Log Analytics workspace retention is set on the workspace and is not read",
        )
        .done()
}

fn mon_009(t: &Tenant) -> CheckResult {
    let glass = break_glass_accounts(t);
    let out = check("EN-MON-009")
        .expected("An enabled alert fires on every break-glass account sign-in")
        .evidence("Read from", format!("{ARM}: log alert rules"));
    if glass.is_empty() {
        return out
            .found("No account is named or described as break-glass or emergency")
            .affected(
                vec![tenant_item(t, "No break-glass account found to check")],
                "tenant",
            )
            .done();
    }
    let queries: Vec<(String, &str)> = t
        .raw
        .list("azalertrules")
        .iter()
        .filter_map(|r| {
            let p = r.o("properties")?;
            if p.b("enabled") == Some(false) {
                return None;
            }
            let q: String = p
                .at(&["criteria", "allOf"])
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|c| c.s("query"))
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .unwrap_or_default()
                .to_ascii_lowercase();
            Some((q, r.s("name").unwrap_or("rule")))
        })
        .collect();
    let list: Vec<Affected> = glass
        .iter()
        .filter(|(id, upn)| {
            !queries.iter().any(|(q, _)| {
                q.contains(&upn.to_ascii_lowercase()) || q.contains(&id.to_ascii_lowercase())
            })
        })
        .map(|(id, _)| t.affected(id, "No enabled log alert rule mentions this account"))
        .collect();
    out.found(format!(
        "{}; {} without an alert",
        plural(glass.len(), "break-glass account", "break-glass accounts"),
        list.len()
    ))
    .affected(list, "accounts")
    .done()
}

const VM_EXECUTION: [&str; 3] = [
    "microsoft.compute/virtualmachines/runcommand/action",
    "microsoft.compute/virtualmachines/runcommands/write",
    "microsoft.compute/virtualmachines/extensions/write",
];

fn hunt_017(t: &Tenant) -> CheckResult {
    let mut events: Vec<&Value> = t
        .raw
        .list("azactivity")
        .iter()
        .filter(|e| {
            let op = e
                .at(&["operationName", "value"])
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_ascii_lowercase();
            VM_EXECUTION.contains(&op.as_str())
                && e.at(&["status", "value"])
                    .and_then(Value::as_str)
                    .is_none_or(|s| s != "Failed")
        })
        .collect();
    events.sort_by(|a, b| b.s("eventTimestamp").cmp(&a.s("eventTimestamp")));
    // One entry per operation; the activity log has a start and an end event.
    let mut seen = std::collections::BTreeSet::new();
    let list: Vec<Affected> = events
        .into_iter()
        .filter(|e| {
            seen.insert((
                e.s("resourceId"),
                e.at(&["operationName", "value"]).and_then(Value::as_str),
                e.s("eventTimestamp").map(|s| s.get(..16).unwrap_or(s)),
            ))
        })
        .map(|e| {
            let res = e.s("resourceId").unwrap_or_default();
            let vm = res
                .split('/')
                .collect::<Vec<_>>()
                .windows(2)
                .find(|w| w[0].eq_ignore_ascii_case("virtualMachines"))
                .map(|w| w[1])
                .unwrap_or(res);
            let what = if res.to_ascii_lowercase().contains("/extensions/") {
                "Extension installed or changed"
            } else {
                "Run Command executed"
            };
            t.object(
                "vm",
                vm,
                Some(when(e.s("eventTimestamp"))),
                format!("{what} by {}", e.s("caller").unwrap_or("an unknown caller")),
            )
            .seen_at(e.s("eventTimestamp"))
        })
        .collect();
    check("HUNT-EN-017")
        .expected("Commands and extensions run on VMs, above all domain controllers, are all known")
        .found(
            plural(
                list.len(),
                "VM command or extension change",
                "VM commands or extension changes",
            ) + " in the last 30 days",
        )
        .affected(list, "operations")
        .evidence("Read from", format!("{ARM}: activity log, last 30 days"))
        .done()
}

fn mon_011(t: &Tenant) -> CheckResult {
    let services = t.raw.list("azconnecthealth");
    let synced = t
        .raw
        .first("organization")
        .and_then(|o| o.b("onPremisesSyncEnabled"))
        == Some(true);
    let mut list: Vec<Affected> = services
        .iter()
        .filter(|s| {
            s.s("health")
                .is_some_and(|h| !h.eq_ignore_ascii_case("Healthy"))
        })
        .map(|s| {
            t.object(
                "service",
                s.s("displayName")
                    .or(s.s("serviceName"))
                    .unwrap_or("Connect Health service"),
                s.s("serviceType").map(str::to_string),
                format!("Health: {}", s.s("health").unwrap_or("unknown")),
            )
        })
        .collect();
    if synced
        && !services.iter().any(|s| {
            s.s("serviceType")
                .is_some_and(|k| k.eq_ignore_ascii_case("AadSyncService"))
        })
    {
        list.push(tenant_item(
            t,
            "Directory sync is on but no Entra Connect Health agent reports for the sync service",
        ));
    }
    check("EN-MON-011")
        .expected("Entra Connect Health agents report for sync and federation servers, and all are healthy")
        .found(format!("{} registered; {}", plural(services.len(), "service", "services"), plural(list.len(), "finding", "findings")))
        .affected(list, "services")
        .evidence("Read from", format!("{ARM}: Microsoft.ADHybridHealthService"))
        .done()
}

/// Callers that first read a vault's secrets within this many days of the
/// end of the 30-day window are new.
const NEW_CALLER_DAYS: i64 = 7;

fn hunt_018(t: &Tenant) -> CheckResult {
    // Rows of each workspace's answer: Resource, Caller, Reads, First, Last.
    let mut rows: Vec<(String, String, i64, i64)> = Vec::new();
    for answer in t.raw.list("kvreads") {
        for table in answer.a("tables") {
            let cols: Vec<&str> = table
                .a("columns")
                .iter()
                .filter_map(|c| c.s("name"))
                .collect();
            let at = |n: &str| cols.iter().position(|c| *c == n);
            let (Some(r), Some(c), Some(n), Some(f)) =
                (at("Resource"), at("Caller"), at("Reads"), at("First"))
            else {
                continue;
            };
            for row in table.a("rows") {
                let get = |i: usize| row.get(i);
                let first = get(f)
                    .and_then(Value::as_str)
                    .and_then(crate::time::parse_iso);
                rows.push((
                    get(r)
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    get(c)
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    get(n).and_then(Value::as_i64).unwrap_or(0),
                    first.unwrap_or(0),
                ));
            }
        }
    }
    let start = t.now - 30 * crate::time::DAY;
    let list: Vec<Affected> = rows
        .iter()
        .filter(|(_, _, _, first)| *first > 0 && *first >= start + (30 - NEW_CALLER_DAYS) * crate::time::DAY)
        .map(|(vault, caller, reads, first)| {
            let who = if t.principal(caller).is_some() { t.name_of(caller) } else { caller.clone() };
            t.object(
                "caller",
                who,
                Some(vault.to_lowercase()),
                format!("Started reading secrets on {} ({} reads): a caller not seen in the weeks before", &crate::time::iso(*first)[..10], reads),
            )
        })
        .collect();
    let callers: std::collections::BTreeSet<&str> = rows.iter().map(|r| r.1.as_str()).collect();
    check("HUNT-EN-018")
        .expected(format!("No new identity started reading Key Vault secrets in the last {NEW_CALLER_DAYS} days unannounced"))
        .found(format!("{} reading secrets; {} new", plural(callers.len(), "caller", "callers"), list.len()))
        .affected(list, "callers")
        .evidence("Read from", "Key Vault diagnostic logs (SecretGet) in Log Analytics, last 30 days")
        .evidence("Note", "Only vaults that send diagnostics to a Log Analytics workspace can be searched")
        .done()
}

pub static RULES: &[Rule] = &[
    Rule {
        id: "HUNT-EN-018",
        needs: &["azvaults", "kvreads"],
        run: hunt_018,
    },
    Rule {
        id: "EN-MON-011",
        needs: &["azconnecthealth", "organization"],
        run: mon_011,
    },
    Rule {
        id: "EN-MON-001",
        needs: &["aaddiagnostics"],
        run: mon_001,
    },
    Rule {
        id: "EN-MON-002",
        needs: &["aaddiagnostics"],
        run: mon_002,
    },
    Rule {
        id: "EN-MON-009",
        needs: &["users", "azalertrules"],
        run: mon_009,
    },
    Rule {
        id: "HUNT-EN-017",
        needs: &["azactivity"],
        run: hunt_017,
    },
];
