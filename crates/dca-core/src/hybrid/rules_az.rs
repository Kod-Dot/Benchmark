//! Domain controllers and Tier 0 servers that live in Azure: as virtual
//! machines or as Azure Arc-connected servers. Matched to Active Directory
//! by host name.

use std::collections::BTreeMap;

use serde_json::Value;

use super::rules::tier0_hosts;
use super::{Ctx, Rule};
use crate::ad::model::Model;
use crate::ad::rules::{check, item, plural};
use crate::entra::model::{Tenant, J};
use crate::entra::rules_az::{
    assignments, principal_item, role_label, scope_text, CONTRIBUTOR, OWNER, USER_ACCESS_ADMIN,
};
use crate::entra::rules_az2::{covers, tier0_vaults};
use crate::results::{Affected, CheckResult};

const VM_CONTRIBUTOR: &str = "9980e02c-c2be-4d73-94e8-173b1dc7cf3c";
const VM_ADMIN_LOGIN: &str = "1c0163c0-47e6-4577-8991-ea5c82e286e4";
const DISK_SNAPSHOT_CONTRIBUTOR: &str = "7efff54f-a5b4-42b5-a1c5-5411624893ce";
const ARC_RESOURCE_ADMIN: &str = "cd570a14-e51a-42ad-bac8-bafd67325302";
const HYBRID_SERVER_ADMIN: &str = "48b40c6e-82e0-4eb3-90d5-19e40f49b624";

fn tenant<'s, 'r>(ctx: &Ctx<'s, 'r>) -> &'s Tenant<'r> {
    ctx.tenant
        .expect("rules that read Entra data only run with a tenant")
}

fn read_from(ctx: &Ctx) -> String {
    let mut parts: Vec<String> = ctx
        .domains
        .iter()
        .map(|m| format!("LDAP on {}", m.raw.info.server))
        .collect();
    if let Some(t) = ctx.tenant {
        parts.push(format!(
            "Azure Resource Manager, signed in as {}",
            t.raw.info.account
        ));
    }
    parts.join("; ")
}

/// Host names a VM or Arc machine is known by, lower case.
fn host_names(r: &Value) -> Vec<String> {
    let mut names = vec![r.s("name").unwrap_or_default().to_lowercase()];
    for key in [
        ["properties", "osProfile"],
        ["properties", "machineFqdn"],
        ["properties", "dnsFqdn"],
    ] {
        let v = r.at(&key);
        let text = match v {
            Some(Value::Object(_)) => v.and_then(|o| o.s("computerName")),
            Some(Value::String(s)) => Some(s.as_str()),
            _ => None,
        };
        if let Some(t) = text {
            names.push(t.split('.').next().unwrap_or(t).to_lowercase());
        }
    }
    names
}

/// Azure resources of an area that are domain controllers or Tier 0
/// servers, with the AD computer each one is.
fn tier0_resources<'s, 'r>(
    ctx: &Ctx<'s, 'r>,
    area: &str,
) -> Vec<(&'r Value, &'s Model<'r>, usize)> {
    let hosts = tier0_hosts(ctx);
    tenant(ctx)
        .raw
        .list(area)
        .iter()
        .filter_map(|r| {
            host_names(r)
                .iter()
                .find_map(|n| hosts.get(n))
                .map(|(m, i)| (r, *m, *i))
        })
        .collect()
}

fn what(m: &Model, i: usize) -> &'static str {
    if m.nodes[i].is_dc() {
        "domain controller"
    } else {
        "Tier 0 server"
    }
}

fn control_check(
    ctx: &Ctx,
    id: &str,
    area: &str,
    roles: &[&str],
    expected: &str,
    noun: &str,
) -> CheckResult {
    let t = tenant(ctx);
    let all = assignments(t, "azroleassignments");
    let found = tier0_resources(ctx, area);
    let mut list = Vec::new();
    for (r, m, i) in &found {
        let rid = r.s("id").unwrap_or_default();
        for a in all
            .iter()
            .filter(|a| roles.contains(&a.role.as_str()) && covers(a.scope, rid))
        {
            list.push(principal_item(
                t,
                a,
                format!(
                    "{} on {} ({} {}), through {}",
                    role_label(t, &a.role),
                    r.s("name").unwrap_or_default(),
                    what(m, *i),
                    m.nodes[*i].name.trim_end_matches('$'),
                    scope_text(t, a.scope)
                ),
            ));
        }
    }
    check(id)
        .expected(expected)
        .found(format!(
            "{} {noun}; {}",
            found.len(),
            plural(list.len(), "assignment gives", "assignments give") + " control of them"
        ))
        .affected(list, "assignments")
        .evidence("Read from", read_from(ctx))
        .done()
}

fn rbac_020(ctx: &Ctx) -> CheckResult {
    control_check(
        ctx,
        "AZ-RBAC-020",
        "azvms",
        &[OWNER, CONTRIBUTOR, USER_ACCESS_ADMIN, VM_CONTRIBUTOR, VM_ADMIN_LOGIN, DISK_SNAPSHOT_CONTRIBUTOR],
        "Only Tier 0 admins can run commands on, sign in to or snapshot the disks of domain controller VMs",
        "Tier 0 VMs in Azure",
    )
}

fn rbac_021(ctx: &Ctx) -> CheckResult {
    control_check(
        ctx,
        "AZ-RBAC-021",
        "azarc",
        &[
            OWNER,
            CONTRIBUTOR,
            USER_ACCESS_ADMIN,
            ARC_RESOURCE_ADMIN,
            HYBRID_SERVER_ADMIN,
        ],
        "Only Tier 0 admins can install extensions or run commands on Arc-connected Tier 0 servers",
        "Tier 0 servers connected to Azure Arc",
    )
}

fn path_008(ctx: &Ctx) -> CheckResult {
    let list: Vec<Affected> = tier0_resources(ctx, "azarc")
        .into_iter()
        .map(|(r, m, i)| {
            item(
                m,
                i,
                format!(
                    "Azure Arc agent {} ({}): anyone with extension rights on {} runs code as SYSTEM here",
                    r.at(&["properties", "agentVersion"]).and_then(Value::as_str).unwrap_or("of unknown version"),
                    r.at(&["properties", "status"]).and_then(Value::as_str).unwrap_or("status unknown"),
                    r.s("name").unwrap_or_default()
                ),
            )
        })
        .collect();
    check("HY-PATH-008")
        .expected("No cloud management agent runs on domain controllers or Tier 0 servers, or its management is Tier 0")
        .found(plural(list.len(), "Tier 0 computer runs", "Tier 0 computers run") + " the Azure Arc agent")
        .affected(list, "computers")
        .evidence("Read from", read_from(ctx))
        .done()
}

fn rbac_022(ctx: &Ctx) -> CheckResult {
    let t = tenant(ctx);
    let jit: Vec<String> = t
        .raw
        .list("azjit")
        .iter()
        .flat_map(|p| {
            p.at(&["properties", "virtualMachines"])
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
        })
        .filter_map(|v| v.s("id").map(str::to_lowercase))
        .collect();
    let bastion_subs: Vec<&str> = t
        .raw
        .list("azbastion")
        .iter()
        .filter_map(|b| b.s("@dca.parent"))
        .collect();
    let found = tier0_resources(ctx, "azvms");
    let list: Vec<Affected> = found
        .iter()
        .filter(|(r, _, _)| {
            let id = r.s("id").unwrap_or_default().to_lowercase();
            !jit.contains(&id)
                && !r
                    .s("@dca.parent")
                    .is_some_and(|s| bastion_subs.contains(&s))
        })
        .map(|(r, m, i)| {
            item(
                m,
                *i,
                format!(
                    "VM {} is reached neither through Bastion nor just-in-time access",
                    r.s("name").unwrap_or_default()
                ),
            )
        })
        .collect();
    check("AZ-RBAC-022")
        .expected("Tier 0 VMs are reached only through Azure Bastion or just-in-time VM access")
        .found(format!(
            "{} Tier 0 VMs; {} without Bastion or JIT",
            found.len(),
            list.len()
        ))
        .affected(list, "computers")
        .evidence("Read from", read_from(ctx))
        .done()
}

/// The lock that covers a resource, if any: its own, its resource group's
/// or its subscription's.
fn locked(locks: &[&Value], resource: &str) -> bool {
    locks.iter().any(|l| {
        let id = l.s("id").unwrap_or_default();
        let scope = id
            .split("/providers/Microsoft.Authorization/locks/")
            .next()
            .unwrap_or_default();
        let scope = if scope.len() == id.len() { "" } else { scope };
        !scope.is_empty() && covers(scope, resource)
    })
}

fn rbac_010(ctx: &Ctx) -> CheckResult {
    let t = tenant(ctx);
    let locks: Vec<&Value> = t
        .raw
        .list("azlocks")
        .iter()
        .filter(|l| {
            l.at(&["properties", "level"])
                .and_then(Value::as_str)
                .is_some_and(|x| x == "CanNotDelete" || x == "ReadOnly")
        })
        .collect();
    let mut critical: BTreeMap<String, String> = BTreeMap::new();
    for (r, m, i) in tier0_resources(ctx, "azvms") {
        critical.insert(
            r.s("id").unwrap_or_default().to_string(),
            format!(
                "VM of {} {}",
                what(m, i),
                m.nodes[i].name.trim_end_matches('$')
            ),
        );
    }
    for (id, (v, _)) in tier0_vaults(t) {
        critical.insert(
            id,
            format!(
                "Key Vault {} holding Tier 0 material",
                v.s("name").unwrap_or_default()
            ),
        );
    }
    let list: Vec<Affected> = critical
        .iter()
        .filter(|(id, _)| !locked(&locks, id))
        .map(|(id, desc)| {
            t.object(
                "resource",
                id.rsplit('/').next().unwrap_or(id),
                Some(desc.clone()),
                "No delete lock: one mistaken or malicious delete removes it",
            )
        })
        .collect();
    check("AZ-RBAC-010")
        .expected("Identity infrastructure in Azure has a delete or read-only lock")
        .found(format!(
            "{} critical resources; {} without a lock",
            critical.len(),
            list.len()
        ))
        .affected(list, "resources")
        .evidence("Read from", read_from(ctx))
        .done()
}

pub static RULES: &[Rule] = &[
    Rule {
        id: "AZ-RBAC-010",
        ad: &["computers", "groups"],
        entra: &["azvms", "azlocks", "azvaults", "azkvsecrets", "azkvkeys"],
        run: rbac_010,
    },
    Rule {
        id: "AZ-RBAC-020",
        ad: &["computers", "groups"],
        entra: &["azvms", "azroleassignments"],
        run: rbac_020,
    },
    Rule {
        id: "AZ-RBAC-021",
        ad: &["computers", "groups"],
        entra: &["azarc", "azroleassignments"],
        run: rbac_021,
    },
    Rule {
        id: "AZ-RBAC-022",
        ad: &["computers", "groups"],
        entra: &["azvms", "azjit", "azbastion"],
        run: rbac_022,
    },
    Rule {
        id: "HY-PATH-008",
        ad: &["computers", "groups"],
        entra: &["azarc"],
        run: path_008,
    },
];
