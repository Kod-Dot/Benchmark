//! More Azure checks: Key Vault secret and key metadata, Tier 0 vaults,
//! classic administrators, automation and app identities with high
//! privileges, and credentials in runbooks, deployment scripts and
//! automation variables.

use std::collections::BTreeMap;

use serde_json::Value;

use super::model::{Tenant, J};
use super::rules_az::{
    arm, assignments, role_label, scope_text, sub_name, vault_item, Assignment, CONTRIBUTOR,
    KV_ADMIN, KV_SECRETS_OFFICER, KV_SECRETS_USER, OWNER, USER_ACCESS_ADMIN,
};
use super::Rule;
use crate::ad::rules::plural;
use crate::results::{Affected, CheckResult};
use crate::time;

/// Secrets and keys that expire within this many days are reported.
const EXPIRY_DAYS: i64 = 30;
/// Secrets not updated for this many days have not been rotated.
const ROTATION_DAYS: i64 = 365;
const MIN_RSA_BITS: i64 = 2048;

/// Names of secrets and keys that mark a vault as holding Tier 0 material.
const TIER0_WORDS: [&str; 14] = [
    "adfs",
    "tokensigning",
    "token-signing",
    "aadconnect",
    "entraconnect",
    "adsync",
    "msol",
    "krbtgt",
    "dsrm",
    "domainadmin",
    "enterpriseadmin",
    "rootca",
    "issuingca",
    "pki",
];

/// Roles that give control of a resource or of what it holds.
const CONTROL: [&str; 6] = [
    OWNER,
    CONTRIBUTOR,
    USER_ACCESS_ADMIN,
    KV_ADMIN,
    KV_SECRETS_OFFICER,
    KV_SECRETS_USER,
];
/// Roles that make a managed identity highly privileged.
const HIGH: [&str; 3] = [OWNER, CONTRIBUTOR, USER_ACCESS_ADMIN];

/// The vault an item was read from (its parent), by vault id.
fn vault_of<'a>(t: &Tenant<'a>, item: &Value) -> Option<&'a Value> {
    let parent = item.s("@dca.parent")?;
    t.raw
        .list("azvaults")
        .iter()
        .find(|v| v.s("id").is_some_and(|id| id.eq_ignore_ascii_case(parent)))
}

/// ARM Key Vault attributes are Unix times in seconds.
fn attr(v: &Value, key: &str) -> Option<i64> {
    v.at(&["properties", "attributes", key])
        .and_then(Value::as_i64)
}

fn enabled(v: &Value) -> bool {
    v.at(&["properties", "attributes", "enabled"])
        .and_then(Value::as_bool)
        != Some(false)
}

fn item_in_vault(t: &Tenant, v: &Value, what: &str, reason: String) -> Affected {
    let vault = vault_of(t, v)
        .and_then(|x| x.s("name"))
        .unwrap_or("(key vault)");
    t.object(
        what,
        format!("{vault}/{}", v.s("name").unwrap_or_default()),
        vault_of(t, v)
            .and_then(|x| x.s("@dca.parent"))
            .map(|s| sub_name(t, s)),
        reason,
    )
}

fn kv_005(t: &Tenant) -> CheckResult {
    let mut list = Vec::new();
    for (area, what) in [("azkvsecrets", "secret"), ("azkvkeys", "key")] {
        for v in t.raw.list(area).iter().filter(|v| enabled(v)) {
            match attr(v, "exp") {
                None => list.push(item_in_vault(
                    t,
                    v,
                    what,
                    format!("The {what} has no expiry date"),
                )),
                Some(exp) => {
                    let days = (exp - t.now) / time::DAY;
                    if days < 0 {
                        list.push(item_in_vault(
                            t,
                            v,
                            what,
                            format!("Expired {} days ago and still enabled", -days),
                        ));
                    } else if days <= EXPIRY_DAYS {
                        list.push(item_in_vault(t, v, what, format!("Expires in {days} days")));
                    }
                }
            }
        }
    }
    arm(t, "AZ-KV-005")
        .expected(format!("Secrets and keys have an expiry date and none expires within {EXPIRY_DAYS} days unnoticed"))
        .found(plural(list.len(), "secret or key", "secrets or keys") + " without expiry, expired or expiring")
        .affected(list, "items")
        .done()
}

fn kv_006(t: &Tenant) -> CheckResult {
    let list: Vec<Affected> = t
        .raw
        .list("azkvsecrets")
        .iter()
        .filter(|v| enabled(v))
        .filter_map(|v| {
            let updated = attr(v, "updated").or(attr(v, "created"))?;
            let days = (t.now - updated) / time::DAY;
            (days > ROTATION_DAYS)
                .then(|| item_in_vault(t, v, "secret", format!("Not rotated for {days} days")))
        })
        .collect();
    arm(t, "AZ-KV-006")
        .expected(format!(
            "Secrets are rotated at least every {ROTATION_DAYS} days"
        ))
        .found(plural(list.len(), "secret", "secrets") + " not rotated")
        .affected(list, "secrets")
        .done()
}

/// Vaults whose secrets or keys are named like Tier 0 material, with the
/// names that matched.
pub(crate) fn tier0_vaults<'a>(t: &Tenant<'a>) -> BTreeMap<String, (&'a Value, Vec<String>)> {
    let mut out: BTreeMap<String, (&Value, Vec<String>)> = BTreeMap::new();
    for v in t
        .raw
        .list("azkvsecrets")
        .iter()
        .chain(t.raw.list("azkvkeys"))
    {
        let name = v.s("name").unwrap_or_default();
        let l = name.to_ascii_lowercase();
        if !TIER0_WORDS.iter().any(|w| l.contains(w)) {
            continue;
        }
        let Some(vault) = vault_of(t, v) else {
            continue;
        };
        let id = vault.s("id").unwrap_or_default().to_ascii_lowercase();
        out.entry(id)
            .or_insert((vault, Vec::new()))
            .1
            .push(name.to_string());
    }
    out
}

fn kv_008(t: &Tenant) -> CheckResult {
    let tier0 = tier0_vaults(t);
    let mut list = Vec::new();
    for k in t.raw.list("azkvkeys").iter().filter(|v| enabled(v)) {
        let kty = k
            .at(&["properties", "kty"])
            .and_then(Value::as_str)
            .unwrap_or_default();
        let size = k.at(&["properties", "keySize"]).and_then(Value::as_i64);
        if kty.starts_with("RSA") && size.is_some_and(|s| s < MIN_RSA_BITS) {
            list.push(item_in_vault(
                t,
                k,
                "key",
                format!("{kty} key of {} bits", size.unwrap_or_default()),
            ));
        }
        let in_tier0 = k
            .s("@dca.parent")
            .is_some_and(|p| tier0.contains_key(&p.to_ascii_lowercase()));
        if in_tier0 && !kty.ends_with("-HSM") {
            list.push(item_in_vault(
                t,
                k,
                "key",
                format!("Software-protected {kty} key in a vault holding Tier 0 material"),
            ));
        }
    }
    arm(t, "AZ-KV-008")
        .expected(format!(
            "Keys are at least {MIN_RSA_BITS}-bit RSA (or EC), and critical keys are HSM-protected"
        ))
        .found(plural(list.len(), "weak key", "weak keys"))
        .affected(list, "keys")
        .done()
}

/// Whether an assignment's scope covers a resource id.
pub(crate) fn covers(scope: &str, resource: &str) -> bool {
    let s = scope.trim_end_matches('/').to_ascii_lowercase();
    let r = resource.to_ascii_lowercase();
    s.is_empty() || r == s || r.starts_with(&format!("{s}/"))
}

fn kv_009(t: &Tenant) -> CheckResult {
    let all = assignments(t, "azroleassignments");
    let mut list = Vec::new();
    for (id, (vault, names)) in tier0_vaults(t) {
        let holders: Vec<String> = all
            .iter()
            .filter(|a| CONTROL.contains(&a.role.as_str()) && covers(a.scope, &id))
            .map(|a| format!("{} ({})", t.name_of(a.principal), role_label(t, &a.role)))
            .collect();
        list.push(vault_item(
            t,
            vault,
            format!(
                "Holds {}; {} can reach it: {}",
                names.join(", "),
                plural(holders.len(), "principal", "principals"),
                if holders.is_empty() {
                    "none".to_string()
                } else {
                    holders.join(", ")
                }
            ),
        ));
    }
    arm(t, "AZ-KV-009")
        .expected("Vaults holding AD FS, Entra Connect or CA material are treated as Tier 0, with only Tier 0 admins able to reach them")
        .found(plural(list.len(), "vault holds", "vaults hold") + " Tier 0 material")
        .affected(list, "key vaults")
        .done()
}

fn rbac_007(t: &Tenant) -> CheckResult {
    let list: Vec<Affected> = t
        .raw
        .list("azclassicadmins")
        .iter()
        .filter_map(|a| {
            let role = a.at(&["properties", "role"]).and_then(Value::as_str)?;
            let who = a
                .at(&["properties", "emailAddress"])
                .and_then(Value::as_str)
                .unwrap_or("(unknown)");
            Some(t.object(
                "account",
                who,
                a.s("@dca.parent").map(|s| sub_name(t, s)),
                format!("Classic {role}: has Owner-equivalent rights outside Azure RBAC and PIM"),
            ))
        })
        .collect();
    arm(t, "AZ-RBAC-007")
        .expected("No classic administrators (co-administrators or service administrator) remain")
        .found(plural(
            list.len(),
            "classic administrator",
            "classic administrators",
        ))
        .affected(list, "accounts")
        .done()
}

/// Managed identity principal ids of a resource.
fn identities(r: &Value) -> Vec<&str> {
    let mut ids: Vec<&str> = r
        .at(&["identity", "principalId"])
        .and_then(Value::as_str)
        .into_iter()
        .collect();
    if let Some(u) = r
        .at(&["identity", "userAssignedIdentities"])
        .and_then(Value::as_object)
    {
        ids.extend(u.values().filter_map(|v| v.s("principalId")));
    }
    ids
}

fn privileged_identity(t: &Tenant, r: &Value, all: &[Assignment]) -> Option<String> {
    let mut what: Vec<String> = Vec::new();
    for id in identities(r) {
        for a in all
            .iter()
            .filter(|a| a.principal == id && HIGH.contains(&a.role.as_str()))
        {
            what.push(format!(
                "{} on {}",
                role_label(t, &a.role),
                scope_text(t, a.scope)
            ));
        }
        let roles: Vec<String> = t
            .holders
            .iter()
            .filter(|h| h.principal == id)
            .map(|h| t.role_name(&h.role))
            .collect();
        if !roles.is_empty() {
            what.push(format!("Entra {}", roles.join(", ")));
        }
    }
    what.sort();
    what.dedup();
    (!what.is_empty()).then(|| what.join("; "))
}

fn identity_check(t: &Tenant, id: &str, areas: &[(&str, &str)], expected: &str) -> CheckResult {
    let all = assignments(t, "azroleassignments");
    let mut list = Vec::new();
    for (area, kind) in areas {
        for r in t.raw.list(area) {
            if let Some(what) = privileged_identity(t, r, &all) {
                let k = if *area == "azwebapps"
                    && r.s("kind").is_some_and(|k| k.contains("functionapp"))
                {
                    "Function app"
                } else {
                    kind
                };
                list.push(t.object(
                    "resource",
                    r.s("name").unwrap_or_default(),
                    r.s("@dca.parent").map(|s| sub_name(t, s)),
                    format!("{k} whose managed identity holds {what}: whoever can edit it acts with those rights"),
                ));
            }
        }
    }
    arm(t, id)
        .expected(expected)
        .found(
            plural(list.len(), "resource", "resources")
                + " with a highly privileged managed identity",
        )
        .affected(list, "resources")
        .done()
}

fn rbac_016(t: &Tenant) -> CheckResult {
    identity_check(
        t,
        "AZ-RBAC-016",
        &[("azautomation", "Automation account")],
        "Automation accounts' managed identities hold only the rights their runbooks need",
    )
}

fn rbac_017(t: &Tenant) -> CheckResult {
    identity_check(
        t,
        "AZ-RBAC-017",
        &[("azlogicapps", "Logic app"), ("azwebapps", "App service")],
        "Logic Apps and Functions' managed identities hold only the rights they need",
    )
}

fn secret_name(n: &str) -> bool {
    let l = n.to_ascii_lowercase();
    [
        "password",
        "pwd",
        "secret",
        "key",
        "token",
        "credential",
        "connectionstring",
    ]
    .iter()
    .any(|w| l.contains(w))
}

fn rbac_019(t: &Tenant) -> CheckResult {
    let mut list: Vec<Affected> = t
        .raw
        .list("azscriptscan")
        .iter()
        .map(|s| {
            let mut kinds: Vec<&str> = s
                .a("matches")
                .iter()
                .filter_map(|m| m.s("keyword"))
                .collect();
            kinds.sort_unstable();
            kinds.dedup();
            let lines: Vec<String> = s
                .a("matches")
                .iter()
                .filter_map(|m| m.n("line"))
                .map(|n| n.to_string())
                .collect();
            let what = if s.s("kind") == Some("runbook") {
                "Runbook"
            } else {
                "Deployment script"
            };
            t.object(
                "resource",
                s.s("name").unwrap_or_default(),
                Some(what.to_string()),
                format!(
                    "{what} looks like it holds a credential ({}) on line {}",
                    kinds.join(", "),
                    lines.join(", ")
                ),
            )
        })
        .collect();
    for v in t.raw.list("azautomationvars") {
        let name = v.s("name").unwrap_or_default();
        if v.b("isEncrypted") == Some(false) && v.b("hasValue") == Some(true) && secret_name(name) {
            let account = v
                .s("account")
                .unwrap_or_default()
                .rsplit('/')
                .next()
                .unwrap_or_default();
            list.push(t.object("variable", format!("{account}/{name}"), Some("Automation variable".into()), "Unencrypted variable named like a credential: anyone with Reader on the account can read it"));
        }
    }
    arm(t, "AZ-RBAC-019")
        .expected("Runbooks, deployment scripts and automation variables hold no credentials in clear text")
        .found(plural(list.len(), "place", "places") + " with credential-like content")
        .affected(list, "items")
        .evidence("Note", "Only the keyword and line of each match were recorded, never the text")
        .done()
}

pub static RULES: &[Rule] = &[
    Rule {
        id: "AZ-KV-005",
        needs: &["azvaults", "azkvsecrets", "azkvkeys"],
        run: kv_005,
    },
    Rule {
        id: "AZ-KV-006",
        needs: &["azvaults", "azkvsecrets"],
        run: kv_006,
    },
    Rule {
        id: "AZ-KV-008",
        needs: &["azvaults", "azkvsecrets", "azkvkeys"],
        run: kv_008,
    },
    Rule {
        id: "AZ-KV-009",
        needs: &["azvaults", "azkvsecrets", "azkvkeys", "azroleassignments"],
        run: kv_009,
    },
    Rule {
        id: "AZ-RBAC-007",
        needs: &["azclassicadmins"],
        run: rbac_007,
    },
    Rule {
        id: "AZ-RBAC-016",
        needs: &["azautomation", "azroleassignments"],
        run: rbac_016,
    },
    Rule {
        id: "AZ-RBAC-017",
        needs: &["azlogicapps", "azwebapps", "azroleassignments"],
        run: rbac_017,
    },
    Rule {
        id: "AZ-RBAC-019",
        needs: &["azscriptscan", "azautomationvars"],
        run: rbac_019,
    },
];
