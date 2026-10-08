//! Turns the tenant model into `directory.json` objects and edges: users,
//! groups, directory roles, applications and devices, with role holdings
//! and ownership as edges.

use std::collections::{BTreeMap, HashSet};

use serde_json::Value;

use super::model::{PrincipalKind, Tenant, J};
use crate::results::{DirObject, DirSource, DirectoryFile, Edge, Flag};
use crate::time;

/// Graph properties shown on an object's page, per kind.
const USER_ATTRS: [&str; 10] = [
    "userPrincipalName",
    "mail",
    "userType",
    "jobTitle",
    "department",
    "createdDateTime",
    "onPremisesSyncEnabled",
    "onPremisesSamAccountName",
    "onPremisesLastSyncDateTime",
    "externalUserState",
];
const GROUP_ATTRS: [&str; 7] = [
    "mail",
    "description",
    "groupTypes",
    "securityEnabled",
    "isAssignableToRole",
    "membershipRule",
    "onPremisesSyncEnabled",
];
const APP_ATTRS: [&str; 5] = [
    "appId",
    "servicePrincipalType",
    "appOwnerOrganizationId",
    "signInAudience",
    "createdDateTime",
];
const DEVICE_ATTRS: [&str; 8] = [
    "deviceId",
    "operatingSystem",
    "operatingSystemVersion",
    "trustType",
    "isCompliant",
    "isManaged",
    "registrationDateTime",
    "approximateLastSignInDateTime",
];

fn attributes(v: &Value, keys: &[&str]) -> BTreeMap<String, Value> {
    keys.iter()
        .filter_map(|k| {
            let value = v.get(*k)?;
            let empty = value.is_null()
                || value.as_array().is_some_and(Vec::is_empty)
                || value.as_str().is_some_and(str::is_empty);
            (!empty).then(|| (k.to_string(), value.clone()))
        })
        .collect()
}

fn flag(text: impl Into<String>, level: &str) -> Flag {
    Flag {
        text: text.into(),
        level: level.into(),
    }
}

/// Builds the directory view of one tenant.
pub fn build(t: &Tenant) -> DirectoryFile {
    let source = t.name.clone();
    let role_id = |template: &str| format!("{}:role:{template}", t.id);
    let privileged: HashSet<&str> = t
        .holders
        .iter()
        .filter(|h| t.is_privileged(&h.role))
        .map(|h| h.principal.as_str())
        .collect();
    let mut objects = Vec::new();
    let mut edges = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    let mut users: Vec<_> = t.users.values().collect();
    users.sort_by_key(|u| u.s("userPrincipalName").unwrap_or_default().to_lowercase());
    for u in users {
        let Some(id) = u.s("id") else { continue };
        let mut flags = Vec::new();
        if u.s("userType") == Some("Guest") {
            flags.push(flag("Guest", ""));
        }
        if u.b("onPremisesSyncEnabled") == Some(true) {
            flags.push(flag("Synced from AD", ""));
        }
        if privileged.contains(id) {
            flags.push(flag("Privileged role", "warn"));
        }
        seen.insert(id.to_string());
        objects.push(DirObject {
            id: id.to_string(),
            kind: "user".into(),
            name: u
                .s("userPrincipalName")
                .or(u.s("displayName"))
                .unwrap_or(id)
                .to_string(),
            display_name: u.s("displayName").map(str::to_string),
            source: source.clone(),
            parent: None,
            enabled: u.b("accountEnabled"),
            tier0: privileged.contains(id),
            last_logon: t.last_signin(u).map(time::iso),
            password_last_set: u.s("lastPasswordChangeDateTime").map(str::to_string),
            flags,
            attributes: attributes(u, &USER_ATTRS),
        });
    }

    let mut groups: Vec<_> = t.groups.values().collect();
    groups.sort_by_key(|g| g.s("displayName").unwrap_or_default().to_lowercase());
    for g in groups {
        let Some(id) = g.s("id") else { continue };
        let mut flags = Vec::new();
        if g.b("isAssignableToRole") == Some(true) {
            flags.push(flag("Role-assignable", ""));
        }
        if g.strs("groupTypes").contains(&"Unified") {
            flags.push(flag("Microsoft 365 group", ""));
        }
        if g.strs("groupTypes").contains(&"DynamicMembership") {
            flags.push(flag("Dynamic membership", ""));
        }
        if privileged.contains(id) {
            flags.push(flag("Privileged role", "warn"));
        }
        seen.insert(id.to_string());
        objects.push(DirObject {
            id: id.to_string(),
            kind: "group".into(),
            name: g.s("displayName").unwrap_or(id).to_string(),
            display_name: None,
            source: source.clone(),
            parent: None,
            enabled: None,
            tier0: privileged.contains(id),
            last_logon: None,
            password_last_set: None,
            flags,
            attributes: attributes(g, &GROUP_ATTRS),
        });
        for o in g.a("owners") {
            if let Some(owner) = o.s("id") {
                edges.push(Edge {
                    from: owner.to_string(),
                    to: id.to_string(),
                    kind: "Owns".into(),
                    note: None,
                });
            }
        }
    }
    for (group, members) in &t.group_members {
        for m in members {
            if let Some(mid) = m.s("id") {
                edges.push(Edge {
                    from: mid.to_string(),
                    to: group.to_string(),
                    kind: "MemberOf".into(),
                    note: None,
                });
            }
        }
    }

    let mut sps: Vec<_> = t.sps.values().collect();
    sps.sort_by_key(|s| s.s("displayName").unwrap_or_default().to_lowercase());
    for s in sps {
        let Some(id) = s.s("id") else { continue };
        let first_party = s
            .s("appOwnerOrganizationId")
            .is_some_and(super::model::is_microsoft_tenant);
        // Microsoft's own applications are listed only when they hold a role.
        if first_party && !privileged.contains(id) {
            continue;
        }
        let mut flags = Vec::new();
        match s.s("servicePrincipalType") {
            Some("ManagedIdentity") => flags.push(flag("Managed identity", "")),
            _ if s
                .s("appOwnerOrganizationId")
                .is_some_and(|o| o != t.id && !first_party) =>
            {
                flags.push(flag("Multi-tenant app from another organization", ""))
            }
            _ => {}
        }
        if privileged.contains(id) {
            flags.push(flag("Privileged role", "warn"));
        }
        seen.insert(id.to_string());
        objects.push(DirObject {
            id: id.to_string(),
            kind: "app".into(),
            name: s.s("displayName").unwrap_or(id).to_string(),
            display_name: None,
            source: source.clone(),
            parent: None,
            enabled: s.b("accountEnabled"),
            tier0: privileged.contains(id),
            last_logon: None,
            password_last_set: None,
            flags,
            attributes: attributes(s, &APP_ATTRS),
        });
        for o in s.a("owners") {
            if let Some(owner) = o.s("id") {
                edges.push(Edge {
                    from: owner.to_string(),
                    to: id.to_string(),
                    kind: "Owns".into(),
                    note: None,
                });
            }
        }
    }

    let mut devices: Vec<_> = t.raw.list("devices").iter().collect();
    devices.sort_by_key(|d| d.s("displayName").unwrap_or_default().to_lowercase());
    for d in devices {
        let Some(id) = d.s("id") else { continue };
        let mut flags = Vec::new();
        match d.s("trustType") {
            Some("ServerAd") => flags.push(flag("Hybrid joined", "")),
            Some("AzureAd") => flags.push(flag("Entra joined", "")),
            Some("Workplace") => flags.push(flag("Registered", "")),
            _ => {}
        }
        if d.b("isCompliant") == Some(false) {
            flags.push(flag("Not compliant", "warn"));
        }
        objects.push(DirObject {
            id: id.to_string(),
            kind: "device".into(),
            name: d.s("displayName").unwrap_or(id).to_string(),
            display_name: None,
            source: source.clone(),
            parent: None,
            enabled: d.b("accountEnabled"),
            tier0: false,
            last_logon: d.s("approximateLastSignInDateTime").map(str::to_string),
            password_last_set: None,
            flags,
            attributes: attributes(d, &DEVICE_ATTRS),
        });
    }

    // Roles that someone holds, each with an edge from every direct holder.
    let mut roles: Vec<&str> = t.holders.iter().map(|h| h.role.as_str()).collect();
    roles.sort_by_key(|r| t.role_name(r));
    roles.dedup();
    for role in roles {
        let privileged_role = t.is_privileged(role);
        objects.push(DirObject {
            id: role_id(role),
            kind: "role".into(),
            name: t.role_name(role),
            display_name: None,
            source: source.clone(),
            parent: None,
            enabled: None,
            tier0: privileged_role,
            last_logon: None,
            password_last_set: None,
            flags: if privileged_role {
                vec![flag("Privileged", "warn")]
            } else {
                Vec::new()
            },
            attributes: BTreeMap::from([(
                "templateId".to_string(),
                Value::String(role.to_string()),
            )]),
        });
    }
    let mut direct: HashSet<(String, String, bool)> = HashSet::new();
    for h in t.holders.iter().filter(|h| h.via.is_none()) {
        if !direct.insert((h.principal.clone(), h.role.clone(), h.active)) {
            continue;
        }
        if h.kind == PrincipalKind::Unknown && !seen.contains(&h.principal) {
            continue;
        }
        let mut note = Vec::new();
        if !h.active {
            note.push("eligible");
        } else if h.permanent {
            note.push("permanent");
        }
        if h.scoped {
            note.push("scoped");
        }
        edges.push(Edge {
            from: h.principal.clone(),
            to: role_id(&h.role),
            kind: if h.active { "HasRole" } else { "EligibleFor" }.into(),
            note: (!note.is_empty()).then(|| note.join(", ")),
        });
    }

    // Keep only edges whose ends are in the view.
    let ids: HashSet<&str> = objects.iter().map(|o| o.id.as_str()).collect();
    edges.retain(|e| ids.contains(e.from.as_str()) && ids.contains(e.to.as_str()));

    DirectoryFile {
        sources: vec![DirSource {
            name: source,
            kind: "cloud".into(),
            read_at: t
                .raw
                .finished_at
                .clone()
                .unwrap_or_else(|| t.raw.info.started_at.clone()),
        }],
        objects,
        edges,
    }
}
