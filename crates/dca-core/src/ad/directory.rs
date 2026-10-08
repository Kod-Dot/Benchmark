//! Turns the domain model into `directory.json`: the objects, OU tree,
//! memberships and control edges the Directory and Graph screens show.

use std::collections::{BTreeMap, HashSet};

use serde_json::Value;

use super::model::{uac, Kind, Model};
use crate::results::{DirObject, DirSource, DirectoryFile, Edge, Flag};
use crate::time;

/// Attributes shown on an object's page, with their LDAP display names.
const SHOWN: [(&str, &str); 22] = [
    ("distinguishedname", "distinguishedName"),
    ("samaccountname", "sAMAccountName"),
    ("userprincipalname", "userPrincipalName"),
    ("displayname", "displayName"),
    ("description", "description"),
    ("mail", "mail"),
    ("objectsid", "objectSid"),
    ("whencreated", "whenCreated"),
    ("admincount", "adminCount"),
    ("useraccountcontrol", "userAccountControl"),
    ("primarygroupid", "primaryGroupID"),
    ("serviceprincipalname", "servicePrincipalName"),
    ("msds-allowedtodelegateto", "msDS-AllowedToDelegateTo"),
    (
        "msds-supportedencryptiontypes",
        "msDS-SupportedEncryptionTypes",
    ),
    ("dnshostname", "dNSHostName"),
    ("operatingsystem", "operatingSystem"),
    ("operatingsystemversion", "operatingSystemVersion"),
    ("grouptype", "groupType"),
    ("gpcfilesyspath", "gPCFileSysPath"),
    ("trustdirection", "trustDirection"),
    ("trusttype", "trustType"),
    ("trustattributes", "trustAttributes"),
];

const SECRET_WORDS: [&str; 6] = [
    "password",
    "passwort",
    "passwd",
    "pwd",
    "kennwort",
    "mot de passe",
];

fn attributes(m: &Model, i: usize) -> BTreeMap<String, Value> {
    let n = &m.nodes[i];
    let mut out = BTreeMap::new();
    for (key, name) in SHOWN {
        let values = n.attrs.values(key);
        let value = match values {
            [] => continue,
            [one] => one.clone(),
            many => Value::Array(many.to_vec()),
        };
        // Descriptions are readable by every user, but may hold a password.
        let value = if key == "description"
            && value.as_str().is_some_and(|d| {
                let d = d.to_lowercase();
                SECRET_WORDS.iter().any(|w| d.contains(w))
            }) {
            Value::String("[Hidden: may contain a password, see AD-PWD-019]".into())
        } else if key == "whencreated" {
            Value::String(
                value
                    .as_str()
                    .map(|s| s.get(..10).unwrap_or(s))
                    .unwrap_or_default()
                    .to_string(),
            )
        } else {
            value
        };
        out.insert(name.to_string(), value);
    }
    if n.kind == Kind::Principal {
        out.insert(
            "objectSid".into(),
            Value::String(n.sid.clone().unwrap_or_default()),
        );
    }
    out
}

fn flags(
    m: &Model,
    i: usize,
    admin_of: &BTreeMap<usize, Vec<usize>>,
    protected: &HashSet<usize>,
) -> Vec<Flag> {
    let n = &m.nodes[i];
    let mut f = Vec::new();
    let mut flag = |text: &str, level: &str| {
        f.push(Flag {
            text: text.to_string(),
            level: level.to_string(),
        })
    };
    if let Some(groups) = admin_of.get(&i) {
        let mut names: Vec<(&str, bool)> = groups
            .iter()
            .map(|&g| {
                let rid = m.nodes[g].rid().unwrap_or(0);
                (
                    m.nodes[g].name.as_str(),
                    matches!(rid, 512 | 518 | 519 | 544),
                )
            })
            .collect();
        names.sort_by_key(|(name, crit)| (!crit, *name));
        names.dedup();
        for (name, crit) in names.into_iter().take(2) {
            flag(name, if crit { "crit" } else { "warn" });
        }
    }
    match n.kind {
        Kind::Computer if n.is_dc() => flag("Domain controller", ""),
        Kind::Computer | Kind::User if n.flag(uac::TRUSTED_FOR_DELEGATION) => {
            flag("Unconstrained delegation", "crit")
        }
        _ => {}
    }
    if n.kind == Kind::User {
        let krbtgt = n.rid() == Some(502);
        if n.enabled() && !krbtgt && !n.spns().is_empty() {
            flag("Kerberoastable", "warn");
        }
        if n.enabled() && n.flag(uac::DONT_REQ_PREAUTH) {
            flag("AS-REP roastable", "warn");
        }
        if n.enabled() && n.flag(uac::DONT_EXPIRE_PASSWORD) {
            flag("Password never expires", "warn");
        }
        if protected.contains(&i) {
            flag("Protected Users", "ok");
        }
    }
    if matches!(n.kind, Kind::User | Kind::Computer) {
        if !n.enabled() {
            flag("Disabled", "");
        } else if m.days_since(n.last_logon).is_some_and(|d| d > 90) {
            flag("Stale", "warn");
        }
    }
    f
}

pub fn build(m: &Model) -> DirectoryFile {
    let admin_of: BTreeMap<usize, Vec<usize>> = {
        let mut map: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for g in m.admin_groups() {
            for mbr in m.recursive_members(g) {
                map.entry(mbr).or_default().push(g);
            }
        }
        map
    };
    let protected: HashSet<usize> = m
        .group_by_rid(525)
        .map(|g| m.recursive_members(g).into_iter().collect())
        .unwrap_or_default();

    // Edges first: they decide which SID-only principals are worth showing.
    let mut edges = Vec::new();
    let mut referenced: HashSet<usize> = HashSet::new();
    for (g, members) in m.members.iter().enumerate() {
        for &mbr in members {
            // Primary group membership in Domain Users and Domain Computers
            // is implied for every account; listing it adds nothing.
            let rid = m.nodes[g].rid();
            let implied = matches!(rid, Some(513 | 515))
                && m.nodes[mbr].attrs.int("primarygroupid") == rid.map(i64::from);
            if implied {
                continue;
            }
            edges.push(Edge {
                from: m.nodes[mbr].id.clone(),
                to: m.nodes[g].id.clone(),
                kind: "MemberOf".into(),
                note: None,
            });
            referenced.extend([mbr, g]);
        }
    }
    for e in &m.edges {
        if e.kind == "Contains" || (e.kind != "GPLink" && m.nodes[e.from].tier0) {
            continue;
        }
        edges.push(Edge {
            from: m.nodes[e.from].id.clone(),
            to: m.nodes[e.to].id.clone(),
            kind: e.kind.into(),
            note: None,
        });
        referenced.extend([e.from, e.to]);
    }

    // Containers that hold no accounts and are not OUs are system plumbing.
    let mut useful_container: HashSet<usize> = HashSet::new();
    for (i, n) in m.nodes.iter().enumerate() {
        if matches!(n.kind, Kind::User | Kind::Computer | Kind::Group) || referenced.contains(&i) {
            let mut p = n.parent;
            while let Some(j) = p {
                if !useful_container.insert(j) {
                    break;
                }
                p = m.nodes[j].parent;
            }
        }
    }
    let shown = |i: usize| -> bool {
        match m.nodes[i].kind {
            Kind::Container => useful_container.contains(&i) || referenced.contains(&i),
            Kind::Principal => referenced.contains(&i),
            _ => true,
        }
    };

    let mut objects = Vec::new();
    for i in (0..m.nodes.len()).filter(|&i| shown(i)) {
        let n = &m.nodes[i];
        let mut parent = n.parent;
        while let Some(p) = parent {
            if shown(p) {
                break;
            }
            parent = m.nodes[p].parent;
        }
        if parent.is_none() && n.kind != Kind::Domain && n.kind != Kind::Principal {
            parent = m.domain;
        }
        let account = matches!(n.kind, Kind::User | Kind::Computer);
        objects.push(DirObject {
            id: n.id.clone(),
            kind: n.kind.ui().to_string(),
            name: n.name.clone(),
            display_name: n
                .attrs
                .str("displayname")
                .filter(|d| *d != n.name)
                .map(str::to_string),
            source: m.dns.clone(),
            parent: parent.map(|p| m.nodes[p].id.clone()),
            enabled: account.then(|| n.enabled()),
            tier0: n.tier0,
            last_logon: n.last_logon.map(time::iso),
            password_last_set: n.pwd_last_set.map(time::iso),
            flags: flags(m, i, &admin_of, &protected),
            attributes: attributes(m, i),
        });
    }

    DirectoryFile {
        sources: vec![DirSource {
            name: m.dns.clone(),
            kind: "onprem".into(),
            read_at: m
                .raw
                .finished_at
                .clone()
                .unwrap_or_else(|| m.raw.info.started_at.clone()),
        }],
        objects,
        edges,
    }
}
