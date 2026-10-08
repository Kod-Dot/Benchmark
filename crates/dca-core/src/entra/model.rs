//! The tenant as the rules see it: lookups by id, who holds which directory
//! role (directly, through a role-assignable group, active or eligible),
//! and the licence level.

use std::collections::{HashMap, HashSet};

use serde_json::Value;

use super::raw::RawTenant;
use crate::results::Affected;
use crate::time;

/// Read access to Graph JSON without ceremony.
pub trait J {
    fn s(&self, key: &str) -> Option<&str>;
    fn b(&self, key: &str) -> Option<bool>;
    fn a(&self, key: &str) -> &[Value];
    fn o(&self, key: &str) -> Option<&Value>;
    fn strs(&self, key: &str) -> Vec<&str>;
    fn at(&self, path: &[&str]) -> Option<&Value>;
    fn t(&self, key: &str) -> Option<i64>;
    fn n(&self, key: &str) -> Option<i64>;
}

impl J for Value {
    fn s(&self, key: &str) -> Option<&str> {
        self.get(key).and_then(Value::as_str)
    }
    fn b(&self, key: &str) -> Option<bool> {
        self.get(key).and_then(Value::as_bool)
    }
    fn a(&self, key: &str) -> &[Value] {
        self.get(key)
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }
    fn o(&self, key: &str) -> Option<&Value> {
        self.get(key).filter(|v| v.is_object())
    }
    fn strs(&self, key: &str) -> Vec<&str> {
        self.a(key).iter().filter_map(Value::as_str).collect()
    }
    fn at(&self, path: &[&str]) -> Option<&Value> {
        let mut v = self;
        for p in path {
            v = v.get(*p)?;
        }
        (!v.is_null()).then_some(v)
    }
    fn t(&self, key: &str) -> Option<i64> {
        self.s(key).and_then(time::parse_iso)
    }
    fn n(&self, key: &str) -> Option<i64> {
        match self.get(key)? {
            Value::Number(n) => n.as_i64(),
            Value::String(s) => s.trim().parse().ok(),
            _ => None,
        }
    }
}

pub const GLOBAL_ADMIN: &str = "62e90394-69f5-4237-9190-012177145e10";
pub const PRIV_ROLE_ADMIN: &str = "e8611ab8-c189-46e8-94e1-60213ab1f814";
pub const PRIV_AUTH_ADMIN: &str = "7be44c8a-adaf-4e2a-84d6-ab2649e08a13";
pub const DIR_SYNC: &str = "d29b2b05-8046-44ba-8758-1e26182fcf32";
pub const DEVICE_LOCAL_ADMIN: &str = "9f06204d-73c1-4d4c-880a-6edb90606fd8";
pub const APP_ADMIN: &str = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3";
pub const CLOUD_APP_ADMIN: &str = "158c047a-c907-4556-b7ef-446551a6b5f7";
pub const HYBRID_ADMIN: &str = "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2";
pub const AUTH_ADMIN: &str = "c4e39bd9-1100-46d3-8c65-fb160da0071f";

/// Built-in roles treated as privileged, by template id. Names are used when
/// the role definitions could not be read.
pub const PRIVILEGED: [(&str, &str); 20] = [
    (GLOBAL_ADMIN, "Global Administrator"),
    (PRIV_ROLE_ADMIN, "Privileged Role Administrator"),
    (PRIV_AUTH_ADMIN, "Privileged Authentication Administrator"),
    (
        "194ae4cb-b126-40b2-bd5b-6091b380977d",
        "Security Administrator",
    ),
    (APP_ADMIN, "Application Administrator"),
    (CLOUD_APP_ADMIN, "Cloud Application Administrator"),
    (HYBRID_ADMIN, "Hybrid Identity Administrator"),
    (AUTH_ADMIN, "Authentication Administrator"),
    (
        "29232cdf-9323-42fd-ade2-1d097af3e4de",
        "Exchange Administrator",
    ),
    (
        "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",
        "SharePoint Administrator",
    ),
    (
        "3a2c62db-5318-420d-8d74-23affee5d9d5",
        "Intune Administrator",
    ),
    ("fe930be7-5e62-47db-91af-98c3a49a38b1", "User Administrator"),
    (
        "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",
        "Conditional Access Administrator",
    ),
    (
        "729827e3-9c14-49f7-bb1b-9608f156bbb8",
        "Helpdesk Administrator",
    ),
    (
        "fdd7a751-b60b-444a-984c-02652fe8fa1c",
        "Groups Administrator",
    ),
    (DIR_SYNC, "Directory Synchronization Accounts"),
    (
        "e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8",
        "Partner Tier2 Support",
    ),
    (
        "8329153b-31d0-4727-b945-745eb3bc5f31",
        "Domain Name Administrator",
    ),
    (
        "0526716b-113d-4c15-b2c8-68e3c22b9f80",
        "Authentication Policy Administrator",
    ),
    ("9360feb5-f418-4baa-8175-e2a00bac4301", "Directory Writers"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrincipalKind {
    User,
    Group,
    ServicePrincipal,
    Unknown,
}

/// One principal holding one role, for every way it can hold it.
#[derive(Debug, Clone)]
pub struct Holder {
    /// The role's template id (the definition id for custom roles).
    pub role: String,
    pub principal: String,
    pub kind: PrincipalKind,
    /// Active now; otherwise eligible through PIM.
    pub active: bool,
    /// Active with no end date and not a PIM activation.
    pub permanent: bool,
    /// The role-assignable group the role comes through, if any.
    pub via: Option<String>,
    /// Scoped to an administrative unit or object rather than the tenant.
    pub scoped: bool,
}

pub struct Tenant<'a> {
    pub raw: &'a RawTenant,
    /// When the data was read; ages are measured from here.
    pub now: i64,
    pub id: String,
    pub name: String,
    pub users: HashMap<&'a str, &'a Value>,
    pub groups: HashMap<&'a str, &'a Value>,
    pub sps: HashMap<&'a str, &'a Value>,
    pub sps_by_app: HashMap<&'a str, &'a Value>,
    /// Role definition id and template id to (template id, name, built in).
    pub roles: HashMap<String, (String, String, bool)>,
    pub holders: Vec<Holder>,
    /// Members of role-assignable groups, by group id.
    pub group_members: HashMap<&'a str, Vec<&'a Value>>,
    pub p1: bool,
    pub p2: bool,
    /// The subscribed SKUs were read, so `p1` and `p2` are known.
    pub licences_known: bool,
}

const MICROSOFT_TENANTS: [&str; 3] = [
    "f8cdef31-a31e-4b4a-93e4-5f571e91255a",
    "72f988bf-86f1-41af-91ab-2d7cd011db47",
    "33e01921-4d64-4f8c-a055-5bdaffd5e33d",
];

pub fn is_microsoft_tenant(id: &str) -> bool {
    MICROSOFT_TENANTS.contains(&id)
}

fn principal_kind(p: Option<&Value>) -> Option<PrincipalKind> {
    let t = p?.s("@odata.type")?;
    Some(match t {
        "#microsoft.graph.user" => PrincipalKind::User,
        "#microsoft.graph.group" => PrincipalKind::Group,
        "#microsoft.graph.servicePrincipal" => PrincipalKind::ServicePrincipal,
        _ => PrincipalKind::Unknown,
    })
}

impl<'a> Tenant<'a> {
    pub fn build(raw: &'a RawTenant) -> Tenant<'a> {
        let now = raw
            .finished_at
            .as_deref()
            .or(Some(raw.info.started_at.as_str()))
            .and_then(time::parse_iso)
            .unwrap_or_else(time::now);
        let by_id = |area: &str| -> HashMap<&'a str, &'a Value> {
            raw.list(area)
                .iter()
                .filter_map(|v| Some((v.s("id")?, v)))
                .collect()
        };
        let users = by_id("users");
        let groups = by_id("groups");
        let sps = by_id("serviceprincipals");
        let sps_by_app = raw
            .list("serviceprincipals")
            .iter()
            .filter_map(|v| Some((v.s("appId")?, v)))
            .collect();

        let mut roles = HashMap::new();
        for (id, name) in PRIVILEGED {
            roles.insert(id.to_string(), (id.to_string(), name.to_string(), true));
        }
        for d in raw.list("roledefinitions") {
            let (Some(id), Some(name)) = (d.s("id"), d.s("displayName")) else {
                continue;
            };
            let template = d.s("templateId").unwrap_or(id).to_string();
            let entry = (
                template.clone(),
                name.to_string(),
                d.b("isBuiltIn").unwrap_or(true),
            );
            roles.insert(id.to_string(), entry.clone());
            roles.insert(template, entry);
        }

        let mut group_members: HashMap<&str, Vec<&Value>> = HashMap::new();
        for m in raw.list("rolegroupmembers") {
            if let Some(g) = m.s("@dca.parent") {
                group_members.entry(g).or_default().push(m);
            }
        }

        let org = raw.first("organization");
        let id = org
            .and_then(|o| o.s("id"))
            .map(str::to_string)
            .unwrap_or_else(|| raw.info.tenant_id.clone());
        let name = org
            .and_then(|o| o.s("displayName"))
            .map(str::to_string)
            .unwrap_or_else(|| raw.info.tenant.clone());

        let plan = |name: &str| {
            raw.list("skus").iter().any(|s| {
                s.s("capabilityStatus").is_none_or(|c| c == "Enabled")
                    && s.a("servicePlans")
                        .iter()
                        .any(|p| p.s("servicePlanName") == Some(name))
            })
        };
        let p2 = plan("AAD_PREMIUM_P2");
        let p1 = p2 || plan("AAD_PREMIUM");

        let mut t = Tenant {
            raw,
            now,
            id,
            name,
            users,
            groups,
            sps,
            sps_by_app,
            roles,
            holders: Vec::new(),
            group_members,
            p1,
            p2,
            licences_known: raw.read("skus"),
        };
        t.holders = t.collect_holders();
        t
    }

    fn kind_of(&self, id: &str, expanded: Option<&Value>) -> PrincipalKind {
        if let Some(k) = principal_kind(expanded) {
            return k;
        }
        if self.users.contains_key(id) {
            PrincipalKind::User
        } else if self.groups.contains_key(id) {
            PrincipalKind::Group
        } else if self.sps.contains_key(id) {
            PrincipalKind::ServicePrincipal
        } else {
            PrincipalKind::Unknown
        }
    }

    pub fn template(&self, role_definition_id: &str) -> String {
        self.roles
            .get(role_definition_id)
            .map(|r| r.0.clone())
            .unwrap_or_else(|| role_definition_id.to_string())
    }

    pub fn role_name(&self, role: &str) -> String {
        self.roles
            .get(role)
            .map(|r| r.1.clone())
            .unwrap_or_else(|| format!("Role {role}"))
    }

    pub fn is_privileged(&self, role: &str) -> bool {
        let template = self.template(role);
        PRIVILEGED.iter().any(|(id, _)| *id == template)
    }

    fn collect_holders(&self) -> Vec<Holder> {
        // Active assignments that PIM shows as activations or with an end date.
        let mut temporary: HashSet<(String, String)> = HashSet::new();
        for s in self.raw.list("roleschedules") {
            let (Some(p), Some(r)) = (s.s("principalId"), s.s("roleDefinitionId")) else {
                continue;
            };
            let activated = s.s("assignmentType") == Some("Activated");
            let ends = s
                .at(&["scheduleInfo", "expiration", "type"])
                .and_then(Value::as_str)
                .is_some_and(|t| t != "noExpiration");
            if activated || ends {
                temporary.insert((p.to_string(), self.template(r)));
            }
        }
        let mut out = Vec::new();
        let mut add = |a: &Value, active: bool| {
            let (Some(p), Some(r)) = (a.s("principalId"), a.s("roleDefinitionId")) else {
                return;
            };
            let role = self.template(r);
            let kind = self.kind_of(p, a.o("principal"));
            let scoped = a.s("directoryScopeId").is_some_and(|s| s != "/");
            let permanent = active && !temporary.contains(&(p.to_string(), role.clone()));
            out.push(Holder {
                role: role.clone(),
                principal: p.to_string(),
                kind,
                active,
                permanent,
                via: None,
                scoped,
            });
            if kind == PrincipalKind::Group {
                for m in self.group_members.get(p).map(Vec::as_slice).unwrap_or(&[]) {
                    let Some(mid) = m.s("id") else { continue };
                    out.push(Holder {
                        role: role.clone(),
                        principal: mid.to_string(),
                        kind: self.kind_of(mid, Some(m)),
                        active,
                        permanent,
                        via: Some(p.to_string()),
                        scoped,
                    });
                }
            }
        };
        for a in self.raw.list("roleassignments") {
            add(a, true);
        }
        for a in self.raw.list("roleeligibility") {
            add(a, false);
        }
        out
    }

    /// Holders of `role` who are not groups (members of groups included).
    pub fn holders_of<'s>(&'s self, role: &'s str) -> impl Iterator<Item = &'s Holder> + 's {
        self.holders
            .iter()
            .filter(move |h| h.role == role && h.kind != PrincipalKind::Group)
    }

    /// Distinct principals that hold a privileged role, with the roles.
    pub fn privileged_principals(&self) -> Vec<(String, Vec<&Holder>)> {
        let mut map: Vec<(String, Vec<&Holder>)> = Vec::new();
        for h in self
            .holders
            .iter()
            .filter(|h| h.kind != PrincipalKind::Group && self.is_privileged(&h.role))
        {
            match map.iter_mut().find(|(p, _)| *p == h.principal) {
                Some((_, list)) => list.push(h),
                None => map.push((h.principal.clone(), vec![h])),
            }
        }
        map
    }

    pub fn principal(&self, id: &str) -> Option<&'a Value> {
        self.users
            .get(id)
            .or_else(|| self.groups.get(id))
            .or_else(|| self.sps.get(id))
            .copied()
    }

    pub fn name_of(&self, id: &str) -> String {
        if let Some(u) = self.users.get(id) {
            return u
                .s("userPrincipalName")
                .or(u.s("displayName"))
                .unwrap_or(id)
                .to_string();
        }
        if let Some(v) = self.groups.get(id).or_else(|| self.sps.get(id)) {
            return v.s("displayName").unwrap_or(id).to_string();
        }
        for list in self.group_members.values() {
            if let Some(m) = list.iter().find(|m| m.s("id") == Some(id)) {
                return m
                    .s("userPrincipalName")
                    .or(m.s("displayName"))
                    .unwrap_or(id)
                    .to_string();
            }
        }
        id.to_string()
    }

    /// The roles a principal holds, as "Global Administrator (eligible)".
    pub fn roles_text(&self, list: &[&Holder]) -> String {
        let mut names: Vec<String> = list
            .iter()
            .map(|h| {
                let mut s = self.role_name(&h.role);
                if !h.active {
                    s.push_str(" (eligible)");
                }
                if let Some(g) = &h.via {
                    s.push_str(&format!(" through {}", self.name_of(g)));
                }
                s
            })
            .collect();
        names.sort();
        names.dedup();
        names.join(", ")
    }

    pub fn affected(&self, id: &str, reason: impl Into<String>) -> Affected {
        let (kind, location) = match self.principal(id) {
            Some(v) if self.users.contains_key(id) => {
                ("user", v.s("userPrincipalName").map(str::to_string))
            }
            Some(_) if self.groups.contains_key(id) => ("group", None),
            Some(v) => ("app", v.s("appId").map(|a| format!("App id {a}"))),
            None => ("user", None),
        };
        Affected {
            last_seen: None,
            name: self.name_of(id),
            kind: kind.to_string(),
            location,
            reason: Some(reason.into()),
            object: self.principal(id).map(|_| id.to_string()),
        }
    }

    pub fn object(
        &self,
        kind: &str,
        name: impl Into<String>,
        location: Option<String>,
        reason: impl Into<String>,
    ) -> Affected {
        Affected {
            last_seen: None,
            name: name.into(),
            kind: kind.to_string(),
            location,
            reason: Some(reason.into()),
            object: None,
        }
    }

    /// The latest sign-in of any kind, when sign-in activity was read.
    pub fn last_signin(&self, u: &Value) -> Option<i64> {
        let a = u.o("signInActivity")?;
        [
            "lastSignInDateTime",
            "lastNonInteractiveSignInDateTime",
            "lastSuccessfulSignInDateTime",
        ]
        .iter()
        .filter_map(|k| a.t(k))
        .max()
    }

    pub fn days_since(&self, t: Option<i64>) -> Option<i64> {
        t.map(|t| time::days_between(t, self.now))
    }

    pub fn is_guest(&self, id: &str) -> bool {
        self.users
            .get(id)
            .is_some_and(|u| u.s("userType") == Some("Guest"))
    }

    pub fn synced(&self) -> bool {
        self.raw
            .first("organization")
            .and_then(|o| o.b("onPremisesSyncEnabled"))
            .unwrap_or(false)
    }
}
