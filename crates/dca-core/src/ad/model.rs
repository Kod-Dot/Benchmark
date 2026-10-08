//! The domain as one graph: every object read, indexed by DN and SID, with
//! group membership (including primary groups), the control edges that ACLs,
//! owners and GPO links create, and which objects are Tier 0.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use super::raw::{LdapObject, RawDomain};
use super::sd::{self, right, AceType, SecurityDescriptor};
use crate::time;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    Domain,
    Container,
    Ou,
    User,
    Computer,
    Group,
    Gpo,
    Trust,
    /// A principal known only by SID: a well-known SID (Everyone,
    /// Authenticated Users), a foreign security principal, or a deleted one.
    Principal,
}

impl Kind {
    /// The kind name `directory.json` and the UI use.
    pub fn ui(self) -> &'static str {
        match self {
            Kind::Domain => "domain",
            Kind::Container | Kind::Ou => "ou",
            Kind::User => "user",
            Kind::Computer => "computer",
            Kind::Group | Kind::Principal => "group",
            Kind::Gpo => "gpo",
            Kind::Trust => "trust",
        }
    }

    pub fn is_principal(self) -> bool {
        matches!(
            self,
            Kind::User | Kind::Computer | Kind::Group | Kind::Principal
        )
    }
}

pub mod uac {
    pub const ACCOUNTDISABLE: u32 = 0x0000_0002;
    pub const PASSWD_NOTREQD: u32 = 0x0000_0020;
    pub const ENCRYPTED_TEXT_PWD_ALLOWED: u32 = 0x0000_0080;
    pub const WORKSTATION_TRUST_ACCOUNT: u32 = 0x0000_1000;
    pub const SERVER_TRUST_ACCOUNT: u32 = 0x0000_2000;
    pub const DONT_EXPIRE_PASSWORD: u32 = 0x0001_0000;
    pub const TRUSTED_FOR_DELEGATION: u32 = 0x0008_0000;
    pub const NOT_DELEGATED: u32 = 0x0010_0000;
    pub const USE_DES_KEY_ONLY: u32 = 0x0020_0000;
    pub const DONT_REQ_PREAUTH: u32 = 0x0040_0000;
    pub const TRUSTED_TO_AUTH_FOR_DELEGATION: u32 = 0x0100_0000;
    pub const PARTIAL_SECRETS_ACCOUNT: u32 = 0x0400_0000;
}

/// Directory GUIDs the ACL analysis looks for ([MS-ADA], [MS-ADTS]).
pub mod guid {
    pub const MEMBER: &str = "bf9679c0-0de6-11d0-a285-00aa003049e2";
    pub const SPN: &str = "f3a64788-5306-11d1-a9c5-0000f80367c1";
    pub const KEY_CREDENTIAL_LINK: &str = "5b47d60f-6090-40b2-9f37-2a4de88f3063";
    pub const ALLOWED_TO_ACT: &str = "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79";
    pub const ACCOUNT_RESTRICTIONS: &str = "4c164200-20c0-11d0-a768-00aa003049e2";
    pub const GP_LINK: &str = "f30e3bbe-9ff0-11d1-b603-0000f80367c1";
    pub const FORCE_CHANGE_PASSWORD: &str = "00299570-246d-11d0-a768-00aa006e0529";
    pub const GET_CHANGES: &str = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2";
    pub const GET_CHANGES_ALL: &str = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2";
    pub const GET_CHANGES_FILTERED: &str = "89e95b76-444d-4c62-991a-0facbeda640c";

    /// Schema class GUIDs, to match inheritable ACEs to the object they sit on.
    pub fn class(name: &str) -> Option<&'static str> {
        Some(match name {
            "user" => "bf967aba-0de6-11d0-a285-00aa003049e2",
            "group" => "bf967a9c-0de6-11d0-a285-00aa003049e2",
            "computer" => "bf967a86-0de6-11d0-a285-00aa003049e2",
            "organizationalUnit" => "bf967aa5-0de6-11d0-a285-00aa003049e2",
            "domainDNS" => "19195a5b-6da0-11d0-afd3-00c04fd930c9",
            "groupPolicyContainer" => "f30e3bc2-9ff0-11d1-b603-0000f80367c1",
            "container" => "bf967a8b-0de6-11d0-a285-00aa003049e2",
            _ => return None,
        })
    }
}

/// Names for SIDs that are the same in every domain.
pub fn well_known_name(sid: &str) -> Option<&'static str> {
    Some(match sid {
        "S-1-1-0" => "Everyone",
        "S-1-3-0" => "Creator Owner",
        "S-1-5-7" => "Anonymous Logon",
        "S-1-5-9" => "Enterprise Domain Controllers",
        "S-1-5-10" => "Self",
        "S-1-5-11" => "Authenticated Users",
        "S-1-5-18" => "SYSTEM",
        "S-1-5-32-544" => "Administrators",
        "S-1-5-32-545" => "Users",
        "S-1-5-32-548" => "Account Operators",
        "S-1-5-32-549" => "Server Operators",
        "S-1-5-32-550" => "Print Operators",
        "S-1-5-32-551" => "Backup Operators",
        "S-1-5-32-554" => "Pre-Windows 2000 Compatible Access",
        _ => return None,
    })
}

pub const EVERYONE: &str = "S-1-1-0";
pub const AUTHENTICATED_USERS: &str = "S-1-5-11";
pub const ANONYMOUS: &str = "S-1-5-7";

/// Groups whose members administer the domain. Membership makes an account
/// Tier 0. (RID in the domain, or a BUILTIN SID.)
pub const TIER0_RIDS: [u32; 6] = [512, 516, 518, 519, 526, 527];
pub const TIER0_BUILTIN: [&str; 5] = [
    "S-1-5-32-544",
    "S-1-5-32-548",
    "S-1-5-32-549",
    "S-1-5-32-550",
    "S-1-5-32-551",
];

#[derive(Debug, Clone)]
pub struct Node {
    pub id: String,
    pub kind: Kind,
    pub dn: String,
    pub name: String,
    pub sid: Option<String>,
    pub attrs: LdapObject,
    pub parent: Option<usize>,
    pub uac: u32,
    pub pwd_last_set: Option<i64>,
    pub last_logon: Option<i64>,
    pub created: Option<i64>,
    pub tier0: bool,
}

impl Node {
    pub fn enabled(&self) -> bool {
        self.uac & uac::ACCOUNTDISABLE == 0
    }

    pub fn flag(&self, f: u32) -> bool {
        self.uac & f != 0
    }

    pub fn is_dc(&self) -> bool {
        self.kind == Kind::Computer && self.flag(uac::SERVER_TRUST_ACCOUNT)
    }

    pub fn rid(&self) -> Option<u32> {
        self.sid.as_deref()?.rsplit('-').next()?.parse().ok()
    }

    pub fn spns(&self) -> Vec<&str> {
        self.attrs.strs("serviceprincipalname")
    }
}

#[derive(Debug, Clone)]
pub struct ControlEdge {
    pub from: usize,
    pub to: usize,
    /// GenericAll, WriteDacl, AddMember, DCSync, GPLink, Contains...
    pub kind: &'static str,
}

#[derive(Debug, Clone, Default)]
pub struct PasswordPolicy {
    pub min_length: Option<i64>,
    pub history: Option<i64>,
    pub complexity: Option<bool>,
    pub reversible: Option<bool>,
    pub max_age_days: Option<i64>,
    pub lockout_threshold: Option<i64>,
    pub lockout_minutes: Option<i64>,
    pub window_minutes: Option<i64>,
}

pub struct Model<'a> {
    pub raw: &'a RawDomain,
    pub now: i64,
    pub dns: String,
    pub domain_sid: String,
    pub nodes: Vec<Node>,
    pub by_dn: HashMap<String, usize>,
    pub by_sid: HashMap<String, usize>,
    /// Direct members of each group, including accounts whose primary group
    /// it is.
    pub members: Vec<Vec<usize>>,
    pub edges: Vec<ControlEdge>,
    pub sds: HashMap<usize, SecurityDescriptor>,
    /// DCSync rights on the domain head: principal to the rights it holds.
    pub replication: BTreeMap<usize, Vec<&'static str>>,
    /// GPO to the containers it is linked to (enabled links only).
    pub gpo_links: BTreeMap<usize, Vec<usize>>,
    pub domain: Option<usize>,
}

pub(crate) fn parent_dn(dn: &str) -> Option<&str> {
    // RDN values can contain an escaped comma ("\,").
    let bytes = dn.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b',' => return Some(&dn[i + 1..]),
            _ => i += 1,
        }
    }
    None
}

/// The value of the first RDN, unescaped: `CN=Smith\, John,OU=x` gives `Smith, John`.
pub fn rdn_value(dn: &str) -> String {
    let first = match parent_dn(dn) {
        Some(rest) => &dn[..dn.len() - rest.len() - 1],
        None => dn,
    };
    first
        .split_once('=')
        .map(|(_, v)| v)
        .unwrap_or(first)
        .replace('\\', "")
}

fn key(dn: &str) -> String {
    dn.to_ascii_lowercase()
}

impl<'a> Model<'a> {
    pub fn build(raw: &'a RawDomain) -> Model<'a> {
        let now = raw
            .finished_at
            .as_deref()
            .and_then(time::parse_iso)
            .or_else(|| time::parse_iso(&raw.info.started_at))
            .unwrap_or(0);
        let domain_obj = raw.domain.first();
        let mut m = Model {
            raw,
            now,
            dns: raw.info.domain.clone(),
            domain_sid: domain_obj
                .and_then(|d| d.str("objectsid"))
                .unwrap_or_default()
                .to_string(),
            nodes: Vec::new(),
            by_dn: HashMap::new(),
            by_sid: HashMap::new(),
            members: Vec::new(),
            edges: Vec::new(),
            sds: HashMap::new(),
            replication: BTreeMap::new(),
            gpo_links: BTreeMap::new(),
            domain: None,
        };

        if let Some(d) = domain_obj {
            m.domain = Some(m.add(Kind::Domain, d, raw.info.domain.clone()));
        }
        for c in &raw.containers {
            let kind = if c
                .values("objectclass")
                .iter()
                .any(|v| v == "organizationalUnit")
            {
                Kind::Ou
            } else {
                Kind::Container
            };
            m.add(
                kind,
                c,
                c.str("name")
                    .map(str::to_string)
                    .unwrap_or_else(|| rdn_value(c.dn())),
            );
        }
        for (kind, list) in [
            (Kind::User, &raw.users),
            (Kind::Computer, &raw.computers),
            (Kind::Group, &raw.groups),
        ] {
            for o in list {
                let name = o
                    .str("samaccountname")
                    .or(o.str("name"))
                    .map(str::to_string)
                    .unwrap_or_else(|| rdn_value(o.dn()));
                m.add(kind, o, name);
            }
        }
        for g in &raw.gpos {
            let name = g
                .str("displayname")
                .map(str::to_string)
                .unwrap_or_else(|| rdn_value(g.dn()));
            m.add(Kind::Gpo, g, name);
        }
        for t in &raw.trusts {
            let name = t
                .str("trustpartner")
                .or(t.str("name"))
                .map(str::to_string)
                .unwrap_or_default();
            m.add(Kind::Trust, t, name);
        }

        // Parents.
        for i in 0..m.nodes.len() {
            let mut p = parent_dn(&m.nodes[i].dn);
            while let Some(dn) = p {
                if let Some(&j) = m.by_dn.get(&key(dn)) {
                    m.nodes[i].parent = Some(j);
                    break;
                }
                p = parent_dn(dn);
            }
        }

        m.members = vec![Vec::new(); m.nodes.len()];
        m.resolve_membership();
        m.read_links();
        m.read_acls();
        m.mark_tier0();
        m
    }

    fn add(&mut self, kind: Kind, o: &LdapObject, name: String) -> usize {
        let i = self.nodes.len();
        let sid = o
            .str("objectsid")
            .or(o.str("securityidentifier"))
            .map(str::to_string);
        let id = match (&sid, kind) {
            (Some(s), k) if k.is_principal() => s.clone(),
            _ => key(o.dn()),
        };
        let node = Node {
            id,
            kind,
            dn: o.dn().to_string(),
            name,
            sid: if kind.is_principal() { sid } else { None },
            attrs: o.clone(),
            parent: None,
            uac: o.int("useraccountcontrol").unwrap_or(0) as u32,
            pwd_last_set: o.int("pwdlastset").and_then(time::from_filetime),
            last_logon: o.int("lastlogontimestamp").and_then(time::from_filetime),
            created: o.str("whencreated").and_then(time::parse_iso),
            tier0: false,
        };
        self.by_dn.insert(key(&node.dn), i);
        if let Some(s) = &node.sid {
            self.by_sid.insert(s.clone(), i);
        }
        self.nodes.push(node);
        i
    }

    /// A node for a SID with no object of its own (well-known, foreign or deleted).
    pub fn principal(&mut self, sid: &str) -> usize {
        if let Some(&i) = self.by_sid.get(sid) {
            return i;
        }
        let i = self.nodes.len();
        let name = well_known_name(sid)
            .map(str::to_string)
            .unwrap_or_else(|| sid.to_string());
        self.nodes.push(Node {
            id: sid.to_string(),
            kind: Kind::Principal,
            dn: String::new(),
            name,
            sid: Some(sid.to_string()),
            attrs: LdapObject::default(),
            parent: None,
            uac: 0,
            pwd_last_set: None,
            last_logon: None,
            created: None,
            tier0: false,
        });
        self.members.push(Vec::new());
        self.by_sid.insert(sid.to_string(), i);
        i
    }

    fn resolve_membership(&mut self) {
        let groups: Vec<usize> = (0..self.nodes.len())
            .filter(|&i| self.nodes[i].kind == Kind::Group)
            .collect();
        for g in groups {
            let dns: Vec<String> = self.nodes[g]
                .attrs
                .strs("member")
                .iter()
                .map(|s| s.to_string())
                .collect();
            for dn in dns {
                let member = match self.by_dn.get(&key(&dn)) {
                    Some(&i) => i,
                    // Foreign security principals are named by their SID.
                    None => {
                        let cn = rdn_value(&dn);
                        if cn.starts_with("S-1-") {
                            self.principal(&cn)
                        } else {
                            continue;
                        }
                    }
                };
                self.members[g].push(member);
            }
        }
        // Primary group membership is not in `member`.
        for i in 0..self.nodes.len() {
            let Some(rid) = self.nodes[i].attrs.int("primarygroupid") else {
                continue;
            };
            if let Some(g) = self.group_by_rid(rid as u32) {
                if !self.members[g].contains(&i) {
                    self.members[g].push(i);
                }
            }
        }
    }

    pub fn group_by_rid(&self, rid: u32) -> Option<usize> {
        self.by_sid
            .get(&format!("{}-{rid}", self.domain_sid))
            .copied()
    }

    pub fn by_sid(&self, sid: &str) -> Option<usize> {
        self.by_sid.get(sid).copied()
    }

    pub fn group_by_name(&self, sam: &str) -> Option<usize> {
        self.nodes
            .iter()
            .position(|n| n.kind == Kind::Group && n.name.eq_ignore_ascii_case(sam))
    }

    /// Every member of `group`, following nested groups. Cycle-safe.
    pub fn recursive_members(&self, group: usize) -> Vec<usize> {
        let mut seen = HashSet::from([group]);
        let mut out = Vec::new();
        let mut queue = VecDeque::from([group]);
        while let Some(g) = queue.pop_front() {
            for &m in &self.members[g] {
                if seen.insert(m) {
                    out.push(m);
                    if matches!(self.nodes[m].kind, Kind::Group) {
                        queue.push_back(m);
                    }
                }
            }
        }
        out
    }

    /// Groups that make their members Tier 0.
    pub fn tier0_groups(&self) -> Vec<usize> {
        let mut out: Vec<usize> = TIER0_RIDS
            .iter()
            .filter_map(|&r| self.group_by_rid(r))
            .collect();
        out.extend(TIER0_BUILTIN.iter().filter_map(|s| self.by_sid(s)));
        out.extend(self.group_by_name("DnsAdmins"));
        out
    }

    /// Admin groups as the privileged-account checks mean them: Tier 0
    /// groups without the Domain Controllers group.
    pub fn admin_groups(&self) -> Vec<usize> {
        let dcs = self.group_by_rid(516);
        self.tier0_groups()
            .into_iter()
            .filter(|g| Some(*g) != dcs)
            .collect()
    }

    /// Enabled and disabled user accounts that are in an admin group, with
    /// the admin groups each one is in.
    pub fn privileged_users(&self) -> BTreeMap<usize, Vec<usize>> {
        let mut out: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for g in self.admin_groups() {
            for m in self.recursive_members(g) {
                if self.nodes[m].kind == Kind::User {
                    out.entry(m).or_default().push(g);
                }
            }
        }
        out
    }

    fn read_links(&mut self) {
        // gPLink: [LDAP://cn={GUID},cn=policies,cn=system,DC=...;0][...]
        // Option 1 or 3 means the link is disabled.
        let holders: Vec<usize> = (0..self.nodes.len())
            .filter(|&i| matches!(self.nodes[i].kind, Kind::Domain | Kind::Ou))
            .collect();
        for h in holders {
            let Some(link) = self.nodes[h].attrs.str("gplink").map(str::to_string) else {
                continue;
            };
            for part in link.split('[').filter(|p| !p.is_empty()) {
                let part = part.trim_end_matches(']');
                let Some((path, opts)) = part.rsplit_once(';') else {
                    continue;
                };
                let dn = path
                    .trim_start_matches("LDAP://")
                    .trim_start_matches("ldap://");
                let disabled = matches!(opts.trim(), "1" | "3");
                if disabled {
                    continue;
                }
                if let Some(&g) = self.by_dn.get(&key(dn)) {
                    self.gpo_links.entry(g).or_default().push(h);
                    self.edges.push(ControlEdge {
                        from: g,
                        to: h,
                        kind: "GPLink",
                    });
                }
            }
        }
    }

    /// Accounts that are expected to hold strong rights on directory objects
    /// by default. Their ACEs are not findings.
    pub fn is_default_admin(&self, sid: &str) -> bool {
        if matches!(
            sid,
            "S-1-5-18"
                | "S-1-5-9"
                | "S-1-5-10"
                | "S-1-3-0"
                | "S-1-5-32-544"
                | "S-1-5-32-548"
                | "S-1-5-32-549"
                | "S-1-5-32-550"
                | "S-1-5-32-551"
        ) {
            return true;
        }
        match sid
            .strip_prefix(&self.domain_sid)
            .and_then(|r| r.strip_prefix('-'))
        {
            Some(rid) => matches!(
                rid,
                "498" | "512" | "516" | "518" | "519" | "521" | "526" | "527"
            ),
            // Enterprise Admins and Schema Admins live in the forest root domain.
            None => {
                sid.starts_with("S-1-5-21-")
                    && (sid.ends_with("-519") || sid.ends_with("-518") || sid.ends_with("-498"))
            }
        }
    }

    fn read_acls(&mut self) {
        let raw = self.raw;
        for o in &raw.acls {
            if let Some(&target) = self.by_dn.get(&key(o.dn())) {
                self.read_sd(target, o);
            }
        }
    }

    fn read_sd(&mut self, target: usize, o: &LdapObject) {
        use base64::Engine as _;
        let Some(b64) = o.str("ntsecuritydescriptor") else {
            return;
        };
        let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(b64) else {
            return;
        };
        let Some(sd) = sd::parse(&bytes) else { return };
        let class = o.class().and_then(guid::class);
        let is_domain = Some(target) == self.domain;

        let mut found: Vec<(usize, &'static str)> = Vec::new();
        if let Some(owner) = &sd.owner {
            if !self.is_default_admin(owner) {
                let p = self.principal(owner);
                found.push((p, "Owns"));
            }
        }
        for ace in &sd.dacl {
            if ace.kind != AceType::Allow || ace.inherit_only() {
                continue;
            }
            if let Some(inherited) = &ace.inherited_object_type {
                if Some(inherited.as_str()) != class {
                    continue;
                }
            }
            let ot = ace.object_type.as_deref();
            if is_domain && ace.mask & right::CONTROL_ACCESS != 0 {
                if let Some(r) = match ot {
                    Some(guid::GET_CHANGES) => Some("GetChanges"),
                    Some(guid::GET_CHANGES_ALL) => Some("GetChangesAll"),
                    Some(guid::GET_CHANGES_FILTERED) => Some("GetChangesInFilteredSet"),
                    None => Some("AllExtendedRights"),
                    _ => None,
                } {
                    if !self.is_default_admin(&ace.sid) {
                        let p = self.principal(&ace.sid);
                        let rights = self.replication.entry(p).or_default();
                        if !rights.contains(&r) {
                            rights.push(r);
                        }
                    }
                }
            }
            if self.is_default_admin(&ace.sid) {
                continue;
            }
            let mask = ace.mask;
            let mut kinds: Vec<&'static str> = Vec::new();
            if mask & right::GENERIC_ALL != 0
                || (ot.is_none() && mask & right::FULL_CONTROL == right::FULL_CONTROL)
            {
                kinds.push("GenericAll");
            } else {
                if mask & right::WRITE_DACL != 0 {
                    kinds.push("WriteDacl");
                }
                if mask & right::WRITE_OWNER != 0 {
                    kinds.push("WriteOwner");
                }
                if mask & right::GENERIC_WRITE != 0
                    || (ot.is_none() && mask & right::WRITE_PROP != 0)
                {
                    kinds.push("GenericWrite");
                } else if mask & right::WRITE_PROP != 0 {
                    match ot {
                        Some(guid::MEMBER) => kinds.push("AddMember"),
                        Some(guid::KEY_CREDENTIAL_LINK) => kinds.push("AddKeyCredentialLink"),
                        Some(guid::SPN) => kinds.push("WriteSPN"),
                        Some(guid::ALLOWED_TO_ACT) | Some(guid::ACCOUNT_RESTRICTIONS) => {
                            kinds.push("WriteAccountRestrictions")
                        }
                        Some(guid::GP_LINK) => kinds.push("WriteGPLink"),
                        _ => {}
                    }
                }
                if mask & right::SELF != 0 && ot == Some(guid::MEMBER) {
                    kinds.push("AddSelf");
                }
                if mask & right::CONTROL_ACCESS != 0 {
                    match ot {
                        None => kinds.push("AllExtendedRights"),
                        Some(guid::FORCE_CHANGE_PASSWORD) => kinds.push("ForceChangePassword"),
                        _ => {}
                    }
                }
            }
            if kinds.is_empty() {
                continue;
            }
            let p = self.principal(&ace.sid);
            for k in kinds {
                found.push((p, k));
            }
        }
        found.sort();
        found.dedup();
        for (p, kind) in found {
            if p != target {
                self.edges.push(ControlEdge {
                    from: p,
                    to: target,
                    kind,
                });
            }
        }
        if is_domain {
            for (&p, rights) in &self.replication {
                let all = rights.contains(&"GetChangesAll")
                    || rights.contains(&"GetChangesInFilteredSet");
                if rights.contains(&"GetChanges") && all {
                    self.edges.push(ControlEdge {
                        from: p,
                        to: target,
                        kind: "DCSync",
                    });
                }
            }
        }
        self.sds.insert(target, sd);
    }

    fn mark_tier0(&mut self) {
        let mut t0: HashSet<usize> = HashSet::new();
        for g in self.tier0_groups() {
            t0.insert(g);
            t0.extend(self.recursive_members(g));
        }
        t0.extend(self.domain);
        if let Some(k) = self.by_sid(&format!("{}-502", self.domain_sid)) {
            t0.insert(k);
        }
        let dcs: Vec<usize> = (0..self.nodes.len())
            .filter(|&i| self.nodes[i].is_dc())
            .collect();
        for &dc in &dcs {
            t0.insert(dc);
            if let Some(p) = self.nodes[dc].parent {
                if self.nodes[p].kind == Kind::Ou {
                    t0.insert(p);
                    self.edges.push(ControlEdge {
                        from: p,
                        to: dc,
                        kind: "Contains",
                    });
                }
            }
        }
        for (i, n) in self.nodes.iter().enumerate() {
            if n.kind == Kind::Container && n.name.eq_ignore_ascii_case("AdminSDHolder") {
                t0.insert(i);
            }
        }
        // GPOs that apply to Tier 0 containers.
        for (&gpo, targets) in &self.gpo_links {
            if targets.iter().any(|t| t0.contains(t)) {
                t0.insert(gpo);
            }
        }
        for i in t0 {
            self.nodes[i].tier0 = true;
        }
    }

    pub fn days_since(&self, t: Option<i64>) -> Option<i64> {
        t.map(|t| time::days_between(t, self.now))
    }

    pub fn password_policy(&self) -> PasswordPolicy {
        let Some(d) = self.raw.domain.first() else {
            return PasswordPolicy::default();
        };
        let props = d.int("pwdproperties");
        PasswordPolicy {
            min_length: d.int("minpwdlength"),
            history: d.int("pwdhistorylength"),
            complexity: props.map(|p| p & 1 != 0),
            reversible: props.map(|p| p & 16 != 0),
            max_age_days: d
                .int("maxpwdage")
                .and_then(time::from_interval)
                .map(|s| s / time::DAY),
            lockout_threshold: d.int("lockoutthreshold"),
            lockout_minutes: d
                .int("lockoutduration")
                .and_then(time::from_interval)
                .map(|s| s / 60),
            window_minutes: d
                .int("lockoutobservationwindow")
                .and_then(time::from_interval)
                .map(|s| s / 60),
        }
    }

    pub fn location(&self, i: usize) -> String {
        self.nodes[i].dn.clone()
    }
}
