//! Attack paths: shortest chains of membership and control edges from
//! low-privilege starting points to Tier 0.

use std::collections::{HashMap, VecDeque};

use super::model::{self, uac, Kind, Model};
use crate::catalog::Severity;
use crate::results::{AttackPath, PathStep};

/// Edge kinds that give the source control over the target.
pub const CONTROL: [&str; 16] = [
    "GenericAll",
    "GenericWrite",
    "WriteDacl",
    "WriteOwner",
    "Owns",
    "AllExtendedRights",
    "AddMember",
    "AddSelf",
    "ForceChangePassword",
    "AddKeyCredentialLink",
    "WriteSPN",
    "WriteAccountRestrictions",
    "WriteGPLink",
    "DCSync",
    "GPLink",
    "Contains",
];

const MAX_ACCOUNT_PATHS: usize = 5;

/// A path as (node, edge kind into the next node) pairs.
type Hops = Vec<(usize, Option<&'static str>)>;

struct Graph {
    out: Vec<Vec<(usize, &'static str)>>,
}

impl Graph {
    fn build(m: &Model) -> Graph {
        let mut out = vec![Vec::new(); m.nodes.len()];
        for (g, members) in m.members.iter().enumerate() {
            for &mbr in members {
                out[mbr].push((g, "MemberOf"));
            }
        }
        for e in &m.edges {
            if CONTROL.contains(&e.kind) {
                out[e.from].push((e.to, e.kind));
            }
        }
        Graph { out }
    }

    /// Shortest path from `start` to the nearest Tier 0 node, as (node, edge
    /// kind into the next node) pairs.
    fn shortest(&self, m: &Model, start: usize) -> Option<Hops> {
        self.shortest_to(m, start, |n| m.nodes[n].tier0)
    }

    /// Shortest path from `start` to the nearest node where `goal` holds.
    fn shortest_to(&self, m: &Model, start: usize, goal: impl Fn(usize) -> bool) -> Option<Hops> {
        let mut prev: HashMap<usize, (usize, &'static str)> = HashMap::new();
        let mut queue = VecDeque::from([start]);
        let mut seen = vec![false; m.nodes.len()];
        seen[start] = true;
        while let Some(n) = queue.pop_front() {
            if n != start && goal(n) {
                let mut path = vec![(n, None)];
                let mut cur = n;
                while let Some(&(p, kind)) = prev.get(&cur) {
                    path.push((p, Some(kind)));
                    cur = p;
                }
                path.reverse();
                return Some(path);
            }
            for &(next, kind) in &self.out[n] {
                if !seen[next] {
                    seen[next] = true;
                    prev.insert(next, (n, kind));
                    queue.push_back(next);
                }
            }
        }
        None
    }
}

fn label(kind: &str) -> &'static str {
    match kind {
        "MemberOf" => "Member of",
        "GenericAll" => "Full control",
        "GenericWrite" => "Write all properties",
        "WriteDacl" => "Modify permissions",
        "WriteOwner" => "Take ownership",
        "Owns" => "Owner",
        "AllExtendedRights" => "All extended rights",
        "AddMember" => "Add members",
        "AddSelf" => "Add self",
        "ForceChangePassword" => "Reset password",
        "AddKeyCredentialLink" => "Shadow credentials",
        "WriteSPN" => "Write SPN",
        "WriteAccountRestrictions" => "RBCD",
        "WriteGPLink" => "Link a GPO",
        "DCSync" => "DCSync",
        "GPLink" => "GPO applies to",
        "Contains" => "Contains",
        _ => "Controls",
    }
}

/// The check whose fix removes this edge.
fn check_for(m: &Model, kind: &str, to: usize) -> Option<&'static str> {
    let t = &m.nodes[to];
    Some(match kind {
        "MemberOf" | "GPLink" | "Contains" => return None,
        "DCSync" => "AD-ACL-002",
        "ForceChangePassword" => "AD-ACL-008",
        "WriteSPN" => "AD-ACL-009",
        "AddKeyCredentialLink" => "AD-ACL-010",
        "WriteAccountRestrictions" => "AD-ACL-011",
        "WriteGPLink" => "AD-ACL-025",
        _ if Some(to) == m.domain => "AD-ACL-001",
        _ if t.kind == Kind::Container && t.name.eq_ignore_ascii_case("AdminSDHolder") => {
            "AD-ACL-003"
        }
        _ if t.is_dc() || t.kind == Kind::Ou => "AD-ACL-004",
        _ if t.kind == Kind::Group => "AD-ACL-005",
        _ if t.kind == Kind::Gpo => "AD-ACL-006",
        "Owns" => "AD-ACL-016",
        _ if t.kind == Kind::User => "AD-ACL-008",
        _ => return None,
    })
}

fn to_path(
    m: &Model,
    nodes: &[(usize, Option<&'static str>)],
    title: String,
    severity: Severity,
    first_check: Option<&'static str>,
) -> AttackPath {
    let steps = nodes
        .iter()
        .map(|&(n, via)| PathStep {
            name: m.nodes[n].name.clone(),
            kind: m.nodes[n].kind.ui().to_string(),
            object: Some(m.nodes[n].id.clone()),
            via: via.map(|v| label(v).to_string()),
        })
        .collect();
    let mut checks: Vec<String> = first_check.into_iter().map(str::to_string).collect();
    for w in nodes.windows(2) {
        if let (Some(kind), (to, _)) = (w[0].1, w[1]) {
            if let Some(c) = check_for(m, kind, to) {
                if !checks.iter().any(|x| x == c) {
                    checks.push(c.to_string());
                }
            }
        }
    }
    AttackPath {
        title,
        severity,
        steps,
        checks,
    }
}

fn hops(n: usize) -> String {
    if n == 1 {
        "1 step".into()
    } else {
        format!("{n} steps")
    }
}

/// The shortest chain of membership and control edges from `start` to
/// `target`, as text: "Domain Users, member of Helpdesk, reset password of
/// adm-jsmith". `None` when there is none.
pub fn chain(m: &Model, start: usize, target: usize) -> Option<String> {
    let p = Graph::build(m).shortest_to(m, start, |n| n == target)?;
    let mut text = m.nodes[p[0].0].name.clone();
    for w in p.windows(2) {
        if let Some(kind) = w[0].1 {
            text.push_str(&format!(
                " → {} → {}",
                label(kind).to_lowercase(),
                m.nodes[w[1].0].name
            ));
        }
    }
    Some(text)
}

pub fn find(m: &Model) -> Vec<AttackPath> {
    let g = Graph::build(m);
    let mut out: Vec<AttackPath> = Vec::new();

    let mut broad: Vec<(usize, &str)> = Vec::new();
    for (sid, what) in [
        (model::EVERYONE, "Everyone"),
        (model::AUTHENTICATED_USERS, "Any authenticated user"),
    ] {
        if let Some(i) = m.by_sid(sid) {
            broad.push((i, what));
        }
    }
    if let Some(i) = m.group_by_rid(513) {
        broad.push((i, "Any domain user"));
    }
    if let Some(i) = m.group_by_rid(515) {
        broad.push((i, "Any domain computer"));
    }
    for (start, who) in broad {
        if let Some(p) = g.shortest(m, start) {
            let target = &m.nodes[p.last().unwrap().0].name;
            let title = format!("{who} can take over {target} in {}", hops(p.len() - 1));
            out.push(to_path(
                m,
                &p,
                title,
                Severity::Critical,
                Some("AD-ACL-015"),
            ));
        }
    }

    // Accounts any domain user can compromise offline.
    let mut accounts: Vec<(usize, Hops, &'static str, &'static str)> = Vec::new();
    for i in 0..m.nodes.len() {
        let n = &m.nodes[i];
        if n.kind != Kind::User || !n.enabled() || n.tier0 {
            continue;
        }
        let (how, check) = if n.flag(uac::DONT_REQ_PREAUTH) {
            ("AS-REP roastable", "AD-KRB-002")
        } else if !n.spns().is_empty() {
            ("Kerberoastable", "AD-KRB-001")
        } else {
            continue;
        };
        if let Some(p) = g.shortest(m, i) {
            accounts.push((i, p, how, check));
        }
    }
    accounts.sort_by_key(|(_, p, ..)| p.len());
    for (i, p, how, check) in accounts.into_iter().take(MAX_ACCOUNT_PATHS) {
        let target = &m.nodes[p.last().unwrap().0].name;
        let title = format!(
            "{how} account {} leads to {target} in {}",
            m.nodes[i].name,
            hops(p.len() - 1)
        );
        out.push(to_path(m, &p, title, Severity::High, Some(check)));
    }
    out
}
