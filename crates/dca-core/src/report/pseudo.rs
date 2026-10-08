//! Replaces names with pseudonyms for reports shared with third parties.
//! The same object always gets the same pseudonym (a hash of its name), so
//! two reports of the same environment still line up. Built-in accounts,
//! groups and containers keep their names: they identify nobody.

use std::collections::HashMap;

use crate::compare::Comparison;
use crate::results::{AssessmentView, Finding};

/// FNV-1a: stable across runs and platforms, unlike the std hasher.
fn hash(s: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.to_lowercase().bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{:06X}", h & 0xFF_FFFF)
}

const WELL_KNOWN: [&str; 30] = [
    "administrator",
    "guest",
    "krbtgt",
    "users",
    "builtin",
    "computers",
    "domain controllers",
    "system",
    "domain admins",
    "enterprise admins",
    "schema admins",
    "administrators",
    "domain users",
    "domain computers",
    "domain guests",
    "account operators",
    "server operators",
    "backup operators",
    "print operators",
    "dnsadmins",
    "protected users",
    "group policy creator owners",
    "cert publishers",
    "everyone",
    "authenticated users",
    "key admins",
    "enterprise key admins",
    "read-only domain controllers",
    "managed service accounts",
    "foreignsecurityprincipals",
];

fn prefix(kind: &str) -> &'static str {
    match kind {
        "user" => "User",
        "computer" => "Computer",
        "group" => "Group",
        "ou" => "OU",
        "gpo" => "GPO",
        "trust" => "Trust",
        "domain" => "Domain",
        "client" => "Client",
        "account" => "Account",
        _ => "Object",
    }
}

fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Bytes of `text` that `name` (lower case) matches at its start, ignoring
/// case, when the match ends at a word boundary.
fn match_at(text: &str, name: &str) -> Option<usize> {
    let mut used = 0;
    let mut want = name.chars();
    let mut have = text.char_indices();
    loop {
        let Some(w) = want.next() else {
            let next = text[used..].chars().next();
            return (!next.is_some_and(is_word)).then_some(used);
        };
        let (i, c) = have.next()?;
        let mut lower = c.to_lowercase();
        if lower.next() != Some(w) || lower.next().is_some() {
            return None;
        }
        used = i + c.len_utf8();
    }
}

#[derive(Default)]
pub struct Pseudonyms {
    /// First word (lower case) to candidate names (lower case) and their
    /// pseudonyms, longest first.
    by_first: HashMap<String, Vec<(String, String)>>,
    ids: HashMap<String, String>,
}

impl Pseudonyms {
    fn add(&mut self, original: &str, pseudo: &str) {
        let lower = original.trim().to_lowercase();
        if lower.len() < 2 || WELL_KNOWN.contains(&lower.as_str()) {
            return;
        }
        let first: String = lower.chars().take_while(|c| is_word(*c)).collect();
        if first.is_empty() {
            return;
        }
        let list = self.by_first.entry(first).or_default();
        if list.iter().any(|(o, _)| *o == lower) {
            return;
        }
        list.push((lower, pseudo.to_string()));
        list.sort_by_key(|(o, _)| std::cmp::Reverse(o.len()));
    }

    fn name_for(&self, original: &str) -> Option<&str> {
        let lower = original.trim().to_lowercase();
        let first: String = lower.chars().take_while(|c| is_word(*c)).collect();
        self.by_first
            .get(&first)?
            .iter()
            .find(|(o, _)| *o == lower)
            .map(|(_, p)| p.as_str())
    }

    fn add_domain(&mut self, dns: &str) {
        let dns = dns.trim().to_lowercase();
        if dns.is_empty() || self.name_for(&dns).is_some() {
            return;
        }
        let label = format!("domain{}", hash(&dns).to_lowercase());
        let pseudo = format!("{label}.example");
        self.add(&dns, &pseudo);
        // As a DN (DC=corp,DC=example,DC=com) and as a NetBIOS-style prefix.
        let dn = |d: &str| {
            d.split('.')
                .map(|p| format!("dc={p}"))
                .collect::<Vec<_>>()
                .join(",")
        };
        self.add(&dn(&dns), &dn(&pseudo).replace("dc=", "DC="));
        if let Some(first) = dns.split('.').next() {
            self.add(first, &label.to_uppercase());
        }
    }

    /// Builds the name list from everything the view names.
    pub fn new(view: &AssessmentView, comparison: Option<&Comparison>) -> Pseudonyms {
        let mut p = Pseudonyms::default();
        let runs = view
            .runs
            .iter()
            .chain(comparison.into_iter().flat_map(|c| [&c.earlier, &c.later]));
        for r in runs {
            for d in &r.manifest.scope.domains {
                p.add_domain(d);
            }
            if let Some(t) = &r.manifest.scope.tenant {
                p.add_domain(t);
            }
        }
        if let Some(dir) = &view.directory {
            for s in &dir.sources {
                p.add_domain(&s.name);
            }
            for o in &dir.objects {
                p.ids.insert(o.id.clone(), format!("obj-{}", hash(&o.id)));
                if o.kind == "domain" {
                    p.add_domain(&o.name);
                    continue;
                }
                let rid = o
                    .attributes
                    .get("objectSid")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.rsplit('-').next())
                    .and_then(|r| r.parse::<u32>().ok());
                let builtin = rid.is_some_and(|r| r < 1000)
                    || WELL_KNOWN.contains(&o.name.to_lowercase().as_str());
                let pseudo = if builtin {
                    o.name.clone()
                } else {
                    format!(
                        "{}-{}",
                        prefix(&o.kind),
                        hash(&format!("{}|{}", o.kind, o.name))
                    )
                };
                if builtin {
                    continue;
                }
                p.add(&o.name, &pseudo);
                let short = o.name.trim_end_matches('$');
                if short != o.name {
                    p.add(short, pseudo.trim_end_matches('$'));
                }
                for key in ["sAMAccountName", "displayName"] {
                    if let Some(v) = o.attributes.get(key).and_then(|v| v.as_str()) {
                        p.add(v, &pseudo);
                        p.add(v.trim_end_matches('$'), &pseudo);
                    }
                }
                for key in ["userPrincipalName", "mail", "dNSHostName"] {
                    if let Some(v) = o.attributes.get(key).and_then(|v| v.as_str()) {
                        let host = v.split(['@', '.']).next().unwrap_or(v);
                        let rest = &v[host.len()..];
                        let rest = p.text(rest);
                        p.add(v, &format!("{}{rest}", pseudo.to_lowercase()));
                    }
                }
            }
        }
        // Accounts, clients and DCs named only in findings and paths.
        let findings = view.findings.iter().chain(
            comparison
                .into_iter()
                .flat_map(|c| c.changes.iter().map(|ch| &ch.finding)),
        );
        let mut extra = Vec::new();
        for f in findings {
            for a in &f.affected {
                if a.object.is_none() && p.name_for(&a.name).is_none() {
                    extra.push((a.name.clone(), a.kind.clone()));
                }
            }
        }
        for path in &view.paths {
            for s in &path.steps {
                if p.name_for(&s.name).is_none() {
                    extra.push((s.name.clone(), s.kind.clone()));
                }
            }
        }
        for (name, kind) in extra {
            if let Some(host) = name.split_once('.').filter(|_| kind == "computer") {
                p.add_domain(host.1);
            }
            let pseudo = format!("{}-{}", prefix(&kind), hash(&format!("{kind}|{name}")));
            p.add(&name, &pseudo);
        }
        p
    }

    /// Replaces every known name in free text, whole words only, ignoring
    /// case.
    pub fn text(&self, s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let mut i = 0;
        while i < s.len() {
            let rest = &s[i..];
            let at_start = !s[..i].chars().next_back().is_some_and(is_word);
            if at_start && rest.chars().next().is_some_and(is_word) {
                let word: String = rest.chars().take_while(|c| is_word(*c)).collect();
                let hit = self.by_first.get(&word.to_lowercase()).and_then(|list| {
                    list.iter()
                        .find_map(|(o, pseudo)| match_at(rest, o).map(|n| (n, pseudo)))
                });
                if let Some((n, pseudo)) = hit {
                    out.push_str(pseudo);
                    i += n;
                } else {
                    out.push_str(&word);
                    i += word.len();
                }
                continue;
            }
            let ch = rest.chars().next().unwrap_or(' ');
            out.push(ch);
            i += ch.len_utf8();
        }
        out
    }

    fn id(&self, id: &mut String) {
        if let Some(p) = self.ids.get(id.as_str()) {
            *id = p.clone();
        }
    }

    fn opt(&self, s: &mut Option<String>) {
        if let Some(v) = s {
            *v = self.text(v);
        }
    }

    fn finding(&self, f: &mut Finding) {
        f.run = self.text(&f.run);
        for a in &mut f.affected {
            a.name = self.text(&a.name);
            self.opt(&mut a.location);
            self.opt(&mut a.reason);
            if let Some(o) = &mut a.object {
                self.id(o);
            }
        }
        self.opt(&mut f.expected);
        self.opt(&mut f.found);
        self.opt(&mut f.raw);
        self.opt(&mut f.note);
        for e in &mut f.evidence {
            e.value = self.text(&e.value);
        }
    }

    fn run(&self, r: &mut crate::results::RunInfo) {
        r.path = String::new();
        for d in &mut r.manifest.scope.domains {
            *d = self.text(d);
        }
        self.opt(&mut r.manifest.scope.tenant);
    }

    pub fn apply(&self, view: &mut AssessmentView, comparison: Option<&mut Comparison>) {
        for r in &mut view.runs {
            self.run(r);
        }
        for f in &mut view.findings {
            self.finding(f);
        }
        for path in &mut view.paths {
            path.title = self.text(&path.title);
            for s in &mut path.steps {
                s.name = self.text(&s.name);
                if let Some(o) = &mut s.object {
                    self.id(o);
                }
            }
        }
        if let Some(dir) = &mut view.directory {
            for s in &mut dir.sources {
                s.name = self.text(&s.name);
            }
            const KEEP: [&str; 10] = [
                "whenCreated",
                "adminCount",
                "userAccountControl",
                "primaryGroupID",
                "msDS-SupportedEncryptionTypes",
                "operatingSystem",
                "operatingSystemVersion",
                "groupType",
                "trustDirection",
                "trustType",
            ];
            for o in &mut dir.objects {
                o.name = self.text(&o.name);
                o.display_name = None;
                o.source = self.text(&o.source);
                self.id(&mut o.id);
                if let Some(p) = &mut o.parent {
                    self.id(p);
                }
                for f in &mut o.flags {
                    f.text = self.text(&f.text);
                }
                o.attributes.retain(|k, _| KEEP.contains(&k.as_str()));
            }
            for e in &mut dir.edges {
                self.id(&mut e.from);
                self.id(&mut e.to);
                self.opt(&mut e.note);
            }
        }
        if let Some(c) = comparison {
            self.run(&mut c.earlier);
            self.run(&mut c.later);
            for ch in &mut c.changes {
                self.finding(&mut ch.finding);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(pairs: &[(&str, &str)]) -> Pseudonyms {
        let mut p = Pseudonyms::default();
        p.add_domain("corp.example.com");
        for (o, n) in pairs {
            p.add(o, n);
        }
        p
    }

    #[test]
    fn replaces_whole_names_only() {
        let p = names(&[
            ("svc-sql", "User-1"),
            ("IT Admins", "Group-2"),
            ("dc01.corp.example.com", "computer-3.x"),
        ]);
        assert_eq!(
            p.text("svc-sql can add members to IT Admins"),
            "User-1 can add members to Group-2"
        );
        assert_eq!(
            p.text("svc-sql2 and IT Administrators"),
            "svc-sql2 and IT Administrators"
        );
        assert_eq!(
            p.text("Read on DC01.corp.example.com"),
            "Read on computer-3.x"
        );
        let dn = p.text("CN=svc-sql,CN=Users,DC=corp,DC=example,DC=com");
        assert!(dn.starts_with("CN=User-1,CN=Users,DC=domain"), "{dn}");
        assert!(!dn.to_lowercase().contains("corp"), "{dn}");
        assert!(p.text("CORP\\auditor").starts_with("DOMAIN"));
        assert_eq!(p.text("Domain Admins"), "Domain Admins");
    }

    #[test]
    fn pseudonyms_are_stable() {
        assert_eq!(hash("svc-sql"), hash("SVC-SQL"));
        assert_ne!(hash("svc-sql"), hash("svc-web"));
    }
}
