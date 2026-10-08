//! Parser for self-relative security descriptors (`nTSecurityDescriptor`),
//! as [MS-DTYP] 2.4.6 defines them. The owner and the DACL are read for
//! permissions; the SACL only for the audit entries of a few sensitive
//! objects, which the collector reads separately.

/// Access mask bits used by directory ACEs ([MS-ADTS] 5.1.3.2).
pub mod right {
    pub const CREATE_CHILD: u32 = 0x0000_0001;
    pub const SELF: u32 = 0x0000_0008;
    pub const WRITE_PROP: u32 = 0x0000_0020;
    pub const CONTROL_ACCESS: u32 = 0x0000_0100;
    pub const WRITE_DACL: u32 = 0x0004_0000;
    pub const WRITE_OWNER: u32 = 0x0008_0000;
    pub const GENERIC_ALL: u32 = 0x1000_0000;
    pub const GENERIC_WRITE: u32 = 0x4000_0000;
    /// Every standard and directory-specific right: what "Full control" sets.
    pub const FULL_CONTROL: u32 = 0x000F_01FF;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AceType {
    Allow,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ace {
    pub kind: AceType,
    pub flags: u8,
    pub mask: u32,
    /// The property, property set, extended right or child class the ACE is
    /// limited to, as a lower-case GUID string.
    pub object_type: Option<String>,
    /// For inheritable ACEs: the child class they apply to.
    pub inherited_object_type: Option<String>,
    pub sid: String,
}

pub const ACE_INHERIT_ONLY: u8 = 0x08;
pub const ACE_INHERITED: u8 = 0x10;

impl Ace {
    pub fn inherit_only(&self) -> bool {
        self.flags & ACE_INHERIT_ONLY != 0
    }
}

#[derive(Debug, Clone, Default)]
pub struct SecurityDescriptor {
    pub owner: Option<String>,
    pub dacl: Vec<Ace>,
    /// SE_DACL_PROTECTED: inheritance from the parent is blocked.
    pub protected: bool,
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// A binary SID at `at` as `S-1-...`.
pub fn sid_at(b: &[u8], at: usize) -> Option<String> {
    let revision = *b.get(at)?;
    let count = *b.get(at + 1)? as usize;
    if revision != 1 || count > 15 {
        return None;
    }
    let auth = b.get(at + 2..at + 8)?;
    let authority = auth.iter().fold(0u64, |acc, x| (acc << 8) | u64::from(*x));
    let mut s = format!("S-1-{authority}");
    for i in 0..count {
        s.push('-');
        s.push_str(&u32_at(b, at + 8 + i * 4)?.to_string());
    }
    Some(s)
}

/// A binary GUID (mixed-endian, as Windows stores it) as a lower-case string.
pub fn guid_at(b: &[u8], at: usize) -> Option<String> {
    let g = b.get(at..at + 16)?;
    Some(format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        u32::from_le_bytes(g[0..4].try_into().ok()?),
        u16::from_le_bytes(g[4..6].try_into().ok()?),
        u16::from_le_bytes(g[6..8].try_into().ok()?),
        g[8],
        g[9],
        g[10],
        g[11],
        g[12],
        g[13],
        g[14],
        g[15]
    ))
}

const ACCESS_ALLOWED: u8 = 0x00;
const ACCESS_DENIED: u8 = 0x01;
const ACCESS_ALLOWED_OBJECT: u8 = 0x05;
const ACCESS_DENIED_OBJECT: u8 = 0x06;
const OBJECT_TYPE_PRESENT: u32 = 0x1;
const INHERITED_OBJECT_TYPE_PRESENT: u32 = 0x2;
const SE_DACL_PRESENT: u16 = 0x0004;
const SE_DACL_PROTECTED: u16 = 0x1000;

fn parse_ace(b: &[u8], at: usize) -> Option<(Option<Ace>, usize)> {
    let ace_type = *b.get(at)?;
    let flags = *b.get(at + 1)?;
    let size = u16_at(b, at + 2)? as usize;
    if size < 8 {
        return None;
    }
    let body = at + 4;
    let ace = match ace_type {
        ACCESS_ALLOWED | ACCESS_DENIED => Some(Ace {
            kind: if ace_type == ACCESS_ALLOWED {
                AceType::Allow
            } else {
                AceType::Deny
            },
            flags,
            mask: u32_at(b, body)?,
            object_type: None,
            inherited_object_type: None,
            sid: sid_at(b, body + 4)?,
        }),
        ACCESS_ALLOWED_OBJECT | ACCESS_DENIED_OBJECT => {
            let mask = u32_at(b, body)?;
            let present = u32_at(b, body + 4)?;
            let mut p = body + 8;
            let object_type = if present & OBJECT_TYPE_PRESENT != 0 {
                p += 16;
                Some(guid_at(b, p - 16)?)
            } else {
                None
            };
            let inherited_object_type = if present & INHERITED_OBJECT_TYPE_PRESENT != 0 {
                p += 16;
                Some(guid_at(b, p - 16)?)
            } else {
                None
            };
            Some(Ace {
                kind: if ace_type == ACCESS_ALLOWED_OBJECT {
                    AceType::Allow
                } else {
                    AceType::Deny
                },
                flags,
                mask,
                object_type,
                inherited_object_type,
                sid: sid_at(b, p)?,
            })
        }
        // Audit, callback and other ACE types do not grant access here.
        _ => None,
    };
    Some((ace, size))
}

/// Parses a self-relative security descriptor. Returns `None` when the bytes
/// are not one.
pub fn parse(b: &[u8]) -> Option<SecurityDescriptor> {
    if b.len() < 20 || b[0] != 1 {
        return None;
    }
    let control = u16_at(b, 2)?;
    let owner_at = u32_at(b, 4)? as usize;
    let dacl_at = u32_at(b, 16)? as usize;
    let mut sd = SecurityDescriptor {
        owner: if owner_at != 0 {
            sid_at(b, owner_at)
        } else {
            None
        },
        dacl: Vec::new(),
        protected: control & SE_DACL_PROTECTED != 0,
    };
    if control & SE_DACL_PRESENT != 0 && dacl_at != 0 {
        let count = u16_at(b, dacl_at + 4)? as usize;
        let mut at = dacl_at + 8;
        for _ in 0..count {
            let (ace, size) = parse_ace(b, at)?;
            sd.dacl.extend(ace);
            at += size;
        }
    }
    Some(sd)
}

/// One audit entry of a SACL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditAce {
    pub sid: String,
    pub mask: u32,
    pub success: bool,
    pub failure: bool,
}

const SYSTEM_AUDIT: u8 = 0x02;
const SYSTEM_AUDIT_OBJECT: u8 = 0x07;
const SE_SACL_PRESENT: u16 = 0x0010;
const SUCCESSFUL_ACCESS: u8 = 0x40;
const FAILED_ACCESS: u8 = 0x80;

/// The audit entries of a self-relative security descriptor's SACL. `None`
/// when the bytes are not a descriptor or it carries no SACL.
pub fn parse_sacl(b: &[u8]) -> Option<Vec<AuditAce>> {
    if b.len() < 20 || b[0] != 1 {
        return None;
    }
    let control = u16_at(b, 2)?;
    let sacl_at = u32_at(b, 12)? as usize;
    if control & SE_SACL_PRESENT == 0 || sacl_at == 0 {
        return None;
    }
    let count = u16_at(b, sacl_at + 4)? as usize;
    let mut at = sacl_at + 8;
    let mut out = Vec::new();
    for _ in 0..count {
        let kind = *b.get(at)?;
        let flags = *b.get(at + 1)?;
        let size = u16_at(b, at + 2)? as usize;
        if size < 8 {
            return None;
        }
        let mask = u32_at(b, at + 4)?;
        let sid_at_pos = match kind {
            SYSTEM_AUDIT => Some(at + 8),
            SYSTEM_AUDIT_OBJECT => {
                let present = u32_at(b, at + 8)?;
                let mut p = at + 12;
                if present & OBJECT_TYPE_PRESENT != 0 {
                    p += 16;
                }
                if present & INHERITED_OBJECT_TYPE_PRESENT != 0 {
                    p += 16;
                }
                Some(p)
            }
            _ => None,
        };
        if let Some(p) = sid_at_pos {
            out.push(AuditAce {
                sid: sid_at(b, p)?,
                mask,
                success: flags & SUCCESSFUL_ACCESS != 0,
                failure: flags & FAILED_ACCESS != 0,
            });
        }
        at += size;
    }
    Some(out)
}

/// Builds self-relative security descriptors for tests and fixtures.
#[cfg(test)]
pub mod build {
    pub fn sid(s: &str) -> Vec<u8> {
        let parts: Vec<u64> = s
            .trim_start_matches("S-")
            .split('-')
            .map(|p| p.parse().unwrap())
            .collect();
        let mut b = vec![parts[0] as u8, (parts.len() - 2) as u8];
        b.extend_from_slice(&parts[1].to_be_bytes()[2..]);
        for sub in &parts[2..] {
            b.extend_from_slice(&(*sub as u32).to_le_bytes());
        }
        b
    }

    pub fn guid(g: &str) -> Vec<u8> {
        let h: String = g.chars().filter(|c| *c != '-').collect();
        let bytes: Vec<u8> = (0..16)
            .map(|i| u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap())
            .collect();
        let mut out = Vec::new();
        out.extend(bytes[0..4].iter().rev());
        out.extend(bytes[4..6].iter().rev());
        out.extend(bytes[6..8].iter().rev());
        out.extend(&bytes[8..16]);
        out
    }

    /// (allow, flags, mask, object type, sid)
    pub fn sd(owner: &str, aces: &[(bool, u8, u32, Option<&str>, &str)]) -> Vec<u8> {
        let mut acl_body = Vec::new();
        for (allow, flags, mask, object, who) in aces {
            let mut body = mask.to_le_bytes().to_vec();
            let ace_type = match (allow, object.is_some()) {
                (true, false) => 0u8,
                (false, false) => 1,
                (true, true) => 5,
                (false, true) => 6,
            };
            if let Some(o) = object {
                body.extend_from_slice(&1u32.to_le_bytes());
                body.extend(guid(o));
            }
            body.extend(sid(who));
            let size = (4 + body.len()) as u16;
            acl_body.push(ace_type);
            acl_body.push(*flags);
            acl_body.extend_from_slice(&size.to_le_bytes());
            acl_body.extend(body);
        }
        let owner = sid(owner);
        let owner_at = 20u32;
        let dacl_at = owner_at + owner.len() as u32;
        let mut b = vec![1u8, 0];
        b.extend_from_slice(&0x8004u16.to_le_bytes()); // self-relative, DACL present
        b.extend_from_slice(&owner_at.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&dacl_at.to_le_bytes());
        b.extend(owner);
        b.extend_from_slice(&[4u8, 0]);
        b.extend_from_slice(&((8 + acl_body.len()) as u16).to_le_bytes());
        b.extend_from_slice(&(aces.len() as u16).to_le_bytes());
        b.extend_from_slice(&[0u8, 0]);
        b.extend(acl_body);
        b
    }

    /// A descriptor with only a SACL: (audit flags, mask, sid), plain and
    /// object audit entries.
    pub fn sacl(aces: &[(u8, u32, bool, &str)]) -> Vec<u8> {
        let mut acl_body = Vec::new();
        for (flags, mask, object, who) in aces {
            let mut body = mask.to_le_bytes().to_vec();
            if *object {
                body.extend_from_slice(&1u32.to_le_bytes());
                body.extend(guid("bf9679c0-0de6-11d0-a285-00aa003049e2"));
            }
            body.extend(sid(who));
            acl_body.push(if *object { 7 } else { 2 });
            acl_body.push(*flags);
            acl_body.extend_from_slice(&((4 + body.len()) as u16).to_le_bytes());
            acl_body.extend(body);
        }
        let mut b = vec![1u8, 0];
        b.extend_from_slice(&0x8010u16.to_le_bytes()); // self-relative, SACL present
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&20u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&[4u8, 0]);
        b.extend_from_slice(&((8 + acl_body.len()) as u16).to_le_bytes());
        b.extend_from_slice(&(aces.len() as u16).to_le_bytes());
        b.extend_from_slice(&[0u8, 0]);
        b.extend(acl_body);
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_owner_and_object_aces() {
        let bytes = build::sd(
            "S-1-5-21-1-2-3-512",
            &[
                (true, 0, right::GENERIC_ALL, None, "S-1-5-18"),
                (
                    true,
                    0x12,
                    right::CONTROL_ACCESS,
                    Some("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"),
                    "S-1-5-21-1-2-3-1104",
                ),
                (
                    false,
                    0,
                    right::WRITE_PROP,
                    Some("bf9679c0-0de6-11d0-a285-00aa003049e2"),
                    "S-1-1-0",
                ),
            ],
        );
        let sd = parse(&bytes).unwrap();
        assert_eq!(sd.owner.as_deref(), Some("S-1-5-21-1-2-3-512"));
        assert_eq!(sd.dacl.len(), 3);
        assert_eq!(sd.dacl[0].sid, "S-1-5-18");
        assert_eq!(
            sd.dacl[1].object_type.as_deref(),
            Some("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")
        );
        assert_eq!(sd.dacl[1].flags & ACE_INHERITED, ACE_INHERITED);
        assert_eq!(sd.dacl[2].kind, AceType::Deny);
        assert!(!sd.protected);
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse(&[0u8; 4]).is_none());
        assert!(parse(&[2u8; 40]).is_none());
    }

    #[test]
    fn sacl_audit_entries_are_read() {
        let b = build::sacl(&[
            (0x40, 0x20, false, "S-1-1-0"),
            (0x80 | 0x40, 0x10_0000, true, "S-1-5-11"),
        ]);
        let aces = parse_sacl(&b).unwrap();
        assert_eq!(aces.len(), 2);
        assert_eq!(
            aces[0],
            AuditAce {
                sid: "S-1-1-0".into(),
                mask: 0x20,
                success: true,
                failure: false
            }
        );
        assert!(aces[1].failure && aces[1].success && aces[1].sid == "S-1-5-11");
        // A descriptor without a SACL, as the directory returns it to an
        // account without the auditing right.
        assert!(parse_sacl(&build::sd("S-1-5-32-544", &[])).is_none());
    }
}
