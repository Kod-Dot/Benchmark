//! Reads what `collectors/Invoke-DCACollect.ps1` wrote for one domain:
//! `collection.json`, one `<area>.jsonl` per object type, and the
//! `events.jsonl` log the collector host keeps of the collector's output,
//! plus `dcconfig.jsonl` and `dcevents.jsonl` from the domain controllers.

use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::dc::{DcConfig, DcEvents};
use crate::{Error, Result};

/// Lists that PowerShell may have written as a bare value: it unrolls a
/// one-item list to the item and an empty one to null. The collector keeps
/// lists as lists, but bundles from earlier collectors can still have the
/// bare shapes, so they are read either way.
pub(crate) mod one_or_many {
    use serde::{Deserialize, Deserializer};

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany<T> {
        Many(Vec<T>),
        One(T),
    }

    fn list<T>(v: Option<OneOrMany<T>>) -> Vec<T> {
        match v {
            Some(OneOrMany::Many(v)) => v,
            Some(OneOrMany::One(x)) => vec![x],
            None => Vec::new(),
        }
    }

    pub fn vec<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
    where
        D: Deserializer<'de>,
        T: Deserialize<'de>,
    {
        Ok(list(Option::<OneOrMany<T>>::deserialize(d)?))
    }

    /// For parts that may be missing: null stays `None`, as before.
    pub fn opt<'de, D, T>(d: D) -> Result<Option<Vec<T>>, D::Error>
    where
        D: Deserializer<'de>,
        T: Deserialize<'de>,
    {
        Ok(Option::<OneOrMany<T>>::deserialize(d)?.map(|v| list(Some(v))))
    }
}

/// One directory object: lower-case attribute name to its values.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(transparent)]
pub struct LdapObject(pub BTreeMap<String, Vec<Value>>);

impl LdapObject {
    pub fn values(&self, attr: &str) -> &[Value] {
        self.0.get(attr).map(Vec::as_slice).unwrap_or(&[])
    }

    pub fn str(&self, attr: &str) -> Option<&str> {
        self.values(attr).first().and_then(Value::as_str)
    }

    pub fn strs(&self, attr: &str) -> Vec<&str> {
        self.values(attr).iter().filter_map(Value::as_str).collect()
    }

    /// The first value as an integer, accepting numbers and numeric strings.
    pub fn int(&self, attr: &str) -> Option<i64> {
        match self.values(attr).first()? {
            Value::Number(n) => n.as_i64(),
            Value::String(s) => s.trim().parse().ok(),
            Value::Bool(b) => Some(i64::from(*b)),
            _ => None,
        }
    }

    pub fn has(&self, attr: &str) -> bool {
        !self.values(attr).is_empty()
    }

    pub fn dn(&self) -> &str {
        self.str("distinguishedname").unwrap_or_default()
    }

    /// The most specific object class (LDAP lists them from top down).
    pub fn class(&self) -> Option<&str> {
        self.values("objectclass").last().and_then(Value::as_str)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CollectionInfo {
    pub domain: String,
    #[serde(default)]
    pub server: String,
    #[serde(default)]
    pub account: String,
    #[serde(default)]
    pub computer: String,
    pub started_at: String,
    #[serde(default)]
    pub sources: Vec<String>,
    #[serde(default)]
    pub rootdse: BTreeMap<String, String>,
}

/// One progress line from a collector, as the host logged it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum CollectEvent {
    Start {
        area: String,
    },
    Progress {
        area: String,
        read: u64,
    },
    Done {
        area: String,
        count: u64,
    },
    Error {
        area: String,
        message: String,
    },
    Finished {
        finished_at: String,
    },
    /// Microsoft sign-in is waiting: open `url` (and enter `code` for the
    /// device code flow).
    Signin {
        url: String,
        #[serde(default)]
        code: Option<String>,
    },
    Signedin {
        account: String,
    },
}

impl CollectEvent {
    /// Parses one stdout line. Anything that is not an event returns `None`.
    pub fn parse(line: &str) -> Option<CollectEvent> {
        serde_json::from_str(line.trim()).ok()
    }
}

/// How an area of the collection ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AreaState {
    Read(u64),
    Failed(String),
    /// Never attempted (source not selected, or the collector stopped).
    Missing,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SysvolPolicy {
    pub folder: String,
    #[serde(default, deserialize_with = "one_or_many::vec")]
    pub cpasswords: Vec<GppPassword>,
    /// Paths of the folder's files, relative to it (at most 200). `None`
    /// from collectors that predate the GPO content read.
    #[serde(default, deserialize_with = "one_or_many::opt")]
    pub files: Option<Vec<String>>,
    /// Version from GPT.INI (user << 16 | computer), like versionNumber in AD.
    #[serde(default)]
    pub version: Option<i64>,
    /// GptTmpl.inf: section to key to values.
    #[serde(default)]
    pub inf: Option<BTreeMap<String, BTreeMap<String, Vec<String>>>>,
    #[serde(default, deserialize_with = "one_or_many::opt")]
    pub registry: Option<Vec<PolicyValue>>,
    #[serde(default, deserialize_with = "one_or_many::opt")]
    pub scripts: Option<Vec<PolicyScript>>,
    #[serde(default)]
    pub preferences: Option<Preferences>,
    #[serde(default)]
    pub acl: Option<FolderAcl>,
    /// Advanced audit policy (audit.csv). `None` from older collectors.
    #[serde(default, deserialize_with = "one_or_many::opt")]
    pub audit: Option<Vec<AuditSetting>>,
    /// Part name to why it could not be read.
    #[serde(default)]
    pub errors: BTreeMap<String, String>,
}

impl SysvolPolicy {
    /// The values of a GptTmpl.inf key, if the template sets it.
    pub fn inf_values(&self, section: &str, key: &str) -> Option<&Vec<String>> {
        self.inf
            .as_ref()?
            .get(section)?
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v)
    }

    /// A Registry.pol setting: (scope, key, value name), case-insensitive.
    pub fn policy(&self, scope: &str, key: &str, value: &str) -> Option<&PolicyValue> {
        self.registry.as_ref()?.iter().find(|p| {
            p.scope.eq_ignore_ascii_case(scope)
                && p.key.eq_ignore_ascii_case(key)
                && p.value.eq_ignore_ascii_case(value)
        })
    }
}

/// One Registry.pol setting. Binary data and values named like secrets are
/// not copied.
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyValue {
    #[serde(default)]
    pub scope: String,
    pub key: String,
    pub value: String,
    #[serde(rename = "type", default)]
    pub kind: u32,
    #[serde(default)]
    pub data: serde_json::Value,
}

impl PolicyValue {
    pub fn int(&self) -> Option<i64> {
        match &self.data {
            serde_json::Value::Number(n) => n.as_i64(),
            serde_json::Value::String(s) => s.trim().parse().ok(),
            _ => None,
        }
    }
    pub fn text(&self) -> Option<&str> {
        self.data.as_str()
    }
}

/// One advanced audit policy subcategory from audit.csv. `value` is 0 (no
/// auditing), 1 (success), 2 (failure) or 3 (both).
#[derive(Debug, Clone, Deserialize)]
pub struct AuditSetting {
    #[serde(default)]
    pub subcategory: String,
    pub guid: String,
    #[serde(default)]
    pub value: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PolicyScript {
    pub scope: String,
    /// Startup, Shutdown, Logon or Logoff.
    pub kind: String,
    pub path: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Preferences {
    #[serde(default, deserialize_with = "one_or_many::vec")]
    pub tasks: Vec<PreferenceTask>,
    #[serde(default, deserialize_with = "one_or_many::vec")]
    pub groups: Vec<PreferenceGroup>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PreferenceTask {
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub run_as: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PreferenceGroup {
    #[serde(default)]
    pub group: String,
    #[serde(default)]
    pub sid: String,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub delete_all: bool,
    #[serde(default, deserialize_with = "one_or_many::vec")]
    pub members: Vec<PreferenceMember>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PreferenceMember {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub sid: String,
    #[serde(default)]
    pub action: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct FolderAcl {
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub owner_sid: Option<String>,
    #[serde(default, deserialize_with = "one_or_many::vec")]
    pub writers: Vec<FolderAce>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FolderAce {
    pub identity: String,
    #[serde(default)]
    pub sid: Option<String>,
    pub rights: String,
    #[serde(default)]
    pub inherit_only: bool,
}

/// A line in a logon or policy script that looks like it holds a credential.
/// The line itself is never collected.
#[derive(Debug, Clone, Deserialize)]
pub struct ScriptHit {
    pub file: String,
    pub line: u64,
    pub pattern: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GppPassword {
    pub file: String,
    pub element: String,
    #[serde(default)]
    pub user: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct RawDomain {
    pub info: CollectionInfo,
    pub finished_at: Option<String>,
    pub areas: BTreeMap<String, AreaState>,
    pub domain: Vec<LdapObject>,
    pub partitions: Vec<LdapObject>,
    pub dirservice: Vec<LdapObject>,
    pub schema: Vec<LdapObject>,
    pub users: Vec<LdapObject>,
    pub computers: Vec<LdapObject>,
    pub groups: Vec<LdapObject>,
    pub containers: Vec<LdapObject>,
    pub gpos: Vec<LdapObject>,
    pub trusts: Vec<LdapObject>,
    pub acls: Vec<LdapObject>,
    /// AD CS objects under CN=Public Key Services in the configuration partition.
    pub pki: Vec<LdapObject>,
    /// Standalone, group and delegated managed service accounts.
    pub msas: Vec<LdapObject>,
    /// KDS root keys (never their key material).
    pub kds: Vec<LdapObject>,
    /// Sites, servers, nTDSDSA, site settings, subnets, site links and
    /// bridges in the configuration partition.
    pub sites: Vec<LdapObject>,
    /// DNS zones in DomainDnsZones and ForestDnsZones, with their security
    /// descriptors.
    pub dnszones: Vec<LdapObject>,
    /// Fine-grained password policies (password settings objects).
    pub psos: Vec<LdapObject>,
    /// Accounts with a value in userPassword or a similar readable
    /// attribute (names only, never the value).
    pub pwdattrs: Vec<LdapObject>,
    /// Kerberos authentication policies and silos.
    pub authn: Vec<LdapObject>,
    /// Accounts with msDS-KeyCredentialLink set (names only).
    pub keycreds: Vec<LdapObject>,
    /// BitLocker recovery objects (location and date only).
    pub bitlocker: Vec<LdapObject>,
    /// LDAP areas added after the ones above, by area name: operations
    /// master role objects, the query policy, the configuration and schema
    /// partition heads, display specifiers and extended rights.
    pub extra: BTreeMap<String, Vec<LdapObject>>,
    pub sysvol: Vec<SysvolPolicy>,
    /// Credential-like lines found in NETLOGON and policy scripts.
    pub scripts: Vec<ScriptHit>,
    pub dcconfig: Vec<DcConfig>,
    pub dcevents: Vec<DcEvents>,
    /// Member servers and workstations read over PowerShell remoting.
    pub endpoints: Vec<super::ep::Endpoint>,
}

pub const LDAP_AREAS: [&str; 11] = [
    "domain",
    "partitions",
    "dirservice",
    "schema",
    "users",
    "computers",
    "groups",
    "containers",
    "gpos",
    "trusts",
    "acls",
];

/// LDAP areas kept in [`RawDomain::extra`].
pub const EXTRA_AREAS: [&str; 14] = [
    "roles",
    "querypolicy",
    "ncheads",
    "dispspec",
    "extrights",
    "privmeta",
    "attrmeta",
    "wmifilters",
    "gpsoftware",
    "computerowners",
    "sacls",
    "exchservers",
    "scps",
    "sccm",
];

pub(crate) fn io_err(path: &Path, source: std::io::Error) -> Error {
    Error::Io {
        path: path.display().to_string(),
        source,
    }
}

pub(crate) fn read_lines<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Vec<T>> {
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let file = fs::File::open(path).map_err(|e| io_err(path, e))?;
    let mut out = Vec::new();
    for (n, line) in BufReader::new(file).lines().enumerate() {
        let line = line.map_err(|e| io_err(path, e))?;
        // Windows PowerShell 5.1 can write a BOM even when asked not to.
        let line = line.trim_start_matches('\u{feff}').trim();
        if line.is_empty() {
            continue;
        }
        out.push(serde_json::from_str(line).map_err(|e| Error::Parse {
            path: path.display().to_string(),
            message: format!("line {}: {e}", n + 1),
        })?);
    }
    Ok(out)
}

impl RawDomain {
    /// The objects of an area kept in [`RawDomain::extra`].
    pub fn objects(&self, area: &str) -> &[LdapObject] {
        self.extra.get(area).map(Vec::as_slice).unwrap_or(&[])
    }

    pub fn area(&self, name: &str) -> &AreaState {
        static MISSING: AreaState = AreaState::Missing;
        self.areas.get(name).unwrap_or(&MISSING)
    }

    pub fn load(dir: &Path) -> Result<RawDomain> {
        let info_path = dir.join("collection.json");
        let text = fs::read_to_string(&info_path).map_err(|e| io_err(&info_path, e))?;
        let info: CollectionInfo = serde_json::from_str(text.trim_start_matches('\u{feff}'))
            .map_err(|e| Error::Parse {
                path: info_path.display().to_string(),
                message: e.to_string(),
            })?;

        let mut raw = RawDomain {
            info,
            ..RawDomain::default()
        };
        for event in read_lines::<CollectEvent>(&dir.join("events.jsonl"))? {
            match event {
                CollectEvent::Done { area, count } => {
                    raw.areas.insert(area, AreaState::Read(count));
                }
                CollectEvent::Error { area, message } => {
                    raw.areas.insert(area, AreaState::Failed(message));
                }
                CollectEvent::Finished { finished_at } => raw.finished_at = Some(finished_at),
                _ => {}
            }
        }
        let read = |area: &str| -> Result<Vec<LdapObject>> {
            read_lines(&dir.join(format!("{area}.jsonl")))
        };
        raw.domain = read("domain")?;
        raw.partitions = read("partitions")?;
        raw.dirservice = read("dirservice")?;
        raw.schema = read("schema")?;
        raw.users = read("users")?;
        raw.computers = read("computers")?;
        raw.groups = read("groups")?;
        raw.containers = read("containers")?;
        raw.gpos = read("gpos")?;
        raw.trusts = read("trusts")?;
        raw.acls = read("acls")?;
        raw.pki = read("pki")?;
        raw.msas = read("msas")?;
        raw.kds = read("kds")?;
        raw.sites = read("sites")?;
        raw.dnszones = read("dnszones")?;
        raw.dnszones.extend(read("dnsforestzones")?);
        raw.psos = read("psos")?;
        raw.pwdattrs = read("pwdattrs")?;
        raw.authn = read("authn")?;
        raw.keycreds = read("keycreds")?;
        raw.bitlocker = read("bitlocker")?;
        for area in EXTRA_AREAS {
            raw.extra.insert(area.to_string(), read(area)?);
        }
        raw.sysvol = read_lines(&dir.join("sysvol.jsonl"))?;
        raw.scripts = read_lines(&dir.join("scripts.jsonl"))?;
        raw.dcconfig = read_lines(&dir.join("dcconfig.jsonl"))?;
        raw.dcevents = read_lines(&dir.join("dcevents.jsonl"))?;
        raw.endpoints = read_lines(&dir.join("endpoints.jsonl"))?;
        Ok(raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape a lab collection wrote: one registry setting, one file and
    /// one script as bare objects, no writers as null.
    #[test]
    fn sysvol_reads_unrolled_lists() {
        let line = r#"{"folder":"{31B2F340-016D-11D2-945F-00C04FB984F9}","cpasswords":[],"files":"GPT.INI","version":3,"inf":{},"registry":{"key":"Software\\Policies\\Microsoft\\Windows NT\\DNSClient","value":"EnableMulticast","type":4,"data":0,"scope":"Machine"},"scripts":{"scope":"Machine","kind":"Startup","path":"setup.cmd"},"preferences":{"tasks":{"scope":"Machine","name":"t","run_as":"NT AUTHORITY\\System"},"groups":[]},"acl":{"owner":"BUILTIN\\Administrators","owner_sid":"S-1-5-32-544","writers":null},"errors":{}}"#;
        let p: SysvolPolicy = serde_json::from_str(line).unwrap();
        assert_eq!(p.files.as_deref(), Some(&["GPT.INI".to_string()][..]));
        assert_eq!(p.registry.as_ref().unwrap().len(), 1);
        assert_eq!(
            p.policy(
                "Machine",
                "Software\\Policies\\Microsoft\\Windows NT\\DNSClient",
                "EnableMulticast"
            )
            .and_then(|v| v.int()),
            Some(0)
        );
        assert_eq!(p.scripts.as_ref().unwrap()[0].path, "setup.cmd");
        assert_eq!(p.preferences.as_ref().unwrap().tasks.len(), 1);
        assert!(p.acl.as_ref().unwrap().writers.is_empty());
        // Missing parts stay missing, and lists stay lists.
        let p: SysvolPolicy =
            serde_json::from_str(r#"{"folder":"x","registry":null,"files":["a","b"]}"#).unwrap();
        assert!(p.registry.is_none());
        assert_eq!(p.files.unwrap().len(), 2);
    }

    #[test]
    fn object_accessors() {
        let o: LdapObject = serde_json::from_str(
            r#"{"distinguishedname":["CN=a,DC=x"],"useraccountcontrol":[512],"pwdlastset":["133500000000000000"],"objectclass":["top","person","user"],"serviceprincipalname":["a/b","c/d"]}"#,
        )
        .unwrap();
        assert_eq!(o.dn(), "CN=a,DC=x");
        assert_eq!(o.int("useraccountcontrol"), Some(512));
        assert_eq!(o.int("pwdlastset"), Some(133_500_000_000_000_000));
        assert_eq!(o.class(), Some("user"));
        assert_eq!(o.strs("serviceprincipalname").len(), 2);
        assert!(!o.has("admincount"));
    }

    #[test]
    fn events_parse() {
        assert_eq!(
            CollectEvent::parse(r#"{"type":"done","area":"users","count":3}"#),
            Some(CollectEvent::Done {
                area: "users".into(),
                count: 3
            })
        );
        assert!(CollectEvent::parse("WARNING: x").is_none());
    }
}
