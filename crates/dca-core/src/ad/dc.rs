//! What the collector read from each domain controller: its configuration
//! over PowerShell remoting (`dcconfig.jsonl`) and event counts from its
//! logs (`dcevents.jsonl`). A DC that could not be read keeps its name and
//! the error, so checks can say which DCs they could not assess.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct DcConfig {
    pub name: String,
    #[serde(default)]
    pub error: Option<String>,
    /// When the collector received the reply, in its own clock.
    #[serde(default)]
    pub read_at: Option<String>,
    #[serde(default)]
    pub data: Option<DcData>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct DcData {
    #[serde(default)]
    pub os: Option<Os>,
    #[serde(default)]
    pub hotfixes: Option<Hotfixes>,
    #[serde(default)]
    pub services: Option<Vec<Service>>,
    #[serde(default)]
    pub registry: Option<BTreeMap<String, Value>>,
    #[serde(default)]
    pub netbios: Option<Vec<i64>>,
    #[serde(default)]
    pub firewall: Option<Vec<FirewallProfile>>,
    /// Inbound allow rules for management ports.
    #[serde(default)]
    pub mgmtrules: Option<Vec<serde_json::Value>>,
    /// AD FS, Entra Connect and agent services on the DC.
    #[serde(default)]
    pub identity: Option<serde_json::Value>,
    #[serde(default)]
    pub features: Option<Vec<String>>,
    #[serde(default)]
    pub smb: Option<Smb>,
    #[serde(default)]
    pub shares: Option<Vec<String>>,
    /// Audit subcategory GUID (upper case, no braces) to its setting.
    #[serde(default)]
    pub audit: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pub security_log: Option<SecurityLog>,
    #[serde(default)]
    pub disks: Option<Vec<Disk>>,
    #[serde(default)]
    pub certificates: Option<Vec<Certificate>>,
    #[serde(default)]
    pub credential_guard: Option<Vec<i64>>,
    #[serde(default)]
    pub software: Option<Vec<Software>>,
    #[serde(default)]
    pub dns: Option<DnsServer>,
    /// Inbound replication per partner and partition.
    #[serde(default)]
    pub replication: Option<Vec<ReplPartner>>,
    /// DFSR replicated folders on this DC.
    #[serde(default)]
    pub dfsr: Option<Vec<DfsrFolder>>,
    /// Clients netlogon.log saw from addresses no site covers.
    #[serde(default)]
    pub no_client_site: Option<Vec<NoSiteClient>>,
    /// SCHANNEL cipher Enabled values and the cipher suite order policy.
    #[serde(default)]
    pub ciphers: Option<Value>,
    /// Manufacturer, model, hypervisor and VM-GenerationID support.
    #[serde(default)]
    pub hardware: Option<Value>,
    /// The DC's IPv4 addresses.
    #[serde(default)]
    pub addresses: Option<Vec<String>>,
    /// Microsoft Defender Antivirus state and exclusions.
    #[serde(default)]
    pub defender: Option<Value>,
    /// Services that run as an account other than the built-in ones.
    #[serde(default)]
    pub service_accounts: Option<Vec<Value>>,
    /// Whether each trusted domain's DCs resolve in DNS.
    #[serde(default)]
    pub trust_dns: Option<Vec<Value>>,
    /// Certificate Services configuration, when the DC is also a CA.
    #[serde(default)]
    pub certsvc: Option<Value>,
    /// Part name to why it could not be read.
    #[serde(default)]
    pub errors: BTreeMap<String, String>,
    /// The DC's own clock when it finished.
    #[serde(default)]
    pub now: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Os {
    #[serde(default)]
    pub caption: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub build: i64,
    #[serde(default)]
    pub last_boot: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Hotfixes {
    #[serde(default)]
    pub count: i64,
    #[serde(default)]
    pub last: Option<String>,
    #[serde(default)]
    pub last_id: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Service {
    pub name: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub start: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct FirewallProfile {
    pub name: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Smb {
    pub smb1: bool,
    pub require_signing: bool,
    #[serde(default)]
    pub audit_smb1: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct SecurityLog {
    pub max_bytes: i64,
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub records: i64,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Disk {
    pub drive: String,
    pub size: i64,
    pub free: i64,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Certificate {
    #[serde(default)]
    pub subject: String,
    #[serde(default)]
    pub dns: Vec<String>,
    #[serde(default)]
    pub not_after: Option<String>,
    #[serde(default)]
    pub server_auth: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Software {
    pub name: String,
    #[serde(default)]
    pub publisher: String,
    #[serde(default)]
    pub version: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct DnsServer {
    #[serde(default)]
    pub installed: bool,
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub zones: Vec<DnsZone>,
    /// Wildcard, wpad and isatap records found in primary forward zones.
    #[serde(default)]
    pub records: Vec<DnsRecord>,
    /// Targets of _ldap._tcp.dc._msdcs SRV records.
    #[serde(default)]
    pub dc_srv: Vec<String>,
    #[serde(default)]
    pub recursion: bool,
    #[serde(default)]
    pub forwarders: Vec<String>,
    #[serde(default)]
    pub scavenging: bool,
    #[serde(default)]
    pub scavenging_days: i64,
    #[serde(default)]
    pub block_list: BlockList,
    #[serde(default)]
    pub audit_log: Option<bool>,
    #[serde(default)]
    pub root_hints: Option<i64>,
    /// A records for the DC's own host name.
    #[serde(default)]
    pub own_a: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct DnsZone {
    pub name: String,
    /// Primary, Secondary, Stub or Forwarder.
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub ds: bool,
    #[serde(default)]
    pub reverse: bool,
    /// None, Secure or NonsecureAndSecure.
    #[serde(default)]
    pub dynamic: String,
    /// Forest, Domain, Legacy, Custom or None.
    #[serde(default)]
    pub scope: String,
    /// TransferAnyServer, TransferToZoneNameServer, TransferToSecureServers or NoTransfer.
    #[serde(default)]
    pub transfer: String,
    #[serde(default)]
    pub signed: bool,
    #[serde(default)]
    pub aging: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DnsRecord {
    pub zone: String,
    pub name: String,
    #[serde(rename = "type", default)]
    pub kind: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct BlockList {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub names: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReplPartner {
    /// NTDS Settings DN of the partner.
    pub partner: String,
    #[serde(default)]
    pub partition: String,
    #[serde(default)]
    pub last_success: Option<String>,
    #[serde(default)]
    pub last_attempt: Option<String>,
    #[serde(default)]
    pub last_result: i64,
    #[serde(default)]
    pub failures: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DfsrFolder {
    pub folder: String,
    #[serde(default)]
    pub group: String,
    pub state: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NoSiteClient {
    pub client: String,
    pub ip: String,
    #[serde(default)]
    pub times: u64,
}

impl DcData {
    /// A registry value as an integer; `None` when it is not set.
    pub fn reg_int(&self, key: &str) -> Option<i64> {
        match self.registry.as_ref()?.get(key)? {
            Value::Number(n) => n.as_i64(),
            Value::String(s) => s.trim().parse().ok(),
            Value::Bool(b) => Some(i64::from(*b)),
            _ => None,
        }
    }

    pub fn reg_str(&self, key: &str) -> Option<String> {
        match self.registry.as_ref()?.get(key)? {
            Value::String(s) => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            Value::Array(a) => Some(
                a.iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
            _ => None,
        }
    }

    pub fn service(&self, name: &str) -> Option<&Service> {
        self.services
            .as_ref()?
            .iter()
            .find(|s| s.name.eq_ignore_ascii_case(name))
    }

    pub fn running(&self, name: &str) -> bool {
        self.service(name)
            .is_some_and(|s| s.state.eq_ignore_ascii_case("Running"))
    }

    /// Why `part` is unavailable: the error the DC returned, or that it
    /// returned nothing.
    pub fn why_missing(&self, part: &str) -> String {
        self.errors
            .get(part)
            .cloned()
            .unwrap_or_else(|| format!("{part} was not returned"))
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct DcEvents {
    pub name: String,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub days: i64,
    #[serde(default)]
    pub security_oldest: Option<String>,
    #[serde(default)]
    pub last_clear: Option<String>,
    #[serde(default)]
    pub queries: BTreeMap<String, EventSummary>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct EventSummary {
    #[serde(default)]
    pub count: u64,
    /// The collector stopped at its limit; the real count is higher.
    #[serde(default)]
    pub capped: bool,
    #[serde(default)]
    pub first: Option<String>,
    #[serde(default)]
    pub last: Option<String>,
    #[serde(default)]
    pub top: Vec<EventSource>,
    /// For the 2887 summary: the number of binds it reports.
    #[serde(default)]
    pub binds: Option<u64>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct EventSource {
    pub key: String,
    pub count: u64,
    /// When this source last appeared (hunting queries only).
    #[serde(default)]
    pub last: Option<String>,
}
