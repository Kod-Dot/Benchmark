//! Defender checks on data outside Graph: Defender for Endpoint machines
//! from its own API, and the Microsoft Sentinel connectors from Azure
//! Resource Manager.

use std::collections::BTreeSet;

use serde_json::Value;

use super::model::{Tenant, J};
use super::rules::{read_from, tenant_item};
use super::Rule;
use crate::ad::rules::{check, plural};
use crate::results::{Affected, CheckResult};
use crate::time;

/// Devices that signed in within this many days are expected in Defender.
const ACTIVE_DAYS: i64 = 30;

fn mde_source(t: &Tenant) -> String {
    format!("{}; Defender for Endpoint API", read_from(t))
}

fn def_001(t: &Tenant) -> CheckResult {
    let machines = t.raw.list("mdemachines");
    let onboarded: BTreeSet<String> = machines
        .iter()
        .filter(|m| m.s("onboardingStatus").is_none_or(|s| s == "Onboarded"))
        .filter_map(|m| m.s("aadDeviceId"))
        .map(str::to_lowercase)
        .collect();
    let windows: Vec<&Value> = t
        .raw
        .list("devices")
        .iter()
        .filter(|d| {
            d.s("operatingSystem")
                .is_some_and(|o| o.starts_with("Windows"))
                && d.b("accountEnabled") != Some(false)
        })
        .filter(|d| {
            t.days_since(
                d.s("approximateLastSignInDateTime")
                    .and_then(time::parse_iso),
            )
            .is_some_and(|x| x <= ACTIVE_DAYS)
        })
        .collect();
    let mut list: Vec<Affected> = windows
        .iter()
        .filter(|d| {
            !d.s("deviceId")
                .is_some_and(|id| onboarded.contains(&id.to_lowercase()))
        })
        .map(|d| {
            t.object(
                "device",
                d.s("displayName").unwrap_or_default(),
                d.s("operatingSystemVersion").map(str::to_string),
                "Active Windows device that is not onboarded to Defender for Endpoint",
            )
        })
        .collect();
    let missing = list.len();
    for m in machines.iter().filter(|m| {
        m.s("healthStatus") == Some("Inactive")
            && m.s("isExcluded") != Some("true")
            && m.b("isExcluded") != Some(true)
    }) {
        list.push(t.object(
            "device",
            m.s("computerDnsName").unwrap_or_default(),
            m.s("osPlatform").map(str::to_string),
            "Onboarded but inactive: the sensor stopped reporting",
        ));
    }
    check("M365-DEF-001")
        .expected("Every active Windows device is onboarded to Defender for Endpoint and reporting")
        .found(format!(
            "{} onboarded; {missing} of {} active Windows devices missing",
            plural(onboarded.len(), "device", "devices"),
            windows.len()
        ))
        .affected(list, "devices")
        .evidence("Read from", mde_source(t))
        .done()
}

fn def_003(t: &Tenant) -> CheckResult {
    let list: Vec<Affected> = t
        .raw
        .list("mdemachines")
        .iter()
        .filter(|m| m.s("defenderAvStatus") == Some("Passive") || m.s("defenderAvMode") == Some("Passive"))
        .map(|m| {
            t.object(
                "device",
                m.s("computerDnsName").unwrap_or_default(),
                m.s("osPlatform").map(str::to_string),
                "Defender Antivirus is in passive mode: only EDR in block mode stops what the other antivirus misses",
            )
        })
        .collect();
    check("M365-DEF-003")
        .expected("EDR in block mode covers every device where Defender Antivirus is passive")
        .found(plural(list.len(), "device runs", "devices run") + " Defender Antivirus in passive mode")
        .affected(list, "devices")
        .evidence("Read from", mde_source(t))
        .evidence("Note", "EDR in block mode is a portal setting no API exposes; confirm it is on for these devices")
        .done()
}

fn def_014(t: &Tenant) -> CheckResult {
    let connectors: Vec<&str> = t
        .raw
        .list("azsentinel")
        .iter()
        .filter_map(|c| c.s("kind"))
        .collect();
    let xdr = connectors.contains(&"MicrosoftThreatProtection");
    let list = if xdr {
        Vec::new()
    } else {
        vec![tenant_item(t, "No Microsoft Sentinel workspace has the Microsoft Defender XDR connector: incidents and raw events do not reach a SIEM")]
    };
    check("M365-DEF-014")
        .expected("Defender XDR incidents and events stream to Sentinel or another SIEM")
        .found(if connectors.is_empty() {
            "No Sentinel data connectors".to_string()
        } else {
            format!("Connectors: {}", connectors.join(", "))
        })
        .affected(list, "tenant")
        .evidence(
            "Read from",
            format!(
                "Azure Resource Manager, signed in as {}",
                t.raw.info.account
            ),
        )
        .evidence(
            "Note",
            "A SIEM other than Sentinel fed through the streaming API is not visible here",
        )
        .done()
}

pub static RULES: &[Rule] = &[
    Rule {
        id: "M365-DEF-001",
        needs: &["devices", "mdemachines"],
        run: def_001,
    },
    Rule {
        id: "M365-DEF-003",
        needs: &["mdemachines"],
        run: def_003,
    },
    Rule {
        id: "M365-DEF-014",
        needs: &["azworkspaces", "azsentinel"],
        run: def_014,
    },
];
