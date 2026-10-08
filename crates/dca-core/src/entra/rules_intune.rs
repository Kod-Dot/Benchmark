//! Intune checks from Microsoft Graph: enrollment, compliance, endpoint
//! security and configuration policies, scripts and apps, roles, and the
//! managed devices.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use super::model::{Tenant, J};
use super::rules::{read_from, tenant_item};
use super::rules_ca::policies;
use super::Rule;
use crate::ad::rules::{check, plural, Out};
use crate::results::{Affected, CheckResult};
use crate::time;

/// Grace before a non-compliant device is blocked, in hours.
const GRACE_HOURS: f64 = 72.0;
/// Quality update deferral beyond which patches arrive too late, in days.
const QUALITY_DEFERRAL_DAYS: i64 = 14;
/// Days without a check-in after which a device is stale.
const STALE_DAYS: i64 = 30;
const MDE_CONNECTOR: &str = "fc780465-2017-40d4-a0c5-307022471b92";

fn kind(v: &Value) -> &str {
    v.s("@odata.type")
        .unwrap_or_default()
        .trim_start_matches("#microsoft.graph.")
}

fn assigned(v: &Value) -> bool {
    !v.a("assignments").is_empty() || v.b("isAssigned") == Some(true)
}

fn name(v: &Value) -> &str {
    v.s("displayName")
        .or(v.s("name"))
        .unwrap_or("Unnamed policy")
}

fn intune(t: &Tenant, id: &str) -> Out {
    check(id).evidence("Read from", format!("{}; Intune", read_from(t)))
}

/// Settings catalog and endpoint security policies that are assigned, with
/// their settings as lower-case text for matching setting and value ids.
fn catalog_policies<'a>(t: &Tenant<'a>) -> Vec<(&'a Value, String)> {
    t.raw
        .list("intunepolicies")
        .iter()
        .filter(|p| assigned(p))
        .map(|p| {
            (
                p,
                p.get("settings")
                    .map(Value::to_string)
                    .unwrap_or_default()
                    .to_ascii_lowercase(),
            )
        })
        .collect()
}

fn family(p: &Value) -> &str {
    p.at(&["templateReference", "templateFamily"])
        .and_then(Value::as_str)
        .unwrap_or_default()
}

/// Every string value in the settings that starts with `prefix`.
fn values_with<'a>(text: &'a str, prefix: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(i) = rest.find(prefix) {
        let tail = &rest[i..];
        let end = tail.find('"').unwrap_or(tail.len());
        out.push(&tail[..end]);
        rest = &tail[end..];
    }
    out
}

fn compliance<'a>(t: &Tenant<'a>) -> Vec<&'a Value> {
    t.raw
        .list("intunecompliance")
        .iter()
        .filter(|p| assigned(p))
        .collect()
}

fn configs<'a>(t: &Tenant<'a>, k: &str) -> Vec<&'a Value> {
    t.raw
        .list("intuneconfigs")
        .iter()
        .filter(|p| assigned(p) && kind(p) == k)
        .collect()
}

/// The platform of a compliance policy or a managed device.
fn platform(s: &str) -> Option<&'static str> {
    let s = s.to_ascii_lowercase();
    if s.starts_with("windows") {
        Some("Windows")
    } else if s.starts_with("ios") || s.starts_with("ipados") {
        Some("iOS")
    } else if s.starts_with("android") || s.starts_with("aosp") {
        Some("Android")
    } else if s.starts_with("macos") {
        Some("macOS")
    } else {
        None
    }
}

/// Platforms of the managed devices; Windows is always expected.
fn device_platforms(t: &Tenant) -> BTreeSet<&'static str> {
    let mut p: BTreeSet<&str> = t
        .raw
        .list("intunedevices")
        .iter()
        .filter_map(|d| platform(d.s("operatingSystem").unwrap_or_default()))
        .collect();
    p.insert("Windows");
    p
}

fn tenant_list(t: &Tenant, missing: Vec<String>) -> Vec<Affected> {
    missing.into_iter().map(|m| tenant_item(t, m)).collect()
}

// ---------- Enrollment ----------

fn int_001(t: &Tenant) -> CheckResult {
    let mut list = Vec::new();
    let authority = t
        .raw
        .first("organization")
        .and_then(|o| o.s("mobileDeviceManagementAuthority"))
        .unwrap_or("unknown");
    if !authority.eq_ignore_ascii_case("intune") {
        list.push(tenant_item(
            t,
            format!("The MDM authority is {authority}, not Intune"),
        ));
    }
    for c in t
        .raw
        .list("intuneenrollment")
        .iter()
        .filter(|c| kind(c) == "deviceEnrollmentPlatformRestrictionsConfiguration")
    {
        for (key, label) in [
            ("windowsRestriction", "Windows"),
            ("iosRestriction", "iOS"),
            ("androidRestriction", "Android"),
            ("androidForWorkRestriction", "Android work profile"),
            ("macOSRestriction", "macOS"),
        ] {
            let Some(r) = c.o(key) else { continue };
            if r.b("platformBlocked") != Some(true)
                && r.b("personalDeviceEnrollmentBlocked") != Some(true)
            {
                list.push(t.object(
                    "setting",
                    name(c),
                    Some(label.to_string()),
                    format!(
                        "Personally owned {label} devices can enroll and then count as managed"
                    ),
                ));
            }
        }
    }
    intune(t, "M365-INT-001")
        .expected("Intune is the MDM authority and personal devices cannot enroll")
        .found(format!(
            "MDM authority {authority}; {}",
            plural(list.len(), "finding", "findings")
        ))
        .affected(list, "settings")
        .done()
}

fn int_025(t: &Tenant) -> CheckResult {
    let identifiers = !t.raw.list("intunecorporateids").is_empty();
    let mut list = Vec::new();
    for c in t
        .raw
        .list("intuneenrollment")
        .iter()
        .filter(|c| kind(c) == "deviceEnrollmentLimitConfiguration")
    {
        let limit = c.n("limit").unwrap_or(0);
        if limit >= 15 {
            list.push(t.object(
                "setting",
                name(c),
                None,
                format!("Each user can enroll up to {limit} devices"),
            ));
        }
    }
    intune(t, "M365-INT-025")
        .expected("Corporate devices are identified, and users can enroll only a few devices each")
        .found(format!(
            "Corporate identifiers {}; {}",
            if identifiers {
                "uploaded"
            } else {
                "not uploaded"
            },
            plural(
                list.len(),
                "high enrollment limit",
                "high enrollment limits"
            )
        ))
        .affected(list, "settings")
        .done()
}

fn int_024(t: &Tenant) -> CheckResult {
    let pages: Vec<&Value> = t
        .raw
        .list("intuneenrollment")
        .iter()
        .filter(|c| kind(c) == "windows10EnrollmentCompletionPageConfiguration")
        .collect();
    let mut list = Vec::new();
    if !pages
        .iter()
        .any(|p| p.b("showInstallationProgress") == Some(true))
    {
        list.push(tenant_item(t, "No Enrollment Status Page holds new Windows devices until policies and apps are installed"));
    }
    for p in pages
        .iter()
        .filter(|p| p.b("showInstallationProgress") == Some(true))
    {
        if p.b("allowDeviceUseOnInstallFailure") == Some(true) {
            list.push(t.object(
                "setting",
                name(p),
                None,
                "Users can use the device even when security apps or policies failed to install",
            ));
        }
    }
    intune(t, "M365-INT-024")
        .expected(
            "The Enrollment Status Page blocks use until required apps and policies are installed",
        )
        .found(plural(pages.len(), "status page", "status pages"))
        .affected(list, "settings")
        .done()
}

fn int_023(t: &Tenant) -> CheckResult {
    let profiles: Vec<&Value> = t
        .raw
        .list("intuneautopilot")
        .iter()
        .filter(|p| assigned(p))
        .collect();
    let list: Vec<Affected> = profiles
        .iter()
        .filter(|p| {
            ["outOfBoxExperienceSettings", "outOfBoxExperienceSetting"]
                .iter()
                .any(|k| p.at(&[k, "userType"]).and_then(Value::as_str) == Some("administrator"))
        })
        .map(|p| {
            t.object(
                "profile",
                name(p),
                None,
                "The person setting up the device becomes a local administrator",
            )
        })
        .collect();
    intune(t, "M365-INT-023")
        .expected("Autopilot makes users standard users, not local administrators")
        .found(format!(
            "{}; {} make users admins",
            plural(profiles.len(), "assigned profile", "assigned profiles"),
            list.len()
        ))
        .affected(list, "profiles")
        .done()
}

// ---------- Compliance ----------

fn int_002(t: &Tenant) -> CheckResult {
    let covered: BTreeSet<&str> = compliance(t)
        .iter()
        .filter_map(|p| platform(kind(p)))
        .collect();
    let missing: Vec<String> = device_platforms(t)
        .into_iter()
        .filter(|p| !covered.contains(p))
        .map(|p| format!("No assigned compliance policy for {p}"))
        .collect();
    intune(t, "M365-INT-002")
        .expected("Every platform in use has an assigned compliance policy")
        .found(format!(
            "Covered: {}",
            if covered.is_empty() {
                "none".to_string()
            } else {
                covered.into_iter().collect::<Vec<_>>().join(", ")
            }
        ))
        .affected(tenant_list(t, missing), "platforms")
        .done()
}

fn secure_by_default(t: &Tenant) -> Option<bool> {
    t.raw
        .first("intunesettings")?
        .at(&["settings", "secureByDefault"])
        .and_then(Value::as_bool)
}

fn int_003(t: &Tenant) -> CheckResult {
    let on = secure_by_default(t) == Some(true);
    intune(t, "M365-INT-003")
        .expected("Devices with no compliance policy are marked Not compliant")
        .found(if on { "Not compliant" } else { "Compliant" })
        .affected(
            if on {
                Vec::new()
            } else {
                vec![tenant_item(
                    t,
                    "Devices that no compliance policy targets count as compliant",
                )]
            },
            "tenant",
        )
        .done()
}

fn int_004(t: &Tenant) -> CheckResult {
    let mut list = Vec::new();
    for p in compliance(t) {
        for rule in p.a("scheduledActionsForRule") {
            for a in rule.a("scheduledActionConfigurations") {
                let hours = a
                    .get("gracePeriodHours")
                    .and_then(Value::as_f64)
                    .unwrap_or(0.0);
                if a.s("actionType") == Some("block") && hours > GRACE_HOURS {
                    list.push(t.object(
                        "policy",
                        name(p),
                        None,
                        format!("Non-compliant devices keep access for {hours} hours"),
                    ));
                }
            }
        }
    }
    intune(t, "M365-INT-004")
        .expected(format!(
            "Non-compliant devices are marked within {GRACE_HOURS} hours"
        ))
        .found(plural(
            list.len(),
            "long grace period",
            "long grace periods",
        ))
        .affected(list, "policies")
        .done()
}

fn int_005(t: &Tenant) -> CheckResult {
    let catalog = catalog_policies(t);
    let windows = compliance(t).iter().any(|p| {
        platform(kind(p)) == Some("Windows")
            && (p.b("bitLockerEnabled") == Some(true)
                || p.b("storageRequireEncryption") == Some(true))
    }) || configs(t, "windows10EndpointProtectionConfiguration")
        .iter()
        .any(|c| c.b("bitLockerEncryptDevice") == Some(true))
        || catalog
            .iter()
            .any(|(p, s)| family(p) == "endpointSecurityDiskEncryption" && s.contains("bitlocker"));
    let mac = compliance(t).iter().any(|p| {
        platform(kind(p)) == Some("macOS") && p.b("storageRequireEncryption") == Some(true)
    }) || configs(t, "macOSEndpointProtectionConfiguration")
        .iter()
        .any(|c| c.b("fileVaultEnabled") == Some(true))
        || catalog
            .iter()
            .any(|(p, s)| family(p) == "endpointSecurityDiskEncryption" && s.contains("filevault"));
    let mut missing = Vec::new();
    if !windows {
        missing.push("BitLocker is neither required for compliance nor configured".to_string());
    }
    if !mac && device_platforms(t).contains("macOS") {
        missing.push("FileVault is neither required for compliance nor configured".to_string());
    }
    intune(t, "M365-INT-005")
        .expected("Disk encryption is enforced on Windows and macOS")
        .found(format!(
            "BitLocker {}; FileVault {}",
            if windows { "enforced" } else { "not enforced" },
            if mac { "enforced" } else { "not enforced" }
        ))
        .affected(tenant_list(t, missing), "platforms")
        .done()
}

fn int_006(t: &Tenant) -> CheckResult {
    let connector = t
        .raw
        .list("intunemtd")
        .iter()
        .find(|c| c.s("id") == Some(MDE_CONNECTOR));
    let connected = connector.is_some_and(|c| {
        c.s("partnerState") == Some("enabled") && c.b("windowsEnabled") == Some(true)
    });
    let risk = compliance(t)
        .iter()
        .any(|p| p.b("deviceThreatProtectionEnabled") == Some(true));
    let mut missing = Vec::new();
    if !connected {
        missing.push(
            "Defender for Endpoint is not connected to Intune for Windows devices".to_string(),
        );
    }
    if !risk {
        missing
            .push("No compliance policy requires the machine risk score from Defender".to_string());
    }
    intune(t, "M365-INT-006")
        .expected("Defender for Endpoint is connected and compliance uses its machine risk level")
        .found(format!(
            "Connector {}; risk level {}",
            if connected { "on" } else { "off" },
            if risk { "used" } else { "not used" }
        ))
        .affected(tenant_list(t, missing), "settings")
        .done()
}

fn int_029(t: &Tenant) -> CheckResult {
    let mut has_min: BTreeMap<&str, bool> = BTreeMap::new();
    for p in compliance(t) {
        let Some(pl) = platform(kind(p)).filter(|p| *p != "Windows") else {
            continue;
        };
        let set = p.s("osMinimumVersion").is_some_and(|v| !v.is_empty());
        *has_min.entry(pl).or_default() |= set;
    }
    let missing: Vec<String> = device_platforms(t)
        .into_iter()
        .filter(|p| *p != "Windows" && !has_min.get(p).copied().unwrap_or(false))
        .map(|p| format!("No minimum {p} version is required"))
        .collect();
    intune(t, "M365-INT-029")
        .expected("Compliance requires a minimum OS version on macOS, iOS and Android")
        .found(plural(
            missing.len(),
            "platform without a minimum",
            "platforms without a minimum",
        ))
        .affected(tenant_list(t, missing), "platforms")
        .done()
}

fn int_015(t: &Tenant) -> CheckResult {
    let requiring: Vec<String> = policies(t)
        .iter()
        .filter(|p| p.enabled() && p.grants().contains(&"compliantDevice"))
        .map(|p| p.name().to_string())
        .collect();
    let strict = secure_by_default(t) == Some(true);
    let list = if !requiring.is_empty() && !strict {
        vec![tenant_item(t, "Conditional Access requires compliant devices, but devices without a compliance policy count as compliant")]
    } else {
        Vec::new()
    };
    intune(t, "M365-INT-015")
        .expected("Policies that require compliant devices rely on every device having a compliance policy")
        .found(if requiring.is_empty() {
            "No policy requires a compliant device".to_string()
        } else {
            format!("Required by {}", requiring.join(", "))
        })
        .affected(list, "tenant")
        .done()
}

// ---------- Endpoint security ----------

fn int_007(t: &Tenant) -> CheckResult {
    let legacy: Vec<&Value> = t.raw.list("intuneintents").iter().collect();
    let mut on: Vec<&str> = legacy
        .iter()
        .filter(|i| assigned(i))
        .map(|i| name(i))
        .collect();
    on.extend(
        catalog_policies(t)
            .into_iter()
            .filter(|(p, _)| family(p) == "baseline")
            .map(|(p, _)| name(p)),
    );
    let unassigned: Vec<Affected> = legacy
        .iter()
        .filter(|i| !assigned(i))
        .map(|i| {
            t.object(
                "baseline",
                name(i),
                None,
                "Created but not assigned to any device",
            )
        })
        .collect();
    let list = if on.is_empty() {
        let mut l = vec![tenant_item(t, "No security baseline is assigned")];
        l.extend(unassigned);
        l
    } else {
        unassigned
    };
    intune(t, "M365-INT-007")
        .expected("Security baselines for Windows, Edge and Defender are assigned")
        .found(if on.is_empty() {
            "None assigned".to_string()
        } else {
            format!("Assigned: {}", on.join(", "))
        })
        .affected(list, "baselines")
        .done()
}

const ASR: &str = "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_";

fn int_008(t: &Tenant) -> CheckResult {
    let mut modes: BTreeMap<String, String> = BTreeMap::new();
    for (_, s) in catalog_policies(t) {
        for v in values_with(&s, ASR) {
            let rest = &v[ASR.len()..];
            if let Some((rule, mode)) = rest.rsplit_once('_') {
                // Block anywhere wins over audit elsewhere.
                let e = modes
                    .entry(rule.to_string())
                    .or_insert_with(|| mode.to_string());
                if mode == "block" {
                    *e = mode.to_string();
                }
            }
        }
    }
    let blocked = modes.values().filter(|m| *m == "block").count();
    let mut list: Vec<Affected> = modes
        .iter()
        .filter(|(_, m)| *m != "block")
        .map(|(r, m)| t.object("rule", r, None, format!("In {m} mode, not block")))
        .collect();
    if modes.is_empty() {
        list.push(tenant_item(
            t,
            "No attack surface reduction rules are deployed",
        ));
    }
    intune(t, "M365-INT-008")
        .expected("Attack surface reduction rules are deployed in block mode")
        .found(format!(
            "{} configured, {blocked} in block mode",
            plural(modes.len(), "rule", "rules")
        ))
        .affected(list, "rules")
        .done()
}

fn any_setting(t: &Tenant, needles: &[&str]) -> bool {
    catalog_policies(t)
        .iter()
        .any(|(_, s)| needles.iter().any(|n| s.contains(n)))
}

fn int_009(t: &Tenant) -> CheckResult {
    let on = catalog_policies(t).iter().any(|(_, s)| {
        values_with(s, "device_vendor_msft_laps_policies_backupdirectory_")
            .iter()
            .any(|v| !v.ends_with("_0"))
    });
    intune(t, "M365-INT-009")
        .expected("A Windows LAPS policy backs up local administrator passwords")
        .found(if on {
            "A LAPS policy is assigned"
        } else {
            "No LAPS policy"
        })
        .affected(
            if on {
                Vec::new()
            } else {
                vec![tenant_item(
                    t,
                    "Local administrator passwords are not managed by Windows LAPS through Intune",
                )]
            },
            "tenant",
        )
        .done()
}

fn int_010(t: &Tenant) -> CheckResult {
    let on = any_setting(
        t,
        &[
            "localusersandgroups_configure",
            "restrictedgroups_configuregroupmembership",
        ],
    );
    intune(t, "M365-INT-010")
        .expected("A policy manages who is in the local Administrators group")
        .found(if on {
            "Local group membership is managed"
        } else {
            "Not managed"
        })
        .affected(
            if on {
                Vec::new()
            } else {
                vec![tenant_item(
                    t,
                    "No policy controls local Administrators membership on managed devices",
                )]
            },
            "tenant",
        )
        .done()
}

fn int_011(t: &Tenant) -> CheckResult {
    let legacy = configs(t, "windows10EndpointProtectionConfiguration");
    let cg = any_setting(
        t,
        &["deviceguard_lsacfgflags_1", "deviceguard_lsacfgflags_2"],
    ) || legacy.iter().any(|c| {
        c.s("deviceGuardLocalSystemAuthorityCredentialGuardSettings")
            .is_some_and(|v| v.starts_with("enable"))
    });
    let lsa = any_setting(
        t,
        &[
            "lsa_configurelsaprotectedprocess_1",
            "lsa_configurelsaprotectedprocess_2",
        ],
    );
    let whfb = t.raw.list("intuneenrollment").iter().any(|c| {
        kind(c) == "deviceEnrollmentWindowsHelloForBusinessConfiguration"
            && c.s("state") == Some("enabled")
    }) || any_setting(t, &["passportforwork"]);
    let mut missing = Vec::new();
    for (on, what) in [
        (cg, "Credential Guard"),
        (lsa, "LSA protection"),
        (whfb, "Windows Hello for Business"),
    ] {
        if !on {
            missing.push(format!("{what} is not configured"));
        }
    }
    intune(t, "M365-INT-011")
        .expected("Credential Guard, LSA protection and Windows Hello for Business are configured")
        .found(format!("{} of 3 configured", 3 - missing.len()))
        .affected(tenant_list(t, missing), "settings")
        .done()
}

fn int_012(t: &Tenant) -> CheckResult {
    let catalog = catalog_policies(t);
    let legacy = configs(t, "windows10EndpointProtectionConfiguration");
    let mut missing = Vec::new();
    for (p, key) in [
        ("domain", "firewallProfileDomain"),
        ("private", "firewallProfilePrivate"),
        ("public", "firewallProfilePublic"),
    ] {
        let on = catalog.iter().any(|(_, s)| {
            s.contains(&format!(
                "vendor_msft_firewall_mdmstore_{p}profile_enablefirewall_true"
            ))
        }) || legacy
            .iter()
            .any(|c| c.at(&[key, "firewallEnabled"]).and_then(Value::as_str) == Some("allowed"));
        if !on {
            missing.push(format!(
                "The {p} profile firewall is not turned on by policy"
            ));
        }
    }
    intune(t, "M365-INT-012")
        .expected("Firewall policies turn on the domain, private and public profiles")
        .found(format!("{} of 3 profiles enforced", 3 - missing.len()))
        .affected(tenant_list(t, missing), "profiles")
        .done()
}

fn int_013(t: &Tenant) -> CheckResult {
    let rings = configs(t, "windowsUpdateForBusinessConfiguration");
    let mut list = Vec::new();
    if rings.is_empty() {
        list.push(tenant_item(t, "No Windows update ring is assigned"));
    }
    for r in &rings {
        let q = r.n("qualityUpdatesDeferralPeriodInDays").unwrap_or(0);
        if q > QUALITY_DEFERRAL_DAYS {
            list.push(t.object(
                "ring",
                name(r),
                None,
                format!("Security updates are deferred {q} days"),
            ));
        }
        if r.b("qualityUpdatesPaused") == Some(true) {
            list.push(t.object("ring", name(r), None, "Quality updates are paused"));
        }
    }
    intune(t, "M365-INT-013")
        .expected(format!("Update rings defer security updates at most {QUALITY_DEFERRAL_DAYS} days and are not paused"))
        .found(format!("{}; {}", plural(rings.len(), "ring", "rings"), plural(list.len(), "finding", "findings")))
        .affected(list, "rings")
        .done()
}

fn int_026(t: &Tenant) -> CheckResult {
    let mut list = Vec::new();
    let mut count = 0;
    for (p, s) in catalog_policies(t)
        .into_iter()
        .filter(|(p, _)| family(p) == "endpointSecurityEndpointPrivilegeManagement")
    {
        count += 1;
        let auto = values_with(&s, "device_vendor_msft_policy_privilegemanagement")
            .into_iter()
            .filter(|v| v.ends_with("_automatic"))
            .count();
        if auto > 0 {
            list.push(t.object(
                "policy",
                name(p),
                None,
                format!(
                    "{} elevate automatically, without the user justifying or support approving",
                    plural(auto, "rule or default", "rules or defaults")
                ),
            ));
        }
    }
    intune(t, "M365-INT-026")
        .expected(
            "Endpoint Privilege Management needs user justification or support approval to elevate",
        )
        .found(format!(
            "{}; {} with automatic elevation",
            plural(count, "EPM policy", "EPM policies"),
            list.len()
        ))
        .affected(list, "policies")
        .done()
}

// ---------- Apps and scripts ----------

fn int_014(t: &Tenant) -> CheckResult {
    let all = t.raw.list("intuneappprotection");
    let mut list = Vec::new();
    for (k, label) in [
        ("iosManagedAppProtection", "iOS"),
        ("androidManagedAppProtection", "Android"),
    ] {
        let ps: Vec<&Value> = all.iter().filter(|p| kind(p) == k && assigned(p)).collect();
        if ps.is_empty() {
            list.push(tenant_item(t, format!("No assigned app protection policy for {label}: company data in apps on personal phones is not protected")));
        }
        for p in ps {
            if p.s("allowedOutboundDataTransferDestinations") == Some("allApps") {
                list.push(t.object(
                    "policy",
                    name(p),
                    Some(label.to_string()),
                    "Company data can be sent to any app",
                ));
            }
        }
    }
    intune(t, "M365-INT-014")
        .expected("App protection policies for iOS and Android are assigned and keep data in managed apps")
        .found(plural(list.len(), "finding", "findings"))
        .affected(list, "policies")
        .done()
}

fn int_018(t: &Tenant) -> CheckResult {
    let mut list = Vec::new();
    for (area, what) in [
        ("intunescripts", "PowerShell script"),
        ("intuneremediations", "Remediation"),
    ] {
        for s in t
            .raw
            .list(area)
            .iter()
            .filter(|s| assigned(s) && s.s("runAsAccount") == Some("system"))
        {
            let unsigned = s.b("enforceSignatureCheck") != Some(true);
            list.push(t.object(
                "script",
                name(s),
                Some(what.to_string()),
                format!(
                    "Runs as SYSTEM on every targeted device{}",
                    if unsigned {
                        ", without a signature check"
                    } else {
                        ""
                    }
                ),
            ));
        }
    }
    intune(t, "M365-INT-018")
        .expected("Scripts that run as SYSTEM are known, signed, and their authors limited")
        .found(plural(list.len(), "script runs", "scripts run") + " as SYSTEM")
        .affected(list, "scripts")
        .done()
}

fn int_019(t: &Tenant) -> CheckResult {
    let list: Vec<Affected> = t
        .raw
        .list("intuneapps")
        .iter()
        .filter_map(|a| {
            let cmd = a.s("installCommandLine").unwrap_or_default();
            let l = cmd.to_ascii_lowercase();
            let why = if cmd.contains("\\\\") {
                "installs from a network share"
            } else if l.contains("http://") || l.contains("https://") {
                "downloads from the internet at install time"
            } else {
                return None;
            };
            Some(t.object(
                "app",
                name(a),
                Some(cmd.to_string()),
                format!("Its install command {why}; whoever can write there runs code as SYSTEM"),
            ))
        })
        .collect();
    intune(t, "M365-INT-019")
        .expected("Win32 apps install only from their own package")
        .found(plural(list.len(), "app", "apps") + " with external install sources")
        .affected(list, "apps")
        .done()
}

// ---------- Administration ----------

fn int_016(t: &Tenant) -> CheckResult {
    let list: Vec<Affected> = t
        .raw
        .list("intuneroleassignments")
        .iter()
        .filter(|a| a.s("scopeType").is_some_and(|s| s.starts_with("all")))
        .filter(|a| {
            a.at(&["roleDefinition", "displayName"])
                .and_then(Value::as_str)
                != Some("Read Only Operator")
        })
        .map(|a| {
            t.object(
                "assignment",
                name(a),
                a.at(&["roleDefinition", "displayName"])
                    .and_then(Value::as_str)
                    .map(str::to_string),
                format!(
                    "Scoped to {}: no scope group or scope tag limits it",
                    a.s("scopeType").unwrap_or_default()
                ),
            )
        })
        .collect();
    let custom = t
        .raw
        .list("intuneroles")
        .iter()
        .filter(|r| r.b("isBuiltIn") == Some(false))
        .count();
    intune(t, "M365-INT-016")
        .expected("Intune role assignments are limited by scope groups and scope tags")
        .found(format!(
            "{}; {} with tenant-wide scope",
            plural(custom, "custom role", "custom roles"),
            list.len()
        ))
        .affected(list, "assignments")
        .done()
}

fn int_017(t: &Tenant) -> CheckResult {
    let covered: BTreeSet<&str> = t
        .raw
        .list("intuneapprovals")
        .iter()
        .filter_map(|p| p.s("policyType"))
        .collect();
    let missing: Vec<String> = [
        ("script", "scripts"),
        ("deviceWipe", "device wipes"),
        ("application", "app deployment"),
    ]
    .into_iter()
    .filter(|(k, _)| !covered.contains(k))
    .map(|(_, what)| format!("No multi-admin approval for {what}"))
    .collect();
    intune(t, "M365-INT-017")
        .expected("Multi-admin approval protects scripts, wipes and app deployment")
        .found(if covered.is_empty() {
            "No approval policy".to_string()
        } else {
            format!(
                "Covers {}",
                covered.into_iter().collect::<Vec<_>>().join(", ")
            )
        })
        .affected(tenant_list(t, missing), "actions")
        .done()
}

fn int_027(t: &Tenant) -> CheckResult {
    let mut list = Vec::new();
    if let Some(r) = t.raw.first("intuneremotehelp") {
        if r.s("remoteAssistanceState") == Some("enabled")
            && r.b("allowSessionsToUnenrolledDevices") == Some(true)
        {
            list.push(tenant_item(
                t,
                "Remote Help can connect to devices that are not enrolled",
            ));
        }
    }
    for a in t.raw.list("intuneroleassignments") {
        let role = a
            .get("roleDefinition")
            .map(Value::to_string)
            .unwrap_or_default()
            .to_ascii_lowercase();
        if role.contains("remotetasks") && a.s("scopeType").is_some_and(|s| s.starts_with("all")) {
            list.push(
                t.object(
                    "assignment",
                    name(a),
                    a.at(&["roleDefinition", "displayName"])
                        .and_then(Value::as_str)
                        .map(str::to_string),
                    "Can run remote actions (wipe, retire, remote help) on every device",
                ),
            );
        }
    }
    intune(t, "M365-INT-027")
        .expected("Remote actions and Remote Help are limited to scoped support roles")
        .found(plural(list.len(), "finding", "findings"))
        .affected(list, "settings")
        .done()
}

// ---------- Devices ----------

fn int_021(t: &Tenant) -> CheckResult {
    let days = t
        .raw
        .first("intunecleanup")
        .and_then(|c| c.n("deviceInactivityBeforeRetirementInDays"))
        .unwrap_or(0);
    intune(t, "M365-INT-021")
        .expected("A device cleanup rule removes devices that have not checked in")
        .found(if days > 0 {
            format!("After {days} days")
        } else {
            "No cleanup rule".to_string()
        })
        .affected(
            if days > 0 {
                Vec::new()
            } else {
                vec![tenant_item(
                    t,
                    "Devices that stopped checking in stay in Intune forever",
                )]
            },
            "tenant",
        )
        .done()
}

fn int_022(t: &Tenant) -> CheckResult {
    let devices = t.raw.list("intunedevices");
    let mut stale = 0;
    let mut non = 0;
    let mut list = Vec::new();
    for d in devices {
        let age = t.days_since(d.s("lastSyncDateTime").and_then(time::parse_iso));
        let reason = if age.is_some_and(|a| a > STALE_DAYS) {
            stale += 1;
            format!("No check-in for {} days", age.unwrap_or_default())
        } else if d.s("complianceState") == Some("noncompliant") {
            non += 1;
            "Not compliant".to_string()
        } else {
            continue;
        };
        list.push(t.object(
            "device",
            d.s("deviceName").unwrap_or_default(),
            d.s("operatingSystem").map(str::to_string),
            reason,
        ));
    }
    intune(t, "M365-INT-022")
        .expected(format!(
            "Managed devices check in within {STALE_DAYS} days and are compliant"
        ))
        .found(format!(
            "{}; {stale} stale, {non} not compliant",
            plural(devices.len(), "device", "devices")
        ))
        .affected(list, "devices")
        .done()
}

fn int_028(t: &Tenant) -> CheckResult {
    let list: Vec<Affected> = t
        .raw
        .list("intuneconfigstatus")
        .iter()
        .filter_map(|c| {
            let o = c.o("deviceStatusOverview")?;
            let conflicts = o.n("conflictCount").unwrap_or(0);
            let errors = o.n("errorCount").unwrap_or(0) + o.n("failedCount").unwrap_or(0);
            (conflicts + errors > 0).then(|| {
                t.object(
                    "profile",
                    name(c),
                    None,
                    format!("{conflicts} devices in conflict, {errors} with errors"),
                )
            })
        })
        .collect();
    intune(t, "M365-INT-028")
        .expected("Configuration profiles apply without conflicts or errors")
        .found(plural(list.len(), "profile", "profiles") + " with conflicts or errors")
        .affected(list, "profiles")
        .done()
}

fn int_030(t: &Tenant) -> CheckResult {
    let devices = t.raw.list("intunedevices");
    let co = devices
        .iter()
        .filter(|d| {
            d.s("managementAgent")
                .is_some_and(|m| m.to_ascii_lowercase().contains("configurationmanager"))
        })
        .count();
    intune(t, "M365-INT-030")
        .expected("Co-management workloads are known, and Intune or ConfigMgr owns each")
        .found(format!(
            "{co} of {} co-managed with Configuration Manager",
            plural(devices.len(), "device", "devices")
        ))
        .done()
}

pub static RULES: &[Rule] = &[
    Rule {
        id: "M365-INT-001",
        needs: &["intuneenrollment"],
        run: int_001,
    },
    Rule {
        id: "M365-INT-002",
        needs: &["intunecompliance", "intunedevices"],
        run: int_002,
    },
    Rule {
        id: "M365-INT-003",
        needs: &["intunesettings"],
        run: int_003,
    },
    Rule {
        id: "M365-INT-004",
        needs: &["intunecompliance"],
        run: int_004,
    },
    Rule {
        id: "M365-INT-005",
        needs: &["intunecompliance", "intuneconfigs", "intunepolicies"],
        run: int_005,
    },
    Rule {
        id: "M365-INT-006",
        needs: &["intunemtd", "intunecompliance"],
        run: int_006,
    },
    Rule {
        id: "M365-INT-007",
        needs: &["intuneintents", "intunepolicies"],
        run: int_007,
    },
    Rule {
        id: "M365-INT-008",
        needs: &["intunepolicies"],
        run: int_008,
    },
    Rule {
        id: "M365-INT-009",
        needs: &["intunepolicies"],
        run: int_009,
    },
    Rule {
        id: "M365-INT-010",
        needs: &["intunepolicies"],
        run: int_010,
    },
    Rule {
        id: "M365-INT-011",
        needs: &["intunepolicies", "intuneconfigs", "intuneenrollment"],
        run: int_011,
    },
    Rule {
        id: "M365-INT-012",
        needs: &["intunepolicies", "intuneconfigs"],
        run: int_012,
    },
    Rule {
        id: "M365-INT-013",
        needs: &["intuneconfigs"],
        run: int_013,
    },
    Rule {
        id: "M365-INT-014",
        needs: &["intuneappprotection"],
        run: int_014,
    },
    Rule {
        id: "M365-INT-015",
        needs: &["capolicies", "intunesettings"],
        run: int_015,
    },
    Rule {
        id: "M365-INT-016",
        needs: &["intuneroles", "intuneroleassignments"],
        run: int_016,
    },
    Rule {
        id: "M365-INT-017",
        needs: &["intuneapprovals"],
        run: int_017,
    },
    Rule {
        id: "M365-INT-018",
        needs: &["intunescripts", "intuneremediations"],
        run: int_018,
    },
    Rule {
        id: "M365-INT-019",
        needs: &["intuneapps"],
        run: int_019,
    },
    Rule {
        id: "M365-INT-021",
        needs: &["intunecleanup"],
        run: int_021,
    },
    Rule {
        id: "M365-INT-022",
        needs: &["intunedevices"],
        run: int_022,
    },
    Rule {
        id: "M365-INT-023",
        needs: &["intuneautopilot"],
        run: int_023,
    },
    Rule {
        id: "M365-INT-024",
        needs: &["intuneenrollment"],
        run: int_024,
    },
    Rule {
        id: "M365-INT-025",
        needs: &["intuneenrollment", "intunecorporateids"],
        run: int_025,
    },
    Rule {
        id: "M365-INT-026",
        needs: &["intunepolicies"],
        run: int_026,
    },
    Rule {
        id: "M365-INT-027",
        needs: &["intuneroleassignments", "intuneremotehelp"],
        run: int_027,
    },
    Rule {
        id: "M365-INT-028",
        needs: &["intuneconfigstatus"],
        run: int_028,
    },
    Rule {
        id: "M365-INT-029",
        needs: &["intunecompliance", "intunedevices"],
        run: int_029,
    },
    Rule {
        id: "M365-INT-030",
        needs: &["intunedevices"],
        run: int_030,
    },
];
