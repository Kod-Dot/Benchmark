//! Microsoft Entra ID: reading what the Graph collector wrote, building the
//! tenant model and running the Entra and hybrid checks.

pub mod directory;
pub mod model;
pub mod raw;
pub mod rules;
pub mod rules_az;
pub mod rules_az2;
pub mod rules_azmon;
pub mod rules_ca;
pub mod rules_defender;
pub mod rules_exo;
pub mod rules_exo2;
pub mod rules_intune;
pub mod rules_logs;
pub mod rules_m365;
pub mod rules_mde;
pub mod rules_mon;
pub mod rules_more;
pub mod rules_priv;
pub mod rules_rest;

#[cfg(test)]
pub(crate) mod tests;
#[cfg(test)]
mod tests_az;
#[cfg(test)]
mod tests_az2;
#[cfg(test)]
mod tests_defender;
#[cfg(test)]
mod tests_exo;
#[cfg(test)]
mod tests_exo2;
#[cfg(test)]
mod tests_intune;
#[cfg(test)]
mod tests_m365;
#[cfg(test)]
mod tests_mon;
#[cfg(test)]
mod tests_more;
#[cfg(test)]
mod tests_rest;

use crate::ad::raw::AreaState;
use crate::catalog::Catalog;
use crate::results::{CheckResult, DirectoryFile, ResultStatus};
use model::Tenant;
use raw::RawTenant;

pub struct Rule {
    pub id: &'static str,
    /// Collector areas the rule reads (file names in raw/entra/<tenant>/).
    pub needs: &'static [&'static str],
    pub run: fn(&Tenant) -> CheckResult,
}

pub struct TenantAnalysis {
    pub checks: Vec<CheckResult>,
    pub directory: DirectoryFile,
}

fn area_label(area: &str) -> &str {
    match area {
        "organization" => "The organization settings",
        "skus" => "Licences (subscribed SKUs)",
        "domains" => "Domains",
        "federation" => "Federation settings",
        "users" => "Users",
        "signinactivity" => "User sign-in activity (needs Entra ID P1 and AuditLog.Read.All)",
        "groups" => "Groups",
        "groupowners" => "Group owners",
        "rolegroupmembers" => "Members of role-assignable groups",
        "roledefinitions" => "Role definitions",
        "roleassignments" => "Role assignments",
        "roleeligibility" => "PIM eligible assignments (needs Entra ID P2)",
        "roleschedules" => "PIM assignment schedules (needs Entra ID P2)",
        "pimpolicies" => "PIM role settings (needs Entra ID P2)",
        "capolicies" => "Conditional Access policies",
        "namedlocations" => "Named locations",
        "authstrengths" => "Authentication strengths",
        "authmethods" => "The authentication methods policy",
        "authorization" => "The authorization policy",
        "securitydefaults" => "Security defaults",
        "adminconsent" => "The admin consent request policy",
        "crosstenant" => "Cross-tenant access defaults",
        "crosstenantpartners" => "Cross-tenant partner settings",
        "deviceregistration" => "The device registration policy",
        "groupsettings" => "Directory settings",
        "grouplifecycle" => "Group expiration policies",
        "registration" => "Authentication method registration details",
        "applications" => "App registrations",
        "serviceprincipals" => "Enterprise applications",
        "resources" => "Microsoft resource applications",
        "approleassignments" => "Application permissions",
        "grants" => "Delegated permission grants",
        "devices" => "Devices",
        "onpremsync" => "Directory synchronization settings",
        "adminunits" => "Administrative units",
        "contracts" => "Partner contracts",
        "riskyusers" => "Risky users (needs Entra ID P2)",
        "riskdetections" => "Risk detections (needs Entra ID P2)",
        "riskysps" => "Risky service principals (needs Workload ID Premium)",
        "spsignins" => "Service principal sign-in activity",
        "fedcreds" => "Federated identity credentials",
        "accessreviews" => "Access reviews (needs Entra ID Governance or P2)",
        "pimalerts" => "PIM alerts (needs Entra ID P2)",
        "branding" => "Company branding",
        "intunesettings" => "Intune tenant settings (needs Intune)",
        "intuneenrollment" => "Intune enrollment restrictions and status pages (needs Intune)",
        "intunecompliance" => "Intune compliance policies (needs Intune)",
        "intuneconfigs" => "Intune configuration profiles (needs Intune)",
        "intunepolicies" => "Intune settings catalog and endpoint security policies (needs Intune)",
        "intuneintents" => "Intune security baselines (needs Intune)",
        "intuneconfigstatus" => "Intune profile deployment status (needs Intune)",
        "intuneappprotection" => "Intune app protection policies (needs Intune)",
        "intuneroles" => "Intune roles (needs Intune)",
        "intuneroleassignments" => "Intune role assignments (needs Intune)",
        "intuneapprovals" => "Intune multi-admin approval (needs Intune)",
        "intunescripts" => "Intune PowerShell scripts (needs Intune)",
        "intuneremediations" => "Intune remediations (needs Intune)",
        "intuneapps" => "Intune Win32 apps (needs Intune)",
        "intunecleanup" => "Intune device cleanup rule (needs Intune)",
        "intuneautopilot" => "Autopilot profiles (needs Intune)",
        "intunecorporateids" => "Intune corporate device identifiers (needs Intune)",
        "intuneremotehelp" => "Remote Help settings (needs Intune)",
        "intunemtd" => "Intune mobile threat defense connectors (needs Intune)",
        "intunedevices" => "Intune managed devices (needs Intune)",
        "sposettings" => "SharePoint tenant settings",
        "teamguests" => "Guests in each team",
        "sposignin" => "SharePoint Online sign-in",
        "spotenant" => "SharePoint tenant configuration",
        "spoidle" => "Idle session sign-out",
        "sposync" => "OneDrive sync restrictions",
        "sposites" => "SharePoint sites",
        "spositeusers" => "Site admins and broad grants",
        "tmssignin" => "Teams sign-in",
        "tmsfederation" => "Teams external access",
        "tmsclient" => "Teams client configuration",
        "tmsmeetingconfig" => "Teams meeting configuration",
        "tmsmeeting" => "Teams meeting policies",
        "tmsguestmeeting" => "Teams guest meeting settings",
        "tmsguestmessaging" => "Teams guest messaging settings",
        "tmsappsetup" => "Teams app setup policies",
        "tmsapppermission" => "Teams app permission policies",
        "pursignin" => "Security & Compliance sign-in",
        "purlabels" => "Sensitivity labels",
        "purlabelpolicies" => "Label policies",
        "purautolabel" => "Auto-labeling policies",
        "purdlp" => "DLP policies",
        "purretention" => "Retention policies",
        "puralerts" => "Alert policies",
        "purrolegroups" => "Purview role groups",
        "purcaseadmins" => "eDiscovery administrators",
        "pursecurityfilters" => "Search permission filters",
        "purauditretention" => "Audit log retention policies",
        "purbarriers" => "Information barrier policies",
        "purinsider" => "Insider risk policies",
        "purcommunication" => "Communication compliance policies",
        "incidents" => "Open Defender XDR incidents",
        "mdealerts" => "Defender for Endpoint alerts",
        "securescores" => "Secure Score history",
        "mdisensors" => "Defender for Identity sensors",
        "mdihealth" => "Defender for Identity health issues",
        "intuneprotection" => "Windows device protection state",
        "mdesignin" => "Defender for Endpoint sign-in",
        "mdemachines" => "Defender for Endpoint machines",
        "azworkspaces" => "Log Analytics workspaces",
        "azsentinel" => "Microsoft Sentinel data connectors",
        "bitlockerkeys" => "BitLocker recovery key metadata",
        "groupmembers" => "Group members (first 20 of each)",
        "b2bmanagement" => "Guest invitation domain lists",
        "uxsetting" => "Admin center access setting",
        "appproxy" => "App Proxy applications",
        "azconnecthealth" => "Entra Connect Health services",
        "kvreads" => "Key Vault secret reads (Log Analytics)",
        "kvreadsignin" => "The Log Analytics sign-in",
        "securescore" => "Microsoft Secure Score",
        "audits" => "Audit logs (needs Entra ID P1)",
        "invites" => "Guest invitations in the audit log (needs Entra ID P1)",
        "signinslegacy" => "Legacy authentication sign-ins (needs Entra ID P1)",
        "signinsfailed" => "Failed sign-ins (needs Entra ID P1)",
        "signinsdevicecode" => "Device code sign-ins (needs Entra ID P1)",
        "signins" => "Successful sign-ins (needs Entra ID P1)",
        "signinssp" => "Service principal sign-ins (needs Entra ID P1)",
        "exosignin" => "The Exchange Online sign-in",
        "exoorg" => "The Exchange Online organization configuration",
        "exoquarantine" => "Quarantine policies",
        "exodistgroups" => "Distribution groups",
        "exosendas" => "Send As permissions",
        "exofullaccess" => "Full Access permissions",
        "exoinboxrules" => "Inbox rules",
        "exoualinbox" => "Audit log: inbox rule changes",
        "exoualfiles" => "Audit log: file downloads and anonymous links",
        "exotransport" => "The Exchange Online transport configuration",
        "exoadminaudit" => "The audit log configuration",
        "exoaccepteddomains" => "Accepted domains",
        "exomailboxes" => "Mailboxes",
        "exocas" => "Mailbox protocol settings",
        "exoauditbypass" => "Mailbox audit bypass associations",
        "exoremotedomains" => "Remote domains",
        "exooutboundspam" => "Outbound spam policies",
        "exooutboundspamrules" => "Outbound spam rules",
        "exoappaccess" => "Application access policies",
        "exoimpersonation" => "ApplicationImpersonation role assignments",
        "exorolegroups" => "Exchange role groups",
        "exoantiphish" => "Anti-phishing policies",
        "exoantiphishrules" => "Anti-phishing rules",
        "exosafelinks" => "Safe Links policies (needs Defender for Office 365)",
        "exosafelinksrules" => "Safe Links rules (needs Defender for Office 365)",
        "exosafeattach" => "Safe Attachments policies (needs Defender for Office 365)",
        "exosafeattachrules" => "Safe Attachments rules (needs Defender for Office 365)",
        "exoatpo365" => "Defender for Office 365 settings for SharePoint, OneDrive and Teams",
        "exomalware" => "Anti-malware policies",
        "exomalwarerules" => "Anti-malware rules",
        "exocontentfilter" => "Anti-spam policies",
        "exocontentfilterrules" => "Anti-spam rules",
        "exotransportrules" => "Mail flow rules",
        "exoinbound" => "Inbound connectors",
        "exooutbound" => "Outbound connectors",
        "exodkim" => "DKIM signing configuration",
        "exodns" => "SPF, DMARC, MTA-STS and TLS-RPT records",
        "exopreset" => "Preset security policies",
        "exoowa" => "Outlook on the web policies",
        "exosharing" => "Sharing policies",
        "armsignin" => "The Azure Resource Manager sign-in",
        "azmgmtgroups" => "Management groups",
        "azsubscriptions" => "Azure subscriptions",
        "azroleassignments" => "Azure role assignments",
        "azroledefinitions" => "Custom Azure roles",
        "azeligible" => "PIM eligible Azure role assignments",
        "azactive" => "Azure role assignment schedules",
        "azcontacts" => "Defender for Cloud security contacts",
        "azpricings" => "Defender for Cloud plans",
        "azsecurescore" => "Defender for Cloud secure score",
        "azdiagnostics" => "Activity log diagnostic settings",
        "azlighthouse" => "Azure Lighthouse delegations",
        "azpolicies" => "Azure Policy assignments",
        "azstorage" => "Storage accounts",
        "azvaults" => "Key Vaults",
        "azvaultdiagnostics" => "Key Vault diagnostic settings",
        "azkvsecrets" => "Key Vault secret metadata",
        "azkvkeys" => "Key Vault key metadata",
        "azclassicadmins" => "Classic subscription administrators",
        "azlocks" => "Resource locks",
        "azautomation" => "Automation accounts",
        "azlogicapps" => "Logic Apps",
        "azwebapps" => "App Service and Function apps",
        "azvms" => "Virtual machines",
        "azarc" => "Azure Arc servers",
        "azjit" => "Just-in-time VM access policies",
        "azbastion" => "Azure Bastion hosts",
        "azautomationvars" => "Automation variables (names only)",
        "azscriptscan" => "Runbook and deployment script credential scan",
        "aaddiagnostics" => "Entra diagnostic settings",
        "azactivity" => "The Azure activity log",
        "azalertrules" => "Azure Monitor log alert rules",
        other => other,
    }
}

/// The licence Microsoft said an area needs, when it refused for want of one.
pub fn licence_needed(message: &str) -> Option<&'static str> {
    if message.contains("Request not applicable to target tenant") {
        Some("a Microsoft Intune licence")
    } else if message.contains("AadPremiumLicenseRequired")
        || message.contains("does not have access to any of the reviews")
    {
        Some("Microsoft Entra ID P2 or ID Governance")
    } else {
        None
    }
}

/// Why a rule cannot run, if one of the areas it reads is unavailable.
pub(crate) fn missing(raw: &RawTenant, needs: &[&str]) -> Option<String> {
    for area in needs {
        match raw.area(area) {
            AreaState::Read(_) => {}
            AreaState::Failed(message) => {
                return Some(match licence_needed(message) {
                    Some(licence) => format!(
                        "{} needs {licence}, which this tenant does not have.",
                        area_label(area)
                    ),
                    None => format!("{} could not be read: {message}", area_label(area)),
                })
            }
            AreaState::Missing => {
                return Some(format!(
                    "{} was not collected in this run.",
                    area_label(area)
                ))
            }
        }
    }
    None
}

/// Every Entra rule, in catalog order.
pub fn all_rules() -> impl Iterator<Item = &'static Rule> {
    rules::RULES
        .iter()
        .chain(rules_ca::RULES)
        .chain(rules_priv::RULES)
        .chain(rules_logs::RULES)
        .chain(rules_exo::RULES)
        .chain(rules_az::RULES)
        .chain(rules_more::RULES)
        .chain(rules_mon::RULES)
        .chain(rules_azmon::RULES)
        .chain(rules_intune::RULES)
        .chain(rules_az2::RULES)
        .chain(rules_m365::RULES)
        .chain(rules_defender::RULES)
        .chain(rules_mde::RULES)
        .chain(rules_exo2::RULES)
        .chain(rules_rest::RULES)
}

/// Runs every implemented Entra rule whose area is in `areas` (all of them
/// when `areas` is empty).
pub fn analyze(catalog: &Catalog, raw: &RawTenant, areas: &[String]) -> TenantAnalysis {
    analyze_tenant(catalog, &Tenant::build(raw), areas)
}

/// [`analyze`] for a tenant model that is already built.
pub fn analyze_tenant(catalog: &Catalog, t: &Tenant, areas: &[String]) -> TenantAnalysis {
    let raw = t.raw;
    let selected = |id: &str| {
        let area = catalog
            .check(id)
            .map(|c| c.area.as_str())
            .unwrap_or_default();
        areas.is_empty() || areas.iter().any(|a| a == area)
    };
    let checks = all_rules()
        .filter(|r| selected(r.id))
        .map(|r| match missing(raw, r.needs) {
            Some(note) => CheckResult {
                id: r.id.to_string(),
                status: ResultStatus::NotAssessed,
                severity: None,
                affected_count: None,
                affected_unit: None,
                affected: Vec::new(),
                expected: None,
                found: None,
                evidence: Vec::new(),
                raw: None,
                note: Some(note),
            },
            None => (r.run)(t),
        })
        .collect();
    TenantAnalysis {
        checks,
        directory: directory::build(t),
    }
}
