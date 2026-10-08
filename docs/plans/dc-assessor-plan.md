# DC-Assessor: Build Plan

**Goal:** A read-only assessment tool that audits on-prem Active Directory and Microsoft Entra ID (plus the hybrid glue between them) in depth, and extends to Microsoft 365 workloads, Azure, endpoints, per-setting baselines and threat hunting. It collects telemetry, runs a large catalog of checks, and produces an interactive dashboard and exportable reports.

**Status:** Plan only (revision 2: all areas added). No code yet. Repository `Kod-Dot/DC-Assessor` is currently empty.

---

## 1. Design principles

1. **Read-only, always.** The tool never writes to AD, Entra ID, GPOs, or the registry. Every collector call is a query. This is the first thing a customer's security team will ask.
2. **Collect once, analyze many times.** Collection produces a self-contained, timestamped telemetry bundle (zipped JSON). Analysis, scoring, dashboard and reports all run from that bundle, offline, so you can re-analyze old data when checks improve and compare runs over time.
3. **Checks are data, not hard-coded logic.** Each check is a small definition file (ID, title, area, severity, rule, evidence query, remediation, references). Adding check #401 means adding one file, not editing the engine.
4. **Least privilege first.** A standard domain user can read most of AD. Checks that need more (DC registry, event logs, SYSVOL ACLs, Graph scopes) are flagged, and the tool degrades gracefully with "Not assessed: insufficient rights" instead of failing.
5. **Works air-gapped.** The dashboard is a single offline HTML file. No CDN, no cloud upload, no phone-home.
6. **Every finding carries evidence.** Each failed check lists the exact objects (DN / objectId), the attribute values seen, why it matters, how to fix it, and framework mappings.

---

## 2. Architecture

```
 ┌───────────────────────────┐      ┌───────────────────────────┐
 │  Collector: On-prem AD    │      │  Collector: Entra ID      │
 │  (PowerShell, LDAP/ADSI,  │      │  (Microsoft Graph,        │
 │   WinRM/RPC to DCs,       │      │   delegated or app-only,  │
 │   SYSVOL, event logs)     │      │   read-only scopes)       │
 └────────────┬──────────────┘      └────────────┬──────────────┘
              │   raw JSON per area              │
              └──────────────┬───────────────────┘
                             ▼
              ┌───────────────────────────────┐
              │  Telemetry bundle (.zip)      │
              │  manifest + raw/*.json +      │
              │  collection log + hashes      │
              └──────────────┬────────────────┘
                             ▼
              ┌───────────────────────────────┐
              │  Analysis engine              │
              │  loads check catalog, runs    │
              │  rules, builds attack-path    │
              │  graph, scores, diffs runs    │
              └──────────────┬────────────────┘
                             ▼
              ┌───────────────────────────────┐
              │  results.json                 │
              └───────┬───────────────┬───────┘
                      ▼               ▼
        ┌──────────────────┐  ┌────────────────────────┐
        │ Dashboard        │  │ Reports                │
        │ single offline   │  │ Executive PDF, full    │
        │ HTML file        │  │ technical HTML/PDF,    │
        │                  │  │ XLSX, CSV, JSON, SARIF │
        └──────────────────┘  └────────────────────────┘
```

### Recommended stack

| Layer | Recommendation | Why |
|---|---|---|
| Collector | PowerShell module, compatible with Windows PowerShell 5.1 **and** PowerShell 7 | Runs natively on any domain-joined Windows box or DC; no installs needed on locked-down servers. Uses `System.DirectoryServices` (LDAP) directly so the RSAT ActiveDirectory module is optional. |
| Entra collector | Same module, Microsoft Graph via REST (`Invoke-RestMethod`) with MSAL auth; optional use of `Microsoft.Graph` SDK | Avoids a heavy SDK dependency; paging and throttling handled in one helper. |
| Analysis engine | PowerShell 7 (same module) | One tool to ship. Check rules are PowerShell scriptblocks or a small declarative rule language over the JSON. |
| Dashboard | Prebuilt single-file HTML app (Svelte or React + ECharts, bundled with Vite into one file) with results JSON embedded | Opens by double-click, works offline, looks polished. |
| Reports | HTML templates → PDF via headless Edge/Chromium; XLSX via the `ImportExcel` module (optional); CSV/JSON native | No Office dependency. |

Alternative to discuss: write the analyzer and report generator in Python or .NET instead. That gives stronger tooling for graphs and PDFs but adds a runtime on the analyst machine. My recommendation is to stay all-PowerShell for v1 and keep the bundle format language-neutral so the analyzer can be rewritten later without touching the collectors.

### Repository layout (proposed)

```
DC-Assessor/
  src/DCAssessor/                 PowerShell module
    Collectors/OnPrem/            one file per collection area
    Collectors/Entra/
    Collectors/Hybrid/
    Engine/                       rule runner, scoring, attack-path graph, diff
    Reports/                      report templates and exporters
  checks/                         the catalog, one .psd1/.yaml per check
    ad/  entra/  hybrid/
  dashboard/                      front-end source (built into one HTML)
  tests/                          Pester tests + fixture bundles
  docs/                           permissions, check reference, how to run
```

---

## 3. Coverage: the check catalog

The catalog below lists **804 hand-written checks across 46 areas** (on-prem AD, Entra ID, hybrid, Microsoft 365 workloads, Azure, endpoints and threat hunting), plus **2,000 to 3,000 generated per-setting baseline checks** (Part G). It is not a cap and will keep growing. Each check gets a stable ID (for example `AD-PRIV-012`), a severity (Critical / High / Medium / Low / Info), and mappings to MITRE ATT&CK, CIS Benchmarks, ANSSI AD points, Microsoft security baselines, and the Entra ID Secure Score where they apply.

### PART A: On-prem Active Directory

#### A1. Forest and domain fundamentals (AD-FND) — 18 checks
1. Forest functional level below 2016
2. Domain functional level below 2016
3. Domains or trusts still running deprecated DC OSes (2008 R2, 2012, 2012 R2)
4. Schema version and schema extensions inventory (Exchange, LAPS, SCCM, third party)
5. FSMO role placement and holders reachable
6. FSMO roles held by a DC that is offline or decommissioned (orphaned metadata)
7. Tombstone lifetime below 180 days
8. AD Recycle Bin not enabled
9. Deleted-object lifetime configuration
10. Optional features inventory (Privileged Access Management feature)
11. dSHeuristics anomalies (anonymous LDAP enabled, List Object mode, AdminSDHolder exclusions)
12. ms-DS-MachineAccountQuota above 0
13. Domain naming: single-label domain names, disjoint namespace
14. UPN suffixes and alternate suffixes inventory
15. Number of domains, sites, DCs and objects (sizing context)
16. Lingering or stale cross-references in the Partitions container
17. Application partitions inventory and orphaned DNS partitions
18. Forest-wide `LDAPAdminLimits` (MaxPageSize, MaxQueryDuration) changed from defaults

#### A2. Domain controller health and hardening (AD-DC) — 32 checks
1. DC operating system version and support lifecycle
2. DC patch level (last installed hotfix date, missing critical cumulative updates)
3. DCs not in the Domain Controllers OU
4. DC computer objects with unexpected owners
5. DC uptime (very long uptime means missed reboots for patches)
6. Print Spooler service running on DCs (PrinterBug / PrintNightmare)
7. Unneeded roles and features on DCs (IIS, file server shares, Hyper-V, etc.)
8. Third-party agents and software installed on DCs (inventory)
9. SMBv1 enabled on DCs
10. SMB signing not required on DCs
11. LDAP signing not required
12. LDAP channel binding not enforced
13. LDAPS certificate present, valid and not expiring soon
14. NTLM restrictions and NTLM auditing policy on DCs
15. LM hash storage (NoLMHash) not set
16. LmCompatibilityLevel below 5
17. Null session / anonymous enumeration (RestrictAnonymous, RestrictAnonymousSAM)
18. Netlogon secure channel enforcement (ZeroLogon FullSecureChannelProtection)
19. Kerberos PAC validation and KDC hardening registry values (CVE-2022-37967, -26923 enforcement)
20. DSRM admin logon behavior and DSRM password age
21. Windows Firewall disabled on any profile
22. RDP exposure and NLA on DCs
23. WinRM/PowerShell remoting configuration on DCs
24. Credential Guard / LSA protection (RunAsPPL) on DCs
25. WDigest UseLogonCredential enabled
26. Cached logons count on DCs
27. Antivirus/EDR presence and exclusions on DCs (inventory)
28. Time source: PDC emulator syncs to a reliable external source; others sync from domain hierarchy
29. DC clock skew between DCs
30. Disk space on NTDS, logs and SYSVOL volumes
31. NTDS.dit and log file location on separate volume (informational)
32. Read-Only DCs: Password Replication Policy (allowed/denied lists, privileged accounts cached on RODCs)

#### A3. Replication and topology (AD-REP) — 16 checks
1. Replication failures per partner (repadmin /showrepl equivalent)
2. Last successful replication older than threshold
3. USN rollback indicators
4. Lingering objects risk (strict replication consistency disabled)
5. KCC errors and ISTG placement
6. Sites with no DCs
7. Subnets not assigned to a site
8. Clients authenticating from unmapped subnets (from Netlogon.log)
9. Site links with high cost or schedule gaps
10. Bridge-all-site-links setting review
11. SYSVOL replication: still on FRS instead of DFSR
12. DFSR SYSVOL backlog and state
13. SYSVOL and NETLOGON shares present on every DC
14. GPO version mismatch between AD and SYSVOL across DCs
15. Orphaned DC metadata (NTDS Settings without a computer)
16. Global Catalog placement per site

#### A4. Privileged groups and Tier 0 (AD-PRIV) — 30 checks
1. Membership of Enterprise Admins (should be empty day to day)
2. Membership of Schema Admins (should be empty)
3. Domain Admins count above threshold
4. Built-in Administrators group members
5. Account Operators, Server Operators, Print Operators, Backup Operators membership (should be empty)
6. DnsAdmins membership (DLL load path to SYSTEM on DCs)
7. Group Policy Creator Owners membership
8. Cert Publishers and Key Admins / Enterprise Key Admins membership
9. Hyper-V admins / virtualization admins with access to virtual DCs
10. Nested group membership depth into privileged groups (full recursive expansion)
11. Disabled or stale accounts still in privileged groups
12. Service accounts in privileged groups
13. Privileged accounts with password never expires
14. Privileged accounts with old passwords (> 1 year)
15. Privileged accounts not in Protected Users
16. Privileged accounts without "Account is sensitive and cannot be delegated"
17. Privileged accounts with SPNs (kerberoastable admins)
18. Privileged accounts with mailboxes / email (phishing exposure)
19. Built-in Administrator (RID 500) used recently, password age, renamed or not
20. Guest account enabled
21. krbtgt password age above 180 days
22. Read-only DC krbtgt accounts (krbtgt_xxxxx) password age
23. AdminSDHolder ACL deviations from default
24. Accounts with adminCount=1 that are no longer privileged (orphaned protection)
25. Objects in privileged groups via primaryGroupID (hidden membership)
26. Foreign security principals in privileged groups
27. Privileged group membership changes in the last 30 days (from replication metadata)
28. Tier 0 asset inventory (DCs, AD CS, ADFS, Entra Connect, PAM, backup servers) and who can log on to them
29. Admin accounts used for daily work (logon to workstations, from event telemetry)
30. Break-glass / emergency account presence and monitoring

#### A5. Dangerous ACLs and delegation of control (AD-ACL) — 28 checks
1. Non-default principals with GenericAll / GenericWrite / WriteDACL / WriteOwner on the domain root
2. DCSync rights (Replicating Directory Changes / All / In Filtered Set) held by non-DC principals
3. Dangerous rights on AdminSDHolder
4. Dangerous rights on the Domain Controllers OU and DC objects
5. Dangerous rights on privileged groups (add-member paths)
6. Dangerous rights on GPOs linked to Tier 0 OUs
7. Rights on the Configuration and Schema partitions
8. ResetPassword / ForceChangePassword over privileged users
9. Write on servicePrincipalName (targeted kerberoasting)
10. Write on msDS-KeyCredentialLink (Shadow Credentials)
11. Write on msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD takeover)
12. Write on userAccountControl or altSecurityIdentities on sensitive objects
13. Rights to read LAPS passwords (ms-Mcs-AdmPwd / msLAPS-Password) held too broadly
14. Rights to read gMSA passwords (msDS-GroupMSAMembership) held too broadly
15. Everyone / Authenticated Users / Domain Users with write rights anywhere sensitive
16. Owner of sensitive objects is not Domain Admins / Enterprise Admins / SYSTEM
17. Inheritance disabled on sensitive OUs (inventory)
18. Explicit deny ACEs hiding objects (inventory)
19. Exchange-related legacy permissions (Exchange Windows Permissions WriteDACL on domain)
20. Rights on the MicrosoftDNS container and zones
21. Rights on the Certificate Templates and PKI containers (feeds AD CS checks)
22. Delegated OU permissions inventory (who can manage what)
23. Create-child rights on OUs that hold privileged objects
24. Rights over computer objects of Tier 0 servers
25. Write rights on `gPLink` / `gPOptions` of OUs containing privileged objects
26. Rights to the `Password Settings Container` (FGPP tampering)
27. Unresolvable SIDs in ACLs (deleted principals)
28. Full attack-path analysis: shortest paths from low-privilege groups to Domain Admins (graph built from ACLs, memberships, sessions, delegation)

#### A6. Kerberos and delegation (AD-KRB) — 20 checks
1. Users with SPNs (kerberoastable), weighted by password age and privilege
2. Accounts with "Do not require Kerberos preauthentication" (AS-REP roastable)
3. Unconstrained delegation on non-DC computers
4. Unconstrained delegation on user accounts
5. Constrained delegation with protocol transition (TrustedToAuthForDelegation) inventory
6. Constrained delegation to sensitive SPNs (ldap, cifs on DCs, krbtgt)
7. Resource-based constrained delegation configured on sensitive objects
8. Accounts using DES encryption types
9. Accounts and DCs still allowing RC4 (msDS-SupportedEncryptionTypes)
10. Domain-wide Kerberos encryption type policy
11. Kerberos max ticket lifetime and renewal policy deviations
12. Duplicate SPNs
13. SPNs pointing at non-existent hosts (inventory)
14. Accounts with "Use only Kerberos DES" flag
15. Kerberos armoring (FAST) / claims support configuration
16. Authentication policies and silos defined and applied to Tier 0
17. Protected Users group membership coverage
18. S4U2Self abuse exposure on computer accounts
19. Golden-ticket exposure indicators (krbtgt age, RC4 allowed on krbtgt)
20. Kerberos audit events enabled (4768/4769/4771)

#### A7. Password and account policy (AD-PWD) — 20 checks
1. Default domain password policy: minimum length below 14
2. Complexity disabled
3. Maximum password age policy
4. Password history below 24
5. Reversible encryption enabled (policy or per-account)
6. Account lockout threshold disabled or too high
7. Lockout duration and observation window
8. Fine-grained password policies inventory and precedence
9. FGPPs weaker than the default policy
10. Privileged accounts not covered by a strong FGPP
11. Users with PASSWD_NOTREQD flag
12. Users with password never expires
13. Users with blank passwords (where detectable via PASSWD_NOTREQD + pwdLastSet=0)
14. Accounts never logged on but enabled
15. Passwords not changed in > 1 year
16. Users who must change password at next logon but never did
19. Passwords stored in description, info or comment attributes
20. Passwords in `userPassword`, `unixUserPassword`, `unicodePwd`-adjacent readable attributes
21. Microsoft Entra Password Protection for on-prem deployed (DC agent present)
22. Smart-card-required accounts with password hash not rotated

#### A8. Account hygiene (AD-ACC) — 18 checks
1. Stale enabled users (no logon in 90 days, using lastLogonTimestamp)
2. Stale enabled computers
3. Disabled accounts not moved or cleaned
4. Accounts expired but enabled
5. Computers with very old pwdLastSet (machine password not rotating)
6. Accounts with SID History (and SID History from the same domain)
7. Accounts with non-standard primaryGroupID
8. Duplicate accounts (same displayName / employeeID)
9. Users with userAccountControl anomalies (DONT_EXPIRE, TRUSTED_FOR_DELEGATION, etc.)
10. Pre-Windows 2000 compatible access group members (Everyone / Anonymous)
11. Pre-created computer accounts with default passwords (pre-2000 computers)
12. Accounts with altSecurityIdentities (certificate mapping) inventory
13. Shadow Credentials present (msDS-KeyCredentialLink on users and computers that do not use WHfB)
14. Objects with logonHours or userWorkstations restrictions inventory
15. Orphaned foreign security principals
16. Empty groups and groups with no manager (inventory)
17. Circular group nesting
18. Large groups (> N members) that grant access to resources

#### A9. Service accounts (AD-SVC) — 10 checks
1. gMSA adoption versus regular user service accounts
2. gMSA PrincipalsAllowedToRetrieveManagedPassword too broad
3. KDS root key present
4. dMSA (delegated MSA, Server 2025) configuration and BadSuccessor exposure (who can create dMSAs in which OUs)
5. Service accounts allowed to log on interactively
6. Service accounts with password never expires and old passwords
7. Service accounts with SPNs and RC4 enabled
8. Service accounts in privileged groups
9. sMSA inventory
10. Service account naming and ownership documented (description/manager populated)

#### A10. LAPS and local admin management (AD-LAPS) — 8 checks
1. Windows LAPS or legacy LAPS schema present
2. Percentage of computers with a managed LAPS password
3. Computers with expired LAPS passwords
4. LAPS password encryption enabled (Windows LAPS)
5. LAPS policy settings (length, complexity, age)
6. DSRM password managed by Windows LAPS on DCs
7. Broad read access to LAPS attributes (links to AD-ACL-13)
8. Legacy LAPS and Windows LAPS both present (migration state)

#### A11. Group Policy (AD-GPO) — 30 checks
1. GPO inventory: linked, unlinked, empty, disabled
2. GPOs with broken links (link to non-existent GPO)
3. GPOs present in AD but missing in SYSVOL, and vice versa
4. Group Policy Preferences with cpassword (GPP passwords, MS14-025)
5. Scripts in SYSVOL / NETLOGON containing credentials (keyword scan)
6. Write permissions on SYSVOL folders and scripts for non-admins
7. Write permissions on GPOs for non-admins
8. GPOs that apply to DCs: user rights assignment review (SeDebug, SeBackup, SeTcb, SeImpersonate, SeLoadDriver, SeEnableDelegation, SeTakeOwnership)
9. "Logon locally" / "Logon through RDS" rights on DCs
10. "Access this computer from the network" on DCs
11. Deny logon rights for privileged accounts on Tier 1/2 (tiering enforcement)
12. Audit policy (advanced audit policy) on DCs versus Microsoft/CIS recommendations
13. Security event log size and retention on DCs
14. PowerShell logging (script block, module, transcription)
15. Restricted Groups / Group Policy Preferences local group membership
16. Firewall policy via GPO
17. SMB, LDAP, NTLM hardening delivered by GPO versus local registry
18. Credential delegation (CredSSP, AllowDefaultCredentials) settings
19. WSUS settings (HTTP WSUS server exposes to MITM)
20. AppLocker / WDAC policies inventory
21. Software installation via GPO from writable shares
22. Scheduled tasks deployed by GPO running as privileged accounts
23. Startup/logon scripts pointing to non-existent or user-writable paths
24. GPO WMI filters inventory and broken filters
25. Loopback processing usage
26. Block inheritance and Enforced links inventory
27. Default Domain Policy and Default Domain Controllers Policy modified beyond password/Kerberos settings
28. GPO owners not Domain Admins
29. Security filtering removing Authenticated Users read (MS16-072 breakage)
30. Settings drift: GPO RSoP vs. Microsoft Security Baseline comparison (per setting)

#### A12. AD Certificate Services (AD-PKI) — 24 checks
1. Enterprise CAs inventory, OS and patch level
2. ESC1: templates allowing enrollee-supplied subject with client auth EKU and low-priv enrollment
3. ESC2: Any Purpose / no EKU templates enrollable by low-priv users
4. ESC3: Enrollment agent templates
5. ESC4: Writable certificate templates
6. ESC5: Writable PKI objects (CA computer, NTAuth, AIA, CDP containers)
7. ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 on CA
8. ESC7: ManageCA / ManageCertificates held by low-priv users
9. ESC8: Web enrollment (HTTP) endpoints exposed to NTLM relay
10. ESC9 / ESC10: weak certificate mapping (StrongCertificateBindingEnforcement, CertificateMappingMethods)
11. ESC11: RPC enrollment without packet privacy (IF_ENFORCEENCRYPTICERTREQUEST)
12. ESC13: issuance policy linked to groups
13. ESC14: weak explicit mappings (altSecurityIdentities)
14. ESC15 / EKUwu: schema v1 templates with application policies
15. ESC16: CA-wide security extension disabled
16. CA certificate key length and hash algorithm
17. CA certificate expiry and CRL publication health
18. Templates with manager approval disabled for sensitive EKUs
19. Templates with very long validity
20. NTAuth store contents (unexpected CAs trusted for logon)
21. Root CA online (should be offline)
22. CA backup and private key protection (HSM) inventory
23. Auditing enabled on CAs
24. Published but unused templates

#### A13. Trusts (AD-TRU) — 12 checks
1. Trust inventory (type, direction, transitivity)
2. SID filtering (quarantine) disabled on external trusts
3. SID history enabled on forest trusts (TREAT_AS_EXTERNAL / EnableSIDHistory)
4. Selective authentication not used on external/forest trusts
5. Trusts with RC4 only / no AES
6. Trust password (trust key) age
7. Trusts to domains that no longer exist or are unreachable
8. Bidirectional trusts to less-trusted forests
9. TGT delegation across trusts enabled
10. MIT/realm trusts inventory
11. Shortcut trusts inventory
12. Foreign principals from trusted domains holding privileges here

#### A14. DNS (AD-DNS) — 14 checks
1. AD-integrated zones with insecure dynamic updates (nonsecure and secure)
2. Zone transfers allowed to any server
3. Wildcard and WPAD records (or missing WPAD global query block list)
4. ADIDNS: Authenticated Users can create records (default, abuse for spoofing)
5. Stale records and scavenging disabled
6. Conditional forwarders and forwarders inventory and reachability
7. DNS recursion open to the internet
8. DNSSEC status (informational)
9. DNS server log and debug logging
10. Missing or broken SRV records for DCs
11. DnsAdmins ServerLevelPluginDll configured
12. Zones replicated to wrong scope
13. Duplicate A records for DCs
14. Root hints and forwarder security (inventory)

#### A15. Legacy and insecure protocols (AD-LEG) — 12 checks
1. NTLMv1 usage seen (from 4624 events)
2. LM usage seen
3. SMBv1 clients seen on DCs
4. Unsigned/simple LDAP binds seen (event 2887/2889)
5. LDAP binds without channel binding (event 3039)
6. RC4 Kerberos tickets issued (event 4769 encryption type)
7. Netlogon vulnerable connections (event 5827/5828/5829)
8. Kerberos PAC/certificate mapping warnings (events 39/40/41 KDC)
9. TLS 1.0/1.1 enabled on DCs
10. Weak cipher suites on DCs
11. LLMNR / NBT-NS / mDNS not disabled by policy
12. WebClient / WebDAV relay surface (inventory)

#### A16. Auditing and monitoring readiness (AD-AUD) — 12 checks
1. Advanced audit policy actually effective on each DC (auditpol), not just in GPO
2. Directory Service Changes auditing enabled
3. SACLs on sensitive objects (AdminSDHolder, domain root, privileged groups) for change auditing
4. Security log size and wrap behavior
5. Log forwarding (WEF/SIEM agent presence) inventory
6. Microsoft Defender for Identity sensor deployed on all DCs (and AD CS, ADFS, Entra Connect)
7. Honeytoken / decoy accounts configured (informational)
8. Sysmon presence on DCs (informational)
9. PowerShell transcription target protected
10. Event log reader and audit admin rights held by non-admins
11. Time since last security log clear (event 1102)
12. Recent suspicious events summary (lockout storms, 4625 spikes, 4742 on DCs)

#### A17. Backup and recovery (AD-BKP) — 8 checks
1. Last successful system state backup per domain (from dsaSignature / backup metadata)
2. Backup older than tombstone lifetime
3. Backup Operators membership (links to AD-PRIV-5)
4. DSRM password set and rotated
5. Forest recovery plan artifacts (informational questionnaire)
6. AD Recycle Bin (links to AD-FND-8)
7. Backup software service accounts privileges
8. Virtual DC snapshot safety (VM-GenerationID support)

#### A18. Exchange and legacy application footprint in AD (AD-APP) — 8 checks
1. Exchange schema present and Exchange groups' rights on the domain (PrivExchange)
2. Exchange Trusted Subsystem / Exchange Windows Permissions membership
3. SCCM/MECM accounts and their rights (NAA, client push accounts)
4. SQL service accounts with SPNs in privileged groups
5. Legacy applications using LDAP simple bind (from events)
6. Azure AD/Entra Connect service account rights (links to hybrid)
7. Third-party identity tool service accounts with DCSync
8. Orphaned application objects in Configuration partition

#### A19. OU structure and administrative model (AD-OU) — 8 checks
1. OU structure inventory and depth
2. Objects in default Users/Computers containers
3. Default container redirection (redircmp/redirusr)
4. OUs not protected from accidental deletion
5. Tiered administration model evidence (Tier 0/1/2 OUs, admin account separation)
6. Privileged Access Workstations defined and enforced via logon restrictions
7. Admin accounts and normal accounts not separated (same person, one account)
8. Delegated admin groups with members outside the expected OU

#### A20. Computers and endpoints seen from AD (AD-CMP) — 10 checks
1. Unsupported operating systems (Windows 7, 2008, XP) still enabled
2. OS version distribution
3. Computers with unconstrained delegation (links to AD-KRB-3)
4. Computers with SID history or RBCD configured
5. Computers where Domain Users are local admins (needs remote collection, optional)
6. BitLocker recovery keys escrowed to AD (coverage)
7. Computers without LAPS (links to AD-LAPS-2)
8. Computer objects created by normal users (ms-DS-CreatorSID)
9. Servers with Print Spooler and WebClient (coercion surface, optional remote)
10. Computers with non-standard owner

#### A21. Schema and configuration anomalies (AD-SCH) — 6 checks
1. Schema attributes marked confidential that should be (LAPS, BitLocker)
2. Custom attributes holding secrets (inventory of attributes named like *pass*, *pwd*, *secret*)
3. Attributes with searchFlags changed (filtered attribute set, RODC)
4. Display specifiers modified (persistence via context menus)
5. Extended rights added to configuration
6. Schema changes in the last 90 days

#### A22. Persistence and compromise indicators (AD-IOC) — 14 checks
1. AdminSDHolder ACL changed recently
2. Unusual SID History on privileged accounts
3. Accounts with recent changes to servicePrincipalName or msDS-KeyCredentialLink
4. Rogue DCs (DCShadow indicators: nTDSDSA objects without matching DC)
5. GPOs modified recently that apply to DCs
6. Skeleton key / LSA plugin indicators (registry, optional remote)
7. DSRM network logon enabled (DsrmAdminLogonBehavior = 2)
8. Hidden privileged accounts (denied read ACE on objects in privileged groups)
9. primaryGroupID set to 512/519 on non-admin accounts
10. Recently created privileged accounts
11. krbtgt delegation set (msDS-AllowedToDelegateTo on krbtgt)
12. Unexpected ACEs granting DCSync created recently (from metadata)
13. Golden gMSA exposure (KDS root key read rights)
14. Computer accounts with userAccountControl SERVER_TRUST_ACCOUNT that are not DCs

---

### PART B: Microsoft Entra ID

#### B1. Tenant configuration (EN-TEN) — 18 checks
1. Tenant inventory: licenses (P1/P2/E5), verified domains, data location
2. Security Defaults vs. Conditional Access state (one of them must be on)
3. Users can register applications
4. Users can create tenants
5. Users can create security groups / Microsoft 365 groups
6. Guest user access restriction level
7. Guest invite settings (who can invite)
8. External collaboration allow/deny domain list
9. Cross-tenant access settings (inbound/outbound defaults and partner overrides)
10. B2B direct connect and cross-tenant sync configuration
11. Users can read other users (default directory permissions)
12. Restrict access to Entra admin portal for non-admins
13. LinkedIn account connection / third-party integrations
14. Self-service sign-up (viral tenants) and email-verified users
15. Technical and security contact set
16. Company branding and sign-in page tampering (informational)
17. Unverified or stale custom domains
18. Federated domains inventory (links to hybrid ADFS)

#### B2. Identities and accounts (EN-ID) — 16 checks
1. Stale members (no sign-in in 90 days, using signInActivity)
2. Stale guests and guests that never redeemed invitations
3. Guests with privileged roles
4. Disabled users still assigned licenses or roles
5. Accounts with password never expires (Entra password policy)
6. Cloud-only vs. synced account distribution
7. Synced accounts holding Entra privileged roles (should be cloud-only)
8. Break-glass accounts: existence, excluded from CA correctly, monitored, FIDO2
9. Shared mailbox / resource accounts with sign-in enabled
10. Users with on-premisesImmutableId mismatches / soft-match risk
11. Accounts with insecure legacy authentication sign-ins in the last 30 days
12. Risky users not remediated (Identity Protection)
13. Users at high user risk with no policy response
14. Duplicate UPN/proxyAddresses conflicts
15. Users with directly assigned (not group-based) licenses (hygiene)
16. Account lifecycle: access reviews configured for guests

#### B3. Authentication and MFA (EN-AUTH) — 20 checks
1. Users without any MFA method registered
2. Privileged users without phishing-resistant MFA (FIDO2, WHfB, CBA)
3. Authentication methods policy: SMS and voice enabled
4. Microsoft Authenticator number matching and additional context
5. Legacy per-user MFA still in use (migration state)
6. Legacy MFA/SSPR policies migrated to authentication methods policy
7. Temporary Access Pass configuration (lifetime, one-time use)
8. FIDO2 / passkey policy (attestation, key restrictions)
9. Certificate-based authentication configuration and CA trust list
10. SSPR enabled, methods required, and admin SSPR policy
11. Password protection: custom banned list and lockout threshold
12. Smart lockout settings
13. Seamless SSO account (AZUREADSSOACC) Kerberos key age (links to hybrid)
14. Password hash sync enabled (leaked credential detection depends on it)
15. Registration campaign (nudge) configuration
16. Authentication strengths defined and used
17. System-preferred MFA enabled
18. MFA fatigue indicators (denied push spikes from sign-in logs)
19. Email OTP for guests configuration
20. Report suspicious activity enabled

#### B4. Conditional Access (EN-CA) — 24 checks
1. CA policy inventory with state (on, report-only, off)
2. Policy requiring MFA for all users exists and is enforced
3. Policy requiring phishing-resistant MFA for admins
4. Legacy authentication blocked for all users
5. Device code flow and authentication transfer restricted
6. Sign-in risk policy (P2)
7. User risk policy (P2)
8. Security info registration protected (trusted location or compliant device)
9. Azure management / admin portals require MFA
10. Compliant or hybrid-joined device required for admins
11. Guest access policies
12. Session controls: sign-in frequency and persistent browser for admins
13. Token protection / continuous access evaluation settings
14. Named locations: overly broad trusted IP ranges
15. Exclusions analysis: users, groups and apps excluded from critical policies
16. Excluded groups that are large, dynamic, or editable by non-admins
17. Policies that target "All users" but exclude a role that has many members
18. Coverage gap analysis: users or apps not covered by any MFA policy (what-if simulation across all users × apps)
19. Report-only policies left for a long time
20. Conflicting or redundant policies
21. Workload identity CA policies (service principals)
22. Policies relying on deprecated conditions (e.g., legacy "require approved client app")
23. Break-glass accounts excluded from all blocking policies
24. Policy change history in the last 30 days (from audit logs)

#### B5. Privileged roles and PIM (EN-PRIV) — 22 checks
1. Global Administrator count (target 2 to 4 including break-glass)
2. Permanent (active) assignments to privileged roles instead of PIM eligible
3. PIM role settings: MFA on activation, approval, justification, max duration
4. Privileged Role Administrator / Privileged Authentication Administrator holders
5. Role-assignable groups and their owners
6. Roles assigned to service principals
7. Roles assigned to guests
8. Administrative units and restricted management AUs
9. Custom roles with dangerous permissions
10. Admins without a dedicated admin account (same account for email and admin)
11. Admin accounts with mailboxes/licenses for productivity apps
12. PIM alerts unresolved
13. Access reviews for privileged roles
14. Stale privileged accounts (no sign-in, no activation)
15. Azure subscription Owner / User Access Administrator held by Entra admins (elevate access state)
16. "Access management for Azure resources" (root elevate) toggled on
17. Directory synchronization accounts role holders
18. Partner relationships (GDAP / DAP) and delegated admin privileges
19. Privileged roles assigned through nested or dynamic groups
20. Intune / Exchange / SharePoint administrators inventory
21. Cloud Device Local Administrator / Entra joined device local admins
22. Roles with Tier 0 equivalence (Application Admin, Cloud App Admin, Hybrid Identity Admin)

#### B6. Applications and service principals (EN-APP) — 24 checks
1. Users can consent to apps (user consent settings)
2. Admin consent workflow enabled
3. Apps with high-risk delegated permissions (Mail.ReadWrite, Files.ReadWrite.All, etc.) granted tenant-wide
4. Apps with high-risk application permissions (RoleManagement.ReadWrite.Directory, AppRoleAssignment.ReadWrite.All, Directory.ReadWrite.All, Application.ReadWrite.All)
5. Service principals with privileged directory roles
6. Applications with expired or soon-expiring secrets and certificates
7. Applications with long-lived secrets (> 1 year)
8. Applications using client secrets instead of certificates or federated credentials
9. Owners of privileged applications (non-admin owners can escalate)
10. Multi-tenant apps from unverified publishers with consent
11. Apps with redirect URIs to unregistered/wildcard/localhost/http domains (takeover risk)
12. Unused apps and service principals (no sign-in)
13. First-party Microsoft service principals with added credentials (backdoor indicator)
14. Federated identity credentials inventory (GitHub, Kubernetes subjects too broad)
15. Managed identities with privileged roles
16. App instance property lock not enabled
17. Apps allowing implicit grant flows
18. Apps with "assignment required" off and broad permissions
19. Illicit consent indicators (recent consents to unknown apps)
20. Enterprise apps with SAML signing certificates expiring
21. App proxy apps without pre-authentication
22. Apps with secrets in notes or description (inventory)
23. Workload identity risk detections
24. Microsoft Graph PowerShell / CLI apps consented with broad scopes

#### B7. Devices (EN-DEV) — 12 checks
1. Who can join devices to Entra ID
2. Device join requires MFA
3. Max devices per user
4. Additional local administrators on Entra-joined devices
5. Stale devices (no activity in 90 days)
6. Devices without compliance state (if Intune present)
7. Hybrid join status and errors
8. BitLocker keys stored in Entra (coverage)
9. Users can read BitLocker keys for own devices setting
10. Windows LAPS in Entra enabled and coverage
11. Device registration via Workplace join controls
12. Non-compliant devices accessing resources (sign-in logs)

#### B8. Groups and collaboration (EN-GRP) — 10 checks
1. Dynamic group rules based on user-editable attributes (privilege escalation)
2. Role-assignable groups count and ownership
3. Groups with guests as owners
4. Microsoft 365 group creation and naming policy
5. Groups granting access to privileged resources with no owners
6. Group expiration policy
7. Public Microsoft 365 groups with sensitive membership
8. Groups with "membership can be managed by members"
9. Sensitivity labels on groups enabled
10. Nested group cycles and empty groups

#### B9. Logging, monitoring and Identity Protection (EN-MON) — 12 checks
1. Diagnostic settings export sign-in and audit logs to Log Analytics / SIEM
2. Log retention period
3. Identity Protection risk detections in last 30 days summary
4. Unresolved risky sign-ins
5. Sign-ins from unexpected countries (summary)
6. Legacy auth sign-in volume by protocol and app
7. Failed MFA and blocked sign-in trends
8. Microsoft Defender for Cloud Apps / Defender XDR connection (informational)
9. Alerts for break-glass account sign-ins
10. Audit of recent changes to CA, roles, app credentials, and federation settings
11. Service health / Entra Connect Health agents reporting
12. Secure Score identity controls status (pulled from Graph Secure Score)

---

### PART C: Hybrid and cross-cutting

#### C1. Entra Connect / Cloud Sync (HY-SYNC) — 16 checks
1. Sync engine version and support status
2. Last sync cycle time and errors
3. Sync server treated as Tier 0 (who is local admin, who can log on)
4. AD DS connector account (MSOL_xxx) permissions too broad (DCSync, write on admins)
5. AD DS connector account password age
6. Entra connector account (Sync_xxx) / Directory Synchronization Accounts role
7. Privileged on-prem accounts synced to Entra
8. Sync scope: Tier 0 OUs synced unnecessarily
9. Password writeback enabled and its permission scope (can reset privileged on-prem accounts)
10. Device writeback / group writeback scope
11. Hard match / soft match takeover protection (BlockSoftMatch, BlockCloudObjectTakeoverThroughHardMatch)
12. Staging server configuration consistency
13. Cloud Sync agents inventory and gMSA used
14. Seamless SSO enabled and AZUREADSSOACC key rollover age
15. Pass-through Authentication agents inventory and placement
16. Attribute filtering and duplicate attribute resiliency errors

#### C2. Federation (HY-FED) — 10 checks
1. ADFS farm inventory, version, patch
2. Token-signing certificate age and key storage (Golden SAML exposure)
3. ADFS service account privileges and gMSA usage
4. Extranet smart lockout enabled
5. ADFS endpoints exposed unnecessarily (WS-Trust usernamemixed, etc.)
6. Federated domain configuration in Entra (supportsMfa, federatedIdpMfaBehavior, preferredAuthenticationProtocol)
7. Unexpected federated domains or added certificates (backdoor indicator)
8. Migration readiness: federation still needed or can move to PHS/PTA
9. ADFS auditing enabled
10. Relying party trusts inventory with weak claims rules

#### C3. Cross-environment privilege paths (HY-PATH) — 8 checks
1. On-prem admins who are also Entra Global Admins (same synced identity)
2. Entra roles that can take over on-prem (Hybrid Identity Admin, password writeback reach)
3. On-prem groups that grant Entra roles via sync
4. Cloud admins whose on-prem account is weakly protected
5. Synced service accounts with cloud permissions
6. Combined attack graph: shortest paths crossing the hybrid boundary
7. Intune/Endpoint management of DCs or Tier 0 servers from the cloud (cloud-to-Tier-0 path)
8. Azure Arc / cloud agents on DCs with management rights (inventory)

### PART D: Microsoft 365 workloads

#### D1. Exchange Online (M365-EXO) — 32 checks
1. Modern authentication enabled organization-wide
2. Basic/legacy auth protocols still enabled per mailbox (POP, IMAP, SMTP AUTH, EWS, ActiveSync)
3. SMTP AUTH enabled tenant-wide
4. External auto-forwarding allowed (remote domains, outbound spam policy)
5. Mailbox forwarding rules to external addresses (ForwardingSmtpAddress)
6. Inbox rules forwarding, deleting or hiding mail (compromise indicator)
7. Mailbox auditing enabled by default and audit bypass accounts
8. Unified audit log ingestion enabled
9. Full Access / Send As / Send on Behalf permissions granted to unexpected users
10. Application access policies for apps with Mail.* application permissions (RBAC for Applications)
11. EWS / Graph impersonation role assignments
12. Exchange admin role groups membership (Organization Management, etc.)
13. Shared mailboxes with sign-in enabled
14. Anti-phishing policy: impersonation protection, mailbox intelligence, spoof intelligence
15. Safe Links policy coverage
16. Safe Attachments policy coverage and dynamic delivery
17. Anti-malware policy: common attachment filter, ZAP enabled
18. Anti-spam policies: bulk threshold, allowed sender domains lists
19. Allowed sender/domain lists containing your own domain or public domains
20. Transport rules bypassing filtering (SCL -1) or redirecting mail
21. Connectors: inbound connectors without TLS/cert restriction, outbound to unknown smarthosts
22. SPF records for all accepted domains
23. DKIM enabled for all accepted domains
24. DMARC records and policy strength (p=none vs quarantine/reject)
25. MTA-STS and TLS-RPT (informational)
26. Preset security policies (Standard/Strict) adoption
27. Quarantine policies and user release permissions
28. OWA policies: external storage providers, attachment download on unmanaged devices
29. Mail flow to/from deprecated hybrid Exchange servers
30. Customer Lockbox enabled
31. Mailboxes on litigation hold / retention (informational)
32. Calendar external sharing and free/busy detail exposure

#### D2. SharePoint Online and OneDrive (M365-SPO) — 18 checks
1. External sharing level for tenant and per site
2. "Anyone" links allowed, default link type and expiry
3. Guest access expiration and re-authentication
4. Sharing restricted to allowed domains
5. Sites with "Everyone except external users" permissions on sensitive libraries
6. Legacy auth to SharePoint allowed
7. Unmanaged device access policy (limited/blocked)
8. Idle session sign-out
9. OneDrive sync restricted to domain-joined/Entra-joined devices
10. Default sharing link permission (view vs edit)
11. Site collection admins inventory (orphaned or external admins)
12. Sites without owners
13. Infected file download blocked
14. Custom script allowed on sites
15. Site creation by users
16. OneDrive retention for departed users
17. Sensitivity labels for sites applied
18. Oversharing report summary (sites with most broad grants)

#### D3. Teams (M365-TMS) — 14 checks
1. External access (federation) open to all domains
2. Communication with unmanaged Teams accounts (consumer) allowed
3. Guest access settings and guest capabilities
4. Anonymous users can join and start meetings
5. Lobby bypass settings
6. Third-party and custom app upload allowed
7. App permission policies and blocked apps
8. Teams created without owners
9. Teams with guests and sensitive labels
10. Email into channels allowed
11. Cloud storage providers enabled in Teams
12. Meeting recording storage and expiration
13. External chat file sharing
14. Teams admin roles assignments

#### D4. Intune and endpoint management (M365-INT) — 30 checks
1. MDM authority and enrollment restrictions (personal devices, platforms)
2. Device compliance policies exist for each platform
3. "Mark devices with no compliance policy as" set to Not compliant
4. Compliance grace periods too long
5. BitLocker / FileVault enforced through compliance or configuration
6. Defender for Endpoint onboarding via Intune and compliance risk level integration
7. Security baselines deployed (Windows, Edge, Defender) and assignment coverage
8. Attack surface reduction rules in block mode
9. Windows LAPS policy via Intune
10. Local admin management (account protection / local user group membership policies)
11. Credential Guard, LSA protection, and Windows Hello for Business policies
12. Firewall policies per profile
13. Windows Update rings: deferral too long, update compliance
14. App protection policies (MAM) for iOS/Android
15. Conditional Access dependency on compliance (devices without policy)
16. Intune RBAC: custom roles and scope tags too broad
17. Multi-admin approval for scripts, wipes and app deployment
18. PowerShell scripts and remediations deployed: who can create, what runs as SYSTEM
19. Win32 apps deployed from writable or external sources
20. Enrollment of DCs or Tier 0 servers into Intune/co-management (cloud-to-Tier-0 path)
21. Device cleanup rules
22. Stale and non-compliant device counts
23. Autopilot profile settings (user as local admin)
24. Enrollment Status Page blocking settings
25. Corporate device identifiers / device enrollment managers
26. Endpoint Privilege Management rules (elevation without approval)
27. Remote help and remote actions permissions
28. Configuration conflicts and policy errors
29. macOS/iOS/Android OS minimum versions enforced
30. Co-management workload split with ConfigMgr

#### D5. Purview, audit and data protection (M365-PUR) — 14 checks
1. Unified audit log enabled and retention (Audit Standard vs Premium)
2. Audit log search role holders
3. Sensitivity labels published and default labeling
4. Auto-labeling policies
5. DLP policies for Exchange, SharePoint, OneDrive, Teams and endpoints
6. DLP policies in test mode for a long time
7. Retention policies for key workloads
8. eDiscovery admin and eDiscovery Manager role holders
9. Insider risk management configured (informational)
10. Communication compliance (informational)
11. Customer Key / double key encryption (informational)
12. Alert policies enabled (default high-severity alerts)
13. Information barriers (informational)
14. Content search permissions too broad

#### D6. Defender XDR and security tooling posture (M365-DEF) — 14 checks
1. Defender for Endpoint coverage (onboarded vs total devices)
2. Tamper protection enabled
3. EDR in block mode
4. Network protection and web protection
5. Automated investigation and remediation level
6. Defender for Identity sensors health and coverage (links to AD-AUD-6)
7. Defender for Cloud Apps connected apps and session policies
8. Defender for Office 365 coverage (links to D1)
9. Device exclusions and global exclusions in AV (too broad paths, processes)
10. Unified RBAC in Defender portal: who can run live response
11. Live response unsigned scripts allowed
12. Exposure Management / Secure Score trend (informational)
13. Incidents unresolved older than 30 days
14. Streaming API / SIEM connection

### PART E: Azure resources (identity-relevant)

#### E1. Azure control plane and RBAC (AZ-RBAC) — 22 checks
1. Management group hierarchy and root management group access
2. Owner, Contributor and User Access Administrator assignments at root/MG/subscription scope
3. Permanent vs PIM-eligible Azure role assignments
4. Guests with Azure roles
5. Service principals and managed identities with Owner/UAA
6. Custom Azure roles with `*` actions or `Microsoft.Authorization/*/write`
7. Classic administrators (co-admins) still present
8. Orphaned role assignments (deleted principals)
9. Subscriptions without owners or security contacts
10. Resource locks on critical resources (identity infrastructure)
11. Azure Policy assignments for security baseline (informational coverage)
12. Defender for Cloud plans enabled per subscription
13. Defender for Cloud secure score and high-severity recommendations
14. Activity log exported to Log Analytics / SIEM
15. Azure Lighthouse delegations to external tenants
16. Automation accounts with Run As / managed identities holding high privileges
17. Logic Apps / Functions with privileged managed identities
18. Storage accounts with shared key access and public blob access
19. Deployment scripts / runbooks containing credentials (keyword scan)
20. Azure VMs hosting DCs: who has VM Contributor, Run Command, disk snapshot rights (Tier 0 exposure)
21. Azure Arc-connected servers that are DCs or Tier 0, and who can run extensions on them
22. Azure Bastion / JIT VM access for Tier 0 VMs

#### E2. Key Vault and secrets (AZ-KV) — 10 checks
1. Key Vaults using access policies instead of RBAC
2. Broad secret/key get or list permissions
3. Soft delete and purge protection
4. Public network access enabled
5. Secrets and certificates without expiry, or expiring soon
6. Secret rotation for app credentials stored in vaults
7. Key Vault diagnostic logging
8. Managed HSM / key type and size for critical keys
9. Vaults holding ADFS / Entra Connect / CA material (Tier 0 vaults)
10. Firewall and private endpoint configuration

### PART F: Endpoints and member servers

Collected per machine through WinRM/CIM (agentless) or by a lightweight script deployed via GPO/Intune that drops results into a share. Every check runs per machine and is rolled up as "x of y machines failing."

#### F1. Windows endpoint and server hardening (EP-HARD) — 46 checks
1. Local Administrators group membership (Domain Users, Everyone, unexpected groups)
2. Local accounts enabled (built-in Administrator, Guest)
3. LAPS-managed local admin present and password fresh
4. Credential Guard running
5. LSA protection (RunAsPPL)
6. WDigest disabled
7. Cached domain logons count
8. SMBv1 enabled
9. SMB signing required (client and server)
10. LLMNR and NBT-NS disabled
11. WPAD / proxy auto-detect
12. WebClient service running (relay surface)
13. Print Spooler running on servers that are not print servers
14. RDP enabled, NLA required, restricted admin / remote credential guard
15. WinRM listeners over HTTP and allowed hosts
16. PowerShell v2 engine installed
17. PowerShell logging (script block, transcription)
18. Constrained language mode / AppLocker / WDAC enforcement
19. Windows Firewall enabled with inbound default block
20. BitLocker enabled on OS drive, recovery key escrowed
21. Secure Boot and TPM status
22. Virtualization-based security and HVCI
23. Defender AV real-time protection and signature age
24. Defender exclusions on the machine
25. ASR rules effective state
26. OS build and patch age, missing critical updates
27. Unsupported OS versions
28. Installed software with known critical vulnerabilities (version inventory matched against a local CVE list)
29. Services running as domain accounts (credential exposure on the box)
30. Services with unquoted paths or writable binaries
31. Scheduled tasks running as privileged domain accounts
32. Autoruns in user-writable locations
33. Writable directories in the system PATH
34. AlwaysInstallElevated enabled
35. UAC settings (admin approval mode, remote UAC token filtering LocalAccountTokenFilterPolicy)
36. Stored credentials (Credential Manager entries for domain accounts, count only)
37. Privileged domain accounts with sessions on the machine (Tier violation, feeds attack graph)
38. Shares with Everyone/Authenticated Users write access
39. NTLM settings (LmCompatibilityLevel, outgoing NTLM restrictions)
40. TLS 1.0/1.1 and weak ciphers enabled
41. Audit policy and event log sizes
42. Sysmon / EDR agent present and healthy
43. Remote Registry service running
44. Anonymous enumeration settings
45. Windows Hello for Business and smart card policies (workstations)
46. Kiosk/shared machine autologon with stored password (Winlogon DefaultPassword)

#### F2. Tier 0 servers beyond DCs (EP-T0) — 10 checks
1. AD CS servers hardened like DCs (all F1 checks enforced at higher severity)
2. Entra Connect server hardening and local admins
3. ADFS / WAP servers hardening
4. PAM / PAW / jump servers: who can log on, internet access
5. Backup servers with DC backups: who has admin
6. Hypervisor hosts running virtual DCs: who has admin (vCenter/Hyper-V)
7. SCCM site servers with control over DCs
8. Monitoring/agent servers that can run code on DCs (SCOM, Ansible, Puppet, RMM tools)
9. Tier 0 servers reachable from user VLANs (network exposure, informational)
10. Tier 0 servers with internet browsing or email clients installed

### PART G: Per-setting baseline compliance (BSL)

Instead of one check per topic, this part compares **every individual setting** against the published baselines and reports each deviation. These checks are generated from the baseline files, not written by hand.

| Baseline | Applies to | Approx. settings |
|---|---|---|
| CIS Microsoft Windows Server 2016/2019/2022/2025 (DC profile, L1 and L2) | Domain controllers | 350 to 400 per version |
| CIS Windows Server (Member Server profile) | Member servers | 350 to 400 |
| CIS Windows 10/11 Enterprise | Workstations | 400 to 450 |
| Microsoft Security Baselines (Server, Windows 11, Edge, Defender, Office) | All | about 600 combined |
| CIS Microsoft 365 Foundations | Tenant | about 130 |
| CIS Microsoft Azure Foundations | Azure | about 150 |
| CISA SCuBA (Entra, Exchange, Defender, SharePoint, Teams, Power Platform) | Tenant | about 200 |
| DISA STIG for Active Directory Domain and Forest, Windows Server | AD and DCs | about 300 |

Each setting check reports expected value, actual value, where it was set (which GPO, Intune profile or local), and the baseline reference. Customers pick which baselines apply; settings that duplicate a hand-written check link to it instead of being counted twice. This adds **roughly 2,000 to 3,000 generated setting checks** depending on which baselines are selected.

### PART H: Beyond configuration: threat hunting and compromise assessment (HUNT)

These look at activity and history, not settings, to answer "has something already happened?" They run from the collected event summaries, replication metadata and Entra logs.

#### H1. On-prem hunt (HUNT-AD) — 24 checks
1. DCSync performed by a non-DC (event 4662 with replication GUIDs)
2. Kerberoasting patterns (many TGS requests with RC4 from one account)
3. AS-REP roasting attempts (4768 without preauth)
4. Password spraying (4625/4771 across many accounts from one source)
5. Brute force and lockout storms
6. Golden ticket indicators (TGS without prior TGT, abnormal ticket lifetimes)
7. Silver ticket / forged PAC indicators (KDC PAC validation events)
8. Pass-the-hash / overpass-the-hash patterns (4624 logon type 9, NTLM from unusual hosts)
9. DCShadow (new nTDSDSA objects, unexpected SPN registration of GC/E3514235)
10. AdminSDHolder or domain root ACL changes (5136)
11. New members added to privileged groups (4728/4732/4756) in the window
12. GPO changes outside change windows
13. New services or scheduled tasks created on DCs (7045/4698)
14. Security log cleared (1102) or audit policy changed (4719)
15. SID History injection (4765/4766)
16. Shadow credentials writes (msDS-KeyCredentialLink changes)
17. Certificate requests with SAN for privileged users (AD CS event 4886/4887)
18. NTDS.dit access or shadow copy creation on DCs
19. LSASS access by unexpected processes (if Sysmon/EDR data available)
20. Coercion attempts (PetitPotam, PrinterBug: EFSRPC/MS-RPRN events)
21. Anomalous logon of admin accounts to non-Tier 0 machines
22. Accounts with sudden SPN additions followed by TGS requests
23. Replication metadata timeline: objects changed on unexpected DCs or at odd times
24. Known attack-tool artifacts (default names: Mimikatz service names, Impacket patterns, atexec task names)

#### H2. Cloud hunt (HUNT-EN) — 20 checks
1. Impossible travel and anomalous sign-ins (beyond what Identity Protection flagged)
2. Token replay indicators (same session from different IPs/devices)
3. Password spray against Entra (many users, few attempts, one IP or ASN)
4. MFA fatigue (repeated denied pushes followed by approval)
5. New credentials added to existing apps or service principals
6. New federated domain or federation certificate change
7. Consent grants to unfamiliar or newly registered apps
8. New privileged role assignments outside PIM
9. Conditional Access policy disabled or modified
10. Mailbox rules created right after a risky sign-in
11. Mass file download or sharing in SharePoint/OneDrive
12. Device code phishing patterns (device code flow sign-ins)
13. Sign-ins from anonymizers / TOR / hosting ASNs
14. Guest invitations at scale
15. Partner (GDAP) relationship changes
16. Azure: role assignments at root scope, elevate-access events
17. Azure: Run Command / extension execution on DC VMs
18. Key Vault secret reads by unusual identities
19. Service principal sign-ins from new locations
20. Changes to sync settings or Entra Connect accounts

Hunt results are presented as **"Observations"** with a confidence level, separate from configuration findings, so a clean config score never hides an active incident. They depend on the log window collected (default 30 days on-prem, 30 days Entra; configurable).

### PART I: Keeping the catalog current

- A versioned catalog file is released separately from the engine, so new checks ship without a tool upgrade.
- Sources tracked for new checks: Microsoft security updates and hardening enforcement timelines, new AD CS ESC research, CISA advisories, SCuBA and CIS releases, MITRE ATT&CK updates.
- Every check records the date added and the catalog version, and the dashboard shows "new since your last run."

---

**Totals.** Hand-written checks: On-prem AD 358, Entra ID 158, Hybrid 34, Microsoft 365 workloads 122, Azure 32, Endpoints and Tier 0 servers 56, Threat hunting 44, for **804 in all** (about a dozen are deliberate cross-links). On top of that, Part G generates **roughly 2,000 to 3,000 per-setting baseline checks** depending on which baselines are selected. None of this is a cap: adding a check is one file, and Part I keeps the catalog growing.

---

## 4. Telemetry collection

### What gets collected

| Source | Method | Rights needed |
|---|---|---|
| All AD objects and key attributes (users, computers, groups, OUs, GPOs, trusts, sites, subnets, PKI, DNS zones, schema, config) | Paged LDAP queries via `System.DirectoryServices`, one per partition | Domain user (some attributes like LAPS need delegated read, which itself becomes a finding) |
| Security descriptors (ACLs) on sensitive objects and all OUs/GPOs | LDAP `nTSecurityDescriptor` with SD flags | Domain user |
| Replication metadata (`msDS-ReplAttributeMetaData`, `msDS-ReplValueMetaData`) | LDAP | Domain user |
| Replication status | `repadmin`-equivalent via LDAP `msDS-ReplNeighbor` / RPC | Domain user (some details need admin) |
| SYSVOL contents (GPO files, scripts, GPP XML) | SMB read of `\\domain\SYSVOL` | Domain user |
| DC configuration (registry hardening values, services, installed features, hotfixes, auditpol, firewall, TLS) | WinRM / remote registry / CIM, per DC | Local admin on DCs (optional tier) |
| DC security event summaries (NTLMv1, unsigned LDAP, RC4, Netlogon, 1102) | `Get-WinEvent` with XPath filters, last N days, counts plus samples only | Event Log Readers on DCs |
| AD CS configuration | LDAP (templates, CAs) + optional `certutil`/RPC to CA for flags | Domain user; CA flags need CA read |
| DNS zones and settings | LDAP for ADIDNS + optional DNS server CIM | Domain user / DnsAdmins read |
| Entra ID configuration | Microsoft Graph v1.0 and beta (read-only) | App registration or delegated with read scopes (see below) |
| Entra sign-in and audit logs | Graph `auditLogs/*`, last 30 days, aggregated | `AuditLog.Read.All` (needs P1) |
| Entra Connect server | Optional local collection on the sync server (config export, version) | Local admin on sync server |
| Exchange Online, Teams, SharePoint, Purview | Graph plus the Exchange Online / Teams / SharePoint PowerShell endpoints (read-only cmdlets: Get-*) | Global Reader plus Exchange View-Only Organization Management; SharePoint admin read |
| Intune and Defender XDR | Graph `deviceManagement/*` and Defender APIs | `DeviceManagementConfiguration.Read.All`, `DeviceManagementManagedDevices.Read.All`, `DeviceManagementRBAC.Read.All`, Defender `Machine.Read.All`, `SecurityRecommendation.Read.All` |
| Azure resources | Azure Resource Manager and Azure Resource Graph REST | Reader + (for RBAC at root) Reader at root management group |
| Endpoints and member servers | Agentless WinRM/CIM in batches, or a collection script deployed by GPO/Intune that writes to a share | Local admin on targets (agentless) or SYSTEM via deployment |
| Baselines | Effective settings from the same DC/endpoint/tenant collectors, compared to baseline definition files shipped with the catalog | Same as the source collectors |
| Hunting data | Extended event queries on DCs (selected event IDs, last N days), Entra sign-in/audit logs, Azure activity log, unified audit log; optional import of existing SIEM exports or MDI/MDE advanced hunting queries | Event Log Readers; `AuditLog.Read.All`; `ThreatHunting.Read.All` for advanced hunting |

### Collection tiers

The operator picks a tier so the tool runs even where rights are limited:

- **Tier A, "Domain user"**: LDAP + SYSVOL only. Covers roughly 70% of on-prem checks.
- **Tier B, "Domain user + DC read"**: adds DC registry, services, events. Covers nearly everything on-prem.
- **Tier C, "Entra read"**: Graph with read scopes: `Directory.Read.All`, `Policy.Read.All`, `RoleManagement.Read.All`, `AuditLog.Read.All`, `UserAuthenticationMethod.Read.All`, `IdentityRiskyUser.Read.All`, `IdentityRiskEvent.Read.All`, `Application.Read.All`, `PrivilegedAccess.Read.AzureADGroup`, `RoleEligibilitySchedule.Read.Directory`, `SecurityEvents.Read.All`, `CrossTenantInformation.ReadBasic.All`, `Device.Read.All`, `Reports.Read.All`, `OnPremDirectorySynchronization.Read.All`. Global Reader role is enough for delegated mode.

- **Tier D, "Workloads"**: Microsoft 365, Intune, Defender and Azure read access.
- **Tier E, "Endpoints"**: per-machine collection on workstations and member servers (sampled or full).
- **Tier F, "Hunt"**: extended log collection for the threat-hunting module.

Checks whose data was not collected show as **Not assessed** with the reason, so the score stays honest.

### Bundle format

```
dcassessor-<forest>-<tenant>-<yyyyMMdd-HHmm>.zip
  manifest.json      tool version, catalog version, tier, who ran it, where, start/end, per-collector status
  raw/ad/<domain>/users.json, groups.json, acls.json, gpo/*.json, ...
  raw/dc/<dcname>/registry.json, services.json, events.json, ...
  raw/entra/<tenantId>/users.json, ca-policies.json, roles.json, apps.json, ...
  logs/collection.log
  hashes.sha256      integrity of every file
```

Sensitive data handling: no password hashes or secrets are ever collected. LAPS values, BitLocker keys and gMSA blobs are **never** read, only who can read them. The bundle can optionally be encrypted with a passphrase. A `-Redact` switch replaces names with stable pseudonyms for sharing with third parties.

### Performance targets

- Paged LDAP with attribute selection; 100k-object domains should collect in under 15 minutes.
- Graph calls batched (`$batch`), with throttling back-off and `$select` everywhere.
- Per-DC collection runs in parallel (runspaces) with a concurrency cap.
- Resumable: collectors write per-area files so a failure in one area does not lose the others.

---

## 5. Analysis engine

1. **Load** the bundle and normalize into an in-memory model (objects by SID/objectId, group membership expanded recursively, ACL entries resolved to principals).
2. **Run checks.** Each check definition has:
   ```
   Id, Title, Area, Severity, Platform (AD | Entra | Hybrid),
   RequiresTier, DataSources, Rule (scriptblock returning affected objects),
   Threshold/parameters (overridable per customer),
   Description, Impact, Remediation (with PowerShell/portal steps),
   References (MS docs, ANSSI, CIS, MITRE technique IDs)
   ```
   Result per check: `Pass | Fail | Warning | Not assessed | Error | Info`, plus affected object list and evidence values.
3. **Attack-path graph.** Build a directed graph (nodes: users, groups, computers, GPOs, OUs, templates, Entra principals, apps, roles; edges: MemberOf, GenericAll, WriteDACL, AddKeyCredentialLink, AllowedToDelegate, CanEnroll-ESC, HasSession, SyncedTo, OwnsApp, HasRole…). Compute shortest paths from "Everyone/Domain Users/All guests" to Tier 0. This powers AD-ACL-28 and HY-PATH-6 and the graph view in the dashboard.
4. **Scoring.**
   - Per-check weight = severity × exposure (number and privilege of affected objects).
   - Area score 0 to 100, overall score 0 to 100, and a maturity level (1 to 5, similar to the ANSSI/PingCastle style so it reads familiarly).
   - Separate scores for On-prem, Entra, Hybrid.
5. **Compliance views.** Results rolled up per framework: CIS, ANSSI, Microsoft baselines, MITRE ATT&CK matrix coverage, NIST CSF 2.0 functions.
6. **Diff between runs.** Given two bundles: new findings, fixed findings, score trend, new privileged accounts, new risky apps.
7. **Exceptions.** A customer exception file (check ID + object + reason + expiry) marks accepted risks so they show as "Accepted" rather than "Fail".

---

## 6. Dashboard

Single self-contained HTML file (`DCAssessor-Dashboard.html`), results embedded, opens offline in any modern browser. Light and dark themes.

**Pages:**

1. **Overview.** Overall score gauge and maturity level; On-prem / Entra / Hybrid score tiles; counts by severity; top 10 risks with one-line impact; trend line when multiple runs exist.
2. **Areas heatmap.** All 47 areas (46 plus baselines) as a grid colored by score; click to drill in.
3. **Findings explorer.** Filterable, searchable table (severity, area, platform, status, framework). Each row expands to description, impact, affected objects (paged list with export), evidence values, remediation steps with copyable commands, references.
4. **Privileged access.** Tier 0 inventory, privileged group membership tree (nested), Entra role assignments (permanent vs. eligible), break-glass status, admin MFA strength.
5. **Attack paths.** Interactive graph (force layout) showing shortest paths to Domain Admins / Global Admin, with node details; "top choke points" list (fixing one edge breaks the most paths).
6. **Identity hygiene.** Stale users/computers/guests, password age histograms, password-never-expires, kerberoastable and AS-REP roastable counts.
7. **Authentication.** MFA registration coverage, method mix, legacy auth usage, NTLMv1/RC4/unsigned LDAP volumes from DCs, Conditional Access coverage matrix (users × apps).
8. **Infrastructure.** DC table (OS, patch age, hardening flags as green/red chips), replication matrix, site/subnet map, AD CS templates with ESC flags, trusts diagram.
9. **Applications.** Risky apps and permissions, expiring credentials timeline, consent grants.
10. **Compliance.** Framework scorecards and the MITRE ATT&CK matrix with techniques highlighted.
11. **Microsoft 365.** Exchange, SharePoint, Teams, Purview and Defender posture, mail authentication (SPF/DKIM/DMARC) per domain.
12. **Intune and endpoints.** Fleet hardening matrix (machines × controls), patch age, local admin sprawl, Tier 0 server status.
13. **Azure.** RBAC exposure by scope, privileged identities, Key Vault and DC VM exposure.
14. **Baselines.** Per-baseline compliance percentage, drill-down to every failing setting with expected vs actual and source GPO/profile.
15. **Threat hunting.** Observations timeline with confidence, kept separate from the config score, with an "active incident suspected" banner when high-confidence observations exist.
16. **Compare.** Side-by-side of two runs.
17. **Collection info.** What was collected, tier, gaps ("Not assessed" list) and errors, so readers know the limits.

Charts with ECharts (bundled), graph view with Cytoscape.js (bundled). All assets inlined so nothing loads from the internet.

---

## 7. Reports

| Report | Audience | Format | Content |
|---|---|---|---|
| Executive summary | Leadership | PDF (and HTML) | 3 to 5 pages: score, maturity, top risks in business language, trend, key recommendations, effort estimate |
| Full technical report | Admins / security team | PDF + HTML | Everything: methodology, scope, per-area results, every finding with evidence, remediation, references; appendix of affected objects |
| Remediation plan | Project managers | XLSX + CSV | One row per finding: ID, severity, effort (S/M/L), owner, quick win flag, suggested order (phased: 30 / 90 / 180 days) |
| Raw results | Automation / SIEM | JSON, CSV, SARIF | Machine-readable output for tickets and pipelines |
| Delta report | Ongoing programs | PDF + HTML | What changed since the last assessment |

Customizable: company logo, colors, assessor name, scope statement, classification marking. PDF generated by printing the HTML through headless Edge/Chromium so the report and dashboard share one design.

---

## 8. How an operator runs it

```powershell
Import-Module DCAssessor

# Collect (on a domain-joined machine)
Invoke-DCACollection -Domain contoso.com -Tier B -IncludeEntra -TenantId <id> -OutputPath .\out

# Analyze and build outputs (can be on another machine)
Invoke-DCAAnalysis -Bundle .\out\dcassessor-contoso-...zip -Exceptions .\exceptions.json
New-DCADashboard -Results .\out\results.json
New-DCAReport -Results .\out\results.json -Type Executive,Technical,Remediation -Format PDF,XLSX
```

Also: `Compare-DCARun -Old <bundle> -New <bundle>` and a `-WhatIf`-style `Test-DCAPrerequisites` that reports which tier and which checks will be possible before collecting.

---

## 9. Quality and testing

- **Pester unit tests** per check using small fixture bundles (one passing, one failing case each).
- **Lab environment**: a scripted vulnerable lab (e.g., GOAD or a Hyper-V/Azure lab built from scripts) plus a test Entra tenant (Microsoft 365 developer tenant) seeded with known misconfigurations; expected-findings file asserts each is detected.
- **Read-only guard**: a test that scans collector code for write cmdlets/verbs (`Set-`, `New-`, `Remove-`, LDAP modify) and fails the build.
- **Accuracy cross-check** against established tools (PingCastle, Purple Knight, ScubaGear/Maester) on the same lab to catch gaps and false positives.
- CI on GitHub Actions: PSScriptAnalyzer, Pester, dashboard build, catalog schema validation, generated check reference docs.

---

## 10. Delivery phases

| Phase | Scope | Outcome |
|---|---|---|
| 0. Foundations | Repo layout, module skeleton, bundle format, check definition schema, CI, read-only guard | Empty pipeline runs end to end |
| 1. On-prem core | Collectors for LDAP, ACLs, SYSVOL; areas A1, A4, A5, A6, A7, A8, A9, A10, A11 (~190 checks) | First useful on-prem assessment |
| 2. Dashboard + reports v1 | Overview, findings explorer, privileged access pages; executive and technical HTML/PDF; CSV/JSON | Shareable output |
| 3. On-prem depth | DC remote collection (Tier B), events; areas A2, A3, A12–A22; attack-path graph | Full on-prem coverage |
| 4. Entra ID | Graph collector; areas B1–B9 (~158 checks) | Full cloud coverage |
| 5. Hybrid | C1–C3, combined attack graph | Cross-boundary findings |
| 6. Polish | Compare runs, exceptions, frameworks pages, XLSX remediation plan, redaction, encryption, branding | Production-ready release |
| 7. Microsoft 365 and Azure | Parts D and E (~154 checks) | Workload and cloud infrastructure coverage |
| 8. Endpoints | Part F (~56 checks), agentless and deployed-script collectors, fleet roll-ups | Coverage beyond DCs |
| 9. Baselines | Part G generator and baseline definition files (CIS, Microsoft, SCuBA, STIG) | Per-setting compliance |
| 10. Threat hunting | Part H (~44 checks), extended log collection, observations view | Compromise assessment alongside configuration review |

---

## 11. Decisions for you

1. **Language.** All-PowerShell (recommended, simplest to deploy on Windows servers) or PowerShell collectors with a Python/.NET analyzer.
2. **Dashboard form.** Single offline HTML file (recommended) or a hosted web app with history stored in a database.
3. **Where to start.** Phase 1 on-prem first (recommended, since it is the larger and higher-risk surface) or Entra first.
4. **Licensing / distribution.** Internal tool, open source, or commercial; this affects branding and which third-party libraries we bundle.
5. **Baselines to license.** CIS benchmarks have usage terms for commercial tools; Microsoft baselines, SCuBA and STIGs are free. Decide whether CIS content is in scope.
6. **Endpoint collection mode.** Agentless WinRM (recommended for assessments) or a deployed script (better for large fleets).
