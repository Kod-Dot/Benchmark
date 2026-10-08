<script lang="ts" module>
  import type { CollectScope } from '../lib/types';

  export interface AreaRow {
    /** `scope:area`, unique across both collectors. */
    key: string;
    scope: CollectScope;
    area: string;
    label: string;
    state: 'waiting' | 'reading' | 'read' | 'failed' | 'unlicensed';
    count: number;
    message: string;
  }

  /** The on-prem collector's areas, in the order it reads them. */
  export const COLLECTOR_AREAS: { area: string; label: string; source: string }[] = [
    { area: 'domain', label: 'Domain head and password policy', source: 'ldap' },
    { area: 'partitions', label: 'Forest configuration', source: 'ldap' },
    { area: 'dirservice', label: 'Directory service settings', source: 'ldap' },
    { area: 'schema', label: 'Schema', source: 'ldap' },
    { area: 'users', label: 'Users', source: 'ldap' },
    { area: 'computers', label: 'Computers', source: 'ldap' },
    { area: 'groups', label: 'Groups', source: 'ldap' },
    { area: 'containers', label: 'OUs and containers', source: 'ldap' },
    { area: 'gpos', label: 'Group Policy objects', source: 'ldap' },
    { area: 'trusts', label: 'Trusts', source: 'ldap' },
    { area: 'acls', label: 'Permissions on sensitive objects', source: 'ldap' },
    { area: 'roles', label: 'Operations master roles', source: 'ldap' },
    { area: 'querypolicy', label: 'LDAP query policy', source: 'ldap' },
    { area: 'ncheads', label: 'Configuration and schema permissions', source: 'ldap' },
    { area: 'dispspec', label: 'Display specifier menus', source: 'ldap' },
    { area: 'extrights', label: 'Extended rights', source: 'ldap' },
    { area: 'privmeta', label: 'Privileged group change history', source: 'ldap' },
    { area: 'attrmeta', label: 'SPN and key credential change history', source: 'ldap' },
    { area: 'wmifilters', label: 'WMI filters', source: 'ldap' },
    { area: 'computerowners', label: 'Computer object owners', source: 'ldap' },
    { area: 'sacls', label: 'Audit entries of sensitive objects', source: 'ldap' },
    { area: 'exchservers', label: 'Exchange servers', source: 'ldap' },
    { area: 'scps', label: 'Service connection points', source: 'ldap' },
    { area: 'sccm', label: 'Configuration Manager in AD', source: 'ldap' },
    { area: 'gpsoftware', label: 'GPO software packages', source: 'ldap' },
    { area: 'msas', label: 'Managed service accounts', source: 'ldap' },
    { area: 'psos', label: 'Fine-grained password policies', source: 'ldap' },
    { area: 'pwdattrs', label: 'Readable password attributes', source: 'ldap' },
    { area: 'keycreds', label: 'Key credentials on accounts', source: 'ldap' },
    { area: 'bitlocker', label: 'BitLocker recovery objects', source: 'ldap' },
    { area: 'kds', label: 'KDS root keys', source: 'ldap' },
    { area: 'authn', label: 'Authentication policies and silos', source: 'ldap' },
    { area: 'sites', label: 'Sites, subnets and site links', source: 'ldap' },
    { area: 'dnszones', label: 'DNS zones (domain)', source: 'ldap' },
    { area: 'dnsforestzones', label: 'DNS zones (forest)', source: 'ldap' },
    { area: 'pki', label: 'Certificate services (AD CS)', source: 'ldap' },
    { area: 'sysvol', label: 'SYSVOL policy files', source: 'sysvol' },
    { area: 'scripts', label: 'Logon scripts (credential scan)', source: 'sysvol' },
    { area: 'dcconfig', label: 'Domain controller configuration', source: 'dc-remote' },
    { area: 'dcevents', label: 'Domain controller event logs', source: 'dc-events' },
    { area: 'endpoints', label: 'Member servers and workstations', source: 'endpoints' },
  ];

  /** The Entra collector's areas (collectors/Invoke-DCAEntra.ps1), in order. */
  export const ENTRA_AREAS: { area: string; label: string; source?: string }[] = [
    { area: 'signin', label: 'Microsoft sign-in' },
    { area: 'organization', label: 'Organization settings' },
    { area: 'skus', label: 'Licences' },
    { area: 'domains', label: 'Domains' },
    { area: 'federation', label: 'Federation settings' },
    { area: 'users', label: 'Users' },
    { area: 'signinactivity', label: 'User sign-in activity' },
    { area: 'groups', label: 'Groups' },
    { area: 'groupowners', label: 'Group owners' },
    { area: 'rolegroupmembers', label: 'Members of role-assignable groups' },
    { area: 'roledefinitions', label: 'Role definitions' },
    { area: 'roleassignments', label: 'Role assignments' },
    { area: 'roleeligibility', label: 'PIM eligible assignments' },
    { area: 'roleschedules', label: 'PIM assignment schedules' },
    { area: 'pimpolicies', label: 'PIM role settings' },
    { area: 'capolicies', label: 'Conditional Access policies' },
    { area: 'namedlocations', label: 'Named locations' },
    { area: 'authstrengths', label: 'Authentication strengths' },
    { area: 'authmethods', label: 'Authentication methods policy' },
    { area: 'authorization', label: 'Authorization policy' },
    { area: 'securitydefaults', label: 'Security defaults' },
    { area: 'adminconsent', label: 'Admin consent requests' },
    { area: 'crosstenant', label: 'Cross-tenant access defaults' },
    { area: 'crosstenantpartners', label: 'Cross-tenant partners' },
    { area: 'deviceregistration', label: 'Device registration policy' },
    { area: 'groupsettings', label: 'Directory settings' },
    { area: 'grouplifecycle', label: 'Group expiration' },
    { area: 'registration', label: 'Authentication method registration' },
    { area: 'applications', label: 'App registrations' },
    { area: 'serviceprincipals', label: 'Enterprise applications' },
    { area: 'resources', label: 'Microsoft resource applications' },
    { area: 'approleassignments', label: 'Application permissions' },
    { area: 'grants', label: 'Delegated permission grants' },
    { area: 'devices', label: 'Devices' },
    { area: 'onpremsync', label: 'Directory synchronization settings' },
    { area: 'adminunits', label: 'Administrative units' },
    { area: 'contracts', label: 'Partner contracts' },
    { area: 'riskyusers', label: 'Risky users' },
    { area: 'riskdetections', label: 'Risk detections' },
    { area: 'riskysps', label: 'Risky service principals' },
    { area: 'spsignins', label: 'Service principal sign-in activity' },
    { area: 'fedcreds', label: 'Federated identity credentials' },
    { area: 'accessreviews', label: 'Access reviews' },
    { area: 'pimalerts', label: 'PIM alerts' },
    { area: 'branding', label: 'Company branding' },
    { area: 'intunesettings', label: 'Intune tenant settings' },
    { area: 'intuneenrollment', label: 'Intune enrollment restrictions and status pages' },
    { area: 'intunecompliance', label: 'Intune compliance policies' },
    { area: 'intuneconfigs', label: 'Intune configuration profiles' },
    { area: 'intunepolicies', label: 'Intune settings catalog and endpoint security policies' },
    { area: 'intuneintents', label: 'Intune security baselines' },
    { area: 'intuneconfigstatus', label: 'Intune profile deployment status' },
    { area: 'intuneappprotection', label: 'Intune app protection policies' },
    { area: 'intuneroles', label: 'Intune roles' },
    { area: 'intuneroleassignments', label: 'Intune role assignments' },
    { area: 'intuneapprovals', label: 'Intune multi-admin approval' },
    { area: 'intunescripts', label: 'Intune PowerShell scripts' },
    { area: 'intuneremediations', label: 'Intune remediations' },
    { area: 'intuneapps', label: 'Intune Win32 apps' },
    { area: 'intunecleanup', label: 'Intune device cleanup rule' },
    { area: 'intuneautopilot', label: 'Autopilot profiles' },
    { area: 'intunecorporateids', label: 'Intune corporate device identifiers' },
    { area: 'intuneremotehelp', label: 'Remote Help settings' },
    { area: 'intunemtd', label: 'Intune mobile threat defense connectors' },
    { area: 'intunedevices', label: 'Intune managed devices' },
    { area: 'sposettings', label: 'SharePoint tenant settings' },
    { area: 'teamguests', label: 'Guests in each team' },
    { area: 'bitlockerkeys', label: 'BitLocker recovery key metadata' },
    { area: 'groupmembers', label: 'Group members (first 20 of each)' },
    { area: 'b2bmanagement', label: 'Guest invitation domain lists' },
    { area: 'uxsetting', label: 'Admin center access setting' },
    { area: 'appproxy', label: 'App Proxy applications' },
    { area: 'securescore', label: 'Secure Score' },
    { area: 'audits', label: 'Audit log: roles, apps, policies and settings', source: 'graph-logs' },
    { area: 'invites', label: 'Audit log: guest invitations', source: 'graph-logs' },
    { area: 'signinslegacy', label: 'Sign-ins over legacy authentication', source: 'graph-logs' },
    { area: 'signinsfailed', label: 'Failed sign-ins and MFA prompts', source: 'graph-logs' },
    { area: 'signinsdevicecode', label: 'Device code sign-ins', source: 'graph-logs' },
    { area: 'signins', label: 'Successful sign-ins (sample)', source: 'graph-logs' },
    { area: 'signinssp', label: 'Service principal sign-ins', source: 'graph-logs' },
    { area: 'exosignin', label: 'Exchange Online sign-in', source: 'exo' },
    { area: 'exoorg', label: 'Exchange organization settings', source: 'exo' },
    { area: 'exoquarantine', label: 'Quarantine policies', source: 'exo' },
    { area: 'exodistgroups', label: 'Distribution groups', source: 'exo' },
    { area: 'exosendas', label: 'Send As permissions', source: 'exo' },
    { area: 'exofullaccess', label: 'Full Access permissions', source: 'exo' },
    { area: 'exoinboxrules', label: 'Inbox rules', source: 'exo' },
    { area: 'exoualinbox', label: 'Audit log: inbox rule changes', source: 'exo' },
    { area: 'exoualfiles', label: 'Audit log: file downloads and anonymous links', source: 'exo' },
    { area: 'exotransport', label: 'Transport settings', source: 'exo' },
    { area: 'exoadminaudit', label: 'Audit log settings', source: 'exo' },
    { area: 'exoaccepteddomains', label: 'Accepted domains', source: 'exo' },
    { area: 'exomailboxes', label: 'Mailboxes', source: 'exo' },
    { area: 'exocas', label: 'Mailbox protocols', source: 'exo' },
    { area: 'exoauditbypass', label: 'Mailbox audit bypass', source: 'exo' },
    { area: 'exoremotedomains', label: 'Remote domains', source: 'exo' },
    { area: 'exooutboundspam', label: 'Outbound spam policies', source: 'exo' },
    { area: 'exooutboundspamrules', label: 'Outbound spam rules', source: 'exo' },
    { area: 'exoappaccess', label: 'Application access policies', source: 'exo' },
    { area: 'exoimpersonation', label: 'Impersonation role assignments', source: 'exo' },
    { area: 'exorolegroups', label: 'Exchange role groups', source: 'exo' },
    { area: 'exoantiphish', label: 'Anti-phishing policies', source: 'exo' },
    { area: 'exoantiphishrules', label: 'Anti-phishing rules', source: 'exo' },
    { area: 'exosafelinks', label: 'Safe Links policies', source: 'exo' },
    { area: 'exosafelinksrules', label: 'Safe Links rules', source: 'exo' },
    { area: 'exosafeattach', label: 'Safe Attachments policies', source: 'exo' },
    { area: 'exosafeattachrules', label: 'Safe Attachments rules', source: 'exo' },
    { area: 'exoatpo365', label: 'Defender for SharePoint, OneDrive and Teams', source: 'exo' },
    { area: 'exomalware', label: 'Anti-malware policies', source: 'exo' },
    { area: 'exomalwarerules', label: 'Anti-malware rules', source: 'exo' },
    { area: 'exocontentfilter', label: 'Anti-spam policies', source: 'exo' },
    { area: 'exocontentfilterrules', label: 'Anti-spam rules', source: 'exo' },
    { area: 'exotransportrules', label: 'Mail flow rules', source: 'exo' },
    { area: 'exoinbound', label: 'Inbound connectors', source: 'exo' },
    { area: 'exooutbound', label: 'Outbound connectors', source: 'exo' },
    { area: 'exodkim', label: 'DKIM signing', source: 'exo' },
    { area: 'exopreset', label: 'Preset security policies', source: 'exo' },
    { area: 'exoowa', label: 'Outlook on the web policies', source: 'exo' },
    { area: 'exosharing', label: 'Calendar sharing policies', source: 'exo' },
    { area: 'exodns', label: 'SPF, DMARC, MTA-STS and TLS-RPT records', source: 'exo' },
    { area: 'armsignin', label: 'Azure Resource Manager sign-in', source: 'arm' },
    { area: 'azmgmtgroups', label: 'Management groups', source: 'arm' },
    { area: 'azsubscriptions', label: 'Subscriptions', source: 'arm' },
    { area: 'azroleassignments', label: 'Azure role assignments', source: 'arm' },
    { area: 'azroledefinitions', label: 'Custom Azure roles', source: 'arm' },
    { area: 'azeligible', label: 'PIM eligible Azure roles', source: 'arm' },
    { area: 'azactive', label: 'Active Azure role instances', source: 'arm' },
    { area: 'azcontacts', label: 'Defender for Cloud security contacts', source: 'arm' },
    { area: 'azpricings', label: 'Defender for Cloud plans', source: 'arm' },
    { area: 'azsecurescore', label: 'Secure score', source: 'arm' },
    { area: 'azdiagnostics', label: 'Activity log export', source: 'arm' },
    { area: 'azlighthouse', label: 'Lighthouse delegations', source: 'arm' },
    { area: 'azpolicies', label: 'Policy assignments', source: 'arm' },
    { area: 'azstorage', label: 'Storage accounts', source: 'arm' },
    { area: 'azvaults', label: 'Key Vaults', source: 'arm' },
    { area: 'azvaultdiagnostics', label: 'Key Vault diagnostic settings', source: 'arm' },
    { area: 'azkvsecrets', label: 'Key Vault secret metadata', source: 'arm' },
    { area: 'azkvkeys', label: 'Key Vault key metadata', source: 'arm' },
    { area: 'azclassicadmins', label: 'Classic subscription administrators', source: 'arm' },
    { area: 'azlocks', label: 'Resource locks', source: 'arm' },
    { area: 'azautomation', label: 'Automation accounts', source: 'arm' },
    { area: 'azlogicapps', label: 'Logic Apps', source: 'arm' },
    { area: 'azwebapps', label: 'App Service and Function apps', source: 'arm' },
    { area: 'azvms', label: 'Virtual machines', source: 'arm' },
    { area: 'azarc', label: 'Azure Arc servers', source: 'arm' },
    { area: 'azjit', label: 'Just-in-time VM access policies', source: 'arm' },
    { area: 'azbastion', label: 'Azure Bastion hosts', source: 'arm' },
    { area: 'azautomationvars', label: 'Automation variables (names only)', source: 'arm' },
    { area: 'azscriptscan', label: 'Runbook and deployment script credential scan', source: 'arm' },
    { area: 'sposignin', label: 'SharePoint Online sign-in', source: 'spo' },
    { area: 'spotenant', label: 'SharePoint tenant configuration', source: 'spo' },
    { area: 'spoidle', label: 'Idle session sign-out', source: 'spo' },
    { area: 'sposync', label: 'OneDrive sync restrictions', source: 'spo' },
    { area: 'sposites', label: 'SharePoint sites', source: 'spo' },
    { area: 'spositeusers', label: 'Site admins and broad grants', source: 'spo' },
    { area: 'tmssignin', label: 'Teams sign-in', source: 'teams' },
    { area: 'tmsfederation', label: 'Teams external access', source: 'teams' },
    { area: 'tmsclient', label: 'Teams client configuration', source: 'teams' },
    { area: 'tmsmeetingconfig', label: 'Teams meeting configuration', source: 'teams' },
    { area: 'tmsmeeting', label: 'Teams meeting policies', source: 'teams' },
    { area: 'tmsguestmeeting', label: 'Teams guest meeting settings', source: 'teams' },
    { area: 'tmsguestmessaging', label: 'Teams guest messaging settings', source: 'teams' },
    { area: 'tmsappsetup', label: 'Teams app setup policies', source: 'teams' },
    { area: 'tmsapppermission', label: 'Teams app permission policies', source: 'teams' },
    { area: 'pursignin', label: 'Security & Compliance sign-in', source: 'purview' },
    { area: 'purlabels', label: 'Sensitivity labels', source: 'purview' },
    { area: 'purlabelpolicies', label: 'Label policies', source: 'purview' },
    { area: 'purautolabel', label: 'Auto-labeling policies', source: 'purview' },
    { area: 'purdlp', label: 'DLP policies', source: 'purview' },
    { area: 'purretention', label: 'Retention policies', source: 'purview' },
    { area: 'puralerts', label: 'Alert policies', source: 'purview' },
    { area: 'purrolegroups', label: 'Purview role groups', source: 'purview' },
    { area: 'purcaseadmins', label: 'eDiscovery administrators', source: 'purview' },
    { area: 'pursecurityfilters', label: 'Search permission filters', source: 'purview' },
    { area: 'purauditretention', label: 'Audit log retention policies', source: 'purview' },
    { area: 'purbarriers', label: 'Information barrier policies', source: 'purview' },
    { area: 'purinsider', label: 'Insider risk policies', source: 'purview' },
    { area: 'purcommunication', label: 'Communication compliance policies', source: 'purview' },
    { area: 'incidents', label: 'Open Defender XDR incidents', source: 'defender' },
    { area: 'mdealerts', label: 'Defender for Endpoint alerts', source: 'defender' },
    { area: 'securescores', label: 'Secure Score history', source: 'defender' },
    { area: 'mdisensors', label: 'Defender for Identity sensors', source: 'defender' },
    { area: 'mdihealth', label: 'Defender for Identity health issues', source: 'defender' },
    { area: 'intuneprotection', label: 'Windows device protection state', source: 'defender' },
    { area: 'mdesignin', label: 'Defender for Endpoint sign-in', source: 'defender' },
    { area: 'mdemachines', label: 'Defender for Endpoint machines', source: 'defender' },
    { area: 'azworkspaces', label: 'Log Analytics workspaces', source: 'arm' },
    { area: 'azsentinel', label: 'Microsoft Sentinel data connectors', source: 'arm' },
    { area: 'azconnecthealth', label: 'Entra Connect Health services', source: 'arm' },
    { area: 'kvreads', label: 'Key Vault secret reads (Log Analytics)', source: 'arm' },
    { area: 'aaddiagnostics', label: 'Entra diagnostic settings', source: 'arm' },
    { area: 'azactivity', label: 'Activity log: VM commands and extensions', source: 'arm' },
    { area: 'azalertrules', label: 'Log alert rules', source: 'arm' },
  ];

  /** Sources the Microsoft cloud collector reads. */
  const CLOUD = ['graph', 'graph-logs', 'exo', 'arm', 'spo', 'teams', 'purview', 'defender'];

  /** Sources this version can collect. */
  const BUILT = ['ldap', 'sysvol', 'dc-remote', 'dc-events', 'endpoints', 'graph', 'graph-logs', 'exo', 'arm', 'spo', 'teams', 'purview', 'defender'];
</script>

<script lang="ts">
  import { onDestroy } from 'svelte';
  import Icon from '../components/Icon.svelte';
  import Notice from '../components/Notice.svelte';
  import { cancelCollection, inDesktopApp, onCollectProgress, openSignIn, runCollection } from '../lib/backend';
  import { num } from '../lib/format';
  import { licenceNeeded } from '../lib/licence';
  import type { IconName } from '../lib/icons';
  import type { CatalogSummary, CollectOutcome } from '../lib/types';

  let {
    catalog,
    domain,
    tenant,
    selected,
    name = $bindable(),
    onBack,
    onDone,
  }: {
    catalog: CatalogSummary;
    domain: string;
    tenant: string;
    selected: Set<string>;
    name: string;
    onBack: () => void;
    onDone: (outcome: CollectOutcome, rows: AreaRow[]) => void;
  } = $props();

  const areas = $derived(catalog.groups.flatMap((g) => g.areas).filter((a) => selected.has(a.code)));
  const sources = $derived(
    catalog.sources.filter((s) => areas.some((a) => a.sources.includes(s.id))).map((s) => s.id),
  );
  /** The logs and Exchange Online are read after the tenant's configuration, so they bring graph with them. */
  const collected: string[] = $derived.by(() => {
    const built = sources.filter((s) => BUILT.includes(s));
    return built.some((s) => CLOUD.includes(s)) && !built.includes('graph') ? ['graph', ...built] : built;
  });
  const cloud = $derived(collected.includes('graph') && !!tenant.trim());
  const onprem = $derived(collected.some((s) => !CLOUD.includes(s)) && !!domain.trim());
  /** What the on-prem collector reads, in words, for the line above the tables. */
  const reads = $derived(
    [
      collected.includes('ldap') && 'over LDAP',
      collected.includes('sysvol') && 'the SYSVOL share',
      collected.includes('dc-remote') && "each domain controller's configuration over PowerShell remoting",
      collected.includes('dc-events') && 'their event logs',
      collected.includes('endpoints') &&
        'the member servers and the most recently active workstations that signed in within 30 days (up to 200 and 50) over PowerShell remoting',
    ].filter(Boolean) as string[],
  );
  const skipped = $derived(catalog.sources.filter((s) => sources.includes(s.id) && !collected.includes(s.id)));

  const fresh = (): AreaRow[] => [
    ...(cloud ? ENTRA_AREAS.filter((a) => !a.source || collected.includes(a.source)).map((a) => ({ ...a, scope: 'entra' as const })) : []),
    ...(onprem ? COLLECTOR_AREAS.filter((a) => collected.includes(a.source)).map((a) => ({ ...a, scope: 'ad' as const })) : []),
  ].map((a) => ({ key: `${a.scope}:${a.area}`, scope: a.scope, area: a.area, label: a.label, state: 'waiting', count: 0, message: '' }));

  let rows = $state<AreaRow[]>([]);
  let phase = $state<'idle' | 'collecting' | 'analyzing'>('idle');
  let error = $state<string | null>(null);
  /** The pending Microsoft sign-in, until it completes. */
  let signin = $state<{ url: string; code: string | null } | null>(null);
  let account = $state<string | null>(null);
  let copied = $state(false);

  const entraRows = $derived(rows.filter((r) => r.scope === 'entra'));
  const adRows = $derived(rows.filter((r) => r.scope === 'ad'));

  $effect(() => {
    if (phase === 'idle' && rows.length === 0) rows = fresh();
  });

  function update(key: string, change: Partial<AreaRow>) {
    rows = rows.map((r) => (r.key === key ? { ...r, ...change } : r));
  }

  const unlisten = onCollectProgress((p) => {
    if (p.type === 'analyzing') {
      phase = 'analyzing';
      return;
    }
    const e = p.event;
    if (e.type === 'signin') {
      signin = { url: e.url, code: e.code };
      return;
    }
    if (e.type === 'signedin') {
      signin = null;
      account = e.account;
      return;
    }
    if (e.type === 'finished') return;
    const key = `${p.scope}:${e.area}`;
    if (e.type === 'start') update(key, { state: 'reading' });
    else if (e.type === 'progress') update(key, { state: 'reading', count: e.read });
    else if (e.type === 'done') update(key, { state: 'read', count: e.count });
    else if (e.type === 'error') {
      const licence = licenceNeeded(e.message);
      if (licence) update(key, { state: 'unlicensed', message: `Needs ${licence}, which this tenant does not have.` });
      else update(key, { state: 'failed', message: e.message });
      if (e.area === 'signin') signin = null;
    }
  });
  onDestroy(() => unlisten.then((f) => f()));

  async function start() {
    error = null;
    signin = null;
    account = null;
    rows = fresh();
    phase = 'collecting';
    try {
      const outcome = await runCollection({
        name: name.trim() || null,
        domain: onprem ? domain.trim() : '',
        tenant: cloud ? tenant.trim() : null,
        areas: [...selected],
        sources: collected,
      });
      onDone(outcome, rows);
    } catch (e) {
      error = String((e as Error)?.message ?? e);
      phase = 'idle';
      signin = null;
    }
  }

  async function cancel() {
    try {
      await cancelCollection();
    } catch (e) {
      error = String((e as Error)?.message ?? e);
    }
  }

  async function reopen() {
    if (!signin) return;
    try {
      await openSignIn(signin.url);
    } catch (e) {
      error = String((e as Error)?.message ?? e);
    }
  }

  async function copyCode() {
    if (!signin?.code) return;
    try {
      await navigator.clipboard.writeText(signin.code);
      copied = true;
      setTimeout(() => (copied = false), 2000);
    } catch {
      copied = false;
    }
  }

  const stateView: Record<AreaRow['state'], { icon: IconName; label: string; tone: string }> = {
    waiting: { icon: 'circle', label: 'Waiting', tone: 'neutral' },
    reading: { icon: 'arrowSync', label: 'Reading', tone: 'neutral' },
    read: { icon: 'checkmarkCircle', label: 'Read', tone: 'ok' },
    failed: { icon: 'dismissCircle', label: 'Could not read', tone: 'failed' },
    unlicensed: { icon: 'subtractCircle', label: 'Not licensed', tone: 'neutral' },
  };

  const running = $derived(phase !== 'idle');
</script>

{#snippet areaTable(list: AreaRow[])}
  <table>
    <thead>
      <tr><th class="c-area">Data</th><th class="c-state">Status</th><th class="c-count right">Objects</th><th>Detail</th></tr>
    </thead>
    <tbody>
      {#each list as r (r.key)}
        {@const v = stateView[r.state]}
        <tr>
          <td class="area">{r.label}</td>
          <td><span class="state {v.tone}"><Icon name={v.icon} size={16} /> {v.label}</span></td>
          <td class="right num">{r.state === 'waiting' || r.area === 'signin' ? '' : num(r.count)}</td>
          <td class="detail">{r.area === 'signin' && r.state === 'read' && account ? `Signed in as ${account}` : r.message}</td>
        </tr>
      {/each}
    </tbody>
  </table>
{/snippet}

<div class="body">
  <div class="intro">
    <label class="name">
      <span class="label">Assessment name</span>
      <input type="text" bind:value={name} placeholder="For example: Quarterly review" disabled={running} maxlength="80" />
      <span class="muted small">Optional. Shown on the start screen and in reports.</span>
    </label>
    <p class="muted">
      {#if cloud}
        Signs in to Microsoft and reads <strong class="text">{tenant}</strong> from Microsoft Graph{collected.includes('graph-logs') ? ', with its sign-in and audit logs of the last 30 days' : ''}{collected.includes('exo') ? '. Exchange Online is read through the ExchangeOnlineManagement module, which asks you to sign in again' : ''}{collected.includes('arm') ? '. Azure resources are read from Azure Resource Manager, which may ask you to sign in once more' : ''}{collected.some((c) => ['spo', 'teams', 'purview'].includes(c)) ? '. SharePoint, Teams and Purview are read through Microsoft\'s own modules, which each ask you to sign in' : ''}.
      {/if}
      {#if onprem}
        Reads <strong class="text">{domain}</strong>
        {reads.length > 1 ? `${reads.slice(0, -1).join(', ')} and ${reads[reads.length - 1]}` : reads[0]}
        as the signed-in Windows account.
      {/if}
      Nothing is changed: the collectors only read.
    </p>
  </div>

  {#if !inDesktopApp}
    <Notice>Collection reads your directory, so it only runs in the desktop app on Windows.</Notice>
  {/if}
  {#if error}
    <Notice>{error}</Notice>
  {/if}
  {#if !cloud && !onprem}
    <Notice>The chosen areas need sources this version cannot collect yet. Choose other areas on the Scope step.</Notice>
  {/if}

  {#if signin}
    <section class="signin" aria-live="polite">
      <Icon name="personKey" size={24} />
      {#if signin.code}
        <div class="what">
          <strong>Sign in to Microsoft on any device</strong>
          <span class="muted">Open <span class="text">{signin.url}</span> and enter this code. Use an account with the Global Reader role; areas it cannot read are reported as not assessed.</span>
        </div>
        <code class="code">{signin.code}</code>
        <button class="btn" onclick={copyCode}><Icon name={copied ? 'checkmarkCircle' : 'copy'} size={18} /> {copied ? 'Copied' : 'Copy code'}</button>
        <button class="btn" onclick={reopen}><Icon name="open" size={18} /> Open page</button>
      {:else}
        <div class="what">
          <strong>Finish signing in to Microsoft in your browser</strong>
          <span class="muted">A sign-in page opened in your default browser. Use an account with the Global Reader role; areas it cannot read are reported as not assessed.</span>
        </div>
        <button class="btn" onclick={reopen}><Icon name="open" size={18} /> Open sign-in page again</button>
      {/if}
    </section>
  {/if}

  {#if entraRows.length}
    <h3>Microsoft Entra ID · <span class="target">{tenant}</span></h3>
    {@render areaTable(entraRows)}
  {/if}
  {#if adRows.length}
    <h3>On-premises · <span class="target">{domain}</span></h3>
    {@render areaTable(adRows)}
  {/if}

  {#if skipped.length}
    <div class="later">
      <h3>Not collected in this run</h3>
      <ul>
        {#each skipped as s (s.id)}
          <li><strong>{s.title}</strong> <span class="muted">· its collector is not built yet; checks that need it show as not assessed.</span></li>
        {/each}
      </ul>
    </div>
  {/if}
</div>

<footer class="bar">
  <button class="btn" onclick={onBack} disabled={running}><Icon name="arrowLeft" size={18} /> Back to access check</button>
  <div class="next">
    {#if phase === 'analyzing'}
      <span class="muted">Running checks on the collected data…</span>
    {:else if phase === 'collecting'}
      <button class="btn" onclick={cancel}><Icon name="dismissCircle" size={18} /> Cancel</button>
    {/if}
    <button class="btn primary" onclick={start} disabled={running || !inDesktopApp || (!cloud && !onprem)}>
      <Icon name={running ? 'arrowSync' : 'play'} size={18} />
      {running ? 'Collecting…' : error ? 'Try again' : 'Start collection'}
    </button>
  </div>
</footer>

<style>
  .body {
    flex: 1;
    min-height: 0;
    overflow: auto;
    padding: var(--space-5);
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }

  .intro {
    display: flex;
    align-items: flex-end;
    justify-content: space-between;
    gap: var(--space-6);
  }

  .intro p {
    max-width: 520px;
  }

  .name {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
    width: 380px;
  }

  .label {
    font-weight: 500;
  }

  .text {
    color: var(--text);
  }

  table {
    background: var(--surface);
    border-radius: var(--radius-lg);
    border-collapse: separate;
    border-spacing: 0;
    overflow: hidden;
    table-layout: fixed;
  }

  .c-area {
    width: 32%;
  }

  .c-state {
    width: 170px;
  }

  .c-count {
    width: 120px;
  }

  tbody tr:last-child td {
    border-bottom: none;
  }

  .area {
    font-weight: 500;
  }

  .right {
    text-align: right;
  }

  .num {
    font-variant-numeric: tabular-nums;
  }

  .state {
    display: inline-flex;
    align-items: center;
    gap: var(--space-1);
    white-space: nowrap;
  }

  .state.ok {
    color: var(--sev-low);
  }

  .state.failed {
    color: var(--sev-critical);
  }

  .state.neutral {
    color: var(--text-muted);
  }

  .detail {
    font-size: 13px;
    overflow-wrap: anywhere;
  }

  .target {
    text-transform: none;
    letter-spacing: 0;
    font-weight: 500;
  }

  .signin {
    display: flex;
    align-items: center;
    gap: var(--space-4);
    padding: var(--space-4);
    border: 1px solid var(--accent);
    border-radius: var(--radius);
    background: var(--surface);
    color: var(--accent-ink);
  }

  .what {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
    color: var(--text);
  }

  .code {
    font-family: var(--font-mono);
    font-size: 22px;
    letter-spacing: 0.12em;
    color: var(--text);
    padding: var(--space-2) var(--space-3);
    border-radius: var(--radius-md);
    background: var(--surface);
    user-select: all;
  }

  .later ul {
    margin: var(--space-2) 0 0;
    padding-left: var(--space-5);
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
  }

  .bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: var(--space-3) var(--space-5);
  }

  .next {
    display: flex;
    align-items: center;
    gap: var(--space-3);
  }
</style>
