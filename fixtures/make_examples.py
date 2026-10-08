"""Writes the example assessments in fixtures/example-assessments.

These are EXAMPLE runs against the reserved example domains (corp.example.com,
branch.example.com, example.onmicrosoft.com). They exist for the Rust tests
and for the browser preview of the UI (`npm run dev`), which labels them as
examples. They are never bundled into the desktop app.

Run from the repo root: python3 fixtures/make_examples.py
"""

import json
import pathlib
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / 'fixtures' / 'example-assessments'

catalog = {}
area_group = {}
for line in tomllib.loads((ROOT / 'checks/areas.toml').read_text())['area']:
    area_group[line['code']] = line['group']
for p in sorted((ROOT / 'checks').rglob('*.toml')):
    d = tomllib.loads(p.read_text())
    for c in d.get('check', []):
        catalog[c['id']] = d['area']


def aff(name, kind, location=None, reason=None, obj=None):
    a = {'name': name, 'kind': kind}
    if location:
        a['location'] = location
    if reason:
        a['reason'] = reason
    if obj:
        a['object'] = obj
    return a


DN = 'DC=corp,DC=example,DC=com'

# ---------- October review: failed checks ----------
OCT_FAILED = [
    dict(id='AD-ACL-002', affected_count=2, affected_unit='principals',
         affected=[aff('svc-backup', 'user', f'CN=svc-backup,OU=Service Accounts,{DN}', 'Has Replicating Directory Changes All on the domain root', 'u-svc-backup'),
                   aff('SYNC01$', 'computer', f'CN=SYNC01,OU=Servers,OU=Tier 0,{DN}', 'Has Replicating Directory Changes All; Entra Connect uses password hash sync', 'c-sync01')],
         expected='Only domain controllers, Domain Controllers, Enterprise Domain Controllers and Administrators hold replication rights',
         found='2 other principals hold Replicating Directory Changes and Replicating Directory Changes All',
         evidence=[{'label': 'Read from', 'value': 'nTSecurityDescriptor of the domain root via LDAP on DC01'}],
         raw='ObjectType  1131f6ad-9c07-11d1-f79f-00c04fc2dcd2  (DS-Replication-Get-Changes-All)\nCORP\\svc-backup   Allow\nCORP\\SYNC01$      Allow'),
    dict(id='AD-PKI-002', affected_count=1, affected_unit='template',
         affected=[aff('UserAuth-Legacy', 'template', f'CN=UserAuth-Legacy,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{DN}', 'Enroll: Domain Users; supplies subject; Client Authentication; no manager approval', 't-userauth'),
                   aff('CORP-ISSUING-CA', 'ca', 'PKI01.corp.example.com', 'Publishes UserAuth-Legacy', 'ca-issuing'),
                   aff('Domain Users', 'group', f'CN=Domain Users,CN=Users,{DN}', 'Every member can enroll', 'g-domain-users')],
         expected='Templates with Client Authentication do not let low-privileged principals supply the subject',
         found='1 template fails: enrollee supplies subject and Domain Users can enroll',
         evidence=[{'label': 'Read from', 'value': 'Configuration partition via LDAP on DC01, CA registry on PKI01'}],
         raw='msPKI-Certificate-Name-Flag : 0x00000001  (ENROLLEE_SUPPLIES_SUBJECT)\npKIExtendedKeyUsage        : 1.3.6.1.5.5.7.3.2  (Client Authentication)\nmsPKI-Enrollment-Flag      : 0x00000000  (no manager approval)\nmsPKI-RA-Signature         : 0\nnTSecurityDescriptor       : CORP\\Domain Users  Allow  Enroll\nPublished by               : CORP-ISSUING-CA'),
    dict(id='AD-KRB-003', affected_count=2, affected_unit='computers',
         affected=[aff('APP01', 'computer', f'CN=APP01,OU=Servers,{DN}', 'TrustedForDelegation', 'c-app01'),
                   aff('FS01', 'computer', f'CN=FS01,OU=Servers,{DN}', 'TrustedForDelegation', 'c-fs01')],
         expected='Only domain controllers are trusted for unconstrained delegation',
         found='2 member servers are trusted for unconstrained delegation',
         raw='userAccountControl : 0x81000  (WORKSTATION_TRUST_ACCOUNT, TRUSTED_FOR_DELEGATION)'),
    dict(id='EN-CA-004', affected_count=None, affected_unit=None,
         affected=[aff('example.onmicrosoft.com', 'tenant', reason='No enabled policy blocks Exchange ActiveSync and other legacy clients')],
         expected='An enabled policy blocks legacy authentication for all users',
         found='Policy "CA010 Block legacy auth" exists but is in report-only mode',
         evidence=[{'label': 'Read from', 'value': 'Microsoft Graph /identity/conditionalAccess/policies'}]),
    dict(id='AD-PRIV-021', affected_count=1, affected_unit='account',
         affected=[aff('krbtgt', 'user', f'CN=krbtgt,CN=Users,{DN}', 'Password last set 7 Jul 2023, 1,186 days ago', 'u-krbtgt')],
         expected='krbtgt password changed in the last 180 days', found='Last changed 1,186 days ago',
         evidence=[{'label': 'pwdLastSet', 'value': '2023-07-07 09:14:22 UTC'}, {'label': 'Threshold', 'value': '180 days'}]),
    dict(id='AD-PRIV-017', affected_count=1, affected_unit='account',
         affected=[aff('adm-jsmith', 'user', f'CN=adm-jsmith,OU=Admins,OU=Tier 0,{DN}', 'MSSQLSvc/sql-old.corp.example.com:1433', 'u-adm-jsmith')]),
    dict(id='AD-PRIV-015', affected_count=3, affected_unit='accounts',
         affected=[aff('adm-jsmith', 'user', obj='u-adm-jsmith'), aff('adm-mlopez', 'user', obj='u-adm-mlopez'), aff('svc-backup', 'user', obj='u-svc-backup')]),
    dict(id='EN-PRIV-002', affected_count=4, affected_unit='assignments',
         affected=[aff('admin.r.lee@example.onmicrosoft.com', 'user', reason='Global Administrator, permanent', obj='e-admin-rlee'),
                   aff('it-ops@example.onmicrosoft.com', 'user', reason='Global Administrator, permanent', obj='e-itops'),
                   aff('a.khan@example.com', 'user', reason='Exchange Administrator, permanent', obj='e-akhan'),
                   aff('HelpdeskApp', 'app', reason='Privileged Authentication Administrator, permanent', obj='e-app-helpdesk')]),
    dict(id='AD-DC-011', affected_count=3, affected_unit='domain controllers',
         affected=[aff('DC01', 'computer', obj='c-dc01'), aff('DC02', 'computer', obj='c-dc02'), aff('DC03', 'computer', obj='c-dc03')],
         expected='LDAPServerIntegrity = 2 (require signing)', found='LDAPServerIntegrity = 1 on all domain controllers'),
    dict(id='AD-PRIV-003', affected_count=7, affected_unit='members', severity='medium',
         affected=[aff('adm-jsmith', 'user', obj='u-adm-jsmith'), aff('adm-mlopez', 'user', obj='u-adm-mlopez'), aff('Administrator', 'user', obj='u-administrator')],
         expected='5 members or fewer', found='7 members, 2 of them nested through IT-Admins'),
    dict(id='AD-CMP-007', affected_count=6, affected_unit='computers',
         affected=[aff('WS-LON-014', 'computer', obj='c-ws-lon-014'), aff('WS-LON-022', 'computer', obj='c-ws-lon-022'), aff('WS-MAD-003', 'computer', obj='c-ws-mad-003')]),
    dict(id='AD-GPO-004', affected_count=1, affected_unit='GPO',
         affected=[aff('Legacy Local Admin', 'gpo', r'\\corp.example.com\SYSVOL\corp.example.com\Policies\{6AC1786C-016F-11D2-945F-00C04FB984F9}\Machine\Preferences\Groups\Groups.xml', 'cpassword for the local Administrator', 'gpo-legacy')]),
    dict(id='AD-ACC-001', affected_count=2, affected_unit='users',
         affected=[aff('m.garcia', 'user', obj='u-mgarcia'), aff('helpdesk01', 'user', obj='u-helpdesk01')]),
    dict(id='AD-PWD-012', affected_count=3, affected_unit='users',
         affected=[aff('svc-backup', 'user', obj='u-svc-backup'), aff('helpdesk01', 'user', obj='u-helpdesk01'), aff('svc-sql01', 'user', obj='u-svc-sql01')]),
    dict(id='AD-PRIV-011', affected_count=1, affected_unit='account',
         affected=[aff('t.nguyen', 'user', reason='Disabled, still in IT-Admins', obj='u-tnguyen')]),
    dict(id='EN-AUTH-001', affected_count=2, affected_unit='users',
         affected=[aff('r.lee@example.com', 'user', obj='e-rlee'), aff('m.garcia@example.com', 'user', obj='e-mgarcia')]),
]

OCT_NOT_ASSESSED = {
    'AD-DC-001': 'DC03 configuration was not readable: Access is denied',
    'AD-DC-002': 'DC03 configuration was not readable: Access is denied',
    'AD-LEG-001': 'Security log of DC03 was not readable',
}
OCT_ACCEPTED = {'AD-PRIV-002': 'Accepted until 31 Dec 2026: Schema Admins used for the Exchange upgrade project'}

SCOPE_GROUPS = {'onprem', 'entra', 'hybrid'}


def passed_ids(skip, stride, groups):
    ids = [i for i, area in catalog.items() if area_group[area] in groups and i not in skip]
    return ids[::stride]


def run(name, started, finished, failed, not_assessed, accepted, paths, domains, tenant, stride=2):
    groups = SCOPE_GROUPS if tenant else {'onprem'}
    checks = []
    for f in failed:
        r = {'id': f['id'], 'status': 'failed'}
        r.update({k: v for k, v in f.items() if k != 'id' and v is not None})
        checks.append(r)
    for cid, note in not_assessed.items():
        checks.append({'id': cid, 'status': 'not_assessed', 'note': note})
    for cid, note in accepted.items():
        checks.append({'id': cid, 'status': 'accepted', 'note': note})
    skip = {c['id'] for c in checks}
    checks += [{'id': cid, 'status': 'passed'} for cid in passed_ids(skip, stride, groups)]
    for c in checks:
        assert c['id'] in catalog, c['id']
    manifest = {
        'name': name, 'tool_version': '0.1.0', 'catalog_version': '2026.10',
        'scope': {'domains': domains, 'tenant': tenant},
        'started_at': started, 'finished_at': finished,
    }
    return manifest, {'checks': checks, 'paths': paths}


PATHS = [
    {'title': 'Any domain user can become Domain Admin in 2 steps', 'severity': 'critical', 'checks': ['AD-PKI-002'],
     'steps': [{'name': 'Domain Users', 'kind': 'group', 'object': 'g-domain-users', 'via': 'Enroll'},
               {'name': 'UserAuth-Legacy', 'kind': 'template', 'object': 't-userauth', 'via': 'ESC1: any subject'},
               {'name': 'Domain Admins', 'kind': 'group', 'object': 'g-domain-admins'}]},
    {'title': 'Helpdesk can reach Domain Admins in 3 steps', 'severity': 'critical', 'checks': ['AD-KRB-003', 'AD-PRIV-016'],
     'steps': [{'name': 'Helpdesk', 'kind': 'group', 'object': 'g-helpdesk', 'via': 'GenericWrite'},
               {'name': 'APP01', 'kind': 'computer', 'object': 'c-app01', 'via': 'HasSession'},
               {'name': 'adm-jsmith', 'kind': 'user', 'object': 'u-adm-jsmith', 'via': 'MemberOf'},
               {'name': 'Domain Admins', 'kind': 'group', 'object': 'g-domain-admins'}]},
    {'title': 'svc-backup can read every password hash', 'severity': 'critical', 'checks': ['AD-ACL-002'],
     'steps': [{'name': 'svc-backup', 'kind': 'user', 'object': 'u-svc-backup', 'via': 'DCSync'},
               {'name': 'corp.example.com', 'kind': 'domain', 'object': 'd-corp'}]},
    {'title': 'On-premises account reaches Global Administrator', 'severity': 'high', 'checks': ['EN-PRIV-002'],
     'steps': [{'name': 'Server Operators', 'kind': 'group', 'object': 'g-server-operators', 'via': 'AdminTo'},
               {'name': 'SYNC01', 'kind': 'computer', 'object': 'c-sync01', 'via': 'Password writeback'},
               {'name': 'admin.r.lee', 'kind': 'user', 'object': 'e-admin-rlee', 'via': 'HasRole'},
               {'name': 'Global Administrator', 'kind': 'role', 'object': 'r-global-admin'}]},
]


# ---------- Directory telemetry for October review ----------
objs, edges = [], []


def ou(id, name, parent):
    objs.append({'id': id, 'kind': 'ou', 'name': name, 'source': 'corp.example.com', 'parent': parent,
                 'attributes': {'distinguishedName': name}})


def obj(id, kind, name, parent, source='corp.example.com', **kw):
    o = {'id': id, 'kind': kind, 'name': name, 'source': source, 'parent': parent}
    o.update(kw)
    objs.append(o)


def edge(a, b, kind, note=None):
    e = {'from': a, 'to': b, 'kind': kind}
    if note:
        e['note'] = note
    edges.append(e)


objs.append({'id': 'd-corp', 'kind': 'domain', 'name': 'corp.example.com', 'source': 'corp.example.com', 'tier0': True,
             'attributes': {'distinguishedName': DN, 'domainFunctionality': 'Windows2016Domain', 'forest': 'corp.example.com'}})
for oid, name, parent in [
    ('ou-users-cn', 'Users', 'd-corp'), ('ou-computers-cn', 'Computers', 'd-corp'), ('ou-dcs', 'Domain Controllers', 'd-corp'),
    ('ou-t0', 'Tier 0', 'd-corp'), ('ou-t0-admins', 'Admins', 'ou-t0'), ('ou-t0-servers', 'Servers', 'ou-t0'),
    ('ou-svc', 'Service Accounts', 'd-corp'), ('ou-servers', 'Servers', 'd-corp'), ('ou-people', 'People', 'd-corp'),
    ('ou-london', 'London', 'ou-people'), ('ou-madrid', 'Madrid', 'ou-people'), ('ou-it', 'IT', 'ou-people'),
    ('ou-leavers', 'Leavers', 'ou-people'), ('ou-ws', 'Workstations', 'd-corp'), ('ou-groups', 'Groups', 'd-corp'),
]:
    ou(oid, name, parent)


def user(id, sam, display, parent, enabled=True, tier0=False, logon='2026-10-04T08:51:00Z', pwd='2026-03-06T10:00:00Z', flags=(), **attrs):
    a = {'sAMAccountName': sam, 'userPrincipalName': f'{sam}@corp.example.com', 'whenCreated': attrs.pop('created', '2019-02-14')}
    a.update(attrs)
    obj(id, 'user', sam, parent, display_name=display, enabled=enabled, tier0=tier0, last_logon=logon,
        password_last_set=pwd, flags=[{'text': t, 'level': l} for t, l in flags], attributes=a)


user('u-administrator', 'Administrator', 'Built-in administrator', 'ou-users-cn', tier0=True, logon='2026-06-02T11:00:00Z', pwd='2025-11-20T09:00:00Z', flags=[('Domain Admins', 'crit')], adminCount=1)
user('u-krbtgt', 'krbtgt', 'Key Distribution Center service', 'ou-users-cn', enabled=False, tier0=True, logon=None, pwd='2023-07-07T09:14:22Z', flags=[('Password 1,186 days old', 'warn')])
user('u-adm-jsmith', 'adm-jsmith', 'John Smith (admin)', 'ou-t0-admins', tier0=True, flags=[('Domain Admins', 'crit'), ('Kerberoastable', 'warn')],
     adminCount=1, servicePrincipalName='MSSQLSvc/sql-old.corp.example.com:1433', objectSid='S-1-5-21-3623811015-3361044348-30300820-1167')
user('u-adm-mlopez', 'adm-mlopez', 'Maria Lopez (admin)', 'ou-t0-admins', tier0=True, logon='2026-10-02T16:10:00Z', pwd='2026-08-01T10:00:00Z', flags=[('Domain Admins', 'crit')], adminCount=1)
user('u-svc-backup', 'svc-backup', 'Backup service', 'ou-svc', logon='2026-10-05T02:00:00Z', pwd='2022-12-03T10:00:00Z', flags=[('DCSync', 'crit'), ('Password never expires', 'warn')], created='2018-05-02')
user('u-svc-sql01', 'svc-sql01', 'SQL service on APP01', 'ou-svc', logon='2026-10-05T03:00:00Z', pwd='2024-01-21T10:00:00Z', flags=[('Kerberoastable', 'warn'), ('Password never expires', 'warn')], servicePrincipalName='MSSQLSvc/app01.corp.example.com:1433')
user('u-akhan', 'a.khan', 'Aisha Khan', 'ou-london', logon='2026-10-05T07:58:00Z', pwd='2026-08-25T10:00:00Z', flags=[('Synced', '')], mail='a.khan@example.com')
user('u-rlee', 'r.lee', 'Robin Lee', 'ou-london', logon='2026-10-03T09:12:00Z', pwd='2026-07-20T10:00:00Z', flags=[('Synced', '')], mail='r.lee@example.com')
user('u-mgarcia', 'm.garcia', 'Maria Garcia', 'ou-madrid', logon='2026-06-12T08:00:00Z', pwd='2025-12-08T10:00:00Z', flags=[('Stale 115 days', 'warn'), ('Synced', '')])
user('u-helpdesk01', 'helpdesk01', 'Helpdesk shared account', 'ou-it', logon='2026-05-30T08:00:00Z', pwd='2024-12-25T10:00:00Z', flags=[('Shared account', 'warn'), ('Password never expires', 'warn')])
user('u-kosei', 'k.osei', 'Kwame Osei', 'ou-it', logon='2026-10-04T12:30:00Z', pwd='2026-09-23T10:00:00Z', flags=[('Synced', '')])
user('u-tnguyen', 't.nguyen', 'Tran Nguyen', 'ou-leavers', enabled=False, logon='2026-03-02T17:40:00Z', pwd='2025-08-21T10:00:00Z', flags=[('Disabled', ''), ('Still in IT-Admins', 'warn')])


def computer(id, name, parent, os, tier0=False, flags=(), logon='2026-10-05T06:00:00Z'):
    obj(id, 'computer', name, parent, enabled=True, tier0=tier0, last_logon=logon,
        flags=[{'text': t, 'level': l} for t, l in flags],
        attributes={'dNSHostName': f'{name.lower()}.corp.example.com', 'operatingSystem': os})


computer('c-dc01', 'DC01', 'ou-dcs', 'Windows Server 2022 Datacenter', tier0=True, flags=[('Domain controller', '')])
computer('c-dc02', 'DC02', 'ou-dcs', 'Windows Server 2022 Datacenter', tier0=True, flags=[('Domain controller', '')])
computer('c-dc03', 'DC03', 'ou-dcs', 'Windows Server 2019 Datacenter', tier0=True, flags=[('Domain controller', ''), ('Not readable', 'warn')])
computer('c-sync01', 'SYNC01', 'ou-t0-servers', 'Windows Server 2022 Standard', tier0=True, flags=[('Entra Connect', ''), ('DCSync', 'crit')])
computer('c-pki01', 'PKI01', 'ou-t0-servers', 'Windows Server 2022 Standard', tier0=True, flags=[('Enterprise CA', '')])
computer('c-adm-ws01', 'ADM-WS01', 'ou-t0-servers', 'Windows 11 Enterprise', tier0=True, flags=[('Tier 0 PAW', 'ok')])
computer('c-app01', 'APP01', 'ou-servers', 'Windows Server 2019 Standard', flags=[('Unconstrained delegation', 'crit')])
computer('c-fs01', 'FS01', 'ou-servers', 'Windows Server 2016 Standard', flags=[('Unconstrained delegation', 'crit')])
computer('c-sql01', 'SQL01', 'ou-servers', 'Windows Server 2022 Standard')
computer('c-ws-lon-014', 'WS-LON-014', 'ou-ws', 'Windows 11 Enterprise', flags=[('No LAPS', 'warn')])
computer('c-ws-lon-022', 'WS-LON-022', 'ou-ws', 'Windows 11 Enterprise', flags=[('No LAPS', 'warn')])
computer('c-ws-mad-003', 'WS-MAD-003', 'ou-ws', 'Windows 10 Enterprise', flags=[('No LAPS', 'warn'), ('Windows 10', 'warn')])


def group(id, name, parent, tier0=False, desc=None):
    a = {'groupScope': 'Global' if parent == 'ou-groups' else 'DomainLocal'}
    if desc:
        a['description'] = desc
    obj(id, 'group', name, parent, tier0=tier0, attributes=a)


group('g-domain-admins', 'Domain Admins', 'ou-users-cn', True)
group('g-enterprise-admins', 'Enterprise Admins', 'ou-users-cn', True)
group('g-administrators', 'Administrators', 'ou-users-cn', True)
group('g-schema-admins', 'Schema Admins', 'ou-users-cn', True)
group('g-server-operators', 'Server Operators', 'ou-users-cn', True)
group('g-protected-users', 'Protected Users', 'ou-users-cn')
group('g-domain-users', 'Domain Users', 'ou-users-cn')
group('g-it-admins', 'IT-Admins', 'ou-groups', desc='Server administrators')
group('g-helpdesk', 'Helpdesk', 'ou-groups', desc='First-line support')
group('g-vpn', 'VPN-Users', 'ou-groups')
group('g-rdp', 'Remote Desktop Users', 'ou-users-cn')

for gid, name, linked in [('gpo-ddp', 'Default Domain Policy', 'd-corp'), ('gpo-dc', 'Default Domain Controllers Policy', 'ou-dcs'),
                          ('gpo-server', 'Server Baseline', 'ou-servers'), ('gpo-ws', 'Workstation Baseline', 'ou-ws'),
                          ('gpo-legacy', 'Legacy Local Admin', 'ou-ws')]:
    obj(gid, 'gpo', name, linked, flags=[{'text': 'Stores a password', 'level': 'crit'}] if gid == 'gpo-legacy' else [],
        attributes={'linkedTo': linked})
obj('t-userauth', 'template', 'UserAuth-Legacy', 'd-corp', flags=[{'text': 'ESC1', 'level': 'crit'}],
    attributes={'msPKI-Certificate-Name-Flag': '0x1', 'pKIExtendedKeyUsage': 'Client Authentication'})
obj('t-webserver', 'template', 'WebServer', 'd-corp', attributes={'pKIExtendedKeyUsage': 'Server Authentication'})
obj('ca-issuing', 'ca', 'CORP-ISSUING-CA', 'd-corp', tier0=True, attributes={'dNSHostName': 'pki01.corp.example.com'})
obj('tr-branch', 'trust', 'branch.example.com', 'd-corp', attributes={'trustDirection': 'Bidirectional', 'trustType': 'Forest', 'sidFiltering': True})

# Entra ID objects
for eid, name, display, flags in [
    ('e-admin-rlee', 'admin.r.lee@example.onmicrosoft.com', 'Robin Lee (cloud admin)', [('Global Administrator', 'crit'), ('Synced', '')]),
    ('e-itops', 'it-ops@example.onmicrosoft.com', 'IT operations', [('Global Administrator', 'crit')]),
    ('e-akhan', 'a.khan@example.com', 'Aisha Khan', [('Exchange Administrator', 'warn'), ('MFA', 'ok')]),
    ('e-rlee', 'r.lee@example.com', 'Robin Lee', [('No MFA', 'warn')]),
    ('e-mgarcia', 'm.garcia@example.com', 'Maria Garcia', [('No MFA', 'warn')]),
]:
    obj(eid, 'user', name, None, source='example.onmicrosoft.com', display_name=display, enabled=True,
        tier0='Global' in flags[0][0], flags=[{'text': t, 'level': l} for t, l in flags], attributes={'userPrincipalName': name})
obj('r-global-admin', 'role', 'Global Administrator', None, source='example.onmicrosoft.com', tier0=True, attributes={'roleTemplateId': '62e90394-69f5-4237-9190-012177145e10'})
obj('r-exchange-admin', 'role', 'Exchange Administrator', None, source='example.onmicrosoft.com', attributes={'roleTemplateId': '29232cdf-9323-42fd-ade2-1d097af3e4de'})
obj('e-app-helpdesk', 'app', 'HelpdeskApp', None, source='example.onmicrosoft.com', flags=[{'text': 'Privileged role', 'level': 'warn'}], attributes={'appId': '00000000-0000-0000-0000-000000000000'})

for m, g in [('u-adm-jsmith', 'g-domain-admins'), ('u-adm-mlopez', 'g-domain-admins'), ('u-administrator', 'g-domain-admins'),
             ('g-it-admins', 'g-domain-admins'), ('g-domain-admins', 'g-administrators'), ('g-enterprise-admins', 'g-administrators'),
             ('u-adm-jsmith', 'g-it-admins'), ('u-tnguyen', 'g-it-admins'), ('u-adm-jsmith', 'g-vpn'), ('u-kosei', 'g-helpdesk'),
             ('u-helpdesk01', 'g-helpdesk'), ('g-it-admins', 'g-rdp'), ('u-akhan', 'g-domain-users'), ('u-rlee', 'g-domain-users'),
             ('u-mgarcia', 'g-domain-users'), ('u-kosei', 'g-domain-users'), ('u-adm-mlopez', 'g-protected-users')]:
    edge(m, g, 'MemberOf')
edge('g-domain-users', 't-userauth', 'Enroll')
edge('t-userauth', 'g-domain-admins', 'ESC1', 'Any subject, so any account including Domain Admins')
edge('ca-issuing', 't-userauth', 'Publishes')
edge('g-helpdesk', 'c-app01', 'GenericWrite')
edge('c-app01', 'u-adm-jsmith', 'HasSession', 'Signed in 21 Sep 2026')
edge('u-svc-backup', 'd-corp', 'DCSync')
edge('c-sync01', 'd-corp', 'DCSync')
edge('g-domain-admins', 'd-corp', 'GenericAll')
edge('g-domain-admins', 'c-dc01', 'AdminTo')
edge('g-it-admins', 'ou-servers', 'GenericAll')
edge('u-adm-jsmith', 'ou-people', 'ResetPassword')
edge('u-adm-jsmith', 'gpo-server', 'Owns')
edge('g-server-operators', 'c-sync01', 'AdminTo')
edge('c-sync01', 'e-admin-rlee', 'PasswordWriteback')
edge('u-rlee', 'e-admin-rlee', 'SyncedTo')
edge('e-admin-rlee', 'r-global-admin', 'HasRole')
edge('e-itops', 'r-global-admin', 'HasRole')
edge('e-akhan', 'r-exchange-admin', 'HasRole')
edge('u-akhan', 'e-akhan', 'SyncedTo')
edge('u-mgarcia', 'e-mgarcia', 'SyncedTo')
edge('c-adm-ws01', 'u-adm-jsmith', 'HasSession', 'Signed in 4 Oct 2026')
edge('c-dc01', 'u-adm-jsmith', 'HasSession', 'Signed in 29 Sep 2026')
edge('gpo-server', 'ou-servers', 'GPLink')
edge('gpo-ws', 'ou-ws', 'GPLink')
edge('gpo-legacy', 'ou-ws', 'GPLink')
edge('gpo-ddp', 'd-corp', 'GPLink')
edge('gpo-dc', 'ou-dcs', 'GPLink')

DIRECTORY = {
    'sources': [{'name': 'corp.example.com', 'kind': 'onprem', 'read_at': '2026-10-05T14:22:15Z'},
                {'name': 'example.onmicrosoft.com', 'kind': 'cloud', 'read_at': '2026-10-05T14:28:12Z'}],
    'objects': objs, 'edges': edges,
}


def write(folder, manifest, results, directory=None):
    d = OUT / folder
    d.mkdir(parents=True, exist_ok=True)
    (d / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    (d / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
    if directory:
        (d / 'directory.json').write_text(json.dumps(directory, indent=2) + '\n')


DOMAINS, TENANT = ['corp.example.com'], 'example.onmicrosoft.com'
write('october-review', *run('October review', '2026-10-05T14:20:05Z', '2026-10-05T14:32:40Z', OCT_FAILED,
                             OCT_NOT_ASSESSED, OCT_ACCEPTED, PATHS, DOMAINS, TENANT), DIRECTORY)

# Q3 baseline: DCSync and PIM findings were not there yet; Print Spooler, NTLMv1
# and the missing MFA baseline were failing and have since been fixed.
q3 = [f for f in OCT_FAILED if f['id'] not in ('AD-ACL-002', 'EN-PRIV-002')]
q3 = [dict(f, affected_count=2) if f['id'] == 'AD-PKI-002' else f for f in q3]
q3 = [dict(f, affected_count=4) if f['id'] == 'AD-CMP-007' else f for f in q3]
q3 += [
    dict(id='AD-DC-006', affected_count=3, affected_unit='domain controllers',
         affected=[aff('DC01', 'computer'), aff('DC02', 'computer'), aff('DC03', 'computer')]),
    dict(id='AD-LEG-001', affected_count=3, affected_unit='domain controllers', affected=[aff('DC01', 'computer')]),
    dict(id='EN-TEN-002', affected=[aff('example.onmicrosoft.com', 'tenant')]),
    dict(id='AD-ACL-001', affected_count=1, affected_unit='principal', affected=[aff('Exchange Windows Permissions', 'group')]),
]
write('q3-baseline', *run('Q3 baseline', '2026-07-02T09:10:00Z', '2026-07-02T09:24:51Z', q3, {}, {},
                          [p for p in PATHS if p['checks'] != ['AD-ACL-002']] + [
                              {'title': 'Exchange Windows Permissions can grant itself DCSync', 'severity': 'critical', 'checks': ['AD-ACL-001'],
                               'steps': [{'name': 'Exchange Windows Permissions', 'kind': 'group', 'via': 'WriteDACL'},
                                         {'name': 'corp.example.com', 'kind': 'domain'}]}],
                          DOMAINS, TENANT, stride=3))

branch_failed = [
    dict(id='AD-PRIV-021', affected_count=1, affected_unit='account', affected=[aff('krbtgt', 'user', 'CN=krbtgt,CN=Users,DC=branch,DC=example,DC=com')]),
    dict(id='AD-DC-011', affected_count=1, affected_unit='domain controller', affected=[aff('BR-DC01', 'computer')]),
    dict(id='AD-ACC-001', affected_count=1, affected_unit='user', affected=[aff('kiosk01', 'user')]),
]
write('branch-forest', *run('Branch forest', '2026-06-18T16:45:00Z', '2026-06-18T16:52:10Z', branch_failed, {}, {}, [],
                            ['branch.example.com'], None, stride=4))
print('wrote', OUT)
