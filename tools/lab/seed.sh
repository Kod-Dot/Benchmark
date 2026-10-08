#!/usr/bin/env bash
# Seeds the lab domain (tools/lab/start-domain.sh) with objects that should
# trigger checks, so CI can confirm each check finds them in a real directory.
# Each block names the check it feeds; tools/lab/expected.json lists what
# the analysis must report.
set -euo pipefail

BASE="DC=corp,DC=example,DC=com"
USERS="CN=Users,$BASE"
PASS='Passw0rd!Lab'
SAM=/var/lib/samba/private/sam.ldb
PY="${SAMBA_PYTHON:-python3}"
tool() { "$PY" /usr/bin/samba-tool "$@" >/dev/null; }
ldif() { ldbmodify -H "$SAM" --controls=relax:0 >/dev/null; }
add() { ldbadd -H "$SAM" --controls=relax:0 >/dev/null; }

# Windows FILETIME for N days ago.
filetime() { echo $(( ( $(date +%s) - $1 * 86400 + 11644473600 ) * 10000000 )); }

user() { tool user create "$1" "$PASS" "${@:2}"; }

# AD-ACC-009: password never expires.
user lab-noexpire
tool user setexpiry lab-noexpire --noexpiry

# AD-ACC-014: a workstation restriction.
user lab-restricted
ldif <<L
dn: CN=lab-restricted,$USERS
changetype: modify
replace: userWorkstations
userWorkstations: LABWS01
L

# AD-PRIV-012: a service account (SPN) in Domain Admins.
user lab-svc-da
tool spn add MSSQLSvc/sql01.corp.example.com:1433 lab-svc-da
tool group addmembers 'Domain Admins' lab-svc-da

# AD-PRIV-004 / 007 / 008: extra members of built-in privileged groups.
user lab-helpdesk
tool group addmembers 'Administrators' lab-helpdesk
tool group addmembers 'Group Policy Creator Owners' lab-helpdesk
tool group addmembers 'Cert Publishers' lab-helpdesk

# AD-IOC-009: Domain Admins as the primary group.
user lab-hidden
tool group addmembers 'Domain Admins' lab-hidden
DA_RID=512
ldif <<L
dn: CN=lab-hidden,$USERS
changetype: modify
replace: primaryGroupID
primaryGroupID: $DA_RID
L

# AD-ACC-015 / AD-PRIV-026: a foreign security principal from a domain that
# is not trusted, in Domain Admins.
# Samba creates the foreign principal itself when the member is given by SID
# (without the relax control).
ldbmodify -H "$SAM" >/dev/null <<L
dn: CN=Domain Admins,$USERS
changetype: modify
add: member
member: <SID=S-1-5-21-9-9-9-1234>
L

# AD-CMP-003 / AD-LAPS-002: an active server with unconstrained delegation
# and no LAPS password.
tool computer create LABAPP01
ldif <<L
dn: CN=LABAPP01,CN=Computers,$BASE
changetype: modify
replace: userAccountControl
userAccountControl: 528384
-
replace: lastLogonTimestamp
lastLogonTimestamp: $(filetime 3)
L

# AD-ACC-018: a group with more than 500 members.
{
  for i in $(seq 1 501); do
    printf 'dn: CN=lab-bulk%03d,%s\nobjectClass: user\nsAMAccountName: lab-bulk%03d\nuserAccountControl: 514\n\n' "$i" "$USERS" "$i"
  done
} | add
{
  printf 'dn: CN=lab-everyone,%s\nobjectClass: group\nsAMAccountName: lab-everyone\n' "$USERS"
  for i in $(seq 1 501); do printf 'member: CN=lab-bulk%03d,%s\n' "$i" "$USERS"; done
} | add

# AD-OU-001: OUs nested eleven levels deep.
DN="$BASE"
for i in $(seq 1 11); do
  DN="OU=lab-depth$i,$DN"
  printf 'dn: %s\nobjectClass: organizationalUnit\n' "$DN" | add
done

CONFIG="CN=Configuration,$BASE"
sid_of() { ldbsearch -H "$SAM" "(sAMAccountName=$1)" objectSid | awk '/^objectSid/{print $2}'; }
grant() { tool dsacl set -H "$SAM" --objectdn="$1" --sddl="$2"; }
HELPDESK=$(sid_of lab-helpdesk)
DC_DN=$(ldbsearch -H "$SAM" -b "OU=Domain Controllers,$BASE" '(objectClass=computer)' dn | awk '/^dn: /{sub(/^dn: /,""); print; exit}')

# AD-FND-014: a user whose UPN suffix the forest does not know.
user lab-upn
ldif <<L
dn: CN=lab-upn,$USERS
changetype: modify
replace: userPrincipalName
userPrincipalName: lab-upn@fabrikam.test
L

# AD-FND-016: a disabled cross-reference left in CN=Partitions.
add <<L
dn: CN=OLD,CN=Partitions,$CONFIG
objectClass: crossRef
nCName: DC=old,DC=example,DC=com
dnsRoot: old.example.com
enabled: FALSE
systemFlags: 3
L

# AD-SCH-004: a context menu entry that runs a program.
ldif <<L
dn: CN=user-Display,CN=409,CN=DisplaySpecifiers,$CONFIG
changetype: modify
add: adminContextMenu
adminContextMenu: 9,&Reset tool,\\\\fileserver\\tools\\reset.exe
L

# AD-ACL-007: full control on the configuration partition.
grant "$CONFIG" "(A;;GA;;;$HELPDESK)"

# AD-ACL-019: an Exchange group with WriteDACL on the domain head.
tool group add 'Exchange Windows Permissions'
grant "$BASE" "(A;;WD;;;$(sid_of 'Exchange Windows Permissions'))"

# AD-ACL-024 / AD-ACL-022: an ordinary account with control of a domain
# controller's computer object and of an OU.
user lab-operator
OPERATOR=$(sid_of lab-operator)
grant "$DC_DN" "(A;;GA;;;$OPERATOR)"
grant "OU=lab-depth2,OU=lab-depth1,$BASE" "(A;;GA;;;$OPERATOR)"

# AD-ACL-026: rights to create password policies.
grant "CN=Password Settings Container,CN=System,$BASE" "(A;;CC;;;$HELPDESK)"

# AD-ACL-018: a deny entry hiding an OU from a group. (A deny that covers
# the collecting account hides the object from the collector too.)
grant "OU=lab-depth1,$BASE" "(D;;LCRP;;;$(sid_of lab-everyone))"

# AD-ACL-017: inheritance disabled on the Domain Controllers OU (Tier 0).
SDDL=$("$PY" /usr/bin/samba-tool dsacl get -H "$SAM" --objectdn="OU=Domain Controllers,$BASE" | tail -1 | sed 's/D:AI(/D:PAI(/')
ldbmodify -H "$SAM" >/dev/null <<L
dn: OU=Domain Controllers,$BASE
changetype: modify
replace: nTSecurityDescriptor
nTSecurityDescriptor: $SDDL
L

# AD-ACL-012: write altSecurityIdentities on the built-in Administrator.
grant "CN=Administrator,$USERS" "(OA;;WP;00fbf30c-91fe-11d1-aebc-0000f80367c1;;$OPERATOR)"

# AD-ACL-013: all extended rights (which read LAPS passwords) for Domain Users.
grant "OU=lab-depth3,OU=lab-depth2,OU=lab-depth1,$BASE" "(A;;CR;;;DU)"

# AD-ACL-020: control of a DNS zone.
grant "DC=corp.example.com,CN=MicrosoftDNS,DC=DomainDnsZones,$BASE" "(A;;GA;;;$OPERATOR)"

# AD-ACL-021: change permissions on the Certificate Templates container (ESC5).
grant "CN=Certificate Templates,CN=Public Key Services,CN=Services,$CONFIG" "(A;;WD;;;$OPERATOR)"

# AD-ACL-023 / AD-OU-005: an admin OU holding a Domain Admin, where an
# ordinary account can create objects.
printf 'dn: OU=lab-admins,%s\nobjectClass: organizationalUnit\n' "$BASE" | add
tool user create lab-admin2 "$PASS" --userou=OU=lab-admins
tool group addmembers 'Domain Admins' lab-admin2
grant "OU=lab-admins,$BASE" "(A;;CC;;;$OPERATOR)"

# AD-PRIV-023: an extra (read) entry on AdminSDHolder.
grant "CN=AdminSDHolder,CN=System,$BASE" "(A;;RP;;;$OPERATOR)"

# AD-APP-007: an identity tool account with DCSync rights.
user lab-varonis-svc --description='Varonis collector'
VARONIS=$(sid_of lab-varonis-svc)
grant "$BASE" "(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;$VARONIS)(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;$VARONIS)"

# AD-AUD-007 / AD-PRIV-030: a decoy account and a break-glass account.
user lab-honey --description='Decoy account, alert on use'
user lab-breakglass --description='Emergency access account'
tool group addmembers 'Domain Admins' lab-breakglass

# AD-BKP-003: a member of Backup Operators.
user lab-backup
tool group addmembers 'Backup Operators' lab-backup

# AD-KRB-018: a computer with protocol transition.
tool computer create LABAPP02
ldif <<L
dn: CN=LABAPP02,CN=Computers,$BASE
changetype: modify
replace: userAccountControl
userAccountControl: 16781312
L

# AD-PRIV-010: groups nested three levels into Domain Admins.
tool group add lab-nest1
tool group add lab-nest2
tool group add lab-nest3
tool group addmembers 'Domain Admins' lab-nest1
tool group addmembers lab-nest1 lab-nest2
tool group addmembers lab-nest2 lab-nest3

# AD-PRIV-018: a privileged account with an email address.
ldif <<L
dn: CN=lab-svc-da,$USERS
changetype: modify
replace: mail
mail: lab-svc-da@corp.example.com
L

# Group Policy content in SYSVOL (AD-GPO-010/012/013/016/017/020/025/030,
# AD-SVC-005): the Default Domain Controllers Policy gets weak settings,
# and the Default Domain Policy denies local sign-in to one service account.
POLICIES=/var/lib/samba/sysvol/corp.example.com/Policies
DDP='{31B2F340-016D-11D2-945F-00C04FB984F9}'
DDCP='{6AC1786C-016F-11D2-945F-00C04FB984F9}'
user lab-svc-denied
tool spn add HTTP/web01.corp.example.com lab-svc-denied
python3 "$(dirname "$0")/write-policy.py" "$POLICIES/$DDCP" -
python3 "$(dirname "$0")/write-policy.py" "$POLICIES/$DDP" "$(sid_of lab-svc-denied)"

# AD-GPO-024: a WMI filter, and a GPO that uses one that does not exist.
add <<L
dn: CN={AAAA0000-0000-0000-0000-000000000000},CN=SOM,CN=WMIPolicy,CN=System,$BASE
objectClass: msWMI-Som
msWMI-Name: Servers only
msWMI-ID: {AAAA0000-0000-0000-0000-000000000000}
msWMI-Parm2: 1;3;10;43;WQL;root\\CIMv2;SELECT * FROM Win32_OperatingSystem WHERE ProductType = 3;
L
ldif <<L
dn: CN=$DDP,CN=Policies,CN=System,$BASE
changetype: modify
replace: gPCWQLFilter
gPCWQLFilter: [corp.example.com;{11111111-2222-3333-4444-555555555555};0]
L

# AD-GPO-021: a software package installed from a file share.
MACHINE_DN="CN=Machine,CN=$DDP,CN=Policies,CN=System,$BASE"
add <<L
dn: CN=Class Store,$MACHINE_DN
objectClass: classStore

dn: CN={BBBB0000-0000-0000-0000-000000000000},CN=Class Store,$MACHINE_DN
objectClass: packageRegistration
displayName: Monitoring Agent
msiFileList: 0:\\\\fileserver\\apps\\agent.msi
L

echo "Lab domain seeded."
