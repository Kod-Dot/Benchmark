# Lab domain for CI

CI builds a real Active Directory domain with Samba on a Linux runner, then
checks the analysis against it. This tests the checks on directory data the
shipped collector actually read, not only on hand-written fixtures.

1. `start-domain.sh` provisions `corp.example.com` and starts Samba (as root).
2. `seed.sh` adds objects that should trigger checks. Each block names its check.
3. The collector reads the domain over LDAP with PowerShell 7
   (`-Credential`, which uses System.DirectoryServices.Protocols), and a copy
   of its SYSVOL with `-SysvolPath`. `write-policy.py` puts Group Policy
   files (GptTmpl.inf, audit.csv, Registry.pol) in SYSVOL the way the Group
   Policy editor writes them.
4. `cargo test -p dca-core --lib -- --ignored live_lab_domain` checks every
   entry in `expected.json`. It also fails if any area the collector returned
   could not be read.

To add a check to the lab, seed what it should find in `seed.sh` and add its
expected result to `expected.json`.

Samba covers what a domain stores over LDAP and in SYSVOL. Domain controller
registry and event logs come from Windows, so those checks stay "Not
assessed" here; the `live-windows` job covers them on a Windows Server
runner. Samba also does not return replication metadata
(msDS-ReplValueMetaData, msDS-ReplAttributeMetaData), and SYSVOL folder
permissions cannot be read off Windows.

To run it locally (Ubuntu, as root):

```sh
apt-get install samba samba-ad-dc samba-ad-provision winbind ldb-tools ldap-utils
tools/lab/start-domain.sh && tools/lab/seed.sh
cp -r /var/lib/samba/sysvol/corp.example.com /tmp/sysvol
pwsh -c '$c = New-Object pscredential("Administrator@corp.example.com", (ConvertTo-SecureString "Passw0rd!Lab" -AsPlainText -Force));
  ./collectors/Invoke-DCACollect.ps1 -Domain corp.example.com -Server 127.0.0.1 -Credential $c -Sources "ldap,sysvol" -SysvolPath /tmp/sysvol -OutDir /tmp/lab -Bundle /tmp/lab.zip'
DCA_LAB_DIR=/tmp/lab cargo test -p dca-core --lib -- --ignored live_lab_domain --nocapture
```
