#!/usr/bin/env bash
# Builds a throw-away Active Directory domain (corp.example.com) on this
# Linux machine with Samba, for CI: the collector reads it over LDAP like a
# Windows domain controller. Run as root. Lab only: the password is public
# and simple binds over plain LDAP are allowed.
set -euo pipefail

PY="${SAMBA_PYTHON:-python3}"
pkill -x samba 2>/dev/null || true
sleep 1
rm -f /etc/samba/smb.conf
rm -rf /var/lib/samba/private/* /var/lib/samba/sysvol/* /var/cache/samba/* 2>/dev/null || true
"$PY" /usr/bin/samba-tool domain provision --realm=CORP.EXAMPLE.COM --domain=CORP --server-role=dc \
  --dns-backend=SAMBA_INTERNAL --adminpass='Passw0rd!Lab' --option='ldap server require strong auth = no' \
  --option='dns port = 5353' >/dev/null
grep -q 'ldap server require strong auth' /etc/samba/smb.conf ||
  sed -i 's/^\[global\]/[global]\n\tldap server require strong auth = no/' /etc/samba/smb.conf
samba -D
for _ in $(seq 1 60); do
  if ldapsearch -x -H ldap://127.0.0.1 -D 'Administrator@corp.example.com' -w 'Passw0rd!Lab' -b '' -s base >/dev/null 2>&1; then
    echo "Lab domain is up."
    exit 0
  fi
  sleep 1
done
echo "Samba did not start." >&2
exit 1
