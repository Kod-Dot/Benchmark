#!/usr/bin/env python3
"""Writes Group Policy files into the lab domain's SYSVOL the way the Group
Policy editor does: GptTmpl.inf (UTF-16 with BOM), audit.csv and
Registry.pol (PReg). Used by seed.sh.

    write-policy.py <policy folder> <deny-logon SID or ->
"""
import os
import struct
import sys

folder, deny_sid = sys.argv[1], sys.argv[2]
machine = os.path.join(folder, "MACHINE")


def write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def inf(lines):
    text = "\r\n".join(["[Unicode]", "Unicode=yes"] + lines + ["[Version]", 'signature="$CHICAGO$"', "Revision=1", ""])
    return b"\xff\xfe" + text.encode("utf-16-le")


def preg(entries):
    out = b"PReg" + struct.pack("<I", 1)
    for key, value, kind, data in entries:
        if kind == 4:
            raw = struct.pack("<I", data)
        else:
            raw = (data + "\0").encode("utf-16-le")
        out += "[".encode("utf-16-le")
        out += (key + "\0").encode("utf-16-le") + ";".encode("utf-16-le")
        out += (value + "\0").encode("utf-16-le") + ";".encode("utf-16-le")
        out += struct.pack("<I", kind) + ";".encode("utf-16-le")
        out += struct.pack("<I", len(raw)) + ";".encode("utf-16-le")
        out += raw + "]".encode("utf-16-le")
    return out


if deny_sid == "-":
    # Default Domain Controllers Policy: settings the checks look at.
    write(
        os.path.join(machine, "Microsoft", "Windows NT", "SecEdit", "GptTmpl.inf"),
        inf(
            [
                "[Privilege Rights]",
                "SeNetworkLogonRight = *S-1-1-0,*S-1-5-11,*S-1-5-32-544,*S-1-5-9,*S-1-5-32-554",
                "[Security Log]",
                "MaximumLogSize = 131072",
                "[Registry Values]",
                "MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters\\LDAPServerIntegrity=4,1",
                "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel=4,5",
            ]
        ),
    )
    write(
        os.path.join(machine, "Microsoft", "Windows NT", "Audit", "audit.csv"),
        (
            "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value\r\n"
            ",System,Audit Logon,{0cce9215-69ae-11d9-bed3-505054503030},Success and Failure,,3\r\n"
            ",System,Audit Credential Validation,{0cce923f-69ae-11d9-bed3-505054503030},Success,,1\r\n"
        ).encode("utf-8-sig"),
    )
    write(
        os.path.join(machine, "Registry.pol"),
        preg(
            [
                ("Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile", "EnableFirewall", 4, 1),
                ("Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile", "EnableFirewall", 4, 0),
                ("Software\\Policies\\Microsoft\\Windows\\System", "UserPolicyMode", 4, 2),
                ("Software\\Policies\\Microsoft\\Windows\\SrpV2\\Exe", "EnforcementMode", 4, 1),
            ]
        ),
    )
else:
    # Default Domain Policy: deny local sign-in to one service account.
    write(
        os.path.join(machine, "Microsoft", "Windows NT", "SecEdit", "GptTmpl.inf"),
        inf(["[Privilege Rights]", "SeDenyInteractiveLogonRight = *" + deny_sid]),
    )
