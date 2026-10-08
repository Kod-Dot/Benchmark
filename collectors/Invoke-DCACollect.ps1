<#
.SYNOPSIS
    Collects on-premises Active Directory data for Benchmark. Read-only.

.DESCRIPTION
    Reads one domain over LDAP (and, when asked, the SYSVOL share) and writes
    the raw data to -OutDir:

        collection.json     where and when it was read, RootDSE values
        <area>.jsonl        one JSON object per directory object, keyed by
                            lower-case LDAP attribute name; every value is
                            an array, exactly as LDAP returned it

        dcconfig.jsonl      with dc-remote: one object per domain controller,
                            read over PowerShell remoting (registry values,
                            services, audit policy, SMB, firewall, disks)
        dcevents.jsonl      with dc-events: one object per domain controller,
                            counts of legacy-protocol and security events from
                            its logs over the last -EventDays days, and the
                            distinct sources of threat-hunting events
                            (account, host and object names only)
        endpoints.jsonl     with endpoints: one object per member server or
                            workstation, read over PowerShell remoting
                            (registry values, services, local groups,
                            Defender, firewall, SMB, sessions); the autologon
                            password is never read, only whether one is set

    Progress goes to stdout as JSON lines, one per event:

        {"type":"start","area":"users"}
        {"type":"progress","area":"users","read":1500}
        {"type":"done","area":"users","count":48210}
        {"type":"error","area":"acls","message":"..."}

    An area that fails does not stop the others. Passwords, LAPS values,
    BitLocker keys and gMSA blobs are never read; only their expiry times
    and who can read them. GPP cpassword values are detected, never copied.

    Compatible with Windows PowerShell 5.1 and PowerShell 7.

.PARAMETER Domain
    DNS name of the domain, for example corp.example.com.

.PARAMETER OutDir
    Folder to write to. Created if missing.

.PARAMETER Sources
    Comma-separated source ids from checks/sources.toml. This script reads
    ldap, sysvol, dc-remote, dc-events and endpoints; other ids are ignored.

.PARAMETER Server
    Domain controller to read from. Defaults to the one the locator picks.

.PARAMETER Credential
    Account to read the directory as, instead of the signed-in user. With a
    credential, or when not running on Windows, LDAP is read through
    System.DirectoryServices.Protocols with a simple bind; use -Ldaps so the
    password is not sent in clear text. Only the ldap source works this way.

.PARAMETER SysvolPath
    Folder that holds the domain's SYSVOL content (Policies and scripts),
    for reading a copy or a mounted share. Defaults to
    \\<domain>\SYSVOL\<domain>. Off Windows, names in it are matched
    without regard to case, as Windows does.

.PARAMETER Ldaps
    With -Credential, or off Windows: connect over LDAPS (port 636).

.PARAMETER EventDays
    How many days of event logs dc-events looks back over.

.PARAMETER Endpoints
    Comma-separated host names for the endpoints source. When left out, the
    enabled Windows member servers and workstations that signed in within
    30 days are read: up to -EndpointServers servers and the
    -EndpointWorkstations most recently active workstations.

.PARAMETER Bundle
    For running the collector on its own, for example on a domain
    controller: also keeps the progress log in -OutDir (events.jsonl) and,
    when collection finishes, packs -OutDir into this .zip file. Open it in
    the Benchmark app with Open bundle to analyze it there.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Domain,
    [Parameter(Mandatory)] [string] $OutDir,
    [string] $Sources = 'ldap,sysvol',
    [string] $Server,
    [pscredential] $Credential,
    [switch] $Ldaps,
    [string] $SysvolPath,
    [ValidateRange(1, 90)] [int] $EventDays = 7,
    [string] $Endpoints,
    [ValidateRange(0, 5000)] [int] $EndpointServers = 200,
    [ValidateRange(0, 5000)] [int] $EndpointWorkstations = 50,
    [string] $Bundle
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

$utf8 = New-Object System.Text.UTF8Encoding($false)
$sidAttributes = @('objectsid', 'sidhistory', 'securityidentifier', 'ms-ds-creatorsid')
$guidAttributes = @('objectguid', 'schemaidguid')

$script:eventLog = $null
$script:schemaNc = $null
$script:ldapHost = $null
$script:useLdaps = $Ldaps.IsPresent
$script:onWindows = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
$script:sysvolRoot = if ($SysvolPath) { $SysvolPath } else { "\\$Domain\SYSVOL\$Domain" }

function Write-Event([hashtable] $Data) {
    $line = ConvertTo-Json -InputObject $Data -Compress
    [Console]::Out.WriteLine($line)
    if ($script:eventLog) { [System.IO.File]::AppendAllText($script:eventLog, $line + [Environment]::NewLine, $utf8) }
}

function Get-FirstLine([System.Management.Automation.ErrorRecord] $ErrorRecord) {
    $message = $ErrorRecord.Exception.Message
    if ($ErrorRecord.Exception.InnerException) { $message = $ErrorRecord.Exception.InnerException.Message }
    ($message -split "`r?`n")[0].Trim()
}

# S-1-<authority>-<sub authorities>, without the Windows-only SecurityIdentifier
# class, so the collector also runs on PowerShell 7 off Windows.
function ConvertTo-SidString([byte[]] $Bytes) {
    $authority = [uint64]0
    for ($i = 2; $i -lt 8; $i++) { $authority = ($authority -shl 8) -bor $Bytes[$i] }
    $parts = @('S', $Bytes[0], $authority)
    for ($i = 0; $i -lt $Bytes[1]; $i++) { $parts += [BitConverter]::ToUInt32($Bytes, 8 + 4 * $i) }
    $parts -join '-'
}

function ConvertTo-JsonValue([string] $Name, $Value) {
    if ($Value -is [byte[]]) {
        if ($sidAttributes -contains $Name) {
            return (ConvertTo-SidString $Value)
        }
        if ($guidAttributes -contains $Name) { return (New-Object System.Guid(, $Value)).ToString() }
        return [Convert]::ToBase64String($Value)
    }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
    $Value
}

function Get-LdapEntry([string] $Dn) {
    New-Object System.DirectoryServices.DirectoryEntry("LDAP://$script:server/$($Dn.Replace('/', '\/'))")
}

# Values past the server's per-attribute limit (1500 for member) come back
# as attr;range=0-1499. Reads the rest, one range at a time.
function Get-RangedValue([string] $Dn, [string] $Attribute, [int] $Start) {
    $values = New-Object System.Collections.Generic.List[object]
    $low = $Start
    while ($true) {
        $searcher = New-Object System.DirectoryServices.DirectorySearcher((Get-LdapEntry $Dn), '(objectClass=*)', @("$Attribute;range=$low-*"))
        $searcher.SearchScope = 'Base'
        $result = $searcher.FindOne()
        if ($null -eq $result) { break }
        $name = @($result.Properties.PropertyNames | Where-Object { $_ -like "$Attribute;range=*" }) | Select-Object -First 1
        if (-not $name) { break }
        foreach ($v in $result.Properties[$name]) { $values.Add((ConvertTo-JsonValue $Attribute $v)) }
        if ($name.EndsWith('-*')) { break }
        $low += $result.Properties[$name].Count
    }
    , $values.ToArray()
}

# ---------- LDAP through System.DirectoryServices.Protocols ----------
# Used with -Credential and off Windows (PowerShell 7 on Linux or macOS),
# where System.DirectoryServices (ADSI) is not available. Only searches are
# sent: the connection never carries an add, modify or delete request.

$script:useProtocols = $false
$script:ldap = $null
$script:syntax = @{}

function Get-LdapConnection {
    if ($null -eq $script:ldap) {
        Add-Type -AssemblyName System.DirectoryServices.Protocols
        $port = if ($script:useLdaps) { 636 } else { 389 }
        $id = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($script:ldapHost, $port)
        $connection = New-Object System.DirectoryServices.Protocols.LdapConnection($id)
        $connection.SessionOptions.ProtocolVersion = 3
        $connection.SessionOptions.ReferralChasing = [System.DirectoryServices.Protocols.ReferralChasingOptions]::None
        if ($script:useLdaps) { $connection.SessionOptions.SecureSocketLayer = $true }
        $connection.Timeout = [TimeSpan]::FromMinutes(10)
        if ($Credential) {
            $connection.AuthType = [System.DirectoryServices.Protocols.AuthType]::Basic
            $connection.Credential = $Credential.GetNetworkCredential()
        }
        else {
            $connection.AuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate
        }
        $connection.Bind()
        $script:ldap = $connection
    }
    $script:ldap
}

# attributeSyntax of each attribute, read from the schema once per name, so
# values come out typed the way ADSI types them: numbers, booleans, dates
# and binary values.
function Get-AttributeSyntax([string[]] $Names) {
    $unknown = @($Names | Where-Object { -not $script:syntax.ContainsKey($_) -and $_ -notmatch ';' })
    if ($unknown.Count -and $script:schemaNc) {
        $filter = '(|' + (($unknown | ForEach-Object { "(lDAPDisplayName=$_)" }) -join '') + ')'
        foreach ($entry in (Find-ProtocolsEntry -Base $script:schemaNc -Filter $filter -Attributes @('ldapdisplayname', 'attributesyntax') -Scope 'OneLevel' -Raw)) {
            $script:syntax[([string]$entry['ldapdisplayname'][0]).ToLowerInvariant()] = [string]$entry['attributesyntax'][0]
        }
        foreach ($n in $unknown) { if (-not $script:syntax.ContainsKey($n)) { $script:syntax[$n] = '' } }
    }
}

function ConvertFrom-LdapAttribute([string] $Name, [System.DirectoryServices.Protocols.DirectoryAttribute] $Attribute, [bool] $Raw) {
    $base = ($Name -split ';')[0]
    $syntax = if ($Raw) { '' } else { $script:syntax[$base] }
    if ($base -eq 'ntsecuritydescriptor' -or $syntax -in @('2.5.5.10', '2.5.5.15', '2.5.5.17')) {
        return , @(foreach ($v in $Attribute.GetValues([byte[]])) { ConvertTo-JsonValue $base $v })
    }
    , @(foreach ($v in $Attribute.GetValues([string])) {
            switch ($syntax) {
                { $_ -in @('2.5.5.9', '2.5.5.16') } { [int64]$v; break }
                '2.5.5.8' { $v -eq 'TRUE'; break }
                '2.5.5.11' {
                    [DateTime]::ParseExact($v.Substring(0, 14), 'yyyyMMddHHmmss', [Globalization.CultureInfo]::InvariantCulture,
                        [Globalization.DateTimeStyles]'AssumeUniversal, AdjustToUniversal').ToString('yyyy-MM-ddTHH:mm:ssZ')
                    break
                }
                default { $v }
            }
        })
}

# Every object under $Base matching $Filter, as ordered name -> values maps,
# reading the rest of ranged values (member;range=0-1499) as ADSI does.
function Find-ProtocolsEntry {
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Base,
        [Parameter(Mandatory)] [string] $Filter,
        [Parameter(Mandatory)] [string[]] $Attributes,
        [string] $Scope = 'Subtree',
        [switch] $SecurityDescriptor,
        [string] $Masks = 'Owner, Dacl',
        [switch] $Raw
    )
    $connection = Get-LdapConnection
    if (-not $Raw) { Get-AttributeSyntax $Attributes }
    $request = New-Object System.DirectoryServices.Protocols.SearchRequest($Base, $Filter, [System.DirectoryServices.Protocols.SearchScope]$Scope, $Attributes)
    $paging = $null
    if ($Scope -ne 'Base') {
        $paging = New-Object System.DirectoryServices.Protocols.PageResultRequestControl(1000)
        $null = $request.Controls.Add($paging)
    }
    if ($SecurityDescriptor) {
        # Owner and DACL unless an area asks for less, or for the SACL alone.
        $flags = [System.DirectoryServices.Protocols.SecurityMasks]$Masks
        $null = $request.Controls.Add((New-Object System.DirectoryServices.Protocols.SecurityDescriptorFlagControl($flags)))
    }
    while ($true) {
        $response = [System.DirectoryServices.Protocols.SearchResponse]$connection.SendRequest($request)
        foreach ($entry in $response.Entries) {
            $object = [ordered]@{}
            foreach ($name in @($entry.Attributes.AttributeNames | Sort-Object)) {
                $lower = ([string]$name).ToLowerInvariant()
                $values = ConvertFrom-LdapAttribute $lower $entry.Attributes[$name] $Raw.IsPresent
                if ($lower -match '^(.+);range=(\d+)-(\d+|\*)$') {
                    $attribute = $Matches[1]
                    $all = New-Object System.Collections.Generic.List[object]
                    $all.AddRange([object[]]$values)
                    $done = $Matches[3] -eq '*'
                    while (-not $done) {
                        $more = New-Object System.DirectoryServices.Protocols.SearchRequest($entry.DistinguishedName, '(objectClass=*)', [System.DirectoryServices.Protocols.SearchScope]::Base, @("$attribute;range=$($all.Count)-*"))
                        $next = ([System.DirectoryServices.Protocols.SearchResponse]$connection.SendRequest($more)).Entries[0]
                        $rangeName = @($next.Attributes.AttributeNames | Where-Object { ([string]$_) -like "$attribute;range=*" }) | Select-Object -First 1
                        if (-not $rangeName) { break }
                        $all.AddRange([object[]](ConvertFrom-LdapAttribute $attribute $next.Attributes[$rangeName] $Raw.IsPresent))
                        $done = ([string]$rangeName).EndsWith('-*')
                    }
                    $object[$attribute] = $all.ToArray()
                }
                else {
                    $object[$lower] = $values
                }
            }
            if (-not $object.Contains('distinguishedname') -and ($Attributes -contains 'distinguishedname')) {
                $object['distinguishedname'] = @($entry.DistinguishedName)
            }
            $object
        }
        if ($null -eq $paging) { break }
        $cookie = $null
        foreach ($control in $response.Controls) {
            if ($control -is [System.DirectoryServices.Protocols.PageResultResponseControl]) { $cookie = $control.Cookie }
        }
        if ($null -eq $cookie -or $cookie.Length -eq 0) { break }
        $paging.Cookie = $cookie
    }
}

# Writes every object matching $Filter under $Base to <OutDir>/<Area>.jsonl.
function Export-LdapObject {
    param(
        [Parameter(Mandatory)] [string] $Area,
        [Parameter(Mandatory)] [string] $Base,
        [Parameter(Mandatory)] [string] $Filter,
        [Parameter(Mandatory)] [string[]] $Attributes,
        [string] $Scope = 'Subtree',
        [switch] $SecurityDescriptor,
        [string] $Masks = 'Owner, Dacl'
    )
    Write-Event @{ type = 'start'; area = $Area }
    $count = 0
    $results = $null
    if ($script:useProtocols) {
        try {
            $writer = New-Object System.IO.StreamWriter((Join-Path $OutDir "$Area.jsonl"), $false, $utf8)
            try {
                foreach ($object in (Find-ProtocolsEntry -Base $Base -Filter $Filter -Attributes $Attributes -Scope $Scope -SecurityDescriptor:$SecurityDescriptor -Masks $Masks)) {
                    $writer.WriteLine((ConvertTo-Json -InputObject $object -Compress -Depth 3))
                    $count++
                    if ($count % 1000 -eq 0) { Write-Event @{ type = 'progress'; area = $Area; read = $count } }
                }
            }
            finally { $writer.Dispose() }
            Write-Event @{ type = 'done'; area = $Area; count = $count }
        }
        catch {
            Write-Event @{ type = 'error'; area = $Area; message = (Get-FirstLine $_) }
        }
        return
    }
    try {
        $searcher = New-Object System.DirectoryServices.DirectorySearcher((Get-LdapEntry $Base), $Filter, $Attributes)
        $searcher.SearchScope = $Scope
        if ($Scope -ne 'Base') { $searcher.PageSize = 1000 }
        if ($SecurityDescriptor) {
            $searcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]$Masks
        }
        $writer = New-Object System.IO.StreamWriter((Join-Path $OutDir "$Area.jsonl"), $false, $utf8)
        try {
            $results = $searcher.FindAll()
            foreach ($result in $results) {
                $object = [ordered]@{}
                foreach ($name in $result.Properties.PropertyNames) {
                    if ($name -eq 'adspath') { continue }
                    $values = @(foreach ($v in $result.Properties[$name]) { ConvertTo-JsonValue $name $v })
                    if ($name -match '^(.+);range=0-\d+$') {
                        $attribute = $Matches[1]
                        $rest = Get-RangedValue ([string]$result.Properties['distinguishedname'][0]) $attribute $values.Count
                        $object[$attribute] = @($values + $rest)
                    }
                    else {
                        $object[$name] = $values
                    }
                }
                $writer.WriteLine((ConvertTo-Json -InputObject $object -Compress -Depth 3))
                $count++
                if ($count % 1000 -eq 0) { Write-Event @{ type = 'progress'; area = $Area; read = $count } }
            }
        }
        finally {
            if ($results) { $results.Dispose() }
            $writer.Dispose()
        }
        Write-Event @{ type = 'done'; area = $Area; count = $count }
    }
    catch {
        Write-Event @{ type = 'error'; area = $Area; message = (Get-FirstLine $_) }
    }
}

# ---------- SYSVOL ----------

# Values whose names suggest a secret are never copied, only noted.
# Policy settings about passwords (lengths, ages, plain-text switches) are
# not secrets and are kept.
$secretName = '(?i)pass(word|wd)?|pwd|secret'
$passwordSetting = '(?i)(Minimum|Maximum)Password|PasswordComplexity|PasswordHistorySize|ClearTextPassword|RequireLogonToChangePassword|DisablePasswordChange|PasswordExpiryWarning|PlainTextPassword|PasswordAge'

function Test-SecretName([string] $Name) {
    $Name -match $secretName -and $Name -notmatch $passwordSetting
}

# Sections of a security template (GptTmpl.inf): section -> key -> values.
function Read-SecurityTemplate([string] $Path) {
    $sections = [ordered]@{}
    $current = $null
    foreach ($line in [System.IO.File]::ReadAllLines($Path)) {
        $t = $line.Trim()
        if ($t -match '^\[(.+)\]$') {
            $current = [ordered]@{}
            $sections[$Matches[1]] = $current
            continue
        }
        if ($null -eq $current -or $t -eq '' -or $t.StartsWith(';')) { continue }
        $eq = $t.IndexOf('=')
        if ($eq -lt 1) { continue }
        $key = $t.Substring(0, $eq).Trim()
        $value = $t.Substring($eq + 1).Trim()
        if (Test-SecretName $key) {
            $current[$key] = @('[not copied]')
            continue
        }
        $current[$key] = @($value -split ',' | ForEach-Object { $_.Trim() })
    }
    $sections
}

# Settings in a Registry.pol file (PReg format): key, value, type and data.
# Binary data is not copied; nor is any value whose name suggests a secret.
function Read-RegistryPolicy([string] $Path) {
    $b = [System.IO.File]::ReadAllBytes($Path)
    $u = [System.Text.Encoding]::Unicode
    $entries = New-Object System.Collections.Generic.List[object]
    if ($b.Length -lt 8 -or [System.Text.Encoding]::ASCII.GetString($b, 0, 4) -ne 'PReg') { return , $entries.ToArray() }
    $i = 8
    while ($i + 2 -le $b.Length -and $u.GetString($b, $i, 2) -eq '[') {
        $i += 2
        $text = @()
        foreach ($f in 0, 1) {
            $start = $i
            while ($i + 1 -lt $b.Length -and ($b[$i] -ne 0 -or $b[$i + 1] -ne 0)) { $i += 2 }
            $text += $u.GetString($b, $start, $i - $start)
            $i += 4
        }
        if ($i + 12 -gt $b.Length) { break }
        $type = [BitConverter]::ToUInt32($b, $i)
        $size = [int][BitConverter]::ToUInt32($b, $i + 6)
        $i += 12
        if ($size -lt 0 -or $i + $size -gt $b.Length) { break }
        $data = $null
        if (Test-SecretName $text[1]) { $data = '[not copied]' }
        elseif ($type -in 1, 2) { $data = $u.GetString($b, $i, $size).TrimEnd([char]0) }
        elseif ($type -eq 4 -and $size -ge 4) { $data = [BitConverter]::ToUInt32($b, $i) }
        elseif ($type -eq 11 -and $size -ge 8) { $data = [BitConverter]::ToUInt64($b, $i) }
        elseif ($type -eq 7) { $data = @($u.GetString($b, $i, $size).Split([char]0) | Where-Object { $_ }) }
        $i += $size + 2
        $entries.Add([ordered]@{ key = $text[0]; value = $text[1]; type = $type; data = $data })
    }
    , $entries.ToArray()
}

# Startup, shutdown, logon and logoff scripts: the command only, never its
# parameters.
function Read-ScriptList([string] $Path, [string] $Scope) {
    $kind = $null
    foreach ($line in [System.IO.File]::ReadAllLines($Path)) {
        $t = $line.Trim()
        if ($t -match '^\[(.+)\]$') { $kind = $Matches[1]; continue }
        if ($kind -and $t -match '^\d+CmdLine=(.*)$') {
            [ordered]@{ scope = $Scope; kind = $kind; path = $Matches[1].Trim() }
        }
    }
}

# Group Policy Preferences scheduled tasks and local groups. Passwords are
# handled by the cpassword scan and never copied here.
function Read-Preference([string] $Folder) {
    $tasks = @()
    $groups = @()
    foreach ($side in 'Machine', 'User') {
        $file = Get-SysvolPath $Folder "$side\Preferences\ScheduledTasks\ScheduledTasks.xml"
        if ([System.IO.File]::Exists($file)) {
            $xml = [xml][System.IO.File]::ReadAllText($file)
            $kinds = @('Task', 'ImmediateTask', 'TaskV2', 'ImmediateTaskV2')
            foreach ($t in @($xml.DocumentElement.ChildNodes | Where-Object { $kinds -contains $_.LocalName })) {
                $p = $t.SelectSingleNode('Properties')
                $runAs = $null
                if ($p) {
                    $runAs = $p.GetAttribute('runAs')
                    if (-not $runAs) {
                        $id = $p.SelectSingleNode('Task/Principals/Principal/UserId')
                        if ($id) { $runAs = $id.InnerText }
                    }
                }
                $tasks += [ordered]@{ scope = $side; name = $t.GetAttribute('name'); run_as = $runAs }
            }
        }
        $file = Get-SysvolPath $Folder "$side\Preferences\Groups\Groups.xml"
        if ([System.IO.File]::Exists($file)) {
            $xml = [xml][System.IO.File]::ReadAllText($file)
            foreach ($g in $xml.SelectNodes('//Group')) {
                $p = $g.SelectSingleNode('Properties')
                if (-not $p) { continue }
                $members = @(foreach ($m in $p.SelectNodes('Members/Member')) {
                        [ordered]@{ name = $m.GetAttribute('name'); sid = $m.GetAttribute('sid'); action = $m.GetAttribute('action') }
                    })
                $groups += [ordered]@{
                    group = $p.GetAttribute('groupName'); sid = $p.GetAttribute('groupSid'); action = $p.GetAttribute('action')
                    delete_all = ($p.GetAttribute('deleteAllUsers') -eq '1'); members = $members
                }
            }
        }
    }
    [ordered]@{ tasks = $tasks; groups = $groups }
}

# Who other than the owner can write to a policy folder.
function Read-FolderAcl([string] $Path) {
    $acl = Get-Acl -LiteralPath $Path
    $sid = {
        param($identity)
        try { $identity.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $null }
    }
    $writers = @(foreach ($r in $acl.Access) {
            if ($r.AccessControlType -ne 'Allow') { continue }
            $rights = [string]$r.FileSystemRights
            if ($rights -notmatch 'Write|Modify|FullControl|ChangePermissions|TakeOwnership|CreateFiles|AppendData|268435456|1073741824') { continue }
            [ordered]@{ identity = $r.IdentityReference.Value; sid = (& $sid $r.IdentityReference); rights = $rights; inherit_only = [bool]($r.PropagationFlags -band 2) }
        })
    $owner = $acl.GetOwner([System.Security.Principal.NTAccount])
    [ordered]@{ owner = $owner.Value; owner_sid = (& $sid $owner); writers = $writers }
}

# $Relative (written with backslashes) under $Base. Off Windows, each name
# is matched without regard to case, as on a Windows share.
function Get-SysvolPath([string] $Base, [string] $Relative) {
    if ($script:onWindows) { return Join-Path $Base $Relative }
    $path = $Base
    foreach ($part in @($Relative -split '[\\/]' | Where-Object { $_ })) {
        $next = [System.IO.Path]::Combine($path, $part)
        if (-not ([System.IO.File]::Exists($next) -or [System.IO.Directory]::Exists($next)) -and [System.IO.Directory]::Exists($path)) {
            $match = @([System.IO.Directory]::GetFileSystemEntries($path) | Where-Object { [System.IO.Path]::GetFileName($_) -ieq $part }) | Select-Object -First 1
            if ($match) { $next = $match }
        }
        $path = $next
    }
    $path
}

# A path below a SYSVOL folder as Windows writes it: backslashes.
function Get-RelativePath([string] $Full, [string] $Base) {
    $Full.Substring($Base.Length).TrimStart('\', '/').Replace('/', '\')
}

# SYSVOL: each policy folder, its security template, registry policy,
# scripts, preferences, permissions and file list, and which Group Policy
# Preferences files hold a cpassword. The cpassword value itself is never
# copied, nor are script parameters or values whose names suggest secrets.
function Export-SysvolPolicy {
    $area = 'sysvol'
    Write-Event @{ type = 'start'; area = $area }
    $root = Get-SysvolPath $script:sysvolRoot 'Policies'
    $count = 0
    try {
        $writer = New-Object System.IO.StreamWriter((Join-Path $OutDir "$area.jsonl"), $false, $utf8)
        try {
            foreach ($folder in Get-ChildItem -LiteralPath $root -Directory) {
                $gpp = @()
                foreach ($side in 'Machine', 'User') {
                    $prefs = Get-SysvolPath $folder.FullName "$side\Preferences"
                    if (-not (Test-Path -LiteralPath $prefs)) { continue }
                    foreach ($file in Get-ChildItem -LiteralPath $prefs -Recurse -Filter *.xml -File) {
                        $text = [System.IO.File]::ReadAllText($file.FullName)
                        foreach ($m in [regex]::Matches($text, '<(\w+)\s[^>]*\bcpassword="([^"]+)"[^>]*>')) {
                            $user = [regex]::Match($m.Value, '\b(?:userName|runAs|accountName)="([^"]*)"')
                            $gpp += [ordered]@{
                                file = Get-RelativePath $file.FullName $folder.FullName
                                element = $m.Groups[1].Value
                                user = $(if ($user.Success) { $user.Groups[1].Value } else { $null })
                            }
                        }
                    }
                }
                $record = [ordered]@{ folder = $folder.Name; cpasswords = @($gpp) }
                $errors = [ordered]@{}
                # -List keeps a list a list: PowerShell unrolls one item to a
                # bare value and no items to $null.
                $part = {
                    param([string] $Name, [scriptblock] $Read, [switch] $List)
                    try { if ($List) { $record[$Name] = @(& $Read) } else { $record[$Name] = & $Read } }
                    catch { $errors[$Name] = Get-FirstLine $_ }
                }
                & $part 'files' -List {
                    @(Get-ChildItem -LiteralPath $folder.FullName -Recurse -File -Force | Select-Object -First 200 |
                        ForEach-Object { Get-RelativePath $_.FullName $folder.FullName })
                }
                & $part 'version' {
                    $ini = Get-SysvolPath $folder.FullName 'GPT.INI'
                    if ([System.IO.File]::Exists($ini)) {
                        $v = [regex]::Match([System.IO.File]::ReadAllText($ini), '(?im)^\s*Version\s*=\s*(\d+)')
                        if ($v.Success) { [int64]$v.Groups[1].Value }
                    }
                }
                & $part 'inf' {
                    $inf = Get-SysvolPath $folder.FullName 'Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf'
                    if ([System.IO.File]::Exists($inf)) { Read-SecurityTemplate $inf } else { [ordered]@{} }
                }
                & $part 'registry' -List {
                    @(foreach ($side in 'Machine', 'User') {
                            $pol = Get-SysvolPath $folder.FullName "$side\Registry.pol"
                            if ([System.IO.File]::Exists($pol)) {
                                # Assigned first: the function returns its list as one
                                # object, which foreach over the call would not unroll.
                                $entries = Read-RegistryPolicy $pol
                                foreach ($e in $entries) { $e['scope'] = $side; $e }
                            }
                        })
                }
                & $part 'scripts' -List {
                    @(foreach ($side in 'Machine', 'User') {
                            foreach ($name in 'scripts.ini', 'psscripts.ini') {
                                $ini = Get-SysvolPath $folder.FullName "$side\Scripts\$name"
                                if ([System.IO.File]::Exists($ini)) { Read-ScriptList $ini $side }
                            }
                        })
                }
                & $part 'audit' -List {
                    $csv = Get-SysvolPath $folder.FullName 'Machine\Microsoft\Windows NT\Audit\audit.csv'
                    if ([System.IO.File]::Exists($csv)) {
                        foreach ($row in ([System.IO.File]::ReadAllText($csv) | ConvertFrom-Csv)) {
                            if (-not $row.'Subcategory GUID') { continue }
                            [ordered]@{ subcategory = $row.Subcategory; guid = $row.'Subcategory GUID'.Trim('{}').ToLowerInvariant(); value = [int]$row.'Setting Value' }
                        }
                    }
                }
                & $part 'preferences' { Read-Preference $folder.FullName }
                & $part 'acl' { Read-FolderAcl $folder.FullName }
                $record.errors = $errors
                $writer.WriteLine((ConvertTo-Json -InputObject $record -Compress -Depth 8))
                $count++
            }
        }
        finally { $writer.Dispose() }
        Write-Event @{ type = 'done'; area = $area; count = $count }
    }
    catch {
        Write-Event @{ type = 'error'; area = $area; message = ("Could not read ${root}: " + (Get-FirstLine $_)) }
    }
}

# Logon scripts in NETLOGON and policy script folders that look like they
# hold credentials. Only the file, the line number and which pattern
# matched are recorded, never the line itself.
function Export-ScriptScan {
    $area = 'scripts'
    Write-Event @{ type = 'start'; area = $area }
    $patterns = [ordered]@{
        password_assignment = '(?i)\b(pass(word|wd)?|pwd)\s*[=:]\s*["'']?(?!Read-Host|Get-Credential|ConvertTo-SecureString)[^\s"''$%(\[]'
        net_use_user = '(?i)\bnet\s+use\b.*\s/u(ser)?:'
        plain_securestring = '(?i)ConvertTo-SecureString\b.*-AsPlainText'
        runas_savecred = '(?i)\brunas\b.*\/savecred'
        connection_string = '(?i)(password|pwd)\s*=\s*[^;"''\s]+\s*;'
        psexec_password = '(?i)\bpsexec(64)?(\.exe)?\b.*\s-p\s+\S'
    }
    $extensions = @('.bat', '.cmd', '.ps1', '.psm1', '.vbs', '.js', '.kix', '.txt', '.ini', '.xml', '.config', '.reg', '.wsf')
    $roots = @(
        @('NETLOGON', $(if ($SysvolPath) { Get-SysvolPath $SysvolPath 'scripts' } else { "\\$Domain\NETLOGON" })),
        @('Policies', (Get-SysvolPath $script:sysvolRoot 'Policies'))
    )
    $count = 0
    $files = 0
    try {
        $writer = New-Object System.IO.StreamWriter((Join-Path $OutDir "$area.jsonl"), $false, $utf8)
        try {
            foreach ($r in $roots) {
                if (-not (Test-Path -LiteralPath $r[1])) { continue }
                foreach ($file in Get-ChildItem -LiteralPath $r[1] -Recurse -File -Force -ErrorAction SilentlyContinue) {
                    if ($extensions -notcontains $file.Extension.ToLowerInvariant() -or $file.Length -gt 2MB) { continue }
                    # Preferences XML is covered by the cpassword scan.
                    if ($r[0] -eq 'Policies' -and $file.FullName -notmatch '[\\/]Scripts[\\/]') { continue }
                    if (++$files -gt 10000) { break }
                    $n = 0
                    foreach ($line in [System.IO.File]::ReadLines($file.FullName)) {
                        $n++
                        foreach ($name in $patterns.Keys) {
                            if ($line -match $patterns[$name]) {
                                $writer.WriteLine((ConvertTo-Json -Compress -InputObject ([ordered]@{
                                                file = $r[0] + '\' + (Get-RelativePath $file.FullName $r[1]); line = $n; pattern = $name
                                            })))
                                $count++
                                break
                            }
                        }
                    }
                }
            }
        }
        finally { $writer.Dispose() }
        Write-Event @{ type = 'done'; area = $area; count = $count }
    }
    catch {
        Write-Event @{ type = 'error'; area = $area; message = (Get-FirstLine $_) }
    }
}

# ---------- Domain controllers (dc-remote and dc-events) ----------

# Host names of every writable and read-only DC of the domain, from LDAP.
function Get-DomainControllerHost {
    $searcher = New-Object System.DirectoryServices.DirectorySearcher((Get-LdapEntry $domainNc),
        '(&(objectCategory=computer)(|(userAccountControl:1.2.840.113556.1.4.803:=8192)(userAccountControl:1.2.840.113556.1.4.803:=67108864)))',
        @('dnshostname', 'name'))
    $searcher.PageSize = 1000
    $results = $searcher.FindAll()
    try {
        @(foreach ($r in $results) {
                if ($r.Properties['dnshostname'].Count) { [string]$r.Properties['dnshostname'][0] }
                else { [string]$r.Properties['name'][0] }
            }) | Sort-Object -Unique
    }
    finally { $results.Dispose() }
}

# Registry values read on each DC: key in the output, path, value name.
$dcRegistry = @(
    @('ntds.ldapserverintegrity', 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters', 'LDAPServerIntegrity'),
    @('ntds.ldapenforcechannelbinding', 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters', 'LdapEnforceChannelBinding'),
    @('ntds.database', 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters', 'DSA Database file'),
    @('ntds.logs', 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters', 'Database log files path'),
    @('ntds.strictreplication', 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters', 'Strict Replication Consistency'),
    @('ntds.dsanotwritable', 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters', 'Dsa Not Writable'),
    @('dfsr.sysvolstate', 'HKLM:\SYSTEM\CurrentControlSet\Services\DFSR\Parameters\SysVols\Migrating SysVols', 'Local State'),
    @('netlogon.sysvol', 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters', 'SysVol'),
    @('netlogon.fullsecurechannelprotection', 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters', 'FullSecureChannelProtection'),
    @('netlogon.vulnerablechannelallowlist', 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters', 'VulnerableChannelAllowList'),
    @('netlogon.restrictntlmindomain', 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters', 'RestrictNTLMInDomain'),
    @('netlogon.auditntlmindomain', 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters', 'AuditNTLMInDomain'),
    @('lsa.nolmhash', 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa', 'NoLMHash'),
    @('lsa.lmcompatibilitylevel', 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa', 'LmCompatibilityLevel'),
    @('lsa.restrictanonymous', 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa', 'RestrictAnonymous'),
    @('lsa.restrictanonymoussam', 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa', 'RestrictAnonymousSAM'),
    @('lsa.everyoneincludesanonymous', 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa', 'EveryoneIncludesAnonymous'),
    @('lsa.runasppl', 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa', 'RunAsPPL'),
    @('lsa.lsacfgflags', 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa', 'LsaCfgFlags'),
    @('lsa.dsrmadminlogonbehavior', 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa', 'DsrmAdminLogonBehavior'),
    @('lsa.securitypackages', 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa', 'Security Packages'),
    @('lsa.authenticationpackages', 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa', 'Authentication Packages'),
    @('lsa.notificationpackages', 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa', 'Notification Packages'),
    @('msv1_0.auditreceivingntlmtraffic', 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0', 'AuditReceivingNTLMTraffic'),
    @('msv1_0.restrictreceivingntlmtraffic', 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0', 'RestrictReceivingNTLMTraffic'),
    @('wdigest.uselogoncredential', 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest', 'UseLogonCredential'),
    @('kdc.strongcertificatebindingenforcement', 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc', 'StrongCertificateBindingEnforcement'),
    @('kdc.krbtgtfullpacsignature', 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc', 'KrbtgtFullPacSignature'),
    @('rdp.fdenytsconnections', 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server', 'fDenyTSConnections'),
    @('rdp.userauthentication', 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp', 'UserAuthentication'),
    @('rdp.policyuserauthentication', 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services', 'UserAuthentication'),
    @('winlogon.cachedlogonscount', 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon', 'CachedLogonsCount'),
    @('wef.subscriptionmanager', 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager', '1'),
    @('w32time.type', 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters', 'Type'),
    @('w32time.ntpserver', 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters', 'NtpServer'),
    @('dns.serverlevelplugindll', 'HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters', 'ServerLevelPluginDll'),
    @('dnsclient.enablemulticast', 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient', 'EnableMulticast'),
    @('winrm.allowunencryptedtraffic', 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service', 'AllowUnencryptedTraffic'),
    @('winrm.allowbasic', 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service', 'AllowBasic'),
    @('powershell.enabletranscripting', 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription', 'EnableTranscripting'),
    @('powershell.enablescriptblocklogging', 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging', 'EnableScriptBlockLogging'),
    @('powershell.outputdirectory', 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription', 'OutputDirectory'),
    @('schannel.ssl3.enabled', 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server', 'Enabled'),
    @('schannel.ssl3.disabledbydefault', 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server', 'DisabledByDefault'),
    @('schannel.tls10.enabled', 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server', 'Enabled'),
    @('schannel.tls10.disabledbydefault', 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server', 'DisabledByDefault'),
    @('schannel.tls11.enabled', 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server', 'Enabled'),
    @('schannel.tls11.disabledbydefault', 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server', 'DisabledByDefault')
)

# Runs on each DC. Reads only, and returns one JSON document. Every part is
# read on its own, so one that fails (for example Get-WindowsFeature on a
# Server Core DC without the module) leaves the others intact; its error is
# kept under "errors".
$dcConfigScript = {
    param($Registry)
    $ErrorActionPreference = 'Stop'
    $wantedValues = $Registry
    $out = [ordered]@{}
    $errors = [ordered]@{}
    # -List keeps a list a list: PowerShell unrolls one item to a bare value
    # and no items to $null, which would read as a missing part.
    function Read-Part([string] $Name, [switch] $List, [scriptblock] $Read) {
        try { if ($List) { $out[$Name] = @(& $Read) } else { $out[$Name] = & $Read } }
        catch { $out[$Name] = $null; $errors[$Name] = ($_.Exception.Message -split "`r?`n")[0] }
    }
    function Get-Iso($Date) { if ($Date) { ([datetime]$Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } }

    Read-Part 'os' {
        $os = Get-CimInstance Win32_OperatingSystem
        [ordered]@{ caption = $os.Caption; version = $os.Version; build = [int]$os.BuildNumber; last_boot = (Get-Iso $os.LastBootUpTime) }
    }
    Read-Part 'hotfixes' {
        $fixes = @(Get-HotFix | Where-Object { $_.InstalledOn })
        $last = $fixes | Sort-Object InstalledOn -Descending | Select-Object -First 1
        [ordered]@{ count = $fixes.Count; last = $(if ($last) { Get-Iso $last.InstalledOn }); last_id = $(if ($last) { $last.HotFixID }) }
    }
    Read-Part 'services' -List {
        @(Get-CimInstance Win32_Service | ForEach-Object { [ordered]@{ name = $_.Name; state = $_.State; start = $_.StartMode } })
    }
    Read-Part 'registry' {
        $values = [ordered]@{}
        foreach ($r in $wantedValues) {
            $item = Get-ItemProperty -LiteralPath $r[1] -Name $r[2] -ErrorAction SilentlyContinue
            $values[$r[0]] = $(if ($item) { $v = $item.($r[2]); if ($v -is [array]) { @($v | ForEach-Object { [string]$_ }) } else { $v } })
        }
        $values
    }
    Read-Part 'netbios' -List {
        @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' | ForEach-Object {
                $v = (Get-ItemProperty -LiteralPath $_.PSPath -Name NetbiosOptions -ErrorAction SilentlyContinue)
                if ($v) { [int]$v.NetbiosOptions } else { 0 }
            })
    }
    # Inbound allow rules for management ports (RDP, WinRM, SMB, RPC, SSH)
    # and the remote addresses they accept.
    Read-Part 'mgmtrules' -List {
        $ports = @{}
        foreach ($f in @(Get-NetFirewallPortFilter -All)) { $ports[$f.InstanceID] = $f }
        $addrs = @{}
        foreach ($f in @(Get-NetFirewallAddressFilter -All)) { $addrs[$f.InstanceID] = $f }
        @(Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow | ForEach-Object {
                $pf = $ports[$_.InstanceID]
                $local = @($(if ($pf) { $pf.LocalPort }) | ForEach-Object { [string]$_ })
                if ($local | Where-Object { $_ -in '3389', '5985', '5986', '445', '135', '22' }) {
                    [ordered]@{ name = [string]$_.DisplayName; ports = $local; profile = [string]$_.Profile
                        remote = @($(if ($addrs[$_.InstanceID]) { $addrs[$_.InstanceID].RemoteAddress }) | ForEach-Object { [string]$_ }) }
                }
            })
    }
    Read-Part 'firewall' -List {
        @(Get-NetFirewallProfile | ForEach-Object { [ordered]@{ name = [string]$_.Name; enabled = [string]$_.Enabled -eq 'True' } })
    }
    Read-Part 'features' -List { @(Get-WindowsFeature | Where-Object { $_.Installed } | ForEach-Object { $_.Name }) }
    Read-Part 'smb' {
        $c = Get-SmbServerConfiguration
        [ordered]@{ smb1 = [bool]$c.EnableSMB1Protocol; require_signing = [bool]$c.RequireSecuritySignature; audit_smb1 = [bool]$c.AuditSmb1Access }
    }
    Read-Part 'shares' -List { @(Get-SmbShare | ForEach-Object { $_.Name }) }
    Read-Part 'audit' {
        # auditpol's CSV report keys each subcategory by GUID, so this does not
        # depend on the display language.
        $map = [ordered]@{}
        foreach ($row in (& auditpol.exe /get /category:* /r | Where-Object { $_ } | ConvertFrom-Csv)) {
            $guid = [string]$row.'Subcategory GUID'
            if ($guid) { $map[$guid.Trim('{}').ToUpperInvariant()] = [string]$row.'Inclusion Setting' }
        }
        if ($map.Count -eq 0) { throw 'auditpol returned no subcategories.' }
        $map
    }
    Read-Part 'security_log' {
        $log = Get-WinEvent -ListLog Security
        [ordered]@{ max_bytes = [int64]$log.MaximumSizeInBytes; mode = [string]$log.LogMode; records = [int64]$log.RecordCount }
    }
    Read-Part 'disks' -List {
        @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
                [ordered]@{ drive = $_.DeviceID; size = [int64]$_.Size; free = [int64]$_.FreeSpace }
            })
    }
    Read-Part 'certificates' -List {
        @(Get-ChildItem Cert:\LocalMachine\My | ForEach-Object {
                $eku = @($_.EnhancedKeyUsageList | ForEach-Object { $_.ObjectId })
                [ordered]@{
                    subject = $_.Subject
                    dns = @($_.DnsNameList | ForEach-Object { [string]$_ })
                    not_after = (Get-Iso $_.NotAfter)
                    server_auth = ($eku.Count -eq 0 -or $eku -contains '1.3.6.1.5.5.7.3.1')
                }
            })
    }
    Read-Part 'credential_guard' -List {
        $dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard
        @($dg.SecurityServicesRunning | ForEach-Object { [int]$_ })
    }
    Read-Part 'software' -List {
        # Select-Object gives entries without a publisher or version an empty one.
        $keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        @(Get-ItemProperty -Path $keys -ErrorAction SilentlyContinue | Where-Object { $_.PSObject.Properties['DisplayName'] -and $_.DisplayName } |
            Select-Object DisplayName, Publisher, DisplayVersion |
            ForEach-Object { [ordered]@{ name = [string]$_.DisplayName; publisher = [string]$_.Publisher; version = [string]$_.DisplayVersion } })
    }
    # Cipher key names hold '/', which PowerShell registry paths cannot, so
    # these are read with the registry API. Enabled is only the stored value.
    Read-Part 'ciphers' {
        $lm = [Microsoft.Win32.Registry]::LocalMachine
        $enabled = [ordered]@{}
        $base = $lm.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers')
        if ($base) {
            foreach ($n in $base.GetSubKeyNames()) {
                $v = $base.OpenSubKey($n).GetValue('Enabled')
                if ($null -ne $v) { $enabled[$n] = [int64]$v }
            }
        }
        $suites = $lm.OpenSubKey('SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002')
        [ordered]@{ enabled = $enabled; suite_policy = $(if ($suites) { [string]$suites.GetValue('Functions') }) }
    }
    Read-Part 'hardware' {
        $cs = Get-CimInstance Win32_ComputerSystem
        $gen = Get-Service -Name vmgencounter -ErrorAction SilentlyContinue
        [ordered]@{
            manufacturer = [string]$cs.Manufacturer; model = [string]$cs.Model; hypervisor = [bool]$cs.HypervisorPresent
            vm_generation_id = $(if ($gen) { [string]$gen.Status -eq 'Running' } else { $false })
        }
    }
    Read-Part 'addresses' -List {
        @(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } | ForEach-Object { [string]$_.IPAddress })
    }
    Read-Part 'defender' {
        $st = Get-MpComputerStatus
        $p = Get-MpPreference
        [ordered]@{
            enabled = [bool]$st.AMServiceEnabled; realtime = [bool]$st.RealTimeProtectionEnabled; mode = [string]$st.AMRunningMode
            exclusions = @(@($p.ExclusionPath) + @($p.ExclusionProcess) + @($p.ExclusionExtension) | Where-Object { $_ } | ForEach-Object { [string]$_ })
        }
    }
    # Services that run as an account other than the built-in ones: the
    # account name only.
    Read-Part 'service_accounts' -List {
        @(Get-CimInstance Win32_Service | Where-Object { $_.StartName -and [string]$_.StartName -notmatch '^(LocalSystem|NT AUTHORITY\\|NT SERVICE\\|\.\\)' } |
            ForEach-Object { [ordered]@{ name = [string]$_.Name; display = [string]$_.DisplayName; account = [string]$_.StartName; state = [string]$_.State } })
    }
    # Whether each trusted domain's DCs can still be found in DNS.
    Read-Part 'trust_dns' -List {
        @(Get-ADTrust -Filter * | ForEach-Object {
                $t = [string]$_.Target
                $srv = Resolve-DnsName -Name "_ldap._tcp.dc._msdcs.$t" -Type SRV -DnsOnly -ErrorAction SilentlyContinue
                [ordered]@{ partner = $t; resolves = [bool]($srv | Where-Object { $_.Type -eq 'SRV' }) }
            })
    }
    # Identity servers: AD FS, Microsoft Entra Connect Sync, Cloud Sync and
    # pass-through authentication agents. Get- cmdlets of their own modules
    # only; certificates are public parts, never private keys.
    Read-Part 'identity' {
        $names = 'adfssrv', 'ADSync', 'AADConnectProvisioningAgent', 'AzureADConnectAuthenticationAgent'
        $svc = [ordered]@{}
        foreach ($s in @(Get-CimInstance Win32_Service | Where-Object { $names -contains $_.Name })) {
            $exe = ([string]$s.PathName).Trim('"').Split('"')[0].Trim()
            $version = $(try { [System.Diagnostics.FileVersionInfo]::GetVersionInfo($exe).FileVersion } catch { $null })
            $svc[$s.Name] = [ordered]@{ account = [string]$s.StartName; state = [string]$s.State; version = $version }
        }
        $o = [ordered]@{ services = $svc }
        if ($svc.Contains('adfssrv')) {
            $adfs = [ordered]@{}
            try {
                Import-Module ADFS -ErrorAction Stop
                $p = Get-AdfsProperties
                $adfs.properties = [ordered]@{
                    host = [string]$p.HostName; identifier = [string]$p.Identifier; lockout_enabled = [bool]$p.ExtranetLockoutEnabled
                    lockout_mode = [string]$p.ExtranetLockoutMode; lockout_threshold = [int]$p.ExtranetLockoutThreshold
                    audit_level = [string]$p.AuditLevel; log_level = @($p.LogLevel | ForEach-Object { [string]$_ })
                    auto_rollover = [bool]$p.AutoCertificateRollover
                }
                $adfs.farm_behavior = $(try { [int](Get-AdfsFarmInformation).CurrentFarmBehavior } catch { $null })
                $adfs.certificates = @(Get-AdfsCertificate | ForEach-Object {
                        $c = $_.Certificate
                        $key = $(try { [string]$c.PrivateKey.CspKeyContainerInfo.ProviderName } catch { '' })
                        [ordered]@{ type = [string]$_.CertificateType; primary = [bool]$_.IsPrimary; thumbprint = [string]$_.Thumbprint
                            not_before = (Get-Iso $c.NotBefore); not_after = (Get-Iso $c.NotAfter); provider = $key
                            raw = [Convert]::ToBase64String($c.RawData) }
                    })
                $adfs.endpoints = @(Get-AdfsEndpoint | Where-Object { $_.Enabled } | ForEach-Object { [ordered]@{ path = [string]$_.AddressPath; proxy = [bool]$_.Proxy } })
                $adfs.relying_parties = @(Get-AdfsRelyingPartyTrust | ForEach-Object {
                        [ordered]@{ name = [string]$_.Name; enabled = [bool]$_.Enabled; access_policy = [string]$_.AccessControlPolicyName
                            authorization = [string]$_.IssuanceAuthorizationRules; signature = [string]$_.SignatureAlgorithm; encrypt = [bool]$_.EncryptClaims }
                    })
            }
            catch { $adfs.error = ($_.Exception.Message -split "`r?`n")[0] }
            $o.adfs = $adfs
        }
        if ($svc.Contains('ADSync')) {
            $sync = [ordered]@{}
            try {
                Import-Module ADSync -ErrorAction Stop
                $sched = Get-ADSyncScheduler
                $sync.staging = [bool]$sched.StagingModeEnabled
                $sync.cycle_enabled = [bool]$sched.SyncCycleEnabled
                $features = [ordered]@{}
                $f = Get-ADSyncAADCompanyFeature
                foreach ($pp in $f.PSObject.Properties) { if ($pp.Value -is [bool]) { $features[$pp.Name] = $pp.Value } }
                $sync.features = $features
                $sync.writeback = @((Get-ADSyncGlobalSettings).Parameters | Where-Object { $_.Name -match 'writeback' } | ForEach-Object { [ordered]@{ name = [string]$_.Name; value = [string]$_.Value } })
                $sync.connectors = @(Get-ADSyncConnector | ForEach-Object { [ordered]@{ name = [string]$_.Name; type = [string]$_.ConnectorTypeName } })
            }
            catch { $sync.error = ($_.Exception.Message -split "`r?`n")[0] }
            $o.sync = $sync
        }
        $o
    }
    # Certificate Services, when this machine is a CA: the active CA's
    # flags, auditing, key storage provider, who holds CA roles, web
    # enrollment, and which templates it issued in the last 90 days.
    Read-Part 'certsvc' {
        if (-not (Get-Service -Name CertSvc -ErrorAction SilentlyContinue)) { return [ordered]@{ installed = $false } }
        $root = 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'
        $active = [string](Get-ItemProperty -LiteralPath $root -Name Active).Active
        $ca = Join-Path $root $active
        $p = Get-ItemProperty -LiteralPath $ca
        $policy = Get-ItemProperty -LiteralPath (Join-Path $ca 'PolicyModules\CertificateAuthority_MicrosoftDefault.Policy') -ErrorAction SilentlyContinue
        $csp = Get-ItemProperty -LiteralPath (Join-Path $ca 'CSP') -ErrorAction SilentlyContinue
        $aces = @()
        if ($p.PSObject.Properties['Security']) {
            $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor(([byte[]]$p.Security), 0)
            $aces = @(foreach ($a in $sd.DiscretionaryAcl) {
                    [ordered]@{ sid = [string]$a.SecurityIdentifier; mask = [int64]$a.AccessMask; allow = [string]$a.AceQualifier -eq 'AccessAllowed' }
                })
        }
        $web = [ordered]@{ installed = (Test-Path -LiteralPath (Join-Path $env:SystemRoot 'System32\CertSrv\en-US')) }
        if ($web.installed) {
            try {
                Import-Module WebAdministration -ErrorAction Stop
                $bindings = @(Get-WebBinding -Name 'Default Web Site')
                $web.http = [bool]($bindings | Where-Object { $_.protocol -eq 'http' })
                $web.https = [bool]($bindings | Where-Object { $_.protocol -eq 'https' })
                $web.epa = [string](Get-WebConfigurationProperty -PSPath 'IIS:\' -Location 'Default Web Site/CertSrv' -Filter 'system.webServer/security/authentication/windowsAuthentication/extendedProtection' -Name tokenChecking)
            }
            catch { $web.error = ($_.Exception.Message -split "`r?`n")[0] }
        }
        # Templates of certificates issued in the last 90 days, through the
        # CA's read-only view interface (ICertView).
        $issued = $null
        try {
            $view = New-Object -ComObject CertificateAuthority.View
            $view.OpenConnection("$env:COMPUTERNAME\$active")
            $view.SetRestriction($view.GetColumnIndex(0, 'Disposition'), 1, 0, 20)
            # CVR_SEEK_GE (8): issued on or after the date.
            $view.SetRestriction($view.GetColumnIndex(0, 'NotBefore'), 8, 0, [DateTime]::Now.AddDays(-90))
            $view.SetResultColumnCount(1)
            $view.SetResultColumn($view.GetColumnIndex(0, 'CertificateTemplate'))
            $rows = $view.OpenView()
            $seen = @{}
            $n = 0
            while ($rows.Next() -ne -1 -and $n -lt 100000) {
                $n++
                $cols = $rows.EnumCertViewColumn()
                if ($cols.Next() -ne -1) { $t = [string]$cols.GetValue(1); if ($t) { $seen[$t] = $true } }
            }
            $issued = @($seen.Keys | Sort-Object)
        }
        catch { $issued = $null }
        # Requests of the last 90 days that named another user: a SAN in the
        # request attributes, or an issued UPN. Only who asked, for whom,
        # with which template and when.
        $san = $null
        try {
            $view = New-Object -ComObject CertificateAuthority.View
            $view.OpenConnection("$env:COMPUTERNAME\$active")
            $view.SetRestriction($view.GetColumnIndex(0, 'Disposition'), 1, 0, 20)
            $view.SetRestriction($view.GetColumnIndex(0, 'NotBefore'), 8, 0, [DateTime]::Now.AddDays(-90))
            $names = @('Request.RequesterName', 'CertificateTemplate', 'Request.RequestAttributes', 'NotBefore')
            # Not every CA database has the issued UPN column.
            try { $null = $view.GetColumnIndex(0, 'UPN'); $names += 'UPN' } catch { $null = $_ }
            $view.SetResultColumnCount($names.Count)
            foreach ($n in $names) { $view.SetResultColumn($view.GetColumnIndex(0, $n)) }
            $rows = $view.OpenView()
            $san = New-Object System.Collections.Generic.List[object]
            while ($rows.Next() -ne -1 -and $san.Count -lt 1000) {
                $cols = $rows.EnumCertViewColumn()
                $v = @{}
                $i = 0
                while ($cols.Next() -ne -1) { $v[$names[$i]] = $cols.GetValue(1); $i++ }
                $attrs = [string]$v['Request.RequestAttributes']
                $target = $(if ($attrs -match '(?i)san:[^\r\n]*?upn=([^&\s]+)') { $Matches[1] } elseif ($v['UPN']) { [string]$v['UPN'] })
                $requester = [string]$v['Request.RequesterName']
                # A certificate for the requester's own name is the normal case.
                $self = $target -and (($target -split '@')[0] -eq ($requester -split '\\')[-1])
                if ($target -and -not ($self -and $attrs -notmatch '(?i)san:')) {
                    $san.Add([ordered]@{ requester = $requester; template = [string]$v['CertificateTemplate']
                            upn = $target; from_attributes = [bool]($attrs -match '(?i)san:'); issued = ([DateTime]$v['NotBefore']).ToUniversalTime().ToString('o') })
                }
            }
            $san = $san.ToArray()
        }
        catch { $san = $null }
        [ordered]@{
            installed = $true; name = $active; state = [string](Get-Service CertSvc).Status
            edit_flags = $(if ($policy) { [int64]$policy.EditFlags }); interface_flags = [int64]$p.InterfaceFlags
            audit_filter = $(if ($p.PSObject.Properties['AuditFilter']) { [int64]$p.AuditFilter } else { 0 })
            disabled_extensions = @($(if ($policy -and $policy.PSObject.Properties['DisableExtensionList']) { $policy.DisableExtensionList }) | Where-Object { $_ } | ForEach-Object { [string]$_ })
            provider = $(if ($csp) { [string]$csp.Provider })
            aces = $aces; web = $web; issued_templates = $issued; san_requests = $san
        }
    }
    # DNS server settings, when the DC runs DNS. Zone names, settings and
    # the targets of a few records; no zone contents are copied.
    Read-Part 'dns' {
        if (-not (Get-Service -Name DNS -ErrorAction SilentlyContinue)) { return [ordered]@{ installed = $false } }
        $domain = (Get-CimInstance Win32_ComputerSystem).Domain
        $zones = @(Get-DnsServerZone | Where-Object { -not $_.IsAutoCreated -and $_.ZoneName -ne 'TrustAnchors' })
        $records = @(foreach ($z in $zones | Where-Object { -not $_.IsReverseLookupZone -and $_.ZoneType -eq 'Primary' -and $_.ZoneName -notlike '_msdcs.*' }) {
                foreach ($name in '*', 'wpad', 'isatap') {
                    foreach ($r in @(Get-DnsServerResourceRecord -ZoneName $z.ZoneName -Name $name -ErrorAction SilentlyContinue)) {
                        [ordered]@{ zone = $z.ZoneName; name = $name; type = [string]$r.RecordType }
                    }
                }
            })
        $srv = @(Get-DnsServerResourceRecord -ZoneName "_msdcs.$domain" -Name '_ldap._tcp.dc' -RRType Srv -ErrorAction SilentlyContinue)
        if (-not $srv.Count) { $srv = @(Get-DnsServerResourceRecord -ZoneName $domain -Name '_ldap._tcp.dc._msdcs' -RRType Srv -ErrorAction SilentlyContinue) }
        $scavenging = Get-DnsServerScavenging
        $gqbl = Get-DnsServerGlobalQueryBlockList
        $audit = Get-WinEvent -ListLog 'Microsoft-Windows-DNSServer/Audit' -ErrorAction SilentlyContinue
        [ordered]@{
            installed = $true
            domain = $domain
            zones = @($zones | ForEach-Object {
                    $aging = Get-DnsServerZoneAging -Name $_.ZoneName -ErrorAction SilentlyContinue
                    [ordered]@{
                        name = $_.ZoneName; type = [string]$_.ZoneType; ds = [bool]$_.IsDsIntegrated; reverse = [bool]$_.IsReverseLookupZone
                        dynamic = [string]$_.DynamicUpdate; scope = [string]$_.ReplicationScope; transfer = [string]$_.SecureSecondaries
                        signed = [bool]$_.IsSigned; aging = $(if ($aging) { [bool]$aging.AgingEnabled })
                    }
                })
            records = $records
            dc_srv = @($srv | ForEach-Object { ([string]$_.RecordData.DomainName).TrimEnd('.') })
            recursion = [bool](Get-DnsServerRecursion).Enable
            forwarders = @((Get-DnsServerForwarder).IPAddress | ForEach-Object { [string]$_ })
            scavenging = [bool]$scavenging.ScavengingState
            scavenging_days = [int]$scavenging.ScavengingInterval.TotalDays
            block_list = [ordered]@{ enabled = [bool]$gqbl.Enable; names = @($gqbl.List | ForEach-Object { [string]$_ }) }
            audit_log = $(if ($audit) { [bool]$audit.IsEnabled })
            root_hints = @(Get-DnsServerRootHint -ErrorAction SilentlyContinue).Count
            own_a = @(Get-DnsServerResourceRecord -ZoneName $domain -Name $env:COMPUTERNAME -RRType A -ErrorAction SilentlyContinue | ForEach-Object { [string]$_.RecordData.IPv4Address })
        }
    }
    # Inbound replication from each partner, per partition.
    Read-Part 'replication' -List {
        @(Get-ADReplicationPartnerMetadata -Target $env:COMPUTERNAME -Scope Server -Partition * | ForEach-Object {
                [ordered]@{
                    partner = [string]$_.Partner; partition = [string]$_.Partition
                    last_success = (Get-Iso $_.LastReplicationSuccess); last_attempt = (Get-Iso $_.LastReplicationAttempt)
                    last_result = [int64]$_.LastReplicationResult; failures = [int]$_.ConsecutiveReplicationFailures
                }
            })
    }
    # State of the SYSVOL replicated folder in DFSR: 0 uninitialized,
    # 1 initialized, 2 initial sync, 3 auto recovery, 4 normal, 5 in error.
    Read-Part 'dfsr' -List {
        @(Get-CimInstance -Namespace root\microsoftdfs -ClassName DfsrReplicatedFolderInfo | ForEach-Object {
                [ordered]@{ folder = [string]$_.ReplicatedFolderName; group = [string]$_.ReplicationGroupName; state = [int]$_.State }
            })
    }
    # Clients that signed in from an address no site covers (NO_CLIENT_SITE
    # in netlogon.log): client name, address and how often, top 50.
    Read-Part 'no_client_site' -List {
        $log = Join-Path $env:SystemRoot 'debug\netlogon.log'
        if (-not [System.IO.File]::Exists($log)) { return @() }
        $seen = @{}
        foreach ($line in [System.IO.File]::ReadLines($log)) {
            if ($line -match 'NO_CLIENT_SITE:\s+(\S+)\s+(\S+)') {
                $key = $Matches[2]
                if (-not $seen.ContainsKey($key)) { $seen[$key] = [ordered]@{ client = $Matches[1]; ip = $key; times = 0 } }
                $seen[$key].times++
            }
        }
        @($seen.Values | Sort-Object { $_.times } -Descending | Select-Object -First 50)
    }
    $out['errors'] = $errors
    $out['now'] = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    ConvertTo-Json -InputObject $out -Depth 6 -Compress
}

function Export-DcConfig([string[]] $Dcs) {
    $area = 'dcconfig'
    Write-Event @{ type = 'start'; area = $area }
    $read = 0
    $firstError = $null
    try {
        $option = New-PSSessionOption -OpenTimeout 15000 -OperationTimeout 180000
        $writer = New-Object System.IO.StreamWriter((Join-Path $OutDir "$area.jsonl"), $false, $utf8)
        try {
            foreach ($dc in $Dcs) {
                $line = $null
                try {
                    $json = Invoke-Command -ComputerName $dc -SessionOption $option -ScriptBlock $dcConfigScript -ArgumentList (, $dcRegistry) -ErrorAction Stop
                    # The DC's clock is read at the end of the script, so the
                    # time the reply took to arrive is the only error here.
                    $local = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
                    $line = '{"name":' + (ConvertTo-Json $dc) + ',"read_at":"' + $local + '","data":' + [string]$json + '}'
                    $read++
                }
                catch {
                    $message = Get-FirstLine $_
                    if (-not $firstError) { $firstError = "${dc}: $message" }
                    $line = ConvertTo-Json -InputObject ([ordered]@{ name = $dc; error = $message }) -Compress
                }
                $writer.WriteLine($line)
                Write-Event @{ type = 'progress'; area = $area; read = $read }
            }
        }
        finally { $writer.Dispose() }
        if ($read -eq 0 -and $firstError) { Write-Event @{ type = 'error'; area = $area; message = "No domain controller could be read. $firstError" } }
        else { Write-Event @{ type = 'done'; area = $area; count = $read } }
    }
    catch {
        Write-Event @{ type = 'error'; area = $area; message = (Get-FirstLine $_) }
    }
}

# ---------- Workstations and member servers (endpoints) ----------

# The machines to read: -Endpoints when given, otherwise the enabled Windows
# member servers and workstations that signed in within the last 30 days,
# servers first (by name), then the most recently active workstations.
function Get-EndpointHost([int] $Servers, [int] $Workstations) {
    if ($Endpoints) { return @($Endpoints.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Sort-Object -Unique) }
    $since = [DateTime]::UtcNow.AddDays(-30).ToFileTimeUtc()
    $filter = '(&(objectCategory=computer)(operatingSystem=Windows*)(!(userAccountControl:1.2.840.113556.1.4.803:=2))' +
    '(!(userAccountControl:1.2.840.113556.1.4.803:=8192))(!(userAccountControl:1.2.840.113556.1.4.803:=67108864))' +
    "(lastLogonTimestamp>=$since))"
    $searcher = New-Object System.DirectoryServices.DirectorySearcher((Get-LdapEntry $domainNc), $filter, @('dnshostname', 'name', 'operatingsystem', 'lastlogontimestamp'))
    $searcher.PageSize = 1000
    $results = $searcher.FindAll()
    try {
        $all = @(foreach ($r in $results) {
                $p = $r.Properties
                [pscustomobject]@{
                    host = $(if ($p['dnshostname'].Count) { [string]$p['dnshostname'][0] } else { [string]$p['name'][0] })
                    server = ([string]$p['operatingsystem'][0]) -like '*Server*'
                    logon = $(if ($p['lastlogontimestamp'].Count) { [int64]$p['lastlogontimestamp'][0] } else { [int64]0 })
                }
            })
    }
    finally { $results.Dispose() }
    @($all | Where-Object { $_.server } | Sort-Object host | Select-Object -First $Servers | ForEach-Object { $_.host }) +
    @($all | Where-Object { -not $_.server } | Sort-Object logon -Descending | Select-Object -First $Workstations | ForEach-Object { $_.host })
}

# Registry values read on each endpoint: key in the output, path, value name.
# Winlogon DefaultPassword is never read; only whether it exists.
$epRegistry = @(
    @('lsa.runasppl', 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa', 'RunAsPPL'),
    @('lsa.lsacfgflags', 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa', 'LsaCfgFlags'),
    @('lsa.lmcompatibilitylevel', 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa', 'LmCompatibilityLevel'),
    @('lsa.nolmhash', 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa', 'NoLMHash'),
    @('lsa.restrictanonymous', 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa', 'RestrictAnonymous'),
    @('lsa.restrictanonymoussam', 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa', 'RestrictAnonymousSAM'),
    @('lsa.everyoneincludesanonymous', 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa', 'EveryoneIncludesAnonymous'),
    @('lsa.disablerestrictedadmin', 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa', 'DisableRestrictedAdmin'),
    @('msv1_0.restrictsendingntlmtraffic', 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0', 'RestrictSendingNTLMTraffic'),
    @('wdigest.uselogoncredential', 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest', 'UseLogonCredential'),
    @('winlogon.cachedlogonscount', 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon', 'CachedLogonsCount'),
    @('winlogon.autoadminlogon', 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon', 'AutoAdminLogon'),
    @('winlogon.defaultusername', 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon', 'DefaultUserName'),
    @('smbclient.requiresecuritysignature', 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters', 'RequireSecuritySignature'),
    @('dnsclient.enablemulticast', 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient', 'EnableMulticast'),
    @('winhttp.disablewpad', 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinHttp', 'DisableWpad'),
    @('rdp.fdenytsconnections', 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server', 'fDenyTSConnections'),
    @('rdp.userauthentication', 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp', 'UserAuthentication'),
    @('rdp.policyuserauthentication', 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services', 'UserAuthentication'),
    @('credssp.restrictedremoteadministration', 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation', 'RestrictedRemoteAdministration'),
    @('winrm.allowunencryptedtraffic', 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service', 'AllowUnencryptedTraffic'),
    @('winrm.allowbasic', 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service', 'AllowBasic'),
    @('powershell.enabletranscripting', 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription', 'EnableTranscripting'),
    @('powershell.enablescriptblocklogging', 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging', 'EnableScriptBlockLogging'),
    @('installer.alwaysinstallelevated', 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer', 'AlwaysInstallElevated'),
    @('uac.enablelua', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', 'EnableLUA'),
    @('uac.consentpromptbehavioradmin', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', 'ConsentPromptBehaviorAdmin'),
    @('uac.localaccounttokenfilterpolicy', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', 'LocalAccountTokenFilterPolicy'),
    @('uac.filteradministratortoken', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', 'FilterAdministratorToken'),
    @('laps.backupdirectory', 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS', 'BackupDirectory'),
    @('laps.policybackupdirectory', 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd', 'AdmPwdEnabled'),
    @('schannel.tls10.enabled', 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server', 'Enabled'),
    @('schannel.tls11.enabled', 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server', 'Enabled'),
    @('passportforwork.enabled', 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork', 'Enabled'),
    @('system.scforceoption', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', 'scforceoption')
)

# Runs on each endpoint. Reads only, and returns one JSON document; a part
# that fails keeps its error under "errors" and leaves the others intact.
$endpointScript = {
    param($Registry)
    $ErrorActionPreference = 'Stop'
    $wantedValues = $Registry
    $out = [ordered]@{}
    $errors = [ordered]@{}
    # -List keeps a list a list: PowerShell unrolls one item to a bare value
    # and no items to $null, which would read as a missing part.
    function Read-Part([string] $Name, [switch] $List, [scriptblock] $Read) {
        try { if ($List) { $out[$Name] = @(& $Read) } else { $out[$Name] = & $Read } }
        catch { $out[$Name] = $null; $errors[$Name] = ($_.Exception.Message -split "`r?`n")[0] }
    }
    function Get-Iso($Date) { if ($Date) { ([datetime]$Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } }
    # Broad groups that should never be able to change a file or folder.
    $broad = @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545', 'S-1-5-7')
    $domainSid = $null
    try { $domainSid = ((New-Object System.Security.Principal.NTAccount("$env:USERDOMAIN\Domain Users")).Translate([System.Security.Principal.SecurityIdentifier])).Value } catch { $domainSid = $null }
    if ($domainSid) { $broad += $domainSid }
    # True when a broad group may write to $Path (file or folder).
    function Test-BroadWrite([string] $Path) {
        if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $false }
        $acl = Get-Acl -LiteralPath $Path
        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            $sid = $null
            try { $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { continue }
            if ($broad -notcontains $sid) { continue }
            $r = [int]$ace.FileSystemRights
            # WriteData/CreateFiles 0x2, AppendData 0x4, WriteDAC 0x40000, WriteOwner 0x80000
            if ($r -band 0xC0006) { return $true }
        }
        $false
    }
    # The executable of a command line, unquoted.
    function Get-ExePath([string] $Command) {
        if (-not $Command) { return $null }
        $c = [Environment]::ExpandEnvironmentVariables($Command.Trim())
        if ($c.StartsWith('"')) { return $c.Substring(1, $c.IndexOf('"', 1) - 1) }
        if ($c -match '^(.+?\.exe)\b') { return $Matches[1] }
        ($c -split ' ')[0]
    }

    Read-Part 'os' {
        $os = Get-CimInstance Win32_OperatingSystem
        [ordered]@{ caption = $os.Caption; version = $os.Version; build = [int]$os.BuildNumber; product_type = [int]$os.ProductType; last_boot = (Get-Iso $os.LastBootUpTime) }
    }
    Read-Part 'hotfixes' {
        $fixes = @(Get-HotFix | Where-Object { $_.InstalledOn })
        $last = $fixes | Sort-Object InstalledOn -Descending | Select-Object -First 1
        [ordered]@{ count = $fixes.Count; last = $(if ($last) { Get-Iso $last.InstalledOn }); last_id = $(if ($last) { $last.HotFixID }) }
    }
    Read-Part 'services' -List {
        @(Get-CimInstance Win32_Service | ForEach-Object {
                $exe = Get-ExePath $_.PathName
                [ordered]@{
                    name = $_.Name; state = $_.State; start = $_.StartMode; account = [string]$_.StartName
                    unquoted = ([string]$_.PathName -notmatch '^\s*"' -and $exe -match ' ' -and [string]$_.PathName -notmatch '^\s*[A-Za-z]:\\Windows\\')
                    writable = (Test-BroadWrite $exe)
                }
            })
    }
    Read-Part 'registry' {
        $values = [ordered]@{}
        foreach ($r in $wantedValues) {
            $item = Get-ItemProperty -LiteralPath $r[1] -Name $r[2] -ErrorAction SilentlyContinue
            $values[$r[0]] = $(if ($item) { $v = $item.($r[2]); if ($v -is [array]) { @($v | ForEach-Object { [string]$_ }) } else { $v } })
        }
        $winlogon = Get-Item -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        $values['winlogon.defaultpassword_present'] = @($winlogon.GetValueNames()) -contains 'DefaultPassword'
        $values
    }
    Read-Part 'netbios' -List {
        @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' | ForEach-Object {
                $v = (Get-ItemProperty -LiteralPath $_.PSPath -Name NetbiosOptions -ErrorAction SilentlyContinue)
                if ($v) { [int]$v.NetbiosOptions } else { 0 }
            })
    }
    # Inbound allow rules for management ports (RDP, WinRM, SMB, RPC, SSH)
    # and the remote addresses they accept.
    Read-Part 'mgmtrules' -List {
        $ports = @{}
        foreach ($f in @(Get-NetFirewallPortFilter -All)) { $ports[$f.InstanceID] = $f }
        $addrs = @{}
        foreach ($f in @(Get-NetFirewallAddressFilter -All)) { $addrs[$f.InstanceID] = $f }
        @(Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow | ForEach-Object {
                $pf = $ports[$_.InstanceID]
                $local = @($(if ($pf) { $pf.LocalPort }) | ForEach-Object { [string]$_ })
                if ($local | Where-Object { $_ -in '3389', '5985', '5986', '445', '135', '22' }) {
                    [ordered]@{ name = [string]$_.DisplayName; ports = $local; profile = [string]$_.Profile
                        remote = @($(if ($addrs[$_.InstanceID]) { $addrs[$_.InstanceID].RemoteAddress }) | ForEach-Object { [string]$_ }) }
                }
            })
    }
    Read-Part 'firewall' -List {
        @(Get-NetFirewallProfile | ForEach-Object { [ordered]@{ name = [string]$_.Name; enabled = [string]$_.Enabled -eq 'True'; inbound = [string]$_.DefaultInboundAction } })
    }
    Read-Part 'smb' {
        $c = Get-SmbServerConfiguration
        $k = Get-SmbClientConfiguration
        [ordered]@{ smb1 = [bool]$c.EnableSMB1Protocol; require_signing = [bool]$c.RequireSecuritySignature; client_require_signing = [bool]$k.RequireSecuritySignature }
    }
    Read-Part 'shares' -List {
        $risky = @('Everyone', 'Authenticated Users', 'Users', 'Domain Users')
        @(Get-SmbShare | Where-Object { $_.Name -notmatch '\$$' } | ForEach-Object {
                $share = $_.Name
                $open = @(Get-SmbShareAccess -Name $share | Where-Object {
                        $_.AccessControlType -eq 'Allow' -and [string]$_.AccessRight -in 'Full', 'Change' -and ($risky -contains ([string]$_.AccountName).Split('\')[-1])
                    } | ForEach-Object { "$($_.AccountName): $($_.AccessRight)" })
                [ordered]@{ name = $share; path = [string]$_.Path; broad_write = $open }
            })
    }
    Read-Part 'local_admins' -List {
        @(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object {
                [ordered]@{ name = [string]$_.Name; sid = [string]$_.SID; class = [string]$_.ObjectClass; source = [string]$_.PrincipalSource }
            })
    }
    Read-Part 'local_users' -List {
        @(Get-LocalUser | ForEach-Object {
                [ordered]@{ name = $_.Name; sid = [string]$_.SID; enabled = [bool]$_.Enabled; password_last_set = (Get-Iso $_.PasswordLastSet) }
            })
    }
    Read-Part 'device_guard' {
        $dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard
        [ordered]@{
            vbs = [int]$dg.VirtualizationBasedSecurityStatus
            running = @($dg.SecurityServicesRunning | ForEach-Object { [int]$_ })
            ci_policy = [int]$dg.CodeIntegrityPolicyEnforcementStatus
            umci_policy = [int]$dg.UsermodeCodeIntegrityPolicyEnforcementStatus
        }
    }
    Read-Part 'bitlocker' {
        $v = Get-CimInstance -Namespace root\cimv2\Security\MicrosoftVolumeEncryption -ClassName Win32_EncryptableVolume -Filter "DriveLetter='$env:SystemDrive'"
        if (-not $v) { return [ordered]@{ protection = 0 } }
        [ordered]@{ protection = [int]$v.ProtectionStatus }
    }
    Read-Part 'secure_boot' { [bool](Confirm-SecureBootUEFI) }
    Read-Part 'tpm' {
        $t = Get-CimInstance -Namespace root\cimv2\Security\MicrosoftTpm -ClassName Win32_Tpm
        [ordered]@{ present = [bool]$t; enabled = $(if ($t) { [bool]$t.IsEnabled_InitialValue }) }
    }
    Read-Part 'defender' {
        $s = Get-MpComputerStatus
        $p = Get-MpPreference
        $asr = [ordered]@{}
        $ids = @($p.AttackSurfaceReductionRules_Ids)
        $actions = @($p.AttackSurfaceReductionRules_Actions)
        for ($i = 0; $i -lt $ids.Count; $i++) { if ($ids[$i]) { $asr[([string]$ids[$i]).ToLowerInvariant()] = [int]$actions[$i] } }
        [ordered]@{
            enabled = [bool]$s.AMServiceEnabled; realtime = [bool]$s.RealTimeProtectionEnabled; signature_age = [int]$s.AntivirusSignatureAge
            tamper = [bool]$s.IsTamperProtected
            exclusions = @(@($p.ExclusionPath) + @($p.ExclusionProcess) + @($p.ExclusionExtension) | Where-Object { $_ } | ForEach-Object { [string]$_ })
            asr = $asr
        }
    }
    Read-Part 'psv2' {
        $f = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction SilentlyContinue
        if ($f) { return [string]$f.State -eq 'Enabled' }
        # Neither knows the feature on Windows versions that removed PowerShell 2.0.
        $w = Get-WindowsFeature -Name PowerShell-V2 -ErrorAction SilentlyContinue
        [bool]($w -and $w.Installed)
    }
    Read-Part 'winrm_listeners' -List {
        @(Get-ChildItem WSMan:\localhost\Listener | ForEach-Object {
                $keys = @($_.Keys)
                [ordered]@{ transport = (($keys | Where-Object { $_ -like 'Transport=*' }) -replace '^Transport=', ''); address = (($keys | Where-Object { $_ -like 'Address=*' }) -replace '^Address=', '') }
            })
    }
    Read-Part 'applocker' -List {
        $xml = [xml](Get-AppLockerPolicy -Effective -Xml)
        @($xml.SelectNodes('/AppLockerPolicy/RuleCollection') | ForEach-Object { [ordered]@{ type = [string]$_.Type; mode = [string]$_.EnforcementMode; rules = @($_.ChildNodes).Count } })
    }
    Read-Part 'tasks' -List {
        @(Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' -and $_.Principal.UserId -and [string]$_.Principal.UserId -match '\\|@' -and [string]$_.Principal.UserId -notmatch '^(NT AUTHORITY|BUILTIN|NT SERVICE)\\' } |
            ForEach-Object { [ordered]@{ name = "$($_.TaskPath)$($_.TaskName)"; user = [string]$_.Principal.UserId; logon = [string]$_.Principal.LogonType } })
    }
    Read-Part 'autoruns' -List {
        $keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
        @(foreach ($k in $keys) {
                $item = Get-Item -LiteralPath $k -ErrorAction SilentlyContinue
                if (-not $item) { continue }
                foreach ($n in $item.GetValueNames()) {
                    $exe = Get-ExePath ([string]$item.GetValue($n))
                    if ($exe -and (Test-BroadWrite $exe)) { [ordered]@{ key = $k; name = $n; path = $exe } }
                }
            })
    }
    Read-Part 'path_writable' -List {
        $path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
        @($path.Split(';') | Where-Object { $_ } | ForEach-Object { [Environment]::ExpandEnvironmentVariables($_) } | Where-Object { Test-BroadWrite $_ })
    }
    Read-Part 'software' -List {
        # Select-Object gives entries without a publisher or version an empty one.
        $keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        @(Get-ItemProperty -Path $keys -ErrorAction SilentlyContinue | Where-Object { $_.PSObject.Properties['DisplayName'] -and $_.DisplayName } |
            Select-Object DisplayName, Publisher, DisplayVersion |
            ForEach-Object { [ordered]@{ name = [string]$_.DisplayName; publisher = [string]$_.Publisher; version = [string]$_.DisplayVersion } })
    }
    # How many saved Credential Manager entries each profile holds: the
    # number of credential files only, never their content.
    Read-Part 'credential_files' {
        $count = 0
        foreach ($p in @(Get-CimInstance Win32_UserProfile | Where-Object { -not $_.Special })) {
            foreach ($sub in 'AppData\Local\Microsoft\Credentials', 'AppData\Roaming\Microsoft\Credentials') {
                $dir = Join-Path $p.LocalPath $sub
                if (Test-Path -LiteralPath $dir) { $count += @(Get-ChildItem -LiteralPath $dir -File -Force -ErrorAction SilentlyContinue).Count }
            }
        }
        $count
    }
    # Certificate Services, when this machine is a CA: the active CA's
    # flags, auditing, key storage provider, who holds CA roles, web
    # enrollment, and which templates it issued in the last 90 days.
    Read-Part 'certsvc' {
        if (-not (Get-Service -Name CertSvc -ErrorAction SilentlyContinue)) { return [ordered]@{ installed = $false } }
        $root = 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'
        $active = [string](Get-ItemProperty -LiteralPath $root -Name Active).Active
        $ca = Join-Path $root $active
        $p = Get-ItemProperty -LiteralPath $ca
        $policy = Get-ItemProperty -LiteralPath (Join-Path $ca 'PolicyModules\CertificateAuthority_MicrosoftDefault.Policy') -ErrorAction SilentlyContinue
        $csp = Get-ItemProperty -LiteralPath (Join-Path $ca 'CSP') -ErrorAction SilentlyContinue
        $aces = @()
        if ($p.PSObject.Properties['Security']) {
            $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor(([byte[]]$p.Security), 0)
            $aces = @(foreach ($a in $sd.DiscretionaryAcl) {
                    [ordered]@{ sid = [string]$a.SecurityIdentifier; mask = [int64]$a.AccessMask; allow = [string]$a.AceQualifier -eq 'AccessAllowed' }
                })
        }
        $web = [ordered]@{ installed = (Test-Path -LiteralPath (Join-Path $env:SystemRoot 'System32\CertSrv\en-US')) }
        if ($web.installed) {
            try {
                Import-Module WebAdministration -ErrorAction Stop
                $bindings = @(Get-WebBinding -Name 'Default Web Site')
                $web.http = [bool]($bindings | Where-Object { $_.protocol -eq 'http' })
                $web.https = [bool]($bindings | Where-Object { $_.protocol -eq 'https' })
                $web.epa = [string](Get-WebConfigurationProperty -PSPath 'IIS:\' -Location 'Default Web Site/CertSrv' -Filter 'system.webServer/security/authentication/windowsAuthentication/extendedProtection' -Name tokenChecking)
            }
            catch { $web.error = ($_.Exception.Message -split "`r?`n")[0] }
        }
        # Templates of certificates issued in the last 90 days, through the
        # CA's read-only view interface (ICertView).
        $issued = $null
        try {
            $view = New-Object -ComObject CertificateAuthority.View
            $view.OpenConnection("$env:COMPUTERNAME\$active")
            $view.SetRestriction($view.GetColumnIndex(0, 'Disposition'), 1, 0, 20)
            # CVR_SEEK_GE (8): issued on or after the date.
            $view.SetRestriction($view.GetColumnIndex(0, 'NotBefore'), 8, 0, [DateTime]::Now.AddDays(-90))
            $view.SetResultColumnCount(1)
            $view.SetResultColumn($view.GetColumnIndex(0, 'CertificateTemplate'))
            $rows = $view.OpenView()
            $seen = @{}
            $n = 0
            while ($rows.Next() -ne -1 -and $n -lt 100000) {
                $n++
                $cols = $rows.EnumCertViewColumn()
                if ($cols.Next() -ne -1) { $t = [string]$cols.GetValue(1); if ($t) { $seen[$t] = $true } }
            }
            $issued = @($seen.Keys | Sort-Object)
        }
        catch { $issued = $null }
        # Requests of the last 90 days that named another user: a SAN in the
        # request attributes, or an issued UPN. Only who asked, for whom,
        # with which template and when.
        $san = $null
        try {
            $view = New-Object -ComObject CertificateAuthority.View
            $view.OpenConnection("$env:COMPUTERNAME\$active")
            $view.SetRestriction($view.GetColumnIndex(0, 'Disposition'), 1, 0, 20)
            $view.SetRestriction($view.GetColumnIndex(0, 'NotBefore'), 8, 0, [DateTime]::Now.AddDays(-90))
            $names = @('Request.RequesterName', 'CertificateTemplate', 'Request.RequestAttributes', 'NotBefore')
            # Not every CA database has the issued UPN column.
            try { $null = $view.GetColumnIndex(0, 'UPN'); $names += 'UPN' } catch { $null = $_ }
            $view.SetResultColumnCount($names.Count)
            foreach ($n in $names) { $view.SetResultColumn($view.GetColumnIndex(0, $n)) }
            $rows = $view.OpenView()
            $san = New-Object System.Collections.Generic.List[object]
            while ($rows.Next() -ne -1 -and $san.Count -lt 1000) {
                $cols = $rows.EnumCertViewColumn()
                $v = @{}
                $i = 0
                while ($cols.Next() -ne -1) { $v[$names[$i]] = $cols.GetValue(1); $i++ }
                $attrs = [string]$v['Request.RequestAttributes']
                $target = $(if ($attrs -match '(?i)san:[^\r\n]*?upn=([^&\s]+)') { $Matches[1] } elseif ($v['UPN']) { [string]$v['UPN'] })
                $requester = [string]$v['Request.RequesterName']
                # A certificate for the requester's own name is the normal case.
                $self = $target -and (($target -split '@')[0] -eq ($requester -split '\\')[-1])
                if ($target -and -not ($self -and $attrs -notmatch '(?i)san:')) {
                    $san.Add([ordered]@{ requester = $requester; template = [string]$v['CertificateTemplate']
                            upn = $target; from_attributes = [bool]($attrs -match '(?i)san:'); issued = ([DateTime]$v['NotBefore']).ToUniversalTime().ToString('o') })
                }
            }
            $san = $san.ToArray()
        }
        catch { $san = $null }
        [ordered]@{
            installed = $true; name = $active; state = [string](Get-Service CertSvc).Status
            edit_flags = $(if ($policy) { [int64]$policy.EditFlags }); interface_flags = [int64]$p.InterfaceFlags
            audit_filter = $(if ($p.PSObject.Properties['AuditFilter']) { [int64]$p.AuditFilter } else { 0 })
            disabled_extensions = @($(if ($policy -and $policy.PSObject.Properties['DisableExtensionList']) { $policy.DisableExtensionList }) | Where-Object { $_ } | ForEach-Object { [string]$_ })
            provider = $(if ($csp) { [string]$csp.Provider })
            aces = $aces; web = $web; issued_templates = $issued; san_requests = $san
        }
    }
    # Identity servers: AD FS, Microsoft Entra Connect Sync, Cloud Sync and
    # pass-through authentication agents. Get- cmdlets of their own modules
    # only; certificates are public parts, never private keys.
    Read-Part 'identity' {
        $names = 'adfssrv', 'ADSync', 'AADConnectProvisioningAgent', 'AzureADConnectAuthenticationAgent'
        $svc = [ordered]@{}
        foreach ($s in @(Get-CimInstance Win32_Service | Where-Object { $names -contains $_.Name })) {
            $exe = ([string]$s.PathName).Trim('"').Split('"')[0].Trim()
            $version = $(try { [System.Diagnostics.FileVersionInfo]::GetVersionInfo($exe).FileVersion } catch { $null })
            $svc[$s.Name] = [ordered]@{ account = [string]$s.StartName; state = [string]$s.State; version = $version }
        }
        $o = [ordered]@{ services = $svc }
        if ($svc.Contains('adfssrv')) {
            $adfs = [ordered]@{}
            try {
                Import-Module ADFS -ErrorAction Stop
                $p = Get-AdfsProperties
                $adfs.properties = [ordered]@{
                    host = [string]$p.HostName; identifier = [string]$p.Identifier; lockout_enabled = [bool]$p.ExtranetLockoutEnabled
                    lockout_mode = [string]$p.ExtranetLockoutMode; lockout_threshold = [int]$p.ExtranetLockoutThreshold
                    audit_level = [string]$p.AuditLevel; log_level = @($p.LogLevel | ForEach-Object { [string]$_ })
                    auto_rollover = [bool]$p.AutoCertificateRollover
                }
                $adfs.farm_behavior = $(try { [int](Get-AdfsFarmInformation).CurrentFarmBehavior } catch { $null })
                $adfs.certificates = @(Get-AdfsCertificate | ForEach-Object {
                        $c = $_.Certificate
                        $key = $(try { [string]$c.PrivateKey.CspKeyContainerInfo.ProviderName } catch { '' })
                        [ordered]@{ type = [string]$_.CertificateType; primary = [bool]$_.IsPrimary; thumbprint = [string]$_.Thumbprint
                            not_before = (Get-Iso $c.NotBefore); not_after = (Get-Iso $c.NotAfter); provider = $key
                            raw = [Convert]::ToBase64String($c.RawData) }
                    })
                $adfs.endpoints = @(Get-AdfsEndpoint | Where-Object { $_.Enabled } | ForEach-Object { [ordered]@{ path = [string]$_.AddressPath; proxy = [bool]$_.Proxy } })
                $adfs.relying_parties = @(Get-AdfsRelyingPartyTrust | ForEach-Object {
                        [ordered]@{ name = [string]$_.Name; enabled = [bool]$_.Enabled; access_policy = [string]$_.AccessControlPolicyName
                            authorization = [string]$_.IssuanceAuthorizationRules; signature = [string]$_.SignatureAlgorithm; encrypt = [bool]$_.EncryptClaims }
                    })
            }
            catch { $adfs.error = ($_.Exception.Message -split "`r?`n")[0] }
            $o.adfs = $adfs
        }
        if ($svc.Contains('ADSync')) {
            $sync = [ordered]@{}
            try {
                Import-Module ADSync -ErrorAction Stop
                $sched = Get-ADSyncScheduler
                $sync.staging = [bool]$sched.StagingModeEnabled
                $sync.cycle_enabled = [bool]$sched.SyncCycleEnabled
                $features = [ordered]@{}
                $f = Get-ADSyncAADCompanyFeature
                foreach ($pp in $f.PSObject.Properties) { if ($pp.Value -is [bool]) { $features[$pp.Name] = $pp.Value } }
                $sync.features = $features
                $sync.writeback = @((Get-ADSyncGlobalSettings).Parameters | Where-Object { $_.Name -match 'writeback' } | ForEach-Object { [ordered]@{ name = [string]$_.Name; value = [string]$_.Value } })
                $sync.connectors = @(Get-ADSyncConnector | ForEach-Object { [ordered]@{ name = [string]$_.Name; type = [string]$_.ConnectorTypeName } })
            }
            catch { $sync.error = ($_.Exception.Message -split "`r?`n")[0] }
            $o.sync = $sync
        }
        $o
    }
    Read-Part 'sessions' -List {
        @(Get-CimInstance Win32_LogonSession -Filter 'LogonType=2 or LogonType=10 or LogonType=11' | ForEach-Object {
                Get-CimAssociatedInstance -InputObject $_ -ResultClassName Win32_Account -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Domain)\$($_.Name)" }
            } | Sort-Object -Unique)
    }
    Read-Part 'audit' {
        $map = [ordered]@{}
        foreach ($row in (& auditpol.exe /get /category:* /r | Where-Object { $_ } | ConvertFrom-Csv)) {
            $guid = [string]$row.'Subcategory GUID'
            if ($guid) { $map[$guid.Trim('{}').ToUpperInvariant()] = [string]$row.'Inclusion Setting' }
        }
        if ($map.Count -eq 0) { throw 'auditpol returned no subcategories.' }
        $map
    }
    Read-Part 'security_log' {
        $log = Get-WinEvent -ListLog Security
        [ordered]@{ max_bytes = [int64]$log.MaximumSizeInBytes; mode = [string]$log.LogMode }
    }
    $out['errors'] = $errors
    $out['now'] = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    ConvertTo-Json -InputObject $out -Depth 6 -Compress
}

# Reads the endpoints 32 at a time in parallel. A machine that cannot be
# reached keeps its name and the error.
function Export-Endpoint([string[]] $Hosts) {
    $area = 'endpoints'
    Write-Event @{ type = 'start'; area = $area }
    $read = 0
    try {
        $option = New-PSSessionOption -OpenTimeout 15000 -OperationTimeout 180000
        $writer = New-Object System.IO.StreamWriter((Join-Path $OutDir "$area.jsonl"), $false, $utf8)
        try {
            for ($i = 0; $i -lt $Hosts.Count; $i += 32) {
                $batch = @($Hosts[$i..([Math]::Min($i + 31, $Hosts.Count - 1))])
                $remoteErrors = $null
                $replies = @(Invoke-Command -ComputerName $batch -SessionOption $option -ThrottleLimit 32 -ScriptBlock $endpointScript -ArgumentList (, $epRegistry) -ErrorAction SilentlyContinue -ErrorVariable remoteErrors)
                $local = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
                $answered = @{}
                foreach ($r in $replies) {
                    $name = [string]$r.PSComputerName
                    if ($answered.ContainsKey($name)) { continue }
                    $answered[$name] = $true
                    $writer.WriteLine('{"name":' + (ConvertTo-Json $name) + ',"read_at":"' + $local + '","data":' + [string]$r + '}')
                    $read++
                }
                foreach ($h in $batch | Where-Object { -not $answered.ContainsKey($_) }) {
                    $message = 'No reply over PowerShell remoting.'
                    foreach ($e in @($remoteErrors)) {
                        $target = if ($e.PSObject.Properties['OriginInfo'] -and $e.OriginInfo) { [string]$e.OriginInfo.PSComputerName } else { [string]$e.TargetObject }
                        if ($target -eq $h) { $message = Get-FirstLine $e; break }
                    }
                    $writer.WriteLine((ConvertTo-Json -InputObject ([ordered]@{ name = $h; error = $message }) -Compress))
                }
                Write-Event @{ type = 'progress'; area = $area; read = $read }
            }
        }
        finally { $writer.Dispose() }
        if ($read -eq 0 -and $Hosts.Count) { Write-Event @{ type = 'error'; area = $area; message = "None of the $($Hosts.Count) machines answered over PowerShell remoting." } }
        else { Write-Event @{ type = 'done'; area = $area; count = $read } }
    }
    catch { Write-Event @{ type = 'error'; area = $area; message = (Get-FirstLine $_) } }
}

# Counts matching events in one log of one DC, with the most frequent
# sources. Only the fields named by $Key are read; event messages are not
# copied.
function Get-EventSummary {
    param(
        [string] $Dc, [string] $Log, [string] $XPath, [scriptblock] $Key, [int] $Max = 5000, [int] $Top = 25
    )
    $summary = [ordered]@{ count = 0; capped = $false; first = $null; last = $null; top = @() }
    try {
        $events = @(Get-WinEvent -ComputerName $Dc -LogName $Log -FilterXPath $XPath -MaxEvents $Max -ErrorAction Stop)
    }
    catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { return $summary }
        return [ordered]@{ error = (Get-FirstLine $_) }
    }
    $summary.capped = $events.Count -ge $Max
    if ($Key) {
        # A key of $null drops the event: the XPath cannot express every filter.
        $keyed = @(foreach ($e in $events) {
                $k = & $Key $e
                if ($null -ne $k) { [pscustomobject]@{ key = [string]$k; time = $e.TimeCreated } }
            })
        $summary.count = $keyed.Count
        if ($keyed.Count -eq 0) { return $summary }
        $summary.first = $keyed[-1].time.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        $summary.last = $keyed[0].time.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        # Events arrive newest first, so each group's first event is its latest.
        $summary.top = @($keyed | Group-Object key | Sort-Object Count -Descending | Select-Object -First $Top |
            ForEach-Object { [ordered]@{ key = $_.Name; count = $_.Count; last = $_.Group[0].time.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } })
        return $summary
    }
    $summary.count = $events.Count
    $summary.first = $events[-1].TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $summary.last = $events[0].TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $summary
}

# The EventData fields of an event. An empty field has no text node and some
# events keep their fields in UserData instead, so nothing here assumes either.
function Get-EventDataNode($EventRecord) {
    $xml = [xml]$EventRecord.ToXml()
    @($xml.GetElementsByTagName('EventData') | ForEach-Object { $_.ChildNodes } | Where-Object { $_.LocalName -eq 'Data' })
}

function Get-EventField($EventRecord, [string] $Name) {
    foreach ($d in (Get-EventDataNode $EventRecord)) { if ($d.GetAttribute('Name') -eq $Name) { return $d.InnerText } }
    $null
}

# Every named EventData field of an event, read from its XML once.
function Get-EventData($EventRecord) {
    $fields = @{}
    foreach ($d in (Get-EventDataNode $EventRecord)) { $fields[$d.GetAttribute('Name')] = $d.InnerText }
    $fields
}

function Get-EventProperty($EventRecord, [int] $Index) {
    if ($EventRecord.Properties.Count -gt $Index) { [string]$EventRecord.Properties[$Index].Value }
}

# Reads one DC's event logs: legacy-protocol counts and threat hunting.
# Throws when the DC's Security log cannot be read at all.
function Read-DcEventLog([string] $Dc, [int] $Days) {
    $window = "TimeCreated[timediff(@SystemTime) <= $([int64]$Days * 86400000)]"
    $logon = { param($e) '{0}\{1} from {2}' -f (Get-EventField $e 'TargetDomainName'), (Get-EventField $e 'TargetUserName'), (Get-EventField $e 'IpAddress') }
    $client = { param($e) '{0} from {1}' -f (Get-EventProperty $e 1), ((Get-EventProperty $e 0) -replace ':\d+$', '') }
    $first = { param($e) Get-EventProperty $e 0 }
    $queries = [ordered]@{
        ntlmv1 = @('Security', "*[System[EventID=4624 and $window]] and *[EventData[Data[@Name='LmPackageName']='NTLM V1']]", $logon)
        lm = @('Security', "*[System[EventID=4624 and $window]] and *[EventData[Data[@Name='LmPackageName']='LM']]", $logon)
        rc4 = @('Security', "*[System[EventID=4769 and $window]] and *[EventData[Data[@Name='TicketEncryptionType']='0x17']]", { param($e) Get-EventField $e 'ServiceName' })
        ldap_unsigned_summary = @('Directory Service', "*[System[EventID=2887 and $window]]", $null)
        ldap_unsigned = @('Directory Service', "*[System[EventID=2889 and $window]]", $client)
        ldap_cbt = @('Directory Service', "*[System[EventID=3039 and $window]]", $client)
        netlogon = @('System', "*[System[Provider[@Name='NETLOGON'] and (EventID=5827 or EventID=5828 or EventID=5829) and $window]]", $first)
        kdc_cert = @('System', "*[System[Provider[@Name='Microsoft-Windows-Kerberos-Key-Distribution-Center' or @Name='Kdc'] and (EventID=39 or EventID=40 or EventID=41) and $window]]", $first)
        smb1 = @('Microsoft-Windows-SMBServer/Audit', "*[System[EventID=3000 and $window]]", $first)
        audit_ticket_ops = @('Security', "*[System[(EventID=4769 or EventID=4768) and $window]]", $null)
    }
    # Threat hunting. Keys join the fields a rule needs with '|'; account
    # names, hosts and object DNs only, never message text or command lines.
    $replication = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2|89e95b76-444d-4c62-991a-0facbeda640c'
    $ip = { param($v) $v -replace '^::ffff:', '' }
    $hunts = [ordered]@{
        hunt_dcsync = @('Security', "*[System[EventID=4662 and $window]] and *[EventData[Data[@Name='AccessMask']='0x100']]", {
                param($e) $d = Get-EventData $e
                if ($d.Properties -match $replication) { '{0}\{1}|{2}' -f $d.SubjectDomainName, $d.SubjectUserName, $d.SubjectUserSid }
            })
        hunt_kerberoast = @('Security', "*[System[EventID=4769 and $window]] and *[EventData[Data[@Name='TicketEncryptionType']='0x17' and Data[@Name='Status']='0x0']]", {
                param($e) $d = Get-EventData $e
                if ($d.ServiceName -notmatch '\$$' -and $d.ServiceName -ne 'krbtgt') { '{0}|{1}|{2}' -f $d.TargetUserName, $d.ServiceName, (& $ip $d.IpAddress) }
            })
        hunt_asrep = @('Security', "*[System[EventID=4768 and $window]] and *[EventData[Data[@Name='PreAuthType']='0' and Data[@Name='Status']='0x0']]", {
                param($e) $d = Get-EventData $e; '{0}|{1}' -f $d.TargetUserName, (& $ip $d.IpAddress)
            })
        hunt_failures = @('Security', "*[System[(EventID=4625 or EventID=4771) and $window]]", {
                param($e) $d = Get-EventData $e
                # 4771 0x18 is a wrong password; other codes are not guesses.
                if ($e.Id -eq 4625 -or $d.Status -eq '0x18') { '{0}|{1}' -f (& $ip $d.IpAddress), $d.TargetUserName }
            })
        hunt_lockouts = @('Security', "*[System[EventID=4740 and $window]]", {
                param($e) $d = Get-EventData $e; '{0}|{1}' -f $d.TargetUserName, $d.TargetDomainName
            })
        hunt_ntlm = @('Security', "*[System[EventID=4624 and $window]] and *[EventData[Data[@Name='LogonType']='3' and Data[@Name='AuthenticationPackageName']='NTLM']]", {
                param($e) $d = Get-EventData $e
                if ($d.TargetUserSid -ne 'S-1-5-7') { '{0}|{1}|{2}|{3}' -f $d.TargetUserSid, $d.TargetUserName, $d.WorkstationName, (& $ip $d.IpAddress) }
            })
        hunt_dsobjects = @('Security', "*[System[EventID=5137 and $window]] and *[EventData[Data[@Name='ObjectClass']='nTDSDSA']]", {
                param($e) $d = Get-EventData $e; '{0}\{1}|{2}' -f $d.SubjectDomainName, $d.SubjectUserName, $d.ObjectDN
            })
        hunt_dschanges = @('Security', "*[System[EventID=5136 and $window]] and *[EventData[Data[@Name='OperationType']='%%14674']]", {
                param($e) $d = Get-EventData $e
                $attr = $d.AttributeLDAPDisplayName
                $sensitive = ($attr -eq 'nTSecurityDescriptor' -and ($d.ObjectDN -like 'CN=AdminSDHolder,*' -or $d.ObjectDN -match '^DC=[^,]+(,DC=[^,]+)*$')) -or
                $attr -eq 'msDS-KeyCredentialLink' -or ($attr -eq 'servicePrincipalName' -and $d.ObjectClass -eq 'user')
                if ($sensitive) { '{0}|{1}|{2}\{3}|{4}' -f $attr, $d.ObjectDN, $d.SubjectDomainName, $d.SubjectUserName, $d.SubjectUserSid }
            })
        hunt_groupadds = @('Security', "*[System[(EventID=4728 or EventID=4732 or EventID=4756) and $window]]", {
                param($e) $d = Get-EventData $e
                '{0}|{1}|{2}|{3}|{4}\{5}' -f $d.TargetSid, $d.TargetUserName, $d.MemberSid, $d.MemberName, $d.SubjectDomainName, $d.SubjectUserName
            })
        hunt_services = @('System', "*[System[Provider[@Name='Service Control Manager'] and EventID=7045 and $window]]", {
                param($e) $d = Get-EventData $e
                # The program only: arguments can carry commands or secrets.
                $image = [string]$d.ImagePath
                $program = $(if ($image -match '^\s*"([^"]+)"') { $Matches[1] } else { ($image.Trim() -split '\s+')[0] })
                '{0}|{1}|{2}' -f $d.ServiceName, $program, $d.AccountName
            })
        # The DSRM administrator password was set (4794).
        hunt_dsrm = @('Security', "*[System[EventID=4794 and $window]]", {
                param($e) $d = Get-EventData $e; '{0}\{1}|{2}' -f $d.SubjectDomainName, $d.SubjectUserName, $d.Status
            })
        hunt_tasks = @('Security', "*[System[EventID=4698 and $window]]", {
                param($e) $d = Get-EventData $e; '{0}|{1}\{2}' -f $d.TaskName, $d.SubjectDomainName, $d.SubjectUserName
            })
        hunt_auditpolicy = @('Security', "*[System[EventID=4719 and $window]]", {
                param($e) $d = Get-EventData $e; '{0}\{1}|{2}' -f $d.SubjectDomainName, $d.SubjectUserName, $d.SubjectUserSid
            })
        hunt_clears = @('Security', "*[System[EventID=1102 and $window]]", {
                # 1102 keeps its fields in UserData: SubjectUserSid, SubjectUserName, SubjectDomainName.
                param($e) '{0}\{1}' -f (Get-EventProperty $e 2), (Get-EventProperty $e 1)
            })
        hunt_sidhistory = @('Security', "*[System[(EventID=4765 or EventID=4766) and $window]]", {
                param($e) $d = Get-EventData $e
                '{0}|{1}|{2}|{3}\{4}' -f $e.Id, $d.TargetUserName, $d.SidList, $d.SubjectDomainName, $d.SubjectUserName
            })
        # Tickets for an account domain written in lower case: real tickets
        # carry the realm in upper case, forging tools often do not.
        hunt_golden = @('Security', "*[System[EventID=4769 and $window]] and *[EventData[Data[@Name='Status']='0x0']]", {
                param($e) $d = Get-EventData $e
                if ([string]$d.TargetDomainName -cmatch '[a-z]') { '{0}|{1}|{2}' -f $d.TargetDomainName, $d.TargetUserName, (& $ip $d.IpAddress) }
            })
        hunt_pac = @('System', "*[System[Provider[@Name='Microsoft-Windows-Kerberos-Key-Distribution-Center' or @Name='Kdc'] and (EventID=35 or EventID=36 or EventID=37 or EventID=38) and $window]]", {
                param($e) '{0}|{1}' -f $e.Id, (Get-EventProperty $e 0)
            })
        hunt_gpochanges = @('Security', "*[System[EventID=5136 and $window]] and *[EventData[Data[@Name='ObjectClass']='groupPolicyContainer']]", {
                param($e) $d = Get-EventData $e
                $t = $e.TimeCreated.ToUniversalTime()
                '{0}|{1}|{2}|{3}\{4}' -f $t.Hour, [int]$t.DayOfWeek, $d.ObjectDN, $d.SubjectDomainName, $d.SubjectUserName
            })
        hunt_ntds = @('Security', "*[System[EventID=4688 and $window]]", {
                param($e) $d = Get-EventData $e
                if ([string]$d.NewProcessName -match '\\(ntdsutil|vssadmin|esentutl|diskshadow|wbadmin)\.exe$') { '{0}|{1}\{2}' -f ([string]$d.NewProcessName).Split('\')[-1], $d.SubjectDomainName, $d.SubjectUserName }
            })
        hunt_lsass = @('Microsoft-Windows-Sysmon/Operational', "*[System[EventID=10 and $window]]", {
                param($e) $d = Get-EventData $e
                if ([string]$d.TargetImage -match '\\lsass\.exe$') { [string]$d.SourceImage }
            })
        hunt_ticketuse = @('Security', "*[System[EventID=4769 and $window]] and *[EventData[Data[@Name='Status']='0x0']]", {
                param($e) $d = Get-EventData $e
                if ([string]$d.ServiceName -match '\$$') { '{0}|{1}' -f (([string]$d.TargetUserName) -replace '@.*$', ''), $d.ServiceName }
            })
        hunt_computerchanges = @('Security', "*[System[EventID=4742 and $window]]", {
                param($e) $d = Get-EventData $e; '{0}|{1}\{2}' -f $d.TargetUserName, $d.SubjectDomainName, $d.SubjectUserName
            })
        # 2889: the third field is the bind type, 1 for a simple bind.
        ldap_simple = @('Directory Service', "*[System[EventID=2889 and $window]]", {
                param($e) if ([string](Get-EventProperty $e 2) -eq '1') { & $client $e }
            })
        hunt_coercion = @('Security', "*[System[EventID=5145 and $window]] and *[EventData[Data[@Name='ShareName']='\\\\*\\IPC$' and (Data[@Name='RelativeTargetName']='efsrpc' or Data[@Name='RelativeTargetName']='spoolss' or Data[@Name='RelativeTargetName']='netdfs')]]", {
                param($e) $d = Get-EventData $e
                '{0}|{1}|{2}\{3}' -f $d.RelativeTargetName, (& $ip $d.IpAddress), $d.SubjectDomainName, $d.SubjectUserName
            })
    }
    $record = [ordered]@{ name = $Dc; days = $Days }
    # One cheap read first, so an unreachable DC fails once
    # instead of once per query.
    $oldest = Get-WinEvent -ComputerName $Dc -LogName Security -MaxEvents 1 -Oldest -ErrorAction Stop
    $record.security_oldest = $oldest.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $results = [ordered]@{}
    foreach ($name in $queries.Keys) {
        $q = $queries[$name]
        $max = $(if ($name -eq 'audit_ticket_ops') { 1 } else { 5000 })
        $results[$name] = Get-EventSummary -Dc $Dc -Log $q[0] -XPath $q[1] -Key $q[2] -Max $max
    }
    foreach ($name in $hunts.Keys) {
        $q = $hunts[$name]
        $results[$name] = Get-EventSummary -Dc $Dc -Log $q[0] -XPath $q[1] -Key $q[2] -Max 5000 -Top 500
    }
    $results.ldap_unsigned_summary.binds = 0
    if (-not $results.ldap_unsigned_summary.Contains('error') -and $results.ldap_unsigned_summary.count) {
        # 2887 is a daily summary: simple binds without TLS, then unsigned SASL binds.
        $binds = 0
        foreach ($e in @(Get-WinEvent -ComputerName $Dc -LogName 'Directory Service' -FilterXPath $queries.ldap_unsigned_summary[1] -MaxEvents 400 -ErrorAction SilentlyContinue)) {
            $binds += [int64](Get-EventProperty $e 0) + [int64](Get-EventProperty $e 1)
        }
        $results.ldap_unsigned_summary.binds = $binds
    }
    $record.queries = $results
    $clear = Get-EventSummary -Dc $Dc -Log 'Security' -XPath '*[System[EventID=1102]]' -Key $null -Max 1
    $record.last_clear = $(if ($clear.Contains('last')) { $clear.last })
    $record
}

function Export-DcEvent([string[]] $Dcs, [int] $Days) {
    $area = 'dcevents'
    Write-Event @{ type = 'start'; area = $area }
    $read = 0
    $firstError = $null
    try {
        $writer = New-Object System.IO.StreamWriter((Join-Path $OutDir "$area.jsonl"), $false, $utf8)
        try {
            foreach ($dc in $Dcs) {
                try {
                    $record = Read-DcEventLog -Dc $dc -Days $Days
                    $read++
                }
                catch {
                    $message = Get-FirstLine $_
                    if (-not $firstError) { $firstError = "${dc}: $message" }
                    $record = [ordered]@{ name = $dc; days = $Days; error = $message }
                }
                $writer.WriteLine((ConvertTo-Json -InputObject $record -Compress -Depth 6))
                Write-Event @{ type = 'progress'; area = $area; read = $read }
            }
        }
        finally { $writer.Dispose() }
        if ($read -eq 0 -and $firstError) { Write-Event @{ type = 'error'; area = $area; message = "No domain controller's logs could be read. $firstError" } }
        else { Write-Event @{ type = 'done'; area = $area; count = $read } }
    }
    catch {
        Write-Event @{ type = 'error'; area = $area; message = (Get-FirstLine $_) }
    }
}

if (-not (Test-Path -LiteralPath $OutDir)) { $null = New-Item -ItemType Directory -Path $OutDir }
if ($Bundle) {
    # Standalone run: keep the progress log the app would otherwise keep.
    $script:eventLog = Join-Path $OutDir 'events.jsonl'
    [System.IO.File]::WriteAllText($script:eventLog, '', $utf8)
}
$wanted = @($Sources -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$startedAt = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')

try {
    $target = if ($Server) { $Server } else { $Domain }
    $dseNames = @('defaultNamingContext', 'configurationNamingContext', 'schemaNamingContext', 'rootDomainNamingContext',
        'dnsHostName', 'serverName', 'domainFunctionality', 'forestFunctionality', 'domainControllerFunctionality')
    $dse = [ordered]@{}
    $script:useProtocols = $null -ne $Credential -or [Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT
    if ($script:useProtocols) {
        $script:ldapHost = $target
        $entry = @(Find-ProtocolsEntry -Base '' -Filter '(objectClass=*)' -Attributes $dseNames -Scope 'Base' -Raw)[0]
        foreach ($name in $dseNames) {
            $key = $name.ToLowerInvariant()
            $dse[$key] = if ($entry.Contains($key)) { [string]$entry[$key][0] } else { '' }
        }
        $script:schemaNc = $dse['schemanamingcontext']
        $script:server = $dse['dnshostname']
    }
    else {
        $rootDse = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$target/RootDSE")
        $script:server = [string]$rootDse.Properties['dnsHostName'].Value
        foreach ($name in $dseNames) {
            $dse[$name.ToLowerInvariant()] = [string]$rootDse.Properties[$name].Value
        }
    }
}
catch {
    Write-Event @{ type = 'error'; area = 'rootdse'; message = (Get-FirstLine $_) }
    exit 1
}

$domainNc = $dse['defaultnamingcontext']
$configNc = $dse['configurationnamingcontext']
$schemaNc = $dse['schemanamingcontext']

$info = [ordered]@{
    domain = $Domain
    server = $script:server
    account = $(if ($Credential) { $Credential.UserName }
        elseif ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name }
        else { [Environment]::UserName })
    computer = [Environment]::MachineName
    started_at = $startedAt
    sources = $wanted
    rootdse = $dse
}
[System.IO.File]::WriteAllText((Join-Path $OutDir 'collection.json'), (ConvertTo-Json -InputObject $info -Depth 4), $utf8)

if ($wanted -contains 'ldap') {
    $principal = @('distinguishedname', 'name', 'samaccountname', 'objectsid', 'sidhistory', 'useraccountcontrol', 'pwdlastset',
        'lastlogontimestamp', 'accountexpires', 'admincount', 'serviceprincipalname', 'msds-allowedtodelegateto',
        'msds-supportedencryptiontypes', 'primarygroupid', 'memberof', 'whencreated', 'description')

    Export-LdapObject -Area 'domain' -Base $domainNc -Scope 'Base' -Filter '(objectClass=*)' -Attributes @(
        'distinguishedname', 'name', 'objectsid', 'msds-behavior-version', 'ms-ds-machineaccountquota', 'minpwdlength',
        'pwdhistorylength', 'pwdproperties', 'maxpwdage', 'minpwdage', 'lockoutthreshold', 'lockoutduration',
        'lockoutobservationwindow', 'gplink', 'gpoptions', 'whencreated', 'fsmoroleowner', 'msds-replattributemetadata',
        'wellknownobjects', 'msds-expirepasswordsonsmartcardonlyaccounts')
    Export-LdapObject -Area 'partitions' -Base "CN=Partitions,$configNc" -Filter '(|(objectClass=crossRefContainer)(objectClass=crossRef))' -Attributes @(
        'distinguishedname', 'objectclass', 'msds-behavior-version', 'msds-enabledfeature', 'ncname', 'dnsroot', 'netbiosname',
        'enabled', 'systemflags', 'msds-nc-replica-locations', 'upnsuffixes', 'fsmoroleowner', 'whencreated')
    Export-LdapObject -Area 'dirservice' -Base "CN=Directory Service,CN=Windows NT,CN=Services,$configNc" -Scope 'Base' -Filter '(objectClass=*)' -Attributes @(
        'distinguishedname', 'tombstonelifetime', 'msds-deletedobjectlifetime', 'dsheuristics')
    # Every attribute and class definition: names, flags and dates, to find
    # LAPS and BitLocker attributes, custom secret-like attributes and
    # recent schema changes.
    Export-LdapObject -Area 'schema' -Base $schemaNc -Filter '(|(objectClass=dMD)(objectClass=attributeSchema)(objectClass=classSchema))' -Attributes @(
        'distinguishedname', 'objectclass', 'objectversion', 'ldapdisplayname', 'schemaidguid', 'searchflags', 'systemflags',
        'whencreated', 'whenchanged', 'fsmoroleowner')
    Export-LdapObject -Area 'users' -Base $domainNc -Filter '(&(objectCategory=person)(objectClass=user))' -Attributes @(
        $principal + @('userprincipalname', 'displayname', 'mail', 'altsecurityidentities', 'manager',
            'msds-allowedtoactonbehalfofotheridentity', 'msds-assignedauthnpolicysilo', 'msds-assignedauthnpolicy',
            'logonhours', 'userworkstations', 'proxyaddresses', 'msexchmailboxguid'))
    Export-LdapObject -Area 'computers' -Base $domainNc -Filter '(objectCategory=computer)' -Attributes @(
        $principal + @('dnshostname', 'operatingsystem', 'operatingsystemversion', 'msds-allowedtoactonbehalfofotheridentity',
            'ms-mcs-admpwdexpirationtime', 'mslaps-passwordexpirationtime', 'ms-ds-creatorsid', 'msds-revealondemandgroup',
            'msds-neverrevealgroup', 'msds-revealedusers'))
    Export-LdapObject -Area 'groups' -Base $domainNc -Filter '(objectClass=group)' -Attributes @(
        'distinguishedname', 'name', 'samaccountname', 'objectsid', 'sidhistory', 'grouptype', 'member', 'admincount',
        'description', 'managedby', 'whencreated')
    Export-LdapObject -Area 'containers' -Base $domainNc -Filter '(|(objectClass=organizationalUnit)(objectClass=container)(objectClass=builtinDomain))' -Attributes @(
        'distinguishedname', 'name', 'objectclass', 'gplink', 'gpoptions', 'whencreated')
    Export-LdapObject -Area 'gpos' -Base "CN=Policies,CN=System,$domainNc" -Scope 'OneLevel' -Filter '(objectClass=groupPolicyContainer)' -Attributes @(
        'distinguishedname', 'name', 'displayname', 'gpcfilesyspath', 'flags', 'versionnumber', 'whencreated', 'whenchanged',
        'gpcwqlfilter')
    Export-LdapObject -Area 'trusts' -Base "CN=System,$domainNc" -Filter '(objectClass=trustedDomain)' -Attributes @(
        'distinguishedname', 'name', 'trustpartner', 'flatname', 'trustdirection', 'trusttype', 'trustattributes',
        'securityidentifier', 'msds-supportedencryptiontypes', 'whencreated', 'whenchanged')
    # Security descriptors (owner and DACL, never the SACL) of the objects that
    # matter for privilege paths: the domain head, AdminSDHolder, protected
    # accounts and groups, all groups, OUs, GPOs and domain controllers.
    Export-LdapObject -Area 'acls' -Base $domainNc -SecurityDescriptor -Filter '(|(objectClass=domainDNS)(adminCount=1)(objectClass=group)(objectClass=organizationalUnit)(objectClass=groupPolicyContainer)(cn=AdminSDHolder)(cn=Password Settings Container)(userAccountControl:1.2.840.113556.1.4.803:=8192))' -Attributes @(
        'distinguishedname', 'objectclass', 'ntsecuritydescriptor', 'whenchanged')
    # Operations master role objects (RID master, infrastructure master).
    # The PDC emulator is on the domain head, the schema master on the
    # schema head and the domain naming master on CN=Partitions.
    Export-LdapObject -Area 'roles' -Base $domainNc -Filter '(&(fsmoRoleOwner=*)(|(objectClass=rIDManager)(objectClass=infrastructureUpdate)))' -Attributes @(
        'distinguishedname', 'objectclass', 'fsmoroleowner')
    # The forest's LDAP query policy (MaxPageSize, MaxQueryDuration...).
    Export-LdapObject -Area 'querypolicy' -Base "CN=Query-Policies,CN=Directory Service,CN=Windows NT,CN=Services,$configNc" -Scope 'OneLevel' -Filter '(objectClass=queryPolicy)' -Attributes @(
        'distinguishedname', 'name', 'ldapadminlimits', 'whenchanged')
    # Who holds rights on the configuration and schema partitions.
    Export-LdapObject -Area 'ncheads' -Base $configNc -SecurityDescriptor -Filter '(|(objectClass=configuration)(objectClass=dMD))' -Attributes @(
        'distinguishedname', 'objectclass', 'ntsecuritydescriptor')
    # Context menu entries added to display specifiers (a persistence spot).
    Export-LdapObject -Area 'dispspec' -Base "CN=DisplaySpecifiers,$configNc" -Filter '(&(objectClass=displaySpecifier)(|(adminContextMenu=*)(shellContextMenu=*)))' -Attributes @(
        'distinguishedname', 'admincontextmenu', 'shellcontextmenu', 'whencreated', 'whenchanged')
    # Extended rights defined in the forest, with when they were added.
    Export-LdapObject -Area 'extrights' -Base "CN=Extended-Rights,$configNc" -Scope 'OneLevel' -Filter '(objectClass=controlAccessRight)' -Attributes @(
        'distinguishedname', 'name', 'displayname', 'rightsguid', 'validaccesses', 'whencreated')
    # Replication metadata: when each member of a protected group was added
    # or removed, and when SPNs and key credentials of user accounts last
    # changed. Not every directory returns these constructed attributes.
    Export-LdapObject -Area 'privmeta' -Base $domainNc -Filter '(&(objectClass=group)(adminCount=1))' -Attributes @(
        'distinguishedname', 'msds-replvaluemetadata')
    Export-LdapObject -Area 'attrmeta' -Base $domainNc -Filter '(&(objectCategory=person)(|(servicePrincipalName=*)(msDS-KeyCredentialLink=*)))' -Attributes @(
        'distinguishedname', 'samaccountname', 'whencreated', 'msds-replattributemetadata')
    # WMI filters (their queries) and software installation packages that
    # GPOs deploy (the MSI paths).
    Export-LdapObject -Area 'wmifilters' -Base "CN=System,$domainNc" -Filter '(objectClass=msWMI-Som)' -Attributes @(
        'distinguishedname', 'mswmi-name', 'mswmi-id', 'mswmi-parm2', 'whenchanged')
    Export-LdapObject -Area 'gpsoftware' -Base "CN=Policies,CN=System,$domainNc" -Filter '(objectClass=packageRegistration)' -Attributes @(
        'distinguishedname', 'displayname', 'msifilelist', 'whenchanged')
    # The owner of every computer object (owner only, to keep it small).
    Export-LdapObject -Area 'computerowners' -Base $domainNc -SecurityDescriptor -Masks 'Owner' -Filter '(objectClass=computer)' -Attributes @(
        'distinguishedname', 'samaccountname', 'ntsecuritydescriptor')
    # Audit entries (SACL) of the objects whose changes must be audited.
    # Reading a SACL needs the "Manage auditing and security log" right;
    # without it the directory returns no descriptor and the check says so.
    Export-LdapObject -Area 'sacls' -Base $domainNc -SecurityDescriptor -Masks 'Sacl' -Filter '(|(objectClass=domainDNS)(cn=AdminSDHolder)(&(objectClass=group)(adminCount=1)))' -Attributes @(
        'distinguishedname', 'ntsecuritydescriptor')
    # Exchange servers in the forest, with their versions.
    Export-LdapObject -Area 'exchservers' -Base "CN=Services,$configNc" -Filter '(objectClass=msExchExchangeServer)' -Attributes @(
        'distinguishedname', 'name', 'serialnumber', 'msexchcurrentserverroles', 'networkaddress', 'whencreated')
    # Service connection points, which applications publish under their servers.
    Export-LdapObject -Area 'scps' -Base $domainNc -Filter '(objectClass=serviceConnectionPoint)' -Attributes @(
        'distinguishedname', 'name', 'keywords', 'servicednsname', 'serviceclassname', 'whenchanged')
    # Configuration Manager: the System Management container (who controls
    # it) and the sites and management points published in it.
    # Searched from CN=System, since most domains have no such container.
    Export-LdapObject -Area 'sccm' -Base "CN=System,$domainNc" -SecurityDescriptor -Filter '(|(&(objectClass=container)(cn=System Management))(objectClass=mSSMSSite)(objectClass=mSSMSManagementPoint))' -Attributes @(
        'distinguishedname', 'objectclass', 'name', 'mssmssitecode', 'mssmsmpname', 'dnshostname', 'ntsecuritydescriptor', 'whenchanged')
    # Fine-grained password policies. Reading them needs delegated rights, so
    # a standard account usually sees none.
    Export-LdapObject -Area 'psos' -Base "CN=Password Settings Container,CN=System,$domainNc" -Filter '(objectClass=msDS-PasswordSettings)' -Attributes @(
        'distinguishedname', 'name', 'whencreated', 'msds-passwordsettingsprecedence', 'msds-minimumpasswordlength',
        'msds-passwordhistorylength', 'msds-passwordcomplexityenabled', 'msds-passwordreversibleencryptionenabled',
        'msds-maximumpasswordage', 'msds-minimumpasswordage', 'msds-lockoutthreshold', 'msds-lockoutduration',
        'msds-lockoutobservationwindow', 'msds-psoappliesto')
    # Accounts with a value in a password attribute that LDAP can return.
    # Only which accounts have one is recorded; the attribute itself is not
    # requested.
    Export-LdapObject -Area 'pwdattrs' -Base $domainNc -Filter '(|(userPassword=*)(unixUserPassword=*)(msSFU30Password=*)(os400Password=*))' -Attributes @(
        'distinguishedname', 'samaccountname', 'objectclass')
    # Accounts with key credentials (Windows Hello for Business or Shadow
    # Credentials). Only which accounts have them is recorded.
    Export-LdapObject -Area 'keycreds' -Base $domainNc -Filter '(msDS-KeyCredentialLink=*)' -Attributes @(
        'distinguishedname', 'samaccountname', 'objectclass')
    # BitLocker recovery objects under computers: where they are and when
    # they were made. The recovery password is never requested.
    Export-LdapObject -Area 'bitlocker' -Base $domainNc -Filter '(objectClass=msFVE-RecoveryInformation)' -Attributes @(
        'distinguishedname', 'whencreated')
    # Managed service accounts (standalone, group and delegated) and who may
    # retrieve their passwords. The managed password itself
    # (msDS-ManagedPassword) is never requested.
    Export-LdapObject -Area 'msas' -Base $domainNc -Filter '(|(objectClass=msDS-GroupManagedServiceAccount)(objectClass=msDS-ManagedServiceAccount)(objectClass=msDS-DelegatedManagedServiceAccount))' -Attributes @(
        $principal + @('objectclass', 'dnshostname', 'msds-groupmsamembership', 'msds-managedpasswordinterval',
            'msds-hostserviceaccountbl', 'msds-managedaccountprecededbylink', 'msds-delegatedmsastate'))
    # KDS root keys for gMSA passwords: when they were made and who can read
    # them. The key material (msKds-RootKeyData) is never requested.
    Export-LdapObject -Area 'kds' -Base "CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,$configNc" -SecurityDescriptor -Filter '(objectClass=msKds-ProvRootKey)' -Attributes @(
        'distinguishedname', 'name', 'whencreated', 'mskds-usestarttime', 'mskds-version', 'ntsecuritydescriptor')
        # Sites, the servers in them and their directory service agents
    # (nTDSDSA), site settings, subnets, site links and bridges.
    Export-LdapObject -Area 'sites' -Base "CN=Sites,$configNc" -Filter '(|(objectClass=site)(objectClass=server)(objectClass=nTDSDSA)(objectClass=nTDSSiteSettings)(objectClass=subnet)(objectClass=siteLink)(objectClass=siteLinkBridge)(objectClass=interSiteTransport))' -Attributes @(
        'distinguishedname', 'name', 'objectclass', 'dnshostname', 'serverreference', 'whencreated', 'options', 'siteobject',
        'cost', 'replinterval', 'sitelist', 'sitelinklist', 'intersitetopologygenerator')
    # Kerberos authentication policies and silos.
    Export-LdapObject -Area 'authn' -Base "CN=AuthN Policy Configuration,CN=Services,$configNc" -Filter '(|(objectClass=msDS-AuthNPolicy)(objectClass=msDS-AuthNPolicySilo))' -Attributes @(
        'distinguishedname', 'name', 'objectclass', 'whencreated', 'msds-authnpolicyenforced', 'msds-authnpolicysiloenforced',
        'msds-authnpolicysilomembers', 'msds-userauthnpolicy', 'msds-computerauthnpolicy', 'msds-serviceauthnpolicy',
        'msds-usertgtlifetime')
    # DNS zones stored in AD and who can change them. Records are not read.
    $rootNc = $dse['rootdomainnamingcontext']
    Export-LdapObject -Area 'dnszones' -Base "CN=MicrosoftDNS,DC=DomainDnsZones,$domainNc" -SecurityDescriptor -Filter '(objectClass=dnsZone)' -Attributes @(
        'distinguishedname', 'name', 'whencreated', 'ntsecuritydescriptor')
    Export-LdapObject -Area 'dnsforestzones' -Base "CN=MicrosoftDNS,DC=ForestDnsZones,$rootNc" -SecurityDescriptor -Filter '(objectClass=dnsZone)' -Attributes @(
        'distinguishedname', 'name', 'whencreated', 'ntsecuritydescriptor')
    # Active Directory Certificate Services as published in the forest:
    # certificate templates, enterprise CAs, the NTAuth store, AIA and CDP
    # containers, and issuance policies linked to groups, with their
    # security descriptors. Certificates are public; no private key exists
    # in the directory.
    Export-LdapObject -Area 'pki' -Base "CN=Public Key Services,CN=Services,$configNc" -SecurityDescriptor -Filter '(|(objectClass=pKICertificateTemplate)(objectClass=pKIEnrollmentService)(objectClass=certificationAuthority)(objectClass=container)(&(objectClass=msPKI-Enterprise-Oid)(msDS-OIDToGroupLink=*)))' -Attributes @(
        'distinguishedname', 'name', 'objectclass', 'displayname', 'ntsecuritydescriptor', 'flags', 'whencreated',
        'mspki-certificate-name-flag', 'mspki-enrollment-flag', 'mspki-ra-signature', 'mspki-template-schema-version',
        'pkiextendedkeyusage', 'mspki-certificate-application-policy', 'mspki-certificate-policy', 'pkiexpirationperiod',
        'certificatetemplates', 'dnshostname', 'cacertificate', 'msds-oidtogrouplink', 'mspki-cert-template-oid')
}

if ($wanted -contains 'sysvol') { Export-SysvolPolicy; Export-ScriptScan }

if ($wanted -contains 'dc-remote' -or $wanted -contains 'dc-events') {
    $dcs = @()
    try { $dcs = @(Get-DomainControllerHost) }
    catch {
        $message = 'Could not list the domain controllers: ' + (Get-FirstLine $_)
        foreach ($area in @(if ($wanted -contains 'dc-remote') { 'dcconfig' }) + @(if ($wanted -contains 'dc-events') { 'dcevents' })) {
            Write-Event @{ type = 'error'; area = $area; message = $message }
        }
    }
    if ($dcs.Count) {
        if ($wanted -contains 'dc-remote') { Export-DcConfig $dcs }
        if ($wanted -contains 'dc-events') { Export-DcEvent $dcs $EventDays }
    }
}

if ($wanted -contains 'endpoints') {
    $targets = @()
    try { $targets = @(Get-EndpointHost -Servers $EndpointServers -Workstations $EndpointWorkstations) }
    catch { Write-Event @{ type = 'error'; area = 'endpoints'; message = ('Could not list the machines to read: ' + (Get-FirstLine $_)) } }
    if ($targets.Count) { Export-Endpoint $targets }
    elseif (-not $Endpoints) { Write-Event @{ type = 'done'; area = 'endpoints'; count = 0 } }
}

Write-Event @{ type = 'finished'; finished_at = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ') }

if ($Bundle) {
    $script:eventLog = $null
    Compress-Archive -Path (Join-Path $OutDir '*') -DestinationPath $Bundle -Force
    [Console]::Out.WriteLine((ConvertTo-Json -InputObject @{ type = 'bundle'; path = $Bundle } -Compress))
}
