<#
.SYNOPSIS
    Unit tests for the helper functions inside collectors/Invoke-DCACollect.ps1:
    Read-Part (how a part's value or error is recorded), the event field
    readers and Get-EventSummary (counting, grouping and error handling).

    The functions are taken from the collector itself, unchanged, and run
    under the same strict mode. Get-WinEvent is replaced by a stand-in that
    returns events built from Microsoft's documented event XML, so nothing
    is read from this machine. Exits non-zero when a test fails.

.EXAMPLE
    powershell -NoProfile -File tools\Test-CollectorHelpers.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

$collector = Join-Path $PSScriptRoot '..\collectors\Invoke-DCACollect.ps1'
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $collector), [ref] $null, [ref] $parseErrors)
if ($parseErrors) { throw "The collector does not parse: $($parseErrors[0].Message)" }

# Top-level helpers, and the first Read-Part (the one in the DC script block;
# the endpoint script block defines the same function).
$wanted = @('Export-SysvolPolicy', 'Read-SecurityTemplate', 'Read-RegistryPolicy', 'Read-ScriptList', 'Read-Preference',
    'Read-FolderAcl', 'Get-SysvolPath', 'Get-RelativePath', 'Test-SecretName', 'ConvertTo-SidString', 'Get-FirstLine', 'Get-EventSummary', 'Get-EventDataNode', 'Get-EventField', 'Get-EventData', 'Get-EventProperty')
$all = $ast.FindAll({ param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
foreach ($fn in $all) { if ($wanted -contains $fn.Name -and $fn.Parent -eq $ast.EndBlock) { . ([scriptblock]::Create($fn.Extent.Text)) } }
$readParts = @($all | Where-Object { $_.Name -eq 'Read-Part' })
if ($readParts.Count -ne 2) { throw "Expected Read-Part in the DC and endpoint script blocks, found $($readParts.Count)." }
if ($readParts[0].Extent.Text -ne $readParts[1].Extent.Text) { throw 'The two Read-Part definitions differ.' }
. ([scriptblock]::Create($readParts[0].Extent.Text))
foreach ($n in $wanted) { if (-not (Get-Command $n -CommandType Function -ErrorAction SilentlyContinue)) { throw "Invoke-DCACollect.ps1 no longer defines $n." } }

$script:failed = 0
$script:passed = 0
function Assert-Equal($Actual, $Expected, [string] $Name) {
    $a = ConvertTo-Json -InputObject $Actual -Compress -Depth 6
    $e = ConvertTo-Json -InputObject $Expected -Compress -Depth 6
    if ($a -ceq $e) { $script:passed++ }
    else { $script:failed++; Write-Output "FAIL  $Name`n      expected $e`n      got      $a" }
}

# ---------- ConvertTo-SidString ----------

# Built by hand from the binary SID layout, and checked against Windows'
# own SecurityIdentifier where that class exists.
$sidText = 'S-1-5-21-3712516640-209636377-1972864782-500'
$sidParts = [byte[]](1, 5, 0, 0, 0, 0, 0, 5) + [BitConverter]::GetBytes([uint32]21) + [BitConverter]::GetBytes([uint32]3712516640) +
[BitConverter]::GetBytes([uint32]209636377) + [BitConverter]::GetBytes([uint32]1972864782) + [BitConverter]::GetBytes([uint32]500)
# Joining arrays gives object[] in Windows PowerShell 5.1; make it bytes again.
$sidBytes = [byte[]]$sidParts
Assert-Equal (ConvertTo-SidString $sidBytes) $sidText 'ConvertTo-SidString reads a domain account SID'
Assert-Equal (ConvertTo-SidString ([byte[]](1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0))) 'S-1-5-32-544' 'ConvertTo-SidString reads a built-in SID'
Assert-Equal (ConvertTo-SidString ([byte[]](1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0))) 'S-1-1-0' 'ConvertTo-SidString reads Everyone'
if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
    Assert-Equal (ConvertTo-SidString $sidBytes) (New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)).Value 'ConvertTo-SidString matches SecurityIdentifier'
}

# ---------- Read-Part ----------

$out = [ordered]@{}
$errors = [ordered]@{}
Read-Part 'one' -List { @([ordered]@{ a = 1 }) }
Read-Part 'none' -List { @() }
Read-Part 'many' -List { 1, 2 }
Read-Part 'scalar' { 42 }
Read-Part 'object' { [ordered]@{ on = $true } }
Read-Part 'broken' { throw "Access is denied.`r`nSecond line" }
$json = ConvertTo-Json -InputObject $out -Compress -Depth 4 | ConvertFrom-Json
Assert-Equal @($json.one).Count 1 'Read-Part -List keeps one item a list'
Assert-Equal ((ConvertTo-Json -InputObject $out -Compress -Depth 4) -match '"one":\[') $true 'Read-Part -List writes one item as a JSON array'
Assert-Equal ((ConvertTo-Json -InputObject $out -Compress -Depth 4) -match '"none":\[\]') $true 'Read-Part -List writes no items as []'
Assert-Equal $out.many @(1, 2) 'Read-Part -List keeps several items'
Assert-Equal $out.scalar 42 'Read-Part keeps a single value'
Assert-Equal $out.object.on $true 'Read-Part keeps an object'
Assert-Equal $out.Contains('broken') $true 'Read-Part records a failed part'
Assert-Equal $out.broken $null 'A failed part is null'
Assert-Equal $errors.broken 'Access is denied.' 'A failed part keeps the first line of its error'
Assert-Equal @($errors.Keys) @('broken') 'Only failed parts have errors'

# ---------- Event fields ----------

# Builds an event record the way Get-WinEvent returns it: ToXml(), Id,
# TimeCreated and Properties.
function New-TestEvent([int] $Id, [datetime] $Time, [string] $Body, [object[]] $Properties = @()) {
    $xml = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>$Id</EventID></System>$Body</Event>"
    $e = [pscustomobject]@{ Id = $Id; TimeCreated = $Time; Properties = @($Properties | ForEach-Object { [pscustomobject]@{ Value = $_ } }) }
    $e | Add-Member -MemberType ScriptMethod -Name ToXml -Value ([scriptblock]::Create("'$($xml -replace "'", "''")'"))
    $e
}

# 4769, with an empty field (no text node), as Windows writes it.
$tgs = New-TestEvent 4769 ([datetime]'2026-10-01T10:00:00Z') @"
<EventData><Data Name='TargetUserName'>jdoe@CORP.EXAMPLE.COM</Data><Data Name='ServiceName'>svc-sql</Data><Data Name='TicketEncryptionType'>0x17</Data><Data Name='IpAddress'>::ffff:10.0.0.5</Data><Data Name='TransmittedServices'></Data><Data Name='TransmittedServices2' /></EventData>
"@
Assert-Equal (Get-EventField $tgs 'ServiceName') 'svc-sql' 'Get-EventField reads a named field'
Assert-Equal (Get-EventField $tgs 'TransmittedServices') '' 'Get-EventField reads an empty field as empty text'
Assert-Equal (Get-EventField $tgs 'TransmittedServices2') '' 'Get-EventField reads a self-closed field as empty text'
Assert-Equal (Get-EventField $tgs 'NotThere') $null 'Get-EventField returns null for a missing field'
$d = Get-EventData $tgs
Assert-Equal $d.TicketEncryptionType '0x17' 'Get-EventData reads every field'
Assert-Equal $d.TransmittedServices '' 'Get-EventData reads an empty field as empty text'
Assert-Equal $d.Count 6 'Get-EventData reads all six fields'

# 1102 keeps its fields in UserData, not EventData.
$clear = New-TestEvent 1102 ([datetime]'2026-10-02T08:00:00Z') @"
<UserData><LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'><SubjectUserSid>S-1-5-21-1-2-3-500</SubjectUserSid><SubjectUserName>Administrator</SubjectUserName><SubjectDomainName>CORP</SubjectDomainName></LogFileCleared></UserData>
"@ @('S-1-5-21-1-2-3-500', 'Administrator', 'CORP')
Assert-Equal (Get-EventData $clear).Count 0 'Get-EventData finds no fields in a UserData event'
Assert-Equal (Get-EventField $clear 'SubjectUserName') $null 'Get-EventField returns null on a UserData event'
Assert-Equal (Get-EventProperty $clear 1) 'Administrator' 'Get-EventProperty reads by position'
Assert-Equal (Get-EventProperty $clear 9) $null 'Get-EventProperty returns null past the end'

# ---------- Get-EventSummary ----------

# The stand-in Get-WinEvent: newest first, like the real one.
$script:events = @()
$script:failWith = $null
function Get-WinEvent {
    [CmdletBinding()]
    param($ComputerName, $LogName, $FilterXPath, $MaxEvents, [switch] $Oldest)
    if ($script:failWith) {
        $ex = New-Object System.Exception $script:failWith.message
        $rec = New-Object System.Management.Automation.ErrorRecord $ex, $script:failWith.id, 'ObjectNotFound', $null
        $PSCmdlet.ThrowTerminatingError($rec)
    }
    @($script:events | Select-Object -First $MaxEvents)
}

$t = [datetime]'2026-10-05T12:00:00Z'
$script:events = @(
    (New-TestEvent 4769 $t.AddHours(-1) "<EventData><Data Name='ServiceName'>svc-sql</Data></EventData>"),
    (New-TestEvent 4769 $t.AddHours(-2) "<EventData><Data Name='ServiceName'>svc-web</Data></EventData>"),
    (New-TestEvent 4769 $t.AddHours(-3) "<EventData><Data Name='ServiceName'>svc-sql</Data></EventData>"),
    (New-TestEvent 4769 $t.AddHours(-4) "<EventData><Data Name='ServiceName'>krbtgt</Data></EventData>")
)
$key = { param($e) $s = Get-EventField $e 'ServiceName'; if ($s -ne 'krbtgt') { $s } }
$sum = Get-EventSummary -Dc 'dc01' -Log 'Security' -XPath '*' -Key $key
Assert-Equal $sum.count 3 'Get-EventSummary counts events the key keeps'
Assert-Equal $sum.capped $false 'Get-EventSummary is not capped under the maximum'
Assert-Equal $sum.first '2026-10-05T09:00:00Z' 'first is the oldest kept event'
Assert-Equal $sum.last '2026-10-05T11:00:00Z' 'last is the newest kept event'
Assert-Equal @($sum.top | ForEach-Object { $_.key }) @('svc-sql', 'svc-web') 'top is grouped and ordered by count'
Assert-Equal @($sum.top)[0].count 2 'top counts each key'
Assert-Equal @($sum.top)[0].last '2026-10-05T11:00:00Z' 'top keeps each key''s latest time'

$capped = Get-EventSummary -Dc 'dc01' -Log 'Security' -XPath '*' -Key $null -Max 2
Assert-Equal $capped.count 2 'Get-EventSummary without a key counts every event read'
Assert-Equal $capped.capped $true 'Get-EventSummary reports reaching the maximum'

$script:events = @((New-TestEvent 4769 $t "<EventData><Data Name='ServiceName'>krbtgt</Data></EventData>"))
$none = Get-EventSummary -Dc 'dc01' -Log 'Security' -XPath '*' -Key $key
Assert-Equal $none.count 0 'Get-EventSummary with every event dropped counts none'
Assert-Equal $none.Contains('error') $false 'Dropped events are not an error'

$script:failWith = @{ id = 'NoMatchingEventsFound,Microsoft.PowerShell.Commands.GetWinEventCommand'; message = 'No events were found that match the specified selection criteria.' }
$empty = Get-EventSummary -Dc 'dc01' -Log 'Security' -XPath '*' -Key $key
Assert-Equal $empty.count 0 'No matching events is a count of zero'
Assert-Equal $empty.Contains('error') $false 'No matching events is not an error'

$script:failWith = @{ id = 'NoMatchingLogsFound,Microsoft.PowerShell.Commands.GetWinEventCommand'; message = 'There is not an event log on the dc01 computer that matches "Directory Service".' }
$missing = Get-EventSummary -Dc 'dc01' -Log 'Directory Service' -XPath '*' -Key $null
Assert-Equal $missing.error 'There is not an event log on the dc01 computer that matches "Directory Service".' 'A missing log is reported as an error'
$script:failWith = $null

# ---------- Export-SysvolPolicy ----------

# A policy folder written the way the Group Policy editor writes one, read
# end to end by the collector's SYSVOL reader through -SysvolPath.
foreach ($a in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Parent -eq $ast.EndBlock }, $false)) {
    if ($a.Left.Extent.Text -in '$secretName', '$passwordSetting', '$utf8') { . ([scriptblock]::Create($a.Extent.Text)) }
}
$script:onWindows = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
$script:sysvolEvents = New-Object System.Collections.Generic.List[object]
function Write-Event([hashtable] $Data) { $script:sysvolEvents.Add($Data) }

function New-RegistryPol($Entries) {
    $u = [System.Text.Encoding]::Unicode
    $b = New-Object System.Collections.Generic.List[byte]
    $b.AddRange([System.Text.Encoding]::ASCII.GetBytes('PReg'))
    $b.AddRange([BitConverter]::GetBytes([uint32]1))
    foreach ($e in $Entries) {
        $b.AddRange($u.GetBytes('[' + $e.key + [char]0 + ';' + $e.value + [char]0 + ';'))
        $b.AddRange([BitConverter]::GetBytes([uint32]$e.type))
        $b.AddRange($u.GetBytes(';'))
        $data = if ($e.type -eq 4) { [BitConverter]::GetBytes([uint32]$e.data) } else { $u.GetBytes($e.data + [char]0) }
        $b.AddRange([BitConverter]::GetBytes([uint32]$data.Length))
        $b.AddRange($u.GetBytes(';'))
        $b.AddRange([byte[]]$data)
        $b.AddRange($u.GetBytes(']'))
    }
    , $b.ToArray()
}

$SysvolPath = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
$OutDir = Join-Path $SysvolPath 'out'
$Domain = 'corp.example.com'
$script:sysvolRoot = $SysvolPath
$gpo = Join-Path (Join-Path $SysvolPath 'Policies') '{6AC1786C-016F-11D2-945F-00C04FB984F9}'
$secEdit = Join-Path (Join-Path (Join-Path (Join-Path $gpo 'Machine') 'Microsoft') 'Windows NT') 'SecEdit'
$auditDir = Join-Path (Split-Path $secEdit) 'Audit'
$null = New-Item -ItemType Directory -Force -Path $secEdit, $auditDir, $OutDir
[System.IO.File]::WriteAllText((Join-Path $gpo 'GPT.INI'), "[General]`r`nVersion=3`r`n")
[System.IO.File]::WriteAllText((Join-Path $secEdit 'GptTmpl.inf'),
    "[Unicode]`r`nUnicode=yes`r`n[Privilege Rights]`r`nSeNetworkLogonRight = *S-1-5-11,*S-1-5-32-544`r`n", [System.Text.Encoding]::Unicode)
[System.IO.File]::WriteAllText((Join-Path $auditDir 'audit.csv'),
    "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value`r`n,System,Audit Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success and Failure,,3`r`n")
[System.IO.File]::WriteAllBytes((Join-Path (Join-Path $gpo 'Machine') 'Registry.pol'), (New-RegistryPol @(
            @{ key = 'Software\Policies\Microsoft\WindowsFirewall\DomainProfile'; value = 'EnableFirewall'; type = 4; data = 1 },
            @{ key = 'Software\Policies\Microsoft\Windows\System'; value = 'UserPolicyMode'; type = 4; data = 2 })))
try {
    Export-SysvolPolicy
    foreach ($e in $script:sysvolEvents) { if ($e.type -eq 'error') { Write-Output "Export-SysvolPolicy: $($e.message)" } }
    $record = Get-Content (Join-Path $OutDir 'sysvol.jsonl') | ConvertFrom-Json
    Assert-Equal @($script:sysvolEvents | Where-Object { $_.type -eq 'done' }).Count 1 'Export-SysvolPolicy finishes the area'
    Assert-Equal $record.folder '{6AC1786C-016F-11D2-945F-00C04FB984F9}' 'Export-SysvolPolicy names the policy folder'
    Assert-Equal $record.errors.PSObject.Properties['registry'] $null 'Registry.pol is read without an error'
    Assert-Equal @($record.registry).Count 2 'Every Registry.pol setting is kept'
    Assert-Equal @($record.registry)[1].value 'UserPolicyMode' 'Registry.pol value names are read'
    Assert-Equal @($record.registry)[1].data 2 'Registry.pol DWORD data is read'
    Assert-Equal @($record.registry)[0].scope 'Machine' 'Registry.pol settings carry their scope'
    Assert-Equal @($record.inf.'Privilege Rights'.SeNetworkLogonRight) @('*S-1-5-11', '*S-1-5-32-544') 'GptTmpl.inf (UTF-16) is read'
    Assert-Equal @($record.audit).Count 1 'audit.csv rows with a subcategory are read'
    Assert-Equal @($record.audit)[0].guid '0cce9215-69ae-11d9-bed3-505054503030' 'audit.csv GUIDs are kept without braces, in lower case'
    Assert-Equal @($record.audit)[0].value 3 'audit.csv setting values are numbers'
    Assert-Equal ($record.files -contains 'Machine\Registry.pol') $true 'File paths use backslashes'
}
finally { Remove-Item -Recurse -Force $SysvolPath }

# ---------- Find-Credential (Invoke-DCAEntra.ps1) ----------

$entra = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path (Join-Path $PSScriptRoot '..\collectors\Invoke-DCAEntra.ps1')), [ref] $null, [ref] $parseErrors)
if ($parseErrors) { throw "Invoke-DCAEntra.ps1 does not parse: $($parseErrors[0].Message)" }
$pattern = $entra.Find({ param($a) $a -is [System.Management.Automation.Language.AssignmentStatementAst] -and $a.Left.Extent.Text -eq '$credentialPatterns' }, $false)
. ([scriptblock]::Create($pattern.Extent.Text))
$find = $entra.Find({ param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $a.Name -eq 'Find-Credential' }, $false)
. ([scriptblock]::Create($find.Extent.Text))
$runbook = "param()`n`$user = 'svc'`n`$cred = ConvertTo-SecureString 'Hunter2!' -AsPlainText -Force`nWrite-Output done`n`$conn = 'AccountKey=abc'"
$hits = Find-Credential $runbook
Assert-Equal @($hits).Count 2 'Credentials in runbook text are found'
Assert-Equal @($hits)[0].line 3 'The line of a match is recorded'
Assert-Equal @($hits)[0].keyword 'plain-text SecureString' 'A match is recorded by its label'
Assert-Equal ((ConvertTo-Json $hits -Compress) -match 'Hunter2') $false 'The matched text itself is never recorded'
Assert-Equal @($hits)[1].keyword 'storage or SAS key' 'Storage account keys are found'
$none = Find-Credential "Get-AzVM | Select Name"
Assert-Equal @($none).Count 0 'Text without credentials has no matches'
$two = Find-Credential "password1 secret`npassword2"
Assert-Equal @($two).Count 2 'One match per line'

Write-Output "$($script:passed) passed, $($script:failed) failed"
if ($script:failed) { exit 1 }
