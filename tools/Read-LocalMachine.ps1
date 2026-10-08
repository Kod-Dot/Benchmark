<#
.SYNOPSIS
    Runs the collector's domain controller, endpoint and event log reads
    against this machine and writes their replies the way
    Invoke-DCACollect.ps1 does (dcconfig.jsonl, endpoints.jsonl,
    dcevents.jsonl), so the analysis can be tested against real Windows
    output. CI runs it on a GitHub Windows Server runner.

    The script blocks and functions are taken from
    collectors/Invoke-DCACollect.ps1 itself, unchanged, so this tests exactly
    what ships. They only read. Fails when Windows rejects one of the event
    log queries as malformed.

.EXAMPLE
    powershell -NoProfile -File tools\Read-LocalMachine.ps1 -OutDir C:\Temp\live
#>
[CmdletBinding()]
param([Parameter(Mandatory)] [string] $OutDir)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

$collector = Join-Path $PSScriptRoot '..\collectors\Invoke-DCACollect.ps1'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $collector), [ref] $tokens, [ref] $parseErrors)
if ($parseErrors) { throw "The collector does not parse: $($parseErrors[0].Message)" }

# The top-level assignments of the four variables, evaluated here.
$names = @('dcRegistry', 'dcConfigScript', 'epRegistry', 'endpointScript')
$found = @{}
foreach ($statement in $ast.EndBlock.Statements) {
    if ($statement -isnot [System.Management.Automation.Language.AssignmentStatementAst]) { continue }
    $left = $statement.Left
    if ($left -is [System.Management.Automation.Language.VariableExpressionAst] -and $names -contains $left.VariablePath.UserPath) {
        . ([scriptblock]::Create($statement.Extent.Text))
        $found[$left.VariablePath.UserPath] = $true
    }
}
foreach ($n in $names) { if (-not $found[$n]) { throw "Invoke-DCACollect.ps1 no longer assigns `$$n at the top level." } }

# The event log reader and the helpers it calls.
$functions = @('Get-FirstLine', 'Get-EventSummary', 'Get-EventDataNode', 'Get-EventField', 'Get-EventData', 'Get-EventProperty', 'Read-DcEventLog')
foreach ($fn in $ast.FindAll({ param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
    if ($functions -contains $fn.Name) { . ([scriptblock]::Create($fn.Extent.Text)) }
}
foreach ($n in $functions) { if (-not (Get-Command $n -CommandType Function -ErrorAction SilentlyContinue)) { throw "Invoke-DCACollect.ps1 no longer defines $n." } }

if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }
$name = ([System.Net.Dns]::GetHostEntry('localhost')).HostName
$utf8 = New-Object System.Text.UTF8Encoding($false)

foreach ($run in @(
        @{ area = 'dcconfig'; script = $dcConfigScript; registry = $dcRegistry },
        @{ area = 'endpoints'; script = $endpointScript; registry = $epRegistry })) {
    $json = [string](& $run.script $run.registry)
    $at = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $line = '{"name":' + (ConvertTo-Json $name) + ',"read_at":"' + $at + '","data":' + $json + '}'
    [System.IO.File]::WriteAllText((Join-Path $OutDir "$($run.area).jsonl"), $line + "`n", $utf8)
    $reply = $json | ConvertFrom-Json
    $errors = @($reply.errors.PSObject.Properties | ForEach-Object { "$($_.Name): $($_.Value)" })
    Write-Output "$($run.area): $(@($reply.PSObject.Properties).Count - 2) parts read on $name; $($errors.Count) could not be read on this machine"
    $errors | ForEach-Object { Write-Output "    $_" }
}

# Event logs: every query the collector sends a DC, against this machine's logs.
$events = Read-DcEventLog -Dc 'localhost' -Days 30
$events.name = $name
[System.IO.File]::WriteAllText((Join-Path $OutDir 'dcevents.jsonl'), (ConvertTo-Json -InputObject $events -Compress -Depth 6) + "`n", $utf8)
$malformed = @()
foreach ($q in $events.queries.Keys) {
    $r = $events.queries[$q]
    if ($r.Contains('error')) {
        Write-Output ("    {0,-24} {1}" -f $q, $r.error)
        # A log this machine does not have is expected; a rejected query is a bug.
        if ($r.error -match 'query is invalid|specified query|XPath') { $malformed += $q }
    }
    else { Write-Output ("    {0,-24} {1} events, {2} distinct" -f $q, $r.count, @($r.top).Count) }
}
Write-Output "dcevents: $(@($events.queries.Keys).Count) queries run against this machine's logs"
if ($malformed) { throw "Windows rejected these event log queries: $($malformed -join ', ')" }
