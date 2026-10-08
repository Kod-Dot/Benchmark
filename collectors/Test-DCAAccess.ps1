<#
.SYNOPSIS
    Tests which on-premises data sources the current account can read.

.DESCRIPTION
    Read-only. Writes one JSON line per source to stdout:
        {"type":"probe","source":"ldap","state":"ok","detail":"..."}
    state is ok, partial, failed or untested.
    Compatible with Windows PowerShell 5.1 and PowerShell 7.

.PARAMETER Domain
    DNS name of the domain to test, for example corp.example.com.

.PARAMETER Sources
    Comma-separated source ids from checks/sources.toml.

.PARAMETER MaxDcs
    Domain controllers to test for dc-remote and dc-events. Testing every DC
    in a large forest takes too long for an up-front check; collection tests
    each DC again anyway.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Domain,
    [Parameter(Mandatory)] [string] $Sources,
    [int] $MaxDcs = 5
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

function Write-Probe([string] $Source, [string] $State, [string] $Detail) {
    [Console]::Out.WriteLine((@{ type = 'probe'; source = $Source; state = $State; detail = $Detail } | ConvertTo-Json -Compress))
}

function Get-FirstLine([System.Management.Automation.ErrorRecord] $ErrorRecord) {
    $message = $ErrorRecord.Exception.Message
    if ($ErrorRecord.Exception.InnerException) { $message = $ErrorRecord.Exception.InnerException.Message }
    ($message -split "`r?`n")[0].Trim()
}

$script:dcs = $null
function Get-DomainControllerName {
    if ($null -eq $script:dcs) {
        $context = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)
        $script:dcs = @([System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($context).DomainControllers |
                ForEach-Object { $_.Name } | Sort-Object)
    }
    $script:dcs
}

# Runs $Test against up to $Max DCs and reports ok / partial / failed.
function Test-PerDc([string] $Source, [string] $What, [int] $Max, [scriptblock] $Test) {
    try { $all = Get-DomainControllerName }
    catch { Write-Probe $Source 'failed' ("Could not list domain controllers: " + (Get-FirstLine $_)); return }
    if ($all.Count -eq 0) { Write-Probe $Source 'failed' 'No domain controllers found.'; return }

    $targets = @($all | Select-Object -First $Max)
    $failures = @()
    foreach ($dc in $targets) {
        try { & $Test $dc | Out-Null }
        catch { $failures += ('{0} ({1})' -f $dc, (Get-FirstLine $_)) }
    }
    $passed = $targets.Count - $failures.Count
    $scope = if ($all.Count -gt $targets.Count) { "$($targets.Count) of $($all.Count) domain controllers tested. " } else { '' }
    $summary = '{0}{1} on {2} of {3}.' -f $scope, $What, $passed, $targets.Count
    if ($failures.Count -gt 0) { $summary += ' Failed: ' + ($failures -join '; ') }
    $state = if ($failures.Count -eq 0) { 'ok' } elseif ($passed -gt 0) { 'partial' } else { 'failed' }
    Write-Probe $Source $state $summary
}

foreach ($source in ($Sources -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
    switch ($source) {
        'ldap' {
            try {
                $rootDse = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Domain/RootDSE")
                $server = [string]$rootDse.Properties['dnsHostName'].Value
                $naming = [string]$rootDse.Properties['defaultNamingContext'].Value
                $searcher = New-Object System.DirectoryServices.DirectorySearcher(
                    (New-Object System.DirectoryServices.DirectoryEntry("LDAP://$server/$naming")), '(objectClass=domain)', @('distinguishedName'))
                $searcher.SearchScope = 'Base'
                if ($null -eq $searcher.FindOne()) { throw "The domain object $naming was not returned." }
                Write-Probe 'ldap' 'ok' "Read $naming from $server."
            }
            catch { Write-Probe 'ldap' 'failed' (Get-FirstLine $_) }
        }
        'sysvol' {
            $path = "\\$Domain\SYSVOL\$Domain\Policies"
            try {
                $count = @(Get-ChildItem -LiteralPath $path -Directory).Count
                Write-Probe 'sysvol' 'ok' "Listed $count policy folders in $path."
            }
            catch { Write-Probe 'sysvol' 'failed' ("Could not read ${path}: " + (Get-FirstLine $_)) }
        }
        'dc-remote' {
            try { $sessionOption = New-PSSessionOption -OpenTimeout 10000 -OperationTimeout 15000 }
            catch { Write-Probe 'dc-remote' 'failed' (Get-FirstLine $_); continue }
            Test-PerDc 'dc-remote' 'Remote PowerShell worked' $MaxDcs {
                param($dc)
                Invoke-Command -ComputerName $dc -SessionOption $sessionOption -ScriptBlock { [Environment]::MachineName } -ErrorAction Stop
            }
        }
        'dc-events' {
            Test-PerDc 'dc-events' 'The Security log was readable' $MaxDcs {
                param($dc)
                Get-WinEvent -ComputerName $dc -LogName Security -MaxEvents 1 -ErrorAction Stop
            }
        }
        'endpoints' {
            Write-Probe 'endpoints' 'untested' 'Tested on each machine during collection.'
        }
        default {
            Write-Probe $source 'untested' 'This source is not tested by the on-premises access check.'
        }
    }
}
