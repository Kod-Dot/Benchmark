<#
.SYNOPSIS
    Fails if any collector script calls a command or API that can change a
    directory, a machine or a tenant. Collectors must be read-only.
#>
param([string] $Path = (Join-Path (Join-Path $PSScriptRoot '..') 'collectors'))

$ErrorActionPreference = 'Stop'

# Cmdlet verbs that change state.
$writeVerbs = @('Set', 'Remove', 'Add', 'Clear', 'Rename', 'Move', 'Enable', 'Disable', 'Reset', 'Grant',
    'Revoke', 'Install', 'Uninstall', 'Register', 'Unregister', 'Restart', 'Stop', 'Start', 'Update',
    'Publish', 'Restore', 'Unlock', 'Suspend', 'Resume')
# Commands that only affect the collector's own PowerShell session.
$allowedCommands = @('Set-StrictMode', 'Add-Type')
# ADSI / .NET methods that write.
$writeMethods = @('CommitChanges', 'Put', 'PutEx', 'DeleteTree', 'DeleteObject', 'SetInfo', 'SetPassword',
    'ChangePassword', 'Rename', 'MoveTo', 'Invoke', 'InvokeSet')
# LDAP requests that write (System.DirectoryServices.Protocols).
$writeRequests = @('AddRequest', 'ModifyRequest', 'DeleteRequest', 'ModifyDNRequest', 'ExtendedRequest')
# Native tools that write.
$writeTools = @('dsmod', 'dsadd', 'dsrm', 'dsmove', 'ntdsutil', 'netdom', 'setspn', 'certutil', 'reg')

$violations = foreach ($file in Get-ChildItem -LiteralPath $Path -Recurse -Include *.ps1, *.psm1) {
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
    foreach ($e in $errors) { '{0}:{1}: parse error: {2}' -f $file.Name, $e.Extent.StartLineNumber, $e.Message }

    $commands = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)
    foreach ($c in $commands) {
        $name = $c.GetCommandName()
        if (-not $name -or $allowedCommands -contains $name) { continue }
        $verb = ($name -split '-')[0]
        if (($name -like '*-*' -and $writeVerbs -contains $verb) -or $writeTools -contains ($name -replace '\.exe$', '')) {
            '{0}:{1}: {2}' -f $file.Name, $c.Extent.StartLineNumber, $c.Extent.Text
        }
    }

    $types = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.TypeExpressionAst] -or $n -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true)
    foreach ($t in $types) {
        $text = if ($t -is [System.Management.Automation.Language.TypeExpressionAst]) { $t.TypeName.FullName } else { $t.Value }
        if ($writeRequests | Where-Object { $text -match "(^|\.)$_$" }) {
            '{0}:{1}: {2}' -f $file.Name, $t.Extent.StartLineNumber, $t.Extent.Text
        }
    }

    $members = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true)
    foreach ($m in $members) {
        if ($writeMethods -contains $m.Member.Extent.Text) {
            '{0}:{1}: {2}' -f $file.Name, $m.Extent.StartLineNumber, $m.Extent.Text
        }
    }
}

if ($violations) {
    $violations | ForEach-Object { Write-Host $_ }
    throw "Collectors must be read-only: $(@($violations).Count) violation(s) found."
}
Write-Host 'Collectors are read-only.'
