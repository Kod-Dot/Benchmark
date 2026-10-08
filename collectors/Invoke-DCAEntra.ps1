<#
.SYNOPSIS
    Collects Microsoft Entra ID configuration for Benchmark. Read-only.

.DESCRIPTION
    Signs in to Microsoft (delegated, as the person running the assessment)
    and reads the tenant's configuration from Microsoft Graph with GET
    requests only. Writes to -OutDir:

        collection.json     tenant, account, granted scopes, times
        <area>.jsonl        the Graph responses for one area, one response
                            page per line, exactly as Graph returned them.
                            Pages read per parent object (for example the
                            federation settings of each domain) carry the
                            parent's id as "@dca.parent".

    Progress goes to stdout as JSON lines, the same events as
    Invoke-DCACollect.ps1, plus the sign-in:

        {"type":"signin","url":"https://login.microsoft...","code":null}
        {"type":"signedin","account":"admin@contoso.com"}

    An area that fails (missing licence or permission) does not stop the
    others. Secrets are never read: Graph does not return client secret or
    certificate values, only their names and validity dates, and this
    script does not ask for BitLocker keys or LAPS passwords.

    The access token stays in memory and is never written to disk.

    Compatible with Windows PowerShell 5.1 and PowerShell 7.

.PARAMETER Tenant
    The tenant's domain (contoso.onmicrosoft.com or a verified domain) or id.

.PARAMETER OutDir
    Folder to write to. Created if missing.

.PARAMETER Sources
    Comma-separated source ids from checks/sources.toml. This script reads
    graph (configuration), graph-logs (sign-in and audit logs of the
    last 30 days, filtered to what the checks need) and exo (Exchange
    Online configuration, through the ExchangeOnlineManagement module, and
    the SPF, DMARC, MTA-STS and TLS-RPT records of its accepted domains)
    and arm (Azure role assignments, Defender for Cloud, storage accounts
    and Key Vaults of every enabled subscription the account can read),
    spo (SharePoint Online through Microsoft.Online.SharePoint.PowerShell),
    teams (Teams policies through MicrosoftTeams) and purview (labels, DLP,
    retention, alerts and role groups through Security & Compliance
    PowerShell) and defender (Defender XDR incidents, alerts, Secure Score,
    Defender for Identity sensors and device protection through Graph, and
    machines through the Defender for Endpoint API); other ids are
    ignored. Each module is loaded with its
    Get- cmdlets only.

.PARAMETER ClientId
    The public client application to sign in with. Defaults to Microsoft
    Graph Command Line Tools; organizations that prefer their own app
    registration pass its application id (it needs http://localhost as a
    mobile and desktop redirect URI and the read scopes listed below).

.PARAMETER SignIn
    Browser (default): opens the default browser and receives the answer on
    a local port. DeviceCode: shows a code to enter at microsoft.com/devicelogin,
    for when no browser can be opened on this computer. App: signs in as the
    application -ClientId itself (client credentials), for unattended runs
    such as CI; the app needs the matching read-only application
    permissions. Its secret comes from the DCA_CLIENT_SECRET environment
    variable, or a certificate from -CertificatePath (password in
    DCA_CERT_PASSWORD). Exchange Online accepts only the certificate.

.PARAMETER CertificatePath
    With -SignIn App: a .pfx file holding the app's certificate and key.

.PARAMETER Bundle
    For running the collector on its own, for example on a domain
    controller: also keeps the progress log in -OutDir (events.jsonl) and,
    when collection finishes, packs -OutDir into this .zip file. Open it in
    the Benchmark app with Open bundle to analyze it there.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Tenant,
    [Parameter(Mandatory)] [string] $OutDir,
    [string] $Sources = 'graph',
    [string] $ClientId = '14d82eec-204b-4c2f-b7e8-296a70dab67e',
    [ValidateSet('Browser', 'DeviceCode', 'App')] [string] $SignIn = 'Browser',
    [string] $CertificatePath,
    [string] $Bundle
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

$utf8 = New-Object System.Text.UTF8Encoding($false)
$login = 'https://login.microsoftonline.com'
$graph = 'https://graph.microsoft.com'
$arm = 'https://management.azure.com'
# Azure CLI, the public client used for Azure Resource Manager when the
# sign-in app has no consent for it.
$azureCliClient = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'

# Read-only delegated permissions. Each one only allows reading.
$scopes = @(
    'Directory.Read.All', 'Policy.Read.All', 'RoleManagement.Read.Directory', 'RoleEligibilitySchedule.Read.Directory',
    'RoleAssignmentSchedule.Read.Directory', 'RoleManagementPolicy.Read.Directory', 'AuditLog.Read.All',
    'UserAuthenticationMethod.Read.All', 'Application.Read.All', 'IdentityRiskyUser.Read.All', 'SecurityEvents.Read.All',
    'Device.Read.All', 'OnPremDirectorySynchronization.Read.All', 'Reports.Read.All', 'IdentityRiskEvent.Read.All',
    'IdentityRiskyServicePrincipal.Read.All', 'AccessReview.Read.All', 'RoleManagementAlert.Read.Directory',
    'DeviceManagementConfiguration.Read.All', 'DeviceManagementManagedDevices.Read.All', 'DeviceManagementServiceConfig.Read.All',
    'DeviceManagementRBAC.Read.All', 'DeviceManagementApps.Read.All', 'SharePointTenantSettings.Read.All', 'SecurityIncident.Read.All',
    'SecurityAlert.Read.All', 'SecurityIdentitiesSensors.Read.All', 'SecurityIdentitiesHealth.Read.All', 'BitLockerKey.ReadBasic.All'
) | ForEach-Object { "$graph/$_" }
$scope = (@($scopes) + @('offline_access', 'openid', 'profile')) -join ' '

# Applications whose application permissions are reviewed: Microsoft Graph,
# Exchange Online, SharePoint Online and the retired Azure AD Graph.
$resourceApps = @('00000003-0000-0000-c000-000000000000', '00000002-0000-0ff1-ce00-000000000000',
    '00000003-0000-0ff1-ce00-000000000000', '00000002-0000-0000-c000-000000000000')

[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$script:eventLog = $null
$script:appResource = $null

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

function ConvertTo-Base64Url([byte[]] $Bytes) {
    [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function ConvertFrom-Jwt([string] $Token) {
    $part = $Token.Split('.')[1].Replace('-', '+').Replace('_', '/')
    switch ($part.Length % 4) { 2 { $part += '==' } 3 { $part += '=' } }
    ConvertFrom-Json $utf8.GetString([Convert]::FromBase64String($part))
}

# One HTTP request through the system proxy. Returns the status code and the
# body as text; never throws for an HTTP error status.
function Invoke-Http {
    param([string] $Method, [string] $Uri, [string] $Form, [hashtable] $Headers = @{})
    $request = [System.Net.HttpWebRequest]::Create($Uri)
    $request.Method = $Method
    $request.Timeout = 120000
    $request.ReadWriteTimeout = 300000
    $request.UserAgent = 'Benchmark'
    if ($request.Proxy) { $request.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials }
    foreach ($key in $Headers.Keys) { $request.Headers[$key] = $Headers[$key] }
    if ($Form) {
        $bytes = $utf8.GetBytes($Form)
        $request.ContentType = 'application/x-www-form-urlencoded'
        $request.ContentLength = $bytes.Length
        $stream = $request.GetRequestStream()
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Close()
    }
    try { $response = $request.GetResponse() }
    catch [System.Net.WebException] {
        $response = $_.Exception.Response
        if (-not $response) { throw }
    }
    try {
        $reader = New-Object System.IO.StreamReader($response.GetResponseStream(), $utf8)
        $body = $reader.ReadToEnd()
        $reader.Close()
        @{ status = [int] $response.StatusCode; body = $body; retry = $response.Headers['Retry-After'] }
    }
    finally { $response.Close() }
}

function Get-FormText([hashtable] $Fields) {
    ($Fields.Keys | ForEach-Object { "$_=$([Uri]::EscapeDataString([string] $Fields[$_]))" }) -join '&'
}

function Get-OAuthError([string] $Body) {
    try {
        $e = ConvertFrom-Json $Body
        if ($e.error_description) { return Format-SignInError (($e.error_description -split "`r?`n")[0]) }
        return [string] $e.error
    }
    catch { return $Body }
}

# Plain guidance for the sign-in errors people hit most, after Microsoft's text.
function Format-SignInError([string] $Message) {
    $hint = switch -Regex ($Message) {
        'AADSTS(500208|500200|50020)\b' { 'This looks like a personal Microsoft account (such as outlook.com or hotmail.com), or an account from another organization. Benchmark assesses an organization''s Microsoft 365 tenant, so sign in with a work or school account that belongs to the tenant you entered, for example admin@contoso.onmicrosoft.com.' }
        'AADSTS(90002|900023)\b' { 'The tenant was not found. Enter the tenant''s domain (such as contoso.onmicrosoft.com) or its tenant ID.' }
        'AADSTS(65001|90094|90095)\b' { 'The app needs an administrator''s consent in this tenant. Sign in once as a Global Administrator, or ask one to approve it.' }
        'AADSTS53003\b' { 'A Conditional Access policy blocked the sign-in. Sign in from a device or location the policy allows.' }
        default { $null }
    }
    if ($hint) { "$Message $hint" } else { $Message }
}

function Save-Token($Answer) {
    $script:accessToken = $Answer.access_token
    if ($Answer.PSObject.Properties['refresh_token']) { $script:refreshToken = $Answer.refresh_token }
    $script:expiresAt = [DateTime]::UtcNow.AddSeconds([int] $Answer.expires_in)
}

function Request-Token([hashtable] $Fields) {
    $Fields.client_id = $ClientId
    $r = Invoke-Http -Method POST -Uri "$login/$Tenant/oauth2/v2.0/token" -Form (Get-FormText $Fields)
    $answer = $null
    try { $answer = ConvertFrom-Json $r.body } catch { $answer = $null }
    @{ ok = ($r.status -eq 200); answer = $answer; error = (Get-OAuthError $r.body) }
}

# Authorization code with PKCE, answered on a loopback port: the browser
# signs in (MFA, Conditional Access and all), then redirects to
# http://localhost:<port> with a one-time code.
function Connect-WithBrowser {
    $bytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $verifier = ConvertTo-Base64Url $bytes
    $challenge = ConvertTo-Base64Url ([System.Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::ASCII.GetBytes($verifier)))
    $state = [Guid]::NewGuid().ToString('N')

    $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try {
        $redirect = "http://localhost:$(([System.Net.IPEndPoint] $listener.LocalEndpoint).Port)"
        $url = "$login/$Tenant/oauth2/v2.0/authorize?" + (Get-FormText @{
                client_id = $ClientId; response_type = 'code'; redirect_uri = $redirect; response_mode = 'query'
                scope = $scope; code_challenge = $challenge; code_challenge_method = 'S256'; state = $state; prompt = 'select_account'
            })
        Write-Event @{ type = 'signin'; url = $url; code = $null }
        # Opens the sign-in page in the default browser; changes nothing.
        $open = New-Object System.Diagnostics.ProcessStartInfo $url
        $open.UseShellExecute = $true
        $null = [System.Diagnostics.Process]::Start($open)

        $deadline = [DateTime]::UtcNow.AddMinutes(10)
        while ($true) {
            $accept = $listener.AcceptTcpClientAsync()
            $left = [int] ($deadline - [DateTime]::UtcNow).TotalMilliseconds
            if ($left -le 0 -or -not $accept.Wait($left)) { throw 'Sign-in was not completed within 10 minutes.' }
            $client = $accept.Result
            try {
                $stream = $client.GetStream()
                $reader = New-Object System.IO.StreamReader($stream, [Text.Encoding]::ASCII)
                $requestLine = $reader.ReadLine()
                $query = @{}
                if ($requestLine -match '^GET [^?\s]*\?(\S+)') {
                    foreach ($pair in $Matches[1].Split('&')) {
                        $kv = $pair.Split('=', 2)
                        if ($kv.Count -eq 2) { $query[$kv[0]] = [Uri]::UnescapeDataString($kv[1].Replace('+', ' ')) }
                    }
                }
                $done = $query.ContainsKey('code') -or $query.ContainsKey('error')
                $text = if ($query.ContainsKey('code')) { 'You are signed in. Close this tab and return to Benchmark.' }
                elseif ($query.ContainsKey('error')) { 'Sign-in did not complete. Return to Benchmark for details.' }
                else { 'Waiting for sign-in.' }
                $html = "<!doctype html><meta charset=utf-8><title>Benchmark</title><body style=""font-family:Segoe UI,sans-serif;margin:48px;color:#141413;background:#faf9f5""><h2>$text</h2></body>"
                $payload = $utf8.GetBytes($html)
                $head = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 OK`r`nContent-Type: text/html; charset=utf-8`r`nContent-Length: $($payload.Length)`r`nConnection: close`r`n`r`n")
                $stream.Write($head, 0, $head.Length)
                $stream.Write($payload, 0, $payload.Length)
                $stream.Flush()
            }
            finally { $client.Close() }
            if (-not $done) { continue }
            if ($query.ContainsKey('error')) { throw "Sign-in failed: $(Format-SignInError ($query['error_description'] -replace '\r?\n.*', ''))" }
            if ($query['state'] -ne $state) { throw 'Sign-in answer did not match the request.' }
            break
        }
    }
    finally { $listener.Stop() }

    $t = Request-Token @{ grant_type = 'authorization_code'; code = $query['code']; redirect_uri = $redirect; code_verifier = $verifier; scope = $scope }
    if (-not $t.ok) { throw "Sign-in failed: $($t.error)" }
    Save-Token $t.answer
}

function Connect-WithDeviceCode {
    $r = Invoke-Http -Method POST -Uri "$login/$Tenant/oauth2/v2.0/devicecode" -Form (Get-FormText @{ client_id = $ClientId; scope = $scope })
    if ($r.status -ne 200) { throw "Sign-in failed: $(Get-OAuthError $r.body)" }
    $code = ConvertFrom-Json $r.body
    Write-Event @{ type = 'signin'; url = $code.verification_uri; code = $code.user_code }
    $interval = [Math]::Max(5, [int] $code.interval)
    $deadline = [DateTime]::UtcNow.AddSeconds([int] $code.expires_in)
    while ([DateTime]::UtcNow -lt $deadline) {
        [System.Threading.Thread]::Sleep($interval * 1000)
        $t = Request-Token @{ grant_type = 'urn:ietf:params:oauth:grant-type:device_code'; device_code = $code.device_code }
        if ($t.ok) { Save-Token $t.answer; return }
        $err = if ($t.answer -and $t.answer.PSObject.Properties['error']) { $t.answer.error } else { '' }
        if ($err -eq 'authorization_pending') { continue }
        if ($err -eq 'slow_down') { $interval += 5; continue }
        throw "Sign-in failed: $($t.error)"
    }
    throw 'The sign-in code expired before it was used.'
}

# A signed JWT that proves the app holds its certificate's private key.
function Get-ClientAssertion {
    $password = if ($env:DCA_CERT_PASSWORD) { $env:DCA_CERT_PASSWORD } else { '' }
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertificatePath, $password)
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $header = @{ alg = 'RS256'; typ = 'JWT'; x5t = (ConvertTo-Base64Url $cert.GetCertHash()) }
    $payload = @{
        aud = "$login/$Tenant/oauth2/v2.0/token"; iss = $ClientId; sub = $ClientId
        jti = [Guid]::NewGuid().ToString(); nbf = $now; exp = $now + 600
    }
    $text = (ConvertTo-Base64Url $utf8.GetBytes((ConvertTo-Json $header -Compress))) + '.' + (ConvertTo-Base64Url $utf8.GetBytes((ConvertTo-Json $payload -Compress)))
    $key = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
    $signature = $key.SignData($utf8.GetBytes($text), [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $text + '.' + (ConvertTo-Base64Url $signature)
}

# Client credentials: the app signs in as itself for $Resource.
function Connect-App([string] $Resource) {
    $script:appResource = $Resource
    $fields = @{ grant_type = 'client_credentials'; scope = "$Resource/.default" }
    if ($CertificatePath) {
        $fields.client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        $fields.client_assertion = Get-ClientAssertion
    }
    elseif ($env:DCA_CLIENT_SECRET) { $fields.client_secret = $env:DCA_CLIENT_SECRET }
    else { throw 'App sign-in needs a certificate (-CertificatePath) or a secret (DCA_CLIENT_SECRET).' }
    $t = Request-Token $fields
    if (-not $t.ok) { throw "Sign-in failed: $($t.error)" }
    Save-Token $t.answer
}

function Get-AccessToken {
    if ($SignIn -eq 'App' -and [DateTime]::UtcNow -ge $script:expiresAt.AddMinutes(-5)) { Connect-App $script:appResource }
    elseif ([DateTime]::UtcNow -ge $script:expiresAt.AddMinutes(-5) -and $script:refreshToken) {
        $t = Request-Token @{ grant_type = 'refresh_token'; refresh_token = $script:refreshToken; scope = $scope }
        if ($t.ok) { Save-Token $t.answer }
    }
    $script:accessToken
}

# A GET on Graph with retries for throttling and transient errors. Returns
# the response body; throws with Graph's own error message otherwise.
function Invoke-Graph([string] $Path) {
    $uri = if ($Path.StartsWith('https://')) { $Path } else { "$graph/$Path" }
    for ($attempt = 1; ; $attempt++) {
        # ocp-client-name and -version identify the caller; some APIs (BitLocker) require them.
        $r = Invoke-Http -Method GET -Uri $uri -Headers @{ Authorization = "Bearer $(Get-AccessToken)"; ConsistencyLevel = 'eventual'; 'ocp-client-name' = 'Benchmark'; 'ocp-client-version' = '1.0' }
        if ($r.status -eq 200) { return $r.body }
        if (($r.status -in 429, 500, 502, 503, 504) -and $attempt -lt 6) {
            $wait = 0
            if (-not [int]::TryParse([string] $r.retry, [ref] $wait)) { $wait = [Math]::Pow(2, $attempt) }
            [System.Threading.Thread]::Sleep([Math]::Min(120, [Math]::Max(1, $wait)) * 1000)
            continue
        }
        if ($r.status -eq 401 -and $attempt -eq 1 -and $script:refreshToken) {
            $script:expiresAt = [DateTime]::MinValue
            continue
        }
        $message = "HTTP $($r.status)"
        try {
            $e = (ConvertFrom-Json $r.body).error
            $message = "$($e.code): $(($e.message -split "`r?`n")[0]) (HTTP $($r.status))"
        }
        catch { $message = "HTTP $($r.status)" }
        throw $message
    }
}

# Count of items in a page without parsing large pages twice.
function Measure-Page([string] $Body) {
    $page = ConvertFrom-Json $Body
    if ($page.PSObject.Properties['value']) { return @($page.value).Count }
    1
}

# Reads $Paths (one Graph path, or one per parent id) into <Area>.jsonl,
# following @odata.nextLink. When the first path fails and $Fallback is
# given, tries it instead (for example without a property that needs a
# licence) and reports that through $FallbackArea.
function Export-GraphArea {
    param(
        [Parameter(Mandatory)] [string] $Area,
        # Per-parent lists can be empty, such as a tenant without App Proxy apps.
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Paths,
        [string] $Fallback,
        [string] $FallbackArea,
        [int] $MaxPages = 0,
        # A setting that was never configured answers 404; that reads as empty.
        [switch] $MissingIsEmpty
    )
    Write-Event @{ type = 'start'; area = $Area }
    $file = Join-Path $OutDir "$Area.jsonl"
    $writer = New-Object System.IO.StreamWriter($file, $false, $utf8)
    $count = 0
    $ok = $false
    try {
        foreach ($entry in $Paths) {
            $parent = $null
            $next = [string] $entry
            if ($entry -is [hashtable]) { $parent = $entry.parent; $next = $entry.path }
            $pages = 0
            while ($next) {
                try { $body = Invoke-Graph $next }
                catch {
                    if ($MissingIsEmpty -and (Get-FirstLine $_) -match 'HTTP 404\b') { $next = $null; continue }
                    if ($Fallback -and $count -eq 0 -and $next -ne $Fallback) {
                        if ($FallbackArea) { Write-Event @{ type = 'error'; area = $FallbackArea; message = (Get-FirstLine $_) } }
                        $FallbackArea = $null
                        $next = $Fallback
                        continue
                    }
                    throw
                }
                $line = $body -replace '[\r\n]+', ' '
                if ($null -ne $parent) { $line = '{"@dca.parent":' + (ConvertTo-Json -InputObject ([string] $parent) -Compress) + ',' + $line.TrimStart().Substring(1) }
                $writer.WriteLine($line)
                $count += Measure-Page $body
                $pages++
                Write-Event @{ type = 'progress'; area = $Area; read = $count }
                $next = $null
                # Graph pages name the next page @odata.nextLink, ARM pages nextLink.
                if ($body -match '"(?:@odata\.)?nextLink"\s*:\s*"([^"]+)"') {
                    if ($MaxPages -eq 0 -or $pages -lt $MaxPages) { $next = $Matches[1].Replace('\u0026', '&') }
                    # More was available than this area reads; the rules say so.
                    else { $writer.WriteLine('{"@dca.truncated":true}') }
                }
            }
        }
        $ok = $true
    }
    catch { Write-Event @{ type = 'error'; area = $Area; message = (Get-FirstLine $_) } }
    finally { $writer.Close() }
    if ($ok) {
        if ($FallbackArea) { Write-Event @{ type = 'done'; area = $FallbackArea; count = $count } }
        Write-Event @{ type = 'done'; area = $Area; count = $count }
    }
    # A failed area leaves no partial file of its own behind.
    else { try { [System.IO.File]::Delete($file) } catch { $null = $_ } }
    $ok
}

# Reads one area and returns its items, for areas whose content decides
# what else to read (federated domains, resource applications).
function Read-AreaItem([string] $Area) {
    $file = Join-Path $OutDir "$Area.jsonl"
    if (-not (Test-Path -LiteralPath $file)) { return @() }
    foreach ($line in [System.IO.File]::ReadAllLines($file, $utf8)) {
        if (-not $line.Trim()) { continue }
        $page = ConvertFrom-Json $line
        if ($page.PSObject.Properties['value']) { $page.value } else { $page }
    }
}

# Looks for credentials in Azure Automation variables, runbooks and
# deployment scripts. Only what matched is written (the resource, which
# keyword and on which line), never the text or the variable's value.
# Each pattern has a fixed label, which is all that is recorded of a match.
$credentialPatterns = [ordered]@{
    'password' = '(?i)(password|passwd|\bpwd\s*=)'
    'secret' = '(?i)(client_?secret|\bsecret\b)'
    'api key' = '(?i)api_?key'
    'connection string' = '(?i)connectionstring'
    'plain-text SecureString' = '(?i)ConvertTo-SecureString\b.*-AsPlainText'
    'storage or SAS key' = '(?i)(accountkey|sharedaccesskey|sharedaccesssignature)'
}
function Find-Credential([string] $Text) {
    $found = New-Object System.Collections.Generic.List[object]
    $n = 0
    foreach ($line in ($Text -split "`r?`n")) {
        $n++
        foreach ($label in $credentialPatterns.Keys) {
            if ($line -match $credentialPatterns[$label]) { $found.Add([ordered]@{ line = $n; keyword = $label }); break }
        }
        if ($found.Count -ge 20) { break }
    }
    , $found.ToArray()
}

function Export-CredentialScan {
    foreach ($a in 'azautomationvars', 'azscriptscan') { Write-Event @{ type = 'start'; area = $a } }
    try {
        $vars = New-Object System.Collections.Generic.List[string]
        $scan = New-Object System.Collections.Generic.List[string]
        $accounts = @(Read-AreaItem 'azautomation' | ForEach-Object { $_.id })
        foreach ($acct in $accounts) {
            foreach ($page in @(Get-ArmPage "$arm$acct/variables?api-version=2023-11-01")) {
                foreach ($v in @($page.value)) {
                    # Unencrypted values come back in plain text; keep only whether one is set.
                    $row = [ordered]@{ account = $acct; name = $v.name; isEncrypted = [bool] $v.properties.isEncrypted
                        hasValue = [bool] ($v.properties.PSObject.Properties['value'] -and $v.properties.value) }
                    $vars.Add((ConvertTo-Json -InputObject $row -Compress))
                }
            }
            $runbooks = @(Get-ArmPage "$arm$acct/runbooks?api-version=2023-11-01" | ForEach-Object { @($_.value) })
            foreach ($rb in ($runbooks | Select-Object -First 200)) {
                try { $text = Invoke-Graph "$arm$($rb.id)/content?api-version=2023-11-01" }
                catch { continue }
                $hits = Find-Credential $text
                if ($hits.Count) { $scan.Add((ConvertTo-Json -InputObject ([ordered]@{ kind = 'runbook'; id = $rb.id; name = $rb.name; matches = $hits }) -Compress -Depth 4)) }
            }
        }
        foreach ($sub in $subs) {
            foreach ($page in @(Get-ArmPage "$arm/subscriptions/$sub/providers/Microsoft.Resources/deploymentScripts?api-version=2023-08-01")) {
                foreach ($d in @($page.value)) {
                    $text = [string] $d.properties.scriptContent
                    foreach ($e in @($d.properties.environmentVariables)) { if ($e -and $e.PSObject.Properties['value']) { $text += "`n$($e.name)=$($e.value)" } }
                    $hits = Find-Credential $text
                    if ($hits.Count) { $scan.Add((ConvertTo-Json -InputObject ([ordered]@{ kind = 'deploymentScript'; id = $d.id; name = $d.name; matches = $hits }) -Compress -Depth 4)) }
                }
            }
        }
        [System.IO.File]::WriteAllLines((Join-Path $OutDir 'azautomationvars.jsonl'), $vars, $utf8)
        [System.IO.File]::WriteAllLines((Join-Path $OutDir 'azscriptscan.jsonl'), $scan, $utf8)
        Write-Event @{ type = 'done'; area = 'azautomationvars'; count = $vars.Count }
        Write-Event @{ type = 'done'; area = 'azscriptscan'; count = $scan.Count }
    }
    catch {
        $message = Get-FirstLine $_
        foreach ($a in 'azautomationvars', 'azscriptscan') { Write-Event @{ type = 'error'; area = $a; message = $message } }
    }
}

# One object with only $Fields, in plain JSON types.
function ConvertTo-PlainObject($Object, [string[]] $Fields) {
    $o = [ordered]@{}
    foreach ($f in $Fields) {
        $p = $Object.PSObject.Properties[$f]
        $v = $null
        if ($p) { $v = $p.Value }
        if ($null -eq $v) { $o[$f] = $null }
        elseif ($v -is [bool] -or $v -is [int] -or $v -is [long]) { $o[$f] = $v }
        elseif ($v -is [System.Collections.IEnumerable] -and $v -isnot [string]) { $o[$f] = [object[]] @($v | ForEach-Object { [string] $_ }) }
        else { $o[$f] = [string] $v }
    }
    $o
}

function Export-ModuleArea([string] $Area, [scriptblock] $Read, [string[]] $Fields) {
    Write-Event @{ type = 'start'; area = $Area }
    try {
        $lines = New-Object System.Collections.Generic.List[string]
        & $Read | ForEach-Object {
            $lines.Add((ConvertTo-Json -InputObject (ConvertTo-PlainObject $_ $Fields) -Compress -Depth 4))
            if ($lines.Count % 500 -eq 0) { Write-Event @{ type = 'progress'; area = $Area; read = $lines.Count } }
        }
        [System.IO.File]::WriteAllLines((Join-Path $OutDir "$Area.jsonl"), $lines, $utf8)
        Write-Event @{ type = 'done'; area = $Area; count = $lines.Count }
        $true
    }
    catch {
        Write-Event @{ type = 'error'; area = $Area; message = (Get-FirstLine $_) }
        $false
    }
}

# Every page of an ARM list, parsed.
function Get-ArmPage([string] $Path) {
    $next = $Path
    while ($next) {
        $page = ConvertFrom-Json (Invoke-Graph $next)
        $page
        $next = if ($page.PSObject.Properties['nextLink']) { $page.nextLink } else { $null }
    }
}

# ---------- Main ----------

$wanted = @($Sources.Split(',') | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ })
if ($wanted -notcontains 'graph') {
    Write-Event @{ type = 'finished'; finished_at = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ') }
    exit 0
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
if ($Bundle) {
    # Standalone run: keep the progress log the app would otherwise keep.
    $script:eventLog = Join-Path $OutDir 'events.jsonl'
    [System.IO.File]::WriteAllText($script:eventLog, '', $utf8)
}
$startedAt = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
$script:accessToken = $null
$script:refreshToken = $null
$script:expiresAt = [DateTime]::MinValue

Write-Event @{ type = 'start'; area = 'signin' }
try {
    if ($SignIn -eq 'App') { Connect-App $graph }
    elseif ($SignIn -eq 'DeviceCode') { Connect-WithDeviceCode }
    else { Connect-WithBrowser }
}
catch {
    Write-Event @{ type = 'error'; area = 'signin'; message = (Get-FirstLine $_) }
    exit 1
}
$claims = ConvertFrom-Jwt $script:accessToken
$account = if ($claims.PSObject.Properties['upn']) { $claims.upn } elseif ($claims.PSObject.Properties['unique_name']) { $claims.unique_name }
elseif ($SignIn -eq 'App') { "app:$ClientId" } else { [string] $claims.oid }
# Delegated tokens list scopes (scp); app tokens list application permissions (roles).
$granted = if ($claims.PSObject.Properties['scp']) { @(([string] $claims.scp).Split(' ') | Where-Object { $_ }) }
elseif ($claims.PSObject.Properties['roles']) { @($claims.roles | ForEach-Object { [string] $_ }) } else { @() }
Write-Event @{ type = 'signedin'; account = $account }
Write-Event @{ type = 'done'; area = 'signin'; count = 1 }

$info = [ordered]@{
    tenant = $Tenant
    tenant_id = [string] $claims.tid
    account = $account
    client_id = $ClientId
    computer = [Environment]::MachineName
    started_at = $startedAt
    sources = $wanted
    scopes = $granted
}
[System.IO.File]::WriteAllText((Join-Path $OutDir 'collection.json'), (ConvertTo-Json -InputObject $info -Depth 4), $utf8)

$userFields = 'id,displayName,userPrincipalName,mail,userType,accountEnabled,createdDateTime,creationType,externalUserState,' +
'externalUserStateChangeDateTime,onPremisesSyncEnabled,onPremisesSamAccountName,onPremisesDomainName,onPremisesImmutableId,' +
'onPremisesLastSyncDateTime,onPremisesSecurityIdentifier,onPremisesProvisioningErrors,passwordPolicies,lastPasswordChangeDateTime,' +
'assignedLicenses,licenseAssignmentStates,proxyAddresses'
$groupFields = 'id,displayName,description,groupTypes,securityEnabled,mailEnabled,isAssignableToRole,membershipRule,' +
'membershipRuleProcessingState,onPremisesSyncEnabled,onPremisesSecurityIdentifier,onPremisesProvisioningErrors,visibility,' +
'createdDateTime,resourceProvisioningOptions,assignedLabels'
$appFields = 'id,appId,displayName,signInAudience,createdDateTime,passwordCredentials,keyCredentials,web,spa,publicClient,' +
'requiredResourceAccess,servicePrincipalLockConfiguration,publisherDomain,verifiedPublisher,notes,description'
$spFields = 'id,appId,displayName,servicePrincipalType,accountEnabled,appOwnerOrganizationId,passwordCredentials,keyCredentials,' +
'appRoleAssignmentRequired,verifiedPublisher,preferredSingleSignOnMode,tags,createdDateTime'
$owners = 'owners($select=id,displayName,userPrincipalName,userType)'

$null = Export-GraphArea -Area 'organization' -Paths @('v1.0/organization')
$null = Export-GraphArea -Area 'skus' -Paths @('v1.0/subscribedSkus?$select=skuId,skuPartNumber,capabilityStatus,consumedUnits,prepaidUnits,servicePlans')
$null = Export-GraphArea -Area 'domains' -Paths @('v1.0/domains')
$federated = @(Read-AreaItem 'domains' | Where-Object { $_.authenticationType -eq 'Federated' } | ForEach-Object { $_.id })
if ($federated.Count) {
    $null = Export-GraphArea -Area 'federation' -Paths @($federated | ForEach-Object { @{ parent = $_; path = "v1.0/domains/$([Uri]::EscapeDataString($_))/federationConfiguration" } })
}
$null = Export-GraphArea -Area 'users' -Paths @("v1.0/users?`$select=$userFields,signInActivity&`$top=500") -Fallback "v1.0/users?`$select=$userFields&`$top=999" -FallbackArea 'signinactivity'
$null = Export-GraphArea -Area 'groups' -Paths @("v1.0/groups?`$select=$groupFields&`$expand=$owners&`$top=999") -Fallback "v1.0/groups?`$select=$groupFields&`$top=999" -FallbackArea 'groupowners'
# Members of role-assignable groups, since their members hold the group's roles.
$roleGroups = @(Read-AreaItem 'groups' | Where-Object { $_.PSObject.Properties['isAssignableToRole'] -and $_.isAssignableToRole } | ForEach-Object { $_.id })
if ($roleGroups.Count) {
    $null = Export-GraphArea -Area 'rolegroupmembers' -Paths @($roleGroups | ForEach-Object { @{ parent = $_; path = "v1.0/groups/$_/transitiveMembers?`$select=id,displayName,userPrincipalName,userType,accountEnabled&`$top=999" } })
}
$null = Export-GraphArea -Area 'roledefinitions' -Paths @('v1.0/roleManagement/directory/roleDefinitions')
$null = Export-GraphArea -Area 'roleassignments' -Paths @('v1.0/roleManagement/directory/roleAssignments?$expand=principal') -Fallback 'v1.0/roleManagement/directory/roleAssignments'
$null = Export-GraphArea -Area 'roleeligibility' -Paths @('v1.0/roleManagement/directory/roleEligibilitySchedules?$expand=principal') -Fallback 'v1.0/roleManagement/directory/roleEligibilitySchedules'
$null = Export-GraphArea -Area 'roleschedules' -Paths @('v1.0/roleManagement/directory/roleAssignmentSchedules')
$null = Export-GraphArea -Area 'pimpolicies' -Paths @("v1.0/policies/roleManagementPolicyAssignments?`$filter=scopeId eq '/' and scopeType eq 'DirectoryRole'&`$expand=policy(`$expand=rules)")
$null = Export-GraphArea -Area 'capolicies' -Paths @('v1.0/identity/conditionalAccess/policies')
$null = Export-GraphArea -Area 'namedlocations' -Paths @('v1.0/identity/conditionalAccess/namedLocations')
$null = Export-GraphArea -Area 'authstrengths' -Paths @('v1.0/policies/authenticationStrengthPolicies')
$null = Export-GraphArea -Area 'authmethods' -Paths @('v1.0/policies/authenticationMethodsPolicy?$expand=authenticationMethodConfigurations')
$null = Export-GraphArea -Area 'authorization' -Paths @('v1.0/policies/authorizationPolicy')
$null = Export-GraphArea -Area 'securitydefaults' -Paths @('v1.0/policies/identitySecurityDefaultsEnforcementPolicy')
$null = Export-GraphArea -Area 'adminconsent' -Paths @('v1.0/policies/adminConsentRequestPolicy')
$null = Export-GraphArea -Area 'crosstenant' -Paths @('v1.0/policies/crossTenantAccessPolicy/default')
$null = Export-GraphArea -Area 'crosstenantpartners' -Paths @('v1.0/policies/crossTenantAccessPolicy/partners')
$null = Export-GraphArea -Area 'deviceregistration' -Paths @('beta/policies/deviceRegistrationPolicy')
$null = Export-GraphArea -Area 'groupsettings' -Paths @('v1.0/groupSettings')
$null = Export-GraphArea -Area 'grouplifecycle' -Paths @('v1.0/groupLifecyclePolicies')
$null = Export-GraphArea -Area 'registration' -Paths @('v1.0/reports/authenticationMethods/userRegistrationDetails?$top=999')
$null = Export-GraphArea -Area 'applications' -Paths @("v1.0/applications?`$select=$appFields&`$expand=$owners&`$top=999") -Fallback "v1.0/applications?`$select=$appFields&`$top=999"
$null = Export-GraphArea -Area 'serviceprincipals' -Paths @("v1.0/servicePrincipals?`$select=$spFields&`$expand=$owners&`$top=999") -Fallback "v1.0/servicePrincipals?`$select=$spFields&`$top=999"
$null = Export-GraphArea -Area 'resources' -Paths @($resourceApps | ForEach-Object { @{ parent = $_; path = "v1.0/servicePrincipals?`$filter=appId eq '$_'&`$select=id,appId,displayName,appRoles,oauth2PermissionScopes" } })
$resourceIds = @(Read-AreaItem 'resources' | ForEach-Object { $_.id })
if ($resourceIds.Count) {
    $null = Export-GraphArea -Area 'approleassignments' -Paths @($resourceIds | ForEach-Object { @{ parent = $_; path = "v1.0/servicePrincipals/$_/appRoleAssignedTo?`$top=999" } })
}
$null = Export-GraphArea -Area 'grants' -Paths @('v1.0/oauth2PermissionGrants?$top=999')
$null = Export-GraphArea -Area 'devices' -Paths @('v1.0/devices?$select=id,deviceId,displayName,operatingSystem,operatingSystemVersion,trustType,isCompliant,isManaged,accountEnabled,approximateLastSignInDateTime,registrationDateTime&$top=999')
$null = Export-GraphArea -Area 'onpremsync' -Paths @('v1.0/directory/onPremisesSynchronization')
$null = Export-GraphArea -Area 'adminunits' -Paths @('v1.0/directory/administrativeUnits')
$null = Export-GraphArea -Area 'contracts' -Paths @('v1.0/contracts')
$null = Export-GraphArea -Area 'riskyusers' -Paths @("v1.0/identityProtection/riskyUsers?`$filter=riskState eq 'atRisk'")
# Identity Protection (Entra ID P2 and, for service principals, Workload ID
# Premium): detections of the last 30 days and risky service principals.
$since = [DateTime]::UtcNow.AddDays(-30).ToString('yyyy-MM-ddTHH:mm:ssZ')
$null = Export-GraphArea -Area 'riskdetections' -Paths @("v1.0/identityProtection/riskDetections?`$filter=detectedDateTime ge $since&`$top=500") -MaxPages 10
$null = Export-GraphArea -Area 'riskysps' -Paths @("v1.0/identityProtection/riskyServicePrincipals?`$filter=riskState eq 'atRisk'")
$null = Export-GraphArea -Area 'spsignins' -Paths @('beta/reports/servicePrincipalSignInActivities?$top=999') -MaxPages 10
$null = Export-GraphArea -Area 'fedcreds' -Paths @('v1.0/applications?$select=id,appId,displayName&$expand=federatedIdentityCredentials&$top=999')
$null = Export-GraphArea -Area 'accessreviews' -Paths @('v1.0/identityGovernance/accessReviews/definitions?$top=100')
$null = Export-GraphArea -Area 'pimalerts' -Paths @("beta/identityGovernance/roleManagementAlerts/alerts?`$filter=scopeId eq '/' and scopeType eq 'DirectoryRole'&`$expand=alertDefinition")
$orgIds = @(Read-AreaItem 'organization' | ForEach-Object { $_.id })
$null = Export-GraphArea -Area 'branding' -MissingIsEmpty -Paths @($orgIds | ForEach-Object { @{ parent = $_; path = "v1.0/organization/$_/branding" } })
# Intune (needs an Intune licence): tenant settings, enrollment, compliance
# and configuration policies, endpoint security, scripts, apps, roles and
# the managed devices themselves.
$null = Export-GraphArea -Area 'intunesettings' -Paths @('v1.0/deviceManagement?$select=id,settings,subscriptionState,intuneAccountId')
$null = Export-GraphArea -Area 'intuneenrollment' -Paths @('v1.0/deviceManagement/deviceEnrollmentConfigurations?$expand=assignments')
$null = Export-GraphArea -Area 'intunecompliance' -Paths @('v1.0/deviceManagement/deviceCompliancePolicies?$expand=assignments,scheduledActionsForRule($expand=scheduledActionConfigurations)')
$null = Export-GraphArea -Area 'intuneconfigs' -Paths @('v1.0/deviceManagement/deviceConfigurations?$expand=assignments')
$null = Export-GraphArea -Area 'intunepolicies' -Paths @('beta/deviceManagement/configurationPolicies?$expand=settings,assignments&$top=100')
$null = Export-GraphArea -Area 'intuneintents' -Paths @('beta/deviceManagement/intents?$top=100')
$null = Export-GraphArea -Area 'intuneconfigstatus' -Paths @('v1.0/deviceManagement/deviceConfigurations?$select=id,displayName&$expand=deviceStatusOverview')
$null = Export-GraphArea -Area 'intuneappprotection' -Paths @('v1.0/deviceAppManagement/managedAppPolicies')
$null = Export-GraphArea -Area 'intuneroles' -Paths @('v1.0/deviceManagement/roleDefinitions')
$null = Export-GraphArea -Area 'intuneroleassignments' -Paths @('beta/deviceManagement/roleAssignments?$expand=roleDefinition')
$null = Export-GraphArea -Area 'intuneapprovals' -Paths @('beta/deviceManagement/operationApprovalPolicies')
$null = Export-GraphArea -Area 'intunescripts' -Paths @('beta/deviceManagement/deviceManagementScripts?$expand=assignments')
$null = Export-GraphArea -Area 'intuneremediations' -Paths @('beta/deviceManagement/deviceHealthScripts?$expand=assignments')
$null = Export-GraphArea -Area 'intuneapps' -Paths @("v1.0/deviceAppManagement/mobileApps/microsoft.graph.win32LobApp?`$select=id,displayName,installCommandLine,uninstallCommandLine,publisher&`$expand=assignments(`$select=id)")
$null = Export-GraphArea -Area 'intunecleanup' -Paths @('beta/deviceManagement/managedDeviceCleanupSettings')
$null = Export-GraphArea -Area 'intuneautopilot' -Paths @('beta/deviceManagement/windowsAutopilotDeploymentProfiles?$expand=assignments')
$null = Export-GraphArea -Area 'intunecorporateids' -Paths @('beta/deviceManagement/importedDeviceIdentities?$top=1') -MaxPages 1
$null = Export-GraphArea -Area 'intuneremotehelp' -Paths @('beta/deviceManagement/remoteAssistanceSettings')
$null = Export-GraphArea -Area 'intunemtd' -Paths @('v1.0/deviceManagement/mobileThreatDefenseConnectors')
$null = Export-GraphArea -Area 'intunedevices' -MaxPages 20 -Paths @('v1.0/deviceManagement/managedDevices?$select=id,deviceName,operatingSystem,osVersion,complianceState,lastSyncDateTime,managementAgent,azureADDeviceId,isEncrypted,managedDeviceOwnerType,enrolledDateTime,deviceEnrollmentType&$top=999')
# BitLocker recovery key metadata (which devices have a key; never the key),
# group members (first 20 of each, for empty groups and nesting loops),
# guest invitation domain lists, the admin portal restriction, and the
# pre-authentication of App Proxy applications.
$null = Export-GraphArea -Area 'bitlockerkeys' -MaxPages 20 -Paths @('v1.0/informationProtection/bitlocker/recoveryKeys?$select=id,createdDateTime,deviceId,volumeType')
$null = Export-GraphArea -Area 'groupmembers' -MaxPages 50 -Paths @('v1.0/groups?$select=id,displayName,groupTypes,membershipRule&$expand=members($select=id)&$top=100')
$null = Export-GraphArea -Area 'b2bmanagement' -Paths @('beta/policies/b2bManagementPolicies')
$null = Export-GraphArea -Area 'uxsetting' -MissingIsEmpty -Paths @('beta/admin/entra/uxSetting')
$proxyApps = @(Read-AreaItem 'serviceprincipals' | Where-Object { @($_.tags) -contains 'WindowsAzureActiveDirectoryOnPremApp' } | ForEach-Object { $_.appId })
$proxyIds = @(Read-AreaItem 'applications' | Where-Object { $proxyApps -contains $_.appId } | ForEach-Object { $_.id })
$null = Export-GraphArea -Area 'appproxy' -Paths @($proxyIds | ForEach-Object { @{ parent = $_; path = "beta/applications/$([Uri]::EscapeDataString($_))?`$select=id,displayName,onPremisesPublishing" } })
# SharePoint tenant settings, and the number of guests in each team.
$null = Export-GraphArea -Area 'sposettings' -Paths @('v1.0/admin/sharepoint/settings')
$teamIds = @(Read-AreaItem 'groups' | Where-Object { $_.PSObject.Properties['resourceProvisioningOptions'] -and @($_.resourceProvisioningOptions) -contains 'Team' } | ForEach-Object { $_.id } | Select-Object -First 500)
$null = Export-GraphArea -Area 'teamguests' -Paths @($teamIds | ForEach-Object { @{ parent = $_; path = "v1.0/groups/$_/members/microsoft.graph.user?`$filter=userType eq 'Guest'&`$count=true&`$select=id&`$top=1" } }) -MaxPages 1
# Defender XDR through Graph: open incidents, Defender for Endpoint alerts
# of 30 days, the Secure Score trend, Defender for Identity sensors and
# health, and each Windows device's protection state as Intune reports it.
if ($wanted -contains 'defender') {
    $null = Export-GraphArea -Area 'incidents' -MaxPages 10 -Paths @("v1.0/security/incidents?`$filter=status eq 'active'&`$top=50", "v1.0/security/incidents?`$filter=status eq 'inProgress'&`$top=50")
    $null = Export-GraphArea -Area 'mdealerts' -MaxPages 10 -Paths @("v1.0/security/alerts_v2?`$filter=createdDateTime ge $since and serviceSource eq 'microsoftDefenderForEndpoint'&`$top=500")
    $null = Export-GraphArea -Area 'securescores' -MaxPages 1 -Paths @('v1.0/security/secureScores?$top=30&$select=createdDateTime,currentScore,maxScore')
    $null = Export-GraphArea -Area 'mdisensors' -Paths @('beta/security/identities/sensors')
    $null = Export-GraphArea -Area 'mdihealth' -Paths @("beta/security/identities/healthIssues?`$filter=status eq 'open'")
    $windows = @(Read-AreaItem 'intunedevices' | Where-Object { $_.operatingSystem -eq 'Windows' } | Select-Object -First 300 | ForEach-Object { $_.id })
    $null = Export-GraphArea -Area 'intuneprotection' -Paths @($windows | ForEach-Object { @{ parent = $_; path = "beta/deviceManagement/managedDevices/$_/windowsProtectionState" } })
}
$null = Export-GraphArea -Area 'securescore' -Paths @('v1.0/security/secureScores?$top=1') -MaxPages 1

# Sign-in and audit logs of the last 30 days (Entra ID P1), filtered on the
# server to what the checks look for, newest first, with a page cap per
# filter so a large tenant does not read millions of records.
if ($wanted -contains 'graph-logs') {
    $since = [DateTime]::UtcNow.AddDays(-30).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $audit = @('RoleManagement', 'ApplicationManagement', 'Policy', 'DirectoryManagement') |
        ForEach-Object { "v1.0/auditLogs/directoryAudits?`$filter=activityDateTime ge $since and category eq '$_'&`$top=999" }
    $null = Export-GraphArea -Area 'audits' -Paths $audit -MaxPages 20
    $null = Export-GraphArea -Area 'invites' -Paths @("v1.0/auditLogs/directoryAudits?`$filter=activityDateTime ge $since and activityDisplayName eq 'Invite external user'&`$top=999") -MaxPages 10
    $legacy = @('Exchange ActiveSync', 'IMAP4', 'POP3', 'Authenticated SMTP', 'MAPI Over HTTP', 'Offline Address Book',
        'Other clients', 'Outlook Anywhere (RPC over HTTP)', 'Exchange Online PowerShell', 'AutoDiscover', 'Reporting Web Services',
        'Exchange Web Services') |
        ForEach-Object { "v1.0/auditLogs/signIns?`$filter=createdDateTime ge $since and clientAppUsed eq '$_'&`$top=999" }
    $null = Export-GraphArea -Area 'signinslegacy' -Paths $legacy -MaxPages 5
    # 50126: wrong user name or password. 500121: MFA not completed (denied or
    # ignored prompts). 53003: blocked by Conditional Access.
    $failed = @(50126, 500121, 53003) |
        ForEach-Object { "v1.0/auditLogs/signIns?`$filter=createdDateTime ge $since and status/errorCode eq $_&`$top=999" }
    $null = Export-GraphArea -Area 'signinsfailed' -Paths $failed -MaxPages 20
    # A sample of successful sign-ins, for countries and device compliance.
    $null = Export-GraphArea -Area 'signins' -Paths @("v1.0/auditLogs/signIns?`$filter=createdDateTime ge $since and status/errorCode eq 0&`$top=999") -MaxPages 10
    $null = Export-GraphArea -Area 'signinssp' -Paths @("beta/auditLogs/signIns?`$filter=createdDateTime ge $since and signInEventTypes/any(t: t eq 'servicePrincipal')&`$top=999") -MaxPages 10
    $null = Export-GraphArea -Area 'signinsdevicecode' -Paths @("beta/auditLogs/signIns?`$filter=createdDateTime ge $since and authenticationProtocol eq 'deviceCode'&`$top=999") -MaxPages 10
}

# Azure resources through Azure Resource Manager, GET requests only. ARM
# needs its own token: the refresh token is tried first, and if the sign-in
# app has no consent for ARM, a second sign-in with the Azure CLI public
# client is asked for.
if ($wanted -contains 'arm') {
    $armAreas = @('azmgmtgroups', 'azsubscriptions', 'azroleassignments', 'azroledefinitions', 'azeligible', 'azactive', 'azcontacts', 'azpricings',
        'azsecurescore', 'azdiagnostics', 'azlighthouse', 'azpolicies', 'azstorage', 'azvaults', 'azvaultdiagnostics', 'aaddiagnostics',
        'azactivity', 'azalertrules', 'azkvsecrets', 'azkvkeys', 'azclassicadmins', 'azlocks', 'azautomation', 'azlogicapps', 'azwebapps',
        'azvms', 'azarc', 'azjit', 'azbastion', 'azautomationvars', 'azscriptscan', 'azworkspaces', 'azsentinel', 'azconnecthealth')
    $armScope = "$arm/user_impersonation offline_access openid profile"
    $armOk = $false
    Write-Event @{ type = 'start'; area = 'armsignin' }
    if ($SignIn -eq 'App') {
        try { Connect-App $arm; $armOk = $true }
        catch {
            $message = Get-FirstLine $_
            Write-Event @{ type = 'error'; area = 'armsignin'; message = $message }
            foreach ($a in $armAreas) { Write-Event @{ type = 'error'; area = $a; message = "Could not sign in to Azure Resource Manager: $message" } }
        }
    }
    elseif ($script:refreshToken) {
        $t = Request-Token @{ grant_type = 'refresh_token'; refresh_token = $script:refreshToken; scope = $armScope }
        if ($t.ok) { $scope = $armScope; Save-Token $t.answer; $armOk = $true }
    }
    if (-not $armOk -and $SignIn -ne 'App') {
        try {
            $ClientId = $azureCliClient
            $scope = $armScope
            if ($SignIn -eq 'DeviceCode') { Connect-WithDeviceCode } else { Connect-WithBrowser }
            Write-Event @{ type = 'signedin'; account = $account }
            $armOk = $true
        }
        catch {
            $message = Get-FirstLine $_
            Write-Event @{ type = 'error'; area = 'armsignin'; message = $message }
            foreach ($a in $armAreas) { Write-Event @{ type = 'error'; area = $a; message = "Could not sign in to Azure Resource Manager: $message" } }
        }
    }
    if ($armOk) {
        Write-Event @{ type = 'done'; area = 'armsignin'; count = 1 }
        $null = Export-GraphArea -Area 'azmgmtgroups' -Paths @("$arm/providers/Microsoft.Management/managementGroups?api-version=2021-04-01")
        $null = Export-GraphArea -Area 'azsubscriptions' -Paths @("$arm/subscriptions?api-version=2022-12-01")
        # Where Entra sends its sign-in and audit logs (tenant level).
        $null = Export-GraphArea -Area 'aaddiagnostics' -Paths @("$arm/providers/microsoft.aadiam/diagnosticSettings?api-version=2017-04-01")
        # Microsoft Entra Connect Health: registered services and their health.
        $null = Export-GraphArea -Area 'azconnecthealth' -Paths @("$arm/providers/Microsoft.ADHybridHealthService/services?api-version=2014-01-01")
        $subs = @(Read-AreaItem 'azsubscriptions' | Where-Object { $_.state -eq 'Enabled' } | ForEach-Object { $_.subscriptionId })
        $perSub = {
            param([string] $Path)
            @($subs | ForEach-Object { @{ parent = $_; path = "$arm/subscriptions/$_/$Path" } })
        }
        if ($subs.Count) {
            # Assignments at, above and below each subscription, so management
            # group and root assignments are included.
            $null = Export-GraphArea -Area 'azroleassignments' -Paths (& $perSub 'providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01')
            $null = Export-GraphArea -Area 'azroledefinitions' -Paths (& $perSub "providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01&`$filter=type eq 'CustomRole'")
            $null = Export-GraphArea -Area 'azeligible' -Paths (& $perSub 'providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=2020-10-01')
            # Active assignment schedules tell permanent assignments from PIM activations.
            $null = Export-GraphArea -Area 'azactive' -Paths (& $perSub 'providers/Microsoft.Authorization/roleAssignmentScheduleInstances?api-version=2020-10-01')
            $null = Export-GraphArea -Area 'azcontacts' -Paths (& $perSub 'providers/Microsoft.Security/securityContacts?api-version=2020-01-01-preview')
            $null = Export-GraphArea -Area 'azpricings' -Paths (& $perSub 'providers/Microsoft.Security/pricings?api-version=2024-01-01')
            $null = Export-GraphArea -Area 'azsecurescore' -Paths (& $perSub 'providers/Microsoft.Security/secureScores?api-version=2020-01-01')
            $null = Export-GraphArea -Area 'azdiagnostics' -Paths (& $perSub 'providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview')
            $null = Export-GraphArea -Area 'azlighthouse' -Paths (& $perSub 'providers/Microsoft.ManagedServices/registrationAssignments?api-version=2022-10-01&$expandRegistrationDefinition=true')
            $null = Export-GraphArea -Area 'azpolicies' -Paths (& $perSub 'providers/Microsoft.Authorization/policyAssignments?api-version=2022-06-01')
            $null = Export-GraphArea -Area 'azstorage' -Paths (& $perSub 'providers/Microsoft.Storage/storageAccounts?api-version=2023-05-01')
            $null = Export-GraphArea -Area 'azvaults' -Paths (& $perSub 'providers/Microsoft.KeyVault/vaults?api-version=2023-07-01')
            # Run Command and extension changes on VMs in the activity log, 30 days.
            $from = [DateTime]::UtcNow.AddDays(-30).ToString('yyyy-MM-ddTHH:mm:ssZ')
            $null = Export-GraphArea -Area 'azactivity' -MaxPages 5 -Paths (& $perSub "providers/Microsoft.Insights/eventtypes/management/values?api-version=2015-04-01&`$filter=eventTimestamp ge '$from' and resourceProvider eq 'Microsoft.Compute'&`$select=operationName,resourceId,caller,eventTimestamp,status")
            $null = Export-GraphArea -Area 'azalertrules' -Paths (& $perSub 'providers/Microsoft.Insights/scheduledQueryRules?api-version=2023-03-15-preview')
            $vaults = @(Read-AreaItem 'azvaults' | ForEach-Object { $_.id })
            if ($vaults.Count) {
                $null = Export-GraphArea -Area 'azvaultdiagnostics' -Paths @($vaults | ForEach-Object { @{ parent = $_; path = "$arm$_/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview" } })
            }
            else { Write-Event @{ type = 'done'; area = 'azvaultdiagnostics'; count = 0 } }
            # Secret and key metadata through the management plane: names,
            # dates, types and sizes. Values are never returned by these calls.
            $null = Export-GraphArea -Area 'azkvsecrets' -Paths @($vaults | ForEach-Object { @{ parent = $_; path = "$arm$_/secrets?api-version=2023-07-01" } })
            $null = Export-GraphArea -Area 'azkvkeys' -Paths @($vaults | ForEach-Object { @{ parent = $_; path = "$arm$_/keys?api-version=2023-07-01" } })
            $null = Export-GraphArea -Area 'azclassicadmins' -Paths (& $perSub 'providers/Microsoft.Authorization/classicAdministrators?api-version=2015-07-01')
            $null = Export-GraphArea -Area 'azlocks' -Paths (& $perSub 'providers/Microsoft.Authorization/locks?api-version=2020-05-01')
            $null = Export-GraphArea -Area 'azautomation' -Paths (& $perSub 'providers/Microsoft.Automation/automationAccounts?api-version=2023-11-01')
            $null = Export-GraphArea -Area 'azlogicapps' -Paths (& $perSub 'providers/Microsoft.Logic/workflows?api-version=2019-05-01&$top=100')
            $null = Export-GraphArea -Area 'azwebapps' -Paths (& $perSub 'providers/Microsoft.Web/sites?api-version=2023-12-01')
            $null = Export-GraphArea -Area 'azvms' -Paths (& $perSub 'providers/Microsoft.Compute/virtualMachines?api-version=2024-03-01')
            $null = Export-GraphArea -Area 'azarc' -Paths (& $perSub 'providers/Microsoft.HybridCompute/machines?api-version=2024-07-10')
            $null = Export-GraphArea -Area 'azjit' -Paths (& $perSub 'providers/Microsoft.Security/jitNetworkAccessPolicies?api-version=2020-01-01')
            # Microsoft Sentinel data connectors of each Log Analytics workspace.
            $null = Export-GraphArea -Area 'azworkspaces' -Paths (& $perSub 'providers/Microsoft.OperationalInsights/workspaces?api-version=2023-09-01')
            $workspaces = @(Read-AreaItem 'azworkspaces' | ForEach-Object { $_.id })
            $null = Export-GraphArea -Area 'azsentinel' -Paths @($workspaces | ForEach-Object { @{ parent = $_; path = "$arm$_/providers/Microsoft.SecurityInsights/dataConnectors?api-version=2023-02-01" } })
            $null = Export-GraphArea -Area 'azbastion' -Paths (& $perSub 'providers/Microsoft.Network/bastionHosts?api-version=2024-01-01')
            Export-CredentialScan
        }
        else {
            foreach ($a in $armAreas | Where-Object { $_ -notin 'azmgmtgroups', 'azsubscriptions', 'aaddiagnostics', 'azconnecthealth' }) { Write-Event @{ type = 'done'; area = $a; count = 0 } }
        }
    }
}

# Key Vault secret reads of 30 days, from the Log Analytics workspaces the
# vaults send their diagnostics to: one read-only query per workspace (the
# query API's GET form), counted per vault and caller.
if ($wanted -contains 'arm') {
    $la = 'https://api.loganalytics.io'
    $targets = @(Read-AreaItem 'azvaultdiagnostics' | ForEach-Object { $_.properties.workspaceId } | Where-Object { $_ } | Sort-Object -Unique)
    $customer = @{}
    foreach ($w in @(Read-AreaItem 'azworkspaces')) { $customer[([string]$w.id).ToLowerInvariant()] = [string]$w.properties.customerId }
    $ids = @($targets | ForEach-Object { $customer[([string]$_).ToLowerInvariant()] } | Where-Object { $_ })
    $kql = 'AzureDiagnostics | where ResourceProvider == "MICROSOFT.KEYVAULT" and OperationName == "SecretGet" | extend Caller = coalesce(identity_claim_appid_g, identity_claim_oid_g, CallerIPAddress) | summarize Reads = count(), First = min(TimeGenerated), Last = max(TimeGenerated) by Resource, Caller'
    if ($ids.Count) {
        Write-Event @{ type = 'start'; area = 'kvreadsignin' }
        try {
            if ($SignIn -eq 'App') { Connect-App $la }
            else {
                $laScope = "$la/Data.Read offline_access"
                $t = Request-Token @{ grant_type = 'refresh_token'; refresh_token = $script:refreshToken; scope = $laScope }
                if (-not $t.ok) { throw "Log Analytics sign-in failed: $($t.error)" }
                $scope = $laScope
                Save-Token $t.answer
            }
            Write-Event @{ type = 'done'; area = 'kvreadsignin'; count = 1 }
            $query = [Uri]::EscapeDataString($kql)
            $null = Export-GraphArea -Area 'kvreads' -Paths @($ids | ForEach-Object { @{ parent = $_; path = "$la/v1/workspaces/$_/query?timespan=P30D&query=$query" } })
        }
        catch {
            $message = Get-FirstLine $_
            Write-Event @{ type = 'error'; area = 'kvreadsignin'; message = $message }
            Write-Event @{ type = 'error'; area = 'kvreads'; message = "Could not query Log Analytics: $message" }
        }
    }
    else { Write-Event @{ type = 'done'; area = 'kvreads'; count = 0 } }
}

# Defender for Endpoint machines, through its own API with GET requests
# only. It needs its own token, as ARM does.
if ($wanted -contains 'defender') {
    $mde = 'https://api.securitycenter.microsoft.com'
    Write-Event @{ type = 'start'; area = 'mdesignin' }
    try {
        if ($SignIn -eq 'App') { Connect-App $mde }
        else {
            $mdeScope = "$mde/Machine.Read offline_access"
            $t = Request-Token @{ grant_type = 'refresh_token'; refresh_token = $script:refreshToken; scope = $mdeScope }
            if (-not $t.ok) { throw "Defender for Endpoint sign-in failed: $($t.error)" }
            $scope = $mdeScope
            Save-Token $t.answer
        }
        Write-Event @{ type = 'done'; area = 'mdesignin'; count = 1 }
        $null = Export-GraphArea -Area 'mdemachines' -MaxPages 20 -Paths @("$mde/api/machines")
    }
    catch {
        $message = Get-FirstLine $_
        Write-Event @{ type = 'error'; area = 'mdesignin'; message = $message }
        Write-Event @{ type = 'error'; area = 'mdemachines'; message = "Could not sign in to Defender for Endpoint: $message" }
    }
}

# Exchange Online, through Microsoft's ExchangeOnlineManagement module (3.0
# or later), which signs in on its own. Only Get- cmdlets are loaded
# (-CommandName), so the session cannot change anything. Each area is one
# JSON object per line with the listed properties only; values that are not
# booleans or numbers are written as text.
if ($wanted -contains 'exo') {
    $exoAreas = [ordered]@{
        exoorg = @{ cmd = { Get-OrganizationConfig }; fields = 'OAuth2ClientProfileEnabled', 'AuditDisabled', 'CustomerLockBoxEnabled', 'DefaultAuthenticationPolicy' }
        exotransport = @{ cmd = { Get-TransportConfig }; fields = 'SmtpClientAuthenticationDisabled' }
        exoadminaudit = @{ cmd = { Get-AdminAuditLogConfig }; fields = 'UnifiedAuditLogIngestionEnabled', 'AdminAuditLogEnabled' }
        exoaccepteddomains = @{ cmd = { Get-AcceptedDomain }; fields = 'DomainName', 'DomainType', 'Default' }
        exomailboxes = @{ cmd = { Get-EXOMailbox -ResultSize Unlimited -PropertySets Minimum -Properties ForwardingSmtpAddress, ForwardingAddress, DeliverToMailboxAndForward, LitigationHoldEnabled, GrantSendOnBehalfTo }
            fields = 'DisplayName', 'UserPrincipalName', 'PrimarySmtpAddress', 'RecipientTypeDetails', 'ExternalDirectoryObjectId', 'ForwardingSmtpAddress', 'ForwardingAddress', 'DeliverToMailboxAndForward', 'LitigationHoldEnabled', 'GrantSendOnBehalfTo' }
        exocas = @{ cmd = { Get-EXOCASMailbox -ResultSize Unlimited -PropertySets Minimum -Properties SmtpClientAuthenticationDisabled }
            fields = 'PrimarySmtpAddress', 'ExternalDirectoryObjectId', 'PopEnabled', 'ImapEnabled', 'ActiveSyncEnabled', 'EwsEnabled', 'SmtpClientAuthenticationDisabled' }
        exoauditbypass = @{ cmd = { Get-MailboxAuditBypassAssociation -ResultSize Unlimited | Where-Object { $_.AuditBypassEnabled } }; fields = 'Name', 'AuditBypassEnabled' }
        exoremotedomains = @{ cmd = { Get-RemoteDomain }; fields = 'Name', 'DomainName', 'AutoForwardEnabled' }
        exooutboundspam = @{ cmd = { Get-HostedOutboundSpamFilterPolicy }; fields = 'Name', 'IsDefault', 'AutoForwardingMode' }
        exooutboundspamrules = @{ cmd = { Get-HostedOutboundSpamFilterRule }; fields = 'Name', 'State', 'HostedOutboundSpamFilterPolicy' }
        exoappaccess = @{ cmd = { Get-ApplicationAccessPolicy }; fields = 'AppId', 'AccessRight', 'ScopeName', 'Description' }
        exoimpersonation = @{ cmd = { Get-ManagementRoleAssignment -Role ApplicationImpersonation }; fields = 'Name', 'RoleAssigneeName', 'RoleAssigneeType', 'Enabled', 'CustomRecipientWriteScope', 'RecipientWriteScope' }
        exorolegroups = @{ cmd = { Get-RoleGroup }; fields = 'Name', 'Members', 'RoleGroupType' }
        exoantiphish = @{ cmd = { Get-AntiPhishPolicy }; fields = 'Name', 'IsDefault', 'Enabled', 'EnableSpoofIntelligence', 'EnableMailboxIntelligence', 'EnableMailboxIntelligenceProtection', 'EnableTargetedUserProtection', 'EnableOrganizationDomainsProtection', 'EnableTargetedDomainsProtection', 'PhishThresholdLevel' }
        exoantiphishrules = @{ cmd = { Get-AntiPhishRule }; fields = 'Name', 'State', 'AntiPhishPolicy' }
        exosafelinks = @{ cmd = { Get-SafeLinksPolicy }; fields = 'Name', 'IsBuiltInProtection', 'EnableSafeLinksForEmail', 'EnableSafeLinksForTeams', 'EnableSafeLinksForOffice', 'ScanUrls', 'AllowClickThrough', 'TrackClicks', 'EnableForInternalSenders' }
        exosafelinksrules = @{ cmd = { Get-SafeLinksRule }; fields = 'Name', 'State', 'SafeLinksPolicy' }
        exosafeattach = @{ cmd = { Get-SafeAttachmentPolicy }; fields = 'Name', 'IsBuiltInProtection', 'Enable', 'Action', 'QuarantineTag' }
        exosafeattachrules = @{ cmd = { Get-SafeAttachmentRule }; fields = 'Name', 'State', 'SafeAttachmentPolicy' }
        exoatpo365 = @{ cmd = { Get-AtpPolicyForO365 }; fields = 'EnableATPForSPOTeamsODB', 'EnableSafeDocs', 'AllowSafeDocsOpen' }
        exomalware = @{ cmd = { Get-MalwareFilterPolicy }; fields = 'Name', 'IsDefault', 'EnableFileFilter', 'ZapEnabled', 'FileTypes', 'QuarantineTag' }
        exomalwarerules = @{ cmd = { Get-MalwareFilterRule }; fields = 'Name', 'State', 'MalwareFilterPolicy' }
        exocontentfilter = @{ cmd = { Get-HostedContentFilterPolicy }; fields = 'Name', 'IsDefault', 'BulkThreshold', 'MarkAsSpamBulkMail', 'AllowedSenders', 'AllowedSenderDomains', 'SpamZapEnabled', 'PhishZapEnabled', 'HighConfidencePhishQuarantineTag', 'PhishQuarantineTag', 'HighConfidenceSpamQuarantineTag' }
        exocontentfilterrules = @{ cmd = { Get-HostedContentFilterRule }; fields = 'Name', 'State', 'HostedContentFilterPolicy' }
        exotransportrules = @{ cmd = { Get-TransportRule -ResultSize Unlimited }; fields = 'Name', 'State', 'Mode', 'Priority', 'SetSCL', 'SetHeaderName', 'SetHeaderValue', 'RedirectMessageTo', 'BlindCopyTo', 'AddToRecipients', 'CopyTo', 'SenderDomainIs', 'FromAddressContainsWords', 'From', 'SenderIpRanges' }
        exoinbound = @{ cmd = { Get-InboundConnector }; fields = 'Name', 'Enabled', 'ConnectorType', 'ConnectorSource', 'RequireTls', 'RestrictDomainsToIPAddresses', 'RestrictDomainsToCertificate', 'TlsSenderCertificateName', 'SenderIPAddresses', 'SenderDomains' }
        exooutbound = @{ cmd = { Get-OutboundConnector }; fields = 'Name', 'Enabled', 'ConnectorType', 'UseMXRecord', 'SmartHosts', 'TlsSettings', 'TlsDomain', 'RecipientDomains', 'IsTransportRuleScoped' }
        exodkim = @{ cmd = { Get-DkimSigningConfig }; fields = 'Domain', 'Enabled', 'Status' }
        exopreset = @{ cmd = { Get-EOPProtectionPolicyRule }; fields = 'Name', 'State', 'Priority' }
        exoowa = @{ cmd = { Get-OwaMailboxPolicy }; fields = 'Name', 'IsDefault', 'AdditionalStorageProvidersAvailable', 'ConditionalAccessPolicy', 'ThirdPartyAttachmentsEnabled' }
        exosharing = @{ cmd = { Get-SharingPolicy }; fields = 'Name', 'Enabled', 'Default', 'Domains' }
        exoquarantine = @{ cmd = { Get-QuarantinePolicy }; fields = 'Name', 'EndUserQuarantinePermissions', 'EndUserQuarantinePermissionsValue', 'ESNEnabled', 'QuarantinePolicyType' }
        exodistgroups = @{ cmd = { Get-DistributionGroup -ResultSize Unlimited }; fields = 'Name', 'PrimarySmtpAddress', 'GroupType', 'MemberJoinRestriction', 'MemberDepartRestriction', 'ExternalDirectoryObjectId' }
        exosendas = @{ cmd = { Get-EXORecipientPermission -ResultSize Unlimited | Where-Object { $_.Trustee -ne 'NT AUTHORITY\SELF' } }; fields = 'Identity', 'Trustee', 'AccessRights' }
        # Per mailbox, for up to 500 user and shared mailboxes.
        exofullaccess = @{ cmd = { foreach ($m in @(Read-ExoMailboxId)) { Get-EXOMailboxPermission -Identity $m | Where-Object { -not $_.IsInherited -and $_.User -ne 'NT AUTHORITY\SELF' } } }
            fields = 'Identity', 'User', 'AccessRights' }
        exoinboxrules = @{ cmd = { foreach ($m in @(Read-ExoMailboxId)) { Get-InboxRule -Mailbox $m -WarningAction SilentlyContinue } }
            fields = 'MailboxOwnerId', 'Name', 'Enabled', 'ForwardTo', 'ForwardAsAttachmentTo', 'RedirectTo', 'DeleteMessage', 'SoftDeleteMessage', 'MoveToFolder', 'MarkAsRead', 'From', 'SubjectContainsWords' }
        # The unified audit log of 30 days: inbox rule changes, and file
        # downloads and anonymous links counted per user and day.
        exoualinbox = @{ cmd = { Search-UnifiedAuditLog -StartDate ([DateTime]::UtcNow.AddDays(-30)) -EndDate ([DateTime]::UtcNow) -Operations New-InboxRule, Set-InboxRule, UpdateInboxRules -ResultSize 5000 }
            fields = 'UserIds', 'Operations', 'CreationDate' }
        exoualfiles = @{ cmd = { Get-FileActivityCount }; fields = 'UserIds', 'Day', 'Operation', 'Count' }
    }
    # The ids of up to 500 user and shared mailboxes, from the mailbox area.
    function Read-ExoMailboxId {
        @(Read-AreaItem 'exomailboxes' | Where-Object { $_.RecipientTypeDetails -in 'UserMailbox', 'SharedMailbox' } | Select-Object -First 500 | ForEach-Object { $_.ExternalDirectoryObjectId })
    }
    function Get-FileActivityCount {
        $counts = @{}
        $session = [guid]::NewGuid().ToString()
        for ($page = 0; $page -lt 10; $page++) {
            $records = @(Search-UnifiedAuditLog -StartDate ([DateTime]::UtcNow.AddDays(-30)) -EndDate ([DateTime]::UtcNow) -Operations FileDownloaded, FileSyncDownloadedFull, AnonymousLinkCreated -SessionId $session -SessionCommand ReturnLargeSet -ResultSize 5000)
            foreach ($r in $records) {
                $key = '{0}|{1}|{2}' -f $r.UserIds, ([DateTime]$r.CreationDate).ToString('yyyy-MM-dd'), $r.Operations
                $counts[$key] = 1 + $(if ($counts.ContainsKey($key)) { $counts[$key] } else { 0 })
            }
            if ($records.Count -lt 5000) { break }
        }
        foreach ($k in $counts.Keys) {
            $u, $d, $o = $k -split '\|'
            [pscustomobject]@{ UserIds = $u; Day = $d; Operation = $o; Count = [int] $counts[$k] }
        }
    }
    $exoCommands = @('Get-OrganizationConfig', 'Get-TransportConfig', 'Get-AdminAuditLogConfig', 'Get-AcceptedDomain', 'Get-EXOMailbox',
        'Get-EXOCASMailbox', 'Get-MailboxAuditBypassAssociation', 'Get-RemoteDomain', 'Get-HostedOutboundSpamFilterPolicy',
        'Get-HostedOutboundSpamFilterRule', 'Get-ApplicationAccessPolicy', 'Get-ManagementRoleAssignment', 'Get-RoleGroup',
        'Get-AntiPhishPolicy', 'Get-AntiPhishRule', 'Get-SafeLinksPolicy', 'Get-SafeLinksRule', 'Get-SafeAttachmentPolicy',
        'Get-SafeAttachmentRule', 'Get-AtpPolicyForO365', 'Get-MalwareFilterPolicy', 'Get-MalwareFilterRule',
        'Get-HostedContentFilterPolicy', 'Get-HostedContentFilterRule', 'Get-TransportRule', 'Get-InboundConnector',
        'Get-OutboundConnector', 'Get-DkimSigningConfig', 'Get-EOPProtectionPolicyRule', 'Get-OwaMailboxPolicy', 'Get-SharingPolicy',
        'Get-QuarantinePolicy', 'Get-DistributionGroup', 'Get-EXORecipientPermission', 'Get-EXOMailboxPermission', 'Get-InboxRule', 'Search-UnifiedAuditLog')

    $exoAreaNames = @($exoAreas.Keys) + @('exodns')
    $failExo = {
        param([string] $Message)
        foreach ($a in $exoAreaNames) { Write-Event @{ type = 'error'; area = $a; message = $Message } }
    }
    $module = Get-Module -ListAvailable -Name ExchangeOnlineManagement | Sort-Object Version -Descending | Select-Object -First 1
    if (-not $module -or $module.Version.Major -lt 3) {
        & $failExo 'The ExchangeOnlineManagement module (version 3 or later) is not installed on this computer. Install it from the PowerShell Gallery and run the assessment again.'
    }
    else {
        $exoConnected = $false
        Write-Event @{ type = 'start'; area = 'exosignin' }
        try {
            Import-Module $module.Path -ErrorAction Stop
            $connect = @{ ShowBanner = $false; CommandName = $exoCommands; ErrorAction = 'Stop' }
            if ($SignIn -eq 'App') {
                if (-not $CertificatePath) { throw 'Exchange Online app sign-in needs a certificate (-CertificatePath).' }
                $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertificatePath, $(if ($env:DCA_CERT_PASSWORD) { $env:DCA_CERT_PASSWORD } else { '' }))
                $organization = @(Read-AreaItem 'domains' | Where-Object { $_.isInitial } | ForEach-Object { $_.id })[0]
                Connect-ExchangeOnline @connect -AppId $ClientId -Certificate $cert -Organization $organization
            }
            elseif ($SignIn -eq 'DeviceCode') {
                # The module prints the code; pass it on as a sign-in event.
                Connect-ExchangeOnline @connect -Device 6>&1 | ForEach-Object {
                    if ("$_" -match '\b([A-Z0-9]{8,9})\b' -and "$_" -match 'microsoft\.com/devicelogin') {
                        Write-Event @{ type = 'signin'; url = 'https://microsoft.com/devicelogin'; code = $Matches[1] }
                    }
                }
            }
            else { Connect-ExchangeOnline @connect -UserPrincipalName $account 6>$null }
            $exoConnected = $true
            Write-Event @{ type = 'signedin'; account = $account }
            Write-Event @{ type = 'done'; area = 'exosignin'; count = 1 }
        }
        catch {
            Write-Event @{ type = 'error'; area = 'exosignin'; message = (Get-FirstLine $_) }
            & $failExo "Could not sign in to Exchange Online: $(Get-FirstLine $_)"
        }
        if ($exoConnected) {
            try {
                foreach ($name in $exoAreas.Keys) { $null = Export-ModuleArea $name $exoAreas[$name].cmd $exoAreas[$name].fields }

                # SPF, DMARC, MTA-STS and TLS-RPT records of each accepted
                # domain, from this computer's DNS resolver. A name that does
                # not resolve gives an empty list.
                Write-Event @{ type = 'start'; area = 'exodns' }
                try {
                    $txt = {
                        param([string] $Name)
                        try { Resolve-DnsName -Name $Name -Type TXT -DnsOnly -ErrorAction Stop | Where-Object { $_.Type -eq 'TXT' } | ForEach-Object { $_.Strings -join '' } }
                        catch { $null = $_ }
                    }
                    $lines = New-Object System.Collections.Generic.List[string]
                    foreach ($d in @(Get-AcceptedDomain | ForEach-Object { [string] $_.DomainName })) {
                        $row = [ordered]@{
                            domain = $d
                            spf = @(& $txt $d | Where-Object { $_ -match '^v=spf1(\s|$)' })
                            dmarc = @(& $txt "_dmarc.$d" | Where-Object { $_ -match '^v=DMARC1' })
                            mtasts = @(& $txt "_mta-sts.$d" | Where-Object { $_ -match '^v=STSv1' })
                            tlsrpt = @(& $txt "_smtp._tls.$d" | Where-Object { $_ -match '^v=TLSRPTv1' })
                        }
                        $lines.Add((ConvertTo-Json -InputObject $row -Compress -Depth 3))
                    }
                    [System.IO.File]::WriteAllLines((Join-Path $OutDir 'exodns.jsonl'), $lines, $utf8)
                    Write-Event @{ type = 'done'; area = 'exodns'; count = $lines.Count }
                }
                catch { Write-Event @{ type = 'error'; area = 'exodns'; message = (Get-FirstLine $_) } }
            }
            finally { try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue 6>$null } catch { $null = $_ } }
        }
    }
}

# Runs one Microsoft module's areas: imports only the listed cmdlets (all
# Get- plus the module's own Connect- and Disconnect-), signs in with
# $Connect, exports each area with Export-ModuleArea, then runs $Extra.
function Invoke-ModuleSource {
    param([string] $Source, [string] $Module, [string] $Minimum, [string[]] $Commands, [System.Collections.Specialized.OrderedDictionary] $Areas,
        [string[]] $ExtraAreas, [scriptblock] $Connect, [scriptblock] $Extra, [scriptblock] $Disconnect)
    $names = @($Areas.Keys) + @($ExtraAreas)
    $fail = { param([string] $Message) foreach ($a in $names) { Write-Event @{ type = 'error'; area = $a; message = $Message } } }
    $found = Get-Module -ListAvailable -Name $Module | Sort-Object Version -Descending | Select-Object -First 1
    if (-not $found -or ($Minimum -and $found.Version -lt [version] $Minimum)) {
        & $fail "The $Module module$(if ($Minimum) { " (version $Minimum or later)" }) is not installed on this computer. Install it from the PowerShell Gallery and run the assessment again."
        return
    }
    Write-Event @{ type = 'start'; area = "${Source}signin" }
    try {
        Import-Module $found.Path -Cmdlet $Commands -Function $Commands -ErrorAction Stop -WarningAction SilentlyContinue
        & $Connect
        Write-Event @{ type = 'done'; area = "${Source}signin"; count = 1 }
    }
    catch {
        Write-Event @{ type = 'error'; area = "${Source}signin"; message = (Get-FirstLine $_) }
        & $fail "Could not sign in to $Module`: $(Get-FirstLine $_)"
        return
    }
    try {
        foreach ($name in $Areas.Keys) { $null = Export-ModuleArea $name $Areas[$name].cmd $Areas[$name].fields }
        if ($Extra) { & $Extra }
    }
    finally { try { & $Disconnect } catch { $null = $_ } }
}

# The tenant's initial domain prefix (contoso for contoso.onmicrosoft.com).
$initialDomain = @(Read-AreaItem 'domains' | Where-Object { $_.isInitial } | ForEach-Object { $_.id })[0]
$tenantPrefix = if ($initialDomain) { ($initialDomain -split '\.')[0] } else { '' }

# SharePoint Online and OneDrive, through Microsoft.Online.SharePoint.PowerShell.
if ($wanted -contains 'spo') {
    $spoAreas = [ordered]@{
        spotenant = @{ cmd = { Get-SPOTenant }; fields = 'SharingCapability', 'OneDriveSharingCapability', 'DefaultSharingLinkType', 'DefaultLinkPermission',
            'FileAnonymousLinkType', 'FolderAnonymousLinkType', 'RequireAnonymousLinksExpireInDays', 'ExternalUserExpirationRequired',
            'ExternalUserExpireInDays', 'EmailAttestationRequired', 'EmailAttestationReAuthDays', 'SharingDomainRestrictionMode',
            'SharingAllowedDomainList', 'SharingBlockedDomainList', 'LegacyAuthProtocolsEnabled', 'ConditionalAccessPolicy',
            'DisallowInfectedFileDownload', 'OrphanedPersonalSitesRetentionPeriod', 'PreventExternalUsersFromResharing',
            'ShowEveryoneExceptExternalUsersClaim', 'ShowAllUsersClaim', 'EnableAIPIntegration', 'DenyAddAndCustomizePages' }
        spoidle = @{ cmd = { Get-SPOBrowserIdleSignOut }; fields = 'Enabled', 'WarnAfter', 'SignOutAfter' }
        sposync = @{ cmd = { Get-SPOTenantSyncClientRestriction }; fields = 'TenantRestrictionEnabled', 'AllowedDomainList', 'BlockMacSync' }
        sposites = @{ cmd = { Get-SPOSite -Limit All }; fields = 'Url', 'Title', 'Template', 'Owner', 'SharingCapability', 'DenyAddAndCustomizePages',
            'SensitivityLabel', 'ConditionalAccessPolicy', 'GroupId', 'LockState', 'IsTeamsConnected' }
    }
    # Site administrators and broad grants ("Everyone", "Everyone except
    # external users") of up to 200 sites: who is listed, not what they read.
    $spoUsers = {
        Write-Event @{ type = 'start'; area = 'spositeusers' }
        try {
            $lines = New-Object System.Collections.Generic.List[string]
            $sites = @(Read-AreaItem 'sposites' | Where-Object { $_.Template -notmatch '^(SPSPERS|REDIRECTSITE|APPCATALOG)' } | Select-Object -First 200)
            foreach ($site in $sites) {
                foreach ($u in @(Get-SPOUser -Site $site.Url -Limit All)) {
                    $broad = $u.LoginName -match 'spo-grid-all-users|^c:0\(\.s\|true$|^c:0-\.f\|rolemanager\|'
                    if ($u.IsSiteAdmin -or $broad) {
                        $row = ConvertTo-PlainObject $u 'LoginName', 'DisplayName', 'IsSiteAdmin', 'IsGroup', 'UserType'
                        $row['Site'] = [string] $site.Url
                        $row['Broad'] = [bool] $broad
                        $lines.Add((ConvertTo-Json -InputObject $row -Compress))
                    }
                }
            }
            [System.IO.File]::WriteAllLines((Join-Path $OutDir 'spositeusers.jsonl'), $lines, $utf8)
            Write-Event @{ type = 'done'; area = 'spositeusers'; count = $lines.Count }
        }
        catch { Write-Event @{ type = 'error'; area = 'spositeusers'; message = (Get-FirstLine $_) } }
    }
    Invoke-ModuleSource -Source 'spo' -Module 'Microsoft.Online.SharePoint.PowerShell' -Areas $spoAreas -ExtraAreas 'spositeusers' -Extra $spoUsers `
        -Commands 'Connect-SPOService', 'Disconnect-SPOService', 'Get-SPOTenant', 'Get-SPOBrowserIdleSignOut', 'Get-SPOTenantSyncClientRestriction', 'Get-SPOSite', 'Get-SPOUser' `
        -Connect {
            if ($SignIn -ne 'Browser') { throw 'SharePoint Online is read with an interactive sign-in only (-SignIn Browser).' }
            Connect-SPOService -Url "https://$tenantPrefix-admin.sharepoint.com" -ErrorAction Stop
        } -Disconnect { Disconnect-SPOService }
}

# Microsoft Teams, through the MicrosoftTeams module.
if ($wanted -contains 'teams') {
    $teamsAreas = [ordered]@{
        tmsfederation = @{ cmd = { Get-CsTenantFederationConfiguration }; fields = 'AllowFederatedUsers', 'AllowedDomains', 'BlockedDomains', 'AllowTeamsConsumer',
            'AllowTeamsConsumerInbound', 'AllowPublicUsers' }
        tmsclient = @{ cmd = { Get-CsTeamsClientConfiguration }; fields = 'Identity', 'AllowGuestUser', 'AllowEmailIntoChannel', 'RestrictedSenderList',
            'AllowDropBox', 'AllowBox', 'AllowGoogleDrive', 'AllowShareFile', 'AllowEgnyte' }
        tmsmeetingconfig = @{ cmd = { Get-CsTeamsMeetingConfiguration }; fields = 'Identity', 'DisableAnonymousJoin' }
        tmsmeeting = @{ cmd = { Get-CsTeamsMeetingPolicy }; fields = 'Identity', 'AllowAnonymousUsersToJoinMeeting', 'AllowAnonymousUsersToStartMeeting',
            'AutoAdmittedUsers', 'AllowPSTNUsersToBypassLobby', 'AllowCloudRecording', 'NewMeetingRecordingExpirationDays', 'AllowExternalParticipantGiveRequestControl' }
        tmsguestmeeting = @{ cmd = { Get-CsTeamsGuestMeetingConfiguration }; fields = 'AllowIPVideo', 'ScreenSharingMode', 'AllowMeetNow' }
        tmsguestmessaging = @{ cmd = { Get-CsTeamsGuestMessagingConfiguration }; fields = 'AllowUserEditMessage', 'AllowUserDeleteMessage', 'AllowUserChat', 'AllowGiphy' }
        tmsappsetup = @{ cmd = { Get-CsTeamsAppSetupPolicy }; fields = 'Identity', 'AllowSideLoading', 'AllowUserPinning' }
        tmsapppermission = @{ cmd = { Get-CsTeamsAppPermissionPolicy }; fields = 'Identity', 'DefaultCatalogAppsType', 'GlobalCatalogAppsType', 'PrivateCatalogAppsType',
            'DefaultCatalogApps', 'GlobalCatalogApps', 'PrivateCatalogApps' }
    }
    Invoke-ModuleSource -Source 'tms' -Module 'MicrosoftTeams' -Minimum '5.0' -Areas $teamsAreas `
        -Commands 'Connect-MicrosoftTeams', 'Disconnect-MicrosoftTeams', 'Get-CsTenantFederationConfiguration', 'Get-CsTeamsClientConfiguration',
            'Get-CsTeamsMeetingConfiguration', 'Get-CsTeamsMeetingPolicy', 'Get-CsTeamsGuestMeetingConfiguration', 'Get-CsTeamsGuestMessagingConfiguration',
            'Get-CsTeamsAppSetupPolicy', 'Get-CsTeamsAppPermissionPolicy' `
        -Connect {
            if ($SignIn -eq 'App') {
                if (-not $CertificatePath) { throw 'Teams app sign-in needs a certificate (-CertificatePath).' }
                $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertificatePath, $(if ($env:DCA_CERT_PASSWORD) { $env:DCA_CERT_PASSWORD } else { '' }))
                $null = Connect-MicrosoftTeams -ApplicationId $ClientId -Certificate $cert -TenantId ([string] $claims.tid) -ErrorAction Stop
            }
            elseif ($SignIn -eq 'DeviceCode') { $null = Connect-MicrosoftTeams -UseDeviceAuthentication -ErrorAction Stop }
            else { $null = Connect-MicrosoftTeams -ErrorAction Stop }
        } -Disconnect { Disconnect-MicrosoftTeams }
}

# Microsoft Purview, through Security & Compliance PowerShell
# (Connect-IPPSSession in ExchangeOnlineManagement).
if ($wanted -contains 'purview') {
    $roleMembers = {
        foreach ($g in @(Get-RoleGroup)) {
            [pscustomobject]@{ Name = $g.Name; Roles = @($g.Roles | ForEach-Object { ($_ -split '\\')[-1] }); Members = @(Get-RoleGroupMember -Identity $g.Identity | ForEach-Object { $_.Name }) }
        }
    }
    $purAreas = [ordered]@{
        purlabels = @{ cmd = { Get-Label }; fields = 'Name', 'DisplayName', 'Disabled', 'ContentType', 'Priority' }
        purlabelpolicies = @{ cmd = { Get-LabelPolicy }; fields = 'Name', 'Enabled', 'Mode', 'Labels', 'Settings', 'ExchangeLocation', 'ModernGroupLocation' }
        purautolabel = @{ cmd = { Get-AutoSensitivityLabelPolicy }; fields = 'Name', 'Enabled', 'Mode', 'ApplySensitivityLabel', 'WhenCreatedUTC' }
        purdlp = @{ cmd = { Get-DlpCompliancePolicy }; fields = 'Name', 'Enabled', 'Mode', 'Workload', 'ExchangeLocation', 'SharePointLocation',
            'OneDriveLocation', 'TeamsLocation', 'EndpointDlpLocation', 'WhenCreatedUTC', 'WhenChangedUTC' }
        purretention = @{ cmd = { Get-RetentionCompliancePolicy }; fields = 'Name', 'Enabled', 'Mode', 'Workload', 'ExchangeLocation', 'SharePointLocation',
            'OneDriveLocation', 'ModernGroupLocation', 'TeamsChannelLocation', 'TeamsChatLocation' }
        puralerts = @{ cmd = { Get-ProtectionAlert }; fields = 'Name', 'Severity', 'Disabled', 'IsSystemRule', 'Category' }
        purrolegroups = @{ cmd = $roleMembers; fields = 'Name', 'Roles', 'Members' }
        purcaseadmins = @{ cmd = { Get-eDiscoveryCaseAdmin }; fields = 'Name', 'PrimarySmtpAddress' }
        pursecurityfilters = @{ cmd = { Get-ComplianceSecurityFilter }; fields = 'FilterName', 'Action', 'Users', 'Filters' }
        purauditretention = @{ cmd = { Get-UnifiedAuditLogRetentionPolicy }; fields = 'Name', 'RetentionDuration', 'Enabled', 'Priority' }
        purbarriers = @{ cmd = { Get-InformationBarrierPolicy }; fields = 'Name', 'State' }
        purinsider = @{ cmd = { Get-InsiderRiskPolicy }; fields = 'Name', 'Enabled', 'InsiderRiskScenario' }
        purcommunication = @{ cmd = { Get-SupervisoryReviewPolicyV2 }; fields = 'Name', 'Enabled' }
    }
    $purCommands = @('Connect-IPPSSession', 'Disconnect-ExchangeOnline', 'Get-Label', 'Get-LabelPolicy', 'Get-AutoSensitivityLabelPolicy', 'Get-DlpCompliancePolicy',
        'Get-RetentionCompliancePolicy', 'Get-ProtectionAlert', 'Get-RoleGroup', 'Get-RoleGroupMember', 'Get-eDiscoveryCaseAdmin', 'Get-ComplianceSecurityFilter',
        'Get-UnifiedAuditLogRetentionPolicy', 'Get-InformationBarrierPolicy', 'Get-InsiderRiskPolicy', 'Get-SupervisoryReviewPolicyV2')
    Invoke-ModuleSource -Source 'pur' -Module 'ExchangeOnlineManagement' -Minimum '3.0' -Areas $purAreas -Commands $purCommands `
        -Connect {
            # Only the Get- cmdlets come through into the remote session.
            $connect = @{ ShowBanner = $false; ErrorAction = 'Stop'; CommandName = @($purCommands | Where-Object { $_ -like 'Get-*' }) }
            if ($SignIn -eq 'App') {
                if (-not $CertificatePath) { throw 'Purview app sign-in needs a certificate (-CertificatePath).' }
                $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertificatePath, $(if ($env:DCA_CERT_PASSWORD) { $env:DCA_CERT_PASSWORD } else { '' }))
                Connect-IPPSSession @connect -AppId $ClientId -Certificate $cert -Organization $initialDomain
            }
            else { Connect-IPPSSession @connect -UserPrincipalName $account 6>$null }
        } -Disconnect { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue 6>$null }
}

Write-Event @{ type = 'finished'; finished_at = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ') }

if ($Bundle) {
    $script:eventLog = $null
    Compress-Archive -Path (Join-Path $OutDir '*') -DestinationPath $Bundle -Force
    [Console]::Out.WriteLine((ConvertTo-Json -InputObject @{ type = 'bundle'; path = $Bundle } -Compress))
}
