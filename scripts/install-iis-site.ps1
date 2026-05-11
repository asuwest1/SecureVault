<#
.SYNOPSIS
    Creates the IIS site that reverse-proxies HTTPS traffic to the SecureVault
    Kestrel backend on http://127.0.0.1:8080.

.DESCRIPTION
    Prerequisites (install once on the server):
      - IIS role with these features:
            Web-Server, Web-WebServer, Web-Common-Http, Web-Static-Content,
            Web-Default-Doc, Web-Http-Errors, Web-Http-Logging, Web-Filtering,
            Web-Http-Redirect, Web-Performance, Web-Stat-Compression,
            Web-Dyn-Compression, Web-Mgmt-Tools
      - URL Rewrite (https://www.iis.net/downloads/microsoft/url-rewrite)
      - Application Request Routing (ARR) 3.0
            (https://www.iis.net/downloads/microsoft/application-request-routing)

    This script:
      1. Enables ARR as a reverse proxy at the server level.
      2. Creates the SecureVault IIS site bound to HTTPS with the supplied cert.
      3. Drops a web.config that:
            - rewrites all inbound requests to http://127.0.0.1:8080
            - adds HSTS, CSP, X-Frame-Options, Referrer-Policy, X-Content-Type-Options
            - disables response compression on HTTPS (CRIME/BREACH mitigation)
            - forwards X-Forwarded-For / X-Forwarded-Proto
            - limits request body to 10 MB

.PARAMETER CertThumbprint
    Thumbprint of the TLS cert in LocalMachine\My to bind to the HTTPS endpoint.

.PARAMETER HostName
    Public host header for the binding, e.g. vault.example.com.

.PARAMETER SitePath
    Filesystem path that IIS will use as the site's physical root. Only contains
    web.config; the SPA bundle is served by Kestrel from the publish directory.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$CertThumbprint,
    [Parameter(Mandatory=$true)][string]$HostName,
    [string]$SiteName = 'SecureVault',
    [string]$SitePath = 'C:\inetpub\SecureVault'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module WebAdministration

# ─── 1. Enable ARR proxy at server level ───────────────────────────────────────
$psPath = 'MACHINE/WEBROOT/APPHOST'
Set-WebConfigurationProperty -PSPath $psPath -Filter 'system.webServer/proxy' -Name 'enabled' -Value 'true' -ErrorAction SilentlyContinue
# Suppress the Via header and forward the client's scheme.
Set-WebConfigurationProperty -PSPath $psPath -Filter 'system.webServer/proxy' -Name 'preserveHostHeader' -Value 'true' -ErrorAction SilentlyContinue

# ─── 2. Filesystem layout + web.config ─────────────────────────────────────────
New-Item -ItemType Directory -Force -Path $SitePath | Out-Null
$webConfig = Join-Path $PSScriptRoot 'iis-web.config'
if (-not (Test-Path -LiteralPath $webConfig)) { throw "Template not found: $webConfig" }
Copy-Item -LiteralPath $webConfig -Destination (Join-Path $SitePath 'web.config') -Force

# Grant IIS_IUSRS read on the site root.
& icacls.exe $SitePath /grant:r 'BUILTIN\IIS_IUSRS:(OI)(CI)RX' | Out-Null

# ─── 3. Create app pool + site ─────────────────────────────────────────────────
if (Get-Item "IIS:\AppPools\$SiteName" -ErrorAction SilentlyContinue) {
    Remove-WebAppPool -Name $SiteName
}
New-WebAppPool -Name $SiteName | Out-Null
Set-ItemProperty "IIS:\AppPools\$SiteName" -Name managedRuntimeVersion -Value ''     # No managed runtime — ARR proxy only
Set-ItemProperty "IIS:\AppPools\$SiteName" -Name startMode -Value AlwaysRunning
Set-ItemProperty "IIS:\AppPools\$SiteName" -Name autoStart -Value $true

if (Get-Website -Name $SiteName -ErrorAction SilentlyContinue) {
    Remove-Website -Name $SiteName
}
New-Website -Name $SiteName -PhysicalPath $SitePath -ApplicationPool $SiteName `
            -HostHeader $HostName -Port 443 -Ssl | Out-Null

# Bind the cert.
$binding = Get-WebBinding -Name $SiteName -Protocol https
$binding.AddSslCertificate($CertThumbprint, 'My')

# Optional: HTTP→HTTPS redirect binding on port 80.
New-WebBinding -Name $SiteName -Protocol http -Port 80 -HostHeader $HostName -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "IIS site '$SiteName' created and bound to https://$HostName"
Write-Host "Verify with:  Invoke-WebRequest https://$HostName/api/v1/setup/status -UseBasicParsing"
