<#
.SYNOPSIS
    Installs SecureVault as a Windows Service.

.DESCRIPTION
    Creates the SecureVault service running under the local "SecureVault"
    virtual service account, lays out C:\ProgramData\SecureVault directories
    with restrictive ACLs, and registers the service for delayed-auto start.

    Hosting model: IIS reverse-proxy → Kestrel listening on http://127.0.0.1:8080.
    This script installs the *backend* service only. The IIS site that fronts it
    is created by install-iis-site.ps1.

.PARAMETER InstallDir
    Where the published API binaries (SecureVault.Api.dll + deps) live.
    Default: C:\Program Files\SecureVault
#>

[CmdletBinding()]
param(
    [string]$ServiceName  = 'SecureVault',
    [string]$DisplayName  = 'SecureVault API',
    [string]$InstallDir   = 'C:\Program Files\SecureVault',
    [string]$DataDir      = 'C:\ProgramData\SecureVault',
    [string]$EnvFile      = 'C:\ProgramData\SecureVault\securevault.env'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrators')) {
    throw "This script must be run from an elevated PowerShell prompt (Run as Administrator)."
}

# ─── 1. Directory layout ───────────────────────────────────────────────────────
$secretsDir = Join-Path $DataDir 'secrets'
$logsDir    = Join-Path $DataDir 'logs'
$keyringDir = Join-Path $DataDir 'keyring'
$backupsDir = Join-Path $DataDir 'backups'
foreach ($d in @($DataDir, $secretsDir, $logsDir, $keyringDir, $backupsDir, $InstallDir)) {
    New-Item -ItemType Directory -Force -Path $d | Out-Null
}

# ─── 2. Service account & ACLs ─────────────────────────────────────────────────
# Use the virtual service SID "NT SERVICE\<service name>" — created automatically
# when the service is registered with `sc.exe create ... obj= "NT SERVICE\<name>"`.
$svcSid = "NT SERVICE\$ServiceName"

Write-Host "Applying ACLs to $DataDir ..."
# Install dir: service reads only.
& icacls.exe $InstallDir /inheritance:r `
    /grant:r "BUILTIN\Administrators:(OI)(CI)F" "NT AUTHORITY\SYSTEM:(OI)(CI)F" "$svcSid:(OI)(CI)RX" `
    /remove "Users" "Authenticated Users" | Out-Null

# Data dir: service has full control on logs/keyring, read-only on secrets.
& icacls.exe $DataDir /inheritance:r `
    /grant:r "BUILTIN\Administrators:(OI)(CI)F" "NT AUTHORITY\SYSTEM:(OI)(CI)F" | Out-Null
& icacls.exe $logsDir    /grant:r "$svcSid:(OI)(CI)M" | Out-Null
& icacls.exe $keyringDir /grant:r "$svcSid:(OI)(CI)M" | Out-Null
& icacls.exe $backupsDir /grant:r "$svcSid:(OI)(CI)M" | Out-Null
# Secrets: READ-ONLY for service, no inheritance, no Users.
& icacls.exe $secretsDir /inheritance:r `
    /grant:r "BUILTIN\Administrators:(OI)(CI)F" "NT AUTHORITY\SYSTEM:(OI)(CI)F" "$svcSid:(OI)(CI)R" `
    /remove "Users" "Authenticated Users" | Out-Null

# ─── 3. Create/refresh service ────────────────────────────────────────────────
$dotnet = (Get-Command dotnet -ErrorAction Stop).Source
$dll    = Join-Path $InstallDir 'SecureVault.Api.dll'
if (-not (Test-Path -LiteralPath $dll)) {
    Write-Warning "$dll not found. Publish the API to $InstallDir before starting the service."
}

if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Write-Host "Stopping existing $ServiceName service ..."
    Stop-Service -Name $ServiceName -ErrorAction SilentlyContinue
    & sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}

# binPath quoting matters: use the call operator and let PS quote each arg.
$binPath = "`"$dotnet`" `"$dll`""
& sc.exe create $ServiceName binPath= "$binPath" start= delayed-auto obj= "$svcSid" DisplayName= "$DisplayName" | Out-Null
& sc.exe description $ServiceName "SecureVault on-premises secrets management API" | Out-Null
& sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null

# Environment variables (read by ASP.NET Core): set on the service via the registry
# Environment value, populated from the env file.
if (Test-Path -LiteralPath $EnvFile) {
    $envBlock = (Get-Content -LiteralPath $EnvFile | Where-Object { $_ -and $_ -notmatch '^\s*#' })
    $regPath  = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
    New-ItemProperty -Path $regPath -Name Environment -PropertyType MultiString -Value $envBlock -Force | Out-Null
    Write-Host "Loaded $($envBlock.Count) environment variables from $EnvFile into the service."
} else {
    Write-Warning "Env file $EnvFile not found — service will start without environment overrides."
}

Write-Host ""
Write-Host "Service '$ServiceName' installed."
Write-Host "Start with:  Start-Service $ServiceName"
Write-Host "Logs:        Get-EventLog -LogName Application -Source $ServiceName -Newest 50"
