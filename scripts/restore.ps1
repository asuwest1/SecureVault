<#
.SYNOPSIS
    Restores a SecureVault backup produced by backup.ps1.

.DESCRIPTION
    Verifies the AES-256-GCM authentication tag, extracts the bundle, restores
    the MEK key file FIRST (so the app cannot start partial), then restores the
    database with RESTORE DATABASE ... WITH REPLACE.

    The application service MUST be stopped before running this script:
        Stop-Service SecureVault

.PARAMETER BackupFile
    Path to the .svbk file produced by backup.ps1.

.PARAMETER VerifyOnly
    Verify the backup's authentication tag and manifest checksums without
    overwriting the live MEK or database.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$BackupFile,
    [string]$MekDest        = $env:SECUREVAULT_KEY_FILE          ?? 'C:\ProgramData\SecureVault\secrets\securevault-mek.bin',
    [string]$PassphraseFile = $env:SECUREVAULT_BACKUP_PASSPHRASE ?? 'C:\ProgramData\SecureVault\secrets\backup-passphrase.txt',
    [string]$SqlServer      = $env:SECUREVAULT_DB_SERVER         ?? 'localhost',
    [string]$Database       = $env:SECUREVAULT_DB_NAME           ?? 'securevault',
    [switch]$VerifyOnly
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Stamp([string]$Message) {
    Write-Host ("[{0:HH:mm:ss}] {1}" -f (Get-Date).ToUniversalTime(), $Message)
}

if (-not (Test-Path -LiteralPath $BackupFile))     { throw "Backup file not found: $BackupFile" }
if (-not (Test-Path -LiteralPath $PassphraseFile)) { throw "Passphrase file not found: $PassphraseFile" }
if ($Database -notmatch '^[A-Za-z_][A-Za-z0-9_]*$') { throw "Invalid database name: $Database" }

$workDir = Join-Path ([System.IO.Path]::GetTempPath()) ("svrs-" + [guid]::NewGuid())
New-Item -ItemType Directory -Force -Path $workDir | Out-Null

try {
    # ─── 1. Parse container, verify GCM tag, decrypt ───────────────────────────
    Write-Stamp "Reading backup envelope..."
    $bytes = [System.IO.File]::ReadAllBytes($BackupFile)
    if ($bytes.Length -lt (4+1+4+16+12+16)) { throw "Backup file is truncated." }
    $magic = [System.Text.Encoding]::ASCII.GetString($bytes, 0, 4)
    if ($magic -ne 'SVBK') { throw "Not a SecureVault backup (bad magic)." }
    if ($bytes[4] -ne 1)   { throw "Unsupported backup format version: $($bytes[4])" }
    $iterBytes = $bytes[5..8]
    if ([System.BitConverter]::IsLittleEndian) { [Array]::Reverse($iterBytes) }
    $iterations = [System.BitConverter]::ToInt32($iterBytes, 0)
    $salt   = $bytes[9..24]
    $nonce  = $bytes[25..36]
    $tag    = $bytes[37..52]
    $cipher = $bytes[53..($bytes.Length-1)]

    $passphrase = (Get-Content -LiteralPath $PassphraseFile -Raw).Trim()
    $kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($passphrase, [byte[]]$salt, $iterations, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    try { $key = $kdf.GetBytes(32) } finally { $kdf.Dispose() }

    $plain = New-Object byte[] $cipher.Length
    $gcm = New-Object System.Security.Cryptography.AesGcm($key, 16)
    try {
        $gcm.Decrypt([byte[]]$nonce, [byte[]]$cipher, [byte[]]$tag, $plain)
    } catch {
        throw "Backup authentication failed — wrong passphrase or tampered file."
    } finally { $gcm.Dispose() }
    [System.Security.Cryptography.CryptographicOperations]::ZeroMemory($key)
    Write-Stamp "Authentication tag verified."

    $zipPath = Join-Path $workDir 'bundle.zip'
    [System.IO.File]::WriteAllBytes($zipPath, $plain)
    Expand-Archive -LiteralPath $zipPath -DestinationPath $workDir -Force
    Remove-Item -LiteralPath $zipPath -Force

    # ─── 2. Verify manifest checksums ──────────────────────────────────────────
    $manifestPath = Join-Path $workDir 'manifest.json'
    if (Test-Path -LiteralPath $manifestPath) {
        $m = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        $dbHash  = (Get-FileHash -LiteralPath (Join-Path $workDir 'database.bak')        -Algorithm SHA256).Hash.ToLower()
        $mekHash = (Get-FileHash -LiteralPath (Join-Path $workDir 'securevault-mek.bin') -Algorithm SHA256).Hash.ToLower()
        if ($m.db_checksum_sha256  -ne $dbHash)  { throw "Database checksum mismatch in manifest." }
        if ($m.mek_checksum_sha256 -ne $mekHash) { throw "MEK checksum mismatch in manifest." }
        Write-Stamp "Manifest checksums verified."
    }

    if ($VerifyOnly) {
        Write-Stamp "Verify-only run: integrity OK. Exiting without restoring."
        return
    }

    # ─── 3. Confirm + 10s abort window ─────────────────────────────────────────
    Write-Host @"
╔══════════════════════════════════════════════════════════════╗
║              SecureVault Restore - WARNING                   ║
╠══════════════════════════════════════════════════════════════╣
║  This will OVERWRITE the current database and MEK file.      ║
║  The SecureVault service MUST be stopped before proceeding.  ║
║  Aborting in 10 seconds... (Ctrl+C to cancel)                ║
╚══════════════════════════════════════════════════════════════╝
"@
    for ($i = 10; $i -ge 1; $i--) {
        Write-Host -NoNewline ("`r  Restoring in {0,2} seconds...  " -f $i)
        Start-Sleep -Seconds 1
    }
    Write-Host ""

    # ─── 4. Restore MEK FIRST ──────────────────────────────────────────────────
    Write-Stamp "Restoring MEK file to $MekDest ..."
    $mekDestDir = Split-Path -Parent $MekDest
    New-Item -ItemType Directory -Force -Path $mekDestDir | Out-Null
    Copy-Item -LiteralPath (Join-Path $workDir 'securevault-mek.bin') -Destination $MekDest -Force
    # Re-apply ACL: only the service account and Administrators may read it.
    & icacls.exe $MekDest /inheritance:r /grant:r "NT SERVICE\SecureVault:(R)" "BUILTIN\Administrators:(F)" /remove "Users" "Authenticated Users" | Out-Null

    # ─── 5. Restore database WITH REPLACE ──────────────────────────────────────
    Write-Stamp "Restoring database $Database ..."
    $bakInContainer = Join-Path $workDir 'database.bak'
    # Drop existing connections so the restore can take exclusive lock.
    $killSql = "IF DB_ID(N'$Database') IS NOT NULL ALTER DATABASE [$Database] SET SINGLE_USER WITH ROLLBACK IMMEDIATE;"
    & sqlcmd -S $SqlServer -E -b -Q $killSql
    if ($LASTEXITCODE -ne 0) { throw "Failed to put $Database into SINGLE_USER mode." }

    $restoreSql = "RESTORE DATABASE [$Database] FROM DISK = N'$bakInContainer' WITH REPLACE, RECOVERY, CHECKSUM;"
    & sqlcmd -S $SqlServer -E -b -Q $restoreSql
    if ($LASTEXITCODE -ne 0) { throw "RESTORE DATABASE failed." }

    & sqlcmd -S $SqlServer -E -b -Q "ALTER DATABASE [$Database] SET MULTI_USER;"

    Write-Stamp "Database restored."
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════╗"
    Write-Host "║                    Restore Complete!                          ║"
    Write-Host "║  Verify MEK at: $MekDest"
    Write-Host "║  Start service: Start-Service SecureVault                     ║"
    Write-Host "╚══════════════════════════════════════════════════════════════╝"
}
finally {
    Remove-Item -Recurse -Force -LiteralPath $workDir -ErrorAction SilentlyContinue
}
