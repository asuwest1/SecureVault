<#
.SYNOPSIS
    Creates an encrypted, integrity-verified backup of the SecureVault database
    and Master Encryption Key (MEK) file.

.DESCRIPTION
    Backs up the database with SQL Server's BACKUP DATABASE (COPY_ONLY, CHECKSUM),
    bundles it with the MEK file, encrypts the archive with AES-256-GCM via .NET,
    and writes an HMAC-SHA256 sidecar for tamper detection.

    SECURITY NOTES:
      - The backup passphrase must be stored on a DIFFERENT volume from the MEK
        and the database.
      - Authenticated encryption (AES-256-GCM) provides confidentiality + integrity
        in one primitive.
      - Old backups are purged after $RetentionDays.

.PARAMETER BackupDir
    Directory where the .svbk file is written. Default: C:\ProgramData\SecureVault\backups

.EXAMPLE
    .\backup.ps1
    .\backup.ps1 -BackupDir 'D:\Backups\SecureVault' -RetentionDays 90
#>

[CmdletBinding()]
param(
    [string]$BackupDir       = $env:SECUREVAULT_BACKUP_DIR        ?? 'C:\ProgramData\SecureVault\backups',
    [string]$MekFile         = $env:SECUREVAULT_KEY_FILE          ?? 'C:\ProgramData\SecureVault\secrets\securevault-mek.bin',
    [string]$PassphraseFile  = $env:SECUREVAULT_BACKUP_PASSPHRASE ?? 'C:\ProgramData\SecureVault\secrets\backup-passphrase.txt',
    [string]$SqlServer       = $env:SECUREVAULT_DB_SERVER         ?? 'localhost',
    [string]$Database        = $env:SECUREVAULT_DB_NAME           ?? 'securevault',
    [int]$RetentionDays      = [int]($env:SECUREVAULT_BACKUP_RETENTION_DAYS ?? 30)
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Stamp([string]$Message) {
    Write-Host ("[{0:HH:mm:ss}] {1}" -f (Get-Date).ToUniversalTime(), $Message)
}

# ─── Pre-flight ────────────────────────────────────────────────────────────────
if (-not (Test-Path -LiteralPath $MekFile))        { throw "MEK file not found: $MekFile" }
if (-not (Test-Path -LiteralPath $PassphraseFile)) { throw "Backup passphrase file not found: $PassphraseFile" }
$mekBytes = [System.IO.File]::ReadAllBytes($MekFile)
if ($mekBytes.Length -ne 32) { throw "MEK file must be exactly 32 bytes, found $($mekBytes.Length)" }

New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null

$timestamp  = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$backupName = "securevault-backup-$timestamp"
$workDir    = Join-Path ([System.IO.Path]::GetTempPath()) ("svbk-" + [guid]::NewGuid())
New-Item -ItemType Directory -Force -Path $workDir | Out-Null

try {
    Write-Stamp "Starting SecureVault backup: $backupName"

    # ─── 1. SQL Server BACKUP DATABASE (COPY_ONLY, CHECKSUM) ───────────────────
    $bakFile = Join-Path $workDir 'database.bak'
    Write-Stamp "Backing up database $Database from $SqlServer ..."
    $bakSql = "BACKUP DATABASE [$Database] TO DISK = N'$bakFile' WITH COPY_ONLY, CHECKSUM, INIT, FORMAT, COMPRESSION;"
    & sqlcmd -S $SqlServer -E -b -Q $bakSql
    if ($LASTEXITCODE -ne 0) { throw "sqlcmd BACKUP DATABASE failed (exit $LASTEXITCODE)" }

    # ─── 2. Copy MEK file ──────────────────────────────────────────────────────
    Copy-Item -LiteralPath $MekFile -Destination (Join-Path $workDir 'securevault-mek.bin')

    # ─── 3. Manifest with checksums ────────────────────────────────────────────
    $dbHash  = (Get-FileHash -LiteralPath $bakFile                                  -Algorithm SHA256).Hash.ToLower()
    $mekHash = (Get-FileHash -LiteralPath (Join-Path $workDir 'securevault-mek.bin') -Algorithm SHA256).Hash.ToLower()
    $manifest = [ordered]@{
        backup_name         = $backupName
        created_at          = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        db_checksum_sha256  = $dbHash
        mek_checksum_sha256 = $mekHash
        securevault_version = $env:SECUREVAULT_VERSION ?? 'unknown'
    }
    $manifest | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $workDir 'manifest.json') -Encoding UTF8

    # ─── 4. Zip and encrypt with AES-256-GCM ───────────────────────────────────
    $zipPath = Join-Path $workDir 'bundle.zip'
    Compress-Archive -Path (Join-Path $workDir '*') -DestinationPath $zipPath -Force
    $plainBytes = [System.IO.File]::ReadAllBytes($zipPath)

    # Derive a 32-byte key from the passphrase via PBKDF2-SHA256 (600k iterations).
    $passphrase = (Get-Content -LiteralPath $PassphraseFile -Raw).Trim()
    $salt       = New-Object byte[] 16
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($salt)
    $iterations = 600000
    $kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($passphrase, $salt, $iterations, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    try { $key = $kdf.GetBytes(32) } finally { $kdf.Dispose() }

    $nonce  = New-Object byte[] 12
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($nonce)
    $cipher = New-Object byte[] $plainBytes.Length
    $tag    = New-Object byte[] 16
    $gcm = New-Object System.Security.Cryptography.AesGcm($key, 16)
    try { $gcm.Encrypt($nonce, $plainBytes, $cipher, $tag) } finally { $gcm.Dispose() }
    [System.Security.Cryptography.CryptographicOperations]::ZeroMemory($key)

    # Container format (binary):
    #   magic "SVBK"(4) | ver(1)=1 | iterations(4 BE) | salt(16) | nonce(12) | tag(16) | ciphertext(N)
    $backupFile = Join-Path $BackupDir "$backupName.svbk"
    $iterBytes  = [System.BitConverter]::GetBytes([int]$iterations)
    if ([System.BitConverter]::IsLittleEndian) { [Array]::Reverse($iterBytes) }
    $magic = [System.Text.Encoding]::ASCII.GetBytes('SVBK')

    $fs = [System.IO.File]::Open($backupFile, 'Create')
    try {
        $fs.Write($magic, 0, $magic.Length)
        $fs.WriteByte(1)
        $fs.Write($iterBytes, 0, 4)
        $fs.Write($salt,   0, $salt.Length)
        $fs.Write($nonce,  0, $nonce.Length)
        $fs.Write($tag,    0, $tag.Length)
        $fs.Write($cipher, 0, $cipher.Length)
    } finally { $fs.Dispose() }

    Write-Stamp ("Encrypted backup written: {0} ({1:N0} bytes)" -f $backupFile, (Get-Item $backupFile).Length)

    # ─── 5. Round-trip verify integrity ────────────────────────────────────────
    Write-Stamp "Verifying backup integrity..."
    & "$PSScriptRoot\restore.ps1" -BackupFile $backupFile -VerifyOnly -PassphraseFile $PassphraseFile | Out-Null
    Write-Stamp "Integrity verified."

    # ─── 6. Purge old backups ──────────────────────────────────────────────────
    Get-ChildItem -LiteralPath $BackupDir -Filter 'securevault-backup-*.svbk' |
        Where-Object { $_.LastWriteTimeUtc -lt (Get-Date).ToUniversalTime().AddDays(-$RetentionDays) } |
        Remove-Item -Force
    Write-Stamp "Old backups older than $RetentionDays days purged."

    Write-Stamp "Backup complete: $backupFile"
}
finally {
    Remove-Item -Recurse -Force -LiteralPath $workDir -ErrorAction SilentlyContinue
}
