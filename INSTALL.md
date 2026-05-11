# SecureVault Installation Guide — Windows Server + SQL Server

This guide walks through a fresh install of SecureVault on Windows Server with
Microsoft SQL Server as the database and IIS as the TLS-terminating reverse
proxy in front of the .NET 8 Kestrel backend.

---

## 1. Prerequisites

| Component | Required Version |
|-----------|------------------|
| Windows Server | 2019 or 2022 (x64) |
| .NET 8 Hosting Bundle | 8.0.x (includes ASP.NET Core runtime + IIS module) |
| .NET SDK | 8.0.404 (build host only — pinned in `global.json`) |
| Node.js | 20 LTS (build host only) |
| Microsoft SQL Server | 2019 or 2022 — Express, Standard, or Enterprise |
| sqlcmd / sqlpackage | Bundled with SQL Server tools |
| IIS | With **URL Rewrite** + **Application Request Routing (ARR) 3.0** |
| PowerShell | 5.1 or PowerShell 7+ |

Open ports:
- **443/tcp** (IIS, public)
- **80/tcp** (IIS, optional HTTP→HTTPS redirect)
- **1433/tcp** (SQL Server, localhost only by default)

The Kestrel backend listens on **127.0.0.1:8080** and must NOT be exposed.

---

## 2. Install SQL Server

Install SQL Server with Database Engine Services and enable **Mixed-Mode**
authentication if you plan to use a SQL login (the default in this guide).
Alternatively, use **Windows Authentication** with the virtual service account
created by `install-windows-service.ps1` — see the env-file template for both
connection-string forms.

After installation, confirm the instance is reachable:

```powershell
sqlcmd -S localhost -E -Q "SELECT @@VERSION"
```

---

## 3. Build the application (developer workstation)

```powershell
# Frontend bundle
cd frontend
npm ci
npm run build
cd ..

# Backend publish (creates .\publish with all required DLLs + wwwroot)
dotnet publish src\SecureVault.Api\SecureVault.Api.csproj -c Release -o .\publish
Copy-Item -Recurse frontend\dist\* .\publish\wwwroot\
```

Copy `.\publish\*` to the server at `C:\Program Files\SecureVault\`.

---

## 4. Lay out the data directory and ACLs

`install-windows-service.ps1` performs this automatically, but the layout for
reference:

```
C:\ProgramData\SecureVault\
  ├── secrets\                     (ACL: NT SERVICE\SecureVault read-only)
  │     ├── securevault-mek.bin    (32 bytes, AES-256 MEK)
  │     ├── jwt-signing.pem        (RSA private key for JWT RS256)
  │     └── backup-passphrase.txt  (passphrase for backup.ps1)
  ├── keyring\                     (DataProtection key ring, modify)
  ├── logs\                        (structured logs, modify)
  ├── backups\                     (PowerShell backup output, modify)
  └── securevault.env              (service environment block)
```

### Generate the MEK and JWT key

```powershell
$mek = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Fill($mek)
[System.IO.File]::WriteAllBytes('C:\ProgramData\SecureVault\secrets\securevault-mek.bin', $mek)

# JWT RSA key (2048-bit, PKCS#8 PEM)
$rsa = [System.Security.Cryptography.RSA]::Create(2048)
$pem = "-----BEGIN PRIVATE KEY-----`n" +
       [Convert]::ToBase64String($rsa.ExportPkcs8PrivateKey(), 'InsertLineBreaks') +
       "`n-----END PRIVATE KEY-----"
Set-Content -LiteralPath 'C:\ProgramData\SecureVault\secrets\jwt-signing.pem' -Value $pem -Encoding ASCII

# Backup passphrase (CSPRNG — store on a different volume in production)
$bytes = New-Object byte[] 48
[System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
[Convert]::ToBase64String($bytes) | Set-Content `
    -LiteralPath 'C:\ProgramData\SecureVault\secrets\backup-passphrase.txt' -Encoding ASCII
```

---

## 5. Provision the database

```powershell
# 1) Apply schema via EF Core (run from the source tree on the build host).
dotnet ef database update `
    --project src\SecureVault.Infrastructure `
    --startup-project src\SecureVault.Api `
    --connection "Server=<db-host>;Database=securevault;User Id=sa;Password=<sa_pwd>;TrustServerCertificate=True"

# 2) Create the application login + least-privilege grants + DENY UPDATE/DELETE
#    on audit_log. Run from the build host or directly on the server.
sqlcmd -S localhost -U sa -P <sa_pwd> -i scripts\db-setup.sql `
       -v DbName="securevault" AppLogin="securevault_app" AppPassword="<app_pwd>"
```

The EF Core migration installs `INSTEAD OF UPDATE` and `INSTEAD OF DELETE`
triggers on `dbo.audit_log` to enforce append-only semantics; `db-setup.sql`
additionally `DENY`s those permissions to the app login for defense in depth.

---

## 6. Install the Windows Service

From an elevated PowerShell prompt on the server:

```powershell
# Fill in C:\ProgramData\SecureVault\securevault.env from the template first.
Copy-Item scripts\securevault.env.example C:\ProgramData\SecureVault\securevault.env
notepad   C:\ProgramData\SecureVault\securevault.env

# Then install + start the service.
.\scripts\install-windows-service.ps1
Start-Service SecureVault

# Verify Kestrel is up on 127.0.0.1:8080
Invoke-WebRequest http://127.0.0.1:8080/api/v1/setup/status -UseBasicParsing
```

The service runs under the **virtual service account** `NT SERVICE\SecureVault`,
which is created automatically and isolated from interactive logins.

---

## 7. Install the IIS reverse proxy

Install the IIS role + URL Rewrite + ARR 3.0 (the script verifies, doesn't
install, those prerequisites). Bind a TLS certificate in `LocalMachine\My`,
then:

```powershell
.\scripts\install-iis-site.ps1 `
    -CertThumbprint 'A1B2C3...' `
    -HostName       'vault.example.com'
```

The site listens on `https://vault.example.com`, forwards to
`http://127.0.0.1:8080`, and injects HSTS, CSP, X-Frame-Options,
Referrer-Policy, and X-Content-Type-Options on every response.

HTTPS-side response compression is disabled (CRIME/BREACH mitigation).

---

## 8. First-run wizard

Browse to `https://vault.example.com/`. The SPA detects the un-initialised
state and prompts for the Super Admin credentials. Submit; the API:

1. Validates password strength (12 chars, mixed case, digit, symbol).
2. Creates the Super Admin user with an Argon2id-hashed password.
3. Creates the root folder.
4. Writes an `audit_log` row with `action = SystemInitialized`.

After completion, `GET /api/v1/setup/status` returns `410 Gone` and the wizard
is permanently disabled.

---

## 9. Scheduled backups

`scripts/backup.ps1` is idempotent and self-verifying. Schedule it via Task
Scheduler:

```powershell
$action    = New-ScheduledTaskAction -Execute 'pwsh.exe' `
              -Argument '-NoProfile -File "C:\Program Files\SecureVault\scripts\backup.ps1"'
$trigger   = New-ScheduledTaskTrigger -Daily -At 2am
$principal = New-ScheduledTaskPrincipal -UserId 'NT SERVICE\SecureVault' -LogonType ServiceAccount
Register-ScheduledTask -TaskName 'SecureVault Nightly Backup' `
    -Action $action -Trigger $trigger -Principal $principal -RunLevel Highest
```

To restore:

```powershell
Stop-Service SecureVault
.\scripts\restore.ps1 -BackupFile 'C:\ProgramData\SecureVault\backups\securevault-backup-...svbk'
Start-Service SecureVault
```

---

## 10. Operational notes

- **Service logs:** Serilog writes to `C:\ProgramData\SecureVault\logs\` and to
  the Windows Event Log (`Application` → source `SecureVault`).
- **TLS cert renewal:** rebind via `New-WebBinding` and `AddSslCertificate`; no
  service restart required.
- **SQL Server backup vs application backup:** they cover different surfaces.
  The app backup script bundles the MEK with the database — restoring one
  without the other leaves all ciphertext unreadable.
- **Audit-log retention:** `RetentionCleanupJob` runs in-process and DELETEs
  rows older than `Logging:AuditRetentionDays`. The DELETE trigger permits this
  only when the executing principal is a member of `db_owner`. Grant the app
  login `db_owner` *only* if you want in-process retention; otherwise schedule
  a SQL Agent job under a `db_owner` user.
- **Migrations on upgrade:** generate new migrations with
  `dotnet ef migrations add <Name>` — the model snapshot is regenerated
  automatically. Apply on the server with `dotnet ef database update`.

---

## 11. Verifying the install

```powershell
# 1. Service is Running, Delayed Auto Start
Get-Service SecureVault | Select Name, Status, StartType

# 2. Kestrel listening on loopback only
Get-NetTCPConnection -LocalPort 8080 | Select LocalAddress, State

# 3. IIS binding present
Get-WebBinding -Name SecureVault

# 4. Database reachable and migrations applied
sqlcmd -S localhost -d securevault -E -Q "SELECT TOP 5 name FROM sys.tables"

# 5. End-to-end probe
Invoke-WebRequest "https://vault.example.com/api/v1/setup/status" -UseBasicParsing
```
