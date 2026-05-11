# CLAUDE.md — SecureVault Development Guide

SecureVault is an on-premises, role-based secrets management application. It provides AES-256 encrypted storage, RBAC with secret-level permissions, MFA (TOTP), LDAP/AD integration, and comprehensive append-only audit logging.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | ASP.NET Core 8.0 (C# 12) |
| Frontend | React 18 + TypeScript 5 + Vite |
| Database | Microsoft SQL Server 2019/2022 + Entity Framework Core 8 |
| Auth | JWT Bearer + Argon2id password hashing |
| Reverse Proxy | IIS (URL Rewrite + ARR 3.0) — TLS termination, security headers |
| Testing | xUnit + Moq + FluentAssertions + Testcontainers (MSSQL) |
| Deployment | Native Windows Service on Windows Server — no Docker |

---

## Project Structure

```
src/
  SecureVault.Api/           # ASP.NET Core API (controllers, middleware, services)
  SecureVault.Core/          # Domain layer (entities, enums, interfaces)
  SecureVault.Infrastructure/ # EF Core, migrations, encryption, LDAP services
  SecureVault.Tests/         # Unit/, Integration/, Security/ test suites
frontend/
  src/
    api/        # API client code
    components/ # React components
    pages/      # Page-level components
    stores/     # Zustand state management
    hooks/      # Custom React hooks
    utils/      # Utility functions
scripts/        # backup.ps1, restore.ps1, db-setup.sql (T-SQL),
                # install-windows-service.ps1, install-iis-site.ps1,
                # iis-web.config, securevault.env.example
.github/workflows/  # ci.yml, security-scan.yml
```

---

## Build & Run

### Prerequisites
- .NET 8.0.404 SDK (pinned in `global.json`) — build time
- ASP.NET Core 8 Hosting Bundle — production host (includes IIS module)
- Node.js 20 — build time
- Microsoft SQL Server 2019 or 2022 — installed on the production host or a
  reachable database server (LocalDB / SQL Server Express are fine for dev)
- IIS with **URL Rewrite** + **Application Request Routing (ARR) 3.0** — TLS
  termination + reverse proxy in front of Kestrel

### Local Development

```powershell
# Backend (uses (localdb)\MSSQLLocalDB by default in appsettings.Development.json)
dotnet restore --use-lock-file
dotnet build --configuration Release
dotnet run --project src\SecureVault.Api\SecureVault.Api.csproj

# Frontend
cd frontend
npm ci
npm run dev   # Vite dev server at http://localhost:5173
```

### Production Deploy (no Docker)

Full instructions in `INSTALL.md`. Summary:

```powershell
# Build artifacts (build host)
cd frontend; npm ci; npm run build; cd ..
dotnet publish src\SecureVault.Api\SecureVault.Api.csproj -c Release -o .\publish
Copy-Item -Recurse frontend\dist\* .\publish\wwwroot\

# On the Windows Server (elevated PowerShell)
Copy-Item -Recurse .\publish\* 'C:\Program Files\SecureVault\'
Copy-Item scripts\securevault.env.example C:\ProgramData\SecureVault\securevault.env
.\scripts\install-windows-service.ps1
.\scripts\install-iis-site.ps1 -CertThumbprint <thumb> -HostName vault.example.com
Start-Service SecureVault

# Migrations (from source tree, against the production DB)
dotnet ef database update `
  --project src\SecureVault.Infrastructure `
  --startup-project src\SecureVault.Api
```

---

## Testing

```bash
# Unit tests only (no Docker needed)
dotnet test src/SecureVault.Tests/SecureVault.Tests.csproj \
  --filter "Category!=Integration&Category!=Security" \
  --collect:"XPlat Code Coverage"

# Integration + security tests (requires Docker for Testcontainers)
dotnet test src/SecureVault.Tests/SecureVault.Tests.csproj \
  --filter "Category=Integration|Category=Security"

# Frontend type checking
cd frontend && npm run type-check

# Frontend linting (zero-warning policy)
cd frontend && npm run lint
```

**Coverage requirement:** Minimum 15% line coverage enforced in CI.

---

## Code Standards

### Backend (C#)
- Nullable reference types enabled; treat all warnings as errors
- Use Fluent configuration for EF Core entity mappings (no data annotations)
- snake_case for database column names (EFCore.NamingConventions)
- Never log sensitive data (secrets, keys, passwords)
- Generic error messages to users; detailed errors to structured logs only

### Frontend (TypeScript)
- Strict mode enabled; zero ESLint/TypeScript warnings allowed
- State management via Zustand stores
- Lock files (`package-lock.json`) must be committed

### Security Requirements
- Passwords hashed with **Argon2id** (not Argon2i — see critical finding below)
- Secrets encrypted with AES-256-GCM (two-tier: MEK + per-secret DEK)
- TLS 1.2+ enforced; TLS 1.3 preferred
- All auth events logged to the append-only audit trail
- Clipboard auto-clears after 30 seconds for revealed secrets
- Account lockout: 5 failed logins; session timeout: 15 minutes idle

---

## Architecture Decisions

- **Two-Tier Encryption:** Master Encryption Key (MEK) stored as a host file at `C:\ProgramData\SecureVault\secrets\securevault-mek.bin`, NTFS-ACLed to `NT SERVICE\SecureVault` read-only and `BUILTIN\Administrators` full. Never stored in DB. Each secret has its own Data Encryption Key (DEK) encrypted by the MEK.
- **Append-Only Audit Log:** `INSTEAD OF UPDATE/DELETE` triggers on `dbo.audit_log` block modification by the application principal; `db-setup.sql` additionally `DENY`s those permissions to the app login for defense in depth.
- **JWT + httpOnly Cookies:** Stateless API auth; tokens stored in httpOnly secure cookies.
- **LDAP/AD in v1.0:** Configurable via `AUTH_MODE` environment variable.
- **HTTPS response compression disabled:** Mitigation for CRIME/BREACH attacks (`urlCompression`/`httpCompression` cleared in `scripts/iis-web.config`).
- **Tags column:** SQL Server has no native array type, so `Secret.Tags` is serialized via an EF Core `ValueConverter` to a U+001F-delimited `nvarchar(2048)`. Tag values may not contain U+001F.
- **Full-text search:** SQL Server's full-text catalog is optional and not always installed; the application performs LIKE-based search on `name`/`username`/`notes` instead.
- **Recursive ACL CTE:** SQL Server doesn't support the `WITH RECURSIVE` keyword. `PermissionService` uses the standard T-SQL recursive CTE form and inlines role-id parameters as `IN (@p1, @p2, ...)` since EF Core's `SqlQueryRaw` cannot expand collections.

---

## CI/CD (GitHub Actions)

**`ci.yml`** — Runs on push to `main`, `develop`, `feature/*`, `hotfix/*` and on PRs:
1. Frontend: `npm ci` → type-check → build → `npm audit`
2. Backend: restore → build → unit tests → vulnerability scan
3. Integration tests (Testcontainers + Microsoft SQL Server 2022)
4. Trivy filesystem scan (fails on CRITICAL/HIGH CVEs)

> Note: there is no production Docker image. The Testcontainers-based
> integration test suite still requires a Docker daemon on the CI runner
> because it spins up the `mcr.microsoft.com/mssql/server:2022-latest`
> container for tests; production runs natively as a Windows Service.

**`security-scan.yml`** — Weekly (Mondays 02:00 UTC):
- CodeQL SAST (C# + JavaScript)
- Dependency review (fails on HIGH severity)

---

## Known Critical Issues (from CODE_REVIEW.md)

These must be fixed before any production deployment:

1. **Argon2 Type Misconfiguration** — Currently uses Argon2i; must use **Argon2id** per spec.
2. **Setup Endpoint Path Traversal** — User-controlled path flows to `File.WriteAllBytesAsync`; sanitize before use.
3. **Backup Encryption Mode** — the new `backup.ps1` uses **AES-256-GCM** with PBKDF2-SHA256 (600k iterations) for key derivation; the historical Linux `backup.sh` (AES-256-CBC, removed in this branch) is no longer in tree.

High-severity issues also exist around plaintext secret memory not being zeroed, sensitive data in logs, and weak key derivation. See `CODE_REVIEW.md` for the full list.

---

## Useful References

- `SecureVault_PRD.md` — Product requirements and feature specifications
- `SecureVault_TechSpec.md` — Technical architecture and design decisions
- `CODE_REVIEW.md` — Security code review findings with severity ratings
- `INSTALL.md` — Step-by-step Windows Server + SQL Server installation guide
- `.env.example` — Variables for shell scripts (backup/restore, db setup)
- `scripts/securevault.env.example` — App env vars loaded into the service's `Environment` registry block
- `scripts/install-windows-service.ps1` — Creates the SecureVault Windows Service (virtual service account, delayed-auto start)
- `scripts/install-iis-site.ps1` + `scripts/iis-web.config` — IIS site + URL Rewrite / ARR reverse-proxy config
- `scripts/backup.ps1` / `scripts/restore.ps1` — AES-256-GCM-encrypted backups bundling the DB + MEK
- `scripts/db-setup.sql` — T-SQL: creates the app login, grants least privilege, verifies audit-log triggers
