# CLAUDE.md — SecureVault Development Guide

SecureVault is an on-premises, role-based secrets management application. It provides AES-256 encrypted storage, RBAC with secret-level permissions, MFA (TOTP), LDAP/AD integration, and comprehensive append-only audit logging.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | ASP.NET Core 8.0 (C# 12) |
| Frontend | React 18 + TypeScript 5 + Vite |
| Database | PostgreSQL 16 + Entity Framework Core 8 |
| Auth | JWT Bearer + Argon2id password hashing |
| Reverse Proxy | Nginx (TLS termination, security headers) |
| Testing | xUnit + Moq + FluentAssertions + Testcontainers |
| Containerization | Docker + Docker Compose |

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
scripts/        # backup.sh, restore.sh, db-setup.sql
nginx/          # nginx.conf (TLS, HSTS, CSP, rate limiting)
.github/workflows/  # ci.yml, security-scan.yml
```

---

## Build & Run

### Prerequisites
- .NET 8.0.404 SDK (pinned in `global.json`)
- Node.js 20
- PostgreSQL 16 or Docker

### Local Development

```bash
# Backend
dotnet restore --use-lock-file
dotnet build --configuration Release
dotnet run --project src/SecureVault.Api/SecureVault.Api.csproj

# Frontend
cd frontend
npm ci
npm run dev   # Vite dev server at http://localhost:5173
```

### Docker (Full Stack)

```bash
docker build -t securevault:latest .
docker-compose up -d

# Run database migrations
docker-compose run migrator dotnet ef database update \
  --project src/SecureVault.Infrastructure \
  --startup-project src/SecureVault.Api
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

- **Two-Tier Encryption:** Master Encryption Key (MEK) stored in Docker secret, never in DB. Each secret has its own Data Encryption Key (DEK) encrypted by the MEK.
- **Append-Only Audit Log:** Database revokes DELETE/UPDATE on `audit_log` from the application role — immutable by design.
- **JWT + httpOnly Cookies:** Stateless API auth; tokens stored in httpOnly secure cookies.
- **LDAP/AD in v1.0:** Configurable via `AUTH_MODE` environment variable.
- **gzip disabled on HTTPS:** Mitigation for CRIME/BREACH attacks.

---

## CI/CD (GitHub Actions)

**`ci.yml`** — Runs on push to `main`, `develop`, `feature/*`, `hotfix/*` and on PRs:
1. Frontend: `npm ci` → type-check → build → `npm audit`
2. Backend: restore → build → unit tests → vulnerability scan
3. Integration tests (Testcontainers + PostgreSQL)
4. Trivy filesystem scan (fails on CRITICAL/HIGH CVEs)
5. Docker build & push to GHCR (main branch only, cosign signed)

**`security-scan.yml`** — Weekly (Mondays 02:00 UTC):
- CodeQL SAST (C# + JavaScript)
- Dependency review (fails on HIGH severity)

---

## Known Critical Issues (from CODE_REVIEW.md)

These must be fixed before any production deployment:

1. **Argon2 Type Misconfiguration** — Currently uses Argon2i; must use **Argon2id** per spec.
2. **Setup Endpoint Path Traversal** — User-controlled path flows to `File.WriteAllBytesAsync`; sanitize before use.
3. **Backup Encryption Mode** — `backup.sh` uses AES-256-CBC; must use **AES-256-GCM** per spec.

High-severity issues also exist around plaintext secret memory not being zeroed, sensitive data in logs, and weak key derivation. See `CODE_REVIEW.md` for the full list.

---

## Useful References

- `SecureVault_PRD.md` — Product requirements and feature specifications
- `SecureVault_TechSpec.md` — Technical architecture and design decisions
- `CODE_REVIEW.md` — Security code review findings with severity ratings
- `.env.example` — All required environment variables with descriptions
- `scripts/db-setup.sql` — Database initialization and audit log constraints
