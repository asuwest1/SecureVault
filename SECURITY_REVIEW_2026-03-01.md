# SecureVault Review (2026-03-01)

Scope reviewed:
- Backend API, infrastructure services, and operational scripts.
- Frontend lint/type checks.

## A) Code errors / correctness issues

### 1) Hard-coded database owner in restore workflow
- **Severity:** Medium
- **Why it matters:** `restore.sh` recreates the DB with owner `securevault_app` regardless of runtime configuration. In environments where that role does not exist (or uses a different role name), restore fails.
- **Evidence:** `CREATE DATABASE %I OWNER securevault_app` is hard-coded in restore SQL.
- **Location:** `scripts/restore.sh`

### 2) Soft-delete query filter expectation does not match DbContext configuration
- **Severity:** Low
- **Why it matters:** cleanup code uses `IgnoreQueryFilters()` for secrets purge, but `AppDbContext` defines no global query filter. This is an indicator that soft-delete behavior may be inconsistently enforced and easy to regress.
- **Evidence:** `IgnoreQueryFilters()` is used in cleanup job, but no `HasQueryFilter(...)` is configured for `Secret` in `AppDbContext`.
- **Location:** `src/SecureVault.Infrastructure/Services/RetentionCleanupJob.cs`, `src/SecureVault.Infrastructure/Data/AppDbContext.cs`

## B) Security issues

### 1) Soft-deleted secrets remain accessible (read/update/view-value)
- **Severity:** **High**
- **Why it matters:** `Delete` marks a secret as deleted (`deleted_at`, `purge_after`) but multiple read/update endpoints query by `Id` without excluding deleted rows. This enables continued access to data that should be logically deleted until purge.
- **Impact:** Confidentiality/integrity risk (deleted secrets can still be read or modified if caller has ACL).
- **Evidence:**
  - Delete is soft-delete only.
  - `Get`, `GetValue`, `Update` load by `Id` without `DeletedAt == null` predicate.
  - Super-admin accessible IDs query returns all secrets and does not filter soft-deleted rows.
- **Locations:**
  - `src/SecureVault.Api/Controllers/SecretsController.cs`
  - `src/SecureVault.Infrastructure/Services/PermissionService.cs`

### 2) Audit logging failure is non-blocking and silently permits state-changing actions
- **Severity:** Medium
- **Why it matters:** `AuditService.LogAsync` catches all exceptions and does not rethrow. If audit persistence fails, sensitive operations (auth, secret view/change/delete, user management) can still succeed without immutable evidence.
- **Impact:** Accountability/compliance gap; post-incident forensics weakened.
- **Evidence:** broad `catch` logs error then returns.
- **Location:** `src/SecureVault.Infrastructure/Services/AuditService.cs`

### 3) API token creation does not validate target user existence/active state
- **Severity:** Medium
- **Why it matters:** `CreateApiToken` allows creating a token for `id` without checking whether user exists/is active. Depending on DB constraints and exception handling, this can produce avoidable 500s and inconsistent security behavior.
- **Impact:** robustness/security hygiene issue; potential enumeration/DoS vector via repeated invalid IDs.
- **Location:** `src/SecureVault.Api/Controllers/UsersController.cs`

## Validation commands run
- `cd frontend && npm ci`
- `cd frontend && npm run lint`
- `cd frontend && npm run type-check`
- `bash -n scripts/backup.sh && bash -n scripts/restore.sh`
- `dotnet build SecureVault.sln -c Release` (failed in environment: dotnet SDK not installed)
- `cd frontend && npm audit --omit=dev --json` (failed in environment: npm advisory endpoint returned HTTP 403)

