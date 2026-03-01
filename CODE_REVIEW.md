# SecureVault Code Review

**Reviewed:** 2026-02-27
**Updated:** 2026-03-01
**Scope:** Full codebase — backend (C# / ASP.NET Core 8), frontend (React/TypeScript), deployment (Docker/nginx), CI/CD, scripts
**Reviewer:** Claude (automated code review)

---

## Review Update (2026-03-01)

A follow-up review was conducted on 2026-03-01 to verify remediation of the original findings. The results below reflect the current state of the codebase. Status tags have been added to each finding:

- **[FIXED]** — Issue is fully remediated
- **[PARTIALLY FIXED]** — Significant progress made; residual issues remain (see notes)
- **[OPEN]** — Not yet remediated

**Remediation summary:** 13 of 18 original findings fully fixed; 2 partially fixed; 3 still open.

**New findings from 2026-03-01 review:** 7 (see `security_review_2026-03-01.md` for full detail)

---

## Executive Summary

SecureVault is a well-architected secrets management application with a strong security foundation. The two-tier encryption model (MEK/DEK), append-only audit logging, and defense-in-depth approach demonstrate serious attention to security. The 2026-03-01 review found that all critical and high-severity original findings have been resolved or significantly improved. That said, residual issues remain around backup encryption specification compliance and a misleading setup wizard UI. Three low-severity findings remain open.

**Original finding counts:** 3 Critical, 4 High, 6 Medium, 5 Low
**Current open counts:** 0 Critical, 0 High, 0 Medium, 3 Low (plus 2 partially fixed)

---

## Critical Findings

### C-1: Argon2 Type Misconfiguration — Using Argon2i Instead of Argon2id

**File:** `src/SecureVault.Infrastructure/Services/EncryptionService.cs:166`
**Severity:** CRITICAL
**Status:** **[FIXED]** — Verified 2026-03-01

The code previously set `Type = Argon2Type.DataIndependentAddressing` (Argon2i). The fix correctly changed this to `Argon2Type.HybridAddressing` (Argon2id) at line 169. Additionally, password byte arrays are now properly zeroed in `finally` blocks in both `HashPassword` (line 186) and `VerifyPassword` (line 209).

```csharp
// FIXED — current code:
var config = new Argon2Config
{
    Type = Argon2Type.HybridAddressing,  // ← Correct: Argon2id
    Version = Argon2Version.Nineteen,
    TimeCost = 3,
    MemoryCost = 65536,  // 64 MB
    Lanes = 4,
    Threads = 4,
    HashLength = 32,
    Password = passwordBytes,
    Salt = GenerateRandomSalt(16)
};
// ...
finally { CryptographicOperations.ZeroMemory(passwordBytes); }
```

The unit test at `EncryptionServiceTests.cs:117` asserts `hash.Should().StartWith("$argon2id$")`, which now correctly validates the algorithm.

---

### C-2: Setup Endpoint Allows Arbitrary File Write via User-Controlled KeyFilePath

**File:** `src/SecureVault.Api/Controllers/SetupController.cs:40` → `FirstRunService.cs:67`
**Severity:** CRITICAL
**Status:** **[PARTIALLY FIXED]** — Backend fixed; frontend residual issue (see N-1 in new findings)

The backend `InitializeRequest` record no longer contains a `KeyFilePath` property. The key file path is now derived exclusively from the `SECUREVAULT_KEY_FILE` environment variable or `Encryption:KeyFilePath` server configuration, never from user input. The `chmod` vulnerability was also resolved using `File.SetUnixFileMode()` (see M-4).

```csharp
// FIXED — InitializeRequest no longer accepts KeyFilePath:
public record InitializeRequest(
    string AdminUsername,
    string AdminEmail,
    string AdminPassword
);

// Key path sourced from server config only:
var keyFilePath = Environment.GetEnvironmentVariable("SECUREVAULT_KEY_FILE")
    ?? _config["Encryption:KeyFilePath"]
    ?? throw new InvalidOperationException("...");
```

**Residual issue:** The frontend setup wizard (`frontend/src/pages/FirstRunPage.tsx`) still collects `keyFilePath` from the user and sends it in the request body. The backend ignores it (extra JSON fields are discarded by ASP.NET Core model binding), but the UI misleads operators into believing they are configuring the MEK path via the wizard. See finding N-1 in `security_review_2026-03-01.md`.

---

### C-3: Backup Encryption Uses AES-256-CBC (Unauthenticated) Instead of AES-256-GCM

**File:** `scripts/backup.sh:98`
**Severity:** CRITICAL
**Status:** **[PARTIALLY FIXED]** — No longer unauthenticated CBC; spec deviation remains (see N-2 in new findings)

The backup script was changed from unauthenticated `openssl enc -aes-256-cbc` to `openssl enc -aes-256-ctr` with an appended HMAC-SHA256 (Encrypt-then-MAC). This eliminates the original padding oracle risk and provides cryptographic integrity. The `restore.sh` script correctly verifies the HMAC *before* decryption, preventing decryption oracle attacks.

```bash
# PARTIALLY FIXED — now uses CTR + HMAC (Encrypt-then-MAC):
tar -czf - -C "${WORK_DIR}" . | \
    openssl enc -aes-256-ctr \
        -pass "file:${PASSPHRASE_FILE}" \
        -pbkdf2 -iter 600000 \
        -salt \
        -out "${BACKUP_FILE}"

openssl dgst -sha256 -mac HMAC -macopt "key:file:${PASSPHRASE_FILE}" \
    -binary "${BACKUP_FILE}" | xxd -p -c 256 > "${HMAC_FILE}"
```

**Residual issue:** The TechSpec requires AES-256-GCM. AES-256-CTR+HMAC is cryptographically sound and provides equivalent authenticated encryption guarantees, but deviates from specification. The header comment in `backup.sh` (line 7) incorrectly states "Backup is AES-256-GCM encrypted" while the implementation uses CTR+HMAC. See finding N-2 in `security_review_2026-03-01.md`.

**Recommendation:** Either update the specification to document the CTR+HMAC decision, or migrate to a tool that natively supports AES-256-GCM streaming (e.g., `age`).

---

## High Severity Findings

### H-1: Decrypted Secret Plaintext Not Zeroed in Memory

**File:** `src/SecureVault.Api/Controllers/SecretsController.cs:114-131`
**Severity:** HIGH
**Status:** **[FIXED]** — Verified 2026-03-01

The `GetValue` endpoint now zeroes both the decrypted `plaintext` byte array and the DEK in a `finally` block:

```csharp
// FIXED:
finally
{
    if (plaintext != null) CryptographicOperations.ZeroMemory(plaintext);
    CryptographicOperations.ZeroMemory(dek);
}
```

The inherent .NET limitation — that the `string` produced by `Encoding.UTF8.GetString(plaintext)` cannot be zeroed due to string immutability — remains documented and accepted. The byte array window is now minimized.

---

### H-2: Refresh Token Rotation Has a Race Condition

**File:** `src/SecureVault.Infrastructure/Services/TokenService.cs:130-157`
**Severity:** HIGH
**Status:** **[FIXED]** — Verified 2026-03-01

The race condition between read and revoke has been eliminated with a single atomic `ExecuteUpdateAsync()` database operation:

```csharp
// FIXED — atomic revocation:
var rowsAffected = await db.RefreshTokens
    .Where(rt => rt.TokenHash == tokenHash
        && !rt.IsRevoked
        && rt.ExpiresAt > DateTimeOffset.UtcNow)
    .ExecuteUpdateAsync(
        s => s.SetProperty(rt => rt.IsRevoked, true),
        cancellationToken);

if (rowsAffected == 0) return null;  // Token already used or doesn't exist
```

If 0 rows are affected, the token was already used (potential theft indicator) or never existed.

---

### H-3: Folder Listing Exposes All Folder Names Regardless of Permissions

**File:** `src/SecureVault.Api/Controllers/FoldersController.cs:32-42`
**Severity:** HIGH
**Status:** **[FIXED]** — Verified 2026-03-01

The `List` endpoint now filters folders based on user permissions before returning results:

```csharp
// FIXED:
var accessibleIds = await _permissions.GetAccessibleFolderIdsAsync(userId, roleIds, isSuperAdmin, ct);

var folders = await _db.Folders
    .AsNoTracking()
    .Where(f => f.ParentFolderId == null && accessibleIds.Contains(f.Id))
    .Include(f => f.Children)
    .ToListAsync(ct);

return Ok(folders.Select(f => MapFolderFiltered(f, accessibleIds)));
```

`MapFolderFiltered` recursively applies the permission filter to child folders.

---

### H-4: Secrets List Endpoint Missing Soft-Delete Filter for Super Admins

**File:** `src/SecureVault.Api/Controllers/SecretsController.cs:47-53`
**Severity:** HIGH
**Status:** **[FIXED]** — Verified 2026-03-01

The base query now includes a `DeletedAt == null` filter before the super-admin branch, ensuring deleted secrets are never returned regardless of role:

```csharp
// FIXED — filter applied before super-admin branch:
IQueryable<Secret> query = _db.Secrets.AsNoTracking().Where(s => s.DeletedAt == null);

if (!isSuperAdmin)
{
    var accessibleIds = await _permissions.GetAccessibleSecretIdsAsync(userId, roleIds, false, ct);
    query = query.Where(s => accessibleIds.Contains(s.Id));
}
```

The same `s.DeletedAt == null` filter is present on all individual secret lookups (`Get`, `GetValue`, `Update`).

---

## Medium Severity Findings

### M-1: Password Bytes Not Zeroed After Hashing/Verification

**File:** `src/SecureVault.Infrastructure/Services/EncryptionService.cs:173, 187`
**Status:** **[FIXED]** — Verified 2026-03-01

Both `HashPassword` and `VerifyPassword` now zero the intermediate `passwordBytes` array in `finally` blocks. See also C-1 fix.

---

### M-2: SyslogForwarder Creates New TCP Connection Per Message

**File:** `src/SecureVault.Infrastructure/Services/SyslogForwarder.cs:53-56`
**Status:** **[FIXED]** — Verified 2026-03-01

The `SyslogForwarder` was completely rewritten. It now maintains a persistent TCP/TLS connection with automatic reconnection on failure, and uses a bounded `Channel<AuditLog>` (capacity 10,000, `DropOldest`) with a single background sender task. This eliminates port exhaustion and per-message connection overhead.

```csharp
// FIXED — persistent connection + channel buffer:
_channel = Channel.CreateBounded<AuditLog>(new BoundedChannelOptions(10_000)
{
    FullMode = BoundedChannelFullMode.DropOldest,
    SingleReader = true
});
if (_enabled)
    _senderTask = Task.Run(() => ProcessQueueAsync(_cts.Token));
```

**Note:** Under extreme audit volume, the `DropOldest` strategy silently drops the oldest syslog-forwarded events (database audit log is unaffected). See finding N-5 in `security_review_2026-03-01.md`.

---

### M-3: `AllowedHosts: "*"` Enables Host Header Injection

**File:** `src/SecureVault.Api/appsettings.json:62`
**Status:** **[FIXED]** — Verified 2026-03-01

`AllowedHosts` is now set to `"localhost"` in `appsettings.json`. Deployers should update this to the actual production hostname.

---

### M-4: `FirstRunService.chmod` Vulnerable to Path Injection

**File:** `src/SecureVault.Api/Services/FirstRunService.cs:71-73`
**Status:** **[FIXED]** — Verified 2026-03-01

The `Process.Start("chmod", ...)` call has been replaced with the .NET 8 API:

```csharp
// FIXED:
File.SetUnixFileMode(filePath, UnixFileMode.UserRead);
```

This eliminates any shell injection risk regardless of path contents.

---

### M-5: Audit CSV Export Doesn't Apply Date Filters in the Query

**File:** `src/SecureVault.Api/Controllers/AuditController.cs:72-77`
**Status:** **[FIXED]** — Verified 2026-03-01

Date filters are now applied in the LINQ/SQL query before streaming:

```csharp
// FIXED:
IQueryable<Core.Entities.AuditLog> query = _db.AuditLogs.AsNoTracking();
if (from.HasValue) query = query.Where(a => a.EventTime >= from);
if (to.HasValue) query = query.Where(a => a.EventTime <= to);
var stream = query.OrderBy(a => a.EventTime).AsAsyncEnumerable();
```

---

### M-6: Duplicate RSA Key Loading

**File:** `src/SecureVault.Api/Program.cs:65-67` and `src/SecureVault.Infrastructure/Services/TokenService.cs:35-37`
**Status:** **[FIXED]** — Verified 2026-03-01

The `RsaSecurityKey` is registered as a singleton in DI and injected into both the JWT bearer middleware and `TokenService` via constructor injection. The PEM file is read exactly once at startup.

---

## Low Severity Findings

### L-1: Docker Compose `version: "3.9"` is Deprecated

**File:** `docker-compose.yml:1`
**Status:** **[FIXED]** — Verified 2026-03-01

The `version` field has been removed from `docker-compose.yml`. Docker Compose V2 ignores it and its presence caused confusion.

---

### L-2: Incomplete Security Test for Privilege Escalation

**File:** `src/SecureVault.Tests/Security/SecurityTests.cs:152`
**Status:** **[OPEN]**

The `RegularUser_CannotAccess_AdminEndpoints` test still only verifies that the super admin *can* access admin endpoints. The most important assertion — that a regular user is *denied* — contains a `// TODO` comment and is not implemented.

**Recommendation:** Complete the test by creating a non-admin user and asserting 401/403/404 responses on `/api/v1/users`, `/api/v1/roles`, and `/api/v1/audit`.

---

### L-3: `RequireSuperAdmin()` Throws Exception Instead of Returning ActionResult

**File:** `UsersController.cs:219-223`, `RolesController.cs:152-156`, `AuditController.cs:93-97`, `FoldersController.cs:202-207`
**Status:** **[OPEN]**

Multiple controllers implement `RequireSuperAdmin()` by throwing `UnauthorizedAccessException`, caught by `GlobalExceptionMiddleware` and mapped to 401. This is exception-based control flow on a hot path and is inconsistent across controllers.

**Recommendation:** Use `[Authorize(Policy = "SuperAdmin")]` registered in DI, or at minimum use an `IAuthorizationFilter` attribute.

---

### L-4: `RetentionCleanupJob` DateTime/DateTimeOffset Mixing

**File:** `src/SecureVault.Infrastructure/Services/RetentionCleanupJob.cs:96-97`
**Status:** **[FIXED]** — Verified 2026-03-01

The `WaitUntilMidnightUtcAsync` method now correctly constructs next midnight as a proper `DateTimeOffset`:

```csharp
// FIXED:
var now = DateTimeOffset.UtcNow;
var nextMidnight = new DateTimeOffset(now.UtcDateTime.Date.AddDays(1), TimeSpan.Zero);
var delay = nextMidnight - now;
```

---

### L-5: Frontend `silentRefresh` in useAuth Duplicates Logic in API Client

**File:** `frontend/src/hooks/useAuth.ts:34-48` and `frontend/src/api/index.ts:23-55`
**Status:** **[FIXED]** — Verified 2026-03-01

The `useAuth` hook now delegates to the single `silentRefresh` implementation exported from the API module:

```typescript
// FIXED — delegation, not duplication:
import { silentRefresh as apiSilentRefresh } from '@/api'

const silentRefresh = useCallback(() => apiSilentRefresh(), [])
```

---

## Positive Observations

The following security practices continue to be implemented well and should be preserved:

| Practice | Location | Notes |
|----------|----------|-------|
| AES-256-GCM with random nonce | `EncryptionService.cs` | Correct 12-byte nonce, 16-byte tag, proper span management |
| Two-tier key model (MEK/DEK) | `EncryptionService.cs` | Per-secret DEKs wrapped by MEK — key rotation possible without re-encrypting all secrets |
| DEK + plaintext zeroing | `SecretsController.cs:133-136` | Both arrays zeroed in `finally` block |
| Constant-time authentication | `AuthController.cs` | Dummy Argon2 verify on missing user prevents timing-based user enumeration |
| 404 instead of 403 | `RequireSecretPermissionAttribute.cs:51` | Prevents existence disclosure for inaccessible secrets |
| Append-only audit log | `db-setup.sql:32` | DB-level REVOKE DELETE/UPDATE enforces immutability beyond application code |
| Separate audit DbContext | `AuditService.cs:55` | Business transaction rollbacks don't affect audit entries |
| HttpOnly + Secure + SameSite=Strict cookies | `AuthController.cs` | Refresh token scoped to `/api/v1/auth/refresh` path only |
| Atomic refresh token rotation | `TokenService.cs` | Single `ExecuteUpdateAsync()` eliminates race condition |
| JWT algorithm restriction | `TokenService.cs` | `ValidAlgorithms = [RS256]` prevents algorithm confusion attacks |
| Zero clock skew | `TokenService.cs` | No grace period for expired tokens |
| LDAP injection prevention | `LdapService.cs` | RFC 4515 special character escaping |
| Docker secrets | `docker-compose.yml` | MEK and JWT key mounted as Docker secrets, not environment variables |
| Non-root container user | `Dockerfile` | `securevault` user with read-only filesystem |
| Internal Docker network | `docker-compose.yml` | DB and app isolated; only nginx on external network |
| gzip disabled | `nginx.conf:18` | Prevents CRIME/BREACH attacks on encrypted connections |
| Comprehensive security headers | `nginx.conf` | HSTS, CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy |
| TLS 1.2+/1.3 with strong ciphers | `nginx.conf` | ECDHE + AES-GCM/ChaCha20 only |
| Container image signing | `ci.yml` | Cosign keyless via GitHub OIDC |
| In-memory token storage | `authStore.ts` | No localStorage/sessionStorage — cleared on page refresh |
| Clipboard auto-clear | `clipboard.ts` | 30-second timeout with comparison check |
| Idle timeout auto-logout | `useIdleTimeout.ts` | 15-minute inactivity trigger |
| Persistent syslog connection | `SyslogForwarder.cs` | Channel-buffered sender, TLS 1.2+, reconnects on failure |

---

## Recommended Priority Order (Remaining Open Items)

1. **N-1** (Frontend wizard sends unused `keyFilePath`) — Remove `keyFilePath` from `FirstRunPage.tsx` wizard entirely
2. **N-2** (Backup comment vs. implementation mismatch) — Fix `backup.sh:7` comment to reflect CTR+HMAC or migrate to GCM tool
3. **L-2** (Incomplete privilege escalation test) — Complete the negative assertion in `SecurityTests.cs`
4. **L-3** (`RequireSuperAdmin` exception flow) — Refactor to authorization policy
5. **N-3** through **N-7** — See `security_review_2026-03-01.md` for full detail

---

*Original review: 2026-02-27. Status update: 2026-03-01.*
