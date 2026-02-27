# SecureVault Code Review

**Reviewed:** 2026-02-27
**Scope:** Full codebase — backend (C# / ASP.NET Core 8), frontend (React/TypeScript), deployment (Docker/nginx), CI/CD, scripts
**Reviewer:** Claude (automated code review)

---

## Executive Summary

SecureVault is a well-architected secrets management application with a strong security foundation. The two-tier encryption model (MEK/DEK), append-only audit logging, and defense-in-depth approach demonstrate serious attention to security. That said, the review identified several issues across severity levels — including a critical Argon2 misconfiguration, missing plaintext zeroing in sensitive paths, an arbitrary file-write vector in the setup endpoint, and backup encryption using unauthenticated CBC mode instead of the spec'd GCM.

**Finding counts:** 3 Critical, 4 High, 6 Medium, 5 Low

---

## Critical Findings

### C-1: Argon2 Type Misconfiguration — Using Argon2i Instead of Argon2id

**File:** `src/SecureVault.Infrastructure/Services/EncryptionService.cs:166`
**Severity:** CRITICAL

The code sets `Type = Argon2Type.DataIndependentAddressing`, which maps to **Argon2i** in the Isopoh.Cryptography.Argon2 library — not Argon2id as the comment claims. Argon2id (the hybrid variant recommended by OWASP and NIST SP 800-63B) requires `Argon2Type.HybridAddressing`.

```csharp
// CURRENT (incorrect):
var config = new Argon2Config
{
    Type = Argon2Type.DataIndependentAddressing,  // ← This is Argon2i, NOT Argon2id
    ...
};

// SHOULD BE:
var config = new Argon2Config
{
    Type = Argon2Type.HybridAddressing,  // ← This is Argon2id
    ...
};
```

Argon2i is vulnerable to certain side-channel attacks (tradeoff attacks) that Argon2id is specifically designed to resist. The unit test at `EncryptionServiceTests.cs:117` asserts `hash.Should().StartWith("$argon2id$")` — if this test passes, the library may have different enum semantics than expected, but this must be verified. If the test hasn't been run against a real database, the misconfiguration is live.

**Recommendation:** Change to `Argon2Type.HybridAddressing`, verify the hash output prefix is `$argon2id$`, and re-hash all existing passwords on next login.

---

### C-2: Setup Endpoint Allows Arbitrary File Write via User-Controlled KeyFilePath

**File:** `src/SecureVault.Api/Controllers/SetupController.cs:40` → `FirstRunService.cs:67`
**Severity:** CRITICAL

The `InitializeRequest.KeyFilePath` is taken directly from the HTTP request body and passed to `File.WriteAllBytesAsync()` without any path validation or sandboxing:

```csharp
// SetupController.cs — user-controlled path flows to file write
await _firstRun.InitializeAsync(
    request.AdminUsername, request.AdminEmail, request.AdminPassword,
    request.KeyFilePath, ct);  // ← user-controlled path

// FirstRunService.cs — writes 32 random bytes to arbitrary path
await File.WriteAllBytesAsync(keyFilePath, mek, ct);
```

Before initialization, this endpoint is accessible to **any network client** without authentication. An attacker who reaches the endpoint first could:
- Overwrite critical system files (e.g., `/etc/crontab`, `/app/appsettings.json`)
- Write to shared volumes accessible by other services
- Cause denial of service by filling disk at arbitrary mount points

**Recommendation:**
1. Remove `KeyFilePath` from the request entirely — derive it from server configuration (`Encryption:KeyFilePath` or `SECUREVAULT_KEY_FILE`)
2. If user-configurable paths are required, validate against an allowlist of directories
3. Bind the setup endpoint to localhost only, or require a one-time setup token

---

### C-3: Backup Encryption Uses AES-256-CBC (Unauthenticated) Instead of AES-256-GCM

**File:** `scripts/backup.sh:98`
**Severity:** CRITICAL

The backup script encrypts with `openssl enc -aes-256-cbc`, which provides confidentiality but **not integrity**. The TechSpec calls for AES-256-GCM. CBC mode is vulnerable to padding oracle attacks if the decryption process leaks error information, and a tampered backup could potentially be restored without detection.

```bash
# CURRENT — unauthenticated encryption:
openssl enc -aes-256-cbc -salt -S "${SALT}" -pass "file:${PASSPHRASE_FILE}" ...

# The tar integrity check only validates archive structure, not cryptographic authenticity
```

The verification step (`tar -tzf -`) only confirms the tar archive is well-formed after decryption — it does not verify cryptographic integrity. An attacker with write access to the backup volume could modify the encrypted backup in a way that decrypts to a valid-but-tampered archive.

**Recommendation:** Use `openssl enc -aes-256-gcm` or, better, use `age` or `gpg --symmetric --cipher-algo AES256` which provide authenticated encryption. Alternatively, add an HMAC-SHA256 over the ciphertext with a separate key.

---

## High Severity Findings

### H-1: Decrypted Secret Plaintext Not Zeroed in Memory

**File:** `src/SecureVault.Api/Controllers/SecretsController.cs:114-131`
**Severity:** HIGH

The `GetValue` endpoint correctly zeroes the DEK in a `finally` block, but the decrypted `plaintext` byte array is never zeroed. It persists in managed memory until garbage collected, potentially for an extended period:

```csharp
var plaintext = _encryption.Decrypt(secret.ValueEnc, secret.Nonce, dek);
// ... audit log ...
return Ok(new SecretValueResponse(Encoding.UTF8.GetString(plaintext)));
// ← plaintext byte[] is never zeroed
```

The same issue applies to the string produced by `Encoding.UTF8.GetString(plaintext)` — strings in .NET are immutable and cannot be zeroed. Consider returning the value as a byte stream instead.

**Recommendation:** Add `CryptographicOperations.ZeroMemory(plaintext)` in the finally block. For the string representation, this is an inherent .NET limitation — document the accepted risk or consider streaming the decrypted value directly to the response body without materializing a string.

---

### H-2: Refresh Token Rotation Has a Race Condition

**File:** `src/SecureVault.Infrastructure/Services/TokenService.cs:130-157`
**Severity:** HIGH

The `ValidateRefreshTokenAsync` method reads the token with `AsNoTracking()`, then performs a separate `FindAsync` to revoke it. Between these two operations, a concurrent request could validate and use the same refresh token:

```csharp
// Request A reads token (valid, not revoked)
var refreshToken = await db.RefreshTokens.AsNoTracking()
    .FirstOrDefaultAsync(rt => rt.TokenHash == tokenHash && !rt.IsRevoked ...);

// Request B reads same token (still valid, not yet revoked by A)
// Both requests proceed to issue new tokens

// Request A revokes token
tracked.IsRevoked = true;
await db.SaveChangesAsync(ct);
// Request B also revokes — but already issued a second set of tokens
```

This defeats refresh token rotation, which is designed to detect token theft.

**Recommendation:** Use a single atomic operation: `UPDATE refresh_tokens SET is_revoked = true WHERE token_hash = @hash AND is_revoked = false RETURNING *`. If 0 rows are affected, the token was already used (potential theft — revoke all tokens for the user).

---

### H-3: Folder Listing Exposes All Folder Names Regardless of Permissions

**File:** `src/SecureVault.Api/Controllers/FoldersController.cs:32-42`
**Severity:** HIGH

The `List` endpoint returns **all** root-level folders with their children without any permission filtering:

```csharp
[HttpGet]
public async Task<IActionResult> List(CancellationToken ct)
{
    var folders = await _db.Folders.AsNoTracking()
        .Where(f => f.ParentFolderId == null)
        .Include(f => f.Children)
        .ToListAsync(ct);
    return Ok(folders.Select(MapFolder));
}
```

Any authenticated user can see the entire folder hierarchy, including folder names that may contain sensitive information (e.g., "AWS-Production-Keys", "Executive-Compensation", "M&A-Target-Credentials"). The secret *contents* are protected, but the organizational structure is fully disclosed.

**Recommendation:** Filter folders based on the user's role permissions, returning only folders where the user has at least one permission (View) via the folder ACL hierarchy.

---

### H-4: Secrets List Endpoint Missing Soft-Delete Filter for Super Admins

**File:** `src/SecureVault.Api/Controllers/SecretsController.cs:47-53`
**Severity:** HIGH

The `List` endpoint queries `_db.Secrets` without filtering `DeletedAt IS NULL`. For non-super-admin users, the permission service's raw SQL includes this filter (`WHERE s.deleted_at IS NULL`), but super admins bypass permission checks entirely and get the unfiltered query:

```csharp
if (!isSuperAdmin)
{
    var accessibleIds = await _permissions.GetAccessibleSecretIdsAsync(...);
    query = query.Where(s => accessibleIds.Contains(s.Id));
}
// Super admins hit the unfiltered query — includes soft-deleted secrets
```

Unless there is a global query filter on the `Secret` entity (not visible in the `AppDbContext` or entity configuration), super admins will see soft-deleted secrets in the listing. While arguably a feature, this is likely unintentional and inconsistent with the API contract.

**Recommendation:** Add `.Where(s => s.DeletedAt == null)` to the base query, or configure a global query filter in the EF Core model configuration for the Secret entity.

---

## Medium Severity Findings

### M-1: Password Bytes Not Zeroed After Hashing/Verification

**File:** `src/SecureVault.Infrastructure/Services/EncryptionService.cs:173, 187`

`System.Text.Encoding.UTF8.GetBytes(password)` creates a byte array that is passed to Argon2 but never zeroed. The password sits in managed memory until GC:

```csharp
Password = System.Text.Encoding.UTF8.GetBytes(password),  // never zeroed
```

**Recommendation:** Extract the byte array to a variable and zero it after Argon2 processing. Note that the `string password` parameter itself cannot be zeroed (immutable .NET strings), but minimizing the window of plaintext exposure is still worthwhile.

---

### M-2: SyslogForwarder Creates New TCP Connection Per Message

**File:** `src/SecureVault.Infrastructure/Services/SyslogForwarder.cs:53-56`

Each audit log entry creates a new `TcpClient`, performs DNS resolution, TCP handshake, sends data, and closes. Under high audit volume, this causes:
- Port exhaustion (ephemeral port depletion)
- Excessive connection overhead
- Potential DNS amplification

```csharp
using var client = new TcpClient();
await client.ConnectAsync(_host!, _port);  // New connection every time
```

**Recommendation:** Maintain a persistent connection with automatic reconnection. Use a `Channel<AuditLog>` as a buffer with a single background sender, or use a library like Serilog.Sinks.Syslog.

---

### M-3: `AllowedHosts: "*"` Enables Host Header Injection

**File:** `src/SecureVault.Api/appsettings.json:62`

```json
"AllowedHosts": "*"
```

This allows any `Host` header value, which can be exploited in:
- Password reset link poisoning (if email features are added)
- Cache poisoning via CDN/proxy
- SSRF redirect attacks

**Recommendation:** Set this to the actual hostname(s) the application is deployed on: `"AllowedHosts": "vault.example.com"`.

---

### M-4: `FirstRunService.chmod` Vulnerable to Path Injection

**File:** `src/SecureVault.Api/Services/FirstRunService.cs:71-73`

```csharp
var chmod = System.Diagnostics.Process.Start("chmod", $"400 {keyFilePath}");
```

If `keyFilePath` contains spaces or shell metacharacters, this could fail or behave unexpectedly. Combined with the C-2 finding (user-controlled path), this could potentially be exploited.

**Recommendation:** Use `ProcessStartInfo` with `ArgumentList` (which properly handles escaping), or use `File.SetUnixFileMode()` available in .NET 8:
```csharp
File.SetUnixFileMode(keyFilePath, UnixFileMode.OwnerRead);
```

---

### M-5: Audit CSV Export Doesn't Apply Date Filters in the Query

**File:** `src/SecureVault.Api/Controllers/AuditController.cs:72-77`

The export endpoint accepts `from` and `to` parameters but applies them in C# iteration rather than in the SQL query:

```csharp
var query = _db.AuditLogs.AsNoTracking().OrderBy(a => a.EventTime).AsAsyncEnumerable();
await foreach (var entry in query.WithCancellation(ct))
{
    if (from.HasValue && entry.EventTime < from) continue;  // Loads ALL rows from DB
    if (to.HasValue && entry.EventTime > to) break;
}
```

This loads the **entire** audit log table into memory for streaming. For a system with a 1-year retention policy, this could be millions of rows.

**Recommendation:** Apply the filters in the LINQ query before calling `AsAsyncEnumerable()`:
```csharp
var query = _db.AuditLogs.AsNoTracking();
if (from.HasValue) query = query.Where(a => a.EventTime >= from);
if (to.HasValue) query = query.Where(a => a.EventTime <= to);
var stream = query.OrderBy(a => a.EventTime).AsAsyncEnumerable();
```

---

### M-6: Duplicate RSA Key Loading

**File:** `src/SecureVault.Api/Program.cs:65-67` and `src/SecureVault.Infrastructure/Services/TokenService.cs:35-37`

The JWT signing key PEM file is read and parsed twice — once in `Program.cs` for JWT validation middleware and again in `TokenService` for token generation. This creates two separate unmanaged RSA instances, doubling memory usage for key material and creating two disposal responsibilities.

**Recommendation:** Load the `RsaSecurityKey` once in DI registration and inject it into both the JWT bearer options and `TokenService`. Register it as a singleton:
```csharp
builder.Services.AddSingleton(jwtSigningKey);
```

---

## Low Severity Findings

### L-1: Docker Compose `version: "3.9"` is Deprecated

**File:** `docker-compose.yml:1`

Docker Compose V2 ignores the `version` field entirely. Its presence can cause confusion.

**Recommendation:** Remove the `version: "3.9"` line.

---

### L-2: Incomplete Security Test for Privilege Escalation

**File:** `src/SecureVault.Tests/Security/SecurityTests.cs:152`

```csharp
// TODO: Create a non-admin user and verify they get 404/403
```

The `RegularUser_CannotAccess_AdminEndpoints` test only verifies that the super admin *can* access admin endpoints. It does not test the inverse — that a regular user is denied. This is the most important assertion for a privilege escalation test.

**Recommendation:** Complete the test by creating a non-admin user and verifying they receive 401/403/404 when accessing `/api/v1/users`, `/api/v1/roles`, and `/api/v1/audit`.

---

### L-3: `RequireSuperAdmin()` Throws Exception Instead of Returning ActionResult

**File:** `UsersController.cs:219-223`, `RolesController.cs:152-156`, `AuditController.cs:93-97`, `FoldersController.cs:202-207`

Multiple controllers implement `RequireSuperAdmin()` by throwing `UnauthorizedAccessException`, which is caught by `GlobalExceptionMiddleware` and mapped to 401. This has two issues:
1. Exception-based control flow is expensive — this is a hot path for every admin request
2. Inconsistent across controllers: `FoldersController.RequireSuperAdmin` returns `bool`, while others return `void`

**Recommendation:** Use an `[Authorize(Policy = "SuperAdmin")]` policy registered in DI, or at minimum use an `IAuthorizationFilter` attribute. This centralizes the check and avoids exception overhead.

---

### L-4: `RetentionCleanupJob` DateTime/DateTimeOffset Mixing

**File:** `src/SecureVault.Infrastructure/Services/RetentionCleanupJob.cs:96-97`

```csharp
var now = DateTimeOffset.UtcNow;
var midnight = now.Date.AddDays(1);       // .Date returns DateTime (Kind=Unspecified)
var delay = midnight - now.DateTime;       // .DateTime loses offset info
```

`DateTimeOffset.Date` returns a `DateTime` with `Kind = Unspecified`, and subtracting `now.DateTime` from it discards timezone awareness. While this works correctly when UTC offset is zero, it's fragile.

**Recommendation:**
```csharp
var now = DateTimeOffset.UtcNow;
var midnight = now.Date.AddDays(1).ToUniversalTime();
var delay = midnight - now.UtcDateTime;
```

---

### L-5: Frontend `silentRefresh` in useAuth Duplicates Logic in API Client

**File:** `frontend/src/hooks/useAuth.ts:34-48` and `frontend/src/api/index.ts:23-55`

The `silentRefresh` function exists in both the `useAuth` hook and the API client module with slightly different implementations. The hook version calls `authApi.refresh()` and manually processes the response, while the API client version is used for automatic 401 retry.

**Recommendation:** Consolidate to a single `silentRefresh` implementation in the API client module, and have the hook delegate to it.

---

## Positive Observations

The following security practices are implemented well and should be preserved:

| Practice | Location | Notes |
|----------|----------|-------|
| AES-256-GCM with random nonce | `EncryptionService.cs` | Correct 12-byte nonce, 16-byte tag, proper span management |
| Two-tier key model (MEK/DEK) | `EncryptionService.cs` | Per-secret DEKs wrapped by MEK — key rotation possible without re-encrypting all secrets |
| DEK zeroing via `CryptographicOperations.ZeroMemory` | `SecretsController.cs:130` | Proper `finally` block ensures zeroing even on exceptions |
| Constant-time authentication | `AuthController.cs:62-65` | Dummy Argon2 verify on missing user prevents timing-based user enumeration |
| 404 instead of 403 | `RequireSecretPermissionAttribute.cs:51` | Prevents existence disclosure for inaccessible secrets |
| Append-only audit log | `db-setup.sql:32` | DB-level REVOKE DELETE/UPDATE enforces immutability beyond application code |
| Separate audit DbContext | `AuditService.cs:55` | Business transaction rollbacks don't affect audit entries |
| HttpOnly + Secure + SameSite=Strict cookies | `AuthController.cs:230-237` | Refresh token scoped to `/api/v1/auth/refresh` path only |
| Refresh token rotation | `TokenService.cs:148-153` | Old token revoked on each refresh (see H-2 for race condition) |
| JWT algorithm restriction | `TokenService.cs:178` | `ValidAlgorithms = [RS256]` prevents algorithm confusion attacks |
| Zero clock skew | `TokenService.cs:176` | No grace period for expired tokens |
| LDAP injection prevention | `LdapService.cs:75-84` | RFC 4515 special character escaping |
| Docker secrets | `docker-compose.yml:39-41` | MEK and JWT key mounted as Docker secrets, not environment variables |
| Non-root container user | `Dockerfile:42-43, 53` | `securevault` user with read-only filesystem (chmod 500) |
| Internal Docker network | `docker-compose.yml:107-108` | DB and app isolated; only nginx on external network |
| gzip disabled | `nginx.conf:18` | Prevents CRIME/BREACH attacks on encrypted connections |
| Comprehensive security headers | `nginx.conf:55-63` | HSTS, CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy |
| TLS 1.2+/1.3 with strong ciphers | `nginx.conf:44-45` | ECDHE + AES-GCM/ChaCha20 only |
| Container image signing | `ci.yml:198-201` | Cosign keyless via GitHub OIDC |
| In-memory token storage | `authStore.ts:3-5` | No localStorage/sessionStorage — cleared on page refresh |
| Clipboard auto-clear | `clipboard.ts:8-18` | 30-second timeout with comparison check |
| Idle timeout auto-logout | `useIdleTimeout.ts` | 15-minute inactivity trigger |
| Log scrubbing | `Program.cs:204-220` | Sensitive field values redacted from structured logs |

---

## Recommended Priority Order

1. **C-1** (Argon2 type) — Verify and fix immediately; affects all password hashes
2. **C-2** (Setup file write) — Remove user-controlled path before any deployment
3. **C-3** (Backup CBC→GCM) — Fix before relying on backups for disaster recovery
4. **H-2** (Refresh token race) — Implement atomic token rotation
5. **H-1** (Plaintext zeroing) — Add zeroing in `finally` blocks
6. **H-3** (Folder listing) — Add permission filtering
7. **H-4** (Soft-delete filter) — Add global query filter or explicit WHERE clause
8. **M-5** (CSV export) — Apply filters in SQL before streaming
9. **M-3** (AllowedHosts) — Set to actual hostname
10. **M-4** (chmod injection) — Use `File.SetUnixFileMode()`

---

*End of review.*
