using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SecureVault.Api.Models.Requests;
using SecureVault.Api.Models.Responses;
using SecureVault.Core.Enums;
using SecureVault.Core.Interfaces;
using SecureVault.Infrastructure.Data;
using SecureVault.Infrastructure.Services;

namespace SecureVault.Api.Controllers;

[ApiController]
[Route("api/v1/auth")]
public class AuthController : ControllerBase
{
    private const int LockoutThreshold = 5;
    private static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(15);

    private readonly AppDbContext _db;
    private readonly IEncryptionService _encryption;
    private readonly TokenService _tokens;
    private readonly MfaService _mfa;
    private readonly IAuditService _audit;
    private readonly IConfiguration _config;
    private readonly ILogger<AuthController> _logger;

    public AuthController(
        AppDbContext db,
        IEncryptionService encryption,
        TokenService tokens,
        MfaService mfa,
        IAuditService audit,
        IConfiguration config,
        ILogger<AuthController> logger)
    {
        _db = db;
        _encryption = encryption;
        _tokens = tokens;
        _mfa = mfa;
        _audit = audit;
        _config = config;
        _logger = logger;
    }

    [HttpPost("login")]
    [AllowAnonymous]
    public async Task<IActionResult> Login([FromBody] LoginRequest request, CancellationToken ct)
    {
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString();
        // Constant-time: always load user (never short-circuit on missing username)
        var user = await _db.Users
            .Include(u => u.UserRoles)
            .FirstOrDefaultAsync(u => u.Username == request.Username, ct);

        // Generic failure message — never reveal which field failed
        const string failureMessage = "Invalid credentials.";

        if (user == null)
        {
            // Perform a dummy password verification to maintain constant time
            _encryption.VerifyPassword(request.Password, "$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
            return Unauthorized(new { error = failureMessage });
        }

        // Check active status — same message as wrong password
        if (!user.IsActive)
        {
            _encryption.VerifyPassword(request.Password, user.PasswordHash ?? "invalid");
            await _audit.LogAsync(AuditAction.AuthLoginFailed, user.Id, user.Username, ipAddress: ip);
            return Unauthorized(new { error = failureMessage });
        }

        // Check lockout — do NOT reveal lockout in response
        if (user.LockedUntil.HasValue && user.LockedUntil > DateTimeOffset.UtcNow)
        {
            _encryption.VerifyPassword(request.Password, user.PasswordHash ?? "invalid");
            await _audit.LogAsync(AuditAction.AuthLoginFailed, user.Id, user.Username, ipAddress: ip);
            return Unauthorized(new { error = failureMessage });
        }

        // LDAP authentication
        if (user.IsLdapUser)
        {
            var ldap = HttpContext.RequestServices.GetService<ILdapService>();
            if (ldap != null)
            {
                var ldapResult = await ldap.AuthenticateAsync(request.Username, request.Password, ct);
                if (ldapResult == null)
                {
                    await HandleFailedAttemptAsync(user, ip, ct);
                    return Unauthorized(new { error = failureMessage });
                }
            }
        }
        else
        {
            // Local Argon2id verification
            if (string.IsNullOrEmpty(user.PasswordHash) ||
                !_encryption.VerifyPassword(request.Password, user.PasswordHash))
            {
                await HandleFailedAttemptAsync(user, ip, ct);
                return Unauthorized(new { error = failureMessage });
            }
        }

        // Success — reset failed attempts
        user.FailedAttempts = 0;
        user.LockedUntil = null;
        user.UpdatedAt = DateTimeOffset.UtcNow;
        await _db.SaveChangesAsync(ct);

        var roleIds = user.UserRoles.Select(ur => ur.RoleId).ToList();

        // MFA required
        if (user.MfaEnabled)
        {
            var mfaToken = _tokens.GenerateMfaChallengeToken(user.Id, user.Username);
            await _audit.LogAsync(AuditAction.AuthLogin, user.Id, user.Username, ipAddress: ip,
                detail: new Dictionary<string, object?> { ["mfa_required"] = true });
            return Ok(new LoginResponse(string.Empty, DateTimeOffset.UtcNow, MfaRequired: true, MfaToken: mfaToken));
        }

        return await IssueTokensAsync(user, roleIds, ip, ct);
    }

    [HttpPost("mfa/verify")]
    [AllowAnonymous]
    public async Task<IActionResult> VerifyMfa([FromBody] MfaVerifyRequest request, CancellationToken ct)
    {
        var principal = _tokens.ValidateMfaChallengeToken(request.MfaToken);
        if (principal == null)
            return Unauthorized(new { error = "Invalid MFA challenge token." });

        var sub = principal.FindFirstValue(JwtRegisteredClaimNames.Sub);
        if (!Guid.TryParse(sub, out var userId))
            return Unauthorized(new { error = "Invalid MFA challenge token." });

        var user = await _db.Users
            .Include(u => u.UserRoles)
            .FirstOrDefaultAsync(u => u.Id == userId, ct);

        if (user == null || !user.IsActive || !user.MfaEnabled || user.MfaSecretEnc == null)
            return Unauthorized(new { error = "Invalid MFA challenge token." });

        if (!_mfa.Verify(user.MfaSecretEnc, request.Code))
        {
            await HandleFailedAttemptAsync(user, HttpContext.Connection.RemoteIpAddress?.ToString(), ct);
            return Unauthorized(new { error = "Invalid MFA code." });
        }

        user.FailedAttempts = 0;
        user.LockedUntil = null;
        user.UpdatedAt = DateTimeOffset.UtcNow;
        await _db.SaveChangesAsync(ct);

        var roleIds = user.UserRoles.Select(ur => ur.RoleId).ToList();
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString();
        return await IssueTokensAsync(user, roleIds, ip, ct);
    }

    [HttpPost("refresh")]
    [AllowAnonymous]
    public async Task<IActionResult> Refresh(CancellationToken ct)
    {
        var rawToken = Request.Cookies["refresh_token"];
        if (string.IsNullOrEmpty(rawToken))
            return Unauthorized(new { error = "No refresh token." });

        var user = await _tokens.ValidateRefreshTokenAsync(rawToken, ct);
        if (user == null)
            return Unauthorized(new { error = "Invalid or expired refresh token." });

        var roleIds = user.UserRoles.Select(ur => ur.RoleId).ToList();
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString();

        await _audit.LogAsync(AuditAction.AuthTokenRefresh, user.Id, user.Username, ipAddress: ip);
        return await IssueTokensAsync(user, roleIds, ip, ct);
    }

    [HttpPost("logout")]
    [Authorize]
    public async Task<IActionResult> Logout(CancellationToken ct)
    {
        var userId = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var username = User.FindFirstValue(ClaimTypes.Name);
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString();

        await _tokens.RevokeAllRefreshTokensAsync(userId, ct);

        Response.Cookies.Delete("refresh_token", new CookieOptions
        {
            Path = "/api/v1/auth/refresh",
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict
        });

        await _audit.LogAsync(AuditAction.AuthLogout, userId, username, ipAddress: ip);
        return Ok();
    }

    private async Task HandleFailedAttemptAsync(
        Core.Entities.User user, string? ip, CancellationToken ct)
    {
        user.FailedAttempts++;
        if (user.FailedAttempts >= LockoutThreshold)
        {
            user.LockedUntil = DateTimeOffset.UtcNow.Add(LockoutDuration);
            await _audit.LogAsync(AuditAction.AuthLockout, user.Id, user.Username, ipAddress: ip);
        }
        else
        {
            await _audit.LogAsync(AuditAction.AuthLoginFailed, user.Id, user.Username, ipAddress: ip);
        }

        user.UpdatedAt = DateTimeOffset.UtcNow;
        await _db.SaveChangesAsync(ct);
    }

    private async Task<IActionResult> IssueTokensAsync(
        Core.Entities.User user, List<Guid> roleIds, string? ip, CancellationToken ct)
    {
        var accessToken = _tokens.GenerateAccessToken(user, roleIds);
        var (refreshToken, expiresAt) = await _tokens.GenerateRefreshTokenAsync(user.Id, ct);

        // HttpOnly cookie scoped to refresh endpoint only
        Response.Cookies.Append("refresh_token", refreshToken, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Path = "/api/v1/auth/refresh",
            Expires = expiresAt.UtcDateTime
        });

        await _audit.LogAsync(AuditAction.AuthLogin, user.Id, user.Username, ipAddress: ip);

        return Ok(new LoginResponse(accessToken, DateTimeOffset.UtcNow.AddMinutes(15)));
    }
}
