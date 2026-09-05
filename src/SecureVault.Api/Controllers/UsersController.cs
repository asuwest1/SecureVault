using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SecureVault.Api.Models.Requests;
using SecureVault.Api.Models.Responses;
using SecureVault.Core.Entities;
using SecureVault.Core.Enums;
using SecureVault.Core.Interfaces;
using SecureVault.Infrastructure.Data;

namespace SecureVault.Api.Controllers;

[ApiController]
[Route("api/v1/users")]
[Authorize]
public class UsersController : ControllerBase
{
    private readonly AppDbContext _db;
    private readonly IEncryptionService _encryption;
    private readonly IAuditService _audit;

    public UsersController(AppDbContext db, IEncryptionService encryption, IAuditService audit)
    {
        _db = db;
        _encryption = encryption;
        _audit = audit;
    }

    [HttpGet]
    [Authorize(Policy = "SuperAdmin")]
    public async Task<IActionResult> List(CancellationToken ct)
    {
        var users = await _db.Users
            .Include(u => u.UserRoles)
            .AsNoTracking()
            .Select(u => new UserResponse(
                u.Id, u.Username, u.Email, u.IsActive, u.IsSuperAdmin, u.IsLdapUser,
                u.MfaEnabled, u.CreatedAt,
                u.UserRoles.Select(ur => ur.RoleId).ToList()))
            .ToListAsync(ct);

        return Ok(users);
    }

    [HttpGet("{id:guid}")]
    public async Task<IActionResult> Get(Guid id, CancellationToken ct)
    {
        var callerId = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var isSuperAdmin = IsSuperAdmin();

        // Users can view their own profile; super admins can view any
        if (!isSuperAdmin && callerId != id)
            return NotFound();

        var user = await _db.Users
            .Include(u => u.UserRoles)
            .AsNoTracking()
            .FirstOrDefaultAsync(u => u.Id == id, ct);

        if (user == null) return NotFound();

        return Ok(new UserResponse(
            user.Id, user.Username, user.Email, user.IsActive, user.IsSuperAdmin,
            user.IsLdapUser, user.MfaEnabled, user.CreatedAt,
            user.UserRoles.Select(ur => ur.RoleId).ToList()));
    }

    [HttpPost]
    [Authorize(Policy = "SuperAdmin")]
    public async Task<IActionResult> Create([FromBody] CreateUserRequest request, CancellationToken ct)
    {
        var callerId = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var callerUsername = User.FindFirstValue(ClaimTypes.Name);
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString();

        var user = new User
        {
            Id = Guid.NewGuid(),
            Username = request.Username,
            Email = request.Email,
            PasswordHash = _encryption.HashPassword(request.Password),
            IsSuperAdmin = request.IsSuperAdmin,
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow,
            UpdatedAt = DateTimeOffset.UtcNow
        };

        _db.Users.Add(user);

        await _audit.LogAsync(
            AuditAction.UserCreated,
            actorUserId: callerId,
            actorUsername: callerUsername,
            targetType: "User",
            targetId: user.Id,
            ipAddress: ip);

        return CreatedAtAction(nameof(Get), new { id = user.Id },
            new UserResponse(user.Id, user.Username, user.Email, user.IsActive,
                user.IsSuperAdmin, user.IsLdapUser, user.MfaEnabled, user.CreatedAt, []));
    }

    [HttpPut("{id:guid}")]
    [Authorize(Policy = "SuperAdmin")]
    public async Task<IActionResult> Update(Guid id, [FromBody] UpdateUserRequest request, CancellationToken ct)
    {
        await using var transaction = await _db.Database.BeginTransactionAsync(ct);
        await _db.Database.ExecuteSqlRawAsync(
            "DECLARE @r int; EXEC @r = sp_getapplock @Resource=N'SecureVault.UserSecurity', @LockMode=N'Exclusive', @LockOwner=N'Transaction', @LockTimeout=15000; IF @r < 0 THROW 51000, 'Security update busy.', 1;", ct);
        var callerId = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var callerUsername = User.FindFirstValue(ClaimTypes.Name);
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString();

        var user = await _db.Users.FindAsync([id], ct);
        if (user == null) return NotFound();

        if (user.IsActive && user.IsSuperAdmin &&
            (request.IsActive == false || request.IsSuperAdmin == false) &&
            !await _db.Users.AnyAsync(u => u.Id != id && u.IsActive && u.IsSuperAdmin, ct))
            return Conflict(new { error = "At least one active super administrator is required." });
        await InvalidateSessionsAsync(user, ct);
        if (request.Email != null) user.Email = request.Email;
        if (request.IsActive.HasValue) user.IsActive = request.IsActive.Value;
        if (request.IsSuperAdmin.HasValue) user.IsSuperAdmin = request.IsSuperAdmin.Value;
        user.UpdatedAt = DateTimeOffset.UtcNow;


        await _audit.LogAsync(AuditAction.UserUpdated, callerId, callerUsername,
            "User", id, ip);
        await transaction.CommitAsync(ct);

        return Ok(new UserResponse(user.Id, user.Username, user.Email, user.IsActive,
            user.IsSuperAdmin, user.IsLdapUser, user.MfaEnabled, user.CreatedAt, []));
    }

    [HttpDelete("{id:guid}")]
    [Authorize(Policy = "SuperAdmin")]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        await using var transaction = await _db.Database.BeginTransactionAsync(ct);
        await _db.Database.ExecuteSqlRawAsync(
            "DECLARE @r int; EXEC @r = sp_getapplock @Resource=N'SecureVault.UserSecurity', @LockMode=N'Exclusive', @LockOwner=N'Transaction', @LockTimeout=15000; IF @r < 0 THROW 51000, 'Security update busy.', 1;", ct);
        var callerId = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        if (callerId == id) return BadRequest(new { error = "Cannot delete your own account." });

        var user = await _db.Users.FindAsync([id], ct);
        if (user == null) return NotFound();

        if (user.IsActive && user.IsSuperAdmin &&
            !await _db.Users.AnyAsync(u => u.Id != id && u.IsActive && u.IsSuperAdmin, ct))
            return Conflict(new { error = "At least one active super administrator is required." });
        await InvalidateSessionsAsync(user, ct);
        // Deactivate instead of hard-delete to preserve audit log foreign keys
        user.IsActive = false;
        user.UpdatedAt = DateTimeOffset.UtcNow;

        await _audit.LogAsync(AuditAction.UserDeleted,
            callerId, User.FindFirstValue(ClaimTypes.Name), "User", id,
            HttpContext.Connection.RemoteIpAddress?.ToString());
        await transaction.CommitAsync(ct);

        return NoContent();
    }

    [HttpPost("{id:guid}/roles")]
    [Authorize(Policy = "SuperAdmin")]
    public async Task<IActionResult> AssignRole(Guid id, [FromBody] AssignRoleRequest request, CancellationToken ct)
    {
        await using var transaction = await _db.Database.BeginTransactionAsync(ct);
        await _db.Database.ExecuteSqlRawAsync(
            "DECLARE @r int; EXEC @r = sp_getapplock @Resource=N'SecureVault.UserSecurity', @LockMode=N'Exclusive', @LockOwner=N'Transaction', @LockTimeout=15000; IF @r < 0 THROW 51000, 'Security update busy.', 1;", ct);
        // Validate both ends of the relationship up front rather than relying
        // on the DB FK violation, which would surface as a generic 500/409 with
        // no useful detail to the caller.
        if (!await _db.Users.AnyAsync(u => u.Id == id, ct))
            return NotFound(new { error = "User not found." });
        if (!await _db.Roles.AnyAsync(r => r.Id == request.RoleId, ct))
            return NotFound(new { error = "Role not found." });

        var exists = await _db.UserRoles.AnyAsync(ur => ur.UserId == id && ur.RoleId == request.RoleId, ct);
        if (exists) return Conflict(new { error = "Role already assigned." });

        await InvalidateSessionsAsync(await _db.Users.SingleAsync(u => u.Id == id, ct), ct);
        _db.UserRoles.Add(new UserRole
        {
            UserId = id,
            RoleId = request.RoleId,
            AssignedAt = DateTimeOffset.UtcNow
        });
        await _audit.LogAsync(AuditAction.RoleMemberAdded,
            Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!), User.FindFirstValue(ClaimTypes.Name),
            "User", id, HttpContext.Connection.RemoteIpAddress?.ToString(),
            new Dictionary<string, object?> { ["role_id"] = request.RoleId }, ct);
        await transaction.CommitAsync(ct);
        return NoContent();
    }

    [HttpDelete("{id:guid}/roles/{roleId:guid}")]
    [Authorize(Policy = "SuperAdmin")]
    public async Task<IActionResult> RemoveRole(Guid id, Guid roleId, CancellationToken ct)
    {
        await using var transaction = await _db.Database.BeginTransactionAsync(ct);
        await _db.Database.ExecuteSqlRawAsync(
            "DECLARE @r int; EXEC @r = sp_getapplock @Resource=N'SecureVault.UserSecurity', @LockMode=N'Exclusive', @LockOwner=N'Transaction', @LockTimeout=15000; IF @r < 0 THROW 51000, 'Security update busy.', 1;", ct);
        var ur = await _db.UserRoles.FirstOrDefaultAsync(ur => ur.UserId == id && ur.RoleId == roleId, ct);
        if (ur == null) return NotFound();

        await InvalidateSessionsAsync(await _db.Users.SingleAsync(u => u.Id == id, ct), ct);
        _db.UserRoles.Remove(ur);
        await _audit.LogAsync(AuditAction.RoleMemberRemoved,
            Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!), User.FindFirstValue(ClaimTypes.Name),
            "User", id, HttpContext.Connection.RemoteIpAddress?.ToString(),
            new Dictionary<string, object?> { ["role_id"] = roleId }, ct);
        await transaction.CommitAsync(ct);
        return NoContent();
    }

    [HttpPost("{id:guid}/api-tokens")]
    public async Task<IActionResult> CreateApiToken(Guid id, [FromBody] CreateApiTokenRequest request, CancellationToken ct)
    {
        var callerId = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        // Users can create tokens for themselves; super admins can create for any user
        if (User.FindFirstValue("purpose") != "access") return Forbid();
        if (!IsSuperAdmin() && callerId != id) return NotFound();
        if (request.ExpiresAt.HasValue && request.ExpiresAt <= DateTimeOffset.UtcNow)
            return BadRequest(new { error = "Token expiry must be in the future." });

        // Confirm the target user exists and is active before issuing a token.
        // Otherwise we'd happily mint a token that the api-token middleware
        // would reject on use, or fail with a DB FK violation if id is bogus.
        var targetActive = await _db.Users
            .AnyAsync(u => u.Id == id && u.IsActive, ct);
        if (!targetActive) return NotFound();

        var rawToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(48));
        var tokenHash = Convert.ToHexString(
            System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(rawToken)));

        var apiToken = new ApiToken
        {
            Id = Guid.NewGuid(),
            UserId = id,
            Name = request.Name,
            TokenHash = tokenHash,
            ExpiresAt = request.ExpiresAt,
            CreatedAt = DateTimeOffset.UtcNow
        };

        _db.ApiTokens.Add(apiToken);

        await _audit.LogAsync(AuditAction.UserApiTokenCreated, callerId, User.FindFirstValue(ClaimTypes.Name),
            "ApiToken", apiToken.Id, HttpContext.Connection.RemoteIpAddress?.ToString(), cancellationToken: ct);
        return Created($"/api/v1/users/{id}/api-tokens/{apiToken.Id}", new ApiTokenCreatedResponse(
            apiToken.Id, apiToken.Name, rawToken, apiToken.ExpiresAt));
    }

    [HttpGet("{id:guid}/api-tokens")]
    public async Task<IActionResult> ListApiTokens(Guid id, CancellationToken ct)
    {
        if (!IsSuperAdmin() && User.FindFirstValue(ClaimTypes.NameIdentifier) != id.ToString()) return NotFound();
        return Ok(await _db.ApiTokens.AsNoTracking().Where(t => t.UserId == id)
            .Select(t => new { t.Id, t.Name, t.ExpiresAt, t.IsRevoked, t.LastUsedAt }).ToListAsync(ct));
    }

    [HttpDelete("{id:guid}/api-tokens/{tokenId:guid}")]
    public async Task<IActionResult> RevokeApiToken(Guid id, Guid tokenId, CancellationToken ct)
    {
        var callerId = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        if (!IsSuperAdmin() && callerId != id) return NotFound();
        var token = await _db.ApiTokens.SingleOrDefaultAsync(t => t.Id == tokenId && t.UserId == id, ct);
        if (token == null) return NotFound();
        token.IsRevoked = true;
        await _audit.LogAsync(AuditAction.UserApiTokenRevoked, callerId, User.FindFirstValue(ClaimTypes.Name),
            "ApiToken", tokenId, HttpContext.Connection.RemoteIpAddress?.ToString(), cancellationToken: ct);
        return NoContent();
    }

    private async Task InvalidateSessionsAsync(User user, CancellationToken ct)
    {
        user.SecurityVersion = Guid.NewGuid();
        await _db.RefreshTokens.Where(t => t.UserId == user.Id && !t.IsRevoked)
            .ExecuteUpdateAsync(s => s.SetProperty(t => t.IsRevoked, true), ct);
        // API tokens check live account status and roles on every request.
    }

    private bool IsSuperAdmin() =>
        bool.Parse(User.FindFirstValue("is_super_admin") ?? "false");
}
