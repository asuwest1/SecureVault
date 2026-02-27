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
    public async Task<IActionResult> List(CancellationToken ct)
    {
        RequireSuperAdmin();
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
    public async Task<IActionResult> Create([FromBody] CreateUserRequest request, CancellationToken ct)
    {
        RequireSuperAdmin();

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
        await _db.SaveChangesAsync(ct);

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
    public async Task<IActionResult> Update(Guid id, [FromBody] UpdateUserRequest request, CancellationToken ct)
    {
        RequireSuperAdmin();

        var callerId = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var callerUsername = User.FindFirstValue(ClaimTypes.Name);
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString();

        var user = await _db.Users.FindAsync([id], ct);
        if (user == null) return NotFound();

        if (request.Email != null) user.Email = request.Email;
        if (request.IsActive.HasValue) user.IsActive = request.IsActive.Value;
        if (request.IsSuperAdmin.HasValue) user.IsSuperAdmin = request.IsSuperAdmin.Value;
        user.UpdatedAt = DateTimeOffset.UtcNow;

        await _db.SaveChangesAsync(ct);

        await _audit.LogAsync(AuditAction.UserUpdated, callerId, callerUsername,
            "User", id, ip);

        return Ok(new UserResponse(user.Id, user.Username, user.Email, user.IsActive,
            user.IsSuperAdmin, user.IsLdapUser, user.MfaEnabled, user.CreatedAt, []));
    }

    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        RequireSuperAdmin();

        var callerId = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        if (callerId == id) return BadRequest(new { error = "Cannot delete your own account." });

        var user = await _db.Users.FindAsync([id], ct);
        if (user == null) return NotFound();

        // Deactivate instead of hard-delete to preserve audit log foreign keys
        user.IsActive = false;
        user.UpdatedAt = DateTimeOffset.UtcNow;
        await _db.SaveChangesAsync(ct);

        await _audit.LogAsync(AuditAction.UserDeleted,
            callerId, User.FindFirstValue(ClaimTypes.Name), "User", id,
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return NoContent();
    }

    [HttpPost("{id:guid}/roles")]
    public async Task<IActionResult> AssignRole(Guid id, [FromBody] AssignRoleRequest request, CancellationToken ct)
    {
        RequireSuperAdmin();

        var exists = await _db.UserRoles.AnyAsync(ur => ur.UserId == id && ur.RoleId == request.RoleId, ct);
        if (exists) return Conflict(new { error = "Role already assigned." });

        _db.UserRoles.Add(new UserRole
        {
            UserId = id,
            RoleId = request.RoleId,
            AssignedAt = DateTimeOffset.UtcNow
        });
        await _db.SaveChangesAsync(ct);

        return NoContent();
    }

    [HttpDelete("{id:guid}/roles/{roleId:guid}")]
    public async Task<IActionResult> RemoveRole(Guid id, Guid roleId, CancellationToken ct)
    {
        RequireSuperAdmin();

        var ur = await _db.UserRoles.FirstOrDefaultAsync(ur => ur.UserId == id && ur.RoleId == roleId, ct);
        if (ur == null) return NotFound();

        _db.UserRoles.Remove(ur);
        await _db.SaveChangesAsync(ct);
        return NoContent();
    }

    [HttpPost("{id:guid}/api-tokens")]
    public async Task<IActionResult> CreateApiToken(Guid id, [FromBody] CreateApiTokenRequest request, CancellationToken ct)
    {
        var callerId = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        // Users can create tokens for themselves; super admins can create for any user
        if (!IsSuperAdmin() && callerId != id) return NotFound();

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
        await _db.SaveChangesAsync(ct);

        return CreatedAtAction(null, null, new ApiTokenCreatedResponse(
            apiToken.Id, apiToken.Name, rawToken, apiToken.ExpiresAt));
    }

    private bool IsSuperAdmin() =>
        bool.Parse(User.FindFirstValue("is_super_admin") ?? "false");

    private void RequireSuperAdmin()
    {
        if (!IsSuperAdmin())
            throw new UnauthorizedAccessException("Super admin required.");
    }
}
