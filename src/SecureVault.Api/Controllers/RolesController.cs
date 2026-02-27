using System.Security.Claims;
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
[Route("api/v1/roles")]
[Authorize]
public class RolesController : ControllerBase
{
    private readonly AppDbContext _db;
    private readonly IAuditService _audit;

    public RolesController(AppDbContext db, IAuditService audit)
    {
        _db = db;
        _audit = audit;
    }

    [HttpGet]
    public async Task<IActionResult> List(CancellationToken ct)
    {
        var roles = await _db.Roles
            .AsNoTracking()
            .Select(r => new RoleResponse(
                r.Id, r.Name, r.Description,
                r.UserRoles.Count,
                r.CreatedAt))
            .ToListAsync(ct);

        return Ok(roles);
    }

    [HttpGet("{id:guid}")]
    public async Task<IActionResult> Get(Guid id, CancellationToken ct)
    {
        var role = await _db.Roles
            .Include(r => r.UserRoles)
            .AsNoTracking()
            .FirstOrDefaultAsync(r => r.Id == id, ct);

        if (role == null) return NotFound();

        return Ok(new RoleResponse(role.Id, role.Name, role.Description, role.UserRoles.Count, role.CreatedAt));
    }

    [HttpPost]
    public async Task<IActionResult> Create([FromBody] CreateRoleRequest request, CancellationToken ct)
    {
        RequireSuperAdmin();

        var callerId = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);

        var role = new Role
        {
            Id = Guid.NewGuid(),
            Name = request.Name,
            Description = request.Description,
            CreatedAt = DateTimeOffset.UtcNow
        };

        _db.Roles.Add(role);
        await _db.SaveChangesAsync(ct);

        await _audit.LogAsync(AuditAction.RoleCreated, callerId, User.FindFirstValue(ClaimTypes.Name),
            "Role", role.Id, HttpContext.Connection.RemoteIpAddress?.ToString());

        return CreatedAtAction(nameof(Get), new { id = role.Id },
            new RoleResponse(role.Id, role.Name, role.Description, 0, role.CreatedAt));
    }

    [HttpPut("{id:guid}")]
    public async Task<IActionResult> Update(Guid id, [FromBody] UpdateRoleRequest request, CancellationToken ct)
    {
        RequireSuperAdmin();

        var role = await _db.Roles.FindAsync([id], ct);
        if (role == null) return NotFound();

        if (request.Name != null) role.Name = request.Name;
        if (request.Description != null) role.Description = request.Description;
        await _db.SaveChangesAsync(ct);

        await _audit.LogAsync(AuditAction.RoleUpdated,
            Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!),
            User.FindFirstValue(ClaimTypes.Name), "Role", id,
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(new RoleResponse(role.Id, role.Name, role.Description, 0, role.CreatedAt));
    }

    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        RequireSuperAdmin();

        var role = await _db.Roles.FindAsync([id], ct);
        if (role == null) return NotFound();

        _db.Roles.Remove(role);
        await _db.SaveChangesAsync(ct);

        await _audit.LogAsync(AuditAction.RoleDeleted,
            Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!),
            User.FindFirstValue(ClaimTypes.Name), "Role", id,
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return NoContent();
    }

    [HttpPut("{id:guid}/secret-acl")]
    public async Task<IActionResult> SetSecretAcl(
        Guid id, [FromBody] SetSecretAclRequest request, CancellationToken ct)
    {
        RequireSuperAdmin();

        // Verify the secret exists
        var secretExists = await _db.Secrets.AnyAsync(s => s.Id == request.RoleId, ct);

        var existing = await _db.SecretAcls
            .FirstOrDefaultAsync(sa => sa.SecretId == request.RoleId && sa.RoleId == id, ct);

        if (existing != null)
        {
            existing.Permissions = request.Permissions;
            existing.UpdatedAt = DateTimeOffset.UtcNow;
        }
        else
        {
            _db.SecretAcls.Add(new SecretAcl
            {
                SecretId = request.RoleId,
                RoleId = id,
                Permissions = request.Permissions,
                UpdatedAt = DateTimeOffset.UtcNow
            });
        }

        await _db.SaveChangesAsync(ct);
        return NoContent();
    }

    private void RequireSuperAdmin()
    {
        if (!bool.Parse(User.FindFirstValue("is_super_admin") ?? "false"))
            throw new UnauthorizedAccessException("Super admin required.");
    }
}
