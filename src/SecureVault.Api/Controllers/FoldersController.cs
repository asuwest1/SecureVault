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
[Route("api/v1/folders")]
[Authorize]
public class FoldersController : ControllerBase
{
    private const int MaxFolderDepth = 10;

    private readonly AppDbContext _db;
    private readonly IPermissionService _permissions;
    private readonly IAuditService _audit;

    public FoldersController(AppDbContext db, IPermissionService permissions, IAuditService audit)
    {
        _db = db;
        _permissions = permissions;
        _audit = audit;
    }

    [HttpGet]
    public async Task<IActionResult> List(CancellationToken ct)
    {
        var folders = await _db.Folders
            .AsNoTracking()
            .Where(f => f.ParentFolderId == null)
            .Include(f => f.Children)
            .ToListAsync(ct);

        return Ok(folders.Select(MapFolder));
    }

    [HttpGet("{id:guid}")]
    public async Task<IActionResult> Get(Guid id, CancellationToken ct)
    {
        var folder = await _db.Folders
            .AsNoTracking()
            .Include(f => f.Children)
            .FirstOrDefaultAsync(f => f.Id == id, ct);

        if (folder == null) return NotFound();
        return Ok(MapFolder(folder));
    }

    [HttpPost]
    public async Task<IActionResult> Create([FromBody] CreateFolderRequest request, CancellationToken ct)
    {
        var (userId, roleIds, isSuperAdmin) = GetCallerInfo();
        var username = User.FindFirstValue(ClaimTypes.Name);
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString();

        int depth = 0;
        if (request.ParentFolderId.HasValue)
        {
            var parent = await _db.Folders.FindAsync([request.ParentFolderId.Value], ct);
            if (parent == null) return NotFound(new { error = "Parent folder not found." });

            depth = parent.Depth + 1;

            // Enforce max depth of 10 levels
            if (depth > MaxFolderDepth)
                return BadRequest(new { error = $"Maximum folder nesting depth is {MaxFolderDepth}." });

            // Verify Add permission on parent folder
            var perm = await _permissions.GetFolderPermissionAsync(
                userId, roleIds, isSuperAdmin, request.ParentFolderId.Value, ct);
            if (!isSuperAdmin && (perm == null || !perm.Value.HasFlag(SecretPermission.Add)))
                return NotFound();
        }
        else if (!isSuperAdmin)
        {
            return Forbid();  // Only super admins can create root-level folders
        }

        var folder = new Folder
        {
            Id = Guid.NewGuid(),
            Name = request.Name,
            ParentFolderId = request.ParentFolderId,
            Depth = depth,
            CreatedAt = DateTimeOffset.UtcNow,
            UpdatedAt = DateTimeOffset.UtcNow
        };

        _db.Folders.Add(folder);
        await _db.SaveChangesAsync(ct);

        await _audit.LogAsync(AuditAction.FolderCreated, userId, username, "Folder", folder.Id, ip,
            new Dictionary<string, object?> { ["parent_folder_id"] = request.ParentFolderId });

        return CreatedAtAction(nameof(Get), new { id = folder.Id }, MapFolder(folder));
    }

    [HttpPut("{id:guid}")]
    public async Task<IActionResult> Update(Guid id, [FromBody] UpdateFolderRequest request, CancellationToken ct)
    {
        var (userId, roleIds, isSuperAdmin) = GetCallerInfo();

        if (!isSuperAdmin)
        {
            var perm = await _permissions.GetFolderPermissionAsync(userId, roleIds, false, id, ct);
            if (perm == null || !perm.Value.HasFlag(SecretPermission.Change))
                return NotFound();
        }

        var folder = await _db.Folders.FindAsync([id], ct);
        if (folder == null) return NotFound();

        if (request.Name != null) folder.Name = request.Name;
        folder.UpdatedAt = DateTimeOffset.UtcNow;
        await _db.SaveChangesAsync(ct);

        await _audit.LogAsync(AuditAction.FolderUpdated, userId, User.FindFirstValue(ClaimTypes.Name),
            "Folder", id, HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(MapFolder(folder));
    }

    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        var (userId, roleIds, isSuperAdmin) = GetCallerInfo();

        if (!isSuperAdmin)
        {
            var perm = await _permissions.GetFolderPermissionAsync(userId, roleIds, false, id, ct);
            if (perm == null || !perm.Value.HasFlag(SecretPermission.Delete))
                return NotFound();
        }

        var folder = await _db.Folders.FindAsync([id], ct);
        if (folder == null) return NotFound();

        _db.Folders.Remove(folder);
        await _db.SaveChangesAsync(ct);

        await _audit.LogAsync(AuditAction.FolderDeleted, userId, User.FindFirstValue(ClaimTypes.Name),
            "Folder", id, HttpContext.Connection.RemoteIpAddress?.ToString());

        return NoContent();
    }

    [HttpPut("{id:guid}/acl")]
    public async Task<IActionResult> SetAcl(Guid id, [FromBody] SetFolderAclRequest request, CancellationToken ct)
    {
        RequireSuperAdmin();

        var existing = await _db.FolderAcls
            .FirstOrDefaultAsync(fa => fa.FolderId == id && fa.RoleId == request.RoleId, ct);

        if (existing != null)
        {
            existing.Permissions = request.Permissions;
            existing.UpdatedAt = DateTimeOffset.UtcNow;
        }
        else
        {
            _db.FolderAcls.Add(new FolderAcl
            {
                FolderId = id,
                RoleId = request.RoleId,
                Permissions = request.Permissions,
                UpdatedAt = DateTimeOffset.UtcNow
            });
        }

        await _db.SaveChangesAsync(ct);

        await _audit.LogAsync(AuditAction.AclUpdated,
            Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!),
            User.FindFirstValue(ClaimTypes.Name),
            "FolderAcl", id,
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            new Dictionary<string, object?> { ["role_id"] = request.RoleId, ["permissions"] = request.Permissions });

        return NoContent();
    }

    private static FolderResponse MapFolder(Folder f) =>
        new(f.Id, f.Name, f.ParentFolderId, f.Depth, f.CreatedAt,
            f.Children?.Select(MapFolder).ToList() ?? []);

    private (Guid userId, List<Guid> roleIds, bool isSuperAdmin) GetCallerInfo()
    {
        var userId = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var roleIds = User.FindAll("role_ids").Select(c => Guid.Parse(c.Value)).ToList();
        var isSuperAdmin = bool.Parse(User.FindFirstValue("is_super_admin") ?? "false");
        return (userId, roleIds, isSuperAdmin);
    }

    private bool RequireSuperAdmin()
    {
        var isSuperAdmin = bool.Parse(User.FindFirstValue("is_super_admin") ?? "false");
        if (!isSuperAdmin) throw new UnauthorizedAccessException("Super admin required.");
        return true;
    }
}
