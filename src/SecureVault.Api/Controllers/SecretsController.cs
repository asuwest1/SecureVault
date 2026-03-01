using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SecureVault.Api.Filters;
using SecureVault.Api.Models.Requests;
using SecureVault.Api.Models.Responses;
using SecureVault.Core.Entities;
using SecureVault.Core.Enums;
using SecureVault.Core.Interfaces;
using SecureVault.Infrastructure.Data;

namespace SecureVault.Api.Controllers;

[ApiController]
[Route("api/v1/secrets")]
[Authorize]
public class SecretsController : ControllerBase
{
    private const int MaxVersions = 20;
    private const int MaxPageSize = 200;

    private readonly AppDbContext _db;
    private readonly IEncryptionService _encryption;
    private readonly IPermissionService _permissions;
    private readonly IAuditService _audit;

    public SecretsController(
        AppDbContext db,
        IEncryptionService encryption,
        IPermissionService permissions,
        IAuditService audit)
    {
        _db = db;
        _encryption = encryption;
        _permissions = permissions;
        _audit = audit;
    }

    [HttpGet]
    public async Task<IActionResult> List([FromQuery] SearchSecretsRequest request, CancellationToken ct)
    {
        var (userId, roleIds, isSuperAdmin) = GetCallerInfo();
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString();

        IQueryable<Secret> query = _db.Secrets.AsNoTracking();

        if (!isSuperAdmin)
        {
            var accessibleIds = await _permissions.GetAccessibleSecretIdsAsync(userId, roleIds, false, ct);
            query = query.Where(s => accessibleIds.Contains(s.Id));
        }

        if (!string.IsNullOrWhiteSpace(request.Query))
            query = query.Where(s => EF.Functions.ToTsVector("english", s.Name + " " + (s.Notes ?? ""))
                .Matches(EF.Functions.PlainToTsQuery("english", request.Query)));

        if (request.Type.HasValue)
            query = query.Where(s => s.Type == request.Type.Value);

        if (request.FolderId.HasValue)
            query = query.Where(s => s.FolderId == request.FolderId.Value);

        var page = Math.Max(request.Page, 1);
        var pageSize = Math.Clamp(request.PageSize, 1, MaxPageSize);

        var total = await query.CountAsync(ct);
        var items = await query
            .OrderBy(s => s.Name)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(s => new SecretSummaryResponse(
                s.Id, s.Name, s.Type, s.FolderId, s.Username, s.Url, s.Tags,
                s.CreatedAt, s.UpdatedAt))
            .ToListAsync(ct);

        return Ok(new PagedResponse<SecretSummaryResponse>(items, page, pageSize, total));
    }

    [HttpGet("{id:guid}")]
    [RequireSecretPermission(SecretPermission.View)]
    public async Task<IActionResult> Get(Guid id, CancellationToken ct)
    {
        var secret = await _db.Secrets.AsNoTracking()
            .FirstOrDefaultAsync(s => s.Id == id, ct);

        if (secret == null) return NotFound();

        // Never expose encrypted fields in metadata response
        return Ok(new SecretDetailResponse(
            secret.Id, secret.Name, secret.Type, secret.FolderId,
            secret.Username, secret.Url, secret.Notes, secret.Tags,
            secret.CreatedByUserId, secret.CreatedAt, secret.UpdatedAt));
    }

    /// <summary>
    /// Most security-sensitive endpoint: decrypts and returns the secret value.
    /// Audit BEFORE returning. DEK zeroed in finally block.
    /// </summary>
    [HttpGet("{id:guid}/value")]
    [RequireSecretPermission(SecretPermission.View)]
    public async Task<IActionResult> GetValue(Guid id, CancellationToken ct)
    {
        var (userId, _, _) = GetCallerInfo();
        var username = User.FindFirstValue(ClaimTypes.Name);
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString();

        var secret = await _db.Secrets.AsNoTracking()
            .FirstOrDefaultAsync(s => s.Id == id, ct);

        if (secret == null) return NotFound();

        var dek = _encryption.UnwrapDek(secret.DekEnc);
        byte[]? plaintext = null;
        try
        {
            plaintext = _encryption.Decrypt(secret.ValueEnc, secret.Nonce, dek);

            // Audit BEFORE returning to caller
            await _audit.LogAsync(
                AuditAction.SecretViewed,
                actorUserId: userId,
                actorUsername: username,
                targetType: "Secret",
                targetId: id,
                ipAddress: ip,
                detail: new Dictionary<string, object?> { ["secret_type"] = secret.Type.ToString() });

            return Ok(new SecretValueResponse(Encoding.UTF8.GetString(plaintext)));
        }
        finally
        {
            if (plaintext != null) CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(dek);
        }
    }

    [HttpPost]
    public async Task<IActionResult> Create([FromBody] CreateSecretRequest request, CancellationToken ct)
    {
        var (userId, roleIds, isSuperAdmin) = GetCallerInfo();
        var username = User.FindFirstValue(ClaimTypes.Name);
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString();

        // Verify Add permission on target folder
        var folderPerm = await _permissions.GetFolderPermissionAsync(
            userId, roleIds, isSuperAdmin, request.FolderId, ct);

        if (folderPerm == null || !folderPerm.Value.HasFlag(SecretPermission.Add))
            return NotFound();  // 404, not 403 — prevents existence disclosure

        var folder = await _db.Folders.FindAsync([request.FolderId], ct);
        if (folder == null) return NotFound();

        // Encrypt value with fresh DEK
        var dek = _encryption.GenerateDek();
        var plaintext = Encoding.UTF8.GetBytes(request.Value);
        var (valueEncWithTag, nonce) = _encryption.Encrypt(plaintext, dek);
        var dekEnc = _encryption.WrapDek(dek);
        CryptographicOperations.ZeroMemory(plaintext);

        try
        {
            var secret = new Secret
            {
                Id = Guid.NewGuid(),
                Name = request.Name,
                Username = request.Username,
                Url = request.Url,
                Notes = request.Notes,
                Type = request.Type,
                Tags = request.Tags ?? Array.Empty<string>(),
                ValueEnc = valueEncWithTag,
                DekEnc = dekEnc,
                Nonce = nonce,
                FolderId = request.FolderId,
                CreatedByUserId = userId,
                CreatedAt = DateTimeOffset.UtcNow,
                UpdatedAt = DateTimeOffset.UtcNow
            };

            _db.Secrets.Add(secret);
            await _db.SaveChangesAsync(ct);

            await _audit.LogAsync(
                AuditAction.SecretCreated,
                actorUserId: userId,
                actorUsername: username,
                targetType: "Secret",
                targetId: secret.Id,
                ipAddress: ip,
                detail: new Dictionary<string, object?> { ["name"] = secret.Name, ["folder_id"] = request.FolderId });

            return CreatedAtAction(nameof(Get), new { id = secret.Id },
                new SecretDetailResponse(secret.Id, secret.Name, secret.Type, secret.FolderId,
                    secret.Username, secret.Url, secret.Notes, secret.Tags,
                    secret.CreatedByUserId, secret.CreatedAt, secret.UpdatedAt));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
        }
    }

    [HttpPut("{id:guid}")]
    [RequireSecretPermission(SecretPermission.Change)]
    public async Task<IActionResult> Update(Guid id, [FromBody] UpdateSecretRequest request, CancellationToken ct)
    {
        var (userId, _, _) = GetCallerInfo();
        var username = User.FindFirstValue(ClaimTypes.Name);
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString();

        var secret = await _db.Secrets
            .Include(s => s.Versions)
            .FirstOrDefaultAsync(s => s.Id == id, ct);

        if (secret == null) return NotFound();

        // Version management: save current version before overwrite
        var currentVersionNum = secret.Versions.Any()
            ? secret.Versions.Max(v => v.VersionNumber)
            : 0;

        // Enforce 20-version cap: delete oldest if at limit
        if (secret.Versions.Count >= MaxVersions)
        {
            var oldest = secret.Versions.OrderBy(v => v.VersionNumber).First();
            _db.SecretVersions.Remove(oldest);
        }

        _db.SecretVersions.Add(new SecretVersion
        {
            Id = Guid.NewGuid(),
            SecretId = secret.Id,
            VersionNumber = currentVersionNum + 1,
            ValueEnc = secret.ValueEnc,
            DekEnc = secret.DekEnc,
            Nonce = secret.Nonce,
            CreatedByUserId = userId,
            CreatedAt = DateTimeOffset.UtcNow
        });

        // Apply updates
        if (request.Name != null) secret.Name = request.Name;
        if (request.Username != null) secret.Username = request.Username;
        if (request.Url != null) secret.Url = request.Url;
        if (request.Notes != null) secret.Notes = request.Notes;
        if (request.Type.HasValue) secret.Type = request.Type.Value;
        if (request.Tags != null) secret.Tags = request.Tags;
        if (request.FolderId.HasValue) secret.FolderId = request.FolderId.Value;

        if (request.Value != null)
        {
            var dek = _encryption.GenerateDek();
            try
            {
                var (valueEncWithTag, nonce) = _encryption.Encrypt(Encoding.UTF8.GetBytes(request.Value), dek);
                secret.ValueEnc = valueEncWithTag;
                secret.Nonce = nonce;
                secret.DekEnc = _encryption.WrapDek(dek);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(dek);
            }
        }

        secret.UpdatedByUserId = userId;
        secret.UpdatedAt = DateTimeOffset.UtcNow;

        await _db.SaveChangesAsync(ct);

        await _audit.LogAsync(
            AuditAction.SecretUpdated,
            actorUserId: userId,
            actorUsername: username,
            targetType: "Secret",
            targetId: id,
            ipAddress: ip);

        return Ok(new SecretDetailResponse(secret.Id, secret.Name, secret.Type, secret.FolderId,
            secret.Username, secret.Url, secret.Notes, secret.Tags,
            secret.CreatedByUserId, secret.CreatedAt, secret.UpdatedAt));
    }

    [HttpDelete("{id:guid}")]
    [RequireSecretPermission(SecretPermission.Delete)]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        var (userId, _, _) = GetCallerInfo();
        var username = User.FindFirstValue(ClaimTypes.Name);
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString();

        var secret = await _db.Secrets.FirstOrDefaultAsync(s => s.Id == id, ct);
        if (secret == null) return NotFound();

        // Soft delete with 30-day retention before purge
        secret.DeletedAt = DateTimeOffset.UtcNow;
        secret.PurgeAfter = DateTimeOffset.UtcNow.AddDays(30);
        await _db.SaveChangesAsync(ct);

        await _audit.LogAsync(
            AuditAction.SecretDeleted,
            actorUserId: userId,
            actorUsername: username,
            targetType: "Secret",
            targetId: id,
            ipAddress: ip);

        return NoContent();
    }

    [HttpGet("{id:guid}/versions")]
    [RequireSecretPermission(SecretPermission.View)]
    public async Task<IActionResult> GetVersions(Guid id, CancellationToken ct)
    {
        var versions = await _db.SecretVersions
            .AsNoTracking()
            .Where(v => v.SecretId == id)
            .OrderByDescending(v => v.VersionNumber)
            .Select(v => new SecretVersionResponse(
                v.Id, v.VersionNumber, v.Notes, v.CreatedByUserId, v.CreatedAt))
            .ToListAsync(ct);

        return Ok(versions);
    }

    private (Guid userId, List<Guid> roleIds, bool isSuperAdmin) GetCallerInfo()
    {
        var userId = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var roleIds = User.FindAll("role_ids").Select(c => Guid.Parse(c.Value)).ToList();
        var isSuperAdmin = bool.Parse(User.FindFirstValue("is_super_admin") ?? "false");
        return (userId, roleIds, isSuperAdmin);
    }
}
