using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SecureVault.Api.Models.Responses;
using SecureVault.Core.Enums;
using SecureVault.Infrastructure.Data;

namespace SecureVault.Api.Controllers;

[ApiController]
[Route("api/v1/audit")]
[Authorize]
public class AuditController : ControllerBase
{
    private readonly AppDbContext _db;

    public AuditController(AppDbContext db)
    {
        _db = db;
    }

    [HttpGet]
    public async Task<IActionResult> List(
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 100,
        [FromQuery] Guid? actorUserId = null,
        [FromQuery] AuditAction? action = null,
        [FromQuery] DateTimeOffset? from = null,
        [FromQuery] DateTimeOffset? to = null,
        CancellationToken ct = default)
    {
        RequireSuperAdmin();

        var query = _db.AuditLogs.AsNoTracking();

        if (actorUserId.HasValue) query = query.Where(a => a.ActorUserId == actorUserId);
        if (action.HasValue) query = query.Where(a => a.Action == action);
        if (from.HasValue) query = query.Where(a => a.EventTime >= from);
        if (to.HasValue) query = query.Where(a => a.EventTime <= to);

        var total = await query.CountAsync(ct);
        var items = await query
            .OrderByDescending(a => a.EventTime)
            .Skip((page - 1) * pageSize)
            .Take(Math.Min(pageSize, 1000))  // Cap at 1000 per page
            .Select(a => new AuditLogResponse(
                a.Id, a.Action.ToString(), a.ActorUserId, a.ActorUsername,
                a.TargetType, a.TargetId, a.IpAddress, a.Detail, a.EventTime))
            .ToListAsync(ct);

        return Ok(new PagedResponse<AuditLogResponse>(items, page, pageSize, total));
    }

    /// <summary>
    /// Streams audit log as CSV — uses IAsyncEnumerable to avoid buffering.
    /// </summary>
    [HttpGet("export")]
    public async Task ExportCsv(
        [FromQuery] DateTimeOffset? from = null,
        [FromQuery] DateTimeOffset? to = null,
        CancellationToken ct = default)
    {
        RequireSuperAdmin();

        Response.ContentType = "text/csv";
        Response.Headers.ContentDisposition = "attachment; filename=audit-log.csv";

        await using var writer = new StreamWriter(Response.Body, Encoding.UTF8);
        await writer.WriteLineAsync("id,event_time,action,actor_username,actor_user_id,target_type,target_id,ip_address");

        var query = _db.AuditLogs.AsNoTracking().OrderBy(a => a.EventTime).AsAsyncEnumerable();

        await foreach (var entry in query.WithCancellation(ct))
        {
            if (from.HasValue && entry.EventTime < from) continue;
            if (to.HasValue && entry.EventTime > to) break;

            await writer.WriteLineAsync(
                $"{entry.Id},{entry.EventTime:o},{entry.Action},{CsvEscape(entry.ActorUsername)}," +
                $"{entry.ActorUserId},{entry.TargetType},{entry.TargetId},{entry.IpAddress}");
        }
    }

    private static string CsvEscape(string? value)
    {
        if (value == null) return string.Empty;
        if (value.Contains(',') || value.Contains('"') || value.Contains('\n'))
            return $"\"{value.Replace("\"", "\"\"")}\"";
        return value;
    }

    private void RequireSuperAdmin()
    {
        if (!bool.Parse(User.FindFirstValue("is_super_admin") ?? "false"))
            throw new UnauthorizedAccessException("Super admin required.");
    }
}
