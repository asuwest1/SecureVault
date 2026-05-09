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
[Authorize(Policy = "SuperAdmin")]
public class AuditController : ControllerBase
{
    private const int MaxPageSize = 1000;

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
        // Clamp pagination — negative or zero values would otherwise produce
        // a negative OFFSET (DB error) or Take(0) (empty page with positive total).
        page = Math.Max(page, 1);
        pageSize = Math.Clamp(pageSize, 1, MaxPageSize);

        var query = _db.AuditLogs.AsNoTracking();

        if (actorUserId.HasValue) query = query.Where(a => a.ActorUserId == actorUserId);
        if (action.HasValue) query = query.Where(a => a.Action == action);
        if (from.HasValue) query = query.Where(a => a.EventTime >= from);
        if (to.HasValue) query = query.Where(a => a.EventTime <= to);

        var total = await query.CountAsync(ct);
        var items = await query
            .OrderByDescending(a => a.EventTime)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
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
        Response.ContentType = "text/csv";
        Response.Headers.ContentDisposition = "attachment; filename=audit-log.csv";

        await using var writer = new StreamWriter(Response.Body, Encoding.UTF8);
        await writer.WriteLineAsync("id,event_time,action,actor_username,actor_user_id,target_type,target_id,ip_address");

        // Apply date filters in SQL to avoid loading the entire audit table into memory
        IQueryable<Core.Entities.AuditLog> query = _db.AuditLogs.AsNoTracking();
        if (from.HasValue) query = query.Where(a => a.EventTime >= from);
        if (to.HasValue) query = query.Where(a => a.EventTime <= to);
        var stream = query.OrderBy(a => a.EventTime).AsAsyncEnumerable();

        await foreach (var entry in stream.WithCancellation(ct))
        {
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
}
