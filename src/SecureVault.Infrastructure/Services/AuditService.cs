using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SecureVault.Core.Entities;
using SecureVault.Core.Enums;
using SecureVault.Core.Interfaces;
using SecureVault.Infrastructure.Data;

namespace SecureVault.Infrastructure.Services;

/// <summary>
/// Append-only audit service. Saves pending business changes and their audit entry
/// together; audit persistence failures prevent sensitive operations from succeeding.
/// </summary>
public class AuditService : IAuditService
{
    private readonly AppDbContext _db;
    private readonly SyslogForwarder _syslog;
    private readonly ILogger<AuditService> _logger;

    public AuditService(
        AppDbContext db,
        SyslogForwarder syslog,
        ILogger<AuditService> logger)
    {
        _db = db;
        _syslog = syslog;
        _logger = logger;
    }

    public async Task LogAsync(
        AuditAction action,
        Guid? actorUserId = null,
        string? actorUsername = null,
        string? targetType = null,
        Guid? targetId = null,
        string? ipAddress = null,
        Dictionary<string, object?>? detail = null,
        CancellationToken cancellationToken = default)
    {
        var entry = new AuditLog
        {
            Action = action,
            ActorUserId = actorUserId,
            ActorUsername = actorUsername,    // Denormalized snapshot — survives user deletion
            TargetType = targetType,
            TargetId = targetId,
            IpAddress = ipAddress,
            Detail = detail,                  // Never contains decrypted values, DEK, or nonce
            EventTime = DateTimeOffset.UtcNow
        };

        try
        {
            // EF saves the pending business changes and audit insert in one transaction.
            _db.AuditLogs.Add(entry);
            await _db.SaveChangesAsync(cancellationToken);

            // Fire-and-forget syslog — unavailability must not block request
            _syslog.Forward(entry);
        }
        catch (Exception ex)
        {
            // Fail closed; callers must not disclose secrets after audit failure.
            _logger.LogError(ex, "Failed to write audit log entry for action {Action}", action);
            throw;
        }
    }
}
