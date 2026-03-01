using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SecureVault.Core.Entities;
using SecureVault.Core.Enums;
using SecureVault.Core.Interfaces;
using SecureVault.Infrastructure.Data;

namespace SecureVault.Infrastructure.Services;

/// <summary>
/// Append-only audit service. Uses a separate DbContext instance so that
/// business transaction rollbacks do NOT roll back audit entries.
/// </summary>
public class AuditService : IAuditService
{
    private readonly IDbContextFactory<AppDbContext> _dbFactory;
    private readonly SyslogForwarder _syslog;
    private readonly ILogger<AuditService> _logger;

    public AuditService(
        IDbContextFactory<AppDbContext> dbFactory,
        SyslogForwarder syslog,
        ILogger<AuditService> logger)
    {
        _dbFactory = dbFactory;
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
            // Separate DbContext instance — isolated from business transaction
            await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
            db.AuditLogs.Add(entry);
            await db.SaveChangesAsync(cancellationToken);

            // Fire-and-forget syslog — unavailability must not block request
            _syslog.Forward(entry);
        }
        catch (Exception ex)
        {
            // Audit failure: log error but do NOT propagate — caller still completes its operation
            _logger.LogError(ex, "Failed to write audit log entry for action {Action}", action);
        }
    }
}
