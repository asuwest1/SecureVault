using SecureVault.Core.Enums;

namespace SecureVault.Core.Interfaces;

public interface IAuditService
{
    Task LogAsync(
        AuditAction action,
        Guid? actorUserId = null,
        string? actorUsername = null,
        string? targetType = null,
        Guid? targetId = null,
        string? ipAddress = null,
        Dictionary<string, object?>? detail = null,
        CancellationToken cancellationToken = default);
}
