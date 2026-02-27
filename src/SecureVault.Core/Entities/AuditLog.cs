using SecureVault.Core.Enums;

namespace SecureVault.Core.Entities;

public class AuditLog
{
    public long Id { get; set; }
    public AuditAction Action { get; set; }
    public Guid? ActorUserId { get; set; }
    public string? ActorUsername { get; set; }  // Denormalized snapshot
    public string? TargetType { get; set; }
    public Guid? TargetId { get; set; }
    public string? IpAddress { get; set; }
    public Dictionary<string, object?>? Detail { get; set; }  // Stored as JSONB; never contains decrypted values
    public DateTimeOffset EventTime { get; set; }
}
