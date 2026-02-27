using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SecureVault.Core.Entities;
using SecureVault.Core.Enums;

namespace SecureVault.Infrastructure.Data.Configurations;

public class AuditLogConfiguration : IEntityTypeConfiguration<AuditLog>
{
    public void Configure(EntityTypeBuilder<AuditLog> builder)
    {
        builder.ToTable("audit_log");
        builder.HasKey(a => a.Id);

        // BIGSERIAL identity column
        builder.Property(a => a.Id)
            .HasColumnName("id")
            .UseIdentityByDefaultColumn();

        builder.Property(a => a.Action)
            .HasColumnName("action")
            .HasConversion<int>();

        builder.Property(a => a.ActorUserId).HasColumnName("actor_user_id");
        builder.Property(a => a.ActorUsername).HasColumnName("actor_username").HasMaxLength(100);
        builder.Property(a => a.TargetType).HasColumnName("target_type").HasMaxLength(50);
        builder.Property(a => a.TargetId).HasColumnName("target_id");
        builder.Property(a => a.IpAddress).HasColumnName("ip_address").HasMaxLength(45);  // IPv6 max length
        builder.Property(a => a.EventTime)
            .HasColumnName("event_time")
            .HasDefaultValueSql("NOW()");

        // Detail stored as JSONB — never contains decrypted values, DEK, or nonce
        builder.Property(a => a.Detail)
            .HasColumnName("detail")
            .HasColumnType("jsonb")
            .HasConversion(
                v => v == null ? null : JsonSerializer.Serialize(v, (JsonSerializerOptions?)null),
                v => v == null ? null : JsonSerializer.Deserialize<Dictionary<string, object?>>(v, (JsonSerializerOptions?)null),
                new ValueComparer<Dictionary<string, object?>>(
                    (c1, c2) => JsonSerializer.Serialize(c1, (JsonSerializerOptions?)null) == JsonSerializer.Serialize(c2, (JsonSerializerOptions?)null),
                    c => c == null ? 0 : JsonSerializer.Serialize(c, (JsonSerializerOptions?)null).GetHashCode(),
                    c => JsonSerializer.Deserialize<Dictionary<string, object?>>(JsonSerializer.Serialize(c, (JsonSerializerOptions?)null), (JsonSerializerOptions?)null)!
                ));

        builder.HasIndex(a => a.EventTime);
        builder.HasIndex(a => a.ActorUserId);
        builder.HasIndex(a => a.Action);
    }
}
