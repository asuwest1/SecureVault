using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SecureVault.Core.Entities;
using SecureVault.Core.Enums;

namespace SecureVault.Infrastructure.Data.Configurations;

public class SecretConfiguration : IEntityTypeConfiguration<Secret>
{
    public void Configure(EntityTypeBuilder<Secret> builder)
    {
        builder.ToTable("secrets");
        builder.HasKey(s => s.Id);

        builder.Property(s => s.Id).HasColumnName("id").HasDefaultValueSql("NEWID()");
        builder.Property(s => s.Name).HasColumnName("name").HasMaxLength(255).IsRequired();
        builder.Property(s => s.Username).HasColumnName("username").HasMaxLength(255);
        builder.Property(s => s.Url).HasColumnName("url").HasMaxLength(2048);
        builder.Property(s => s.Notes).HasColumnName("notes").HasMaxLength(4096);
        builder.Property(s => s.Type).HasColumnName("type").HasConversion<int>();

        // Encrypted binary fields
        builder.Property(s => s.ValueEnc).HasColumnName("value_enc").HasColumnType("varbinary(max)").IsRequired();
        builder.Property(s => s.DekEnc).HasColumnName("dek_enc").HasColumnType("varbinary(max)").IsRequired();
        builder.Property(s => s.Nonce).HasColumnName("nonce").HasColumnType("varbinary(max)").IsRequired();

        // Tags: SQL Server has no native array type. Store as a unit-separator (U+001F) delimited
        // string in nvarchar(2048). Tag values may not contain the delimiter (enforced at the API layer).
        builder.Property(s => s.Tags)
            .HasColumnName("tags")
            .HasColumnType("nvarchar(2048)")
            .IsRequired()
            .HasConversion(
                v => v == null || v.Length == 0 ? string.Empty : string.Join('', v),
                v => string.IsNullOrEmpty(v) ? Array.Empty<string>() : v.Split('', StringSplitOptions.RemoveEmptyEntries),
                new ValueComparer<string[]>(
                    (a, b) => (a ?? Array.Empty<string>()).SequenceEqual(b ?? Array.Empty<string>()),
                    a => a == null ? 0 : a.Aggregate(0, (h, x) => HashCode.Combine(h, x.GetHashCode())),
                    a => a == null ? Array.Empty<string>() : a.ToArray()));

        builder.Property(s => s.FolderId).HasColumnName("folder_id").IsRequired();
        builder.Property(s => s.CreatedByUserId).HasColumnName("created_by_user_id").IsRequired();
        builder.Property(s => s.UpdatedByUserId).HasColumnName("updated_by_user_id");
        builder.Property(s => s.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("SYSUTCDATETIME()");
        builder.Property(s => s.UpdatedAt).HasColumnName("updated_at").HasDefaultValueSql("SYSUTCDATETIME()");
        builder.Property(s => s.DeletedAt).HasColumnName("deleted_at");
        builder.Property(s => s.PurgeAfter).HasColumnName("purge_after");

        builder.HasOne(s => s.Folder)
            .WithMany(f => f.Secrets)
            .HasForeignKey(s => s.FolderId)
            .OnDelete(DeleteBehavior.Restrict);

        builder.HasOne(s => s.CreatedBy)
            .WithMany()
            .HasForeignKey(s => s.CreatedByUserId)
            .OnDelete(DeleteBehavior.Restrict);

        builder.HasIndex(s => s.FolderId);
        builder.HasIndex(s => s.DeletedAt);
        builder.HasIndex(s => s.Type);

        // Global query filter: hide soft-deleted secrets by default
        builder.HasQueryFilter(s => s.DeletedAt == null);
    }
}
