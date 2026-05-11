using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SecureVault.Core.Entities;

namespace SecureVault.Infrastructure.Data.Configurations;

public class SecretVersionConfiguration : IEntityTypeConfiguration<SecretVersion>
{
    public void Configure(EntityTypeBuilder<SecretVersion> builder)
    {
        builder.ToTable("secret_versions");
        builder.HasKey(sv => sv.Id);

        builder.Property(sv => sv.Id).HasColumnName("id").HasDefaultValueSql("NEWID()");
        builder.Property(sv => sv.SecretId).HasColumnName("secret_id").IsRequired();
        builder.Property(sv => sv.VersionNumber).HasColumnName("version_number").IsRequired();
        builder.Property(sv => sv.Notes).HasColumnName("notes").HasMaxLength(500);

        // Encrypted binary fields
        builder.Property(sv => sv.ValueEnc).HasColumnName("value_enc").HasColumnType("varbinary(max)").IsRequired();
        builder.Property(sv => sv.DekEnc).HasColumnName("dek_enc").HasColumnType("varbinary(max)").IsRequired();
        builder.Property(sv => sv.Nonce).HasColumnName("nonce").HasColumnType("varbinary(max)").IsRequired();

        builder.Property(sv => sv.CreatedByUserId).HasColumnName("created_by_user_id").IsRequired();
        builder.Property(sv => sv.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("SYSUTCDATETIME()");

        builder.HasOne(sv => sv.Secret)
            .WithMany(s => s.Versions)
            .HasForeignKey(sv => sv.SecretId)
            .OnDelete(DeleteBehavior.Cascade);

        builder.HasIndex(sv => new { sv.SecretId, sv.VersionNumber }).IsUnique();
    }
}
