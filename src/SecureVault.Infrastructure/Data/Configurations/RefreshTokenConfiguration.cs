using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SecureVault.Core.Entities;

namespace SecureVault.Infrastructure.Data.Configurations;

public class RefreshTokenConfiguration : IEntityTypeConfiguration<RefreshToken>
{
    public void Configure(EntityTypeBuilder<RefreshToken> builder)
    {
        builder.ToTable("refresh_tokens");
        builder.HasKey(rt => rt.Id);

        builder.Property(rt => rt.Id).HasColumnName("id").HasDefaultValueSql("gen_random_uuid()");
        builder.Property(rt => rt.UserId).HasColumnName("user_id").IsRequired();
        builder.Property(rt => rt.TokenHash).HasColumnName("token_hash").HasMaxLength(256).IsRequired();
        builder.Property(rt => rt.ExpiresAt).HasColumnName("expires_at").IsRequired();
        builder.Property(rt => rt.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("NOW()");
        builder.Property(rt => rt.IsRevoked).HasColumnName("is_revoked").HasDefaultValue(false);

        builder.HasOne(rt => rt.User)
            .WithMany()
            .HasForeignKey(rt => rt.UserId)
            .OnDelete(DeleteBehavior.Cascade);

        builder.HasIndex(rt => rt.TokenHash).IsUnique();
        builder.HasIndex(rt => new { rt.UserId, rt.IsRevoked });
    }
}
