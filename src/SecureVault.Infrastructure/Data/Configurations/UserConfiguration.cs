using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SecureVault.Core.Entities;

namespace SecureVault.Infrastructure.Data.Configurations;

public class UserConfiguration : IEntityTypeConfiguration<User>
{
    public void Configure(EntityTypeBuilder<User> builder)
    {
        builder.ToTable("users");
        builder.HasKey(u => u.Id);

        builder.Property(u => u.Id).HasColumnName("id").HasDefaultValueSql("gen_random_uuid()");
        builder.Property(u => u.Username).HasColumnName("username").HasMaxLength(100).IsRequired();
        builder.Property(u => u.Email).HasColumnName("email").HasMaxLength(254).IsRequired();
        builder.Property(u => u.PasswordHash).HasColumnName("password_hash").HasMaxLength(512);
        builder.Property(u => u.IsActive).HasColumnName("is_active").HasDefaultValue(true);
        builder.Property(u => u.IsSuperAdmin).HasColumnName("is_super_admin").HasDefaultValue(false);
        builder.Property(u => u.IsLdapUser).HasColumnName("is_ldap_user").HasDefaultValue(false);
        builder.Property(u => u.FailedAttempts).HasColumnName("failed_attempts").HasDefaultValue(0);
        builder.Property(u => u.LockedUntil).HasColumnName("locked_until");
        builder.Property(u => u.MfaEnabled).HasColumnName("mfa_enabled").HasDefaultValue(false);
        builder.Property(u => u.MfaSecretEnc).HasColumnName("mfa_secret_enc").HasColumnType("bytea");
        builder.Property(u => u.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("NOW()");
        builder.Property(u => u.UpdatedAt).HasColumnName("updated_at").HasDefaultValueSql("NOW()");

        builder.HasIndex(u => u.Username).IsUnique();
        builder.HasIndex(u => u.Email).IsUnique();
    }
}
