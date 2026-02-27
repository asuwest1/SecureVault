using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SecureVault.Core.Entities;

namespace SecureVault.Infrastructure.Data.Configurations;

public class SecretAclConfiguration : IEntityTypeConfiguration<SecretAcl>
{
    public void Configure(EntityTypeBuilder<SecretAcl> builder)
    {
        builder.ToTable("secret_acl");
        builder.HasKey(sa => new { sa.SecretId, sa.RoleId });

        builder.Property(sa => sa.SecretId).HasColumnName("secret_id");
        builder.Property(sa => sa.RoleId).HasColumnName("role_id");
        builder.Property(sa => sa.Permissions).HasColumnName("permissions").HasConversion<int>();
        builder.Property(sa => sa.UpdatedAt).HasColumnName("updated_at").HasDefaultValueSql("NOW()");

        builder.HasOne(sa => sa.Secret)
            .WithMany(s => s.SecretAcls)
            .HasForeignKey(sa => sa.SecretId)
            .OnDelete(DeleteBehavior.Cascade);

        builder.HasOne(sa => sa.Role)
            .WithMany(r => r.SecretAcls)
            .HasForeignKey(sa => sa.RoleId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
