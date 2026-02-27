using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SecureVault.Core.Entities;

namespace SecureVault.Infrastructure.Data.Configurations;

public class FolderAclConfiguration : IEntityTypeConfiguration<FolderAcl>
{
    public void Configure(EntityTypeBuilder<FolderAcl> builder)
    {
        builder.ToTable("folder_acl");
        builder.HasKey(fa => new { fa.FolderId, fa.RoleId });

        builder.Property(fa => fa.FolderId).HasColumnName("folder_id");
        builder.Property(fa => fa.RoleId).HasColumnName("role_id");
        builder.Property(fa => fa.Permissions).HasColumnName("permissions").HasConversion<int>();
        builder.Property(fa => fa.UpdatedAt).HasColumnName("updated_at").HasDefaultValueSql("NOW()");

        builder.HasOne(fa => fa.Folder)
            .WithMany(f => f.FolderAcls)
            .HasForeignKey(fa => fa.FolderId)
            .OnDelete(DeleteBehavior.Cascade);

        builder.HasOne(fa => fa.Role)
            .WithMany(r => r.FolderAcls)
            .HasForeignKey(fa => fa.RoleId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
