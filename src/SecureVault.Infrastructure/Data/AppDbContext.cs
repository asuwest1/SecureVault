using Microsoft.EntityFrameworkCore;
using SecureVault.Core.Entities;
using SecureVault.Infrastructure.Data.Configurations;

namespace SecureVault.Infrastructure.Data;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    public DbSet<User> Users => Set<User>();
    public DbSet<Role> Roles => Set<Role>();
    public DbSet<UserRole> UserRoles => Set<UserRole>();
    public DbSet<Folder> Folders => Set<Folder>();
    public DbSet<Secret> Secrets => Set<Secret>();
    public DbSet<SecretVersion> SecretVersions => Set<SecretVersion>();
    public DbSet<SecretAcl> SecretAcls => Set<SecretAcl>();
    public DbSet<FolderAcl> FolderAcls => Set<FolderAcl>();
    public DbSet<ApiToken> ApiTokens => Set<ApiToken>();
    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();
    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.ApplyConfiguration(new UserConfiguration());
        modelBuilder.ApplyConfiguration(new RoleConfiguration());
        modelBuilder.ApplyConfiguration(new UserRoleConfiguration());
        modelBuilder.ApplyConfiguration(new FolderConfiguration());
        modelBuilder.ApplyConfiguration(new SecretConfiguration());
        modelBuilder.ApplyConfiguration(new SecretVersionConfiguration());
        modelBuilder.ApplyConfiguration(new SecretAclConfiguration());
        modelBuilder.ApplyConfiguration(new FolderAclConfiguration());
        modelBuilder.ApplyConfiguration(new ApiTokenConfiguration());
        modelBuilder.ApplyConfiguration(new AuditLogConfiguration());
        modelBuilder.ApplyConfiguration(new RefreshTokenConfiguration());
    }
}
