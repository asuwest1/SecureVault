namespace SecureVault.Core.Entities;

public class Role
{
    public Guid Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public DateTimeOffset CreatedAt { get; set; }

    public ICollection<UserRole> UserRoles { get; set; } = new List<UserRole>();
    public ICollection<SecretAcl> SecretAcls { get; set; } = new List<SecretAcl>();
    public ICollection<FolderAcl> FolderAcls { get; set; } = new List<FolderAcl>();
}
