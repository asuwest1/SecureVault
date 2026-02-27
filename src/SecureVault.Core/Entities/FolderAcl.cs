using SecureVault.Core.Enums;

namespace SecureVault.Core.Entities;

public class FolderAcl
{
    public Guid FolderId { get; set; }
    public Guid RoleId { get; set; }
    public SecretPermission Permissions { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }

    public Folder Folder { get; set; } = null!;
    public Role Role { get; set; } = null!;
}
