using SecureVault.Core.Enums;

namespace SecureVault.Core.Entities;

public class SecretAcl
{
    public Guid SecretId { get; set; }
    public Guid RoleId { get; set; }
    public SecretPermission Permissions { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }

    public Secret Secret { get; set; } = null!;
    public Role Role { get; set; } = null!;
}
