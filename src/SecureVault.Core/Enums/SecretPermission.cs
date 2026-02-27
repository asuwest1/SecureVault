namespace SecureVault.Core.Enums;

[Flags]
public enum SecretPermission
{
    None = 0,
    View = 1,
    Add = 2,
    Change = 4,
    Delete = 8,
    Full = View | Add | Change | Delete
}
