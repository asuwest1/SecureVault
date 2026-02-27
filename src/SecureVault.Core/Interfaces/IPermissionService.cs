using SecureVault.Core.Enums;

namespace SecureVault.Core.Interfaces;

public interface IPermissionService
{
    /// <summary>
    /// Resolves effective permissions for a user on a specific secret.
    /// Returns null if no ACL exists (DENY by default).
    /// Always returns Full for super admins.
    /// </summary>
    Task<SecretPermission?> GetSecretPermissionAsync(
        Guid userId,
        IEnumerable<Guid> roleIds,
        bool isSuperAdmin,
        Guid secretId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Resolves effective permissions for a user on a specific folder.
    /// Used for folder operations and secret creation within a folder.
    /// </summary>
    Task<SecretPermission?> GetFolderPermissionAsync(
        Guid userId,
        IEnumerable<Guid> roleIds,
        bool isSuperAdmin,
        Guid folderId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Returns IDs of all secrets the user has at least View permission on.
    /// Used for search scoping.
    /// </summary>
    Task<IReadOnlyList<Guid>> GetAccessibleSecretIdsAsync(
        Guid userId,
        IEnumerable<Guid> roleIds,
        bool isSuperAdmin,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Returns IDs of all folders the user has at least one permission on.
    /// Used for filtering folder listings.
    /// </summary>
    Task<IReadOnlySet<Guid>> GetAccessibleFolderIdsAsync(
        Guid userId,
        IEnumerable<Guid> roleIds,
        bool isSuperAdmin,
        CancellationToken cancellationToken = default);
}
