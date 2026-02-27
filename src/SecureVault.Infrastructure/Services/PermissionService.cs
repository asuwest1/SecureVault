using Microsoft.EntityFrameworkCore;
using SecureVault.Core.Enums;
using SecureVault.Core.Interfaces;
using SecureVault.Infrastructure.Data;

namespace SecureVault.Infrastructure.Services;

/// <summary>
/// Resolves ACL permissions per TechSpec §7.1.
/// Resolution order: Super Admin → Secret ACL → Folder hierarchy → DENY
/// Never caches — ACL changes take effect immediately.
/// </summary>
public class PermissionService : IPermissionService
{
    private readonly IDbContextFactory<AppDbContext> _dbFactory;

    public PermissionService(IDbContextFactory<AppDbContext> dbFactory)
    {
        _dbFactory = dbFactory;
    }

    public async Task<SecretPermission?> GetSecretPermissionAsync(
        Guid userId,
        IEnumerable<Guid> roleIds,
        bool isSuperAdmin,
        Guid secretId,
        CancellationToken cancellationToken = default)
    {
        // 1. Super admin shortcut
        if (isSuperAdmin) return SecretPermission.Full;

        var roleIdList = roleIds.ToList();
        if (roleIdList.Count == 0) return null;  // DENY

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);

        // 2. Check secret-level ACL for any of the user's roles
        var secretAcl = await db.SecretAcls
            .AsNoTracking()
            .Where(a => a.SecretId == secretId && roleIdList.Contains(a.RoleId))
            .ToListAsync(cancellationToken);

        if (secretAcl.Count > 0)
        {
            // Additive across roles
            var combined = secretAcl.Aggregate(SecretPermission.None, (acc, a) => acc | a.Permissions);
            return combined == SecretPermission.None ? null : combined;
        }

        // 3. Walk folder hierarchy via recursive CTE
        if (!db.Database.IsRelational())
        {
            var folderId = await db.Secrets
                .AsNoTracking()
                .Where(s => s.Id == secretId)
                .Select(s => s.FolderId)
                .SingleOrDefaultAsync(cancellationToken);

            if (folderId == Guid.Empty)
                return null;

            var nonRelationalFolderPermissions = await GetFolderPermissionsNonRelationalAsync(
                db,
                folderId,
                roleIdList,
                cancellationToken);

            if (nonRelationalFolderPermissions.Count > 0)
            {
                var nonRelationalCombined = nonRelationalFolderPermissions.Aggregate(SecretPermission.None, (acc, p) => acc | p);
                return nonRelationalCombined == SecretPermission.None ? null : nonRelationalCombined;
            }

            return null;
        }

        var sql = @"
            WITH RECURSIVE folder_path AS (
                SELECT f.id, f.parent_folder_id
                FROM folders f
                JOIN secrets s ON s.folder_id = f.id
                WHERE s.id = {0}
                UNION ALL
                SELECT f.id, f.parent_folder_id
                FROM folders f
                JOIN folder_path fp ON fp.parent_folder_id = f.id
            )
            SELECT fa.permissions
            FROM folder_acl fa
            JOIN folder_path fp ON fp.id = fa.folder_id
            WHERE fa.role_id = ANY({1})
        ";

        var roleIdArray = roleIdList.ToArray();
        var folderPermissions = await db.Database
            .SqlQueryRaw<int>(sql, secretId, roleIdArray)
            .ToListAsync(cancellationToken);

        if (folderPermissions.Count > 0)
        {
            var combined = folderPermissions.Aggregate(0, (acc, p) => acc | p);
            var perm = (SecretPermission)combined;
            return perm == SecretPermission.None ? null : perm;
        }

        // 4. No ACL at any level → DENY
        return null;
    }

    public async Task<SecretPermission?> GetFolderPermissionAsync(
        Guid userId,
        IEnumerable<Guid> roleIds,
        bool isSuperAdmin,
        Guid folderId,
        CancellationToken cancellationToken = default)
    {
        if (isSuperAdmin) return SecretPermission.Full;

        var roleIdList = roleIds.ToList();
        if (roleIdList.Count == 0) return null;

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);

        if (!db.Database.IsRelational())
        {
            var nonRelationalPermissions = await GetFolderPermissionsNonRelationalAsync(
                db,
                folderId,
                roleIdList,
                cancellationToken);

            if (nonRelationalPermissions.Count == 0) return null;

            var nonRelationalCombined = nonRelationalPermissions.Aggregate(SecretPermission.None, (acc, p) => acc | p);
            return nonRelationalCombined == SecretPermission.None ? null : nonRelationalCombined;
        }

        var sql = @"
            WITH RECURSIVE folder_path AS (
                SELECT id, parent_folder_id FROM folders WHERE id = {0}
                UNION ALL
                SELECT f.id, f.parent_folder_id FROM folders f
                JOIN folder_path fp ON fp.parent_folder_id = f.id
            )
            SELECT fa.permissions
            FROM folder_acl fa
            JOIN folder_path fp ON fp.id = fa.folder_id
            WHERE fa.role_id = ANY({1})
        ";

        var roleIdArray = roleIdList.ToArray();
        var permissions = await db.Database
            .SqlQueryRaw<int>(sql, folderId, roleIdArray)
            .ToListAsync(cancellationToken);

        if (permissions.Count == 0) return null;

        var combined = (SecretPermission)permissions.Aggregate(0, (acc, p) => acc | p);
        return combined == SecretPermission.None ? null : combined;
    }

    private static async Task<List<SecretPermission>> GetFolderPermissionsNonRelationalAsync(
        AppDbContext db,
        Guid startFolderId,
        IReadOnlyCollection<Guid> roleIds,
        CancellationToken cancellationToken)
    {
        var folderPermissions = new List<SecretPermission>();
        var currentFolderId = startFolderId;

        while (true)
        {
            var currentAcls = await db.FolderAcls
                .AsNoTracking()
                .Where(a => a.FolderId == currentFolderId && roleIds.Contains(a.RoleId))
                .Select(a => a.Permissions)
                .ToListAsync(cancellationToken);

            folderPermissions.AddRange(currentAcls);

            var parentFolderId = await db.Folders
                .AsNoTracking()
                .Where(f => f.Id == currentFolderId)
                .Select(f => f.ParentFolderId)
                .SingleOrDefaultAsync(cancellationToken);

            if (parentFolderId is null) break;

            currentFolderId = parentFolderId.Value;
        }

        return folderPermissions;
    }

    public async Task<IReadOnlyList<Guid>> GetAccessibleSecretIdsAsync(
        Guid userId,
        IEnumerable<Guid> roleIds,
        bool isSuperAdmin,
        CancellationToken cancellationToken = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);

        if (isSuperAdmin)
        {
            return await db.Secrets
                .AsNoTracking()
                .Select(s => s.Id)
                .ToListAsync(cancellationToken);
        }

        var roleIdList = roleIds.ToList();
        if (roleIdList.Count == 0) return Array.Empty<Guid>();

        // Raw SQL per TechSpec §7.3 — EF cannot express this in one query
        var sql = @"
            SELECT DISTINCT s.id
            FROM secrets s
            WHERE s.deleted_at IS NULL
            AND (
                -- Secret-level ACL
                EXISTS (
                    SELECT 1 FROM secret_acl sa
                    WHERE sa.secret_id = s.id
                    AND sa.role_id = ANY({0})
                    AND (sa.permissions & 1) = 1
                )
                OR
                -- Folder hierarchy ACL
                EXISTS (
                    WITH RECURSIVE folder_path AS (
                        SELECT f.id, f.parent_folder_id FROM folders f WHERE f.id = s.folder_id
                        UNION ALL
                        SELECT f.id, f.parent_folder_id FROM folders f
                        JOIN folder_path fp ON fp.parent_folder_id = f.id
                    )
                    SELECT 1 FROM folder_acl fa
                    JOIN folder_path fp ON fp.id = fa.folder_id
                    WHERE fa.role_id = ANY({0})
                    AND (fa.permissions & 1) = 1
                )
            )
        ";

        var roleIdArray = roleIdList.ToArray();
        var ids = await db.Database
            .SqlQueryRaw<Guid>(sql, roleIdArray)
            .ToListAsync(cancellationToken);

        return ids;
    }

    public async Task<IReadOnlySet<Guid>> GetAccessibleFolderIdsAsync(
        Guid userId,
        IEnumerable<Guid> roleIds,
        bool isSuperAdmin,
        CancellationToken cancellationToken = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);

        if (isSuperAdmin)
        {
            var allIds = await db.Folders
                .AsNoTracking()
                .Select(f => f.Id)
                .ToListAsync(cancellationToken);
            return allIds.ToHashSet();
        }

        var roleIdList = roleIds.ToList();
        if (roleIdList.Count == 0) return new HashSet<Guid>();

        // Return folder IDs where the user has any permission via folder ACL hierarchy,
        // plus all ancestor folders (so the tree can be rendered).
        var sql = @"
            WITH RECURSIVE
            -- Folders with direct ACL for user's roles
            acl_folders AS (
                SELECT DISTINCT fa.folder_id AS id
                FROM folder_acl fa
                WHERE fa.role_id = ANY({0})
                AND fa.permissions > 0
            ),
            -- Walk UP to include all ancestor folders for tree rendering
            ancestors AS (
                SELECT f.id, f.parent_folder_id
                FROM folders f
                WHERE f.id IN (SELECT id FROM acl_folders)
                UNION
                SELECT f.id, f.parent_folder_id
                FROM folders f
                JOIN ancestors a ON a.parent_folder_id = f.id
            )
            SELECT DISTINCT id FROM ancestors
        ";

        var roleIdArray = roleIdList.ToArray();
        var ids = await db.Database
            .SqlQueryRaw<Guid>(sql, roleIdArray)
            .ToListAsync(cancellationToken);

        return ids.ToHashSet();
    }
}
