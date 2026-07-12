using Microsoft.EntityFrameworkCore;
using SecureVault.Core.Enums;
using SecureVault.Core.Interfaces;
using SecureVault.Infrastructure.Data;

namespace SecureVault.Infrastructure.Services;

/// <summary>
/// Resolves ACL permissions per TechSpec §7.1.
/// Resolution order: Super Admin → Secret ACL → Folder hierarchy → DENY
/// Never caches — ACL changes take effect immediately.
/// SQL Server-flavored raw SQL: recursive CTE without the WITH RECURSIVE keyword,
/// role lists expanded inline as parameterised IN (...) clauses.
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
                .Where(s => s.Id == secretId && s.DeletedAt == null)
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

        // {0} = secretId, {1..N} = role ids
        var roleInClause = BuildRoleInClause(roleIdList.Count, startIndex: 1);
        var sql = $@"
            WITH folder_path AS (
                SELECT f.id, f.parent_folder_id
                FROM folders f
                JOIN secrets s ON s.folder_id = f.id
                WHERE s.id = {{0}} AND s.deleted_at IS NULL
                UNION ALL
                SELECT f.id, f.parent_folder_id
                FROM folders f
                JOIN folder_path fp ON fp.parent_folder_id = f.id
            )
            SELECT fa.permissions AS Value
            FROM folder_acl fa
            JOIN folder_path fp ON fp.id = fa.folder_id
            WHERE fa.role_id IN ({roleInClause})
        ";

        var args = BuildArgs(secretId, roleIdList);
        var folderPermissions = await db.Database
            .SqlQueryRaw<int>(sql, args)
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

        var roleInClause = BuildRoleInClause(roleIdList.Count, startIndex: 1);
        var sql = $@"
            WITH folder_path AS (
                SELECT id, parent_folder_id FROM folders WHERE id = {{0}}
                UNION ALL
                SELECT f.id, f.parent_folder_id FROM folders f
                JOIN folder_path fp ON fp.parent_folder_id = f.id
            )
            SELECT fa.permissions AS Value
            FROM folder_acl fa
            JOIN folder_path fp ON fp.id = fa.folder_id
            WHERE fa.role_id IN ({roleInClause})
        ";

        var args = BuildArgs(folderId, roleIdList);
        var permissions = await db.Database
            .SqlQueryRaw<int>(sql, args)
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
                .Where(s => s.DeletedAt == null)
                .Select(s => s.Id)
                .ToListAsync(cancellationToken);
        }

        var roleIdList = roleIds.ToList();
        if (roleIdList.Count == 0) return Array.Empty<Guid>();

        // Top-level CTE that walks DOWN from folders with read ACL to all descendants.
        // A secret is accessible if its folder ∈ descendants OR a secret-level ACL grants read.
        var roleInClause = BuildRoleInClause(roleIdList.Count, startIndex: 0);
        var sql = $@"
            WITH acl_folders AS (
                SELECT DISTINCT fa.folder_id AS id
                FROM folder_acl fa
                WHERE fa.role_id IN ({roleInClause})
                AND (fa.permissions & 1) = 1
            ),
            descendants AS (
                SELECT id, CAST(id AS uniqueidentifier) AS root_id FROM folders WHERE id IN (SELECT id FROM acl_folders)
                UNION ALL
                SELECT f.id, d.root_id FROM folders f
                JOIN descendants d ON f.parent_folder_id = d.id
            )
            SELECT DISTINCT s.id AS Value
            FROM secrets s
            WHERE s.deleted_at IS NULL
            AND (
                EXISTS (
                    SELECT 1 FROM secret_acl sa
                    WHERE sa.secret_id = s.id
                    AND sa.role_id IN ({roleInClause})
                    AND (sa.permissions & 1) = 1
                )
                OR s.folder_id IN (SELECT id FROM descendants)
            )
        ";

        var args = BuildArgs(null, roleIdList);
        var ids = await db.Database
            .SqlQueryRaw<Guid>(sql, args)
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

        if (!db.Database.IsRelational())
        {
            var directIds = await db.FolderAcls
                .AsNoTracking()
                .Where(a => roleIdList.Contains(a.RoleId) && a.Permissions != SecretPermission.None)
                .Select(a => a.FolderId)
                .Distinct()
                .ToListAsync(cancellationToken);
            var folders = await db.Folders
                .AsNoTracking()
                .Select(f => new { f.Id, f.ParentFolderId })
                .ToListAsync(cancellationToken);
            var result = directIds.ToHashSet();

            var descendantQueue = new Queue<Guid>(directIds);
            while (descendantQueue.TryDequeue(out var parentId))
            {
                foreach (var child in folders.Where(f => f.ParentFolderId == parentId))
                    if (result.Add(child.Id)) descendantQueue.Enqueue(child.Id);
            }

            foreach (var directId in directIds)
            {
                var current = folders.FirstOrDefault(f => f.Id == directId)?.ParentFolderId;
                while (current.HasValue && result.Add(current.Value))
                    current = folders.FirstOrDefault(f => f.Id == current.Value)?.ParentFolderId;
            }

            return result;
        }

        // Include inherited descendants and ancestors needed for tree rendering.
        var roleInClause = BuildRoleInClause(roleIdList.Count, startIndex: 0);
        var sql = $@"
            WITH acl_folders AS (
                SELECT DISTINCT fa.folder_id AS id
                FROM folder_acl fa
                WHERE fa.role_id IN ({roleInClause})
                AND fa.permissions > 0
            ),
            ancestors AS (
                SELECT f.id, f.parent_folder_id
                FROM folders f
                WHERE f.id IN (SELECT id FROM acl_folders)
                UNION ALL
                SELECT f.id, f.parent_folder_id
                FROM folders f
                JOIN ancestors a ON a.parent_folder_id = f.id
            ),
            descendants AS (
                SELECT f.id, f.parent_folder_id
                FROM folders f
                WHERE f.id IN (SELECT id FROM acl_folders)
                UNION ALL
                SELECT f.id, f.parent_folder_id
                FROM folders f
                JOIN descendants d ON f.parent_folder_id = d.id
            )
            SELECT DISTINCT id AS Value FROM ancestors
            UNION
            SELECT DISTINCT id AS Value FROM descendants
        ";

        var args = BuildArgs(null, roleIdList);
        var ids = await db.Database
            .SqlQueryRaw<Guid>(sql, args)
            .ToListAsync(cancellationToken);

        return ids.ToHashSet();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SQL Server-friendly helpers: build a positional IN ({startIndex},{startIndex+1},...)
    // clause whose tokens line up with the args supplied to SqlQueryRaw.
    // ─────────────────────────────────────────────────────────────────────────
    private static string BuildRoleInClause(int count, int startIndex)
    {
        if (count == 0) return "NULL";
        return string.Join(",", Enumerable.Range(startIndex, count).Select(i => "{" + i + "}"));
    }

    private static object[] BuildArgs(object? leading, IReadOnlyCollection<Guid> roleIds)
    {
        var args = new List<object>(roleIds.Count + (leading is null ? 0 : 1));
        if (leading is not null) args.Add(leading);
        foreach (var r in roleIds) args.Add(r);
        return args.ToArray();
    }
}
