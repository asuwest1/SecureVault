using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using SecureVault.Core.Entities;
using SecureVault.Core.Enums;
using SecureVault.Infrastructure.Data;
using SecureVault.Infrastructure.Services;
using Xunit;

namespace SecureVault.Tests.Unit;

/// <summary>
/// Full ACL matrix tests for PermissionService.
/// Uses an in-memory mock — real PostgreSQL CTE tests are in Integration/.
/// </summary>
public class PermissionServiceTests : IAsyncDisposable
{
    private readonly AppDbContext _db;
    private readonly PermissionService _sut;

    private static readonly Guid _userId = Guid.NewGuid();
    private static readonly Guid _roleId1 = Guid.NewGuid();
    private static readonly Guid _roleId2 = Guid.NewGuid();
    private static readonly Guid _folderId = Guid.NewGuid();
    private static readonly Guid _secretId = Guid.NewGuid();

    public PermissionServiceTests()
    {
        // Note: For PostgreSQL-specific features (CTE, GIN), use Testcontainers in Integration/
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;

        _db = new AppDbContext(options);
        var factory = new TestDbContextFactory(_db);
        _sut = new PermissionService(factory);
    }

    [Fact]
    public async Task SuperAdmin_AlwaysGetsFull_Permission()
    {
        var result = await _sut.GetSecretPermissionAsync(
            _userId, [_roleId1], isSuperAdmin: true, _secretId);

        result.Should().Be(SecretPermission.Full);
    }

    [Fact]
    public async Task NoRoles_ReturnsDeny()
    {
        var result = await _sut.GetSecretPermissionAsync(
            _userId, [], isSuperAdmin: false, _secretId);

        result.Should().BeNull("no roles means DENY");
    }

    [Fact]
    public async Task SecretAcl_MatchingRole_ReturnsCorrectPermission()
    {
        // Setup: secret with ACL for roleId1 granting View
        await SeedBaseDataAsync();
        _db.SecretAcls.Add(new SecretAcl
        {
            SecretId = _secretId,
            RoleId = _roleId1,
            Permissions = SecretPermission.View,
            UpdatedAt = DateTimeOffset.UtcNow
        });
        await _db.SaveChangesAsync();

        var result = await _sut.GetSecretPermissionAsync(
            _userId, [_roleId1], isSuperAdmin: false, _secretId);

        result.Should().Be(SecretPermission.View);
    }

    [Fact]
    public async Task MultipleRoles_PermissionsAreAdditive()
    {
        await SeedBaseDataAsync();

        // Role1 gets View, Role2 gets Change — combined should be View|Change
        _db.SecretAcls.AddRange(
            new SecretAcl { SecretId = _secretId, RoleId = _roleId1, Permissions = SecretPermission.View, UpdatedAt = DateTimeOffset.UtcNow },
            new SecretAcl { SecretId = _secretId, RoleId = _roleId2, Permissions = SecretPermission.Change, UpdatedAt = DateTimeOffset.UtcNow }
        );
        await _db.SaveChangesAsync();

        var result = await _sut.GetSecretPermissionAsync(
            _userId, [_roleId1, _roleId2], isSuperAdmin: false, _secretId);

        result.Should().HaveFlag(SecretPermission.View);
        result.Should().HaveFlag(SecretPermission.Change);
        result.Should().NotHaveFlag(SecretPermission.Delete);
    }

    [Fact]
    public async Task NoAclAtAnyLevel_ReturnsDeny()
    {
        await SeedBaseDataAsync();
        // No ACL entries added

        var result = await _sut.GetSecretPermissionAsync(
            _userId, [_roleId1], isSuperAdmin: false, _secretId);

        result.Should().BeNull("no ACL = DENY");
    }

    private async Task SeedBaseDataAsync()
    {
        _db.Folders.Add(new Folder
        {
            Id = _folderId,
            Name = "Test Folder",
            Depth = 0,
            CreatedAt = DateTimeOffset.UtcNow,
            UpdatedAt = DateTimeOffset.UtcNow
        });

        _db.Users.Add(new User
        {
            Id = _userId,
            Username = "testuser",
            Email = "test@example.com",
            CreatedAt = DateTimeOffset.UtcNow,
            UpdatedAt = DateTimeOffset.UtcNow
        });

        _db.Roles.AddRange(
            new Role { Id = _roleId1, Name = "Role1", CreatedAt = DateTimeOffset.UtcNow },
            new Role { Id = _roleId2, Name = "Role2", CreatedAt = DateTimeOffset.UtcNow }
        );

        _db.Secrets.Add(new Secret
        {
            Id = _secretId,
            Name = "Test Secret",
            Type = SecretType.Password,
            ValueEnc = new byte[32],
            DekEnc = new byte[64],
            Nonce = new byte[12],
            Tags = [],
            FolderId = _folderId,
            CreatedByUserId = _userId,
            CreatedAt = DateTimeOffset.UtcNow,
            UpdatedAt = DateTimeOffset.UtcNow
        });

        await _db.SaveChangesAsync();
    }

    public async ValueTask DisposeAsync()
    {
        await _db.DisposeAsync();
    }
}

/// <summary>Test helper: wraps a single DbContext as an IDbContextFactory.</summary>
internal class TestDbContextFactory : IDbContextFactory<AppDbContext>
{
    private readonly AppDbContext _db;
    public TestDbContextFactory(AppDbContext db) => _db = db;
    public AppDbContext CreateDbContext() => _db;
    public Task<AppDbContext> CreateDbContextAsync(CancellationToken ct = default) =>
        Task.FromResult(_db);
}
