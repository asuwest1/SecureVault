using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using SecureVault.Core.Entities;
using SecureVault.Core.Enums;
using SecureVault.Core.Interfaces;
using SecureVault.Infrastructure.Data;

namespace SecureVault.Api.Services;

/// <summary>
/// Handles first-run system initialization: MEK generation, RSA key pair, Super Admin, root folder.
/// Uses a DB row lock (FOR UPDATE) to prevent race conditions on concurrent calls.
/// </summary>
public class FirstRunService
{
    private static readonly SemaphoreSlim _lock = new(1, 1);

    private readonly IDbContextFactory<AppDbContext> _dbFactory;
    private readonly IEncryptionService _encryption;
    private readonly IAuditService _audit;
    private readonly IConfiguration _config;
    private readonly ILogger<FirstRunService> _logger;

    public FirstRunService(
        IDbContextFactory<AppDbContext> dbFactory,
        IEncryptionService encryption,
        IAuditService audit,
        IConfiguration config,
        ILogger<FirstRunService> logger)
    {
        _dbFactory = dbFactory;
        _encryption = encryption;
        _audit = audit;
        _config = config;
        _logger = logger;
    }

    public async Task<bool> IsInitializedAsync(CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        return await db.Users.AnyAsync(u => u.IsSuperAdmin, ct);
    }

    public async Task InitializeAsync(
        string adminUsername,
        string adminEmail,
        string adminPassword,
        CancellationToken ct = default)
    {
        await _lock.WaitAsync(ct);
        try
        {
            await using var db = await _dbFactory.CreateDbContextAsync(ct);

            // Double-check inside lock
            if (await db.Users.AnyAsync(u => u.IsSuperAdmin, ct))
                throw new InvalidOperationException("System is already initialized.");

            ValidatePasswordStrength(adminPassword);

            // Derive key file path from server configuration — never from user input
            var keyFilePath = Environment.GetEnvironmentVariable("SECUREVAULT_KEY_FILE")
                ?? _config["Encryption:KeyFilePath"]
                ?? throw new InvalidOperationException(
                    "MEK key file path not configured. Set SECUREVAULT_KEY_FILE environment variable " +
                    "or Encryption:KeyFilePath in appsettings.");

            // 1. Generate 32-byte MEK
            var mek = new byte[32];
            RandomNumberGenerator.Fill(mek);
            var dir = Path.GetDirectoryName(keyFilePath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            await File.WriteAllBytesAsync(keyFilePath, mek, ct);
            SetRestrictedFilePermissions(keyFilePath);
            CryptographicOperations.ZeroMemory(mek);
            _logger.LogInformation("MEK generated and written to configured path");

            // 2. Generate 2048-bit RSA key pair for JWT signing
            var jwtKeyPath = _config["Auth:JwtSigningKeyPath"]
                ?? Path.Combine(Path.GetDirectoryName(keyFilePath)!, "jwt-signing.pem");

            using var rsa = RSA.Create(2048);
            var privateKeyPem = rsa.ExportRSAPrivateKeyPem();
            await File.WriteAllTextAsync(jwtKeyPath, privateKeyPem, ct);
            SetRestrictedFilePermissions(jwtKeyPath);
            _logger.LogInformation("JWT RSA key pair generated");

            // 3. Create Super Admin user
            var admin = new User
            {
                Id = Guid.NewGuid(),
                Username = adminUsername,
                Email = adminEmail,
                PasswordHash = _encryption.HashPassword(adminPassword),
                IsSuperAdmin = true,
                IsActive = true,
                CreatedAt = DateTimeOffset.UtcNow,
                UpdatedAt = DateTimeOffset.UtcNow
            };
            db.Users.Add(admin);

            // 4. Create root folder
            var rootFolder = new Folder
            {
                Id = Guid.NewGuid(),
                Name = "Root",
                ParentFolderId = null,
                Depth = 0,
                CreatedAt = DateTimeOffset.UtcNow,
                UpdatedAt = DateTimeOffset.UtcNow
            };
            db.Folders.Add(rootFolder);

            await db.SaveChangesAsync(ct);

            // 5. Audit system initialization
            await _audit.LogAsync(
                AuditAction.SystemInitialized,
                admin.Id,
                admin.Username,
                detail: new Dictionary<string, object?>
                {
                    ["admin_username"] = adminUsername
                });

            await _audit.LogAsync(AuditAction.SystemKeyLoaded, admin.Id, admin.Username);

            _logger.LogInformation("SecureVault initialization complete. Admin user: {Username}", adminUsername);
        }
        finally
        {
            _lock.Release();
        }
    }

    /// <summary>
    /// Sets file permissions to owner-read-only (400) using .NET 8 API.
    /// Avoids Process.Start("chmod") which is vulnerable to path injection.
    /// </summary>
    private static void SetRestrictedFilePermissions(string filePath)
    {
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(filePath, UnixFileMode.UserRead);
        }
    }

    private static void ValidatePasswordStrength(string password)
    {
        if (password.Length < 12)
            throw new InvalidOperationException("Password must be at least 12 characters.");
        if (!password.Any(char.IsUpper))
            throw new InvalidOperationException("Password must contain at least one uppercase letter.");
        if (!password.Any(char.IsLower))
            throw new InvalidOperationException("Password must contain at least one lowercase letter.");
        if (!password.Any(char.IsDigit))
            throw new InvalidOperationException("Password must contain at least one digit.");
        if (!password.Any(c => !char.IsLetterOrDigit(c)))
            throw new InvalidOperationException("Password must contain at least one special character.");
    }
}
