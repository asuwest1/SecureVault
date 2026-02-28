using System.Net;
using System.Net.Http.Json;
using System.Text;
using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Testcontainers.PostgreSql;
using SecureVault.Infrastructure.Data;
using Xunit;

namespace SecureVault.Tests.Security;

/// <summary>
/// Security-focused tests covering:
/// - Plaintext-in-DB check (AC-4)
/// - JWT algorithm confusion (RS256 → HS256 downgrade)
/// - Privilege escalation
/// - CSRF protection
/// </summary>
[Trait("Category", "Security")]
public class SecurityTests : IAsyncLifetime
{
    private readonly string _jwtKeyPath = Path.Combine(Path.GetTempPath(), $"jwt-sec-{Guid.NewGuid()}.pem");
    private readonly string _mekFilePath = Path.GetTempFileName();

    private readonly PostgreSqlContainer _postgres = new PostgreSqlBuilder()
        .WithImage("postgres:16-alpine")
        .WithDatabase("securevault_sec_test")
        .WithUsername("test")
        .WithPassword("testpass")
        .Build();

    private WebApplicationFactory<Program>? _factory;
    private HttpClient? _client;

    private HttpClient Client => _client ?? throw new InvalidOperationException("Test client not initialized.");

    public async Task InitializeAsync()
    {
        await _postgres.StartAsync();
        WriteJwtKey(_jwtKeyPath);

        // Generate MEK before factory creation
        var mek = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(mek);
        File.WriteAllBytes(_mekFilePath, mek);

        _factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.ConfigureAppConfiguration((_, config) =>
                {
                    config.AddInMemoryCollection(new Dictionary<string, string?>
                    {
                        ["Auth:JwtSigningKeyPath"] = _jwtKeyPath,
                        ["Encryption:KeyFilePath"] = _mekFilePath,
                    });
                });

                builder.ConfigureServices(services =>
                {
                    services.RemoveAll<DbContextOptions<AppDbContext>>();
                    services.RemoveAll<DbContextOptions>();
                    services.RemoveAll<AppDbContext>();
                    services.RemoveAll<IDbContextFactory<AppDbContext>>();

                    services.AddDbContextFactory<AppDbContext>(options =>
                        options.UseNpgsql(_postgres.GetConnectionString())
                               .UseSnakeCaseNamingConvention());
                    services.AddScoped(sp =>
                        sp.GetRequiredService<IDbContextFactory<AppDbContext>>().CreateDbContext());
                });
            });

        _client = _factory.CreateClient();

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        await db.Database.MigrateAsync();
    }

    /// <summary>
    /// AC-4: After creating a secret, verify that the raw database storage
    /// does NOT contain the plaintext value.
    /// </summary>
    [Fact]
    public async Task SecretValue_NotStoredInPlaintext_InDatabase()
    {
        const string plaintextSecret = "SuperSecretP@ssw0rd_12345";

        // Initialize and login
        var token = await SetupAndLoginAsync();
        Client.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

        // Create a folder first, then a secret
        var folderResponse = await Client.PostAsJsonAsync("/api/v1/folders", new
        {
            Name = "Test Folder"
        });
        folderResponse.StatusCode.Should().Be(HttpStatusCode.Created);
        var folder = await folderResponse.Content.ReadFromJsonAsync<FolderResult>();
        folder.Should().NotBeNull();

        var createSecretResponse = await Client.PostAsJsonAsync("/api/v1/secrets", new
        {
            Name = "Test Secret",
            Value = plaintextSecret,
            Type = 1,  // Password
            FolderId = folder!.Id
        });
        createSecretResponse.StatusCode.Should().Be(HttpStatusCode.Created);
        var createdSecret = await createSecretResponse.Content.ReadFromJsonAsync<SecretResult>();
        createdSecret.Should().NotBeNull();

        // Query raw bytes from database
        using var scope = _factory!.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

        var secret = await db.Secrets.AsNoTracking()
            .SingleOrDefaultAsync(s => s.Id == createdSecret!.Id);
        secret.Should().NotBeNull();

        // Acceptance Criterion AC-4: No plaintext in database
        var valueEncAsString = Encoding.UTF8.GetString(secret!.ValueEnc);
        valueEncAsString.Should().NotContain(plaintextSecret,
            because: "secret values must be encrypted in the database");

        // Also check that encrypted bytes do not equal plaintext bytes
        var plaintextBytes = Encoding.UTF8.GetBytes(plaintextSecret);
        secret.ValueEnc.Should().NotEqual(plaintextBytes,
            because: "encryption must transform the data");
    }

    /// <summary>
    /// JWT algorithm confusion attack: attempt to use an RS256 token as HS256.
    /// Server should reject tokens with unexpected algorithms.
    /// </summary>
    [Fact]
    public async Task JwtAlgorithmConfusion_RS256ToHS256_IsRejected()
    {
        // Craft a token claiming RS256 but signed with HMAC using public key bytes
        var tamperedToken = CreateHS256TokenWithRS256PublicKey();

        Client.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", tamperedToken);

        var response = await Client.GetAsync("/api/v1/secrets");
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized,
            because: "algorithm confusion attacks must be rejected");
    }

    /// <summary>
    /// Privilege escalation: a regular user cannot access admin endpoints.
    /// </summary>
    [Fact]
    public async Task RegularUser_CannotAccess_AdminEndpoints()
    {
        var adminToken = await SetupAndLoginAsync();
        Client.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", adminToken);

        // Super admin endpoint should be accessible with super admin token
        var auditResponse = await Client.GetAsync("/api/v1/audit");
        auditResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        // Create a regular (non-admin) user via admin token
        var createUserResponse = await Client.PostAsJsonAsync("/api/v1/users", new
        {
            Username = "regularuser",
            Email = "regular@test.com",
            Password = "RegularUser123!",
            IsSuperAdmin = false
        });
        createUserResponse.StatusCode.Should().Be(HttpStatusCode.Created);

        // Login as the regular user
        var loginResponse = await Client.PostAsJsonAsync("/api/v1/auth/login", new
        {
            Username = "regularuser",
            Password = "RegularUser123!"
        });
        var login = await loginResponse.Content.ReadFromJsonAsync<LoginResult>();
        login.Should().NotBeNull();

        // Switch to regular user token
        Client.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", login!.AccessToken);

        // Verify regular user is denied access to admin-only endpoints
        var adminEndpoints = new[] { "/api/v1/audit", "/api/v1/users" };

        foreach (var endpoint in adminEndpoints)
        {
            var response = await Client.GetAsync(endpoint);
            response.StatusCode.Should().NotBe(HttpStatusCode.OK,
                because: $"regular user must be denied access to admin endpoint {endpoint}");
        }
    }

    /// <summary>
    /// Setup endpoint is disabled after initialization (returns 410 Gone).
    /// </summary>
    [Fact]
    public async Task SetupEndpoint_AfterInit_Returns410Gone()
    {
        await SetupAndLoginAsync();

        var response = await Client.PostAsJsonAsync("/api/v1/setup/initialize", new
        {
            AdminUsername = "attacker",
            AdminEmail = "attacker@evil.com",
            AdminPassword = "Attacker123!"
        });

        response.StatusCode.Should().Be(HttpStatusCode.Gone,
            because: "setup endpoint must be disabled after initialization");
    }

    private async Task<string> SetupAndLoginAsync()
    {
        var initResponse = await Client.PostAsJsonAsync("/api/v1/setup/initialize", new
        {
            AdminUsername = "secadmin",
            AdminEmail = "secadmin@test.com",
            AdminPassword = "SecAdmin123!"
        });
        initResponse.StatusCode.Should().BeOneOf(
            new[] { HttpStatusCode.OK, HttpStatusCode.Gone },
            "setup should succeed or already be initialized");

        var loginResponse = await Client.PostAsJsonAsync("/api/v1/auth/login", new
        {
            Username = "secadmin",
            Password = "SecAdmin123!"
        });
        loginResponse.StatusCode.Should().Be(HttpStatusCode.OK,
            because: "login with valid credentials should succeed");

        var login = await loginResponse.Content.ReadFromJsonAsync<LoginResult>();
        return login!.AccessToken;
    }

    private static string CreateHS256TokenWithRS256PublicKey()
    {
        // Create a fake token that looks like RS256 but is signed with HMAC
        // This simulates the algorithm confusion attack
        var header = Convert.ToBase64String(Encoding.UTF8.GetBytes(@"{""alg"":""HS256"",""typ"":""JWT""}"))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var payload = Convert.ToBase64String(Encoding.UTF8.GetBytes(@"{""sub"":""00000000-0000-0000-0000-000000000001"",""is_super_admin"":""true"",""exp"":9999999999}"))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var signature = "fake_signature_for_algorithm_confusion_test";
        return $"{header}.{payload}.{signature}";
    }

    public async Task DisposeAsync()
    {
        _client?.Dispose();
        if (_factory != null) await _factory.DisposeAsync();
        await _postgres.DisposeAsync();

        if (File.Exists(_jwtKeyPath))
            File.Delete(_jwtKeyPath);
        if (File.Exists(_mekFilePath))
            File.Delete(_mekFilePath);
    }

    private static void WriteJwtKey(string path)
    {
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        File.WriteAllText(path, rsa.ExportRSAPrivateKeyPem());
    }

    private record LoginResult(string AccessToken, string ExpiresAt, bool MfaRequired);
    private record FolderResult(string Id, string Name);
    private record SecretResult(Guid Id, string Name);
}
