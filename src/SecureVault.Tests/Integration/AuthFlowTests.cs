using System.Net;
using System.Net.Http.Json;
using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Testcontainers.PostgreSql;
using SecureVault.Infrastructure.Data;
using Xunit;

namespace SecureVault.Tests.Integration;

/// <summary>
/// Integration tests for the authentication flow using Testcontainers (real PostgreSQL 16).
/// Tests run against real migrations — validates migration idempotency.
/// </summary>
public class AuthFlowTests : IAsyncLifetime
{
    private readonly string _jwtKeyPath = Path.Combine(Path.GetTempPath(), $"jwt-auth-{Guid.NewGuid()}.pem");
    private readonly string _mekFilePath = Path.GetTempFileName();

    private readonly PostgreSqlContainer _postgres = new PostgreSqlBuilder()
        .WithImage("postgres:16-alpine")
        .WithDatabase("securevault_test")
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
                    // Replace DB registrations with test container connection.
                    // Program registers both AddDbContext and AddDbContextFactory,
                    // so clear both to avoid lifetime mismatches in tests.
                    services.RemoveAll<DbContextOptions<AppDbContext>>();
                    services.RemoveAll<DbContextOptions>();
                    services.RemoveAll<AppDbContext>();
                    services.RemoveAll<IDbContextFactory<AppDbContext>>();

                    services.AddDbContextFactory<AppDbContext>(options =>
                        options.UseNpgsql(_postgres.GetConnectionString()));
                    services.AddScoped(sp =>
                        sp.GetRequiredService<IDbContextFactory<AppDbContext>>().CreateDbContext());
                });
            });

        _client = _factory.CreateClient();

        // Run migrations
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        await db.Database.MigrateAsync();
    }

    [Fact]
    public async Task Login_ValidCredentials_ReturnsAccessToken()
    {
        // First run: initialize the system
        var initResponse = await Client.PostAsJsonAsync("/api/v1/setup/initialize", new
        {
            AdminUsername = "admin",
            AdminEmail = "admin@test.com",
            AdminPassword = "TestAdmin123!",
            // KeyFilePath removed — derived from server configuration
        });
        initResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        // Login
        var loginResponse = await Client.PostAsJsonAsync("/api/v1/auth/login", new
        {
            Username = "admin",
            Password = "TestAdmin123!"
        });

        loginResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        var result = await loginResponse.Content.ReadFromJsonAsync<LoginResult>();
        result!.AccessToken.Should().NotBeNullOrEmpty();
        result.MfaRequired.Should().BeFalse();
    }

    [Fact]
    public async Task Login_WrongPassword_Returns401()
    {
        var response = await Client.PostAsJsonAsync("/api/v1/auth/login", new
        {
            Username = "admin",
            Password = "WrongPassword!"
        });

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Login_FiveFailedAttempts_LocksAccount()
    {
        // Initialize first
        await Client.PostAsJsonAsync("/api/v1/setup/initialize", new
        {
            AdminUsername = "locktest",
            AdminEmail = "lock@test.com",
            AdminPassword = "TestLock123!",
            // KeyFilePath removed — derived from server configuration
        });

        // 5 failed login attempts
        for (int i = 0; i < 5; i++)
        {
            await Client.PostAsJsonAsync("/api/v1/auth/login", new
            {
                Username = "locktest",
                Password = "WrongPassword!"
            });
        }

        // 6th attempt — should still return 401 (account locked, but message is same)
        var response = await Client.PostAsJsonAsync("/api/v1/auth/login", new
        {
            Username = "locktest",
            Password = "TestLock123!"  // Even correct password fails when locked
        });

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        // Acceptance Criterion AC-6: account locked after 5 failed attempts
    }

    [Fact]
    public async Task Logout_ClearsRefreshToken()
    {
        // Setup + login
        await InitializeTestUserAsync();
        var loginResponse = await Client.PostAsJsonAsync("/api/v1/auth/login", new
        {
            Username = "logouttest",
            Password = "Logout123!"
        });
        var login = await loginResponse.Content.ReadFromJsonAsync<LoginResult>();

        Client.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", login!.AccessToken);

        var logoutResponse = await Client.PostAsync("/api/v1/auth/logout", null);
        logoutResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        // Refresh should fail after logout
        var refreshResponse = await Client.PostAsync("/api/v1/auth/refresh", null);
        refreshResponse.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    private async Task InitializeTestUserAsync()
    {
        await Client.PostAsJsonAsync("/api/v1/setup/initialize", new
        {
            AdminUsername = "logouttest",
            AdminEmail = "logout@test.com",
            AdminPassword = "Logout123!",
            // KeyFilePath removed — derived from server configuration
        });
    }

    private static void WriteJwtKey(string path)
    {
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        File.WriteAllText(path, rsa.ExportRSAPrivateKeyPem());
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

    private record LoginResult(string AccessToken, string ExpiresAt, bool MfaRequired, string? MfaToken);
}
