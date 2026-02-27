using System.Net;
using System.Net.Http.Json;
using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
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
    private readonly PostgreSqlContainer _postgres = new PostgreSqlBuilder()
        .WithImage("postgres:16-alpine")
        .WithDatabase("securevault_test")
        .WithUsername("test")
        .WithPassword("testpass")
        .Build();

    private WebApplicationFactory<Program>? _factory;
    private HttpClient? _client;

    public async Task InitializeAsync()
    {
        await _postgres.StartAsync();

        _factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.ConfigureServices(services =>
                {
                    // Replace DB with test container connection
                    var descriptor = services.SingleOrDefault(
                        d => d.ServiceType == typeof(DbContextOptions<AppDbContext>));
                    if (descriptor != null) services.Remove(descriptor);

                    services.AddDbContext<AppDbContext>(options =>
                        options.UseNpgsql(_postgres.GetConnectionString()));

                    // Use temp MEK for tests — never hardcode keys
                    var mekFile = Path.GetTempFileName();
                    var mek = new byte[32];
                    System.Security.Cryptography.RandomNumberGenerator.Fill(mek);
                    File.WriteAllBytes(mekFile, mek);

                    Environment.SetEnvironmentVariable("SECUREVAULT_KEY_FILE", mekFile);
                    Environment.SetEnvironmentVariable("Auth__JwtSigningKeyPath", CreateTestJwtKey());
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
        var initResponse = await _client!.PostAsJsonAsync("/api/v1/setup/initialize", new
        {
            AdminUsername = "admin",
            AdminEmail = "admin@test.com",
            AdminPassword = "TestAdmin123!",
            KeyFilePath = Environment.GetEnvironmentVariable("SECUREVAULT_KEY_FILE")
        });
        initResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        // Login
        var loginResponse = await _client.PostAsJsonAsync("/api/v1/auth/login", new
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
        var response = await _client!.PostAsJsonAsync("/api/v1/auth/login", new
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
        await _client!.PostAsJsonAsync("/api/v1/setup/initialize", new
        {
            AdminUsername = "locktest",
            AdminEmail = "lock@test.com",
            AdminPassword = "TestLock123!",
            KeyFilePath = Environment.GetEnvironmentVariable("SECUREVAULT_KEY_FILE")
        });

        // 5 failed login attempts
        for (int i = 0; i < 5; i++)
        {
            await _client.PostAsJsonAsync("/api/v1/auth/login", new
            {
                Username = "locktest",
                Password = "WrongPassword!"
            });
        }

        // 6th attempt — should still return 401 (account locked, but message is same)
        var response = await _client.PostAsJsonAsync("/api/v1/auth/login", new
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
        var loginResponse = await _client!.PostAsJsonAsync("/api/v1/auth/login", new
        {
            Username = "logouttest",
            Password = "Logout123!"
        });
        var login = await loginResponse.Content.ReadFromJsonAsync<LoginResult>();

        _client.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", login!.AccessToken);

        var logoutResponse = await _client.PostAsync("/api/v1/auth/logout", null);
        logoutResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        // Refresh should fail after logout
        var refreshResponse = await _client.PostAsync("/api/v1/auth/refresh", null);
        refreshResponse.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    private async Task InitializeTestUserAsync()
    {
        await _client!.PostAsJsonAsync("/api/v1/setup/initialize", new
        {
            AdminUsername = "logouttest",
            AdminEmail = "logout@test.com",
            AdminPassword = "Logout123!",
            KeyFilePath = Environment.GetEnvironmentVariable("SECUREVAULT_KEY_FILE")
        });
    }

    private static string CreateTestJwtKey()
    {
        var keyFile = Path.GetTempFileName();
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        File.WriteAllText(keyFile, rsa.ExportRSAPrivateKeyPem());
        return keyFile;
    }

    public async Task DisposeAsync()
    {
        _client?.Dispose();
        if (_factory != null) await _factory.DisposeAsync();
        await _postgres.DisposeAsync();
    }

    private record LoginResult(string AccessToken, string ExpiresAt, bool MfaRequired, string? MfaToken);
}
