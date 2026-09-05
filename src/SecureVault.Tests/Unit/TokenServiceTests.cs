using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Security.Claims;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Moq;
using SecureVault.Core.Entities;
using SecureVault.Infrastructure.Data;
using SecureVault.Infrastructure.Services;
using Xunit;

namespace SecureVault.Tests.Unit;

public class TokenServiceTests : IDisposable
{
    private readonly RSA _rsa = RSA.Create(2048);
    private readonly TokenService _sut;

    public TokenServiceTests()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Auth:JwtIssuer"] = "SecureVault.Tests",
                ["Auth:JwtAudience"] = "SecureVault.TestClient"
            })
            .Build();

        _sut = new TokenService(
            configuration,
            Mock.Of<IDbContextFactory<AppDbContext>>(),
            new RsaSecurityKey(_rsa));
    }

    [Fact]
    public void GenerateAccessToken_UsesRs256AndIncludesIdentityAndRoles()
    {
        var user = new User
        {
            Id = Guid.NewGuid(),
            Username = "alice",
            IsSuperAdmin = true
        };
        var roles = new[] { Guid.NewGuid(), Guid.NewGuid() };

        var (rawToken, expiresAt) = _sut.GenerateAccessToken(user, roles);

        var token = new JwtSecurityTokenHandler().ReadJwtToken(rawToken);
        token.Header.Alg.Should().Be(SecurityAlgorithms.RsaSha256);
        token.Issuer.Should().Be("SecureVault.Tests");
        token.Audiences.Should().ContainSingle().Which.Should().Be("SecureVault.TestClient");
        token.Subject.Should().Be(user.Id.ToString());
        token.Claims.Single(c => c.Type == "purpose").Value.Should().Be("access");
        token.Claims.Single(c => c.Type == "security_version").Value.Should().Be(user.SecurityVersion.ToString());
        token.Claims.Single(c => c.Type == JwtRegisteredClaimNames.Name).Value.Should().Be("alice");
        token.Claims.Single(c => c.Type == "is_super_admin").Value.Should().Be("true");
        token.Claims.Where(c => c.Type == "role_ids").Select(c => c.Value)
            .Should().BeEquivalentTo(roles.Select(role => role.ToString()));
        expiresAt.Should().BeCloseTo(DateTimeOffset.UtcNow.AddMinutes(15), TimeSpan.FromSeconds(5));
    }

    [Fact]
    public void ValidateMfaChallengeToken_ValidChallenge_ReturnsPrincipal()
    {
        var userId = Guid.NewGuid();
        var token = _sut.GenerateMfaChallengeToken(userId, "alice");

        var principal = _sut.ValidateMfaChallengeToken(token);

        principal.Should().NotBeNull();
        var subject = principal!.FindFirst(JwtRegisteredClaimNames.Sub);
        subject!.Value.Should().Be(userId.ToString());
        principal.FindFirst("purpose")!.Value.Should().Be("mfa_challenge");
    }

    [Fact]
    public void ValidateMfaChallengeToken_AccessTokenWithWrongPurpose_ReturnsNull()
    {
        var user = new User { Id = Guid.NewGuid(), Username = "alice" };
        var (accessToken, _) = _sut.GenerateAccessToken(user, []);

        _sut.ValidateMfaChallengeToken(accessToken).Should().BeNull();
    }

    [Fact]
    public void ValidateMfaChallengeToken_TamperedToken_ReturnsNull()
    {
        var token = _sut.GenerateMfaChallengeToken(Guid.NewGuid(), "alice");
        var parts = token.Split('.');
        parts[1] = parts[1][..^1] + (parts[1][^1] == 'A' ? 'B' : 'A');

        _sut.ValidateMfaChallengeToken(string.Join('.', parts)).Should().BeNull();
    }

    [Fact]
    public void ValidationParameters_RequireIssuerAudienceLifetimeRs256AndNoClockSkew()
    {
        var parameters = _sut.GetValidationParameters();

        parameters.ValidateIssuer.Should().BeTrue();
        parameters.ValidateAudience.Should().BeTrue();
        parameters.ValidateLifetime.Should().BeTrue();
        parameters.ClockSkew.Should().Be(TimeSpan.Zero);
        parameters.ValidAlgorithms.Should().ContainSingle().Which.Should().Be(SecurityAlgorithms.RsaSha256);
    }

    public void Dispose() => _rsa.Dispose();
}
