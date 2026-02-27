using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using SecureVault.Core.Entities;
using SecureVault.Infrastructure.Data;

namespace SecureVault.Infrastructure.Services;

public class TokenService
{
    private const int AccessTokenMinutes = 15;
    private const int RefreshTokenHours = 8;

    private readonly RsaSecurityKey _signingKey;
    private readonly string _issuer;
    private readonly string _audience;
    private readonly IDbContextFactory<AppDbContext> _dbFactory;

    public TokenService(
        IConfiguration configuration,
        IDbContextFactory<AppDbContext> dbFactory,
        RsaSecurityKey signingKey)
    {
        _dbFactory = dbFactory;
        _issuer = configuration["Auth:JwtIssuer"] ?? "SecureVault";
        _audience = configuration["Auth:JwtAudience"] ?? "SecureVault";
        _signingKey = signingKey;
    }

    public string GenerateAccessToken(User user, IEnumerable<Guid> roleIds)
    {
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new(JwtRegisteredClaimNames.Name, user.Username),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new("is_super_admin", user.IsSuperAdmin.ToString().ToLower()),
        };

        foreach (var roleId in roleIds)
            claims.Add(new Claim("role_ids", roleId.ToString()));

        var credentials = new SigningCredentials(_signingKey, SecurityAlgorithms.RsaSha256);
        var token = new JwtSecurityToken(
            issuer: _issuer,
            audience: _audience,
            claims: claims,
            notBefore: DateTime.UtcNow,
            expires: DateTime.UtcNow.AddMinutes(AccessTokenMinutes),
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public string GenerateMfaChallengeToken(Guid userId, string username)
    {
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, userId.ToString()),
            new Claim(JwtRegisteredClaimNames.Name, username),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim("purpose", "mfa_challenge")
        };

        var token = new JwtSecurityToken(
            issuer: _issuer,
            audience: _audience,
            claims: claims,
            notBefore: DateTime.UtcNow,
            expires: DateTime.UtcNow.AddMinutes(5),
            signingCredentials: new SigningCredentials(_signingKey, SecurityAlgorithms.RsaSha256));

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public ClaimsPrincipal? ValidateMfaChallengeToken(string token)
    {
        var parameters = GetValidationParameters();
        var handler = new JwtSecurityTokenHandler();

        try
        {
            var principal = handler.ValidateToken(token, parameters, out var validatedToken);
            if (validatedToken is not JwtSecurityToken)
                return null;

            var purpose = principal.FindFirstValue("purpose");
            if (!string.Equals(purpose, "mfa_challenge", StringComparison.Ordinal))
                return null;

            return principal;
        }
        catch
        {
            return null;
        }
    }

    public async Task<(string token, DateTimeOffset expiresAt)> GenerateRefreshTokenAsync(
        Guid userId, CancellationToken cancellationToken = default)
    {
        var rawToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
        var tokenHash = ComputeHash(rawToken);
        var expiresAt = DateTimeOffset.UtcNow.AddHours(RefreshTokenHours);

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        db.RefreshTokens.Add(new RefreshToken
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            TokenHash = tokenHash,
            ExpiresAt = expiresAt,
            CreatedAt = DateTimeOffset.UtcNow
        });
        await db.SaveChangesAsync(cancellationToken);

        return (rawToken, expiresAt);
    }

    public async Task<User?> ValidateRefreshTokenAsync(
        string rawToken, CancellationToken cancellationToken = default)
    {
        var tokenHash = ComputeHash(rawToken);

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);

        // Atomic revocation: UPDATE ... WHERE is_revoked = false RETURNING the row.
        // If 0 rows updated, the token was already used (potential theft) or doesn't exist.
        var rowsAffected = await db.RefreshTokens
            .Where(rt => rt.TokenHash == tokenHash
                && !rt.IsRevoked
                && rt.ExpiresAt > DateTimeOffset.UtcNow)
            .ExecuteUpdateAsync(
                s => s.SetProperty(rt => rt.IsRevoked, true),
                cancellationToken);

        if (rowsAffected == 0) return null;

        // Token was atomically revoked — now load the user for the new token
        var refreshToken = await db.RefreshTokens
            .Include(rt => rt.User)
            .ThenInclude(u => u.UserRoles)
            .AsNoTracking()
            .FirstOrDefaultAsync(rt => rt.TokenHash == tokenHash, cancellationToken);

        if (refreshToken?.User is not { IsActive: true })
            return null;

        return refreshToken.User;
    }

    public async Task RevokeAllRefreshTokensAsync(
        Guid userId, CancellationToken cancellationToken = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        await db.RefreshTokens
            .Where(rt => rt.UserId == userId && !rt.IsRevoked)
            .ExecuteUpdateAsync(s => s.SetProperty(rt => rt.IsRevoked, true), cancellationToken);
    }

    public TokenValidationParameters GetValidationParameters() =>
        new()
        {
            ValidateIssuer = true,
            ValidIssuer = _issuer,
            ValidateAudience = true,
            ValidAudience = _audience,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero,  // No grace period
            IssuerSigningKey = _signingKey,
            ValidAlgorithms = [SecurityAlgorithms.RsaSha256]
        };

    private static string ComputeHash(string input)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(bytes);
    }
}
