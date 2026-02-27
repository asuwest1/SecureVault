using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using SecureVault.Infrastructure.Data;

namespace SecureVault.Api.Middleware;

/// <summary>
/// Handles API token authentication for programmatic access.
/// Token is SHA-256 hashed for lookup — plaintext token never stored.
/// Sets ClaimsPrincipal on HttpContext.User if token is valid.
/// </summary>
public class ApiTokenAuthMiddleware
{
    private const string HeaderName = "X-Api-Token";
    private readonly RequestDelegate _next;

    public ApiTokenAuthMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context, AppDbContext db)
    {
        if (context.Request.Headers.TryGetValue(HeaderName, out var tokenValue))
        {
            var rawToken = tokenValue.FirstOrDefault();
            if (!string.IsNullOrEmpty(rawToken))
            {
                var tokenHash = ComputeHash(rawToken);

                var apiToken = await db.ApiTokens
                    .Include(t => t.User)
                    .ThenInclude(u => u.UserRoles)
                    .AsNoTracking()
                    .FirstOrDefaultAsync(t =>
                        t.TokenHash == tokenHash &&
                        !t.IsRevoked &&
                        t.User.IsActive &&
                        (t.ExpiresAt == null || t.ExpiresAt > DateTimeOffset.UtcNow));

                if (apiToken != null)
                {
                    // Update last_used_at without loading entire entity
                    await db.ApiTokens
                        .Where(t => t.Id == apiToken.Id)
                        .ExecuteUpdateAsync(s => s.SetProperty(t => t.LastUsedAt, DateTimeOffset.UtcNow));

                    var claims = new List<Claim>
                    {
                        new(ClaimTypes.NameIdentifier, apiToken.User.Id.ToString()),
                        new(ClaimTypes.Name, apiToken.User.Username),
                        new("is_super_admin", apiToken.User.IsSuperAdmin.ToString().ToLower()),
                        new("auth_type", "api_token")
                    };

                    foreach (var ur in apiToken.User.UserRoles)
                        claims.Add(new Claim("role_ids", ur.RoleId.ToString()));

                    var identity = new ClaimsIdentity(claims, "ApiToken");
                    context.User = new ClaimsPrincipal(identity);
                }
            }
        }

        await _next(context);
    }

    private static string ComputeHash(string input)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(bytes);
    }
}
