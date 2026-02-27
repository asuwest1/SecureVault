using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Novell.Directory.Ldap;
using SecureVault.Core.Interfaces;

namespace SecureVault.Infrastructure.Services;

public class LdapService : ILdapService
{
    private readonly string _host;
    private readonly int _port;
    private readonly string _baseDn;
    private readonly string _userDnTemplate;
    private readonly string _emailAttribute;
    private readonly string _displayNameAttribute;
    private readonly ILogger<LdapService> _logger;

    public LdapService(IConfiguration configuration, ILogger<LdapService> logger)
    {
        _host = configuration["Auth:Ldap:Host"] ?? throw new InvalidOperationException("Auth:Ldap:Host required.");
        _port = configuration.GetValue("Auth:Ldap:Port", 636);
        _baseDn = configuration["Auth:Ldap:BaseDn"] ?? throw new InvalidOperationException("Auth:Ldap:BaseDn required.");
        _userDnTemplate = configuration["Auth:Ldap:UserDnTemplate"] ?? $"uid={{0}},{_baseDn}";
        _emailAttribute = configuration["Auth:Ldap:EmailAttribute"] ?? "mail";
        _displayNameAttribute = configuration["Auth:Ldap:DisplayNameAttribute"] ?? "displayName";
        _logger = logger;
    }

    public async Task<LdapUserInfo?> AuthenticateAsync(
        string username, string password, CancellationToken cancellationToken = default)
    {
        // Sanitize username per RFC 4515 to prevent LDAP injection
        var safeUsername = SanitizeLdapInput(username);

        try
        {
            using var conn = new LdapConnection { SecureSocketLayer = (_port == 636) };
            var found = await Task.Run<LdapUserInfo?>(() =>
            {
                conn.Connect(_host, _port);

                var userDn = string.Format(_userDnTemplate, safeUsername);
                conn.Bind(userDn, password);

                // Search for user attributes after successful bind
                var constraints = new LdapSearchConstraints { MaxResults = 1 };
                var filter = $"(uid={safeUsername})";
                var results = conn.Search(_baseDn, LdapConnection.ScopeSub, filter,
                    [_emailAttribute, _displayNameAttribute], false, constraints);

                if (results.HasMore())
                {
                    var entry = results.Next();
                    var email = entry.GetAttributeSet().GetAttribute(_emailAttribute)?.StringValue ?? $"{username}@ldap";
                    var displayName = entry.GetAttributeSet().GetAttribute(_displayNameAttribute)?.StringValue ?? username;
                    return new LdapUserInfo(username, email, displayName);
                }

                return null;
            }, cancellationToken);

            // If bind succeeded but search found nothing, return basic info
            return found ?? new LdapUserInfo(username, $"{username}@ldap", username);
        }
        catch (LdapException ex) when (ex.ResultCode == LdapException.InvalidCredentials)
        {
            _logger.LogDebug("LDAP authentication failed for user '{Username}': invalid credentials", safeUsername);
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "LDAP authentication error for user '{Username}'", safeUsername);
            throw;
        }
    }

    /// <summary>Sanitizes LDAP input per RFC 4515 to prevent injection attacks.</summary>
    private static string SanitizeLdapInput(string input)
    {
        // Escape special LDAP filter characters: ( ) * \ NUL
        return input
            .Replace("\0", string.Empty)   // Remove NUL
            .Replace("\\", "\\5c")
            .Replace("*", "\\2a")
            .Replace("(", "\\28")
            .Replace(")", "\\29");
    }
}
