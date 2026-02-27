namespace SecureVault.Core.Interfaces;

public interface ILdapService
{
    /// <summary>
    /// Authenticates a user against the LDAP/AD directory.
    /// Returns the user's email and display name on success, or null on failure.
    /// </summary>
    Task<LdapUserInfo?> AuthenticateAsync(
        string username,
        string password,
        CancellationToken cancellationToken = default);
}

public record LdapUserInfo(string Username, string Email, string DisplayName);
