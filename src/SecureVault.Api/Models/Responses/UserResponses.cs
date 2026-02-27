namespace SecureVault.Api.Models.Responses;

// PasswordHash is never included in any user response DTO
public record UserResponse(
    Guid Id,
    string Username,
    string Email,
    bool IsActive,
    bool IsSuperAdmin,
    bool IsLdapUser,
    bool MfaEnabled,
    DateTimeOffset CreatedAt,
    IReadOnlyList<Guid> RoleIds
);

public record ApiTokenResponse(
    Guid Id,
    string Name,
    DateTimeOffset? ExpiresAt,
    DateTimeOffset CreatedAt,
    DateTimeOffset? LastUsedAt
);

public record ApiTokenCreatedResponse(
    Guid Id,
    string Name,
    string Token,  // Returned only once at creation; never stored in plaintext
    DateTimeOffset? ExpiresAt
);
