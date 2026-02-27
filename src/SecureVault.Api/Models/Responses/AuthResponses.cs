namespace SecureVault.Api.Models.Responses;

public record LoginResponse(
    string AccessToken,
    DateTimeOffset ExpiresAt,
    bool MfaRequired = false,
    string? MfaToken = null
);

public record UserProfileResponse(
    Guid Id,
    string Username,
    string Email,
    bool IsSuperAdmin,
    bool MfaEnabled,
    IReadOnlyList<Guid> RoleIds
);
