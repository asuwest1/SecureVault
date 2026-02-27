using System.ComponentModel.DataAnnotations;

namespace SecureVault.Api.Models.Requests;

public record CreateUserRequest(
    [Required, StringLength(100)] string Username,
    [Required, EmailAddress] string Email,
    [Required, MinLength(12)] string Password,
    bool IsSuperAdmin = false
);

public record UpdateUserRequest(
    string? Email = null,
    bool? IsActive = null,
    bool? IsSuperAdmin = null
);

public record AssignRoleRequest([Required] Guid RoleId);

public record CreateApiTokenRequest(
    [Required, StringLength(100)] string Name,
    DateTimeOffset? ExpiresAt = null
);
