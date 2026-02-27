using System.ComponentModel.DataAnnotations;
using SecureVault.Core.Enums;

namespace SecureVault.Api.Models.Requests;

public record CreateRoleRequest(
    [Required, StringLength(100)] string Name,
    string? Description = null
);

public record UpdateRoleRequest(
    string? Name = null,
    string? Description = null
);

public record SetSecretAclRequest(
    [Required] Guid SecretId,
    SecretPermission Permissions
);
