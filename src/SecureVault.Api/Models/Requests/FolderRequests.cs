using System.ComponentModel.DataAnnotations;
using SecureVault.Core.Enums;

namespace SecureVault.Api.Models.Requests;

public record CreateFolderRequest(
    [Required, StringLength(255)] string Name,
    Guid? ParentFolderId = null
);

public record UpdateFolderRequest([StringLength(255)] string? Name = null);

public record SetFolderAclRequest(
    [Required] Guid RoleId,
    SecretPermission Permissions
);
