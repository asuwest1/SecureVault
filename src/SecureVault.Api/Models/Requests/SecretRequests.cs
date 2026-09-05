using System.ComponentModel.DataAnnotations;
using SecureVault.Core.Enums;

namespace SecureVault.Api.Models.Requests;

public record CreateSecretRequest(
    [Required, StringLength(255)] string Name,
    [Required] string Value,
    [EnumDataType(typeof(SecretType))] SecretType Type,
    Guid FolderId,
    [StringLength(255)] string? Username = null,
    [StringLength(2048)] string? Url = null,
    [StringLength(4096)] string? Notes = null,
    string[]? Tags = null
);

public record UpdateSecretRequest(
    [StringLength(255)] string? Name = null,
    string? Value = null,
    [EnumDataType(typeof(SecretType))] SecretType? Type = null,
    Guid? FolderId = null,
    [StringLength(255)] string? Username = null,
    [StringLength(2048)] string? Url = null,
    [StringLength(4096)] string? Notes = null,
    string[]? Tags = null
);

public record SearchSecretsRequest(
    string? Query = null,
    [EnumDataType(typeof(SecretType))] SecretType? Type = null,
    string[]? Tags = null,
    Guid? FolderId = null,
    [Range(1, int.MaxValue)] int Page = 1,
    [Range(1, 200)] int PageSize = 50
);
