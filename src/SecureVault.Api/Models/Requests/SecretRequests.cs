using System.ComponentModel.DataAnnotations;
using SecureVault.Core.Enums;

namespace SecureVault.Api.Models.Requests;

public record CreateSecretRequest(
    [Required, StringLength(255)] string Name,
    [Required] string Value,
    SecretType Type,
    Guid FolderId,
    string? Username = null,
    string? Url = null,
    string? Notes = null,
    string[]? Tags = null
);

public record UpdateSecretRequest(
    [StringLength(255)] string? Name = null,
    string? Value = null,
    SecretType? Type = null,
    Guid? FolderId = null,
    string? Username = null,
    string? Url = null,
    string? Notes = null,
    string[]? Tags = null
);

public record SearchSecretsRequest(
    string? Query = null,
    SecretType? Type = null,
    string[]? Tags = null,
    Guid? FolderId = null,
    [Range(1, int.MaxValue)] int Page = 1,
    [Range(1, 200)] int PageSize = 50
);
