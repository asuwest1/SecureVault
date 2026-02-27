using SecureVault.Core.Enums;

namespace SecureVault.Api.Models.Responses;

// IMPORTANT: Never include ValueEnc, DekEnc, Nonce, or PasswordHash in any response DTO

public record SecretSummaryResponse(
    Guid Id,
    string Name,
    SecretType Type,
    Guid FolderId,
    string? Username,
    string? Url,
    string[] Tags,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt
);

public record SecretDetailResponse(
    Guid Id,
    string Name,
    SecretType Type,
    Guid FolderId,
    string? Username,
    string? Url,
    string? Notes,
    string[] Tags,
    Guid CreatedByUserId,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt
);

public record SecretValueResponse(string Value);  // Only returned by GET /secrets/{id}/value

public record SecretVersionResponse(
    Guid Id,
    int VersionNumber,
    string? Notes,
    Guid CreatedByUserId,
    DateTimeOffset CreatedAt
);

public record PagedResponse<T>(
    IReadOnlyList<T> Items,
    int Page,
    int PageSize,
    int TotalCount
);
