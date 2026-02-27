using SecureVault.Core.Enums;

namespace SecureVault.Api.Models.Responses;

public record FolderResponse(
    Guid Id,
    string Name,
    Guid? ParentFolderId,
    int Depth,
    DateTimeOffset CreatedAt,
    IReadOnlyList<FolderResponse> Children
);

public record FolderAclResponse(
    Guid FolderId,
    Guid RoleId,
    SecretPermission Permissions
);

public record RoleResponse(
    Guid Id,
    string Name,
    string? Description,
    int MemberCount,
    DateTimeOffset CreatedAt
);

public record AuditLogResponse(
    long Id,
    string Action,
    Guid? ActorUserId,
    string? ActorUsername,
    string? TargetType,
    Guid? TargetId,
    string? IpAddress,
    Dictionary<string, object?>? Detail,
    DateTimeOffset EventTime
);
