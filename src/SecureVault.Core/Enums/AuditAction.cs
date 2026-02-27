namespace SecureVault.Core.Enums;

public enum AuditAction
{
    // Authentication
    AuthLogin = 100,
    AuthLogout = 101,
    AuthLoginFailed = 102,
    AuthLockout = 103,
    AuthMfaEnabled = 104,
    AuthMfaDisabled = 105,
    AuthMfaVerified = 106,
    AuthTokenRefresh = 107,

    // Secrets
    SecretCreated = 200,
    SecretViewed = 201,
    SecretUpdated = 202,
    SecretDeleted = 203,
    SecretRestored = 204,
    SecretPurged = 205,
    SecretImported = 206,
    SecretVersionViewed = 207,

    // Folders
    FolderCreated = 300,
    FolderUpdated = 301,
    FolderDeleted = 302,

    // Users
    UserCreated = 400,
    UserUpdated = 401,
    UserDeleted = 402,
    UserPasswordChanged = 403,
    UserApiTokenCreated = 404,
    UserApiTokenRevoked = 405,

    // Roles & ACL
    RoleCreated = 500,
    RoleUpdated = 501,
    RoleDeleted = 502,
    RoleMemberAdded = 503,
    RoleMemberRemoved = 504,
    AclUpdated = 505,

    // System
    SystemInitialized = 900,
    SystemKeyLoaded = 901,
    SystemBackupCreated = 902,
    SystemBackupRestored = 903
}
