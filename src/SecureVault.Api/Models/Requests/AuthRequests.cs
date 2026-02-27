using System.ComponentModel.DataAnnotations;

namespace SecureVault.Api.Models.Requests;

public record LoginRequest(
    [Required, StringLength(100)] string Username,
    [Required, StringLength(256)] string Password
);

public record MfaVerifyRequest(
    [Required] string MfaToken,
    [Required, StringLength(6, MinimumLength = 6)] string Code
);

public record ChangePasswordRequest(
    [Required] string CurrentPassword,
    [Required, MinLength(12)] string NewPassword
);
