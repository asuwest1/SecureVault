using System.Security.Cryptography;
using OtpNet;
using SecureVault.Core.Interfaces;

namespace SecureVault.Infrastructure.Services;

public class MfaService
{
    private const string Issuer = "SecureVault";
    private readonly IEncryptionService _encryption;

    public MfaService(IEncryptionService encryption)
    {
        _encryption = encryption;
    }

    /// <summary>Generates a new TOTP secret, encrypts it, and returns the setup URI.</summary>
    public (byte[] encryptedSecret, string otpAuthUri) GenerateSetup(string username)
    {
        var secret = KeyGeneration.GenerateRandomKey(20);  // 160-bit TOTP key
        var encryptedSecret = _encryption.EncryptWithMek(secret);

        var base32Secret = Base32Encoding.ToString(secret);
        var uri = $"otpauth://totp/{Uri.EscapeDataString(Issuer)}:{Uri.EscapeDataString(username)}" +
                  $"?secret={base32Secret}&issuer={Uri.EscapeDataString(Issuer)}&algorithm=SHA1&digits=6&period=30";

        // Zero the plaintext secret
        ClearSensitiveBuffer(secret);

        return (encryptedSecret, uri);
    }

    /// <summary>Verifies a TOTP code against the encrypted secret.</summary>
    public bool Verify(byte[] encryptedSecret, string code)
    {
        if (string.IsNullOrWhiteSpace(code) || code.Length != 6) return false;

        byte[]? secret = null;
        try
        {
            secret = _encryption.DecryptWithMek(encryptedSecret);
            var totp = new Totp(secret, step: 30, totpSize: 6);

            // Allow ±1 step (30-second window) for clock skew
            return totp.VerifyTotp(code, out _, new VerificationWindow(previous: 1, future: 1));
        }
        finally
        {
            if (secret != null)
                ClearSensitiveBuffer(secret);
        }
    }

    private static void ClearSensitiveBuffer(byte[] buffer)
    {
#if NET8_0_OR_GREATER
        CryptographicOperations.ZeroMemory(buffer);
#else
        Array.Clear(buffer, 0, buffer.Length);
#endif
    }
}
