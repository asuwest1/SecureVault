namespace SecureVault.Core.Interfaces;

public interface IEncryptionService
{
    /// <summary>Generates a random 32-byte Data Encryption Key.</summary>
    byte[] GenerateDek();

    /// <summary>Encrypts plaintext with the given key using AES-256-GCM.
    /// Returns (ciphertext ∥ 16-byte GCM tag, fresh 12-byte nonce).</summary>
    (byte[] ciphertext, byte[] nonce) Encrypt(byte[] plaintext, byte[] key);

    /// <summary>Decrypts ciphertext (with appended GCM tag) using nonce and key.</summary>
    byte[] Decrypt(byte[] ciphertextWithTag, byte[] nonce, byte[] key);

    /// <summary>Wraps (encrypts) a DEK with the Master Encryption Key.</summary>
    byte[] WrapDek(byte[] dek);

    /// <summary>Unwraps (decrypts) a DEK with the Master Encryption Key.
    /// Caller MUST zero the returned DEK via CryptographicOperations.ZeroMemory() in a finally block.</summary>
    byte[] UnwrapDek(byte[] dekEnc);

    /// <summary>Overload supporting explicit MEK — for key rotation procedures.</summary>
    byte[] WrapDek(byte[] dek, byte[] mek);

    /// <summary>Overload supporting explicit MEK — for key rotation procedures.</summary>
    byte[] UnwrapDek(byte[] dekEnc, byte[] mek);

    /// <summary>Hashes a password using Argon2id with PHC string output.</summary>
    string HashPassword(string password);

    /// <summary>Verifies a password against an Argon2id PHC string hash.</summary>
    bool VerifyPassword(string password, string hash);

    /// <summary>Encrypts data with the MEK (used for MFA secret storage).
    /// Returns nonce ∥ ciphertext.</summary>
    byte[] EncryptWithMek(byte[] plaintext);

    /// <summary>Decrypts data encrypted with EncryptWithMek.
    /// Input format: nonce ∥ ciphertext.</summary>
    byte[] DecryptWithMek(byte[] noncePlusCiphertext);
}
