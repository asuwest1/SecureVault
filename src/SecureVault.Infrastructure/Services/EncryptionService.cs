using System.Security.Cryptography;
using Isopoh.Cryptography.Argon2;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SecureVault.Core.Interfaces;

namespace SecureVault.Infrastructure.Services;

/// <summary>
/// AES-256-GCM encryption service with two-tier key model (MEK + per-secret DEK).
/// Registered as Singleton — MEK is loaded exactly once at startup.
/// </summary>
public sealed class EncryptionService : IEncryptionService, IDisposable
{
    private const int NonceSize = 12;       // 96-bit nonce for AES-GCM
    private const int TagSize = 16;         // 128-bit GCM authentication tag
    private const int KeySize = 32;         // 256-bit key
    private const int DekSize = 32;

    private readonly byte[] _mek;
    private readonly ILogger<EncryptionService> _logger;
    private bool _disposed;

    public EncryptionService(IConfiguration configuration, ILogger<EncryptionService> logger)
    {
        _logger = logger;
        _mek = LoadMek(configuration);
        _logger.LogInformation("Master Encryption Key loaded successfully ({Bytes} bytes)", _mek.Length);
    }

    private static byte[] LoadMek(IConfiguration configuration)
    {
        var keyFilePath = Environment.GetEnvironmentVariable("SECUREVAULT_KEY_FILE")
            ?? configuration["Encryption:KeyFilePath"]
            ?? throw new InvalidOperationException(
                "MEK key file path not configured. Set SECUREVAULT_KEY_FILE environment variable " +
                "or Encryption:KeyFilePath in appsettings.");

        if (!File.Exists(keyFilePath))
            throw new FileNotFoundException(
                $"MEK key file not found at '{keyFilePath}'. " +
                "Run the first-run wizard to generate the key.", keyFilePath);

        var keyBytes = File.ReadAllBytes(keyFilePath);

        if (keyBytes.Length != KeySize)
            throw new InvalidOperationException(
                $"MEK key file must be exactly {KeySize} bytes (256-bit). " +
                $"Found {keyBytes.Length} bytes at '{keyFilePath}'.");

        return keyBytes;
    }

    public byte[] GenerateDek()
    {
        var dek = new byte[DekSize];
        RandomNumberGenerator.Fill(dek);
        return dek;
    }

    public (byte[] ciphertext, byte[] nonce) Encrypt(byte[] plaintext, byte[] key)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        ArgumentNullException.ThrowIfNull(key);

        if (key.Length != KeySize)
            throw new ArgumentException($"Key must be {KeySize} bytes.", nameof(key));

        var nonce = new byte[NonceSize];
        RandomNumberGenerator.Fill(nonce);

        var ciphertextWithTag = new byte[plaintext.Length + TagSize];
        var ciphertext = ciphertextWithTag.AsSpan(0, plaintext.Length);
        var tag = ciphertextWithTag.AsSpan(plaintext.Length, TagSize);

        using var aes = new AesGcm(key, TagSize);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);

        return (ciphertextWithTag, nonce);
    }

    public byte[] Decrypt(byte[] ciphertextWithTag, byte[] nonce, byte[] key)
    {
        ArgumentNullException.ThrowIfNull(ciphertextWithTag);
        ArgumentNullException.ThrowIfNull(nonce);
        ArgumentNullException.ThrowIfNull(key);

        if (nonce.Length != NonceSize)
            throw new ArgumentException($"Nonce must be {NonceSize} bytes.", nameof(nonce));
        if (key.Length != KeySize)
            throw new ArgumentException($"Key must be {KeySize} bytes.", nameof(key));
        if (ciphertextWithTag.Length < TagSize)
            throw new ArgumentException("Ciphertext too short to contain GCM tag.", nameof(ciphertextWithTag));

        var ciphertextLen = ciphertextWithTag.Length - TagSize;
        var ciphertext = ciphertextWithTag.AsSpan(0, ciphertextLen);
        var tag = ciphertextWithTag.AsSpan(ciphertextLen, TagSize);
        var plaintext = new byte[ciphertextLen];

        using var aes = new AesGcm(key, TagSize);
        aes.Decrypt(nonce, ciphertext, tag, plaintext);  // Throws CryptographicException if tag invalid

        return plaintext;
    }

    public byte[] WrapDek(byte[] dek)
    {
        EnsureNotDisposed();
        return WrapDek(dek, _mek);
    }

    public byte[] WrapDek(byte[] dek, byte[] mek)
    {
        var (ciphertextWithTag, nonce) = Encrypt(dek, mek);
        // Store as nonce ∥ ciphertext+tag for unwrapping
        var result = new byte[NonceSize + ciphertextWithTag.Length];
        nonce.CopyTo(result, 0);
        ciphertextWithTag.CopyTo(result, NonceSize);
        return result;
    }

    public byte[] UnwrapDek(byte[] dekEnc)
    {
        EnsureNotDisposed();
        return UnwrapDek(dekEnc, _mek);
    }

    public byte[] UnwrapDek(byte[] dekEnc, byte[] mek)
    {
        if (dekEnc.Length < NonceSize + TagSize)
            throw new ArgumentException("Wrapped DEK is too short.", nameof(dekEnc));

        var nonce = dekEnc.AsSpan(0, NonceSize).ToArray();
        var ciphertextWithTag = dekEnc.AsSpan(NonceSize).ToArray();
        return Decrypt(ciphertextWithTag, nonce, mek);
    }

    public byte[] EncryptWithMek(byte[] plaintext)
    {
        EnsureNotDisposed();
        var (ciphertextWithTag, nonce) = Encrypt(plaintext, _mek);
        // Format: nonce ∥ ciphertext+tag
        var result = new byte[NonceSize + ciphertextWithTag.Length];
        nonce.CopyTo(result, 0);
        ciphertextWithTag.CopyTo(result, NonceSize);
        return result;
    }

    public byte[] DecryptWithMek(byte[] noncePlusCiphertext)
    {
        EnsureNotDisposed();
        if (noncePlusCiphertext.Length < NonceSize + TagSize)
            throw new ArgumentException("Input too short.", nameof(noncePlusCiphertext));

        var nonce = noncePlusCiphertext.AsSpan(0, NonceSize).ToArray();
        var ciphertextWithTag = noncePlusCiphertext.AsSpan(NonceSize).ToArray();
        return Decrypt(ciphertextWithTag, nonce, _mek);
    }

    public string HashPassword(string password)
    {
        ArgumentException.ThrowIfNullOrEmpty(password);

        var config = new Argon2Config
        {
            Type = Argon2Type.DataIndependentAddressing,  // Argon2id
            Version = Argon2Version.Nineteen,
            TimeCost = 3,
            MemoryCost = 65536,  // 64 MB
            Lanes = 4,
            Threads = 4,
            HashLength = 32,
            Password = System.Text.Encoding.UTF8.GetBytes(password),
            Salt = GenerateRandomSalt(16)
        };

        using var argon2 = new Argon2(config);
        using var hashResult = argon2.Hash();
        return config.EncodeString(hashResult.Buffer);
    }

    public bool VerifyPassword(string password, string hash)
    {
        ArgumentException.ThrowIfNullOrEmpty(password);
        ArgumentException.ThrowIfNullOrEmpty(hash);

        return Argon2.Verify(hash, System.Text.Encoding.UTF8.GetBytes(password));
    }

    private static byte[] GenerateRandomSalt(int length)
    {
        var salt = new byte[length];
        RandomNumberGenerator.Fill(salt);
        return salt;
    }

    private void EnsureNotDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            CryptographicOperations.ZeroMemory(_mek);
            _disposed = true;
        }
    }
}
