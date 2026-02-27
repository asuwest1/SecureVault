using System.Security.Cryptography;
using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using SecureVault.Infrastructure.Services;
using Xunit;

namespace SecureVault.Tests.Unit;

public class EncryptionServiceTests : IDisposable
{
    private readonly string _keyFile;
    private readonly EncryptionService _sut;

    public EncryptionServiceTests()
    {
        // Generate a fresh 32-byte MEK for each test — never hardcode
        _keyFile = Path.GetTempFileName();
        var mek = new byte[32];
        RandomNumberGenerator.Fill(mek);
        File.WriteAllBytes(_keyFile, mek);
        CryptographicOperations.ZeroMemory(mek);

        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Encryption:KeyFilePath"] = _keyFile
            })
            .Build();

        _sut = new EncryptionService(config, NullLogger<EncryptionService>.Instance);
    }

    [Fact]
    public void Encrypt_Decrypt_RoundTrip_Succeeds()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        var plaintext = "super secret password 123!"u8.ToArray();

        var (ciphertextWithTag, nonce) = _sut.Encrypt(plaintext, key);
        var decrypted = _sut.Decrypt(ciphertextWithTag, nonce, key);

        decrypted.Should().Equal(plaintext);
    }

    [Fact]
    public void Decrypt_TamperedTag_ThrowsCryptographicException()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        var plaintext = "test"u8.ToArray();

        var (ciphertextWithTag, nonce) = _sut.Encrypt(plaintext, key);

        // Tamper with the last byte (GCM tag)
        ciphertextWithTag[^1] ^= 0xFF;

        var act = () => _sut.Decrypt(ciphertextWithTag, nonce, key);
        act.Should().Throw<CryptographicException>();
    }

    [Fact]
    public void GenerateDek_ProducesUniqueDeks()
    {
        var dek1 = _sut.GenerateDek();
        var dek2 = _sut.GenerateDek();

        dek1.Should().HaveCount(32);
        dek2.Should().HaveCount(32);
        dek1.Should().NotEqual(dek2, "DEKs must be unique — reuse would be catastrophic");
    }

    [Fact]
    public void Encrypt_ProducesUniqueNonces()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        var plaintext = "test"u8.ToArray();

        var (_, nonce1) = _sut.Encrypt(plaintext, key);
        var (_, nonce2) = _sut.Encrypt(plaintext, key);

        nonce1.Should().NotEqual(nonce2, "Nonces must never be reused");
    }

    [Fact]
    public void WrapDek_UnwrapDek_RoundTrip_Succeeds()
    {
        var dek = _sut.GenerateDek();
        var wrapped = _sut.WrapDek(dek);
        var unwrapped = _sut.UnwrapDek(wrapped);

        unwrapped.Should().Equal(dek);
    }

    [Fact]
    public void WrapDek_DifferentMek_CannotUnwrap()
    {
        var dek = _sut.GenerateDek();
        var wrapped = _sut.WrapDek(dek);

        // Try to unwrap with a different MEK
        var wrongMek = new byte[32];
        RandomNumberGenerator.Fill(wrongMek);

        var act = () => _sut.UnwrapDek(wrapped, wrongMek);
        act.Should().Throw<CryptographicException>();
    }

    [Fact]
    public void HashPassword_ProducesPhcString()
    {
        var hash = _sut.HashPassword("TestPassword123!");

        hash.Should().StartWith("$argon2id$");
        hash.Should().Contain("m=65536");  // 64MB memory cost
        hash.Should().Contain("t=3");      // time cost
    }

    [Fact]
    public void VerifyPassword_CorrectPassword_ReturnsTrue()
    {
        const string password = "TestPassword123!";
        var hash = _sut.HashPassword(password);

        _sut.VerifyPassword(password, hash).Should().BeTrue();
    }

    [Fact]
    public void VerifyPassword_WrongPassword_ReturnsFalse()
    {
        var hash = _sut.HashPassword("CorrectPassword123!");

        _sut.VerifyPassword("WrongPassword456!", hash).Should().BeFalse();
    }

    [Fact]
    public void MissingKeyFile_ThrowsFileNotFoundException()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Encryption:KeyFilePath"] = "/nonexistent/key/file"
            })
            .Build();

        var act = () => new EncryptionService(config, NullLogger<EncryptionService>.Instance);
        act.Should().Throw<FileNotFoundException>();
    }

    [Fact]
    public void WrongSizeKeyFile_ThrowsInvalidOperationException()
    {
        var badKeyFile = Path.GetTempFileName();
        File.WriteAllBytes(badKeyFile, new byte[16]);  // Wrong size (16 bytes, not 32)

        try
        {
            var config = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Encryption:KeyFilePath"] = badKeyFile
                })
                .Build();

            var act = () => new EncryptionService(config, NullLogger<EncryptionService>.Instance);
            act.Should().Throw<InvalidOperationException>().WithMessage("*32 bytes*");
        }
        finally
        {
            File.Delete(badKeyFile);
        }
    }

    [Fact]
    public void EncryptWithMek_DecryptWithMek_RoundTrip()
    {
        var data = "MFA secret"u8.ToArray();

        var encrypted = _sut.EncryptWithMek(data);
        var decrypted = _sut.DecryptWithMek(encrypted);

        decrypted.Should().Equal(data);
    }

    public void Dispose()
    {
        _sut.Dispose();
        File.Delete(_keyFile);
    }
}
