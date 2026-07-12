using FluentAssertions;
using OtpNet;
using SecureVault.Core.Interfaces;
using SecureVault.Infrastructure.Services;
using Xunit;

namespace SecureVault.Tests.Unit;

public class MfaServiceTests
{
    private readonly PassthroughEncryptionService _encryption = new();

    [Fact]
    public void GenerateSetup_ReturnsEncryptedSecretAndEscapedOtpAuthUri()
    {
        var sut = new MfaService(_encryption);

        var (encryptedSecret, otpAuthUri) = sut.GenerateSetup("alice+admin@example.com");

        encryptedSecret.Should().HaveCount(20);
        encryptedSecret.Should().NotBeSameAs(_encryption.LastPlaintextBuffer);
        otpAuthUri.Should().StartWith("otpauth://totp/SecureVault:alice%2Badmin%40example.com?");
        otpAuthUri.Should().Contain($"secret={Base32Encoding.ToString(encryptedSecret)}");
        otpAuthUri.Should().EndWith("issuer=SecureVault&algorithm=SHA1&digits=6&period=30");
        _encryption.LastPlaintextBuffer.Should().OnlyContain(value => value == 0,
            "the plaintext TOTP secret should be cleared after encryption");
    }

    [Fact]
    public void Verify_CurrentTotp_ReturnsTrueAndClearsDecryptedSecret()
    {
        var secret = KeyGeneration.GenerateRandomKey(20);
        var code = new Totp(secret, step: 30, totpSize: 6).ComputeTotp();
        var sut = new MfaService(_encryption);

        var result = sut.Verify(secret, code);

        result.Should().BeTrue();
        _encryption.LastDecryptedBuffer.Should().OnlyContain(value => value == 0,
            "the decrypted TOTP secret should be cleared after verification");
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("12345")]
    [InlineData("1234567")]
    public void Verify_InvalidCodeShape_ReturnsFalseWithoutDecrypting(string code)
    {
        var sut = new MfaService(_encryption);

        sut.Verify([1, 2, 3], code).Should().BeFalse();

        _encryption.DecryptCallCount.Should().Be(0);
    }

    [Fact]
    public void Verify_IncorrectSixDigitCode_ReturnsFalse()
    {
        var secret = KeyGeneration.GenerateRandomKey(20);
        var validCode = new Totp(secret, step: 30, totpSize: 6).ComputeTotp();
        var incorrectCode = validCode == "000000" ? "000001" : "000000";
        var sut = new MfaService(_encryption);

        sut.Verify(secret, incorrectCode).Should().BeFalse();
    }

    private sealed class PassthroughEncryptionService : IEncryptionService
    {
        public byte[] LastPlaintextBuffer { get; private set; } = [];
        public byte[] LastDecryptedBuffer { get; private set; } = [];
        public int DecryptCallCount { get; private set; }

        public byte[] EncryptWithMek(byte[] plaintext)
        {
            LastPlaintextBuffer = plaintext;
            return plaintext.ToArray();
        }

        public byte[] DecryptWithMek(byte[] ciphertext)
        {
            DecryptCallCount++;
            LastDecryptedBuffer = ciphertext.ToArray();
            return LastDecryptedBuffer;
        }

        public byte[] GenerateDek() => throw new NotSupportedException();
        public (byte[] ciphertext, byte[] nonce) Encrypt(byte[] plaintext, byte[] key) => throw new NotSupportedException();
        public byte[] Decrypt(byte[] ciphertextWithTag, byte[] nonce, byte[] key) => throw new NotSupportedException();
        public byte[] WrapDek(byte[] dek) => throw new NotSupportedException();
        public byte[] WrapDek(byte[] dek, byte[] mek) => throw new NotSupportedException();
        public byte[] UnwrapDek(byte[] wrappedDek) => throw new NotSupportedException();
        public byte[] UnwrapDek(byte[] wrappedDek, byte[] mek) => throw new NotSupportedException();
        public string HashPassword(string password) => throw new NotSupportedException();
        public bool VerifyPassword(string password, string hash) => throw new NotSupportedException();
    }
}
