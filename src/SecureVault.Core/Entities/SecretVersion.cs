namespace SecureVault.Core.Entities;

public class SecretVersion
{
    public Guid Id { get; set; }
    public Guid SecretId { get; set; }
    public int VersionNumber { get; set; }
    public string? Notes { get; set; }

    // Encrypted snapshot — all byte[], never string
    public byte[] ValueEnc { get; set; } = Array.Empty<byte>();
    public byte[] DekEnc { get; set; } = Array.Empty<byte>();
    public byte[] Nonce { get; set; } = Array.Empty<byte>();

    public Guid CreatedByUserId { get; set; }
    public DateTimeOffset CreatedAt { get; set; }

    public Secret Secret { get; set; } = null!;
}
