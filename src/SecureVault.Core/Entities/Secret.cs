using SecureVault.Core.Enums;

namespace SecureVault.Core.Entities;

public class Secret
{
    public Guid Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string? Username { get; set; }
    public string? Url { get; set; }
    public string? Notes { get; set; }
    public SecretType Type { get; set; }
    public string[] Tags { get; set; } = Array.Empty<string>();

    // Encrypted fields — always byte[], never string
    public byte[] ValueEnc { get; set; } = Array.Empty<byte>();
    public byte[] DekEnc { get; set; } = Array.Empty<byte>();
    public byte[] Nonce { get; set; } = Array.Empty<byte>();

    public Guid FolderId { get; set; }
    public Guid CreatedByUserId { get; set; }
    public Guid? UpdatedByUserId { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
    public DateTimeOffset? DeletedAt { get; set; }
    public DateTimeOffset? PurgeAfter { get; set; }

    public Folder Folder { get; set; } = null!;
    public User CreatedBy { get; set; } = null!;
    public ICollection<SecretVersion> Versions { get; set; } = new List<SecretVersion>();
    public ICollection<SecretAcl> SecretAcls { get; set; } = new List<SecretAcl>();
}
