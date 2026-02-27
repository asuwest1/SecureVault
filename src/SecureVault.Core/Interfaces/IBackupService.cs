namespace SecureVault.Core.Interfaces;

public interface IBackupService
{
    /// <summary>Creates an encrypted backup and returns the backup file path.</summary>
    Task<string> CreateBackupAsync(CancellationToken cancellationToken = default);

    /// <summary>Restores from an encrypted backup file.</summary>
    Task RestoreBackupAsync(string backupFilePath, string passphrase, CancellationToken cancellationToken = default);
}
