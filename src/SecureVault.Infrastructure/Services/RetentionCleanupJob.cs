using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace SecureVault.Infrastructure.Services;

/// <summary>
/// Background service running at midnight UTC.
/// Handles:
/// - Soft-deleted secret purge (past purge_after)
/// - Secret version trim (cap at 20 per secret)
///
/// Note: Audit log retention (1 year) is handled by pg_cron or superuser cron script,
/// as the application DB user has DELETE revoked on audit_log.
/// </summary>
public class RetentionCleanupJob : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<RetentionCleanupJob> _logger;

    public RetentionCleanupJob(IServiceScopeFactory scopeFactory, ILogger<RetentionCleanupJob> logger)
    {
        _scopeFactory = scopeFactory;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            await WaitUntilMidnightUtcAsync(stoppingToken);

            if (stoppingToken.IsCancellationRequested) break;

            try
            {
                await RunCleanupAsync(stoppingToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Retention cleanup job failed");
            }
        }
    }

    private async Task RunCleanupAsync(CancellationToken cancellationToken)
    {
        using var scope = _scopeFactory.CreateScope();
        var dbFactory = scope.ServiceProvider.GetRequiredService<IDbContextFactory<Data.AppDbContext>>();

        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);

        // Purge soft-deleted secrets past their purge_after date
        var purgedCount = await db.Secrets
            .IgnoreQueryFilters()
            .Where(s => s.DeletedAt != null && s.PurgeAfter != null && s.PurgeAfter <= DateTimeOffset.UtcNow)
            .ExecuteDeleteAsync(cancellationToken);

        _logger.LogInformation("Purged {Count} soft-deleted secrets past purge date", purgedCount);

        // Trim version history: keep only latest 20 versions per secret
        // Get secrets with > 20 versions
        var secretsWithExcessVersions = await db.SecretVersions
            .AsNoTracking()
            .GroupBy(v => v.SecretId)
            .Where(g => g.Count() > 20)
            .Select(g => g.Key)
            .ToListAsync(cancellationToken);

        var trimmedTotal = 0;
        foreach (var secretId in secretsWithExcessVersions)
        {
            var oldVersionIds = await db.SecretVersions
                .Where(v => v.SecretId == secretId)
                .OrderByDescending(v => v.VersionNumber)
                .Skip(20)
                .Select(v => v.Id)
                .ToListAsync(cancellationToken);

            if (oldVersionIds.Count > 0)
            {
                var deleted = await db.SecretVersions
                    .Where(v => oldVersionIds.Contains(v.Id))
                    .ExecuteDeleteAsync(cancellationToken);
                trimmedTotal += deleted;
            }
        }

        _logger.LogInformation("Trimmed {Count} excess secret versions", trimmedTotal);
    }

    private static async Task WaitUntilMidnightUtcAsync(CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        var nextMidnight = new DateTimeOffset(now.UtcDateTime.Date.AddDays(1), TimeSpan.Zero);
        var delay = nextMidnight - now;

        if (delay.TotalMilliseconds > 0)
            await Task.Delay(delay, cancellationToken);
    }
}
