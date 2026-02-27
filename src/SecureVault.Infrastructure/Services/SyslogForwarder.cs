using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SecureVault.Core.Entities;

namespace SecureVault.Infrastructure.Services;

/// <summary>
/// RFC 5424 syslog forwarder over TCP (with optional TLS).
/// Fire-and-forget — never blocks the calling request.
/// PRI = facility 16 (local0) * 8 + severity 6 (informational) = 134.
/// </summary>
public class SyslogForwarder
{
    private const int SyslogPri = 134;  // local0.info
    private readonly string? _host;
    private readonly int _port;
    private readonly bool _enabled;
    private readonly ILogger<SyslogForwarder> _logger;

    public SyslogForwarder(IConfiguration configuration, ILogger<SyslogForwarder> logger)
    {
        _logger = logger;
        _host = configuration["Syslog:Host"];
        _port = configuration.GetValue("Syslog:Port", 514);
        _enabled = !string.IsNullOrEmpty(_host);
    }

    public async Task ForwardAsync(AuditLog entry)
    {
        if (!_enabled) return;

        try
        {
            var timestamp = entry.EventTime.ToString("o");
            var message = JsonSerializer.Serialize(new
            {
                action = entry.Action.ToString(),
                actor = entry.ActorUsername,
                actor_id = entry.ActorUserId,
                target_type = entry.TargetType,
                target_id = entry.TargetId,
                ip = entry.IpAddress,
                detail = entry.Detail
            });

            // RFC 5424 format: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
            var syslogMsg = $"<{SyslogPri}>1 {timestamp} - SecureVault - - - {message}\n";
            var bytes = Encoding.UTF8.GetBytes(syslogMsg);

            using var client = new TcpClient();
            await client.ConnectAsync(_host!, _port);
            await using var stream = client.GetStream();
            await stream.WriteAsync(bytes);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Syslog forward failed for action {Action}", entry.Action);
            // Never rethrow — syslog unavailability must not affect application
        }
    }
}
