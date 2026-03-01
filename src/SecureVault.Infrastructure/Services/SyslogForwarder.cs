using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SecureVault.Core.Entities;

namespace SecureVault.Infrastructure.Services;

/// <summary>
/// RFC 5424 syslog forwarder over TCP with persistent connection and buffered channel.
/// Fire-and-forget — never blocks the calling request.
/// PRI = facility 16 (local0) * 8 + severity 6 (informational) = 134.
/// TLS is enabled by default (Syslog:UseTls). Set to false only for syslog servers
/// that do not support TLS and are reachable exclusively over a private network segment.
/// </summary>
public class SyslogForwarder : IDisposable
{
    private const int SyslogPri = 134;  // local0.info
    private readonly string? _host;
    private readonly int _port;
    private readonly bool _enabled;
    private readonly bool _useTls;
    private readonly ILogger<SyslogForwarder> _logger;
    private readonly Channel<AuditLog> _channel;
    private readonly CancellationTokenSource _cts = new();
    private readonly SemaphoreSlim _connectionLock = new(1, 1);
    private TcpClient? _client;
    private Stream? _stream;
    private Task? _senderTask;

    public SyslogForwarder(IConfiguration configuration, ILogger<SyslogForwarder> logger)
    {
        _logger = logger;
        _host = configuration["Syslog:Host"];
        _port = configuration.GetValue("Syslog:Port", 514);
        _useTls = configuration.GetValue("Syslog:UseTls", true);
        _enabled = !string.IsNullOrEmpty(_host);

        if (_enabled && !_useTls)
        {
            _logger.LogWarning(
                "Syslog:UseTls is false — audit events will be forwarded in plaintext. " +
                "Enable TLS or ensure the syslog server is on a fully trusted private segment.");
        }

        // Bounded channel prevents unbounded memory growth if syslog is down
        _channel = Channel.CreateBounded<AuditLog>(new BoundedChannelOptions(10_000)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = true
        });

        if (_enabled)
        {
            _senderTask = Task.Run(() => ProcessQueueAsync(_cts.Token));
        }
    }

    public void Forward(AuditLog entry)
    {
        if (!_enabled) return;

        // Non-blocking write to channel — DropOldest makes room automatically
        _channel.Writer.TryWrite(entry);
    }

    private async Task ProcessQueueAsync(CancellationToken ct)
    {
        await foreach (var entry in _channel.Reader.ReadAllAsync(ct))
        {
            try
            {
                var bytes = FormatSyslogMessage(entry);
                await SendWithReconnectAsync(bytes, ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogWarning(ex, "Syslog forward failed for action {Action}", entry.Action);
                // Never rethrow — syslog unavailability must not affect application
            }
        }
    }

    private byte[] FormatSyslogMessage(AuditLog entry)
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
        return Encoding.UTF8.GetBytes(syslogMsg);
    }

    private async Task SendWithReconnectAsync(byte[] bytes, CancellationToken ct)
    {
        await _connectionLock.WaitAsync(ct);
        try
        {
            if (_client == null || !_client.Connected)
            {
                await ReconnectAsync(ct);
            }

            try
            {
                await _stream!.WriteAsync(bytes, ct);
            }
            catch (IOException)
            {
                // Connection was lost — reconnect and retry once
                await ReconnectAsync(ct);
                await _stream!.WriteAsync(bytes, ct);
            }
        }
        finally
        {
            _connectionLock.Release();
        }
    }

    private async Task ReconnectAsync(CancellationToken ct)
    {
        _stream?.Dispose();
        _client?.Dispose();

        _client = new TcpClient();
        await _client.ConnectAsync(_host!, _port, ct);

        if (_useTls)
        {
            var sslStream = new SslStream(_client.GetStream(), leaveInnerStreamOpen: false);
            await sslStream.AuthenticateAsClientAsync(
                new SslClientAuthenticationOptions
                {
                    TargetHost = _host!,
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
                },
                ct);
            _stream = sslStream;
            _logger.LogInformation("Syslog TLS connection established to {Host}:{Port}", _host, _port);
        }
        else
        {
            _stream = _client.GetStream();
            _logger.LogInformation("Syslog TCP connection established to {Host}:{Port}", _host, _port);
        }
    }

    public void Dispose()
    {
        _cts.Cancel();
        _channel.Writer.TryComplete();
        _stream?.Dispose();
        _client?.Dispose();
        _cts.Dispose();
        _connectionLock.Dispose();
    }
}
