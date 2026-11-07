using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using LegacyShot.Server.Protocol;
using LegacyShot.Server.Security;
using LegacyShot.Server.Uploads;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace LegacyShot.Server.Net;

// TCP accept loop with global and per-IP connection limits, plus periodic housekeeping.
public sealed class LsupServer : BackgroundService
{
    private readonly ServerOptions _o;
    private readonly UploadManager _uploads;
    private readonly LoginThrottle _throttle;
    private readonly ILoggerFactory _loggers;
    private readonly ILogger<LsupServer> _log;

    private readonly ConcurrentDictionary<string, int> _perIp = new();
    private readonly ConcurrentDictionary<Task, byte> _running = new();
    private int _total;

    public LsupServer(IOptions<ServerOptions> options, UploadManager uploads, LoginThrottle throttle, ILoggerFactory loggers)
    {
        _o = options.Value;
        _uploads = uploads;
        _throttle = throttle;
        _loggers = loggers;
        _log = loggers.CreateLogger<LsupServer>();
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (_o.Users.Count == 0)
            _log.LogWarning("No users configured under Lsup:Users; every login will fail.");
        foreach (var (user, key) in _o.Users)
        {
            if (key.Length < 16)
                _log.LogWarning("API key for {User} is shorter than 16 characters; use 32 random hex characters.", user);
        }

        _uploads.Load();

        var listener = new TcpListener(IPAddress.Parse(_o.ListenAddress), _o.Port);
        listener.Start();
        _log.LogInformation("LSUP/2 listening on {Address}:{Port}.", _o.ListenAddress, _o.Port);

        var housekeeping = HousekeepingAsync(stoppingToken);
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                TcpClient client = await listener.AcceptTcpClientAsync(stoppingToken).ConfigureAwait(false);
                var task = HandleAsync(client, stoppingToken);
                _running.TryAdd(task, 0);
                _ = task.ContinueWith(t => _running.TryRemove(t, out _), TaskScheduler.Default);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
        finally
        {
            listener.Stop();
            await Task.WhenAll(_running.Keys).ConfigureAwait(false);
            try { await housekeeping.ConfigureAwait(false); } catch (OperationCanceledException) { }
            _log.LogInformation("LSUP/2 server stopped.");
        }
    }

    private async Task HandleAsync(TcpClient client, CancellationToken stoppingToken)
    {
        string ip = (client.Client.RemoteEndPoint as IPEndPoint)?.Address.ToString() ?? "unknown";
        int perIp = _perIp.AddOrUpdate(ip, 1, (_, n) => n + 1);
        int total = Interlocked.Increment(ref _total);
        try
        {
            client.NoDelay = true;
            client.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);

            if (total > _o.MaxConnections || perIp > _o.MaxConnectionsPerIp)
            {
                _log.LogWarning("Refusing {Ip}: {PerIp} connection(s) from this address, {Total} in total.", ip, perIp, total);
                await RefuseBusyAsync(client).ConfigureAwait(false);
                return;
            }

            var connection = new ClientConnection(client, ip, _o, _uploads, _throttle, _loggers.CreateLogger<ClientConnection>());
            await connection.RunAsync(stoppingToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Connection handler for {Ip} failed.", ip);
        }
        finally
        {
            Interlocked.Decrement(ref _total);
            _perIp.AddOrUpdate(ip, 0, (_, n) => n - 1);
            _perIp.TryRemove(new KeyValuePair<string, int>(ip, 0));
            client.Dispose();
        }
    }

    private static async Task RefuseBusyAsync(TcpClient client)
    {
        try
        {
            byte[] frame = FrameCodec.Encode(MessageType.Error,
                Messages.Error(ErrorCode.ServerBusy, 0, "Too many connections; retry in 30-60 s."));
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await client.GetStream().WriteAsync(frame, cts.Token).ConfigureAwait(false);
            client.Client.Shutdown(SocketShutdown.Both);
        }
        catch
        {
            // best effort
        }
    }

    private async Task HousekeepingAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(10));
        while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false))
        {
            try
            {
                _uploads.ExpireStale();
                _throttle.Prune();
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "Housekeeping failed.");
            }
        }
    }
}
