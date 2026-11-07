using System.Net.Sockets;
using LegacyShot.Server.Protocol;
using LegacyShot.Server.Security;
using LegacyShot.Server.Uploads;
using Microsoft.Extensions.Logging;

namespace LegacyShot.Server.Net;

// 
// One TCP client. States: AwaitHello → AwaitLogin → Ready.
// Frames are processed strictly one at a time, so chunk order on the wire is the order written to disk.
// 
public sealed class ClientConnection
{
    private enum State { AwaitHello, AwaitLogin, Ready }

    private static long _lastConnectionId;

    private readonly TcpClient _client;
    private readonly NetworkStream _stream;
    private readonly ServerOptions _o;
    private readonly UploadManager _uploads;
    private readonly LoginThrottle _throttle;
    private readonly ILogger _log;
    private readonly string _remoteIp;
    private readonly SemaphoreSlim _sendLock = new(1, 1);
    private readonly long _id = Interlocked.Increment(ref _lastConnectionId);

    private State _state = State.AwaitHello;
    private long _lastSendTicks = Environment.TickCount64;
    private DateTime _loginDeadlineUtc;
    private CancellationToken _ct;

    private byte[] _serverNonce = [];
    private byte[] _sessionToken = [];
    private byte[] _sessionKey = [];
    private string _username = "";

    private ActiveUpload? _active;

    public ClientConnection(TcpClient client, string remoteIp, ServerOptions options, UploadManager uploads,
        LoginThrottle throttle, ILogger log)
    {
        _client = client;
        _stream = client.GetStream();
        _remoteIp = remoteIp;
        _o = options;
        _uploads = uploads;
        _throttle = throttle;
        _log = log;
    }

    public async Task RunAsync(CancellationToken serverStopping)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(serverStopping);
        _ct = cts.Token;
        _loginDeadlineUtc = DateTime.UtcNow.AddSeconds(_o.LoginTimeoutSeconds);
        var pinger = PingLoopAsync(_ct);

        _log.LogInformation("[{Id}] Connected from {Ip}.", _id, _remoteIp);
        try
        {
            while (true)
            {
                Frame? frame = await ReadWithTimeoutAsync().ConfigureAwait(false);
                if (frame is null)
                    break; // clean disconnect

                bool keepOpen;
                try
                {
                    keepOpen = await DispatchAsync(frame.Value).ConfigureAwait(false);
                }
                catch (ProtocolException ex) when (!ex.CloseConnection)
                {
                    _log.LogInformation("[{Id}] {Code}: {Message}", _id, ex.Code, ex.Message);
                    await SendErrorAsync(ex).ConfigureAwait(false);
                    continue;
                }

                if (!keepOpen)
                    break;
            }
        }
        catch (ProtocolException ex)
        {
            _log.LogWarning("[{Id}] Closing: {Code}: {Message}", _id, ex.Code, ex.Message);
            try { await SendErrorAsync(ex).ConfigureAwait(false); } catch { /* peer may be gone */ }
        }
        catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException)
        {
            // IOException also covers EndOfStreamException (peer hung up mid-frame).
            _log.LogInformation("[{Id}] Connection lost: {Message}", _id, ex.Message);
        }
        catch (OperationCanceledException) when (serverStopping.IsCancellationRequested)
        {
            // server shutting down
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "[{Id}] Unexpected error.", _id);
            try
            {
                await SendErrorAsync(new ProtocolException(ErrorCode.InternalError, "Internal server error.")).ConfigureAwait(false);
            }
            catch { /* ignore */ }
        }
        finally
        {
            cts.Cancel();
            await ReleaseActiveAsync().ConfigureAwait(false);
            try { _client.Client.Shutdown(SocketShutdown.Both); } catch { /* ignore */ }
            _client.Dispose();
            try { await pinger.ConfigureAwait(false); } catch { /* ignore */ }
            _log.LogInformation("[{Id}] Disconnected.", _id);
        }
    }

    // ------------------------------------------------------------------ reading / timeouts

    private async Task<Frame?> ReadWithTimeoutAsync()
    {
        TimeSpan timeout = _state == State.Ready
            ? TimeSpan.FromSeconds(_o.IdleTimeoutSeconds)
            : _loginDeadlineUtc - DateTime.UtcNow;
        if (timeout <= TimeSpan.Zero)
            throw new ProtocolException(ErrorCode.Timeout, "Login not completed in time.");

        using var readCts = CancellationTokenSource.CreateLinkedTokenSource(_ct);
        readCts.CancelAfter(timeout);
        try
        {
            return await FrameCodec.ReadAsync(_stream, readCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!_ct.IsCancellationRequested)
        {
            throw new ProtocolException(ErrorCode.Timeout,
                _state == State.Ready ? $"Idle for {_o.IdleTimeoutSeconds} s." : "Login not completed in time.");
        }
    }

    private async Task PingLoopAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                await Task.Delay(TimeSpan.FromSeconds(5), ct).ConfigureAwait(false);
                if (_state != State.Ready)
                    continue;
                long idleMs = Environment.TickCount64 - Interlocked.Read(ref _lastSendTicks);
                if (idleMs >= _o.PingAfterSeconds * 1000L)
                    await SendAsync(MessageType.Ping, []).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException) { }
    }

    // ------------------------------------------------------------------ dispatch

    // <returns>false to close the connection.</returns>
    private async Task<bool> DispatchAsync(Frame f)
    {
        if (!MessageType.IsKnown(f.Type))
            throw new ProtocolException(ErrorCode.UnknownType, $"Unknown message type 0x{f.Type:X2}.", false, f.Type);

        switch (f.Type)
        {
            case MessageType.Ping:
                Messages.ParseEmpty(f.Type, f.Payload);
                await SendAsync(MessageType.Pong, []).ConfigureAwait(false);
                return true;
            case MessageType.Pong:
                return true;
        }

        switch (_state)
        {
            case State.AwaitHello when f.Type == MessageType.Hello:
                return await OnHelloAsync(f.Payload).ConfigureAwait(false);

            case State.AwaitLogin when f.Type == MessageType.Login:
                return await OnLoginAsync(f.Payload).ConfigureAwait(false);

            case State.Ready:
                switch (f.Type)
                {
                    case MessageType.UploadBegin: return await OnUploadBeginAsync(f.Payload).ConfigureAwait(false);
                    case MessageType.Chunk: return await OnChunkAsync(f.Payload).ConfigureAwait(false);
                    case MessageType.UploadEnd: return await OnUploadEndAsync(f.Payload).ConfigureAwait(false);
                    case MessageType.UploadAbort: return await OnUploadAbortAsync(f.Payload).ConfigureAwait(false);
                    case MessageType.Logout:
                        Messages.ParseEmpty(f.Type, f.Payload);
                        _log.LogInformation("[{Id}] {User} logged out.", _id, _username);
                        return false;
                }
                break;
        }

        // Known type, wrong state (e.g. CHUNK before LOGIN, or a server-to-client type sent by a client).
        bool uploadTypeBeforeLogin = _state != State.Ready &&
            f.Type is MessageType.UploadBegin or MessageType.Chunk or MessageType.UploadEnd or MessageType.UploadAbort;
        throw new ProtocolException(
            uploadTypeBeforeLogin ? ErrorCode.BadToken : ErrorCode.MalformedPayload,
            $"{MessageType.Name(f.Type)} is not allowed in state {_state}.", true, f.Type);
    }

    // ------------------------------------------------------------------ login

    private async Task<bool> OnHelloAsync(byte[] payload)
    {
        var hello = Messages.ParseHello(payload);
        if (hello.ProtoVersion != Messages.ProtocolVersion)
            throw new ProtocolException(ErrorCode.BadVersion,
                $"Protocol version {hello.ProtoVersion} not supported; server speaks {Messages.ProtocolVersion}.", true, MessageType.Hello);

        _log.LogInformation("[{Id}] HELLO from {Client} build {Build} (kind {Kind}).",
            _id, hello.ClientName, hello.ClientBuild, hello.ClientKind);

        _serverNonce = LsupCrypto.RandomBytes16();
        await SendAsync(MessageType.Challenge,
            Messages.Challenge(_serverNonce, _o.MinChunkSize, _o.MaxChunkSize, _o.MaxFileSize, (byte)_o.MaxWindow)).ConfigureAwait(false);
        _state = State.AwaitLogin;
        return true;
    }

    private async Task<bool> OnLoginAsync(byte[] payload)
    {
        var login = Messages.ParseLogin(payload);
        string userKey = LoginThrottle.UserKey(login.Username);
        string ipKey = LoginThrottle.IpKey(_remoteIp);

        int lockedFor = _throttle.LockedSeconds(userKey, ipKey);
        if (lockedFor > 0)
        {
            _log.LogWarning("[{Id}] Login for {User} refused: locked for {Seconds} s.", _id, login.Username, lockedFor);
            await SendAsync(MessageType.LoginFail, Messages.LoginFail(ErrorCode.Locked, lockedFor)).ConfigureAwait(false);
            return false;
        }

        // Unknown users are checked against a random key so the response time does not reveal which names exist.
        bool known = _o.Users.TryGetValue(login.Username, out string? apiKey) && !string.IsNullOrEmpty(apiKey);
        byte[] key = known ? LsupCrypto.KeyBytes(apiKey!) : LsupCrypto.RandomBytes16();

        byte[] expected = LsupCrypto.LoginResponse(key, _serverNonce, login.ClientNonce, login.UsernameBytes);
        if (!known || !LsupCrypto.FixedTimeEquals(expected, login.Response))
        {
            _throttle.RecordFailure(userKey, ipKey);
            _log.LogWarning("[{Id}] Login failed for {User} from {Ip}.", _id, login.Username, _remoteIp);
            await SendAsync(MessageType.LoginFail, Messages.LoginFail(ErrorCode.AuthFailed, 0)).ConfigureAwait(false);
            return false;
        }

        _throttle.RecordSuccess(userKey);
        _username = login.Username;
        _sessionToken = LsupCrypto.RandomBytes16();   // bound to this connection only
        _sessionKey = LsupCrypto.SessionKey(key, _serverNonce, login.ClientNonce);
        byte[] proof = LsupCrypto.ServerProof(key, _serverNonce, login.ClientNonce);

        await SendAsync(MessageType.LoginOk, Messages.LoginOk(_sessionToken, proof)).ConfigureAwait(false);
        _state = State.Ready;
        _log.LogInformation("[{Id}] {User} logged in.", _id, _username);
        return true;
    }

    // ------------------------------------------------------------------ uploads

    private void RequireMac(byte[] macInput, byte[] mac, byte type)
    {
        byte[] expected = LsupCrypto.MessageMac(_sessionKey, macInput);
        if (!LsupCrypto.FixedTimeEquals(expected, mac))
            throw new ProtocolException(ErrorCode.BadMac, $"{MessageType.Name(type)} MAC does not verify.", true, type);
    }

    private async Task<bool> OnUploadBeginAsync(byte[] payload)
    {
        var m = Messages.ParseUploadBegin(payload);
        if (!LsupCrypto.FixedTimeEquals(m.SessionToken, _sessionToken))
            throw new ProtocolException(ErrorCode.BadToken, "Session token does not belong to this connection.", true, MessageType.UploadBegin);
        RequireMac(m.MacInput, m.Mac, MessageType.UploadBegin);

        await ReleaseActiveAsync().ConfigureAwait(false); // a new BEGIN replaces any upload in progress

        var begin = _uploads.Begin(_id, _username, m);
        _active = new ActiveUpload { Tracker = begin.Tracker, File = _uploads.OpenForWrite(begin.Tracker) };

        var t = begin.Tracker;
        await SendAsync(MessageType.UploadBeginAck,
            Messages.UploadBeginAck(t.UploadId, t.ChunkSize, t.TotalChunks, begin.ResumeFromChunk, begin.Window)).ConfigureAwait(false);
        return true;
    }

    private async Task<bool> OnChunkAsync(byte[] payload)
    {
        var c = Messages.ParseChunk(payload);
        if (_active is null || _active.Tracker.UploadId != c.UploadId)
            throw new ProtocolException(ErrorCode.BadUploadId, $"No active upload {c.UploadId} on this connection.", false, MessageType.Chunk);

        int ackThrough = await _uploads.WriteChunkAsync(_id, _active, c, _ct).ConfigureAwait(false);
        await SendAsync(MessageType.ChunkAck, Messages.ChunkAck(c.UploadId, ackThrough)).ConfigureAwait(false);
        return true;
    }

    private async Task<bool> OnUploadEndAsync(byte[] payload)
    {
        var m = Messages.ParseUploadEnd(payload);
        if (_active is null || _active.Tracker.UploadId != m.UploadId)
            throw new ProtocolException(ErrorCode.BadUploadId, $"No active upload {m.UploadId} on this connection.", false, MessageType.UploadEnd);
        RequireMac(m.MacInput, m.Mac, MessageType.UploadEnd);

        var result = await _uploads.CompleteAsync(_id, _active, m, _ct).ConfigureAwait(false);
        _active = null;
        await SendAsync(MessageType.UploadResult, Messages.UploadResult(m.UploadId, result.Status, result.Reference)).ConfigureAwait(false);
        return true;
    }

    private async Task<bool> OnUploadAbortAsync(byte[] payload)
    {
        int id = Messages.ParseUploadAbort(payload);
        if (_active is not null && _active.Tracker.UploadId == id)
        {
            await _active.File.DisposeAsync().ConfigureAwait(false);
            _active = null;
        }
        _uploads.Abort(_id, id);
        return true; // no reply defined for UPLOAD_ABORT
    }

    private async Task ReleaseActiveAsync()
    {
        if (_active is null)
            return;
        var a = _active;
        _active = null;
        try
        {
            await _uploads.ReleaseAsync(_id, a).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "[{Id}] Error releasing upload {Upload}.", _id, a.Tracker.UploadId);
        }
    }

    // ------------------------------------------------------------------ sending

    private async Task SendAsync(byte type, byte[] payload)
    {
        byte[] frame = FrameCodec.Encode(type, payload);
        await _sendLock.WaitAsync(_ct).ConfigureAwait(false);
        try
        {
            await _stream.WriteAsync(frame, _ct).ConfigureAwait(false);
            Interlocked.Exchange(ref _lastSendTicks, Environment.TickCount64);
        }
        finally
        {
            _sendLock.Release();
        }
    }

    private Task SendErrorAsync(ProtocolException ex) =>
        SendAsync(MessageType.Error, Messages.Error(ex.Code, ex.RelatedType, ex.Message));
}
