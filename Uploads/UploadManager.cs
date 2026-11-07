using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using LegacyShot.Server.Protocol;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace LegacyShot.Server.Uploads;

// One unfinished upload. Persisted to StatePath so resume survives a restart.
public sealed class UploadTracker
{
    public int UploadId { get; set; }
    public string Username { get; set; } = "";
    public string FileMd5Hex { get; set; } = "";
    public int TotalSize { get; set; }

    // Authoritative chunk size. Offsets are always ChunkIndex × ChunkSize, never re-derived.
    public int ChunkSize { get; set; }
    public int TotalChunks { get; set; }

    // Contiguous chunks known to be flushed to disk; the only count that survives a restart.
    public int DurableChunks { get; set; }

    public byte ImageType { get; set; }
    public string FileName { get; set; } = "";
    public string Description { get; set; } = "";
    public string TempPath { get; set; } = "";
    public DateTime CreatedUtc { get; set; }
    public DateTime LastActivityUtc { get; set; }

    // Contiguous chunks written (may be ahead of DurableChunks until the next flush).
    [JsonIgnore] public int ReceivedChunks { get; set; }

    // Connection currently allowed to write, 0 when none.
    [JsonIgnore] public long OwnerConnectionId { get; set; }

    public static string MakeKey(string username, string md5Hex, int totalSize) =>
        $"{username.ToLowerInvariant()}|{md5Hex}|{totalSize}";

    [JsonIgnore] public string Key => MakeKey(Username, FileMd5Hex, TotalSize);
}

// The upload a connection is currently streaming, with its open temp file.
public sealed class ActiveUpload
{
    public required UploadTracker Tracker { get; init; }
    public required FileStream File { get; init; }
    public DateTime LastPersistUtc { get; set; } = DateTime.UtcNow;
}

public sealed record BeginResult(UploadTracker Tracker, int ResumeFromChunk, byte Window);

public sealed record CompleteResult(ErrorCode Status, string Reference);

// 
// Owns all unfinished uploads: creation and resume lookup by (user, MD5, size), chunk writes,
// MD5 verification, the final atomic move, persistence and expiry.
// 
public sealed class UploadManager
{
    private static readonly TimeSpan PersistInterval = TimeSpan.FromSeconds(2);
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly ServerOptions _o;
    private readonly ILogger<UploadManager> _log;
    private readonly string _tempDir;
    private readonly string _saveDir;
    private readonly string _statePath;

    private readonly object _gate = new();
    private readonly Dictionary<int, UploadTracker> _byId = new();
    private readonly Dictionary<string, UploadTracker> _byKey = new(StringComparer.Ordinal);
    private int _nextId = 1;

    public UploadManager(IOptions<ServerOptions> options, ILogger<UploadManager> log)
    {
        _o = options.Value;
        _log = log;
        _tempDir = Path.GetFullPath(_o.TempUploadPath);
        _saveDir = Path.GetFullPath(_o.UploadSavePath);
        _statePath = Path.GetFullPath(_o.StatePath);
    }

    // ------------------------------------------------------------------ startup / persistence

    // Creates folders, reloads persisted trackers and deletes orphaned .part files.
    public void Load()
    {
        Directory.CreateDirectory(_tempDir);
        Directory.CreateDirectory(_saveDir);
        Directory.CreateDirectory(Path.GetDirectoryName(_statePath)!);

        lock (_gate)
        {
            if (File.Exists(_statePath))
            {
                try
                {
                    var saved = JsonSerializer.Deserialize<List<UploadTracker>>(File.ReadAllText(_statePath), JsonOptions) ?? [];
                    var cutoff = DateTime.UtcNow.AddHours(-_o.ResumeExpiryHours);
                    foreach (var t in saved)
                    {
                        bool usable = File.Exists(t.TempPath)
                                      && new FileInfo(t.TempPath).Length == t.TotalSize
                                      && t.LastActivityUtc >= cutoff
                                      && t.ChunkSize > 0
                                      && t.DurableChunks <= t.TotalChunks;
                        if (!usable)
                        {
                            TryDelete(t.TempPath);
                            continue;
                        }
                        t.ReceivedChunks = t.DurableChunks;
                        t.OwnerConnectionId = 0;
                        _byId[t.UploadId] = t;
                        _byKey[t.Key] = t;
                        _nextId = Math.Max(_nextId, t.UploadId + 1);
                    }
                }
                catch (Exception ex)
                {
                    _log.LogWarning(ex, "Could not read upload state from {Path}; starting with no resumable uploads.", _statePath);
                }
            }

            var known = new HashSet<string>(_byId.Values.Select(t => Path.GetFullPath(t.TempPath)), StringComparer.Ordinal);
            foreach (var part in Directory.EnumerateFiles(_tempDir, "*.part"))
            {
                if (!known.Contains(Path.GetFullPath(part)))
                    TryDelete(part);
            }

            SaveStateLocked();
        }

        _log.LogInformation("Loaded {Count} resumable upload(s).", _byId.Count);
    }

    private void SaveStateLocked()
    {
        try
        {
            string tmp = _statePath + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(_byId.Values.ToList(), JsonOptions));
            File.Move(tmp, _statePath, overwrite: true);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Failed to save upload state to {Path}.", _statePath);
        }
    }

    private void SaveState()
    {
        lock (_gate)
            SaveStateLocked();
    }

    // ------------------------------------------------------------------ begin

    public BeginResult Begin(long connectionId, string username, UploadBeginMessage m)
    {
        if (!ImageTypes.IsDefined(m.ImageType))
            throw Fail(ErrorCode.BadImageType, $"Image type {m.ImageType} is not accepted.");
        if (m.TotalSize <= 0)
            throw Fail(ErrorCode.BadImageType, "File is empty.");
        if (m.TotalSize > _o.MaxFileSize)
            throw Fail(ErrorCode.TooLarge, $"File is {m.TotalSize} bytes; the limit is {_o.MaxFileSize}.");

        var type = (ImageType)m.ImageType;
        string fileName = SanitizeFileName(m.FileName, type);
        string md5Hex = Convert.ToHexString(m.FileMd5).ToLowerInvariant();
        string key = UploadTracker.MakeKey(username, md5Hex, m.TotalSize);
        var now = DateTime.UtcNow;

        lock (_gate)
        {
            if (_byKey.TryGetValue(key, out var existing))
            {
                if (File.Exists(existing.TempPath))
                {
                    lock (existing)
                    {
                        // A newer connection for the same file takes over; the old one's writes are refused.
                        existing.OwnerConnectionId = connectionId;
                        existing.FileName = fileName;
                        existing.Description = m.Description;
                        existing.ImageType = m.ImageType;
                        existing.LastActivityUtc = now;
                    }
                    _log.LogInformation("Resuming upload {Id} for {User} at chunk {Chunk}/{Total}.",
                        existing.UploadId, username, existing.ReceivedChunks, existing.TotalChunks);
                    return new BeginResult(existing, existing.ReceivedChunks, WindowFor(existing.ChunkSize));
                }

                _byId.Remove(existing.UploadId);
                _byKey.Remove(key);
            }

            long inFlight = _byId.Values.Sum(t => (long)t.TotalSize);
            if (inFlight + m.TotalSize > (long)_o.MaxTempStorageMB * 1024 * 1024)
                throw Fail(ErrorCode.QuotaExceeded, "Server temporary storage is full; try again later.");

            int chunk = Math.Clamp(m.RequestedChunkSize, _o.MinChunkSize, _o.MaxChunkSize) / 512 * 512;
            int totalChunks = (int)(((long)m.TotalSize + chunk - 1) / chunk);
            int id = _nextId++;

            var t = new UploadTracker
            {
                UploadId = id,
                Username = username,
                FileMd5Hex = md5Hex,
                TotalSize = m.TotalSize,
                ChunkSize = chunk,
                TotalChunks = totalChunks,
                DurableChunks = 0,
                ReceivedChunks = 0,
                ImageType = m.ImageType,
                FileName = fileName,
                Description = m.Description,
                TempPath = Path.Combine(_tempDir, $"{id:D8}.part"),
                CreatedUtc = now,
                LastActivityUtc = now,
                OwnerConnectionId = connectionId,
            };

            using (var fs = new FileStream(t.TempPath, FileMode.Create, FileAccess.Write, FileShare.None))
                fs.SetLength(t.TotalSize); // pre-allocate so chunks are random-access writes

            _byId[id] = t;
            _byKey[key] = t;
            SaveStateLocked();

            _log.LogInformation("Upload {Id} started for {User}: {Name}, {Size} bytes, {Chunks} x {ChunkSize}.",
                id, username, fileName, t.TotalSize, totalChunks, chunk);
            return new BeginResult(t, 0, WindowFor(chunk));
        }
    }

    public FileStream OpenForWrite(UploadTracker t) =>
        new(t.TempPath, new FileStreamOptions
        {
            Mode = FileMode.Open,
            Access = FileAccess.Write,
            Share = FileShare.ReadWrite, // a dropped connection may still hold a handle until it times out
            Options = FileOptions.Asynchronous,
            BufferSize = 0,
        });

    private byte WindowFor(int chunkSize)
    {
        int w = chunkSize <= 4096 ? 2 : chunkSize <= 16384 ? 3 : 4;
        return (byte)Math.Min(w, _o.MaxWindow);
    }

    // ------------------------------------------------------------------ chunks

    // Writes one in-order chunk and returns the new contiguous count (CHUNK_ACK.AckThrough).
    public async Task<int> WriteChunkAsync(long connectionId, ActiveUpload a, ChunkMessage c, CancellationToken ct)
    {
        var t = a.Tracker;
        long offset;
        lock (t)
        {
            if (t.OwnerConnectionId != connectionId)
                throw new ProtocolException(ErrorCode.BadUploadId, "Upload was taken over by another connection.", true, MessageType.Chunk);
            if (t.ReceivedChunks >= t.TotalChunks)
                throw new ProtocolException(ErrorCode.BadChunk, "All chunks were already received.", true, MessageType.Chunk);
            if (c.ChunkIndex != t.ReceivedChunks)
                throw new ProtocolException(ErrorCode.BadChunk, $"Expected chunk {t.ReceivedChunks}, got {c.ChunkIndex}.", true, MessageType.Chunk);

            offset = (long)c.ChunkIndex * t.ChunkSize;
            long expected = Math.Min(t.ChunkSize, t.TotalSize - offset);
            if (c.Data.Count != expected)
                throw new ProtocolException(ErrorCode.BadChunk, $"Chunk {c.ChunkIndex} is {c.Data.Count} bytes; expected {expected}.", true, MessageType.Chunk);
        }

        a.File.Position = offset;
        await a.File.WriteAsync(c.Data.AsMemory(), ct).ConfigureAwait(false);

        int received;
        lock (t)
        {
            t.ReceivedChunks++;
            t.LastActivityUtc = DateTime.UtcNow;
            received = t.ReceivedChunks;
        }

        if (received == t.TotalChunks || DateTime.UtcNow - a.LastPersistUtc >= PersistInterval)
            Persist(a);

        return received;
    }

    // Flushes the temp file to disk, then records the flushed chunk count.
    private void Persist(ActiveUpload a)
    {
        try
        {
            a.File.Flush(flushToDisk: true);
            lock (a.Tracker)
                a.Tracker.DurableChunks = a.Tracker.ReceivedChunks;
            a.LastPersistUtc = DateTime.UtcNow;
            SaveState();
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Could not persist upload {Id}.", a.Tracker.UploadId);
        }
    }

    // Called when a connection drops or switches uploads: keep the tracker for resume, close the file.
    public async Task ReleaseAsync(long connectionId, ActiveUpload a)
    {
        if (a.File.CanWrite)
            Persist(a);
        await a.File.DisposeAsync().ConfigureAwait(false);
        lock (a.Tracker)
        {
            if (a.Tracker.OwnerConnectionId == connectionId)
                a.Tracker.OwnerConnectionId = 0;
        }
    }

    // ------------------------------------------------------------------ completion

    public async Task<CompleteResult> CompleteAsync(long connectionId, ActiveUpload a, UploadEndMessage m, CancellationToken ct)
    {
        var t = a.Tracker;
        lock (t)
        {
            if (t.OwnerConnectionId != connectionId)
                throw new ProtocolException(ErrorCode.BadUploadId, "Upload was taken over by another connection.", true, MessageType.UploadEnd);
            if (t.ReceivedChunks != t.TotalChunks)
                throw new ProtocolException(ErrorCode.BadChunk,
                    $"UPLOAD_END after {t.ReceivedChunks} of {t.TotalChunks} chunks.", false, MessageType.UploadEnd);
        }

        await a.File.FlushAsync(ct).ConfigureAwait(false);
        a.File.Flush(flushToDisk: true);
        await a.File.DisposeAsync().ConfigureAwait(false);

        string claimedHex = Convert.ToHexString(m.FileMd5).ToLowerInvariant();
        if (claimedHex != t.FileMd5Hex)
        {
            _log.LogWarning("Upload {Id}: UPLOAD_END MD5 {End} differs from UPLOAD_BEGIN MD5 {Begin}.", t.UploadId, claimedHex, t.FileMd5Hex);
            Discard(t);
            return new CompleteResult(ErrorCode.Md5Mismatch, "");
        }

        byte[] actual;
        var head = new byte[8];
        int headLen;
        await using (var rs = new FileStream(t.TempPath, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, useAsync: true))
        {
            actual = await MD5.HashDataAsync(rs, ct).ConfigureAwait(false);
            rs.Position = 0;
            headLen = await rs.ReadAtLeastAsync(head, head.Length, throwOnEndOfStream: false, ct).ConfigureAwait(false);
        }

        string actualHex = Convert.ToHexString(actual).ToLowerInvariant();
        if (actualHex != t.FileMd5Hex)
        {
            _log.LogWarning("Upload {Id}: received data hashes to {Actual}, expected {Expected}. Discarded.", t.UploadId, actualHex, t.FileMd5Hex);
            Discard(t);
            return new CompleteResult(ErrorCode.Md5Mismatch, "");
        }

        if (!ImageTypes.MagicMatches((ImageType)t.ImageType, head.AsSpan(0, headLen)))
        {
            _log.LogWarning("Upload {Id}: content is not a valid {Type}. Discarded.", t.UploadId, (ImageType)t.ImageType);
            Discard(t);
            return new CompleteResult(ErrorCode.BadImageType, "");
        }

        string userSegment = SafeSegment(t.Username);
        string userDir = Path.Combine(_saveDir, userSegment);
        Directory.CreateDirectory(userDir);
        string storedName = "";
        string finalPath = "";
        for (int attempt = 0; ; attempt++)
        {
            storedName = $"{RandomNumberGenerator.GetInt32(100000):D5}-{t.FileName}";
            finalPath = Path.GetFullPath(Path.Combine(userDir, storedName));

            // Defence in depth: SanitizeFileName already guarantees this.
            if (!finalPath.StartsWith(_saveDir + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            {
                Discard(t);
                return new CompleteResult(ErrorCode.BadFileName, "");
            }

            try
            {
                File.Move(t.TempPath, finalPath, overwrite: false); // atomic when temp and save dirs share a volume
                break;
            }
            catch (IOException) when (File.Exists(finalPath) && attempt < 20)
            {
                // Name taken (or another upload just claimed it); pick another.
            }
        }

        var meta = new
        {
            t.Username,
            OriginalName = t.FileName,
            t.Description,
            Md5 = t.FileMd5Hex,
            Size = t.TotalSize,
            ImageType = ((ImageType)t.ImageType).ToString(),
            UploadedUtc = DateTime.UtcNow,
        };
        try
        {
            await File.WriteAllTextAsync(finalPath + ".json", JsonSerializer.Serialize(meta, JsonOptions), ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Upload {Id}: stored, but metadata file could not be written.", t.UploadId);
        }

        lock (_gate)
        {
            _byId.Remove(t.UploadId);
            _byKey.Remove(t.Key);
            SaveStateLocked();
        }

        string reference = string.IsNullOrWhiteSpace(_o.PublicBaseUrl)
            ? $"{userSegment}/{storedName}"
            : $"{_o.PublicBaseUrl.TrimEnd('/')}/{Uri.EscapeDataString(userSegment)}/{Uri.EscapeDataString(storedName)}";

        _log.LogInformation("Upload {Id} stored as {Path}.", t.UploadId, finalPath);
        return new CompleteResult(ErrorCode.None, reference);
    }

    // ------------------------------------------------------------------ abort / expiry

    // UPLOAD_ABORT: forget the upload and delete its temp file. Caller closes its file handle first.
    public void Abort(long connectionId, int uploadId)
    {
        UploadTracker? t;
        lock (_gate)
            _byId.TryGetValue(uploadId, out t);
        if (t is null)
            return;
        lock (t)
        {
            if (t.OwnerConnectionId != connectionId && t.OwnerConnectionId != 0)
                return;
        }
        Discard(t);
        _log.LogInformation("Upload {Id} aborted by client.", uploadId);
    }

    // Deletes unowned uploads idle longer than ResumeExpiryHours.
    public void ExpireStale()
    {
        var cutoff = DateTime.UtcNow.AddHours(-_o.ResumeExpiryHours);
        List<UploadTracker> stale;
        lock (_gate)
            stale = _byId.Values.Where(t => t.OwnerConnectionId == 0 && t.LastActivityUtc < cutoff).ToList();
        foreach (var t in stale)
        {
            Discard(t);
            _log.LogInformation("Upload {Id} expired after {Hours} h idle.", t.UploadId, _o.ResumeExpiryHours);
        }
    }

    private void Discard(UploadTracker t)
    {
        lock (_gate)
        {
            _byId.Remove(t.UploadId);
            _byKey.Remove(t.Key);
            SaveStateLocked();
        }
        TryDelete(t.TempPath);
    }

    // ------------------------------------------------------------------ helpers

    private static ProtocolException Fail(ErrorCode code, string message) =>
        new(code, message, closeConnection: false, relatedType: MessageType.UploadBegin);

    private static bool IsSafeChar(char c) => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or ' ' or '-';

    // 
    // Strips any path, keeps only [A-Za-z0-9._ -], caps the name at 100 characters
    // and forces an extension that matches the declared image type.
    // 
    public static string SanitizeFileName(string raw, ImageType type)
    {
        string name = raw;
        int cut = name.LastIndexOfAny(['\\', '/', ':']);
        if (cut >= 0)
            name = name[(cut + 1)..];

        var sb = new StringBuilder(name.Length);
        foreach (char c in name)
            sb.Append(IsSafeChar(c) ? c : '_');
        name = sb.ToString().Trim(' ', '.');

        string ext = Path.GetExtension(name);
        string stem = (ext.Length > 0 ? name[..^ext.Length] : name).TrimEnd(' ', '.');
        if (!ImageTypes.IsAllowedExtension(type, ext))
            ext = ImageTypes.DefaultExtension(type);
        ext = ext.ToLowerInvariant();

        int maxStem = 100 - ext.Length;
        if (stem.Length > maxStem)
            stem = stem[..maxStem].TrimEnd(' ', '.');
        if (stem.Length == 0)
            throw Fail(ErrorCode.BadFileName, "File name is empty after removing disallowed characters.");

        return stem + ext;
    }

    private static string SafeSegment(string value)
    {
        var sb = new StringBuilder(value.Length);
        foreach (char c in value)
            sb.Append(char.IsAsciiLetterOrDigit(c) || c is '_' or '-' ? char.ToLowerInvariant(c) : '_');
        string s = sb.ToString().Trim('_');
        return s.Length == 0 ? "user" : s;
    }

    private void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
                File.Delete(path);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Could not delete {Path}.", path);
        }
    }
}
