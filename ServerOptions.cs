namespace LegacyShot.Server;

// Configuration bound from the "Lsup" section of appsettings.json.
public sealed class ServerOptions
{
    public const string Section = "Lsup";

    public string ListenAddress { get; set; } = "0.0.0.0";
    public int Port { get; set; } = 7745;

    // Finished files land here, one subfolder per user.
    public string UploadSavePath { get; set; } = "data/uploads";

    // Pre-allocated .part files. Keep on the same volume as UploadSavePath so the final move is atomic.
    public string TempUploadPath { get; set; } = "data/temp";

    // JSON file holding unfinished upload trackers so resume survives a server restart.
    public string StatePath { get; set; } = "data/lsup-state.json";

    // If set, UPLOAD_RESULT returns "{PublicBaseUrl}/{user}/{file}" instead of a relative path.
    public string? PublicBaseUrl { get; set; }

    public int MinChunkSize { get; set; } = 1024;
    public int MaxChunkSize { get; set; } = 65536;
    public int MaxFileSize { get; set; } = 16 * 1024 * 1024;
    public int MaxWindow { get; set; } = 4;
    public int MaxTempStorageMB { get; set; } = 1024;

    public int LoginTimeoutSeconds { get; set; } = 60;
    public int IdleTimeoutSeconds { get; set; } = 120;
    public int PingAfterSeconds { get; set; } = 30;
    public int MaxConnections { get; set; } = 64;
    public int MaxConnectionsPerIp { get; set; } = 4;
    public int ResumeExpiryHours { get; set; } = 48;

    public int LockoutFailures { get; set; } = 5;
    public int LockoutWindowMinutes { get; set; } = 10;
    public int LockoutMinutes { get; set; } = 15;

    // Username → API key. The key's Windows-1252 bytes are the HMAC key.
    public Dictionary<string, string> Users { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    // Clamp values into what the wire format can carry (spec: payload ≤ 65,600, U32 ≤ 0x7FFFFFFF).
    public void Normalize()
    {
        MaxChunkSize = Math.Clamp(MaxChunkSize, 512, 65536) / 512 * 512;
        MinChunkSize = Math.Clamp(MinChunkSize, 512, MaxChunkSize) / 512 * 512;
        MaxFileSize = Math.Clamp(MaxFileSize, 1, int.MaxValue);
        MaxWindow = Math.Clamp(MaxWindow, 1, 16);
        PingAfterSeconds = Math.Max(5, PingAfterSeconds);
        IdleTimeoutSeconds = Math.Max(PingAfterSeconds * 2, IdleTimeoutSeconds);
        LoginTimeoutSeconds = Math.Max(5, LoginTimeoutSeconds);
        MaxConnections = Math.Max(1, MaxConnections);
        MaxConnectionsPerIp = Math.Max(1, MaxConnectionsPerIp);
        ResumeExpiryHours = Math.Max(1, ResumeExpiryHours);
        MaxTempStorageMB = Math.Max(1, MaxTempStorageMB);
    }
}
