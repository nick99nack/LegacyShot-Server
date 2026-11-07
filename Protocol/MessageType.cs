namespace LegacyShot.Server.Protocol;

// LSUP/2 message type codes. Must match modProtocol.bas and the VC++ client header.
public static class MessageType
{
    public const byte Hello = 0x01;
    public const byte Challenge = 0x02;
    public const byte Login = 0x03;
    public const byte LoginOk = 0x04;
    public const byte LoginFail = 0x05;

    public const byte UploadBegin = 0x10;
    public const byte UploadBeginAck = 0x11;
    public const byte Chunk = 0x12;
    public const byte ChunkAck = 0x13;
    public const byte UploadEnd = 0x14;
    public const byte UploadResult = 0x15;
    public const byte UploadAbort = 0x16;

    public const byte Ping = 0x20;
    public const byte Pong = 0x21;
    public const byte Logout = 0x30;
    public const byte Error = 0x7F;

    public static bool IsKnown(byte type) => type switch
    {
        Hello or Challenge or Login or LoginOk or LoginFail or
        UploadBegin or UploadBeginAck or Chunk or ChunkAck or UploadEnd or UploadResult or UploadAbort or
        Ping or Pong or Logout or Error => true,
        _ => false,
    };

    public static string Name(byte type) => type switch
    {
        Hello => "HELLO",
        Challenge => "CHALLENGE",
        Login => "LOGIN",
        LoginOk => "LOGIN_OK",
        LoginFail => "LOGIN_FAIL",
        UploadBegin => "UPLOAD_BEGIN",
        UploadBeginAck => "UPLOAD_BEGIN_ACK",
        Chunk => "CHUNK",
        ChunkAck => "CHUNK_ACK",
        UploadEnd => "UPLOAD_END",
        UploadResult => "UPLOAD_RESULT",
        UploadAbort => "UPLOAD_ABORT",
        Ping => "PING",
        Pong => "PONG",
        Logout => "LOGOUT",
        Error => "ERROR",
        _ => $"0x{type:X2}",
    };
}

// U16 error codes carried in ERROR, LOGIN_FAIL and UPLOAD_RESULT.
public enum ErrorCode : ushort
{
    None = 0x0000,

    BadMagic = 0x0001,
    BadCrc = 0x0002,
    UnknownType = 0x0003,
    FrameTooLarge = 0x0004,
    BadVersion = 0x0005,
    Timeout = 0x0006,
    // Payload too short, trailing bytes, out-of-range value, or a message not allowed in the current state.
    MalformedPayload = 0x0007,

    AuthFailed = 0x0010,
    Locked = 0x0011,
    BadToken = 0x0012,
    BadMac = 0x0013,

    BadUploadId = 0x0100,
    BadChunk = 0x0101,
    TooLarge = 0x0102,
    Md5Mismatch = 0x0103,
    BadFileName = 0x0104,
    BadImageType = 0x0105,
    QuotaExceeded = 0x0106,

    ServerBusy = 0x0200,
    InternalError = 0x0201,
}

// ImageType byte in UPLOAD_BEGIN.
public enum ImageType : byte
{
    Bmp = 1,
    Jpeg = 2,
    Gif = 3,
    Png = 4,
}

public static class ImageTypes
{
    public static bool IsDefined(byte value) => value is >= 1 and <= 4;

    public static string DefaultExtension(ImageType t) => t switch
    {
        ImageType.Bmp => ".bmp",
        ImageType.Jpeg => ".jpg",
        ImageType.Gif => ".gif",
        ImageType.Png => ".png",
        _ => ".bin",
    };

    public static bool IsAllowedExtension(ImageType t, string ext) => t switch
    {
        ImageType.Bmp => ext.Equals(".bmp", StringComparison.OrdinalIgnoreCase),
        ImageType.Jpeg => ext.Equals(".jpg", StringComparison.OrdinalIgnoreCase)
                       || ext.Equals(".jpeg", StringComparison.OrdinalIgnoreCase),
        ImageType.Gif => ext.Equals(".gif", StringComparison.OrdinalIgnoreCase),
        ImageType.Png => ext.Equals(".png", StringComparison.OrdinalIgnoreCase),
        _ => false,
    };

    // Checks the file's leading bytes against the declared type.
    public static bool MagicMatches(ImageType t, ReadOnlySpan<byte> head) => t switch
    {
        ImageType.Bmp => head.Length >= 2 && head[0] == (byte)'B' && head[1] == (byte)'M',
        ImageType.Jpeg => head.Length >= 3 && head[0] == 0xFF && head[1] == 0xD8 && head[2] == 0xFF,
        ImageType.Gif => head.Length >= 4 && head[..4].SequenceEqual("GIF8"u8),
        ImageType.Png => head.Length >= 4 && head[0] == 0x89 && head[1] == 0x50 && head[2] == 0x4E && head[3] == 0x47,
        _ => false,
    };
}
