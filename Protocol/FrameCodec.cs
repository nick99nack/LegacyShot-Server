using System.Buffers.Binary;
using System.Text;

namespace LegacyShot.Server.Protocol;

// Thrown for any protocol violation. The handler turns it into an ERROR frame.
public sealed class ProtocolException : Exception
{
    public ErrorCode Code { get; }

    // When true the connection is closed after the ERROR frame is sent.
    public bool CloseConnection { get; }

    // The message type that caused the error, echoed in ERROR.RelatedType.
    public byte RelatedType { get; }

    public ProtocolException(ErrorCode code, string message, bool closeConnection = true, byte relatedType = 0)
        : base(message)
    {
        Code = code;
        CloseConnection = closeConnection;
        RelatedType = relatedType;
    }
}

public readonly record struct Frame(byte Type, byte[] Payload);

// 
// Frame layout: Magic(AB CD) | Type U8 | Length U32 LE | Payload | CRC32 U32 LE over Type+Length+Payload.
// 
public static class FrameCodec
{
    public const byte Magic0 = 0xAB;
    public const byte Magic1 = 0xCD;
    public const int HeaderSize = 7;
    public const int TrailerSize = 4;
    public const int MaxPayload = 65600;

    public static byte[] Encode(byte type, ReadOnlySpan<byte> payload)
    {
        if (payload.Length > MaxPayload)
            throw new ArgumentException($"Payload of {payload.Length} bytes exceeds {MaxPayload}.", nameof(payload));

        var buf = new byte[HeaderSize + payload.Length + TrailerSize];
        buf[0] = Magic0;
        buf[1] = Magic1;
        buf[2] = type;
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(3, 4), (uint)payload.Length);
        payload.CopyTo(buf.AsSpan(HeaderSize));

        uint crc = Crc32.Compute(buf.AsSpan(2, 5 + payload.Length));
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(HeaderSize + payload.Length, 4), crc);
        return buf;
    }

    // 
    // Reads one frame. Returns null on a clean end of stream between frames;
    // throws EndOfStreamException if the peer disconnects mid-frame and ProtocolException on a bad frame.
    // 
    public static async Task<Frame?> ReadAsync(Stream stream, CancellationToken ct)
    {
        var header = new byte[HeaderSize];
        int got = await stream.ReadAtLeastAsync(header, HeaderSize, throwOnEndOfStream: false, ct).ConfigureAwait(false);
        if (got == 0)
            return null;
        if (got < HeaderSize)
            throw new EndOfStreamException("Connection closed inside a frame header.");

        if (header[0] != Magic0 || header[1] != Magic1)
            throw new ProtocolException(ErrorCode.BadMagic, $"Bad magic {header[0]:X2} {header[1]:X2}.");

        uint length = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(3, 4));
        if (length > MaxPayload)
            throw new ProtocolException(ErrorCode.FrameTooLarge, $"Frame length {length} exceeds {MaxPayload}.", relatedType: header[2]);

        var payload = new byte[length];
        if (length > 0)
            await stream.ReadExactlyAsync(payload, ct).ConfigureAwait(false);

        var trailer = new byte[TrailerSize];
        await stream.ReadExactlyAsync(trailer, ct).ConfigureAwait(false);

        uint expected = BinaryPrimitives.ReadUInt32LittleEndian(trailer);
        uint actual = Crc32.Finish(Crc32.Append(Crc32.Append(Crc32.Initial, header.AsSpan(2, 5)), payload));
        if (expected != actual)
            throw new ProtocolException(ErrorCode.BadCrc, $"CRC mismatch: frame says {expected:X8}, computed {actual:X8}.", relatedType: header[2]);

        return new Frame(header[2], payload);
    }
}

// Windows-1252, the encoding VB6's StrConv produces on Western systems.
public static class Wire
{
    public static readonly Encoding Ansi;

    static Wire()
    {
        // .NET Core ships only UTF/ASCII/Latin-1 by default; code page 1252 needs this provider.
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        Ansi = Encoding.GetEncoding(1252);
    }
}
