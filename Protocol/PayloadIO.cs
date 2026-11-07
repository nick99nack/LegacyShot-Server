using System.Buffers.Binary;

namespace LegacyShot.Server.Protocol;

// Reads LSUP/2 field types from a payload. Any underrun or out-of-range value is MalformedPayload.
public sealed class PayloadReader
{
    private readonly byte[] _buf;
    private readonly byte _type;
    private int _pos;

    public PayloadReader(byte type, byte[] payload)
    {
        _type = type;
        _buf = payload;
    }

    public int Position => _pos;
    public int Remaining => _buf.Length - _pos;

    private ProtocolException Malformed(string why) =>
        new(ErrorCode.MalformedPayload, $"{MessageType.Name(_type)}: {why}", closeConnection: true, relatedType: _type);

    private void Need(int n)
    {
        if (Remaining < n)
            throw Malformed($"needed {n} more bytes at offset {_pos}, have {Remaining}");
    }

    public byte U8()
    {
        Need(1);
        return _buf[_pos++];
    }

    public ushort U16()
    {
        Need(2);
        ushort v = BinaryPrimitives.ReadUInt16LittleEndian(_buf.AsSpan(_pos, 2));
        _pos += 2;
        return v;
    }

    // U32 that must fit in a VB6 Long (≤ 0x7FFFFFFF).
    public int U32()
    {
        Need(4);
        uint v = BinaryPrimitives.ReadUInt32LittleEndian(_buf.AsSpan(_pos, 4));
        _pos += 4;
        if (v > int.MaxValue)
            throw Malformed($"U32 value {v} above 0x7FFFFFFF");
        return (int)v;
    }

    public byte[] B16()
    {
        Need(16);
        byte[] v = _buf.AsSpan(_pos, 16).ToArray();
        _pos += 16;
        return v;
    }

    // STR8 as raw bytes (needed where the bytes feed an HMAC).
    public byte[] Str8Bytes()
    {
        int n = U8();
        Need(n);
        byte[] v = _buf.AsSpan(_pos, n).ToArray();
        _pos += n;
        return v;
    }

    public string Str8() => Wire.Ansi.GetString(Str8Bytes());

    public string Str16()
    {
        int n = U16();
        Need(n);
        string s = Wire.Ansi.GetString(_buf, _pos, n);
        _pos += n;
        return s;
    }

    // Everything left in the payload.
    public ArraySegment<byte> Rest()
    {
        var seg = new ArraySegment<byte>(_buf, _pos, Remaining);
        _pos = _buf.Length;
        return seg;
    }

    // Bytes before the current position, prefixed with the type byte: the MAC input.
    public byte[] MacInputSoFar()
    {
        var input = new byte[1 + _pos];
        input[0] = _type;
        _buf.AsSpan(0, _pos).CopyTo(input.AsSpan(1));
        return input;
    }

    public void End()
    {
        if (Remaining != 0)
            throw Malformed($"{Remaining} trailing bytes");
    }
}

// Builds LSUP/2 payloads.
public sealed class PayloadWriter
{
    private readonly MemoryStream _ms = new();

    public PayloadWriter U8(byte v)
    {
        _ms.WriteByte(v);
        return this;
    }

    public PayloadWriter U16(ushort v)
    {
        Span<byte> b = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(b, v);
        _ms.Write(b);
        return this;
    }

    public PayloadWriter U32(int v)
    {
        if (v < 0)
            throw new ArgumentOutOfRangeException(nameof(v), "U32 fields must be 0..0x7FFFFFFF.");
        Span<byte> b = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(b, (uint)v);
        _ms.Write(b);
        return this;
    }

    public PayloadWriter B16(ReadOnlySpan<byte> v)
    {
        if (v.Length != 16)
            throw new ArgumentException("B16 fields are exactly 16 bytes.", nameof(v));
        _ms.Write(v);
        return this;
    }

    public PayloadWriter Str8(string s)
    {
        byte[] b = Wire.Ansi.GetBytes(s);
        int n = Math.Min(b.Length, byte.MaxValue);
        _ms.WriteByte((byte)n);
        _ms.Write(b, 0, n);
        return this;
    }

    public PayloadWriter Str16(string s)
    {
        byte[] b = Wire.Ansi.GetBytes(s);
        int n = Math.Min(b.Length, ushort.MaxValue);
        U16((ushort)n);
        _ms.Write(b, 0, n);
        return this;
    }

    public byte[] ToArray() => _ms.ToArray();
}
