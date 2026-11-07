namespace LegacyShot.Server.Protocol;

// IEEE 802.3 CRC-32 (reflected, poly 0xEDB88320). Check value for "123456789" is 0xCBF43926.
public static class Crc32
{
    public const uint Initial = 0xFFFFFFFFu;

    private static readonly uint[] Table = BuildTable();

    private static uint[] BuildTable()
    {
        var table = new uint[256];
        for (uint i = 0; i < 256; i++)
        {
            uint c = i;
            for (int k = 0; k < 8; k++)
                c = (c & 1) != 0 ? 0xEDB88320u ^ (c >> 1) : c >> 1;
            table[i] = c;
        }
        return table;
    }

    // Feeds bytes into a running CRC state. Start from <see cref="Initial"/>, finish with <see cref="Finish"/>.
    public static uint Append(uint state, ReadOnlySpan<byte> data)
    {
        foreach (byte b in data)
            state = Table[(state ^ b) & 0xFF] ^ (state >> 8);
        return state;
    }

    public static uint Finish(uint state) => state ^ 0xFFFFFFFFu;

    public static uint Compute(ReadOnlySpan<byte> data) => Finish(Append(Initial, data));
}
