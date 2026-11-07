using LegacyShot.Server.Protocol;
using LegacyShot.Server.Security;
using LegacyShot.Server.Uploads;

namespace LegacyShot.Server;

// `dotnet run -- --selftest`: checks the spec's test vectors and the codec without a network.
public static class SelfTest
{
    private static int _failures;

    public static async Task<int> RunAsync()
    {
        Check("CRC32 check value", Crc32.Compute("123456789"u8).ToString("x8"), "cbf43926");

        Check("HMAC-MD5 RFC 2202 #1",
            Hex(LsupCrypto.HmacMd5(Enumerable.Repeat((byte)0x0B, 16).ToArray(), "Hi There"u8)),
            "9294727a3638bb1c13f48ef8158bfc9d");
        Check("HMAC-MD5 RFC 2202 #2",
            Hex(LsupCrypto.HmacMd5("Jefe"u8, "what do ya want for nothing?"u8)),
            "750c783e6ab0b503eaa86e310a5db738");

        Check("PING frame", Hex(FrameCodec.Encode(MessageType.Ping, [])), "abcd200000000019d8e307");

        byte[] key = LsupCrypto.KeyBytes("demo-secret-key");
        byte[] sn = Enumerable.Range(0, 16).Select(i => (byte)i).ToArray();
        byte[] cn = Enumerable.Range(16, 16).Select(i => (byte)i).ToArray();
        byte[] user = Wire.Ansi.GetBytes("nick");
        Check("Login Response", Hex(LsupCrypto.LoginResponse(key, sn, cn, user)), "a33ac1003a194934be8b175ed75e3d47");
        Check("ServerProof", Hex(LsupCrypto.ServerProof(key, sn, cn)), "c551c78d58f20157c0d0bdecadfb5c58");
        Check("SessionKey", Hex(LsupCrypto.SessionKey(key, sn, cn)), "6b628dddef0c485b9f48d84ae19c9533");

        // Codec round trip and corruption detection.
        var chunkPayload = new PayloadWriter().U32(7).U32(3).ToArray().Concat(new byte[] { 1, 2, 3 }).ToArray();
        byte[] frame = FrameCodec.Encode(MessageType.Chunk, chunkPayload);
        var read = await FrameCodec.ReadAsync(new MemoryStream(frame), CancellationToken.None);
        var chunk = Messages.ParseChunk(read!.Value.Payload);
        Check("CHUNK round trip", $"{chunk.UploadId}/{chunk.ChunkIndex}/{Hex(chunk.Data.ToArray())}", "7/3/010203");

        frame[^5] ^= 0xFF; // flip a payload byte
        try
        {
            await FrameCodec.ReadAsync(new MemoryStream(frame), CancellationToken.None);
            Check("Bad CRC detected", "no error", "BadCrc");
        }
        catch (ProtocolException ex)
        {
            Check("Bad CRC detected", ex.Code.ToString(), "BadCrc");
        }

        Check("Windows-1252 round trip", Hex(Wire.Ansi.GetBytes("caf\u00e9 \u20ac")), "636166e92080");

        Check("Sanitize path + ext", UploadManager.SanitizeFileName(@"C:\WINDOWS\..\shot 1.BMP", ImageType.Bmp), "shot 1.bmp");
        Check("Sanitize wrong ext", UploadManager.SanitizeFileName("../../etc/passwd", ImageType.Png), "passwd.png");
        Check("Sanitize odd chars", UploadManager.SanitizeFileName("a<b>|c?.jpeg", ImageType.Jpeg), "a_b__c_.jpeg");

        Console.WriteLine(_failures == 0 ? "All self-tests passed." : $"{_failures} self-test(s) FAILED.");
        return _failures == 0 ? 0 : 1;
    }

    private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();

    private static void Check(string name, string actual, string expected)
    {
        bool ok = actual == expected;
        if (!ok)
            _failures++;
        Console.WriteLine($"{(ok ? "PASS" : "FAIL")}  {name}{(ok ? "" : $": got {actual}, expected {expected}")}");
    }
}
