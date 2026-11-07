using System.Security.Cryptography;
using LegacyShot.Server.Protocol;

namespace LegacyShot.Server.Security;

// 
// LSUP/2 login and MAC primitives. All are HMAC-MD5 (RFC 2104) so a Windows 95 client
// needs nothing beyond its own MD5 routine.
// 
public static class LsupCrypto
{
    private static readonly byte[] LabelLogin = "LSUP2 LOGIN"u8.ToArray();
    private static readonly byte[] LabelServer = "LSUP2 SERVER"u8.ToArray();
    private static readonly byte[] LabelSessionKey = "LSUP2 SKEY"u8.ToArray();

    public static byte[] KeyBytes(string apiKey) => Wire.Ansi.GetBytes(apiKey);

    public static byte[] HmacMd5(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data) => HMACMD5.HashData(key, data);

    // HMAC-MD5(Key, "LSUP2 LOGIN" ‖ ServerNonce ‖ ClientNonce ‖ U8 len(Username) ‖ Username)
    public static byte[] LoginResponse(byte[] key, byte[] serverNonce, byte[] clientNonce, byte[] usernameBytes) =>
        HmacMd5(key, Concat(LabelLogin, serverNonce, clientNonce, new[] { (byte)usernameBytes.Length }, usernameBytes));

    // HMAC-MD5(Key, "LSUP2 SERVER" ‖ ClientNonce ‖ ServerNonce)
    public static byte[] ServerProof(byte[] key, byte[] serverNonce, byte[] clientNonce) =>
        HmacMd5(key, Concat(LabelServer, clientNonce, serverNonce));

    // HMAC-MD5(Key, "LSUP2 SKEY" ‖ ServerNonce ‖ ClientNonce)
    public static byte[] SessionKey(byte[] key, byte[] serverNonce, byte[] clientNonce) =>
        HmacMd5(key, Concat(LabelSessionKey, serverNonce, clientNonce));

    // MAC = HMAC-MD5(SessionKey, Type ‖ payload bytes before the MAC).
    public static byte[] MessageMac(byte[] sessionKey, byte[] macInput) => HmacMd5(sessionKey, macInput);

    public static bool FixedTimeEquals(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) =>
        CryptographicOperations.FixedTimeEquals(a, b);

    public static byte[] RandomBytes16() => RandomNumberGenerator.GetBytes(16);

    private static byte[] Concat(params byte[][] parts)
    {
        var result = new byte[parts.Sum(p => p.Length)];
        int at = 0;
        foreach (var p in parts)
        {
            p.CopyTo(result, at);
            at += p.Length;
        }
        return result;
    }
}
