namespace LegacyShot.Server.Protocol;

public sealed record HelloMessage(byte ProtoVersion, byte ClientKind, ushort ClientBuild, string ClientName);

// <param name="UsernameBytes">Raw Windows-1252 bytes as sent; these, not a re-encoding, feed the HMAC.</param>
public sealed record LoginMessage(string Username, byte[] UsernameBytes, byte[] ClientNonce, byte[] Response);

public sealed record UploadBeginMessage(
    byte[] SessionToken,
    byte[] FileMd5,
    int TotalSize,
    int RequestedChunkSize,
    byte ImageType,
    string FileName,
    string Description,
    byte[] Mac,
    byte[] MacInput);

public sealed record ChunkMessage(int UploadId, int ChunkIndex, ArraySegment<byte> Data);

public sealed record UploadEndMessage(int UploadId, byte[] FileMd5, byte[] Mac, byte[] MacInput);

// Parsers for client→server messages and builders for server→client messages.
public static class Messages
{
    public const byte ProtocolVersion = 2;

    // ---- parsers (C→S) ----

    public static HelloMessage ParseHello(byte[] payload)
    {
        var r = new PayloadReader(MessageType.Hello, payload);
        var msg = new HelloMessage(r.U8(), r.U8(), r.U16(), r.Str8());
        r.End();
        return msg;
    }

    public static LoginMessage ParseLogin(byte[] payload)
    {
        var r = new PayloadReader(MessageType.Login, payload);
        byte[] user = r.Str8Bytes();
        var msg = new LoginMessage(Wire.Ansi.GetString(user), user, r.B16(), r.B16());
        r.End();
        return msg;
    }

    public static UploadBeginMessage ParseUploadBegin(byte[] payload)
    {
        var r = new PayloadReader(MessageType.UploadBegin, payload);
        byte[] token = r.B16();       // fixed 16 bytes, no length prefix
        byte[] md5 = r.B16();
        int totalSize = r.U32();
        int requested = r.U32();
        byte imageType = r.U8();
        string fileName = r.Str8();
        string description = r.Str16();
        byte[] macInput = r.MacInputSoFar();
        byte[] mac = r.B16();
        r.End();
        return new UploadBeginMessage(token, md5, totalSize, requested, imageType, fileName, description, mac, macInput);
    }

    public static ChunkMessage ParseChunk(byte[] payload)
    {
        var r = new PayloadReader(MessageType.Chunk, payload);
        int uploadId = r.U32();
        int index = r.U32();
        return new ChunkMessage(uploadId, index, r.Rest()); // data length = frame Length − 8
    }

    public static UploadEndMessage ParseUploadEnd(byte[] payload)
    {
        var r = new PayloadReader(MessageType.UploadEnd, payload);
        int uploadId = r.U32();
        byte[] md5 = r.B16();
        byte[] macInput = r.MacInputSoFar();
        byte[] mac = r.B16();
        r.End();
        return new UploadEndMessage(uploadId, md5, mac, macInput);
    }

    public static int ParseUploadAbort(byte[] payload)
    {
        var r = new PayloadReader(MessageType.UploadAbort, payload);
        int id = r.U32();
        r.End();
        return id;
    }

    public static void ParseEmpty(byte type, byte[] payload) => new PayloadReader(type, payload).End();

    // ---- builders (S→C) ----

    public static byte[] Challenge(byte[] serverNonce, int minChunk, int maxChunk, int maxFileSize, byte maxWindow) =>
        new PayloadWriter().B16(serverNonce).U32(minChunk).U32(maxChunk).U32(maxFileSize).U8(maxWindow).ToArray();

    public static byte[] LoginOk(byte[] sessionToken, byte[] serverProof) =>
        new PayloadWriter().B16(sessionToken).B16(serverProof).ToArray();

    public static byte[] LoginFail(ErrorCode code, int retryAfterSeconds) =>
        new PayloadWriter().U16((ushort)code).U16((ushort)Math.Clamp(retryAfterSeconds, 0, ushort.MaxValue)).ToArray();

    public static byte[] UploadBeginAck(int uploadId, int chunkSize, int totalChunks, int resumeFromChunk, byte window) =>
        new PayloadWriter().U32(uploadId).U32(chunkSize).U32(totalChunks).U32(resumeFromChunk).U8(window).ToArray();

    public static byte[] ChunkAck(int uploadId, int ackThrough) =>
        new PayloadWriter().U32(uploadId).U32(ackThrough).ToArray();

    public static byte[] UploadResult(int uploadId, ErrorCode status, string serverReference) =>
        new PayloadWriter().U32(uploadId).U16((ushort)status).Str16(serverReference).ToArray();

    public static byte[] Error(ErrorCode code, byte relatedType, string message) =>
        new PayloadWriter().U16((ushort)code).U8(relatedType).Str8(message).ToArray();
}
