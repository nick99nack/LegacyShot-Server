# LegacyShot Server

.NET server for the LSUP/2 upload protocol. Clients log in with an HMAC-MD5 challenge-response and upload images in resumable, windowed chunks over plain TCP.

## Build and run

```
dotnet build -c Release
dotnet run -c Release                    # listens on 0.0.0.0:7745
```

Publish a self-contained build for a server with no .NET runtime:

```
dotnet publish -c Release -r win-x64 --self-contained   # or linux-x64
```

## Configure (`appsettings.json`, section `Lsup`)

| Setting | Default | Notes |
| --- | --- | --- |
| `Port` / `ListenAddress` | 7745 / 0.0.0.0 | |
| `Users` | — | `"username": "api key"`. Use 32 random hex chars per user. |
| `UploadSavePath` | data/uploads | Finished files, one folder per user, plus a `.json` metadata file each |
| `TempUploadPath` | data/temp | Keep on the **same volume** as `UploadSavePath` so the final move is atomic |
| `StatePath` | data/lsup-state.json | Unfinished uploads; resume survives a restart |
| `MinChunkSize` / `MaxChunkSize` | 1024 / 65536 | Client's request is clamped into this range, rounded down to 512 |
| `MaxFileSize` | 16 MB | |
| `MaxWindow` | 4 | Window is 2 for ≤4 KB chunks, 3 for ≤16 KB, else 4, capped here |
| `IdleTimeoutSeconds` / `PingAfterSeconds` / `LoginTimeoutSeconds` | 120 / 30 / 60 | |
| `MaxConnections` / `MaxConnectionsPerIp` | 64 / 4 | Extra connections get `ERROR ServerBusy` |
| `LockoutFailures` / `LockoutWindowMinutes` / `LockoutMinutes` | 5 / 10 / 15 | Per username and per IP |
| `ResumeExpiryHours` | 48 | Idle unfinished uploads are deleted after this |
| `PublicBaseUrl` | null | If set, `UPLOAD_RESULT` returns a URL instead of `user/file` |

## Notes

- On FIPS-enforcing Windows or Linux hosts, .NET refuses MD5; LSUP/2 needs a non-FIPS host.
- Error `0x0007 MalformedPayload` is used for short/overlong payloads and messages sent in the wrong state.
