using LegacyShot.Server;
using LegacyShot.Server.Net;
using LegacyShot.Server.Security;
using LegacyShot.Server.Uploads;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

if (args.Contains("--selftest"))
    return await SelfTest.RunAsync();

var builder = Host.CreateApplicationBuilder(args);

builder.Services.Configure<ServerOptions>(builder.Configuration.GetSection(ServerOptions.Section));
builder.Services.PostConfigure<ServerOptions>(o => o.Normalize());

builder.Services.AddSingleton<LoginThrottle>();
builder.Services.AddSingleton<UploadManager>();
builder.Services.AddHostedService<LsupServer>();

await builder.Build().RunAsync();
return 0;
