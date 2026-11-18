using System.IO.Compression;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Sas;
using Sas.Auth;
using Sas.Cli;
using Sas.Logging;
using Sas.Server;
using Sas.Trust;

var foundCommands = args.Where(a => Config.ManagementCommands.Contains(a)).ToArray();

if (args.Any(a => a == "--help" || a == "-h"))
{
    Config.ShowHelp();
    Environment.Exit(0);
}

if (foundCommands.Length > 1)
{
    Console.Error.WriteLine("错误：不能同时使用多个管理命令。 / Cannot use multiple management commands at once.");
    Console.Error.WriteLine($"  你输入了 / You entered: {string.Join(" ", foundCommands)}");
    Console.Error.WriteLine("  请一次只运行一个命令 / Please run one command at a time:");
    Console.Error.WriteLine("    sas --add-cluster");
    Console.Error.WriteLine("    sas --list-clusters");
    Environment.Exit(1);
}

if (foundCommands.Length > 0 && args.Any(a => a == "--update"))
{
    Console.Error.WriteLine("错误：--update 不能与管理命令同时使用。 / --update cannot be used with management commands.");
    Console.Error.WriteLine("  请分开执行 / Please run them separately:");
    Console.Error.WriteLine("    sas --update");
    Console.Error.WriteLine($"    sas {foundCommands[0]}");
    Environment.Exit(1);
}

if (args.Any(a => a == "--update"))
{
    await CheckUpdateCommand();
    return;
}

if (args.Any(a => a == "--add-admin"))
{
    Config.AddAdminCommand(args);
    return;
}

if (args.Any(a => a == "--remove-admin"))
{
    Config.RemoveAdminCommand(args);
    return;
}

if (args.Any(a => a == "--list-admins"))
{
    Config.ListAdminsCommand(args);
    return;
}

if (args.Any(a => a == "--add-cluster"))
{
    Config.AddClusterCommand(args);
    return;
}

if (args.Any(a => a == "--remove-cluster"))
{
    Config.RemoveClusterCommand(args);
    return;
}

if (args.Any(a => a == "--list-clusters"))
{
    Config.ListClustersCommand(args);
    return;
}

var config = Config.Load(args);

var version = Assembly.GetEntryAssembly()?
    .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
    .InformationalVersion ?? "unknown";

Logger.Info("        _____ __  __  ___");
Logger.Info("       |  ___|  \\/  |/ _ \\");
Logger.Info("       | |_  | |\\/| | | | |");
Logger.Info("       |  _| | |  | | |_| |");
Logger.Info("       |_|   |_|  |_|\\___/");
Logger.Info("");
Logger.Info("    Server Authorizer Service");
Logger.Info("");

Logger.Info($"Config: {Config.ConfigFilePath}");
Logger.Info($"SAS HTTP auth mode");
Logger.Info($"  MQTT: {config.Mqtt.Host}:{config.Mqtt.Port}");
if (config.Mqtt.Clusters.Length > 0)
{
    Logger.Info($"  Clusters: {config.Mqtt.Clusters.Length} entries");
    foreach (var c in config.Mqtt.Clusters)
        Logger.Info($"    - uid={c.Uid} callsign={c.Callsign} mqtt={c.MqttHost}:{c.MqttPort}");
}

Logger.Info($"  Server: uid={config.Server.Uid} callsign={config.Server.Callsign} certFingerprint={(string.IsNullOrEmpty(config.Server.CertFingerprint) ? "(not set)" : config.Server.CertFingerprint)}");
var adminsCount = config.Server.Admins.Length;
var isAutoAdmin = adminsCount == 1
                  && config.Server.Admins[0].Uid == config.Server.Uid
                  && string.Equals(config.Server.Admins[0].CertFingerprint, config.Server.CertFingerprint, StringComparison.Ordinal);
if (!isAutoAdmin)
{
    var adminsList = adminsCount == 0
        ? "(none)"
        : string.Join(", ", config.Server.Admins.Select(a =>
            $"uid={a.Uid} fp={a.CertFingerprint}"));
    Logger.Info($"  Admins: {adminsCount} {adminsList}");
}

if (adminsCount == 0)
{
    Logger.Warn("  No admins configured: super is granted only to the certificate whose " +
                "fingerprint equals server.certFingerprint");
}

Logger.Info($"  Version: {version}");
Logger.Info($"  Archive: {(config.Archive.Enabled ? config.Archive.Dir : "(disabled)")}");
Logger.Info($"  Rate limit: global={config.Http.RateLimit.GlobalPerMinute}/min breaker={(config.Http.RateLimit.BreakerEnabled ? "on" : "off")}");

var rootStore = new RootCaStore(config.Trust.RootsDir);
var verifier = new CertVerifier();
var crlManager = new CrlManager(config.Trust.RootsDir, config.Crl.RefreshSec);
var aclStore = AclStore.FromRootsDir(config.Trust.RootsDir);
var archive = new AuthArchive(config.Archive);
var rateLimiter = new AuthRateLimiter(config.Http.RateLimit);

Logger.Info("SAS HTTP auth listening on:");
if (config.Http.Addr == "0.0.0.0" || config.Http.Addr == "+")
{
    foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
    {
        if (ni.OperationalStatus != OperationalStatus.Up) continue;
        foreach (var ua in ni.GetIPProperties().UnicastAddresses)
        {
            if (ua.Address.AddressFamily == AddressFamily.InterNetwork)
                Logger.Info($"  http://{ua.Address}:{config.Http.Port}/auth");
        }
    }
}
else
{
    Logger.Info($"  http://{config.Http.Addr}:{config.Http.Port}/auth");
}

crlManager.Initialize(rootStore.AllRoots.ToArray());

var httpHandler = new HttpAuthHandler(config, rootStore, verifier, crlManager, aclStore, archive);
var template = CreateResponseTemplate(config.Http.ResponseTemplate);
var httpServer = new HttpServer(config.Http.Addr, config.Http.Port, config.Http.MaxBodyBytes,
    config.Http.MaxPasswordBytes, config.Http.MaxConcurrent, httpHandler, template, rateLimiter);
httpServer.Start();

if (config.Update.Enabled)
    _ = CheckVersionAsync(version);

using var cts = new CancellationTokenSource();

try
{
    await httpServer.RunAsync(cts.Token);
}
catch (OperationCanceledException)
{
}
finally
{
    httpServer.Stop();
    archive.Flush();
}

Logger.Info("SAS stopped.");
Logger.Flush();

return;

static IResponseTemplate CreateResponseTemplate(string name)
{
    return name.ToLowerInvariant() switch
    {
        "emqx" => new EmqxResponseTemplate(),
        _ => new EmqxResponseTemplate()
    };
}

static string GetCurrentVersion()
{
    return Assembly.GetEntryAssembly()?
        .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
        .InformationalVersion ?? "unknown";
}

static async Task CheckVersionAsync(string currentVersion)
{
    try
    {
        Logger.Info("─── Checking for updates ───");
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
        var json = await http.GetStringAsync("https://bg5esn.com/share/fmo/sas.json");
        var doc = JsonDocument.Parse(json).RootElement;
        var latest = doc.GetProperty("version").GetString() ?? "";

        if (!ConfigParser.TryParseCleanVersion(latest, out var remote) ||
            !ConfigParser.TryParseCleanVersion(currentVersion, out var local))
        {
            Logger.Info("  Update check skipped (failed to parse version).");
            return;
        }

        if (remote <= local)
        {
            Logger.Info("  Already up to date.");
            return;
        }

        var url = doc.TryGetProperty("url", out var u)
            ? u.GetString()
            : null;
        var notes = doc.TryGetProperty("notes", out var n)
            ? n.GetString()
            : null;

        Logger.Warn("┌─────────────────────────────────────────────────────────────────────────────");
        Logger.Warn($"│  New SAS version available: {latest}");
        if (url != null)
            Logger.Warn($"│  {url}");
        if (!string.IsNullOrWhiteSpace(notes))
            Logger.Warn($"│  {notes}");

        if (ConfigParser.IsRunningInDocker())
        {
            Logger.Warn("│  Update: docker pull fmo/sas:latest && docker compose up -d");
        }
        else
        {
            Logger.Warn("│  Update now: sas --update");
        }

        Logger.Warn("└─────────────────────────────────────────────────────────────────────────────");
    }
    catch (Exception ex)
    {
        Logger.Info($"  Update check failed: {ex.Message}");
    }
}

static async Task CheckUpdateCommand()
{
    var version = GetCurrentVersion();
    Console.WriteLine($"SAS version: {version}");

    if (ConfigParser.IsRunningInDocker())
    {
        Console.WriteLine();
        Console.WriteLine("Running in Docker. Update with:");
        Console.WriteLine("  docker pull fmo/sas:latest && docker compose up -d");
        return;
    }

    Console.Write("Checking for updates... ");

    try
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
        var json = await http.GetStringAsync("https://bg5esn.com/share/fmo/sas.json");
        var doc = JsonDocument.Parse(json).RootElement;
        var latest = doc.GetProperty("version").GetString() ?? "";

        if (!ConfigParser.TryParseCleanVersion(latest, out var remote) ||
            !ConfigParser.TryParseCleanVersion(version, out var local))
        {
            Console.WriteLine("Failed to parse version.");
            return;
        }

        if (remote <= local)
        {
            Console.WriteLine("Already up to date.");
            return;
        }

        Console.WriteLine($"v{latest} available!");

        if (!doc.TryGetProperty("assets", out var assets))
        {
            Console.WriteLine("No download assets found in sas.json.");
            return;
        }

        var rid = RuntimeInformation.RuntimeIdentifier;
        if (!assets.TryGetProperty(rid, out var downloadUrl))
        {
            Console.WriteLine($"No asset for platform: {rid}");
            return;
        }

        var dl = downloadUrl.GetString() ?? "";
        Console.WriteLine($"Downloading {dl}...");

        var tempDir = Path.Combine(Path.GetTempPath(), "sas_update");
        if (Directory.Exists(tempDir))
            Directory.Delete(tempDir, true);
        Directory.CreateDirectory(tempDir);

        var ext = dl.EndsWith(".zip", StringComparison.OrdinalIgnoreCase) ? ".zip" : ".tar.gz";
        var archivePath = Path.Combine(tempDir, $"update{ext}");

        using (var response = await http.GetAsync(dl, HttpCompletionOption.ResponseHeadersRead))
        {
            response.EnsureSuccessStatusCode();
            var total = response.Content.Headers.ContentLength ?? -1;
            await using var stream = await response.Content.ReadAsStreamAsync();
            await using var fs = File.Create(archivePath);
            var buffer = new byte[8192];
            long read = 0;
            int len;
            while ((len = await stream.ReadAsync(buffer)) > 0)
            {
                await fs.WriteAsync(buffer.AsMemory(0, len));
                read += len;
                if (total > 0)
                {
                    var pct = (int)(read * 100 / total);
                    var bar = new string('#', pct / 2) + new string(' ', 50 - pct / 2);
                    Console.Write($"\r  [{bar}] {pct,3}% {read / 1024,5:N0}KB / {total / 1024,5:N0}KB");
                }
            }

            Console.WriteLine();
        }

        Console.WriteLine("Extracting...");
        if (ext == ".zip")
            ZipFile.ExtractToDirectory(archivePath, tempDir);
        else
            ExtractTarGz(archivePath, tempDir);
        File.Delete(archivePath);

        var exeName = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "sas.exe" : "sas";
        var newExe = Directory.GetFiles(tempDir, exeName, SearchOption.AllDirectories).FirstOrDefault()
                     ?? throw new InvalidOperationException($"{exeName} not found in archive");

        Console.WriteLine("Ready to update. Replacing binary...");

        var exePath = Environment.ProcessPath ?? "";
        var scriptExt = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "bat" : "sh";
        var scriptPath = Path.Combine(Path.GetTempPath(), $"sas_update.{scriptExt}");

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            File.WriteAllText(scriptPath, $"""
                                           @echo off
                                           setlocal
                                           :wait
                                           timeout /t 1 /nobreak >nul
                                           tasklist /fi "PID eq {Environment.ProcessId}" 2>nul | findstr "{Environment.ProcessId}" >nul
                                           if not errorlevel 1 goto wait
                                           move /y "{newExe}" "{exePath}"
                                           rmdir /s /q "{tempDir}"
                                           echo SAS updated to v{latest}. Run 'sas' to start.
                                           pause
                                           del "%~f0"
                                           """);
        }
        else
        {
            var pid = Environment.ProcessId;
            File.WriteAllText(scriptPath,
                $"#!/bin/sh\n" +
                $"while kill -0 {pid} 2>/dev/null; do sleep 1; done\n" +
                $"mv \"{newExe}\" \"{exePath}\"\n" +
                $"chmod +x \"{exePath}\"\n" +
                $"rm -rf \"{tempDir}\"\n" +
                $"echo \"SAS updated to v{latest}. Run 'sas' to start.\"\n" +
                $"rm \"$0\"\n");
            try
            {
                System.Diagnostics.Process.Start("chmod", $"+x \"{scriptPath}\"")?.WaitForExit();
            }
            catch
            {
            }
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            System.Diagnostics.Process.Start("cmd", $"/c \"{scriptPath}\"");
        else
            System.Diagnostics.Process.Start("sh", scriptPath);

        Environment.Exit(0);
    }
    catch (Exception ex)
    {
        Console.WriteLine();
        Console.WriteLine($"Update failed: {ex.Message}");
    }
}

static void ExtractTarGz(string archivePath, string destDir)
{
    System.Diagnostics.Process.Start("tar", $"-xzf \"{archivePath}\" -C \"{destDir}\"")
        ?.WaitForExit(30_000);
}
