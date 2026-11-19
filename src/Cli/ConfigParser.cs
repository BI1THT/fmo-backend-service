using System.Text;

namespace Sas.Cli;

/// <summary>
/// Pure command-line and version parsing helpers, separated from <see cref="Config"/>
/// so they can be unit-tested without touching the console or the file system.
/// </summary>
internal static class ConfigParser
{
    internal static readonly HashSet<string> InitArgNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "--server-uid", "--server-callsign", "--mqtt-host", "--mqtt-port",
        "--cert-fingerprint", "--issuer-sn", "--allow-issuer-sn", "--roots-dir",
        "--crl-refresh", "--crl-mode", "--http-port", "--http-addr", "--http-ttl", "--log-level",
        "--archive-dir", "--archive-retention"
    };

    /// <summary>
    /// Expands "--name=value" into two tokens. Values may themselves contain '='.
    /// </summary>
    internal static List<string> FlattenEqArgs(string[] args)
    {
        var result = new List<string>(args.Length);
        foreach (var arg in args)
        {
            if (arg.StartsWith("--") && arg.Contains('='))
            {
                var eq = arg.IndexOf('=');
                result.Add(arg[..eq]);
                result.Add(arg[(eq + 1)..]);
            }
            else
            {
                result.Add(arg);
            }
        }

        return result;
    }

    internal static string? ExtractConfigArg(List<string> flatArgs)
    {
        for (int i = 0; i < flatArgs.Count; i++)
        {
            if (flatArgs[i] == "--config" && i + 1 < flatArgs.Count)
                return flatArgs[i + 1];
        }

        return null;
    }

    internal static bool HasInitArgsBeyondConfig(List<string> flatArgs)
    {
        for (int i = 0; i < flatArgs.Count; i++)
        {
            if (InitArgNames.Contains(flatArgs[i]))
                return true;
        }

        return false;
    }

    internal static Config BuildFromArgs(string[] args)
    {
        var config = new Config();
        var flatArgs = FlattenEqArgs(args);

        for (int i = 0; i < flatArgs.Count; i++)
        {
            switch (flatArgs[i])
            {
                case "--config" when i + 1 < flatArgs.Count:
                    Config.ConfigPath = flatArgs[++i];
                    break;
                case "--server-uid" when i + 1 < flatArgs.Count:
                    config.Server.Uid = long.Parse(flatArgs[++i]);
                    break;
                case "--server-callsign" when i + 1 < flatArgs.Count:
                    config.Server.Callsign = flatArgs[++i];
                    break;
                case "--mqtt-host" when i + 1 < flatArgs.Count:
                    config.Mqtt.Host = flatArgs[++i];
                    break;
                case "--mqtt-port" when i + 1 < flatArgs.Count:
                    config.Mqtt.Port = int.Parse(flatArgs[++i]);
                    break;
                case "--allow-issuer-sn" when i + 1 < flatArgs.Count:
                    config.Trust.AllowIssuerSn = ParseIssuerSn(flatArgs[++i]);
                    break;
                case "--roots-dir" when i + 1 < flatArgs.Count:
                    config.Trust.RootsDir = flatArgs[++i];
                    break;
                case "--issuer-sn" when i + 1 < flatArgs.Count:
                    config.Server.IssuerSn = long.Parse(flatArgs[++i]);
                    break;
                case "--cert-fingerprint" when i + 1 < flatArgs.Count:
                    config.Server.CertFingerprint = flatArgs[++i];
                    break;
                case "--crl-refresh" when i + 1 < flatArgs.Count:
                    config.Crl.RefreshSec = int.Parse(flatArgs[++i]);
                    break;
                case "--crl-mode" when i + 1 < flatArgs.Count:
                    config.Crl.Mode = flatArgs[++i];
                    break;
                case "--log-level" when i + 1 < flatArgs.Count:
                    config.Log.Level = flatArgs[++i];
                    break;
                case "--http-port" when i + 1 < flatArgs.Count:
                    config.Http.Port = int.Parse(flatArgs[++i]);
                    break;
                case "--http-addr" when i + 1 < flatArgs.Count:
                    config.Http.Addr = flatArgs[++i];
                    break;
                case "--http-ttl" when i + 1 < flatArgs.Count:
                    config.Http.TtlSec = int.Parse(flatArgs[++i]);
                    break;
                case "--archive-dir" when i + 1 < flatArgs.Count:
                    config.Archive.Dir = flatArgs[++i];
                    break;
                case "--archive-retention" when i + 1 < flatArgs.Count:
                    config.Archive.RetentionDays = int.Parse(flatArgs[++i]);
                    break;
            }
        }

        return config;
    }

    internal static void ApplyArgsToConfig(Config config, string[] args)
    {
        var flatArgs = FlattenEqArgs(args);

        for (int i = 0; i < flatArgs.Count; i++)
        {
            switch (flatArgs[i])
            {
                case "--server-uid" when i + 1 < flatArgs.Count:
                    config.Server.Uid = long.Parse(flatArgs[++i]);
                    break;
                case "--server-callsign" when i + 1 < flatArgs.Count:
                    config.Server.Callsign = flatArgs[++i];
                    break;
                case "--mqtt-host" when i + 1 < flatArgs.Count:
                    config.Mqtt.Host = flatArgs[++i];
                    break;
                case "--mqtt-port" when i + 1 < flatArgs.Count:
                    config.Mqtt.Port = int.Parse(flatArgs[++i]);
                    break;
                case "--allow-issuer-sn" when i + 1 < flatArgs.Count:
                    config.Trust.AllowIssuerSn = ParseIssuerSn(flatArgs[++i]);
                    break;
                case "--roots-dir" when i + 1 < flatArgs.Count:
                    config.Trust.RootsDir = flatArgs[++i];
                    break;
                case "--issuer-sn" when i + 1 < flatArgs.Count:
                    config.Server.IssuerSn = long.Parse(flatArgs[++i]);
                    break;
                case "--cert-fingerprint" when i + 1 < flatArgs.Count:
                    config.Server.CertFingerprint = flatArgs[++i];
                    break;
                case "--crl-refresh" when i + 1 < flatArgs.Count:
                    config.Crl.RefreshSec = int.Parse(flatArgs[++i]);
                    break;
                case "--crl-mode" when i + 1 < flatArgs.Count:
                    config.Crl.Mode = flatArgs[++i];
                    break;
                case "--log-level" when i + 1 < flatArgs.Count:
                    config.Log.Level = flatArgs[++i];
                    break;
                case "--http-port" when i + 1 < flatArgs.Count:
                    config.Http.Port = int.Parse(flatArgs[++i]);
                    break;
                case "--http-addr" when i + 1 < flatArgs.Count:
                    config.Http.Addr = flatArgs[++i];
                    break;
                case "--http-ttl" when i + 1 < flatArgs.Count:
                    config.Http.TtlSec = int.Parse(flatArgs[++i]);
                    break;
                case "--archive-dir" when i + 1 < flatArgs.Count:
                    config.Archive.Dir = flatArgs[++i];
                    break;
                case "--archive-retention" when i + 1 < flatArgs.Count:
                    config.Archive.RetentionDays = int.Parse(flatArgs[++i]);
                    break;
            }
        }
    }

    internal static long[] ParseIssuerSn(string value) =>
        value
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(long.Parse)
            .ToArray();

    /// <summary>
    /// Strips the SemVer build metadata ("+sha") before parsing, so
    /// "1.0.7+abc" compares as 1.0.7.
    /// </summary>
    internal static bool TryParseCleanVersion(string version, [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out Version? result)
    {
        var idx = version.IndexOf('+');
        return Version.TryParse(idx >= 0 ? version[..idx] : version, out result);
    }

    internal static bool IsRunningInDocker()
    {
        return Environment.GetEnvironmentVariable("DOTNET_RUNNING_IN_CONTAINER") == "true"
               || File.Exists("/.dockerenv");
    }

    /// <summary>
    /// Validates required settings and returns human-readable problems.
    /// An empty list means the configuration is usable.
    /// </summary>
    internal static IReadOnlyList<string> FindMissing(Config cfg)
    {
        var missing = new List<string>();

        if (cfg.Server.Uid == 0)
            missing.Add("  server.uid             (required) Server UID");
        if (string.IsNullOrWhiteSpace(cfg.Server.Callsign))
            missing.Add("  server.callsign        (required) Server callsign");
        if (string.IsNullOrWhiteSpace(cfg.Mqtt.Host))
            missing.Add("  mqtt.host              (required) MQTT broker hostname");
        if (string.IsNullOrWhiteSpace(cfg.Server.CertFingerprint))
            missing.Add("  server.certFingerprint (required) Server UserCert fingerprint");
        else if (!IsValidFingerprint(cfg.Server.CertFingerprint))
            missing.Add("  server.certFingerprint (invalid) expected 43-character base64url of a 32-byte SHA-256");

        if (cfg.Http.Port <= 0)
            missing.Add("  http.port              (required) HTTP listen port");
        if (cfg.Http.MaxBodyBytes <= 0)
            missing.Add("  http.maxBodyBytes      (required) must be > 0, e.g. 65536");
        if (cfg.Http.MaxConcurrent <= 0)
            missing.Add("  http.maxConcurrent     (required) must be > 0, e.g. 128");

        return missing;
    }

    internal static bool IsValidFingerprint(string value)
    {
        try
        {
            return Sas.certs.Base64Url.Decode(value).Length == 32;
        }
        catch
        {
            return false;
        }
    }
}
