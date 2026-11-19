using Sas;
using Sas.Cli;

namespace Sas.Tests.Cli;

/// <summary>
/// Unit tests for <see cref="ConfigParser"/>.
/// Marked with the GlobalState collection because both <see cref="Config.ConfigPath"/>
/// and <see cref="ConfigParser.IsRunningInDocker"/> depend on process-wide state
/// (a static field and environment variables respectively).
/// </summary>
[Collection("GlobalState")]
public class ConfigParserTests
{
    public ConfigParserTests()
    {
        Config.ConfigPath = "";
    }

    // ──────────────────────────────────────────────────────────────
    // FlattenEqArgs
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public void FlattenEqArgs_EmptyArray_ReturnsEmptyList()
    {
        var result = ConfigParser.FlattenEqArgs([]);

        Assert.Empty(result);
    }

    [Fact]
    public void FlattenEqArgs_SeparateTokens_AreReturnedUnchanged()
    {
        var result = ConfigParser.FlattenEqArgs(["--a", "1"]);

        Assert.Equal(["--a", "1"], result.ToArray());
    }

    [Fact]
    public void FlattenEqArgs_EqualsForm_IsSplitIntoTokens()
    {
        var result = ConfigParser.FlattenEqArgs(["--a=1"]);

        Assert.Equal(["--a", "1"], result.ToArray());
    }

    [Fact]
    public void FlattenEqArgs_EqualsInValue_SplitsOnlyAtFirstEquals()
    {
        var result = ConfigParser.FlattenEqArgs(["--a=1=2"]);

        Assert.Equal(["--a", "1=2"], result.ToArray());
    }

    [Fact]
    public void FlattenEqArgs_NonOptionTokens_AreReturnedUnchanged()
    {
        var result = ConfigParser.FlattenEqArgs(["plain", "-x"]);

        Assert.Equal(["plain", "-x"], result.ToArray());
    }

    // ──────────────────────────────────────────────────────────────
    // ExtractConfigArg
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public void ExtractConfigArg_NoConfigOption_ReturnsNull()
    {
        var result = ConfigParser.ExtractConfigArg(["--server-uid", "1"]);

        Assert.Null(result);
    }

    [Fact]
    public void ExtractConfigArg_ConfigWithValue_ReturnsValue()
    {
        var result = ConfigParser.ExtractConfigArg(["--config", "/tmp/x"]);

        Assert.Equal("/tmp/x", result);
    }

    [Fact]
    public void ExtractConfigArg_ConfigAtEndWithoutValue_ReturnsNull()
    {
        var result = ConfigParser.ExtractConfigArg(["--server-uid", "1", "--config"]);

        Assert.Null(result);
    }

    [Fact]
    public void ExtractConfigArg_MultipleConfigOptions_ReturnsFirst()
    {
        var result = ConfigParser.ExtractConfigArg(["--config", "/tmp/first", "--config", "/tmp/second"]);

        Assert.Equal("/tmp/first", result);
    }

    [Fact]
    public void ExtractConfigArg_EqualsFormAfterFlattening_ReturnsValue()
    {
        var flat = ConfigParser.FlattenEqArgs(["--config=/tmp/eq"]);

        Assert.Equal("/tmp/eq", ConfigParser.ExtractConfigArg(flat));
    }

    // ──────────────────────────────────────────────────────────────
    // HasInitArgsBeyondConfig
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public void HasInitArgsBeyondConfig_OnlyConfig_ReturnsFalse()
    {
        Assert.False(ConfigParser.HasInitArgsBeyondConfig(["--config", "/tmp/x"]));
    }

    [Fact]
    public void HasInitArgsBeyondConfig_WithServerUid_ReturnsTrue()
    {
        Assert.True(ConfigParser.HasInitArgsBeyondConfig(["--server-uid", "1"]));
    }

    [Fact]
    public void HasInitArgsBeyondConfig_WithHttpPort_ReturnsTrue()
    {
        Assert.True(ConfigParser.HasInitArgsBeyondConfig(["--http-port", "8080"]));
    }

    [Fact]
    public void HasInitArgsBeyondConfig_EmptyList_ReturnsFalse()
    {
        Assert.False(ConfigParser.HasInitArgsBeyondConfig([]));
    }

    // ──────────────────────────────────────────────────────────────
    // BuildFromArgs
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public void BuildFromArgs_AllOptions_MapToConfigProperties()
    {
        var config = ConfigParser.BuildFromArgs([
            "--server-uid", "12345",
            "--server-callsign", "BG5ESN",
            "--mqtt-host", "mqtt.example.test",
            "--mqtt-port", "1884",
            "--cert-fingerprint", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "--issuer-sn", "2001",
            "--allow-issuer-sn", "1001,2001",
            "--roots-dir", "/data/roots",
            "--crl-refresh", "600",
            "--crl-mode", "strict",
            "--log-level", "Debug",
            "--http-port", "9090",
            "--http-addr", "127.0.0.1",
            "--http-ttl", "300",
            "--archive-dir", "/data/archive",
            "--archive-retention", "7"
        ]);

        Assert.Equal(12345, config.Server.Uid);
        Assert.Equal("BG5ESN", config.Server.Callsign);
        Assert.Equal(2001, config.Server.IssuerSn);
        Assert.Equal("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", config.Server.CertFingerprint);

        Assert.Equal("mqtt.example.test", config.Mqtt.Host);
        Assert.Equal(1884, config.Mqtt.Port);

        Assert.Equal([1001L, 2001L], config.Trust.AllowIssuerSn);
        Assert.Equal("/data/roots", config.Trust.RootsDir);

        Assert.Equal(600, config.Crl.RefreshSec);
        Assert.Equal("strict", config.Crl.Mode);
        Assert.Equal("Debug", config.Log.Level);

        Assert.Equal(9090, config.Http.Port);
        Assert.Equal("127.0.0.1", config.Http.Addr);
        Assert.Equal(300, config.Http.TtlSec);

        Assert.Equal("/data/archive", config.Archive.Dir);
        Assert.Equal(7, config.Archive.RetentionDays);

        // Untouched defaults survive.
        Assert.Equal(65536, config.Http.MaxBodyBytes);
        Assert.Equal(128, config.Http.MaxConcurrent);
    }

    [Fact]
    public void BuildFromArgs_AllowIssuerSnWithSpaces_ParsesTrimmedList()
    {
        var config = ConfigParser.BuildFromArgs(["--allow-issuer-sn", "1001, 2001"]);

        Assert.Equal([1001L, 2001L], config.Trust.AllowIssuerSn);
    }

    [Fact]
    public void BuildFromArgs_AllowIssuerSnEmptyString_YieldsEmptyArray()
    {
        var config = ConfigParser.BuildFromArgs(["--allow-issuer-sn", ""]);

        Assert.Empty(config.Trust.AllowIssuerSn);
    }

    [Fact]
    public void BuildFromArgs_DuplicateOption_LastOneWins()
    {
        var config = ConfigParser.BuildFromArgs(["--server-uid", "1", "--server-uid", "2"]);

        Assert.Equal(2, config.Server.Uid);
    }

    [Fact]
    public void BuildFromArgs_OptionWithoutValue_IsIgnoredWithoutThrowing()
    {
        var config = ConfigParser.BuildFromArgs(["--server-uid"]);

        Assert.Equal(0, config.Server.Uid);
    }

    [Fact]
    public void BuildFromArgs_NonNumericHttpPort_ThrowsFormatException()
    {
        Assert.Throws<FormatException>(() => ConfigParser.BuildFromArgs(["--http-port", "abc"]));
    }

    [Fact]
    public void BuildFromArgs_NonNumericServerUid_ThrowsFormatException()
    {
        Assert.Throws<FormatException>(() => ConfigParser.BuildFromArgs(["--server-uid", "not-a-number"]));
    }

    [Fact]
    public void BuildFromArgs_ConfigEqualsForm_SetsStaticConfigPath()
    {
        try
        {
            ConfigParser.BuildFromArgs(["--config=/tmp/path/config.json"]);

            Assert.Equal("/tmp/path/config.json", Config.ConfigPath);
        }
        finally
        {
            Config.ConfigPath = "";
        }
    }

    [Fact]
    public void BuildFromArgs_ConfigSeparateForm_SetsStaticConfigPath()
    {
        try
        {
            ConfigParser.BuildFromArgs(["--config", "/tmp/other/config.json"]);

            Assert.Equal("/tmp/other/config.json", Config.ConfigPath);
        }
        finally
        {
            Config.ConfigPath = "";
        }
    }

    // ──────────────────────────────────────────────────────────────
    // ApplyArgsToConfig
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public void ApplyArgsToConfig_OverridesOnlySpecifiedFields()
    {
        var config = new Config
        {
            Server = { Uid = 1, Callsign = "OLD", CertFingerprint = "OLD-FP", IssuerSn = 11 },
            Mqtt = { Host = "old.host", Port = 1883 },
            Trust = { RootsDir = "/old/roots", AllowIssuerSn = [7] },
            Crl = { RefreshSec = 14400 },
            Log = { Level = "Info" },
            Http = { Port = 8080, Addr = "0.0.0.0", TtlSec = 14400 },
            Archive = { Dir = "/old/archive", RetentionDays = 30 }
        };

        ConfigParser.ApplyArgsToConfig(config, ["--server-uid", "2", "--http-port", "9090"]);

        // Overridden.
        Assert.Equal(2, config.Server.Uid);
        Assert.Equal(9090, config.Http.Port);

        // Preserved.
        Assert.Equal("OLD", config.Server.Callsign);
        Assert.Equal("OLD-FP", config.Server.CertFingerprint);
        Assert.Equal(11, config.Server.IssuerSn);
        Assert.Equal("old.host", config.Mqtt.Host);
        Assert.Equal(1883, config.Mqtt.Port);
        Assert.Equal("/old/roots", config.Trust.RootsDir);
        Assert.Equal([7L], config.Trust.AllowIssuerSn);
        Assert.Equal(14400, config.Crl.RefreshSec);
        Assert.Equal("Info", config.Log.Level);
        Assert.Equal("0.0.0.0", config.Http.Addr);
        Assert.Equal(14400, config.Http.TtlSec);
        Assert.Equal("/old/archive", config.Archive.Dir);
        Assert.Equal(30, config.Archive.RetentionDays);
    }

    [Fact]
    public void ApplyArgsToConfig_EmptyArgs_LeavesConfigUntouched()
    {
        var config = new Config();
        config.Server.Uid = 42;
        config.Mqtt.Host = "keep.me";

        ConfigParser.ApplyArgsToConfig(config, []);

        Assert.Equal(42, config.Server.Uid);
        Assert.Equal("keep.me", config.Mqtt.Host);
    }

    [Fact]
    public void ApplyArgsToConfig_InvalidNumber_ThrowsFormatException()
    {
        Assert.Throws<FormatException>(
            () => ConfigParser.ApplyArgsToConfig(new Config(), ["--http-port", "abc"]));
    }

    // ──────────────────────────────────────────────────────────────
    // ParseIssuerSn
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public void ParseIssuerSn_CommaSeparated_ParsesEachEntry()
    {
        Assert.Equal([1001L, 2001L], ConfigParser.ParseIssuerSn("1001,2001"));
    }

    [Fact]
    public void ParseIssuerSn_WithSurroundingSpaces_TrimsEntries()
    {
        Assert.Equal([1001L, 2001L], ConfigParser.ParseIssuerSn(" 1001 , 2001 "));
    }

    [Fact]
    public void ParseIssuerSn_EmptyString_ReturnsEmptyArray()
    {
        Assert.Empty(ConfigParser.ParseIssuerSn(""));
    }

    [Fact]
    public void ParseIssuerSn_InvalidValue_ThrowsFormatException()
    {
        Assert.Throws<FormatException>(() => ConfigParser.ParseIssuerSn("1001,abc"));
    }

    // ──────────────────────────────────────────────────────────────
    // TryParseCleanVersion
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public void TryParseCleanVersion_PlainVersion_Parses()
    {
        Assert.True(ConfigParser.TryParseCleanVersion("1.0.7", out var result));
        Assert.Equal(new Version(1, 0, 7), result);
    }

    [Fact]
    public void TryParseCleanVersion_WithBuildMetadata_StripsSuffix()
    {
        Assert.True(ConfigParser.TryParseCleanVersion("1.0.7+abcdef", out var result));
        Assert.Equal(new Version(1, 0, 7), result);
    }

    [Fact]
    public void TryParseCleanVersion_Unknown_ReturnsFalseAndNull()
    {
        Assert.False(ConfigParser.TryParseCleanVersion("unknown", out var result));
        Assert.Null(result);
    }

    [Fact]
    public void TryParseCleanVersion_PrefixedWithV_ReturnsFalse()
    {
        Assert.False(ConfigParser.TryParseCleanVersion("v1.0", out var result));
        Assert.Null(result);
    }

    [Fact]
    public void TryParseCleanVersion_TwoComponents_ParsesWithMinusOneBuild()
    {
        Assert.True(ConfigParser.TryParseCleanVersion("1.0", out var result));
        Assert.NotNull(result);
        Assert.Equal(1, result!.Major);
        Assert.Equal(0, result.Minor);
        Assert.Equal(-1, result.Build);
        Assert.Equal(-1, result.Revision);
    }

    // ──────────────────────────────────────────────────────────────
    // FindMissing
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public void FindMissing_DefaultNewConfig_ReportsFourMissing()
    {
        // Behaviour note: `new Config()` already ships non-zero HTTP defaults
        // (port 8080, maxBodyBytes 65536, maxConcurrent 128), so only the four
        // identity/broker fields are reported as missing.
        var missing = ConfigParser.FindMissing(new Config());

        Assert.Equal(4, missing.Count);
        Assert.Contains("server.uid", string.Join("\n", missing));
        Assert.Contains("server.callsign", string.Join("\n", missing));
        Assert.Contains("mqtt.host", string.Join("\n", missing));
        Assert.Contains("server.certFingerprint", string.Join("\n", missing));
    }

    [Fact]
    public void FindMissing_FullyEmptyConfig_ReportsSevenMissing()
    {
        var missing = ConfigParser.FindMissing(CreateFullyEmptyConfig());

        Assert.Equal(7, missing.Count);

        var joined = string.Join("\n", missing);
        Assert.Contains("server.uid", joined);
        Assert.Contains("server.callsign", joined);
        Assert.Contains("mqtt.host", joined);
        Assert.Contains("server.certFingerprint", joined);
        Assert.Contains("http.port", joined);
        Assert.Contains("http.maxBodyBytes", joined);
        Assert.Contains("http.maxConcurrent", joined);
    }

    [Fact]
    public void FindMissing_FillingRequiredFields_ReducesMissingCount()
    {
        var config = CreateFullyEmptyConfig();
        Assert.Equal(7, ConfigParser.FindMissing(config).Count);

        config.Server.Uid = 5001;
        Assert.Equal(6, ConfigParser.FindMissing(config).Count);

        config.Server.Callsign = "BG5ESN";
        Assert.Equal(5, ConfigParser.FindMissing(config).Count);

        config.Mqtt.Host = "mqtt.example.test";
        Assert.Equal(4, ConfigParser.FindMissing(config).Count);

        config.Server.CertFingerprint = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        Assert.Equal(3, ConfigParser.FindMissing(config).Count);

        config.Http.Port = 8080;
        Assert.Equal(2, ConfigParser.FindMissing(config).Count);

        config.Http.MaxBodyBytes = 65536;
        Assert.Single(ConfigParser.FindMissing(config));

        config.Http.MaxConcurrent = 128;
        Assert.Empty(ConfigParser.FindMissing(config));
    }

    [Fact]
    public void FindMissing_AllConfigured_ReturnsEmptyList()
    {
        var config = CreateFullyEmptyConfig();
        config.Server.Uid = 5001;
        config.Server.Callsign = "BG5ESN";
        config.Server.CertFingerprint = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        config.Mqtt.Host = "mqtt.example.test";
        config.Http.Port = 8080;
        config.Http.MaxBodyBytes = 65536;
        config.Http.MaxConcurrent = 128;

        Assert.Empty(ConfigParser.FindMissing(config));
    }

    [Theory]
    [InlineData("!!!")]                                           // not base64url
    [InlineData("abc")]                                           // decodes to 2 bytes
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]    // 42 chars -> 31 bytes
    [InlineData("***************************************************")]
    public void FindMissing_MalformedFingerprint_IsReported(string fingerprint)
    {
        var config = CreateFullyEmptyConfig();
        config.Server.Uid = 5001;
        config.Server.Callsign = "BG5ESN";
        config.Server.CertFingerprint = fingerprint;
        config.Mqtt.Host = "mqtt.example.test";
        config.Http.Port = 8080;
        config.Http.MaxBodyBytes = 65536;
        config.Http.MaxConcurrent = 128;

        var missing = ConfigParser.FindMissing(config);

        var entry = Assert.Single(missing);
        Assert.Contains("server.certFingerprint", entry);
        Assert.Contains("invalid", entry);
    }

    [Fact]
    public void FindMissing_WellFormedFingerprint_IsAccepted()
    {
        var config = CreateFullyEmptyConfig();
        config.Server.Uid = 5001;
        config.Server.Callsign = "BG5ESN";
        config.Server.CertFingerprint = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        config.Mqtt.Host = "mqtt.example.test";
        config.Http.Port = 8080;
        config.Http.MaxBodyBytes = 65536;
        config.Http.MaxConcurrent = 128;

        Assert.Empty(ConfigParser.FindMissing(config));
        Assert.True(ConfigParser.IsValidFingerprint(config.Server.CertFingerprint));
    }

    // ──────────────────────────────────────────────────────────────
    // IsRunningInDocker
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public void IsRunningInDocker_EnvVarTrue_ReturnsTrue()
    {
        const string name = "DOTNET_RUNNING_IN_CONTAINER";
        var original = Environment.GetEnvironmentVariable(name);
        try
        {
            Environment.SetEnvironmentVariable(name, "true");

            Assert.True(ConfigParser.IsRunningInDocker());
        }
        finally
        {
            Environment.SetEnvironmentVariable(name, original);
        }
    }

    [Fact]
    public void IsRunningInDocker_EnvVarFalse_ReturnsFalse()
    {
        const string name = "DOTNET_RUNNING_IN_CONTAINER";
        var original = Environment.GetEnvironmentVariable(name);
        try
        {
            Environment.SetEnvironmentVariable(name, "false");

            Assert.False(ConfigParser.IsRunningInDocker());
        }
        finally
        {
            Environment.SetEnvironmentVariable(name, original);
        }
    }

    // ──────────────────────────────────────────────────────────────
    // Helpers
    // ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Produces a config whose required HTTP numeric fields are all zero,
    /// i.e. the state produced by deserialising a file that omits them.
    /// </summary>
    private static Config CreateFullyEmptyConfig()
    {
        var config = new Config();
        config.Http.Port = 0;
        config.Http.MaxBodyBytes = 0;
        config.Http.MaxConcurrent = 0;
        return config;
    }
}
