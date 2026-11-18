namespace Sas.Tests.Fixtures;

internal static class TestConfig
{
    public const long DefaultServerUid = 5001;
    public const string DefaultCallsign = "BG5ESN";
    public const string DefaultMqttHost = "fmo.example.test";
    public const int DefaultMqttPort = 1883;

    public static Config Create(
        string rootsDir,
        string archiveDir,
        long serverUid = DefaultServerUid,
        string callsign = DefaultCallsign,
        string mqttHost = DefaultMqttHost,
        int mqttPort = DefaultMqttPort,
        string? serverFingerprint = null,
        int ttlSec = 14400)
    {
        var config = new Config();
        config.Server.Uid = serverUid;
        config.Server.Callsign = callsign;
        config.Server.CertFingerprint = serverFingerprint ?? TestPki.RandomFingerprint(0xAB);
        config.Server.Admins = [];

        config.Mqtt.Host = mqttHost;
        config.Mqtt.Port = mqttPort;
        config.Mqtt.Clusters = [];

        config.Trust.RootsDir = rootsDir;
        config.Trust.AllowIssuerSn = [];

        config.Crl.RefreshSec = 0;
        config.Log.Level = "Info";

        config.Http.Addr = "127.0.0.1";
        config.Http.Port = 0;
        config.Http.TtlSec = ttlSec;
        config.Http.MaxBodyBytes = 65536;
        config.Http.MaxPasswordBytes = 32768;
        config.Http.MaxConcurrent = 128;
        config.Http.RateLimit = new Sas.Server.RateLimitConfig();

        config.Update.Enabled = false;

        config.Archive.Enabled = true;
        config.Archive.Dir = archiveDir;
        config.Archive.RecordDenied = true;
        config.Archive.RecordDeniedPayload = false;
        config.Archive.DeniedPayloadSampleRate = 0.0;
        config.Archive.RetentionDays = 30;
        config.Archive.MaxFileBytes = 16 * 1024 * 1024;
        config.Archive.MaxRecordBytes = 16 * 1024;

        return config;
    }
}
