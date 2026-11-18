using Sas.Auth;
using Sas.Logging;
using Sas.Trust;

namespace Sas.Tests.Fixtures;

/// <summary>
/// Wires a real <see cref="HttpAuthHandler"/> against a real Ed25519 chain,
/// real root store, real ACL store and real archive, with only the clock,
/// RNG and revocation policy faked.
/// </summary>
internal sealed class AuthTestEnvironment : IDisposable
{
    public TempDirectory Temp { get; }
    public TestPki Pki { get; }
    public Config Config { get; }
    public FixedTimeProvider Clock { get; }
    public FakeCrlPolicy Crl { get; } = new();
    public RootCaStore RootStore { get; }
    public AclStore Acl { get; }
    public AuthArchive Archive { get; }
    public HttpAuthHandler Handler { get; }
    public string ServerFingerprint { get; }

    public AuthTestEnvironment(
        Action<Config>? configure = null,
        TestPkiOptions? pki = null,
        DateTimeOffset? now = null)
    {
        Temp = new TempDirectory("auth");
        Pki = TestPki.Create(pki);
        Clock = new FixedTimeProvider(now ?? DateTimeOffset.FromUnixTimeSeconds(1_700_000_000));
        ServerFingerprint = TestPki.RandomFingerprint(0xAB);

        var rootsDir = Temp.CreateSubdirectory("roots");
        File.WriteAllText(Path.Combine(rootsDir, "root.json"), Pki.RootJson);

        Config = TestConfig.Create(rootsDir, Temp.Combine("archive"), serverFingerprint: ServerFingerprint);
        configure?.Invoke(Config);

        RootStore = new RootCaStore(rootsDir);
        Acl = new AclStore(Temp.CreateSubdirectory("roles"));
        Archive = new AuthArchive(Config.Archive, Clock);
        Handler = new HttpAuthHandler(Config, RootStore, new CertVerifier(), Crl, Acl, Archive, Clock, new Random(12345));
    }

    public long Now => Clock.GetUtcNow().ToUnixTimeSeconds();

    public string Username => Pki.User.Callsign;

    public long ServerUid => Config.Server.Uid;

    public string ValidPassword(string role = "user") =>
        Pki.BuildPassword(
            Config.Server.Uid,
            Config.Server.Callsign,
            Config.Server.Uid,
            Config.Mqtt.Host,
            Config.Mqtt.Port,
            ServerFingerprint,
            Now,
            role);

    public string ValidPayloadJson(string role = "user") =>
        Pki.BuildPayloadJson(
            Config.Server.Uid,
            Config.Server.Callsign,
            Config.Server.Uid,
            Config.Mqtt.Host,
            Config.Mqtt.Port,
            ServerFingerprint,
            Now,
            role);

    public AuthResult ProcessValid() => Handler.Process(Username, ValidPassword(), "req-test");

    public void Dispose()
    {
        Archive.Flush();
        Temp.Dispose();
    }
}
