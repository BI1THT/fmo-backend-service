using System.Text.Json;
using Sas.Auth;
using Sas.certs;
using Sas.Tests.Fixtures;
using Sas.Trust;

namespace Sas.Tests.Auth;

/// <summary>
/// End-to-end revocation tests: real Intermediate/Root CRL JSON is written to
/// the production cache layout, loaded by a real <see cref="CrlManager"/>, and
/// then exercised through <see cref="HttpAuthHandler.Process"/>.
/// </summary>
public sealed class HttpAuthHandlerCrlTests
{
    private const string RootCrlUrl = "http://crl.test/root.crl";
    private const string IntermediateCrlUrl = "http://crl.test/int.crl";
    private const long RevokedAt = 1_700_000_000;

    private static byte[] Fingerprint(byte fill) =>
        Enumerable.Repeat(fill, 32).ToArray();

    // ------------------------------------------------------ intermediate CRL

    [Fact]
    public void Process_UserInCachedIntermediateCrl_DeniesWithIssuerFingerprint()
    {
        using var env = new CrlEnv(pki: new TestPkiOptions
        {
            IssuerCrlUrl = IntermediateCrlUrl
        });
        var pki = env.Pki;

        TestCrl.WriteIntermediateCache(env.Temp, pki.Intermediate,
            TestCrl.IntermediateCrlJson(pki, 1,
            [
                (pki.User.Uid, pki.User.Fingerprint(), RevokedAt, TestCrl.ReasonKeyCompromise)
            ]));
        env.Initialize();

        var ex = Assert.Throws<AuthDeniedException>(() => env.ProcessValid());

        Assert.Contains("user revoked", ex.Message);
        Assert.Equal(pki.User.Callsign, ex.BreakerKey);

        var record = env.SingleRecord();
        Assert.Equal("deny", record.GetProperty("result").GetString());
        Assert.Contains("user revoked", record.GetProperty("reason").GetString());
        Assert.Equal(CertBase.FingerprintHex(pki.Root.Fingerprint()), record.GetProperty("rootFp").GetString());
        Assert.Equal(CertBase.FingerprintHex(pki.Intermediate.Fingerprint()), record.GetProperty("issuerFp").GetString());
    }

    [Fact]
    public void Process_UserNotListedInIntermediateCrl_Allows()
    {
        using var env = new CrlEnv(pki: new TestPkiOptions
        {
            IssuerCrlUrl = IntermediateCrlUrl
        });
        var pki = env.Pki;

        TestCrl.WriteIntermediateCache(env.Temp, pki.Intermediate,
            TestCrl.IntermediateCrlJson(pki, 1, []));
        env.Initialize();

        var result = env.ProcessValid();

        Assert.Equal(pki.User.Uid, result.Uid);
    }

    [Fact]
    public void Process_IntermediateCrlWithSameUidButDifferentFingerprint_Allows()
    {
        using var env = new CrlEnv(pki: new TestPkiOptions
        {
            IssuerCrlUrl = IntermediateCrlUrl
        });
        var pki = env.Pki;

        // Revocation must match the certificate fingerprint, not only the uid.
        TestCrl.WriteIntermediateCache(env.Temp, pki.Intermediate,
            TestCrl.IntermediateCrlJson(pki, 1,
            [
                (pki.User.Uid, Fingerprint(0xFF), RevokedAt, TestCrl.ReasonKeyCompromise)
            ]));
        env.Initialize();

        var result = env.ProcessValid();

        Assert.Equal(pki.User.Uid, result.Uid);
    }

    [Fact]
    public void Process_OtherIntermediateCrl_DoesNotRevokeUser()
    {
        using var env = new CrlEnv(pki: new TestPkiOptions
        {
            IssuerCrlUrl = IntermediateCrlUrl
        });
        var pki = env.Pki;

        // A second CA below the same Root lists this user. Only the CA that
        // actually issued the user certificate may revoke it.
        var other = TestPki.CreateWithRoot(pki, new TestPkiOptions
        {
            Seed = 20,
            IssuerSn = 1002,
            IssuerCrlUrl = "http://crl.test/other.crl",
            UserCallsign = "BG6AAA",
            UserUid = 60001
        });

        TestCrl.WriteIntermediateCache(env.Temp, pki.Intermediate,
            TestCrl.IntermediateCrlJson(pki, 1, []));
        TestCrl.WriteIntermediateCache(env.Temp, other.Intermediate,
            TestCrl.IntermediateCrlJson(other, 1,
            [
                (pki.User.Uid, pki.User.Fingerprint(), RevokedAt, TestCrl.ReasonKeyCompromise)
            ]));
        env.Initialize();
        env.Crl.RegisterIntermediate(other.Intermediate);

        var result = env.ProcessValid();

        Assert.Equal(pki.User.Uid, result.Uid);
    }

    [Fact]
    public void Process_IntermediateWithSameSnButDifferentFingerprint_DoesNotShareCrl()
    {
        using var env = new CrlEnv(pki: new TestPkiOptions
        {
            IssuerSn = 1001,
            IssuerCrlUrl = IntermediateCrlUrl
        });
        var pki = env.Pki;

        // Same root, same SN, same display name, different key/fingerprint.
        var twin = TestPki.CreateWithRoot(pki, new TestPkiOptions
        {
            Seed = 30,
            IssuerSn = 1001,
            IssuerName = pki.Intermediate.SubjectName,
            IssuerCrlUrl = "http://crl.test/twin.crl",
            UserCallsign = "BG6AAA",
            UserUid = 60001
        });

        Assert.Equal(pki.Intermediate.Sn, twin.Intermediate.Sn);
        Assert.NotEqual(CertBase.FingerprintHex(pki.Intermediate.Fingerprint()),
            CertBase.FingerprintHex(twin.Intermediate.Fingerprint()));

        TestCrl.WriteIntermediateCache(env.Temp, pki.Intermediate,
            TestCrl.IntermediateCrlJson(pki, 1, []));
        TestCrl.WriteIntermediateCache(env.Temp, twin.Intermediate,
            TestCrl.IntermediateCrlJson(twin, 1,
            [
                (pki.User.Uid, pki.User.Fingerprint(), RevokedAt, TestCrl.ReasonKeyCompromise)
            ]));
        env.Initialize();
        env.Crl.RegisterIntermediate(twin.Intermediate);

        var result = env.ProcessValid();

        Assert.Equal(pki.User.Uid, result.Uid);
    }

    [Fact]
    public void Process_CorruptIntermediateCrlCache_DoesNotDeny()
    {
        using var env = new CrlEnv(pki: new TestPkiOptions
        {
            IssuerCrlUrl = IntermediateCrlUrl
        });

        TestCrl.WriteIntermediateCache(env.Temp, env.Pki.Intermediate, "{not json");
        env.Initialize();

        var result = env.ProcessValid();

        Assert.Equal(env.Pki.User.Uid, result.Uid);
    }

    [Fact]
    public void Process_IntermediateCrlSignedByAnotherCa_IsNotTrusted()
    {
        using var env = new CrlEnv(pki: new TestPkiOptions
        {
            IssuerCrlUrl = IntermediateCrlUrl
        });
        var pki = env.Pki;
        var attacker = TestPki.Create(new TestPkiOptions { Seed = 90 });

        // The payload names the real user but is signed by an unrelated CA.
        TestCrl.WriteIntermediateCache(env.Temp, pki.Intermediate,
            TestCrl.IntermediateCrlJson(attacker, 1,
            [
                (pki.User.Uid, pki.User.Fingerprint(), RevokedAt, TestCrl.ReasonKeyCompromise)
            ]));
        env.Initialize();

        var result = env.ProcessValid();

        Assert.Equal(pki.User.Uid, result.Uid);
    }

    [Fact]
    public void Process_WithLoadedCrlCache_DoesNotFetch()
    {
        // Keep background refresh enabled so the assertion proves the cache hit
        // actually suppressed the request; the root has no CRL URL, so the
        // initialize-time refresh does not fetch anything either.
        var http = FakeHttpMessageHandler.Json("{}");
        using var env = new CrlEnv(
            pki: new TestPkiOptions { IssuerCrlUrl = IntermediateCrlUrl },
            http: http,
            refreshSec: 3600);

        TestCrl.WriteIntermediateCache(env.Temp, env.Pki.Intermediate,
            TestCrl.IntermediateCrlJson(env.Pki, 1, []));
        env.Initialize();

        env.ProcessValid();

        Assert.Equal(0, http.CallCount);
    }

    // -------------------------------------------------------------- root CRL

    [Fact]
    public void Process_IntermediateRevokedByRootCrl_Denies()
    {
        using var env = new CrlEnv(pki: new TestPkiOptions
        {
            RootCrlUrl = RootCrlUrl,
            IssuerCrlUrl = IntermediateCrlUrl
        });
        var pki = env.Pki;

        TestCrl.WriteRootCache(env.Temp, pki.Root,
            TestCrl.RootCrlJson(pki, 1,
            [
                (pki.Intermediate.Sn, pki.Intermediate.Fingerprint(),
                    RevokedAt, TestCrl.ReasonKeyCompromise)
            ]));
        TestCrl.WriteIntermediateCache(env.Temp, pki.Intermediate,
            TestCrl.IntermediateCrlJson(pki, 1, []));
        env.Initialize();

        var ex = Assert.Throws<AuthDeniedException>(() => env.ProcessValid());

        Assert.Contains("intermediate revoked", ex.Message);

        var record = env.SingleRecord();
        Assert.Equal("deny", record.GetProperty("result").GetString());
    }

    // --------------------------------------------------------- strict/soft CRL

    [Fact]
    public void Process_StrictModeWithUnconfiguredRootCrl_Denies()
    {
        using var env = new CrlEnv(
            configure: c => c.Crl.Mode = "strict",
            pki: new TestPkiOptions { IssuerCrlUrl = IntermediateCrlUrl });

        TestCrl.WriteIntermediateCache(env.Temp, env.Pki.Intermediate,
            TestCrl.IntermediateCrlJson(env.Pki, 1, []));
        env.Initialize();

        var ex = Assert.Throws<AuthDeniedException>(() => env.ProcessValid());

        Assert.Contains("CRL unavailable", ex.Message);
        Assert.Contains("NotConfigured", ex.Message);
    }

    [Fact]
    public void Process_StrictModeWithStaleIntermediateCrl_Denies()
    {
        using var env = new CrlEnv(
            configure: c => c.Crl.Mode = "strict",
            pki: new TestPkiOptions
            {
                RootCrlUrl = RootCrlUrl,
                IssuerCrlUrl = IntermediateCrlUrl
            },
            now: DateTimeOffset.FromUnixTimeSeconds(1_700_000_101));

        TestCrl.WriteRootCache(env.Temp, env.Pki.Root,
            TestCrl.RootCrlJson(env.Pki, 1, [], nextUpdate: 1_800_000_000));
        TestCrl.WriteIntermediateCache(env.Temp, env.Pki.Intermediate,
            TestCrl.IntermediateCrlJson(env.Pki, 1, [], nextUpdate: 1_700_000_100));
        env.Initialize();

        var ex = Assert.Throws<AuthDeniedException>(() => env.ProcessValid());

        Assert.Contains("CRL unavailable", ex.Message);
        Assert.Contains("Stale", ex.Message);
    }

    [Fact]
    public void Process_SoftModeWithStaleIntermediateCrl_Allows()
    {
        using var env = new CrlEnv(
            configure: c => c.Crl.Mode = "soft",
            pki: new TestPkiOptions
            {
                RootCrlUrl = RootCrlUrl,
                IssuerCrlUrl = IntermediateCrlUrl
            },
            now: DateTimeOffset.FromUnixTimeSeconds(1_700_000_101));

        TestCrl.WriteRootCache(env.Temp, env.Pki.Root,
            TestCrl.RootCrlJson(env.Pki, 1, [], nextUpdate: 1_800_000_000));
        TestCrl.WriteIntermediateCache(env.Temp, env.Pki.Intermediate,
            TestCrl.IntermediateCrlJson(env.Pki, 1, [], nextUpdate: 1_700_000_100));
        env.Initialize();

        var result = env.ProcessValid();

        Assert.Equal(env.Pki.User.Uid, result.Uid);
    }

    [Fact]
    public void Process_SoftModeWithColdIntermediateCache_Allows()
    {
        // Known fail-soft behaviour: the first login for an Intermediate whose
        // CRL is not cached yet starts a background fetch and proceeds. Only
        // strict mode closes this window.
        using var env = new CrlEnv(pki: new TestPkiOptions
        {
            IssuerCrlUrl = IntermediateCrlUrl
        });
        env.Initialize();

        var result = env.ProcessValid();

        Assert.Equal(env.Pki.User.Uid, result.Uid);
    }

    [Fact]
    public void Process_StrictModeWithColdIntermediateCache_Denies()
    {
        using var env = new CrlEnv(
            configure: c => c.Crl.Mode = "strict",
            pki: new TestPkiOptions
            {
                RootCrlUrl = RootCrlUrl,
                IssuerCrlUrl = IntermediateCrlUrl
            });
        TestCrl.WriteRootCache(env.Temp, env.Pki.Root,
            TestCrl.RootCrlJson(env.Pki, 1, [], nextUpdate: 1_800_000_000));
        env.Initialize();

        var ex = Assert.Throws<AuthDeniedException>(() => env.ProcessValid());

        Assert.Contains("CRL unavailable", ex.Message);
    }

    // ------------------------------------------------------------------ fixture

    private sealed class CrlEnv : IDisposable
    {
        public AuthTestEnvironment Auth { get; }
        public CrlManager Crl => (CrlManager)Auth.CrlPolicy;

        public CrlEnv(
            Action<Config>? configure = null,
            TestPkiOptions? pki = null,
            DateTimeOffset? now = null,
            FakeHttpMessageHandler? http = null,
            int refreshSec = -1)
        {
            Auth = new AuthTestEnvironment(configure, pki, now,
                rootsDir => new CrlManager(rootsDir, refreshSec: refreshSec,
                    (http ?? FakeHttpMessageHandler.NotFound()).CreateClient()));
        }

        public TempDirectory Temp => Auth.Temp;

        public TestPki Pki => Auth.Pki;

        public long Now => Auth.Now;

        public AuthResult ProcessValid() => Auth.ProcessValid();

        public void Initialize() => Crl.Initialize([Auth.Pki.Root]);

        public JsonElement SingleRecord()
        {
            Auth.Archive.Flush();
            return Assert.Single(ArchiveProbe.ReadAll(Auth.Config.Archive.Dir));
        }

        public void Dispose() => Auth.Dispose();
    }
}
