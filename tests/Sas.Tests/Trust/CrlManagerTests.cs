using System.Text.Json;
using System.Text.Json.Nodes;
using Sas.certs;
using Sas.Tests.Fixtures;
using Sas.Trust;

namespace Sas.Tests.Trust;

public sealed class CrlManagerTests
{
    private static byte[] Fingerprint(byte fill) => Enumerable.Repeat(fill, 32).ToArray();

    private static string RootCrlJson(TestPki pki, long crlNumber,
        IEnumerable<(long Sn, byte[] Fingerprint, long RevokedAt, int Reason)> entries,
        long nextUpdate = 1_800_000_000)
    {
        var array = new JsonArray();
        foreach (var e in entries)
        {
            array.Add(new JsonObject
            {
                ["sn"] = e.Sn,
                ["certFingerprint"] = Base64Url.Encode(e.Fingerprint),
                ["revokedAt"] = e.RevokedAt,
                ["reason"] = e.Reason
            });
        }

        var draft = new JsonObject
        {
            ["type"] = "rootCRL",
            ["issuerSn"] = pki.Root.Sn,
            ["crlNumber"] = crlNumber,
            ["thisUpdate"] = 1_700_000_000,
            ["nextUpdate"] = nextUpdate,
            ["entries"] = array,
            ["signature"] = Base64Url.Encode(new byte[64])
        };

        var unsigned = RootCrl.FromJson(JsonDocument.Parse(draft.ToJsonString()).RootElement);
        var signature = Ed25519.Sign(pki.RootPrivateKey, unsigned.ToTbsCbor());
        draft["signature"] = Base64Url.Encode(signature);

        return draft.ToJsonString();
    }

    private static string IntermediateCrlJson(TestPki pki, long crlNumber,
        IEnumerable<(long Uid, byte[] Fingerprint, long RevokedAt, int Reason)> entries,
        long nextUpdate = 1_800_000_000)
    {
        var array = new JsonArray();
        foreach (var e in entries)
        {
            array.Add(new JsonObject
            {
                ["uid"] = e.Uid,
                ["certFingerprint"] = Base64Url.Encode(e.Fingerprint),
                ["revokedAt"] = e.RevokedAt,
                ["reason"] = e.Reason
            });
        }

        var draft = new JsonObject
        {
            ["type"] = "intermediateCRL",
            ["issuerSn"] = pki.Intermediate.Sn,
            ["crlNumber"] = crlNumber,
            ["thisUpdate"] = 1_700_000_000,
            ["nextUpdate"] = nextUpdate,
            ["entries"] = array,
            ["signature"] = Base64Url.Encode(new byte[64])
        };

        var unsigned = IntermediateCrl.FromJson(JsonDocument.Parse(draft.ToJsonString()).RootElement);
        var signature = Ed25519.Sign(pki.IntermediatePrivateKey, unsigned.ToTbsCbor());
        draft["signature"] = Base64Url.Encode(signature);

        return draft.ToJsonString();
    }

    private static string RootCacheDirectory(TempDirectory temp, RootCaCert root) =>
        Path.Combine(temp.Path, "crl",
            CrlManager.CacheDirectoryName("root", root.SubjectName, root.Fingerprint()));

    private static string IntermediateCacheDirectory(TempDirectory temp, IntermediateCaCert intermediate) =>
        Path.Combine(temp.Path, "crl",
            CrlManager.CacheDirectoryName("intermediate", intermediate.SubjectName, intermediate.Fingerprint()));

    private static void WriteRootCache(TempDirectory temp, RootCaCert root, string json)
    {
        var dir = RootCacheDirectory(temp, root);
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "root.json"), json);
    }

    private static void WriteIntermediateCache(
        TempDirectory temp, IntermediateCaCert intermediate, string json)
    {
        var dir = IntermediateCacheDirectory(temp, intermediate);
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "intermediate.json"), json);
    }

    [Fact]
    public void Initialize_WithRefreshDisabled_DoesNotFetch()
    {
        using var temp = new TempDirectory("crl");
        var pki = TestPki.Create(new TestPkiOptions { RootCrlUrl = "http://crl.test/root.crl" });
        var http = FakeHttpMessageHandler.NotFound();
        using var manager = new CrlManager(temp.CreateSubdirectory("roots"), refreshSec: -1, http.CreateClient());

        manager.Initialize([pki.Root]);

        Assert.Equal(0, http.CallCount);
    }

    [Fact]
    public void IsRootCrlOutdated_WithNoLoadedCrl_ReturnsFalse()
    {
        using var temp = new TempDirectory("crl");
        var pki = TestPki.Create();
        using var manager = new CrlManager(temp.CreateSubdirectory("roots"), refreshSec: -1);

        manager.Initialize([pki.Root]);

        Assert.False(manager.IsRootCrlOutdated(pki.Root.Fingerprint(), 1_900_000_000));
    }

    [Fact]
    public void Initialize_LoadsValidCachedRootCrl()
    {
        using var temp = new TempDirectory("crl");
        var pki = TestPki.Create();
        WriteRootCache(temp, pki.Root, RootCrlJson(pki, 5, [], nextUpdate: 1_700_000_100));
        using var manager = new CrlManager(temp.CreateSubdirectory("roots"), refreshSec: -1);

        manager.Initialize([pki.Root]);

        Assert.False(manager.IsRootCrlOutdated(pki.Root.Fingerprint(), 1_700_000_000));
        Assert.True(manager.IsRootCrlOutdated(pki.Root.Fingerprint(), 1_700_000_101));
    }

    [Fact]
    public void Initialize_IgnoresCachedRootCrlWithBadSignature()
    {
        using var temp = new TempDirectory("crl");
        var pki = TestPki.Create();
        var other = TestPki.Create(new TestPkiOptions { Seed = 50 });
        WriteRootCache(temp, pki.Root, RootCrlJson(other, 5, [], nextUpdate: 1_700_000_100));
        using var manager = new CrlManager(temp.CreateSubdirectory("roots"), refreshSec: -1);

        manager.Initialize([pki.Root]);

        Assert.False(manager.IsRootCrlOutdated(pki.Root.Fingerprint(), 1_900_000_000));
    }

    [Fact]
    public void Initialize_IgnoresCorruptCachedRootCrl()
    {
        using var temp = new TempDirectory("crl");
        var pki = TestPki.Create();
        WriteRootCache(temp, pki.Root, "{not json");
        using var manager = new CrlManager(temp.CreateSubdirectory("roots"), refreshSec: -1);

        manager.Initialize([pki.Root]);

        Assert.False(manager.IsRootCrlOutdated(pki.Root.Fingerprint(), 1_900_000_000));
    }

    [Fact]
    public void IsIntermediateRevoked_MatchesCachedRootCrlEntry()
    {
        using var temp = new TempDirectory("crl");
        var pki = TestPki.Create();
        var revokedFp = pki.Intermediate.Fingerprint();
        WriteRootCache(temp, pki.Root,
            RootCrlJson(pki, 1, [(pki.Intermediate.Sn, revokedFp, 1_700_000_000, 1)]));
        using var manager = new CrlManager(temp.CreateSubdirectory("roots"), refreshSec: -1);
        manager.Initialize([pki.Root]);

        Assert.True(manager.IsIntermediateRevoked(pki.Root.Fingerprint(), pki.Intermediate.Sn, revokedFp, out var reason));
        Assert.Contains("intermediate CA", reason);
        Assert.False(manager.IsIntermediateRevoked(pki.Root.Fingerprint(), pki.Intermediate.Sn, Fingerprint(0xFF), out _));
    }

    [Fact]
    public void IsIntermediateRevoked_DoesNotUseAnotherRootsCrl()
    {
        using var temp = new TempDirectory("crl");
        var a = TestPki.Create(new TestPkiOptions { Seed = 70, RootSn = 11, IssuerSn = 111 });
        var b = TestPki.Create(new TestPkiOptions { Seed = 80, RootSn = 22, IssuerSn = 222 });
        var bFp = b.Intermediate.Fingerprint();

        // Root A's CRL maliciously lists root B's intermediate. Root B's own
        // CRL is empty.
        WriteRootCache(temp, a.Root,
            RootCrlJson(a, 1, [(b.Intermediate.Sn, bFp, 1_700_000_000, 1)]));
        WriteRootCache(temp, b.Root, RootCrlJson(b, 1, []));

        using var manager = new CrlManager(temp.CreateSubdirectory("roots"), refreshSec: -1);
        manager.Initialize([a.Root, b.Root]);

        Assert.False(manager.IsIntermediateRevoked(
            b.Root.Fingerprint(), b.Intermediate.Sn, bFp, out _));

        // The entry is only visible under the CRL that actually contains it.
        Assert.True(manager.IsIntermediateRevoked(
            a.Root.Fingerprint(), b.Intermediate.Sn, bFp, out var reason));
        Assert.Contains(
            CrlManager.FingerprintKey(a.Root.Fingerprint())[..8], reason);
    }

    [Fact]
    public void IsUserRevoked_DoesNotUseAnotherIntermediatesCrl()
    {
        using var temp = new TempDirectory("crl");
        var a = TestPki.Create(new TestPkiOptions
        {
            Seed = 70,
            RootSn = 11,
            IssuerSn = 111,
            IssuerCrlUrl = "http://crl.test/a.crl"
        });
        var b = TestPki.Create(new TestPkiOptions
        {
            Seed = 80,
            RootSn = 22,
            IssuerSn = 222,
            IssuerCrlUrl = "http://crl.test/b.crl"
        });
        var bUserFp = b.User.Fingerprint();

        // Intermediate A's CRL maliciously lists a user issued by B.
        WriteIntermediateCache(temp, a.Intermediate,
            IntermediateCrlJson(a, 1, [(b.User.Uid, bUserFp, 1_700_000_000, 1)]));
        WriteIntermediateCache(temp, b.Intermediate, IntermediateCrlJson(b, 1, []));

        using var manager = new CrlManager(temp.CreateSubdirectory("roots"), refreshSec: -1);
        manager.Initialize([a.Root, b.Root]);
        manager.RegisterIntermediate(a.Intermediate);
        manager.RegisterIntermediate(b.Intermediate);

        Assert.False(manager.IsUserRevoked(
            b.Intermediate.Fingerprint(), b.User.Uid, bUserFp, out _));

        Assert.True(manager.IsUserRevoked(
            a.Intermediate.Fingerprint(), b.User.Uid, bUserFp, out var reason));
        Assert.Contains(
            CrlManager.FingerprintKey(a.Intermediate.Fingerprint())[..8], reason);
    }

    [Fact]
    public void IsUserRevoked_MatchesCachedIntermediateCrlEntry()
    {
        using var temp = new TempDirectory("crl");
        var pki = TestPki.Create(new TestPkiOptions { IssuerCrlUrl = "http://crl.test/int.crl" });
        var revokedFp = pki.User.Fingerprint();
        WriteIntermediateCache(temp, pki.Intermediate,
            IntermediateCrlJson(pki, 1, [(pki.User.Uid, revokedFp, 1_700_000_000, 1)]));
        using var manager = new CrlManager(temp.CreateSubdirectory("roots"), refreshSec: -1);
        manager.Initialize([pki.Root]);

        manager.RegisterIntermediate(pki.Intermediate);

        Assert.True(manager.IsUserRevoked(pki.Intermediate.Fingerprint(), pki.User.Uid, revokedFp, out var reason));
        Assert.Contains("user cert", reason);
        Assert.False(manager.IsUserRevoked(pki.Intermediate.Fingerprint(), pki.User.Uid, Fingerprint(0xFF), out _));
    }

    [Fact]
    public void RootCrlEntries_DoNotAffectUserRevocation()
    {
        using var temp = new TempDirectory("crl");
        var pki = TestPki.Create();
        var userFp = pki.User.Fingerprint();
        WriteRootCache(temp, pki.Root,
            RootCrlJson(pki, 1, [(pki.User.Uid, userFp, 1_700_000_000, 1)]));
        using var manager = new CrlManager(temp.CreateSubdirectory("roots"), refreshSec: -1);
        manager.Initialize([pki.Root]);

        Assert.False(manager.IsUserRevoked(pki.Intermediate.Fingerprint(), pki.User.Uid, userFp, out _));
    }

    [Fact]
    public void RegisterIntermediate_WithoutCrlUrl_DoesNothing()
    {
        using var temp = new TempDirectory("crl");
        var pki = TestPki.Create();
        var http = FakeHttpMessageHandler.NotFound();
        using var manager = new CrlManager(temp.CreateSubdirectory("roots"), refreshSec: -1, http.CreateClient());
        manager.Initialize([pki.Root]);

        manager.RegisterIntermediate(pki.Intermediate);

        Assert.Equal(0, http.CallCount);
    }

    [Fact]
    public void RegisterIntermediate_WithMissingCache_FetchesOnce()
    {
        using var temp = new TempDirectory("crl");
        var pki = TestPki.Create(new TestPkiOptions { IssuerCrlUrl = "http://crl.test/int.crl" });
        var http = FakeHttpMessageHandler.Json(IntermediateCrlJson(pki, 2, []));
        using var manager = new CrlManager(temp.CreateSubdirectory("roots"), refreshSec: -1, http.CreateClient());
        manager.Initialize([pki.Root]);

        manager.RegisterIntermediate(pki.Intermediate);

        Assert.True(SpinWait.SpinUntil(() => http.CallCount == 1, TimeSpan.FromSeconds(3)));
    }

    [Fact]
    public void RegisterIntermediate_WithValidCache_DoesNotFetch()
    {
        using var temp = new TempDirectory("crl");
        var pki = TestPki.Create(new TestPkiOptions { IssuerCrlUrl = "http://crl.test/int.crl" });
        WriteIntermediateCache(temp, pki.Intermediate,
            IntermediateCrlJson(pki, 1, [(pki.User.Uid, pki.User.Fingerprint(), 1, 1)]));
        var http = FakeHttpMessageHandler.Json(IntermediateCrlJson(pki, 2, []));
        using var manager = new CrlManager(temp.CreateSubdirectory("roots"), refreshSec: -1, http.CreateClient());
        manager.Initialize([pki.Root]);

        manager.RegisterIntermediate(pki.Intermediate);

        Assert.Equal(0, http.CallCount);
        Assert.True(manager.IsUserRevoked(pki.Intermediate.Fingerprint(), pki.User.Uid, pki.User.Fingerprint(), out _));
    }

    [Fact]
    public void IsRootCrlOutdated_ReturnsFalseWhenCrlCoversNow()
    {
        using var temp = new TempDirectory("crl");
        var pki = TestPki.Create();
        WriteRootCache(temp, pki.Root, RootCrlJson(pki, 3, [], nextUpdate: 1_700_003_600));
        using var manager = new CrlManager(temp.CreateSubdirectory("roots"), refreshSec: -1);
        manager.Initialize([pki.Root]);

        Assert.False(manager.IsRootCrlOutdated(pki.Root.Fingerprint(), 1_700_003_600));
        Assert.True(manager.IsRootCrlOutdated(pki.Root.Fingerprint(), 1_700_003_601));
    }

    [Fact]
    public void IsRootCrlOutdated_WithoutCrlForUnknownRoot_ReturnsFalse()
    {
        using var temp = new TempDirectory("crl");
        var pki = TestPki.Create();
        using var manager = new CrlManager(temp.CreateSubdirectory("roots"), refreshSec: -1);
        manager.Initialize([pki.Root]);

        Assert.False(manager.IsRootCrlOutdated(new byte[32], 1_900_000_000));
    }

    [Fact]
    public void GetRootCrlAvailability_NoCrlUrl_IsNotConfigured()
    {
        using var temp = new TempDirectory("crl");
        var pki = TestPki.Create();
        using var manager = new CrlManager(temp.CreateSubdirectory("roots"), refreshSec: -1);
        manager.Initialize([pki.Root]);

        Assert.Equal(CrlAvailability.NotConfigured,
            manager.GetRootCrlAvailability(pki.Root.Fingerprint(), pki.Root.Sn, 1_700_000_000));
    }

    [Fact]
    public void GetRootCrlAvailability_UrlWithoutCrl_IsNotFetched()
    {
        using var temp = new TempDirectory("crl");
        var pki = TestPki.Create(new TestPkiOptions { RootCrlUrl = "http://crl.test/root.crl" });
        using var manager = new CrlManager(temp.CreateSubdirectory("roots"), refreshSec: -1);
        manager.Initialize([pki.Root]);

        Assert.Equal(CrlAvailability.NotFetched,
            manager.GetRootCrlAvailability(pki.Root.Fingerprint(), pki.Root.Sn, 1_700_000_000));
    }

    [Fact]
    public void GetRootCrlAvailability_CachedCrl_IsFreshThenStale()
    {
        using var temp = new TempDirectory("crl");
        var pki = TestPki.Create(new TestPkiOptions { RootCrlUrl = "http://crl.test/root.crl" });
        WriteRootCache(temp, pki.Root, RootCrlJson(pki, 3, [], nextUpdate: 1_700_000_100));
        using var manager = new CrlManager(temp.CreateSubdirectory("roots"), refreshSec: -1);
        manager.Initialize([pki.Root]);

        Assert.Equal(CrlAvailability.Fresh,
            manager.GetRootCrlAvailability(pki.Root.Fingerprint(), pki.Root.Sn, 1_700_000_000));
        Assert.Equal(CrlAvailability.Stale,
            manager.GetRootCrlAvailability(pki.Root.Fingerprint(), pki.Root.Sn, 1_700_000_101));
    }

    [Fact]
    public void GetRootCrlAvailability_When404_IsNotPublished()
    {
        using var temp = new TempDirectory("crl");
        var pki = TestPki.Create(new TestPkiOptions { RootCrlUrl = "http://crl.test/root.crl" });
        var http = FakeHttpMessageHandler.NotFound();
        using var manager = new CrlManager(temp.CreateSubdirectory("roots"), refreshSec: 3600, http.CreateClient());
        manager.Initialize([pki.Root]);

        Assert.True(SpinWait.SpinUntil(
            () => manager.GetRootCrlAvailability(pki.Root.Fingerprint(), pki.Root.Sn, 1_700_000_000) == CrlAvailability.NotPublished,
            TimeSpan.FromSeconds(3)));
    }

    [Fact]
    public void GetRootCrlAvailability_WhenSignatureInvalid_IsFetchFailed()
    {
        using var temp = new TempDirectory("crl");
        var pki = TestPki.Create(new TestPkiOptions { RootCrlUrl = "http://crl.test/root.crl" });
        var other = TestPki.Create(new TestPkiOptions { Seed = 60 });
        var http = FakeHttpMessageHandler.Json(RootCrlJson(other, 3, []));
        using var manager = new CrlManager(temp.CreateSubdirectory("roots"), refreshSec: 3600, http.CreateClient());
        manager.Initialize([pki.Root]);

        Assert.True(SpinWait.SpinUntil(
            () => manager.GetRootCrlAvailability(pki.Root.Fingerprint(), pki.Root.Sn, 1_700_000_000) == CrlAvailability.FetchFailed,
            TimeSpan.FromSeconds(3)));
    }

    [Fact]
    public void GetIntermediateCrlAvailability_NoCrlUrl_IsNotConfigured()
    {
        using var temp = new TempDirectory("crl");
        var pki = TestPki.Create();
        using var manager = new CrlManager(temp.CreateSubdirectory("roots"), refreshSec: -1);
        manager.Initialize([pki.Root]);

        manager.RegisterIntermediate(pki.Intermediate);

        Assert.Equal(CrlAvailability.NotConfigured,
            manager.GetIntermediateCrlAvailability(pki.Intermediate.Fingerprint(), pki.Intermediate.Sn, 1_700_000_000));
    }

    [Fact]
    public void GetIntermediateCrlAvailability_CachedCrl_IsFreshThenStale()
    {
        using var temp = new TempDirectory("crl");
        var pki = TestPki.Create(new TestPkiOptions { IssuerCrlUrl = "http://crl.test/int.crl" });
        WriteIntermediateCache(temp, pki.Intermediate,
            IntermediateCrlJson(pki, 1, [], nextUpdate: 1_700_000_100));
        using var manager = new CrlManager(temp.CreateSubdirectory("roots"), refreshSec: -1);
        manager.Initialize([pki.Root]);

        manager.RegisterIntermediate(pki.Intermediate);

        Assert.Equal(CrlAvailability.Fresh,
            manager.GetIntermediateCrlAvailability(pki.Intermediate.Fingerprint(), pki.Intermediate.Sn, 1_700_000_000));
        Assert.Equal(CrlAvailability.Stale,
            manager.GetIntermediateCrlAvailability(pki.Intermediate.Fingerprint(), pki.Intermediate.Sn, 1_700_000_101));
    }

    [Fact]
    public void CacheDirectoryName_Root_UsesSafeNameAndFingerprintPrefix()
    {
        var pki = TestPki.Create();
        var name = CrlManager.CacheDirectoryName("root", "BG 5/ESN", pki.Root.Fingerprint());

        Assert.StartsWith("root-BG_5_ESN-", name);
        Assert.DoesNotContain('/', name);
        Assert.DoesNotContain('\\', name);
        Assert.Matches(@"^root-BG_5_ESN-[0-9a-f]{16}$", name);
    }

    [Fact]
    public void CacheDirectoryName_Intermediate_UsesSafeNameAndFingerprintPrefix()
    {
        var pki = TestPki.Create();
        var name = CrlManager.CacheDirectoryName(
            "intermediate", "BD 4/WPW", pki.Intermediate.Fingerprint());

        Assert.StartsWith("intermediate-BD_4_WPW-", name);
        Assert.Matches(@"^intermediate-BD_4_WPW-[0-9a-f]{16}$", name);
    }

    [Fact]
    public void Initialize_WithDuplicateRootSn_LoadsBothByFingerprint()
    {
        using var temp = new TempDirectory("crl");
        var a = TestPki.Create(new TestPkiOptions { Seed = 70, RootSn = 1, IssuerSn = 111 });
        var b = TestPki.Create(new TestPkiOptions { Seed = 80, RootSn = 1, IssuerSn = 222 });
        var bFp = b.Intermediate.Fingerprint();

        WriteRootCache(temp, a.Root,
            RootCrlJson(a, 1, [(b.Intermediate.Sn, bFp, 1_700_000_000, 1)]));
        WriteRootCache(temp, b.Root, RootCrlJson(b, 1, []));

        using var manager = new CrlManager(temp.CreateSubdirectory("roots"), refreshSec: -1);
        manager.Initialize([a.Root, b.Root]);

        Assert.False(manager.IsIntermediateRevoked(
            b.Root.Fingerprint(), b.Intermediate.Sn, bFp, out _));
        Assert.True(manager.IsIntermediateRevoked(
            a.Root.Fingerprint(), b.Intermediate.Sn, bFp, out _));

        var aDir = RootCacheDirectory(temp, a.Root);
        var bDir = RootCacheDirectory(temp, b.Root);
        Assert.True(Directory.Exists(aDir));
        Assert.True(Directory.Exists(bDir));
        Assert.NotEqual(aDir, bDir);
    }

    [Fact]
    public void GetRootCrlAvailability_WithDuplicateRootSn_IsIndependent()
    {
        using var temp = new TempDirectory("crl");
        var a = TestPki.Create(new TestPkiOptions
        {
            Seed = 70,
            RootSn = 1,
            RootCrlUrl = "http://crl.test/a.crl"
        });
        var b = TestPki.Create(new TestPkiOptions
        {
            Seed = 80,
            RootSn = 1,
            RootCrlUrl = "http://crl.test/b.crl"
        });

        WriteRootCache(temp, a.Root,
            RootCrlJson(a, 1, [], nextUpdate: 1_700_000_100));
        WriteRootCache(temp, b.Root,
            RootCrlJson(b, 2, [], nextUpdate: 1_800_000_000));

        using var manager = new CrlManager(temp.CreateSubdirectory("roots"), refreshSec: -1);
        manager.Initialize([a.Root, b.Root]);

        Assert.Equal(CrlAvailability.Stale,
            manager.GetRootCrlAvailability(a.Root.Fingerprint(), a.Root.Sn, 1_700_000_101));
        Assert.Equal(CrlAvailability.Fresh,
            manager.GetRootCrlAvailability(b.Root.Fingerprint(), b.Root.Sn, 1_700_000_101));
    }

    [Fact]
    public void RegisterIntermediate_WithDuplicateIntermediateSn_LoadsBothByFingerprint()
    {
        using var temp = new TempDirectory("crl");
        var a = TestPki.Create(new TestPkiOptions
        {
            Seed = 70,
            RootSn = 11,
            IssuerSn = 1001,
            IssuerCrlUrl = "http://crl.test/a.crl"
        });
        var b = TestPki.Create(new TestPkiOptions
        {
            Seed = 80,
            RootSn = 22,
            IssuerSn = 1001,
            IssuerCrlUrl = "http://crl.test/b.crl"
        });
        var bUserFp = b.User.Fingerprint();

        WriteIntermediateCache(temp, a.Intermediate,
            IntermediateCrlJson(a, 1, [(b.User.Uid, bUserFp, 1_700_000_000, 1)]));
        WriteIntermediateCache(temp, b.Intermediate, IntermediateCrlJson(b, 1, []));

        using var manager = new CrlManager(temp.CreateSubdirectory("roots"), refreshSec: -1);
        manager.Initialize([a.Root, b.Root]);
        manager.RegisterIntermediate(a.Intermediate);
        manager.RegisterIntermediate(b.Intermediate);

        Assert.False(manager.IsUserRevoked(
            b.Intermediate.Fingerprint(), b.User.Uid, bUserFp, out _));
        Assert.True(manager.IsUserRevoked(
            a.Intermediate.Fingerprint(), b.User.Uid, bUserFp, out _));
    }

    [Fact]
    public void GetIntermediateCrlAvailability_WithDuplicateIntermediateSn_IsIndependent()
    {
        using var temp = new TempDirectory("crl");
        var a = TestPki.Create(new TestPkiOptions
        {
            Seed = 70,
            RootSn = 11,
            IssuerSn = 1001,
            IssuerCrlUrl = "http://crl.test/a.crl"
        });
        var b = TestPki.Create(new TestPkiOptions
        {
            Seed = 80,
            RootSn = 22,
            IssuerSn = 1001,
            IssuerCrlUrl = "http://crl.test/b.crl"
        });

        WriteIntermediateCache(temp, a.Intermediate,
            IntermediateCrlJson(a, 1, [], nextUpdate: 1_700_000_100));
        WriteIntermediateCache(temp, b.Intermediate,
            IntermediateCrlJson(b, 2, [], nextUpdate: 1_800_000_000));

        using var manager = new CrlManager(temp.CreateSubdirectory("roots"), refreshSec: -1);
        manager.Initialize([a.Root, b.Root]);
        manager.RegisterIntermediate(a.Intermediate);
        manager.RegisterIntermediate(b.Intermediate);

        Assert.Equal(CrlAvailability.Stale,
            manager.GetIntermediateCrlAvailability(
                a.Intermediate.Fingerprint(), a.Intermediate.Sn, 1_700_000_101));
        Assert.Equal(CrlAvailability.Fresh,
            manager.GetIntermediateCrlAvailability(
                b.Intermediate.Fingerprint(), b.Intermediate.Sn, 1_700_000_101));
    }

    [Fact]
    public void Initialize_IgnoresLegacySnCacheDirectory()
    {
        using var temp = new TempDirectory("crl");
        var pki = TestPki.Create(new TestPkiOptions { RootCrlUrl = "http://crl.test/root.crl" });
        var legacyDir = temp.CreateSubdirectory("crl", pki.Root.Sn.ToString());
        File.WriteAllText(Path.Combine(legacyDir, "root.json"),
            RootCrlJson(pki, 5, [], nextUpdate: 1_800_000_000));

        using var manager = new CrlManager(temp.CreateSubdirectory("roots"), refreshSec: -1);
        manager.Initialize([pki.Root]);

        Assert.Equal(CrlAvailability.NotFetched,
            manager.GetRootCrlAvailability(pki.Root.Fingerprint(), pki.Root.Sn, 1_700_000_000));
    }

    [Fact]
    public void MetaFile_ContainsOriginalNameAndFingerprint()
    {
        using var temp = new TempDirectory("crl");
        var pki = TestPki.Create(new TestPkiOptions
        {
            RootName = "  BG 5 ESN  ",
            RootCrlUrl = "http://crl.test/root.crl"
        });

        using var manager = new CrlManager(temp.CreateSubdirectory("roots"), refreshSec: -1);
        manager.Initialize([pki.Root]);

        var metaPath = Path.Combine(RootCacheDirectory(temp, pki.Root), "meta.json");
        Assert.True(File.Exists(metaPath));

        using var doc = JsonDocument.Parse(File.ReadAllText(metaPath));
        var root = doc.RootElement;
        Assert.Equal("root", root.GetProperty("type").GetString());
        Assert.Equal("  BG 5 ESN  ", root.GetProperty("name").GetString());
        Assert.Equal(pki.Root.Sn, root.GetProperty("sn").GetInt64());
        Assert.Equal(CrlManager.FingerprintKey(pki.Root.Fingerprint()),
            root.GetProperty("fingerprint").GetString());
        Assert.Equal("http://crl.test/root.crl", root.GetProperty("crl").GetString());
    }

    [Fact]
    public void Dispose_IsIdempotent()
    {
        using var temp = new TempDirectory("crl");
        var manager = new CrlManager(temp.CreateSubdirectory("roots"), refreshSec: -1);
        manager.Initialize([]);

        manager.Dispose();
        manager.Dispose();
    }

    [Fact]
    public void Initialize_WithRefreshEnabled_FetchesAndCachesRootCrl()
    {
        using var temp = new TempDirectory("crl");
        var pki = TestPki.Create(new TestPkiOptions { RootCrlUrl = "http://crl.test/root.crl" });
        var revokedFp = pki.Intermediate.Fingerprint();
        var http = FakeHttpMessageHandler.Json(
            RootCrlJson(pki, 7, [(pki.Intermediate.Sn, revokedFp, 1_700_000_000, 1)]));
        using var manager = new CrlManager(temp.CreateSubdirectory("roots"), refreshSec: 3600, http.CreateClient());

        manager.Initialize([pki.Root]);

        Assert.True(SpinWait.SpinUntil(
            () => manager.IsIntermediateRevoked(pki.Root.Fingerprint(), pki.Intermediate.Sn, revokedFp, out _),
            TimeSpan.FromSeconds(3)));
        Assert.True(File.Exists(Path.Combine(RootCacheDirectory(temp, pki.Root), "root.json")));
    }

    [Fact]
    public void Initialize_WhenRootCrlReturns404_DoesNotCache()
    {
        using var temp = new TempDirectory("crl");
        var pki = TestPki.Create(new TestPkiOptions { RootCrlUrl = "http://crl.test/root.crl" });
        var http = FakeHttpMessageHandler.NotFound();
        using var manager = new CrlManager(temp.CreateSubdirectory("roots"), refreshSec: 3600, http.CreateClient());

        manager.Initialize([pki.Root]);

        Assert.True(SpinWait.SpinUntil(() => http.CallCount >= 1, TimeSpan.FromSeconds(3)));
        Assert.False(File.Exists(Path.Combine(RootCacheDirectory(temp, pki.Root), "root.json")));
    }

    [Fact]
    public void Initialize_WhenRootCrlSignatureIsInvalid_DoesNotCache()
    {
        using var temp = new TempDirectory("crl");
        var pki = TestPki.Create(new TestPkiOptions { RootCrlUrl = "http://crl.test/root.crl" });
        var other = TestPki.Create(new TestPkiOptions { Seed = 60 });
        var http = FakeHttpMessageHandler.Json(RootCrlJson(other, 3, []));
        using var manager = new CrlManager(temp.CreateSubdirectory("roots"), refreshSec: 3600, http.CreateClient());

        manager.Initialize([pki.Root]);

        Assert.True(SpinWait.SpinUntil(() => http.CallCount >= 1, TimeSpan.FromSeconds(3)));
        Assert.False(File.Exists(Path.Combine(RootCacheDirectory(temp, pki.Root), "root.json")));
    }

    [Fact]
    public void Initialize_WhenPublishedCrlIsOlder_KeepsCachedVersion()
    {
        using var temp = new TempDirectory("crl");
        var pki = TestPki.Create(new TestPkiOptions { RootCrlUrl = "http://crl.test/root.crl" });
        var userFp = pki.User.Fingerprint();
        WriteRootCache(temp, pki.Root, RootCrlJson(pki, 9, []));
        var http = FakeHttpMessageHandler.Json(
            RootCrlJson(pki, 1, [(pki.User.Uid, userFp, 1, 1)]));
        using var manager = new CrlManager(temp.CreateSubdirectory("roots"), refreshSec: 3600, http.CreateClient());

        manager.Initialize([pki.Root]);

        Assert.True(SpinWait.SpinUntil(() => http.CallCount >= 1, TimeSpan.FromSeconds(3)));
        Thread.Sleep(100);
        Assert.False(manager.IsUserRevoked(pki.Intermediate.Fingerprint(), pki.User.Uid, userFp, out _));
    }

    [Fact]
    public void RegisterIntermediate_FetchedCrlEnablesUserRevocation()
    {
        using var temp = new TempDirectory("crl");
        var pki = TestPki.Create(new TestPkiOptions { IssuerCrlUrl = "http://crl.test/int.crl" });
        var userFp = pki.User.Fingerprint();
        var http = FakeHttpMessageHandler.Json(
            IntermediateCrlJson(pki, 4, [(pki.User.Uid, userFp, 1_700_000_000, 1)]));
        using var manager = new CrlManager(temp.CreateSubdirectory("roots"), refreshSec: -1, http.CreateClient());
        manager.Initialize([pki.Root]);

        manager.RegisterIntermediate(pki.Intermediate);

        Assert.True(SpinWait.SpinUntil(
            () => manager.IsUserRevoked(pki.Intermediate.Fingerprint(), pki.User.Uid, userFp, out _),
            TimeSpan.FromSeconds(3)));
        Assert.True(File.Exists(Path.Combine(
            IntermediateCacheDirectory(temp, pki.Intermediate), "intermediate.json")));
    }
}
