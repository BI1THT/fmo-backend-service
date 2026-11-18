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

    private static void WriteRootCache(TempDirectory temp, long sn, string json)
    {
        var dir = temp.CreateSubdirectory("crl", sn.ToString());
        File.WriteAllText(Path.Combine(dir, "root.json"), json);
    }

    private static void WriteIntermediateCache(TempDirectory temp, long sn, string json)
    {
        var dir = temp.CreateSubdirectory("crl", sn.ToString());
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

        Assert.False(manager.IsRootCrlOutdated(pki.Root.Sn, 1_900_000_000));
    }

    [Fact]
    public void Initialize_LoadsValidCachedRootCrl()
    {
        using var temp = new TempDirectory("crl");
        var pki = TestPki.Create();
        WriteRootCache(temp, pki.Root.Sn, RootCrlJson(pki, 5, [], nextUpdate: 1_700_000_100));
        using var manager = new CrlManager(temp.CreateSubdirectory("roots"), refreshSec: -1);

        manager.Initialize([pki.Root]);

        Assert.False(manager.IsRootCrlOutdated(pki.Root.Sn, 1_700_000_000));
        Assert.True(manager.IsRootCrlOutdated(pki.Root.Sn, 1_700_000_101));
    }

    [Fact]
    public void Initialize_IgnoresCachedRootCrlWithBadSignature()
    {
        using var temp = new TempDirectory("crl");
        var pki = TestPki.Create();
        var other = TestPki.Create(new TestPkiOptions { Seed = 50 });
        WriteRootCache(temp, pki.Root.Sn, RootCrlJson(other, 5, [], nextUpdate: 1_700_000_100));
        using var manager = new CrlManager(temp.CreateSubdirectory("roots"), refreshSec: -1);

        manager.Initialize([pki.Root]);

        Assert.False(manager.IsRootCrlOutdated(pki.Root.Sn, 1_900_000_000));
    }

    [Fact]
    public void Initialize_IgnoresCorruptCachedRootCrl()
    {
        using var temp = new TempDirectory("crl");
        var pki = TestPki.Create();
        WriteRootCache(temp, pki.Root.Sn, "{not json");
        using var manager = new CrlManager(temp.CreateSubdirectory("roots"), refreshSec: -1);

        manager.Initialize([pki.Root]);

        Assert.False(manager.IsRootCrlOutdated(pki.Root.Sn, 1_900_000_000));
    }

    [Fact]
    public void IsIntermediateRevoked_MatchesCachedRootCrlEntry()
    {
        using var temp = new TempDirectory("crl");
        var pki = TestPki.Create();
        var revokedFp = pki.Intermediate.Fingerprint();
        WriteRootCache(temp, pki.Root.Sn,
            RootCrlJson(pki, 1, [(pki.Intermediate.Sn, revokedFp, 1_700_000_000, 1)]));
        using var manager = new CrlManager(temp.CreateSubdirectory("roots"), refreshSec: -1);
        manager.Initialize([pki.Root]);

        Assert.True(manager.IsIntermediateRevoked(pki.Intermediate.Sn, revokedFp, out var reason));
        Assert.Contains("intermediate CA", reason);
        Assert.False(manager.IsIntermediateRevoked(pki.Intermediate.Sn, Fingerprint(0xFF), out _));
    }

    [Fact]
    public void IsUserRevoked_MatchesCachedIntermediateCrlEntry()
    {
        using var temp = new TempDirectory("crl");
        var pki = TestPki.Create(new TestPkiOptions { IssuerCrlUrl = "http://crl.test/int.crl" });
        var revokedFp = pki.User.Fingerprint();
        WriteIntermediateCache(temp, pki.Intermediate.Sn,
            IntermediateCrlJson(pki, 1, [(pki.User.Uid, revokedFp, 1_700_000_000, 1)]));
        using var manager = new CrlManager(temp.CreateSubdirectory("roots"), refreshSec: -1);
        manager.Initialize([pki.Root]);

        manager.RegisterIntermediate(pki.Intermediate);

        Assert.True(manager.IsUserRevoked(pki.User.Uid, revokedFp, out var reason));
        Assert.Contains("user cert", reason);
        Assert.False(manager.IsUserRevoked(pki.User.Uid, Fingerprint(0xFF), out _));
    }

    [Fact]
    public void RootCrlEntries_DoNotAffectUserRevocation()
    {
        using var temp = new TempDirectory("crl");
        var pki = TestPki.Create();
        var userFp = pki.User.Fingerprint();
        WriteRootCache(temp, pki.Root.Sn,
            RootCrlJson(pki, 1, [(pki.User.Uid, userFp, 1_700_000_000, 1)]));
        using var manager = new CrlManager(temp.CreateSubdirectory("roots"), refreshSec: -1);
        manager.Initialize([pki.Root]);

        Assert.False(manager.IsUserRevoked(pki.User.Uid, userFp, out _));
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
        WriteIntermediateCache(temp, pki.Intermediate.Sn,
            IntermediateCrlJson(pki, 1, [(pki.User.Uid, pki.User.Fingerprint(), 1, 1)]));
        var http = FakeHttpMessageHandler.Json(IntermediateCrlJson(pki, 2, []));
        using var manager = new CrlManager(temp.CreateSubdirectory("roots"), refreshSec: -1, http.CreateClient());
        manager.Initialize([pki.Root]);

        manager.RegisterIntermediate(pki.Intermediate);

        Assert.Equal(0, http.CallCount);
        Assert.True(manager.IsUserRevoked(pki.User.Uid, pki.User.Fingerprint(), out _));
    }

    [Fact]
    public void IsRootCrlOutdated_ReturnsFalseWhenCrlCoversNow()
    {
        using var temp = new TempDirectory("crl");
        var pki = TestPki.Create();
        WriteRootCache(temp, pki.Root.Sn, RootCrlJson(pki, 3, [], nextUpdate: 1_700_003_600));
        using var manager = new CrlManager(temp.CreateSubdirectory("roots"), refreshSec: -1);
        manager.Initialize([pki.Root]);

        Assert.False(manager.IsRootCrlOutdated(pki.Root.Sn, 1_700_003_600));
        Assert.True(manager.IsRootCrlOutdated(pki.Root.Sn, 1_700_003_601));
    }

    [Fact]
    public void IsRootCrlOutdated_WithoutCrlForUnknownRoot_ReturnsFalse()
    {
        using var temp = new TempDirectory("crl");
        var pki = TestPki.Create();
        using var manager = new CrlManager(temp.CreateSubdirectory("roots"), refreshSec: -1);
        manager.Initialize([pki.Root]);

        Assert.False(manager.IsRootCrlOutdated(9999, 1_900_000_000));
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
            () => manager.IsIntermediateRevoked(pki.Intermediate.Sn, revokedFp, out _),
            TimeSpan.FromSeconds(3)));
        Assert.True(File.Exists(Path.Combine(temp.Path, "crl", pki.Root.Sn.ToString(), "root.json")));
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
        Assert.False(File.Exists(Path.Combine(temp.Path, "crl", pki.Root.Sn.ToString(), "root.json")));
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
        Assert.False(File.Exists(Path.Combine(temp.Path, "crl", pki.Root.Sn.ToString(), "root.json")));
    }

    [Fact]
    public void Initialize_WhenPublishedCrlIsOlder_KeepsCachedVersion()
    {
        using var temp = new TempDirectory("crl");
        var pki = TestPki.Create(new TestPkiOptions { RootCrlUrl = "http://crl.test/root.crl" });
        var userFp = pki.User.Fingerprint();
        WriteRootCache(temp, pki.Root.Sn, RootCrlJson(pki, 9, []));
        var http = FakeHttpMessageHandler.Json(
            RootCrlJson(pki, 1, [(pki.User.Uid, userFp, 1, 1)]));
        using var manager = new CrlManager(temp.CreateSubdirectory("roots"), refreshSec: 3600, http.CreateClient());

        manager.Initialize([pki.Root]);

        Assert.True(SpinWait.SpinUntil(() => http.CallCount >= 1, TimeSpan.FromSeconds(3)));
        Thread.Sleep(100);
        Assert.False(manager.IsUserRevoked(pki.User.Uid, userFp, out _));
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
            () => manager.IsUserRevoked(pki.User.Uid, userFp, out _),
            TimeSpan.FromSeconds(3)));
        Assert.True(File.Exists(Path.Combine(temp.Path, "crl",
            pki.Intermediate.Sn.ToString(), "intermediate.json")));
    }
}
