using System.Text.Json;
using System.Text.Json.Nodes;
using Sas.certs;
using Sas.Tests.Fixtures;

namespace Sas.Tests.Certs;

public sealed class RootCrlTests
{
    internal static string BuildJson(
        long issuerSn,
        long crlNumber,
        IEnumerable<(long Sn, byte[] Fingerprint, long RevokedAt, int Reason)> entries,
        byte[]? signature = null,
        long thisUpdate = 1_700_000_000,
        long nextUpdate = 1_700_003_600)
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

        var obj = new JsonObject
        {
            ["type"] = "rootCRL",
            ["issuerSn"] = issuerSn,
            ["crlNumber"] = crlNumber,
            ["thisUpdate"] = thisUpdate,
            ["nextUpdate"] = nextUpdate,
            ["entries"] = array,
            ["signatureAlgorithm"] = "Ed25519",
            ["signature"] = Base64Url.Encode(signature ?? new byte[64])
        };

        return obj.ToJsonString();
    }

    internal static RootCrl Parse(string json) =>
        RootCrl.FromJson(JsonDocument.Parse(json).RootElement);

    private static RootCrl Sign(TestPki pki, long issuerSn, long crlNumber,
        IEnumerable<(long Sn, byte[] Fingerprint, long RevokedAt, int Reason)> entries,
        long nextUpdate = 1_700_003_600)
    {
        var draft = Parse(BuildJson(issuerSn, crlNumber, entries, nextUpdate: nextUpdate));
        var signature = Ed25519.Sign(pki.RootPrivateKey, draft.ToTbsCbor());
        return Parse(BuildJson(issuerSn, crlNumber, entries, signature, nextUpdate: nextUpdate));
    }

    private static byte[] Fingerprint(byte fill) =>
        Enumerable.Repeat(fill, 32).ToArray();

    [Fact]
    public void FromJson_SortsEntriesBySnThenFingerprint()
    {
        var crl = Parse(BuildJson(1, 3,
        [
            (2, Fingerprint(0x03), 10, 1),
            (1, Fingerprint(0x02), 10, 1),
            (1, Fingerprint(0x01), 10, 1)
        ]));

        Assert.Equal([1L, 1L, 2L], crl.Entries.Select(e => e.Sn));
        Assert.Equal(0x01, crl.Entries[0].CertFingerprint[0]);
        Assert.Equal(0x02, crl.Entries[1].CertFingerprint[0]);
    }

    [Fact]
    public void ToTbsCbor_IsIndependentOfJsonEntryOrder()
    {
        var a = Parse(BuildJson(1, 3,
        [
            (2, Fingerprint(0x03), 10, 1),
            (1, Fingerprint(0x02), 10, 1)
        ]));

        var b = Parse(BuildJson(1, 3,
        [
            (1, Fingerprint(0x02), 10, 1),
            (2, Fingerprint(0x03), 10, 1)
        ]));

        Assert.Equal(a.ToTbsCbor(), b.ToTbsCbor());
    }

    [Fact]
    public void ToTbsCbor_HasStableProtocolShape()
    {
        var tbs = Parse(BuildJson(1, 3, [])).ToTbsCbor();

        // CBOR array of 8 elements (0x88), then "FMO" + version 4.
        Assert.Equal(0x88, tbs[0]);
        Assert.Equal(new byte[] { 0x63, (byte)'F', (byte)'M', (byte)'O', 0x04 }, tbs[1..6]);
    }

    [Fact]
    public void VerifyBy_Issuer_ReturnsTrue()
    {
        var pki = TestPki.Create();
        var crl = Sign(pki, pki.Root.Sn, 1, [(1001, Fingerprint(0x01), 10, 1)]);

        Assert.True(crl.VerifyBy(pki.Root));
    }

    [Fact]
    public void VerifyBy_AfterTampering_ReturnsFalse()
    {
        var pki = TestPki.Create();
        var crl = Sign(pki, pki.Root.Sn, 1, [(1001, Fingerprint(0x01), 10, 1)]);

        var tampered = Parse(BuildJson(pki.Root.Sn, 2,
            [(1001, Fingerprint(0x01), 10, 1)], crl.Signature));

        Assert.False(tampered.VerifyBy(pki.Root));
    }

    [Fact]
    public void IsRevoked_RequiresSnAndFingerprintMatch()
    {
        var crl = Parse(BuildJson(1, 1, [(1001, Fingerprint(0xAA), 10, 1)]));

        Assert.True(crl.IsRevoked(1001, Fingerprint(0xAA)));
        Assert.False(crl.IsRevoked(1001, Fingerprint(0xBB)));
        Assert.False(crl.IsRevoked(1002, Fingerprint(0xAA)));
    }

    [Theory]
    [InlineData(1_700_003_600L, false)]
    [InlineData(1_700_003_601L, true)]
    public void IsOutdated_IsStrictlyGreaterThanNextUpdate(long now, bool expected)
    {
        var crl = Parse(BuildJson(1, 1, [], nextUpdate: 1_700_003_600));

        Assert.Equal(expected, crl.IsOutdated(now));
    }

    [Fact]
    public void CrlNumber_NegativeValue_WrapsToUInt32()
    {
        // Current behaviour: long -> uint is an unchecked cast.
        var crl = Parse(BuildJson(1, -1, []));

        Assert.Equal(uint.MaxValue, crl.CrlNumber);
    }
}

public sealed class IntermediateCrlTests
{
    private static byte[] Fingerprint(byte fill) => Enumerable.Repeat(fill, 32).ToArray();

    private static string BuildJson(long issuerSn, long crlNumber,
        IEnumerable<(long Uid, byte[] Fingerprint, long RevokedAt, int Reason)> entries,
        byte[]? signature = null, long nextUpdate = 1_700_003_600)
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

        var obj = new JsonObject
        {
            ["type"] = "intermediateCRL",
            ["issuerSn"] = issuerSn,
            ["crlNumber"] = crlNumber,
            ["thisUpdate"] = 1_700_000_000,
            ["nextUpdate"] = nextUpdate,
            ["entries"] = array,
            ["signatureAlgorithm"] = "Ed25519",
            ["signature"] = Base64Url.Encode(signature ?? new byte[64])
        };

        return obj.ToJsonString();
    }

    private static IntermediateCrl Parse(string json) =>
        IntermediateCrl.FromJson(JsonDocument.Parse(json).RootElement);

    private static IntermediateCrl Sign(TestPki pki, long issuerSn, long crlNumber,
        IEnumerable<(long Uid, byte[] Fingerprint, long RevokedAt, int Reason)> entries)
    {
        var draft = Parse(BuildJson(issuerSn, crlNumber, entries));
        var signature = Ed25519.Sign(pki.IntermediatePrivateKey, draft.ToTbsCbor());
        return Parse(BuildJson(issuerSn, crlNumber, entries, signature));
    }

    [Fact]
    public void FromJson_SortsEntriesByUidThenFingerprint()
    {
        var crl = Parse(BuildJson(1001, 3,
        [
            (50002, Fingerprint(0x03), 10, 1),
            (50001, Fingerprint(0x02), 10, 1),
            (50001, Fingerprint(0x01), 10, 1)
        ]));

        Assert.Equal([50001L, 50001L, 50002L], crl.Entries.Select(e => e.Uid));
        Assert.Equal(0x01, crl.Entries[0].CertFingerprint[0]);
    }

    [Fact]
    public void ToTbsCbor_IsIndependentOfJsonEntryOrder()
    {
        var a = Parse(BuildJson(1001, 3,
            [(2, Fingerprint(0x03), 10, 1), (1, Fingerprint(0x02), 10, 1)]));

        var b = Parse(BuildJson(1001, 3,
            [(1, Fingerprint(0x02), 10, 1), (2, Fingerprint(0x03), 10, 1)]));

        Assert.Equal(a.ToTbsCbor(), b.ToTbsCbor());
    }

    [Fact]
    public void ToTbsCbor_HasStableProtocolShape()
    {
        var tbs = Parse(BuildJson(1001, 3, [])).ToTbsCbor();

        Assert.Equal(0x88, tbs[0]);
    }

    [Fact]
    public void VerifyBy_Issuer_ReturnsTrue()
    {
        var pki = TestPki.Create();
        var crl = Sign(pki, pki.Intermediate.Sn, 1, [(50001, Fingerprint(0x01), 10, 1)]);

        Assert.True(crl.VerifyBy(pki.Intermediate));
    }

    [Fact]
    public void VerifyBy_WrongIssuer_ReturnsFalse()
    {
        var pki = TestPki.Create();
        var other = TestPki.Create(new TestPkiOptions { Seed = 21 });
        var crl = Sign(pki, pki.Intermediate.Sn, 1, [(50001, Fingerprint(0x01), 10, 1)]);

        Assert.False(crl.VerifyBy(other.Intermediate));
    }

    [Fact]
    public void IsRevoked_RequiresUidAndFingerprintMatch()
    {
        var crl = Parse(BuildJson(1001, 1, [(50001, Fingerprint(0xAA), 10, 1)]));

        Assert.True(crl.IsRevoked(50001, Fingerprint(0xAA)));
        Assert.False(crl.IsRevoked(50001, Fingerprint(0xBB)));
        Assert.False(crl.IsRevoked(50002, Fingerprint(0xAA)));
    }

    [Theory]
    [InlineData(1_700_003_600L, false)]
    [InlineData(1_700_003_601L, true)]
    public void IsOutdated_IsStrictlyGreaterThanNextUpdate(long now, bool expected)
    {
        var crl = Parse(BuildJson(1001, 1, [], nextUpdate: 1_700_003_600));

        Assert.Equal(expected, crl.IsOutdated(now));
    }
}
