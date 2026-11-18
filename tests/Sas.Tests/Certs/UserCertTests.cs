using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sas.certs;
using Sas.Tests.Fixtures;

namespace Sas.Tests.Certs;

public sealed class UserCertTests
{
    private static UserCert Parse(string json) =>
        UserCert.FromJson(JsonDocument.Parse(json).RootElement);

    [Fact]
    public void FromJson_UppercasesCallsign()
    {
        var node = JsonNode.Parse(TestPki.Create().UserJson)!;
        node["subject"]!["callsign"] = "bg6vmz";

        Assert.Equal("BG6VMZ", Parse(node.ToJsonString()).Callsign);
    }

    [Fact]
    public void ToTbsCbor_HasStableProtocolShape()
    {
        var tbs = Parse(TestPki.Create().UserJson).ToTbsCbor();

        // CBOR array of 9 elements (0x89), then "FMO" + version 4.
        Assert.Equal(0x89, tbs[0]);
        Assert.Equal(new byte[] { 0x63, (byte)'F', (byte)'M', (byte)'O', 0x04 }, tbs[1..6]);
    }

    [Fact]
    public void Fingerprint_IsSha256OfTbsCbor()
    {
        var cert = Parse(TestPki.Create().UserJson);

        Assert.Equal(SHA256.HashData(cert.ToTbsCbor()), cert.Fingerprint());
    }

    [Fact]
    public void Fingerprint_ChangesWhenAnySignedFieldChanges()
    {
        var pki = TestPki.Create();
        var original = pki.User.Fingerprint();

        var changedUid = new UserCert
        {
            IssuerSn = pki.User.IssuerSn,
            Callsign = pki.User.Callsign,
            Uid = pki.User.Uid + 1,
            PublicKey = pki.User.PublicKey,
            Iat = pki.User.Iat,
            Exp = pki.User.Exp,
            Signature = pki.User.Signature
        };

        var changedCallsign = new UserCert
        {
            IssuerSn = pki.User.IssuerSn,
            Callsign = "BG0AAA",
            Uid = pki.User.Uid,
            PublicKey = pki.User.PublicKey,
            Iat = pki.User.Iat,
            Exp = pki.User.Exp,
            Signature = pki.User.Signature
        };

        Assert.NotEqual(original, changedUid.Fingerprint());
        Assert.NotEqual(original, changedCallsign.Fingerprint());
    }

    [Fact]
    public void VerifyBy_IssuingIntermediate_ReturnsTrue()
    {
        var pki = TestPki.Create();

        Assert.True(pki.User.VerifyBy(pki.Intermediate));
    }

    [Fact]
    public void VerifyBy_UnrelatedIntermediate_ReturnsFalse()
    {
        var a = TestPki.Create(new TestPkiOptions { Seed = 10 });
        var b = TestPki.Create(new TestPkiOptions { Seed = 20 });

        Assert.False(b.User.VerifyBy(a.Intermediate));
    }

    [Theory]
    [InlineData(1000L, 1000L, true)]
    [InlineData(1000L, 999L, false)]
    public void IsExpired_UsesInclusiveExpiry(long exp, long now, bool expected)
    {
        var cert = TestPki.Create(new TestPkiOptions { UserExp = exp }).User;

        Assert.Equal(expected, cert.IsExpired(now));
    }

    [Fact]
    public void FromJson_MissingProperty_Throws()
    {
        using var doc = JsonDocument.Parse("{}");

        Assert.Throws<KeyNotFoundException>(() => UserCert.FromJson(doc.RootElement));
    }
}
