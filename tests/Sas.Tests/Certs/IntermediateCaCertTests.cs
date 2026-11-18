using System.Text.Json;
using System.Text.Json.Nodes;
using Sas.certs;
using Sas.Tests.Fixtures;

namespace Sas.Tests.Certs;

public sealed class IntermediateCaCertTests
{
    private static IntermediateCaCert Parse(string json) =>
        IntermediateCaCert.FromJson(JsonDocument.Parse(json).RootElement);

    [Fact]
    public void FromJson_ParsesAllFields()
    {
        var cert = Parse(TestPki.Create().IntermediateJson);

        Assert.Equal(1001, cert.Sn);
        Assert.Equal(1, cert.IssuerSn);
        Assert.Equal("bg5esn", cert.IssuerName);
        Assert.Equal("bd4wpw", cert.SubjectName);
        Assert.Equal(5000, cert.UidRangeStart);
        Assert.Equal(99999, cert.UidRangeEnd);
        Assert.Equal(0u, cert.PathLen);
        Assert.True(cert.IsCA);
    }

    [Fact]
    public void FromJson_SortsIssuingCountriesOrdinal()
    {
        var cert = Parse(TestPki.Create(new TestPkiOptions
        {
            IssuingCountries = ["US", "CN", "JP"]
        }).IntermediateJson);

        Assert.Equal(["CN", "JP", "US"], cert.IssuingCountries);
    }

    [Fact]
    public void ToTbsCbor_IsIndependentOfInputCountryOrder()
    {
        var a = Parse(TestPki.Create(new TestPkiOptions
        {
            IssuingCountries = ["US", "CN", "JP"]
        }).IntermediateJson);

        var b = Parse(TestPki.Create(new TestPkiOptions
        {
            IssuingCountries = ["JP", "US", "CN"]
        }).IntermediateJson);

        Assert.Equal(a.ToTbsCbor(), b.ToTbsCbor());
    }

    [Theory]
    [InlineData("cn")]
    [InlineData("CHN")]
    [InlineData("")]
    [InlineData("C1")]
    [InlineData("中国")]
    public void FromJson_RejectsInvalidCountryCode(string country)
    {
        var node = JsonNode.Parse(TestPki.Create().IntermediateJson)!;
        node["extensions"]!["issuingCountries"] = new JsonArray(country);

        Assert.Throws<InvalidOperationException>(() => Parse(node.ToJsonString()));
    }

    [Fact]
    public void ToTbsCbor_HasStableProtocolShape()
    {
        var tbs = Parse(TestPki.Create().IntermediateJson).ToTbsCbor();

        // CBOR array of 20 elements (0x94), then "FMO" + version 4.
        Assert.Equal(0x94, tbs[0]);
        Assert.Equal(new byte[] { 0x63, (byte)'F', (byte)'M', (byte)'O', 0x04 }, tbs[1..6]);
    }

    [Fact]
    public void VerifyBy_CorrectRoot_ReturnsTrue()
    {
        var pki = TestPki.Create();

        Assert.True(pki.Intermediate.VerifyBy(pki.Root));
    }

    [Fact]
    public void VerifyBy_UnrelatedRoot_ReturnsFalse()
    {
        var a = TestPki.Create(new TestPkiOptions { Seed = 10 });
        var b = TestPki.Create(new TestPkiOptions { Seed = 20 });

        Assert.False(b.Intermediate.VerifyBy(a.Root));
    }

    [Theory]
    [InlineData(5000, 99999, 4999, false)]
    [InlineData(5000, 99999, 5000, true)]
    [InlineData(5000, 99999, 50001, true)]
    [InlineData(5000, 99999, 99999, true)]
    [InlineData(5000, 99999, 100000, false)]
    public void CanIssueFor_RespectsInclusiveRange(long start, long end, long uid, bool expected)
    {
        var cert = TestPki.Create(new TestPkiOptions
        {
            UidRangeStart = start,
            UidRangeEnd = end
        }).Intermediate;

        Assert.Equal(expected, cert.CanIssueFor(uid));
    }

    [Theory]
    [InlineData(1000L, 1000L, true)]
    [InlineData(1000L, 999L, false)]
    public void IsExpired_UsesInclusiveExpiry(long exp, long now, bool expected)
    {
        var cert = TestPki.Create(new TestPkiOptions { IssuerExp = exp }).Intermediate;

        Assert.Equal(expected, cert.IsExpired(now));
    }

    [Fact]
    public void FromJson_MissingProperty_Throws()
    {
        using var doc = JsonDocument.Parse("""{"sn":1}""");

        Assert.Throws<KeyNotFoundException>(() => IntermediateCaCert.FromJson(doc.RootElement));
    }
}
