using System.Security.Cryptography;
using System.Text.Json;
using Sas.Tests.Fixtures;

namespace Sas.Tests.Certs;

public sealed class RootCaCertTests
{
    private static string BuiltinRootPath =>
        Path.Combine(AppContext.BaseDirectory, "builtin", "roots", "bg5esn.json");

    private static Sas.certs.RootCaCert LoadBuiltin() =>
        Sas.certs.RootCaCert.FromJson(
            JsonDocument.Parse(File.ReadAllText(BuiltinRootPath)).RootElement);

    [Fact]
    public void BuiltinRoot_IsShippedWithTheTestOutput()
    {
        Assert.True(File.Exists(BuiltinRootPath),
            "builtin/roots/bg5esn.json must be copied to the test output directory");
    }

    [Fact]
    public void BuiltinRoot_ParsesAndSelfVerifies()
    {
        var root = LoadBuiltin();

        Assert.Equal(1, root.Sn);
        Assert.Equal("BG5ESN", root.SubjectName);
        Assert.Equal(32, root.SubjectPubKey.Length);
        Assert.Equal(64, root.Signature.Length);
        Assert.True(root.VerifySelfSignature());
    }

    [Fact]
    public void BuiltinRoot_TbsCbor_HasStableProtocolShape()
    {
        var root = LoadBuiltin();
        var tbs = root.ToTbsCbor();

        // CBOR array of 15 elements (0x8F), then "FMO" + version 4.
        Assert.Equal(0x8F, tbs[0]);
        Assert.Equal(new byte[] { 0x63, (byte)'F', (byte)'M', (byte)'O', 0x04 }, tbs[1..6]);
    }

    [Fact]
    public void BuiltinRoot_TbsCbor_GoldenSha256()
    {
        // Protocol guard: if the signature array ever changes shape or field
        // order, every device in the field stops trusting newly built servers.
        var tbs = LoadBuiltin().ToTbsCbor();
        var hash = Convert.ToHexString(SHA256.HashData(tbs)).ToLowerInvariant();

        Assert.Equal("1d1bf0f07bbd5e985cd3c0aea2db28f45cc3a40202f1d8d8391c2eecacc40eb3", hash);
    }

    [Fact]
    public void VerifySelfSignature_WithTamperedSignature_ReturnsFalse()
    {
        var pki = TestPki.Create();

        Assert.False(pki.RootWithSignature(new byte[64]).VerifySelfSignature());
        Assert.True(pki.Root.VerifySelfSignature());
    }

    [Fact]
    public void FromJson_WithEmptyObject_Throws()
    {
        using var doc = JsonDocument.Parse("{}");

        Assert.Throws<KeyNotFoundException>(() => Sas.certs.RootCaCert.FromJson(doc.RootElement));
    }

    [Theory]
    [InlineData(1_900_000_000L, 1_900_000_000L, true)]
    [InlineData(1_900_000_000L, 1_899_999_999L, false)]
    [InlineData(1_900_000_000L, 1_900_000_001L, true)]
    public void IsExpired_UsesInclusiveExpiry(long exp, long now, bool expected)
    {
        var pki = TestPki.Create(new TestPkiOptions { RootExp = exp });

        Assert.Equal(expected, pki.Root.IsExpired(now));
    }
}
