using System.Text.Json;
using System.Text.Json.Nodes;
using Sas.certs;
using Sas.Trust;

namespace Sas.Tests.Fixtures;

/// <summary>
/// Builds correctly signed Root/Intermediate CRL JSON and installs it into the
/// production cache layout. Shared by CrlManager unit tests and the end-to-end
/// auth-pipeline tests so the on-disk format cannot drift between them.
/// </summary>
public static class TestCrl
{
    public const long DefaultThisUpdate = 1_700_000_000;
    public const long DefaultNextUpdate = 1_800_000_000;
    public const int ReasonKeyCompromise = 1;
    public const int ReasonSuperseded = 4;

    public static string RootCrlJson(
        TestPki pki,
        long crlNumber,
        IEnumerable<(long Sn, byte[] Fingerprint, long RevokedAt, int Reason)> entries,
        long nextUpdate = DefaultNextUpdate,
        long thisUpdate = DefaultThisUpdate)
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
            ["thisUpdate"] = thisUpdate,
            ["nextUpdate"] = nextUpdate,
            ["entries"] = array,
            ["signature"] = Base64Url.Encode(new byte[64])
        };

        var unsigned = RootCrl.FromJson(JsonDocument.Parse(draft.ToJsonString()).RootElement);
        var signature = Ed25519.Sign(pki.RootPrivateKey, unsigned.ToTbsCbor());
        draft["signature"] = Base64Url.Encode(signature);

        return draft.ToJsonString();
    }

    public static string IntermediateCrlJson(
        TestPki pki,
        long crlNumber,
        IEnumerable<(long Uid, byte[] Fingerprint, long RevokedAt, int Reason)> entries,
        long nextUpdate = DefaultNextUpdate,
        long thisUpdate = DefaultThisUpdate)
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
            ["thisUpdate"] = thisUpdate,
            ["nextUpdate"] = nextUpdate,
            ["entries"] = array,
            ["signature"] = Base64Url.Encode(new byte[64])
        };

        var unsigned = IntermediateCrl.FromJson(JsonDocument.Parse(draft.ToJsonString()).RootElement);
        var signature = Ed25519.Sign(pki.IntermediatePrivateKey, unsigned.ToTbsCbor());
        draft["signature"] = Base64Url.Encode(signature);

        return draft.ToJsonString();
    }

    public static string RootCacheDirectory(TempDirectory temp, RootCaCert root) =>
        Path.Combine(temp.Path, "crl",
            CrlManager.CacheDirectoryName("root", root.SubjectName, root.Fingerprint()));

    public static string IntermediateCacheDirectory(
        TempDirectory temp, IntermediateCaCert intermediate) =>
        Path.Combine(temp.Path, "crl",
            CrlManager.CacheDirectoryName(
                "intermediate", intermediate.SubjectName, intermediate.Fingerprint()));

    public static void WriteRootCache(TempDirectory temp, RootCaCert root, string json)
    {
        var dir = RootCacheDirectory(temp, root);
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "root.json"), json);
    }

    public static void WriteIntermediateCache(
        TempDirectory temp, IntermediateCaCert intermediate, string json)
    {
        var dir = IntermediateCacheDirectory(temp, intermediate);
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "intermediate.json"), json);
    }
}
