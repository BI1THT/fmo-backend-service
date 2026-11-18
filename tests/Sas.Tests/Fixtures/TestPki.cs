using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sas.Auth;
using Sas.certs;

namespace Sas.Tests.Fixtures;

public sealed record TestPkiOptions
{
    public long RootSn { get; init; } = 1;
    public long IssuerSn { get; init; } = 1001;
    public long UserUid { get; init; } = 50001;
    public string UserCallsign { get; init; } = "BG6VMZ";
    public string RootName { get; init; } = "bg5esn";
    public string IssuerName { get; init; } = "bd4wpw";
    public long Iat { get; init; } = 1_600_000_000;
    public long RootExp { get; init; } = 1_900_000_000;
    public long IssuerExp { get; init; } = 1_900_000_000;
    public long UserExp { get; init; } = 1_900_000_000;
    public long UidRangeStart { get; init; } = 5000;
    public long UidRangeEnd { get; init; } = 99999;
    public uint PathLen { get; init; } = 0;
    public string[] IssuingCountries { get; init; } = ["CN"];
    public string RootCrlUrl { get; init; } = "";
    public string IssuerCrlUrl { get; init; } = "";
    public byte Seed { get; init; } = 1;
}

/// <summary>
/// Full, real Ed25519 certificate chain used by auth-pipeline tests.
/// Everything is signed exactly like the protocol documents describe, so the
/// production verifiers run unmodified.
/// </summary>
public sealed class TestPki
{
    public RootCaCert Root { get; }
    public IntermediateCaCert Intermediate { get; }
    public UserCert User { get; }

    public byte[] RootPrivateKey { get; }
    public byte[] IntermediatePrivateKey { get; }
    public byte[] UserPrivateKey { get; }

    public string RootJson { get; }
    public string IntermediateJson { get; }
    public string UserJson { get; }

    private TestPki(
        RootCaCert root, IntermediateCaCert intermediate, UserCert user,
        byte[] rootPriv, byte[] interPriv, byte[] userPriv,
        string rootJson, string intermediateJson, string userJson)
    {
        Root = root;
        Intermediate = intermediate;
        User = user;
        RootPrivateKey = rootPriv;
        IntermediatePrivateKey = interPriv;
        UserPrivateKey = userPriv;
        RootJson = rootJson;
        IntermediateJson = intermediateJson;
        UserJson = userJson;
    }

    public static TestPki Create(TestPkiOptions? options = null)
    {
        var o = options ?? new TestPkiOptions();
        var countries = o.IssuingCountries
            .OrderBy(c => c, StringComparer.Ordinal)
            .ToArray();

        var rootKeys = KeyPair(o.Seed);
        var rootDraft = new RootCaCert
        {
            Sn = o.RootSn,
            IssuerName = o.RootName,
            IssuerEmail = "root@example.test",
            SubjectName = o.RootName,
            SubjectPubKey = rootKeys.Public,
            PathLen = 1,
            Crl = o.RootCrlUrl,
            License = "",
            KeyId = "root-key",
            Iat = o.Iat,
            Exp = o.RootExp
        };
        var rootSig = Ed25519.Sign(rootKeys.Private, rootDraft.ToTbsCbor());
        var root = new RootCaCert
        {
            Sn = o.RootSn,
            IssuerName = o.RootName,
            IssuerEmail = "root@example.test",
            SubjectName = o.RootName,
            SubjectPubKey = rootKeys.Public,
            PathLen = 1,
            Crl = o.RootCrlUrl,
            License = "",
            KeyId = "root-key",
            Iat = o.Iat,
            Exp = o.RootExp,
            Signature = rootSig
        };

        var interKeys = KeyPair((byte)(o.Seed + 1));
        var interDraft = new IntermediateCaCert
        {
            Sn = o.IssuerSn,
            IssuerSn = o.RootSn,
            IssuerName = o.RootName,
            IssuerPubKey = rootKeys.Public,
            SubjectName = o.IssuerName,
            SubjectEmail = "issuer@example.test",
            SubjectPubKey = interKeys.Public,
            PathLen = o.PathLen,
            KeyId = "intermediate-key",
            Crl = o.IssuerCrlUrl,
            License = "",
            UidRangeStart = o.UidRangeStart,
            UidRangeEnd = o.UidRangeEnd,
            IssuingCountries = countries,
            Iat = o.Iat,
            Exp = o.IssuerExp
        };
        var interSig = Ed25519.Sign(rootKeys.Private, interDraft.ToTbsCbor());
        var intermediate = new IntermediateCaCert
        {
            Sn = o.IssuerSn,
            IssuerSn = o.RootSn,
            IssuerName = o.RootName,
            IssuerPubKey = rootKeys.Public,
            SubjectName = o.IssuerName,
            SubjectEmail = "issuer@example.test",
            SubjectPubKey = interKeys.Public,
            PathLen = o.PathLen,
            KeyId = "intermediate-key",
            Crl = o.IssuerCrlUrl,
            License = "",
            UidRangeStart = o.UidRangeStart,
            UidRangeEnd = o.UidRangeEnd,
            IssuingCountries = countries,
            Iat = o.Iat,
            Exp = o.IssuerExp,
            Signature = interSig
        };

        var userKeys = KeyPair((byte)(o.Seed + 2));
        var callsign = o.UserCallsign.ToUpperInvariant();
        var userDraft = new UserCert
        {
            IssuerSn = o.IssuerSn,
            Callsign = callsign,
            Uid = o.UserUid,
            PublicKey = userKeys.Public,
            Iat = o.Iat,
            Exp = o.UserExp
        };
        var userSig = Ed25519.Sign(interKeys.Private, userDraft.ToTbsCbor());
        var user = new UserCert
        {
            IssuerSn = o.IssuerSn,
            Callsign = callsign,
            Uid = o.UserUid,
            PublicKey = userKeys.Public,
            Iat = o.Iat,
            Exp = o.UserExp,
            Signature = userSig
        };

        var rootJson = SerializeRoot(root, rootKeys.Public, rootSig);
        var interJson = SerializeIntermediate(intermediate, countries, interSig);
        var userJson = SerializeUser(user, userSig);

        return new TestPki(root, intermediate, user,
            rootKeys.Private, interKeys.Private, userKeys.Private,
            rootJson, interJson, userJson);
    }

    public byte[] SignProof(
        long serverUid,
        string targetCallsign,
        long targetUid,
        string targetUrl,
        int targetPort,
        byte[] serverFingerprint,
        long timestamp,
        string role)
    {
        var tbs = HttpProofVerifier.BuildTbs(serverUid, targetCallsign, targetUid,
            targetUrl, targetPort, serverFingerprint, timestamp, User, role);
        return Ed25519.Sign(UserPrivateKey, tbs);
    }

    /// <summary>
    /// Builds the decoded password JSON. Pass <paramref name="proofSignature"/>
    /// to inject an invalid signature, or leave null for a valid one.
    /// </summary>
    public string BuildPayloadJson(
        long serverUid,
        string targetCallsign,
        long targetUid,
        string targetUrl,
        int targetPort,
        string serverFingerprint,
        long timestamp,
        string role,
        string? proofSignature = null)
    {
        var signature = proofSignature ?? Base64Url.Encode(SignProof(
            serverUid, targetCallsign, targetUid, targetUrl, targetPort,
            Base64Url.Decode(serverFingerprint), timestamp, role));

        var payload = new JsonObject
        {
            ["certPackage"] = new JsonObject
            {
                ["intermediateCert"] = JsonNode.Parse(IntermediateJson),
                ["userCert"] = JsonNode.Parse(UserJson)
            },
            ["role"] = role,
            ["targetCallsign"] = targetCallsign,
            ["targetUID"] = targetUid,
            ["targetUrl"] = targetUrl,
            ["targetPort"] = targetPort,
            ["serverFingerprint"] = serverFingerprint,
            ["timestamp"] = timestamp,
            ["proof"] = new JsonObject { ["signature"] = signature }
        };

        return payload.ToJsonString();
    }

    public string BuildPassword(
        long serverUid,
        string targetCallsign,
        long targetUid,
        string targetUrl,
        int targetPort,
        string serverFingerprint,
        long timestamp,
        string role,
        string? proofSignature = null)
    {
        var json = BuildPayloadJson(serverUid, targetCallsign, targetUid, targetUrl,
            targetPort, serverFingerprint, timestamp, role, proofSignature);
        return Base64Url.Encode(Encoding.UTF8.GetBytes(json));
    }

    public static string EncodePassword(string json) =>
        Base64Url.Encode(Encoding.UTF8.GetBytes(json));

    public static string RandomFingerprint(byte fill)
    {
        var bytes = Enumerable.Repeat(fill, 32).ToArray();
        return Base64Url.Encode(bytes);
    }

    /// <summary>
    /// Rebuilds the root with a replacement signature (used for tamper tests).
    /// </summary>
    public RootCaCert RootWithSignature(byte[] signature) => new()
    {
        Sn = Root.Sn,
        IssuerName = Root.IssuerName,
        IssuerEmail = Root.IssuerEmail,
        SubjectName = Root.SubjectName,
        SubjectPubKey = Root.SubjectPubKey,
        PathLen = Root.PathLen,
        Crl = Root.Crl,
        License = Root.License,
        KeyId = Root.KeyId,
        Iat = Root.Iat,
        Exp = Root.Exp,
        Signature = signature
    };

    private static (byte[] Public, byte[] Private) KeyPair(byte seed)
    {
        var seedBytes = Enumerable.Repeat(seed, 32).ToArray();
        Chaos.NaCl.Ed25519.KeyPairFromSeed(out var publicKey, out var privateKey, seedBytes);
        return (publicKey, privateKey);
    }

    private static string SerializeRoot(RootCaCert root, byte[] publicKey, byte[] signature) =>
        JsonSerializer.Serialize(new
        {
            sn = root.Sn,
            type = "rootCA",
            issuer = new { name = root.IssuerName, email = root.IssuerEmail },
            subject = new { name = root.SubjectName, publicKey = Base64Url.Encode(publicKey) },
            extensions = new
            {
                isCA = true,
                pathLen = root.PathLen,
                crl = root.Crl,
                license = root.License,
                keyId = root.KeyId
            },
            iat = root.Iat,
            exp = root.Exp,
            signatureAlgorithm = "Ed25519",
            signature = Base64Url.Encode(signature)
        });

    private static string SerializeIntermediate(IntermediateCaCert cert, string[] countries, byte[] signature) =>
        JsonSerializer.Serialize(new
        {
            sn = cert.Sn,
            type = "intermediateCA",
            issuer = new
            {
                sn = cert.IssuerSn,
                name = cert.IssuerName,
                publicKey = Base64Url.Encode(cert.IssuerPubKey)
            },
            subject = new
            {
                name = cert.SubjectName,
                email = cert.SubjectEmail,
                publicKey = Base64Url.Encode(cert.SubjectPubKey)
            },
            extensions = new
            {
                isCA = true,
                pathLen = cert.PathLen,
                keyId = cert.KeyId,
                crl = cert.Crl,
                license = cert.License,
                uidRange = new { start = cert.UidRangeStart, end = cert.UidRangeEnd },
                issuingCountries = countries
            },
            iat = cert.Iat,
            exp = cert.Exp,
            signatureAlgorithm = "Ed25519",
            signature = Base64Url.Encode(signature)
        });

    private static string SerializeUser(UserCert cert, byte[] signature) =>
        JsonSerializer.Serialize(new
        {
            type = "userCert",
            issuerSn = cert.IssuerSn,
            subject = new
            {
                callsign = cert.Callsign,
                uid = cert.Uid,
                publicKey = Base64Url.Encode(cert.PublicKey)
            },
            iat = cert.Iat,
            exp = cert.Exp,
            signatureAlgorithm = "Ed25519",
            signature = Base64Url.Encode(signature)
        });
}
