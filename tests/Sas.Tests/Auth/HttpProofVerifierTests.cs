using Sas.Auth;
using Sas.certs;
using Sas.Tests.Fixtures;

namespace Sas.Tests.Auth;

public sealed class HttpProofVerifierTests
{
    private const long ServerUid = 5001;
    private const string Callsign = "BG5ESN";
    private const long TargetUid = 5001;
    private const string Url = "fmo.example.test";
    private const int Port = 1883;
    private const long Timestamp = 1_700_000_000;
    private const string Role = "user";

    private static readonly byte[] ServerFingerprint = Enumerable.Repeat((byte)0xAB, 32).ToArray();

    private static string Sign(TestPki pki, long timestamp = Timestamp, string role = Role,
        string url = Url, int port = Port, byte[]? fingerprint = null, UserCert? user = null,
        string callsign = Callsign, long serverUid = ServerUid, long targetUid = TargetUid)
    {
        var tbs = HttpProofVerifier.BuildTbs(serverUid, callsign, targetUid, url, port,
            fingerprint ?? ServerFingerprint, timestamp, user ?? pki.User, role);
        return Base64Url.Encode(Ed25519.Sign(pki.UserPrivateKey, tbs));
    }

    private static bool Verify(TestPki pki, string signature, long timestamp = Timestamp,
        string role = Role, string url = Url, int port = Port, byte[]? fingerprint = null,
        UserCert? user = null, string callsign = Callsign, long serverUid = ServerUid,
        long targetUid = TargetUid)
    {
        return HttpProofVerifier.Verify(serverUid, callsign, targetUid, url, port,
            fingerprint ?? ServerFingerprint, timestamp, user ?? pki.User, role, signature);
    }

    [Theory]
    [InlineData(0L, true)]
    [InlineData(120L, true)]
    [InlineData(-120L, true)]
    [InlineData(121L, false)]
    [InlineData(-121L, false)]
    public void IsTimestampValid_AllowsTwoMinuteDrift(long drift, bool expected)
    {
        Assert.Equal(expected, HttpProofVerifier.IsTimestampValid(Timestamp + drift, Timestamp));
    }

    [Fact]
    public void Verify_ValidProof_ReturnsTrue()
    {
        var pki = TestPki.Create();

        Assert.True(Verify(pki, Sign(pki)));
    }

    [Fact]
    public void Verify_TargetCallsignIsNormalisedToUppercase()
    {
        var pki = TestPki.Create();

        // Both sides upper-case the callsign, so case does not change the TBS.
        Assert.True(Verify(pki, Sign(pki, callsign: "bg5esn"), callsign: "BG5ESN"));
    }

    [Theory]
    [InlineData("serverUid")]
    [InlineData("targetUid")]
    [InlineData("callsign")]
    [InlineData("url")]
    [InlineData("port")]
    [InlineData("timestamp")]
    [InlineData("role")]
    public void Verify_AnyTamperedBoundField_ReturnsFalse(string field)
    {
        var pki = TestPki.Create();
        var signature = Sign(pki);

        var ok = field switch
        {
            "serverUid" => Verify(pki, signature, serverUid: ServerUid + 1),
            "targetUid" => Verify(pki, signature, targetUid: TargetUid + 1),
            "callsign" => Verify(pki, signature, callsign: "BG0AAA"),
            "url" => Verify(pki, signature, url: "other.example.test"),
            "port" => Verify(pki, signature, port: Port + 1),
            "timestamp" => Verify(pki, signature, timestamp: Timestamp + 1),
            "role" => Verify(pki, signature, role: "super"),
            _ => throw new ArgumentOutOfRangeException(nameof(field))
        };

        Assert.False(ok);
    }

    [Fact]
    public void Verify_TamperedFingerprint_ReturnsFalse()
    {
        var pki = TestPki.Create();
        var signature = Sign(pki);

        Assert.False(Verify(pki, signature, fingerprint: Enumerable.Repeat((byte)0xCD, 32).ToArray()));
    }

    [Fact]
    public void Verify_ProofSignedByAnotherUser_ReturnsFalse()
    {
        var pki = TestPki.Create();
        var other = TestPki.Create(new TestPkiOptions { Seed = 30 });

        Assert.False(Verify(pki, Sign(other)));
    }

    [Fact]
    public void Verify_CertificateSwappedAfterSigning_ReturnsFalse()
    {
        var pki = TestPki.Create();
        var other = TestPki.Create(new TestPkiOptions { Seed = 30 });
        var signature = Sign(pki);

        // Same key material would be needed; a different user cert changes the
        // bound fingerprint and therefore the signed payload.
        Assert.False(Verify(other, signature));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(31)]
    [InlineData(33)]
    public void Verify_UserPublicKeyWithWrongLength_ReturnsFalse(int length)
    {
        var pki = TestPki.Create();
        var brokenUser = new UserCert
        {
            IssuerSn = pki.User.IssuerSn,
            Callsign = pki.User.Callsign,
            Uid = pki.User.Uid,
            PublicKey = new byte[length],
            Iat = pki.User.Iat,
            Exp = pki.User.Exp,
            Signature = pki.User.Signature
        };

        Assert.False(Verify(pki, Sign(pki), user: brokenUser));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(31)]
    [InlineData(33)]
    public void Verify_FingerprintWithWrongLength_ReturnsFalse(int length)
    {
        var pki = TestPki.Create();

        Assert.False(Verify(pki, Sign(pki), fingerprint: new byte[length]));
    }

    [Theory]
    [InlineData("")]
    [InlineData("AAAA")]
    [InlineData("!!!")]
    public void Verify_MalformedSignature_ReturnsFalseWithoutThrowing(string signature)
    {
        var pki = TestPki.Create();

        Assert.False(Verify(pki, signature));
    }

    [Fact]
    public void Verify_TruncatedSignature_ReturnsFalse()
    {
        var pki = TestPki.Create();
        var tbs = HttpProofVerifier.BuildTbs(ServerUid, Callsign, TargetUid, Url, Port,
            ServerFingerprint, Timestamp, pki.User, Role);
        var signature = Ed25519.Sign(pki.UserPrivateKey, tbs);
        var broken = new byte[64];
        Array.Copy(signature, broken, 63);

        Assert.False(Verify(pki, Base64Url.Encode(broken)));
    }

    [Fact]
    public void BuildTbs_IsStableForSameInputs()
    {
        var pki = TestPki.Create();

        var a = HttpProofVerifier.BuildTbs(ServerUid, Callsign, TargetUid, Url, Port,
            ServerFingerprint, Timestamp, pki.User, Role);
        var b = HttpProofVerifier.BuildTbs(ServerUid, Callsign, TargetUid, Url, Port,
            ServerFingerprint, Timestamp, pki.User, Role);

        Assert.Equal(a, b);
        // CBOR array of 12 elements (0x8C).
        Assert.Equal(0x8C, a[0]);
    }
}
