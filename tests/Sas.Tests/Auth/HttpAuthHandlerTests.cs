using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sas.Auth;
using Sas.certs;
using Sas.Logging;
using Sas.Tests.Fixtures;
using Sas.Trust;

namespace Sas.Tests.Auth;

public sealed class HttpAuthHandlerTests
{
    private static AuthDeniedException Deny(AuthTestEnvironment env,
        string? username = null, string? password = null)
    {
        return Assert.Throws<AuthDeniedException>(() =>
            env.Handler.Process(username ?? env.Username, password ?? env.ValidPassword(), "req-test"));
    }

    private static string Mutate(AuthTestEnvironment env, Action<JsonObject> mutate, string role = "user")
    {
        var node = JsonNode.Parse(env.ValidPayloadJson(role))!.AsObject();
        mutate(node);
        return TestPki.EncodePassword(node.ToJsonString());
    }

    // ---------------------------------------------------------------- allow

    [Fact]
    public void Process_ValidUser_ReturnsAllowWithAcl()
    {
        using var env = new AuthTestEnvironment();

        var result = env.ProcessValid();

        Assert.Equal(env.Username, result.Callsign);
        Assert.Equal(env.Pki.User.Uid, result.Uid);
        Assert.Equal("user", result.Role);
        Assert.False(result.IsSuperuser);
        Assert.Equal(env.Now, result.IssuedAt);
        Assert.Contains("FMO/RAW", result.AllTopics);
        Assert.Contains("FMO/QSO/+", result.PubTopics);
        Assert.Contains($"FMO/QSO/UID/{env.Pki.User.Uid}", result.SubTopics);
        Assert.Contains($"FMO/LATE/UID_V1/{env.Pki.User.Uid}", result.SubTopics);
    }

    [Fact]
    public void Process_ServerOwnCert_IsSuperuser()
    {
        using var env = new AuthTestEnvironment(pki: new TestPkiOptions
        {
            UserUid = TestConfig.DefaultServerUid
        });

        var result = env.Handler.Process(env.Username, env.ValidPassword("super"), "req-test");

        Assert.Equal("super", result.Role);
        Assert.True(result.IsSuperuser);
        Assert.Contains("FMO/MUTELIST", result.PubTopics);
    }

    [Fact]
    public void Process_LowercaseUsername_IsAccepted()
    {
        using var env = new AuthTestEnvironment();

        var result = env.Handler.Process(env.Username.ToLowerInvariant(), env.ValidPassword(), "req-test");

        Assert.Equal(env.Username, result.Callsign);
    }

    [Fact]
    public void Process_ExpireAtRespectsConfiguredTtlJitter()
    {
        using var env = new AuthTestEnvironment();
        env.Config.Http.TtlSec = 100;

        var result = env.ProcessValid();
        var jitter = Math.Min(60, Math.Max(1, env.Config.Http.TtlSec / 2));

        Assert.InRange(result.ExpireAt, env.Now + 100 - jitter, env.Now + 100 + jitter);
    }

    [Theory]
    [InlineData(0, 1)]
    [InlineData(1, 1)]
    [InlineData(10, 5)]
    [InlineData(14400, 60)]
    public void Process_TtlJitterIsClamped(int ttlSec, int expectedJitter)
    {
        using var env = new AuthTestEnvironment();
        env.Config.Http.TtlSec = ttlSec;

        var result = env.ProcessValid();

        Assert.InRange(result.ExpireAt, env.Now + ttlSec - expectedJitter, env.Now + ttlSec + expectedJitter);
    }

    [Fact]
    public void Process_MatchingClusterEntry_IsAllowed()
    {
        using var env = new AuthTestEnvironment();
        const string clusterCallsign = "BG0CLU";
        const string clusterHost = "cluster.example.test";
        const int clusterPort = 2883;
        const long clusterUid = 7001;
        var clusterFp = TestPki.RandomFingerprint(0x7E);

        env.Config.Mqtt.Clusters =
        [
            new Config.MqttConfig.ClusterEntry
            {
                Uid = clusterUid,
                Callsign = clusterCallsign,
                MqttHost = clusterHost,
                MqttPort = clusterPort,
                CertFingerprint = clusterFp
            }
        ];

        var password = env.Pki.BuildPassword(clusterUid, clusterCallsign, clusterUid,
            clusterHost, clusterPort, clusterFp, env.Now, "user");

        var result = env.Handler.Process(env.Username, password, "req-test");

        Assert.Equal("user", result.Role);
    }

    [Fact]
    public void Process_ConfiguredAdminEntry_ReturnsAdminRole()
    {
        using var env = new AuthTestEnvironment();
        env.Config.Server.Admins =
        [
            new Config.AdminEntry
            {
                Uid = env.Pki.User.Uid,
                CertFingerprint = Base64Url.Encode(env.Pki.User.Fingerprint()),
                Role = "admin"
            }
        ];

        var result = env.Handler.Process(env.Username, env.ValidPassword("admin"), "req-test");

        Assert.Equal("admin", result.Role);
        Assert.False(result.IsSuperuser);
    }

    [Fact]
    public void Process_AdminEntryWithCustomRole_IsHonoured()
    {
        using var env = new AuthTestEnvironment();
        env.Config.Server.Admins =
        [
            new Config.AdminEntry
            {
                Uid = env.Pki.User.Uid,
                CertFingerprint = Base64Url.Encode(env.Pki.User.Fingerprint()),
                Role = "ops"
            }
        ];

        var result = env.Handler.Process(env.Username, env.ValidPassword("ops"), "req-test");

        Assert.Equal("ops", result.Role);
    }

    [Fact]
    public void Process_EmptyClaimedRole_SkipsRoleCrossCheck()
    {
        using var env = new AuthTestEnvironment();

        var result = env.Handler.Process(env.Username, env.ValidPassword(""), "req-test");

        Assert.Equal("user", result.Role);
    }

    // ---------------------------------------------------------------- deny

    [Theory]
    [InlineData("%%%")]
    [InlineData("not base64url")]
    public void Process_InvalidBase64Password_DeniesWithoutBreakerKey(string password)
    {
        using var env = new AuthTestEnvironment();

        var ex = Deny(env, password: password);

        Assert.Contains("invalid password format", ex.Message);
        Assert.Null(ex.BreakerKey);
    }

    [Fact]
    public void Process_PasswordNotJson_Denies()
    {
        using var env = new AuthTestEnvironment();

        var ex = Deny(env, password: Base64Url.Encode(Encoding.UTF8.GetBytes("hello")));

        Assert.Contains("invalid password format", ex.Message);
        Assert.Null(ex.BreakerKey);
    }

    [Fact]
    public void Process_MissingUserCert_Denies()
    {
        using var env = new AuthTestEnvironment();

        var password = Mutate(env, p => p["certPackage"]!.AsObject().Remove("userCert"));

        var ex = Deny(env, password: password);
        Assert.Contains("invalid certificate format", ex.Message);
    }

    [Fact]
    public void Process_InvalidIssuingCountry_Denies()
    {
        using var env = new AuthTestEnvironment();

        var password = Mutate(env, p =>
            p["certPackage"]!["intermediateCert"]!["extensions"]!["issuingCountries"] = new JsonArray("cn"));

        var ex = Deny(env, password: password);
        Assert.Contains("invalid certificate format", ex.Message);
    }

    [Fact]
    public void Process_InvalidCertificateCallsign_Denies()
    {
        using var env = new AuthTestEnvironment(pki: new TestPkiOptions
        {
            UserCallsign = "BG6 VMZ"
        });

        var ex = Deny(env);

        Assert.Contains("invalid certificate callsign", ex.Message);
    }

    [Theory]
    [InlineData("callsign")]
    [InlineData("uid")]
    [InlineData("url")]
    [InlineData("port")]
    public void Process_ServerIdentityMismatch_Denies(string field)
    {
        using var env = new AuthTestEnvironment();

        var password = Mutate(env, p =>
        {
            switch (field)
            {
                case "callsign": p["targetCallsign"] = "BG0AAA"; break;
                case "uid": p["targetUID"] = env.Config.Server.Uid + 1; break;
                case "url": p["targetUrl"] = "other.example.test"; break;
                case "port": p["targetPort"] = env.Config.Mqtt.Port + 1; break;
            }
        });

        var ex = Deny(env, password: password);

        Assert.Contains("server identity mismatch", ex.Message);
        Assert.Null(ex.BreakerKey);
    }

    [Fact]
    public void Process_ServerFingerprintWithWrongLength_Denies()
    {
        using var env = new AuthTestEnvironment();

        var password = env.Pki.BuildPassword(env.Config.Server.Uid, env.Config.Server.Callsign,
            env.Config.Server.Uid, env.Config.Mqtt.Host, env.Config.Mqtt.Port,
            "abc", env.Now, "user", proofSignature: "");

        var ex = Deny(env, password: password);

        Assert.Contains("invalid server fingerprint", ex.Message);
        Assert.Null(ex.BreakerKey);
    }

    [Theory]
    [InlineData(-121L)]
    [InlineData(121L)]
    public void Process_TimestampOutsideWindow_Denies(long drift)
    {
        using var env = new AuthTestEnvironment();

        var password = env.Pki.BuildPassword(env.Config.Server.Uid, env.Config.Server.Callsign,
            env.Config.Server.Uid, env.Config.Mqtt.Host, env.Config.Mqtt.Port,
            env.ServerFingerprint, env.Now + drift, "user");

        var ex = Deny(env, password: password);

        Assert.Contains("timestamp expired", ex.Message);
        Assert.Null(ex.BreakerKey);
    }

    [Fact]
    public void Process_NoTrustedRoot_Denies()
    {
        using var env = new AuthTestEnvironment();
        using var emptyRoots = new TempDirectory("roots-empty");
        var handler = new HttpAuthHandler(env.Config, new RootCaStore(emptyRoots.Path),
            new CertVerifier(), env.Crl, env.Acl, env.Archive, env.Clock, new Random(1));

        var ex = Assert.Throws<AuthDeniedException>(
            () => handler.Process(env.Username, env.ValidPassword(), "req-test"));

        Assert.Contains("chain invalid: no trusted root", ex.Message);
    }

    [Fact]
    public void Process_ExpiredIntermediate_Denies()
    {
        using var env = new AuthTestEnvironment(pki: new TestPkiOptions
        {
            IssuerExp = 1_700_000_000
        });

        var ex = Deny(env);

        Assert.Contains("chain invalid: intermediate CA expired", ex.Message);
    }

    [Fact]
    public void Process_ExpiredUser_Denies()
    {
        using var env = new AuthTestEnvironment(pki: new TestPkiOptions
        {
            UserExp = 1_700_000_000
        });

        var ex = Deny(env);

        Assert.Contains("chain invalid: user certificate expired", ex.Message);
    }

    [Fact]
    public void Process_UserOutsideUidRange_Denies()
    {
        using var env = new AuthTestEnvironment(pki: new TestPkiOptions
        {
            UidRangeStart = 1000,
            UidRangeEnd = 2000,
            UserUid = 50001
        });

        var ex = Deny(env);

        Assert.Contains("chain invalid: UID out of intermediate CA range", ex.Message);
    }

    [Fact]
    public void Process_IntermediateWithNonZeroPathLen_IsRejected_CurrentBehavior()
    {
        // Current behaviour: IntermediateCaCert.FromJson ignores the JSON
        // "pathLen" extension, so the rebuilt TBS no longer matches the
        // signature and the chain is rejected as untrusted. The pathLen check
        // inside CertVerifier is therefore unreachable through HTTP auth.
        using var env = new AuthTestEnvironment(pki: new TestPkiOptions { PathLen = 1 });

        var ex = Deny(env);

        Assert.Contains("chain invalid: no trusted root", ex.Message);
    }

    [Fact]
    public void Process_UserSignedByDifferentIntermediate_Denies()
    {
        using var env = new AuthTestEnvironment();
        var other = TestPki.Create(new TestPkiOptions { Seed = 40 });

        var password = Mutate(env, p =>
            p["certPackage"]!["userCert"] = JsonNode.Parse(other.UserJson));

        var ex = Deny(env, password: password);

        Assert.Contains("chain invalid: user certificate signature invalid", ex.Message);
    }

    [Fact]
    public void Process_UsernameMismatch_DeniesAndCountsForBreaker()
    {
        using var env = new AuthTestEnvironment();

        var ex = Deny(env, username: "BG0AAA");

        Assert.Contains("username mismatch", ex.Message);
        Assert.Equal(env.Pki.User.Callsign, ex.BreakerKey);
    }

    [Fact]
    public void Process_IssuerNotInWhitelist_Denies()
    {
        using var env = new AuthTestEnvironment();
        env.Config.Trust.AllowIssuerSn = [9999];

        var ex = Deny(env);

        Assert.Contains("intermediate not trusted", ex.Message);
        Assert.Equal(env.Pki.User.Callsign, ex.BreakerKey);
    }

    [Fact]
    public void Process_IssuerInWhitelist_Allows()
    {
        using var env = new AuthTestEnvironment();
        env.Config.Trust.AllowIssuerSn = [env.Pki.Intermediate.Sn];

        var result = env.ProcessValid();

        Assert.Equal("user", result.Role);
    }

    [Fact]
    public void Process_RevokedIntermediate_Denies()
    {
        using var env = new AuthTestEnvironment();
        env.Crl.RevokeIntermediate(env.Pki.Intermediate.Sn, env.Pki.Intermediate.Fingerprint());

        var ex = Deny(env);

        Assert.Contains("intermediate revoked", ex.Message);
        Assert.Equal(env.Pki.User.Callsign, ex.BreakerKey);
    }

    [Fact]
    public void Process_RevokedUser_Denies()
    {
        using var env = new AuthTestEnvironment();
        env.Crl.RevokeUser(env.Pki.User.Uid, env.Pki.User.Fingerprint());

        var ex = Deny(env);

        Assert.Contains("user revoked", ex.Message);
        Assert.Equal(env.Pki.User.Callsign, ex.BreakerKey);
    }

    [Fact]
    public void Process_RoleMismatch_Denies()
    {
        using var env = new AuthTestEnvironment();

        var ex = Deny(env, password: env.ValidPassword("super"));

        Assert.Contains("role mismatch", ex.Message);
        Assert.Equal(env.Pki.User.Callsign, ex.BreakerKey);
    }

    [Fact]
    public void Process_MalformedServerFingerprintEncoding_Denies()
    {
        using var env = new AuthTestEnvironment();
        var badFingerprint = new string('*', 43);

        var password = env.Pki.BuildPassword(env.Config.Server.Uid, env.Config.Server.Callsign,
            env.Config.Server.Uid, env.Config.Mqtt.Host, env.Config.Mqtt.Port,
            badFingerprint, env.Now, "user", proofSignature: "");

        var ex = Deny(env, password: password);

        Assert.Contains("invalid server fingerprint", ex.Message);
    }

    [Fact]
    public void Process_MissingConfiguredServerFingerprint_Denies()
    {
        using var env = new AuthTestEnvironment();
        env.Config.Server.CertFingerprint = "";

        var ex = Deny(env);

        Assert.Contains("server cert fingerprint not configured", ex.Message);
    }

    [Fact]
    public void Process_ConfiguredServerFingerprintNotBase64Url_Denies()
    {
        using var env = new AuthTestEnvironment();
        env.Config.Server.CertFingerprint = new string('*', 43);

        var ex = Deny(env);

        Assert.Contains("invalid base64url", ex.Message);
    }

    [Fact]
    public void Process_ConfiguredServerFingerprintWrongLength_Denies()
    {
        using var env = new AuthTestEnvironment();
        env.Config.Server.CertFingerprint = Base64Url.Encode(new byte[16]);

        var ex = Deny(env);

        Assert.Contains("server fingerprint mismatch", ex.Message);
    }

    [Fact]
    public void Process_ServerFingerprintMismatch_Denies()
    {
        using var env = new AuthTestEnvironment();
        env.Config.Server.CertFingerprint = TestPki.RandomFingerprint(0xCD);

        var ex = Deny(env);

        Assert.Contains("server fingerprint mismatch", ex.Message);
        Assert.Equal(env.Pki.User.Callsign, ex.BreakerKey);
    }

    [Fact]
    public void Process_InvalidProofSignature_Denies()
    {
        using var env = new AuthTestEnvironment();

        var ex = Deny(env, password: env.Pki.BuildPassword(
            env.Config.Server.Uid, env.Config.Server.Callsign, env.Config.Server.Uid,
            env.Config.Mqtt.Host, env.Config.Mqtt.Port, env.ServerFingerprint, env.Now, "user",
            proofSignature: Base64Url.Encode(new byte[64])));

        Assert.Contains("proof invalid", ex.Message);
        Assert.Equal(env.Pki.User.Callsign, ex.BreakerKey);
    }

    // ---------------------------------------------------------------- archive

    private static JsonElement SingleRecord(AuthTestEnvironment env)
    {
        env.Archive.Flush();
        var records = ArchiveProbe.ReadAll(env.Config.Archive.Dir);
        return Assert.Single(records);
    }

    [Fact]
    public void Process_Allow_WritesRecordWithFullPayload()
    {
        using var env = new AuthTestEnvironment();

        env.ProcessValid();

        var record = SingleRecord(env);
        Assert.Equal("allow", record.GetProperty("result").GetString());
        Assert.Equal(env.Username, record.GetProperty("callsign").GetString());
        Assert.Equal("user", record.GetProperty("role").GetString());
        Assert.NotEqual(JsonValueKind.Null, record.GetProperty("password").ValueKind);
        Assert.NotEqual(JsonValueKind.Null, record.GetProperty("payload").ValueKind);
    }

    [Fact]
    public void Process_DenyWithDecodablePayload_WritesSummary()
    {
        using var env = new AuthTestEnvironment();

        Deny(env, password: env.ValidPassword("super"));

        var record = SingleRecord(env);
        Assert.Equal("deny", record.GetProperty("result").GetString());
        Assert.Contains("role mismatch", record.GetProperty("reason").GetString());
        Assert.Equal(JsonValueKind.Null, record.GetProperty("password").ValueKind);
        Assert.Equal(JsonValueKind.Null, record.GetProperty("payload").ValueKind);
        Assert.True(record.GetProperty("passwordLength").GetInt32() > 0);
        Assert.True(record.GetProperty("payloadLength").GetInt32() > 0);
    }

    [Fact]
    public void Process_DenyBeforePayloadDecode_DoesNotArchive()
    {
        using var env = new AuthTestEnvironment();

        Deny(env, password: "%%%");

        env.Archive.Flush();
        Assert.Empty(ArchiveProbe.ReadAll(env.Config.Archive.Dir));
    }

    [Fact]
    public void Process_DenyWhenRecordDeniedDisabled_DoesNotArchive()
    {
        using var env = new AuthTestEnvironment();
        env.Config.Archive.RecordDenied = false;

        Deny(env, password: env.ValidPassword("super"));

        env.Archive.Flush();
        Assert.Empty(ArchiveProbe.ReadAll(env.Config.Archive.Dir));
    }

    [Fact]
    public void Process_DenyWithRecordDeniedPayload_IncludesSecrets()
    {
        using var env = new AuthTestEnvironment();
        env.Config.Archive.RecordDeniedPayload = true;

        Deny(env, password: env.ValidPassword("super"));

        var record = SingleRecord(env);
        Assert.NotEqual(JsonValueKind.Null, record.GetProperty("password").ValueKind);
        Assert.NotEqual(JsonValueKind.Null, record.GetProperty("payload").ValueKind);
    }

    [Fact]
    public void Process_DenyWithFullSampleRate_IncludesSecrets()
    {
        using var env = new AuthTestEnvironment();
        env.Config.Archive.DeniedPayloadSampleRate = 1.0;

        Deny(env, password: env.ValidPassword("super"));

        var record = SingleRecord(env);
        Assert.NotEqual(JsonValueKind.Null, record.GetProperty("password").ValueKind);
    }

    [Fact]
    public void Process_DenyReasonComponentsAreSanitised()
    {
        using var env = new AuthTestEnvironment();

        // targetUrl is attacker-controlled and gets escaped/truncated by LogSafe
        // before it reaches the reason string.
        var password = Mutate(env, p => p["targetUrl"] = "bad\r\n" + new string('a', 600));

        Deny(env, password: password);

        var record = SingleRecord(env);
        var reason = record.GetProperty("reason").GetString()!;
        Assert.DoesNotContain('\n', reason);
        Assert.DoesNotContain('\r', reason);
        Assert.True(reason.Length <= 513);
    }
}
