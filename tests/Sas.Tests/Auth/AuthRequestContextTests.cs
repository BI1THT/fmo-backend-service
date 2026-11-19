using System.Text.Json;
using System.Text.RegularExpressions;
using Sas.Auth;

namespace Sas.Tests.Auth;

public sealed class AuthRequestContextTests
{
    [Fact]
    public void Hash_ReturnsFirst16LowercaseHexOfSha256()
    {
        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223...
        Assert.Equal("ba7816bf8f01cfea", AuthRequestContext.Hash("abc"));
    }

    [Fact]
    public void Hash_IsStableAndDifferentForDifferentInputs()
    {
        Assert.Equal(AuthRequestContext.Hash("payload"), AuthRequestContext.Hash("payload"));
        Assert.NotEqual(AuthRequestContext.Hash("payload"), AuthRequestContext.Hash("payload2"));
    }

    [Fact]
    public void Constructor_InitialisesCallsignAndPasswordMetrics()
    {
        var ctx = new AuthRequestContext("bg6vmz", "secret", "req-1");

        Assert.Equal("bg6vmz", ctx.Username);
        Assert.Equal("bg6vmz", ctx.Callsign);
        Assert.Equal("secret", ctx.PasswordRaw);
        Assert.Equal(6, ctx.PasswordLength);
        Assert.Equal(AuthRequestContext.Hash("secret"), ctx.PasswordHash);
        Assert.Equal("req-1", ctx.RequestId);
        Assert.Equal("-", ctx.PayloadHash);
        Assert.Equal(0, ctx.PayloadLength);
    }

    [Fact]
    public void SetDecodedPayload_RecordsJsonAndHash()
    {
        const string json = """{"targetUID":5001}""";
        using var doc = JsonDocument.Parse(json);
        var ctx = new AuthRequestContext("BG6VMZ", "secret", "req-1");

        ctx.SetDecodedPayload(json, doc.RootElement.Clone());

        Assert.Equal(json, ctx.PayloadJson);
        Assert.Equal(System.Text.Encoding.UTF8.GetByteCount(json), ctx.PayloadLength);
        Assert.Equal(AuthRequestContext.Hash(json), ctx.PayloadHash);
        Assert.True(ctx.Payload.HasValue);
        Assert.Equal(5001, ctx.Payload.Value.GetProperty("targetUID").GetInt64());
    }

    [Fact]
    public void ToRecord_WithoutPayload_OmitsSecretsButKeepsMetrics()
    {
        const string json = """{"role":"user"}""";
        using var doc = JsonDocument.Parse(json);
        var ctx = new AuthRequestContext("BG6VMZ", "secret", "req-1");
        ctx.SetDecodedPayload(json, doc.RootElement.Clone());
        ctx.RootSn = 1;
        ctx.RootName = "bg5esn";
        ctx.IssuerSn = 1001;
        ctx.IssuerName = "bd4wpw";
        ctx.UserUid = 50001;
        ctx.Role = "user";
        ctx.ClaimedRole = "user";
        ctx.TargetCallsign = "BG5ESN";
        ctx.TargetUid = 5001;
        ctx.TargetUrl = "fmo.example.test";
        ctx.TargetPort = 1883;
        ctx.Timestamp = 1_700_000_000;

        var record = ctx.ToRecord("deny", "timestamp expired", includePayload: false);

        Assert.Equal("deny", record.Result);
        Assert.Equal("timestamp expired", record.Reason);
        Assert.Null(record.Password);
        Assert.Null(record.Payload);
        Assert.Equal(6, record.PasswordLength);
        Assert.Equal(AuthRequestContext.Hash("secret"), record.PasswordSha256);
        Assert.Equal(System.Text.Encoding.UTF8.GetByteCount(json), record.PayloadLength);
        Assert.Equal(AuthRequestContext.Hash(json), record.PayloadSha256);
        Assert.Equal(1, record.RootSn);
        Assert.Equal("bg5esn", record.RootName);
        Assert.Equal(1001, record.IssuerSn);
        Assert.Equal("bd4wpw", record.IssuerName);
        Assert.Equal(50001, record.UserUid);
        Assert.Equal("user", record.Role);
        Assert.Equal("user", record.ClaimedRole);
        Assert.Equal("BG5ESN", record.TargetCallsign);
        Assert.Equal(5001, record.TargetUid);
        Assert.Equal("fmo.example.test", record.TargetUrl);
        Assert.Equal(1883, record.TargetPort);
        Assert.Equal(1_700_000_000, record.Timestamp);
        Assert.Equal(1, record.V);
    }

    [Fact]
    public void ToRecord_IncludesRootAndIssuerFingerprints()
    {
        var ctx = new AuthRequestContext("BG6VMZ", "secret", "req-1")
        {
            RootFp = "aabbccdd",
            IssuerFp = "eeff0011"
        };

        var record = ctx.ToRecord("allow", null, includePayload: false);

        Assert.Equal("aabbccdd", record.RootFp);
        Assert.Equal("eeff0011", record.IssuerFp);
    }

    [Fact]
    public void ToRecord_WithPayload_IncludesRawPasswordAndJson()
    {
        using var doc = JsonDocument.Parse("""{"role":"super"}""");
        var ctx = new AuthRequestContext("BG6VMZ", "secret", "req-1");
        ctx.SetDecodedPayload("""{"role":"super"}""", doc.RootElement.Clone());

        var record = ctx.ToRecord("allow", null, includePayload: true);

        Assert.Equal("secret", record.Password);
        Assert.NotNull(record.Payload);
        Assert.Equal("super", record.Payload!.Value.GetProperty("role").GetString());
    }

    [Fact]
    public void ToRecord_TimestampUsesIso8601WithOffset()
    {
        var ctx = new AuthRequestContext("BG6VMZ", "secret", "req-1");

        var record = ctx.ToRecord("allow", null, includePayload: false);

        Assert.Matches(new Regex(@"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}[+-]\d{2}:\d{2}$"), record.Ts);
    }

    [Fact]
    public void PayloadLength_CountsUtf8Bytes()
    {
        const string json = """{"k":"呼号"}""";
        using var doc = JsonDocument.Parse(json);
        var ctx = new AuthRequestContext("BG6VMZ", "secret", "req-1");

        ctx.SetDecodedPayload(json, doc.RootElement.Clone());

        Assert.Equal(System.Text.Encoding.UTF8.GetByteCount(json), ctx.PayloadLength);
    }

    [Fact]
    public void PasswordLength_CountsUtf8Bytes()
    {
        const string password = "呼号";
        var ctx = new AuthRequestContext("BG6VMZ", password, "req-1");

        Assert.Equal(System.Text.Encoding.UTF8.GetByteCount(password), ctx.PasswordLength);
    }
}
