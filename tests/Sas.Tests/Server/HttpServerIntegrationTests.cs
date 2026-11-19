using System.Net;
using System.Text;
using System.Text.Json;
using Sas.Auth;
using Sas.Server;
using Sas.Tests.Fixtures;
using Sas.Trust;

namespace Sas.Tests.Server;

[Trait("Category", "Integration")]
public sealed class HttpServerIntegrationTests
{
    private static AuthRateLimiter UnlimitedLimiter() =>
        new(new RateLimitConfig { GlobalPerMinute = 10_000, BreakerEnabled = false });

    private static StringContent Body(string username, string password) =>
        new(JsonSerializer.Serialize(new { username, password }), Encoding.UTF8, "application/json");

    private static async Task<JsonElement> ReadJson(HttpResponseMessage response)
    {
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return doc.RootElement.Clone();
    }

    [Fact]
    public async Task Post_ValidCredentials_ReturnsAllowWithAcl()
    {
        using var env = new AuthTestEnvironment();
        await using var server = new HttpServerHarness(env.Handler, new EmqxResponseTemplate(), UnlimitedLimiter());
        using var client = server.CreateClient();

        var response = await client.PostAsync("auth", Body(env.Username, env.ValidPassword()));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);

        var json = await ReadJson(response);
        Assert.Equal("allow", json.GetProperty("result").GetString());
        Assert.Equal(env.Username, json.GetProperty("client_attrs").GetProperty("callsign").GetString());
        Assert.True(json.GetProperty("acl").GetArrayLength() > 0);
        Assert.True(json.GetProperty("expire_at").GetInt64() > env.Now);
    }

    [Fact]
    public async Task Get_IsDenied()
    {
        using var env = new AuthTestEnvironment();
        await using var server = new HttpServerHarness(env.Handler, new EmqxResponseTemplate(), UnlimitedLimiter());
        using var client = server.CreateClient();

        var response = await client.GetAsync("auth");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("deny", (await ReadJson(response)).GetProperty("result").GetString());
    }

    [Fact]
    public async Task WrongPath_IsRejectedBeforeReachingTheHandler()
    {
        using var env = new AuthTestEnvironment();
        await using var server = new HttpServerHarness(env.Handler, new EmqxResponseTemplate(), UnlimitedLimiter());
        using var client = server.CreateClient();

        var response = await client.PostAsync("other", Body(env.Username, env.ValidPassword()));

        // The HttpListener prefix only covers /auth/, so other paths never get
        // a JSON deny body from SAS itself.
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task TrailingSlashPath_IsAccepted()
    {
        using var env = new AuthTestEnvironment();
        await using var server = new HttpServerHarness(env.Handler, new EmqxResponseTemplate(), UnlimitedLimiter());
        using var client = server.CreateClient();

        var response = await client.PostAsync("auth/", Body(env.Username, env.ValidPassword()));

        Assert.Equal("allow", (await ReadJson(response)).GetProperty("result").GetString());
    }

    [Fact]
    public async Task MalformedJson_IsDenied()
    {
        using var env = new AuthTestEnvironment();
        await using var server = new HttpServerHarness(env.Handler, new EmqxResponseTemplate(), UnlimitedLimiter());
        using var client = server.CreateClient();

        var response = await client.PostAsync("auth",
            new StringContent("{not json", Encoding.UTF8, "application/json"));

        Assert.Equal("deny", (await ReadJson(response)).GetProperty("result").GetString());
    }

    [Theory]
    [InlineData("", "secret")]
    [InlineData("BG6VMZ", "")]
    public async Task MissingCredentials_AreDenied(string username, string password)
    {
        using var env = new AuthTestEnvironment();
        await using var server = new HttpServerHarness(env.Handler, new EmqxResponseTemplate(), UnlimitedLimiter());
        using var client = server.CreateClient();

        var response = await client.PostAsync("auth", Body(username, password));

        Assert.Equal("deny", (await ReadJson(response)).GetProperty("result").GetString());
    }

    [Fact]
    public async Task IllegalCallsign_IsDenied()
    {
        using var env = new AuthTestEnvironment();
        await using var server = new HttpServerHarness(env.Handler, new EmqxResponseTemplate(), UnlimitedLimiter());
        using var client = server.CreateClient();

        var response = await client.PostAsync("auth", Body("BG6 VMZ", env.ValidPassword()));

        Assert.Equal("deny", (await ReadJson(response)).GetProperty("result").GetString());
    }

    [Fact]
    public async Task PasswordLongerThanLimit_IsDenied()
    {
        using var env = new AuthTestEnvironment();
        await using var server = new HttpServerHarness(env.Handler, new EmqxResponseTemplate(),
            UnlimitedLimiter(), maxPasswordBytes: 16);
        using var client = server.CreateClient();

        var response = await client.PostAsync("auth", Body(env.Username, env.ValidPassword()));

        Assert.Equal("deny", (await ReadJson(response)).GetProperty("result").GetString());
    }

    [Fact]
    public async Task BodyLargerThanLimit_Returns413()
    {
        using var env = new AuthTestEnvironment();
        await using var server = new HttpServerHarness(env.Handler, new EmqxResponseTemplate(),
            UnlimitedLimiter(), maxBodyBytes: 64);
        using var client = server.CreateClient();

        var response = await client.PostAsync("auth", Body(env.Username, env.ValidPassword()));

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
    }

    [Fact]
    public async Task GlobalRateLimitExceeded_IsDenied()
    {
        using var env = new AuthTestEnvironment();
        var limiter = new AuthRateLimiter(new RateLimitConfig
        {
            GlobalPerMinute = 1,
            BreakerEnabled = false
        });
        await using var server = new HttpServerHarness(env.Handler, new EmqxResponseTemplate(), limiter);
        using var client = server.CreateClient();

        var first = await client.PostAsync("auth", Body(env.Username, env.ValidPassword()));
        var second = await client.PostAsync("auth", Body(env.Username, env.ValidPassword()));

        Assert.Equal("allow", (await ReadJson(first)).GetProperty("result").GetString());
        Assert.Equal("deny", (await ReadJson(second)).GetProperty("result").GetString());
    }

    [Fact]
    public async Task BannedCallsign_IsDenied()
    {
        using var env = new AuthTestEnvironment();
        var limiter = new AuthRateLimiter(new RateLimitConfig
        {
            GlobalPerMinute = 10_000,
            BreakerEnabled = true,
            BreakerFailures = 2,
            BreakerWindowSec = 300,
            BreakerBanSec = 600
        });
        limiter.RecordFailure(env.Username, "setup-1");
        limiter.RecordFailure(env.Username, "setup-2");

        await using var server = new HttpServerHarness(env.Handler, new EmqxResponseTemplate(), limiter);
        using var client = server.CreateClient();

        var response = await client.PostAsync("auth", Body(env.Username, env.ValidPassword()));

        Assert.Equal("deny", (await ReadJson(response)).GetProperty("result").GetString());
    }

    [Fact]
    public async Task Post_UserRevokedByIntermediateCrl_ReturnsDeny()
    {
        using var env = new AuthTestEnvironment(
            pki: new TestPkiOptions { IssuerCrlUrl = "http://crl.test/int.crl" },
            crlFactory: rootsDir => new CrlManager(rootsDir, refreshSec: -1,
                FakeHttpMessageHandler.NotFound().CreateClient()));
        var crl = (CrlManager)env.CrlPolicy;

        TestCrl.WriteIntermediateCache(env.Temp, env.Pki.Intermediate,
            TestCrl.IntermediateCrlJson(env.Pki, 1,
            [
                (env.Pki.User.Uid, env.Pki.User.Fingerprint(),
                    1_700_000_000, TestCrl.ReasonKeyCompromise)
            ]));
        crl.Initialize([env.Pki.Root]);

        await using var server = new HttpServerHarness(env.Handler, new EmqxResponseTemplate(), UnlimitedLimiter());
        using var client = server.CreateClient();

        var response = await client.PostAsync("auth", Body(env.Username, env.ValidPassword()));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("deny", (await ReadJson(response)).GetProperty("result").GetString());
    }

    [Fact]
    public async Task WrongPasswordPayload_ReturnsDeny()
    {
        using var env = new AuthTestEnvironment();
        await using var server = new HttpServerHarness(env.Handler, new EmqxResponseTemplate(), UnlimitedLimiter());
        using var client = server.CreateClient();

        var response = await client.PostAsync("auth", Body(env.Username, "not-base64!!!"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("deny", (await ReadJson(response)).GetProperty("result").GetString());
    }
}
