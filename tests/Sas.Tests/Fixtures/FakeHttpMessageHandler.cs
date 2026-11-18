using System.Net;
using System.Net.Http;

namespace Sas.Tests.Fixtures;

/// <summary>
/// Scriptable HTTP transport for CrlManager refresh tests.
/// </summary>
public sealed class FakeHttpMessageHandler : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, HttpResponseMessage> _responder;
    private int _callCount;

    public FakeHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> responder)
        => _responder = responder;

    public FakeHttpMessageHandler(HttpStatusCode status, string body = "")
        : this(_ => new HttpResponseMessage(status)
        {
            Content = new StringContent(body)
        })
    {
    }

    public int CallCount => Volatile.Read(ref _callCount);

    public List<string> RequestUrls { get; } = [];

    public static FakeHttpMessageHandler Json(string body) =>
        new(HttpStatusCode.OK, body);

    public static FakeHttpMessageHandler NotFound() =>
        new(HttpStatusCode.NotFound);

    public HttpClient CreateClient() => new(this, disposeHandler: false);

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref _callCount);
        lock (RequestUrls)
            RequestUrls.Add(request.RequestUri?.ToString() ?? "");

        return Task.FromResult(_responder(request));
    }
}
