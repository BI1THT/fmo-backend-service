using System.Net;
using System.Net.Sockets;
using Sas.Auth;
using Sas.Server;

namespace Sas.Tests.Fixtures;

/// <summary>
/// Starts a real <see cref="HttpServer"/> on a free loopback port.
/// </summary>
internal sealed class HttpServerHarness : IAsyncDisposable
{
    private readonly HttpServer _server;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _run;

    public int Port { get; }

    public string AuthUrl => $"http://127.0.0.1:{Port}/auth";

    public HttpServerHarness(
        IAuthHandler handler,
        IResponseTemplate template,
        AuthRateLimiter rateLimiter,
        int maxBodyBytes = 65536,
        int maxPasswordBytes = 32768,
        int maxConcurrent = 16)
    {
        Port = FindFreePort();
        _server = new HttpServer("127.0.0.1", Port, maxBodyBytes, maxPasswordBytes,
            maxConcurrent, handler, template, rateLimiter);
        _server.Start();
        _run = _server.RunAsync(_cts.Token);
    }

    public HttpClient CreateClient() => new()
    {
        BaseAddress = new Uri($"http://127.0.0.1:{Port}/"),
        Timeout = TimeSpan.FromSeconds(5)
    };

    private static int FindFreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    public async ValueTask DisposeAsync()
    {
        _cts.Cancel();
        try
        {
            await _run.WaitAsync(TimeSpan.FromSeconds(3));
        }
        catch
        {
            // Listener teardown races are expected during shutdown.
        }

        _server.Stop();
        _cts.Dispose();
    }
}
