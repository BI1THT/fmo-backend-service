using System.Net;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Sas.Auth;
using Sas.Logging;

namespace Sas.Server;

sealed class HttpServer
{
    private readonly string _addr;
    private readonly int _port;
    private readonly int _maxBodyBytes;
    private readonly int _maxPasswordBytes;
    private readonly SemaphoreSlim _concurrencyLimit;
    private readonly HttpAuthHandler _handler;
    private readonly IResponseTemplate _template;
    private readonly AuthRateLimiter _rateLimiter;
    private HttpListener? _listener;

    public HttpServer(string addr, int port, int maxBodyBytes, int maxPasswordBytes, int maxConcurrent,
        HttpAuthHandler handler, IResponseTemplate template, AuthRateLimiter rateLimiter)
    {
        _addr = addr;
        _port = port;
        _maxBodyBytes = maxBodyBytes;
        _maxPasswordBytes = maxPasswordBytes;
        _concurrencyLimit = new SemaphoreSlim(maxConcurrent);
        _handler = handler;
        _template = template;
        _rateLimiter = rateLimiter;
    }

    public void Start()
    {
        var host = _addr;
        if (host == "0.0.0.0" || host == "*" || host == "+")
            host = "+";

        var prefix = $"http://{host}:{_port}/auth/";
        _listener = new HttpListener();
        _listener.Prefixes.Add(prefix);
        try
        {
            _listener.Start();
        }
        catch (HttpListenerException ex) when (ex.ErrorCode == 5 || ex.ErrorCode == 50)
        {
            Logger.Error($"HTTP auth: cannot bind to {prefix} (error {ex.ErrorCode})");
            Logger.Error($"  Run as admin or grant URL ACL:");
            Logger.Error($"  netsh http add urlacl url=http://+:{_port}/auth/ user=Everyone");
            throw;
        }
        Logger.Info("HTTP auth server ready");
    }

    public async Task RunAsync(CancellationToken ct = default)
    {
        if (_listener == null)
            throw new InvalidOperationException("Not started");

        while (!ct.IsCancellationRequested)
        {
            HttpListenerContext ctx;
            try
            {
                ctx = await _listener.GetContextAsync().WaitAsync(ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            _ = HandleRequestAsync(ctx);
        }
    }

    private async Task HandleRequestAsync(HttpListenerContext ctx)
    {
        if (!await _concurrencyLimit.WaitAsync(TimeSpan.FromSeconds(5)))
        {
            ctx.Response.StatusCode = 503;
            ctx.Response.Close();
            return;
        }
        try
        {
            await HandleRequestCoreAsync(ctx);
        }
        finally
        {
            _concurrencyLimit.Release();
        }
    }

    private async Task HandleRequestCoreAsync(HttpListenerContext ctx)
    {
        var requestId = Guid.NewGuid().ToString("N")[..12];

        try
        {
            if (ctx.Request.HttpMethod != "POST" ||
                !ctx.Request.Url!.AbsolutePath.TrimEnd('/').EndsWith("/auth", StringComparison.OrdinalIgnoreCase))
            {
                await WriteDenyResponse(ctx.Response);
                return;
            }

            if (!_rateLimiter.TryAcquireGlobal())
            {
                await WriteDenyResponse(ctx.Response);
                return;
            }

            var body = await ReadRequestBodyAsync(ctx.Request);
            if (body == null)
            {
                ctx.Response.StatusCode = 413;
                ctx.Response.Close();
                return;
            }

            JsonElement json;
            try
            {
                using var doc = JsonDocument.Parse(body);
                json = doc.RootElement.Clone();
            }
            catch
            {
                Logger.Warn($"HTTP auth: malformed request body req={requestId} reason=\"invalid json\"");
                await WriteDenyResponse(ctx.Response);
                return;
            }

            var username = ReadString(json, "username");
            var password = ReadString(json, "password");

            var usernameBytes = Encoding.UTF8.GetByteCount(username);
            var passwordBytes = Encoding.UTF8.GetByteCount(password);

            Logger.Debug($"HTTP auth: received request usernameBytes={usernameBytes} passwordBytes={passwordBytes} req={requestId}");

            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                Logger.Warn($"HTTP auth: malformed request req={requestId} reason=\"empty username or password\"");
                await WriteDenyResponse(ctx.Response);
                return;
            }

            if (!CallsignValidator.TryNormalize(username, out var normalizedUsername, out var callsignError))
            {
                Logger.Warn($"HTTP auth: reject callsign req={requestId} usernameBytes={usernameBytes} reason=\"{callsignError}\"");
                await WriteDenyResponse(ctx.Response);
                return;
            }

            if (_maxPasswordBytes > 0 && passwordBytes > _maxPasswordBytes)
            {
                Logger.Warn($"HTTP auth: reject password req={requestId} callsign={LogSafe.Format(normalizedUsername, CallsignValidator.MaxBytes)} passwordBytes={passwordBytes} reason=\"password too long\"");
                await WriteDenyResponse(ctx.Response);
                return;
            }

            if (_rateLimiter.IsBanned(normalizedUsername, requestId, out _))
            {
                await WriteDenyResponse(ctx.Response);
                return;
            }

            object responseBody;
            try
            {
                var result = _handler.Process(normalizedUsername, password, requestId);
                _rateLimiter.RecordSuccess(normalizedUsername);
                responseBody = _template.BuildAllow(result);
            }
            catch (AuthDeniedException ex)
            {
                if (ex.BreakerKey is { } breakerKey)
                    _rateLimiter.RecordFailure(breakerKey, requestId);

                responseBody = _template.BuildDeny();
            }
            catch (Exception ex)
            {
                Logger.Error($"HTTP auth: internal error req={requestId}: {ex}");
                responseBody = _template.BuildDeny();
            }

            var responseJson = JsonSerializer.Serialize(responseBody,
                new JsonSerializerOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
            var buffer = Encoding.UTF8.GetBytes(responseJson);

            ctx.Response.StatusCode = 200;
            ctx.Response.ContentType = "application/json";
            ctx.Response.ContentLength64 = buffer.Length;
            await ctx.Response.OutputStream.WriteAsync(buffer);
            ctx.Response.OutputStream.Close();
        }
        catch (Exception ex)
        {
            Logger.Error($"HTTP auth: request handling error: {ex}");
            try
            {
                ctx.Response.StatusCode = 500;
                ctx.Response.Close();
            }
            catch { }
        }
    }

    private async Task<string?> ReadRequestBodyAsync(HttpListenerRequest request)
    {
        var length = request.ContentLength64;
        if (length > _maxBodyBytes)
            return null;

        int maxRead = length > 0 ? (int)length : _maxBodyBytes;

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        var buffer = new byte[maxRead];
        var totalRead = 0;
        while (totalRead < maxRead)
        {
            var read = await request.InputStream.ReadAsync(
                buffer, totalRead, Math.Min(maxRead - totalRead, 4096), cts.Token);
            if (read == 0) break;
            totalRead += read;
        }
        return Encoding.UTF8.GetString(buffer, 0, totalRead);
    }

    private static string ReadString(JsonElement json, string name)
    {
        return json.TryGetProperty(name, out var element) && element.ValueKind == JsonValueKind.String
            ? element.GetString() ?? ""
            : "";
    }

    private static async Task WriteDenyResponse(HttpListenerResponse response)
    {
        var denyJson = Encoding.UTF8.GetBytes("{\"result\":\"deny\"}");
        response.StatusCode = 200;
        response.ContentType = "application/json";
        response.ContentLength64 = denyJson.Length;
        await response.OutputStream.WriteAsync(denyJson);
        response.OutputStream.Close();
    }

    public void Stop()
    {
        _listener?.Stop();
        _listener?.Close();
    }
}
