using System.Text.Json;

namespace Sas.certs;

internal static class CertJsonFields
{
    /// <summary>
    /// Reads extensions.pathLen. A missing field keeps the legacy default so
    /// certificates produced by older tooling still load; an out-of-range value
    /// is rejected instead of silently wrapping around.
    /// </summary>
    public static uint ReadPathLen(JsonElement extensions, uint fallback)
    {
        if (!extensions.TryGetProperty("pathLen", out var element))
            return fallback;

        var value = element.GetInt64();
        if (value < 0 || value > uint.MaxValue)
            throw new InvalidOperationException($"Invalid pathLen: {value}");

        return (uint)value;
    }
}
