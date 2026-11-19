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

    /// <summary>
    /// Reads crlNumber as a uint32. Negative or larger values are rejected
    /// instead of silently wrapping around.
    /// </summary>
    public static uint ReadCrlNumber(JsonElement json)
    {
        var element = json.GetProperty("crlNumber");
        if (!element.TryGetInt64(out var value))
            throw new FormatException("crlNumber must be an integer");

        if (value < 0 || value > uint.MaxValue)
            throw new FormatException($"crlNumber out of range: {value}");

        return (uint)value;
    }
}
