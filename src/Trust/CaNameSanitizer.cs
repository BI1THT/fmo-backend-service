using System.Text;
using Sas.Auth;

namespace Sas.Trust;

/// <summary>
/// Turns an untrusted CA display name into a safe, ASCII-only path segment.
/// The original name must still be kept in metadata and logs.
/// </summary>
internal static class CaNameSanitizer
{
    public const int DefaultMaxLength = 32;

    public static string Sanitize(string? name, int maxLength = DefaultMaxLength)
    {
        if (string.IsNullOrWhiteSpace(name))
            return "ca";

        if (maxLength < 1)
            maxLength = 1;

        var sb = new StringBuilder(Math.Min(name.Length, maxLength));

        foreach (var ch in name.Trim())
        {
            if (sb.Length >= maxLength)
                break;

            if (!IsAllowed(ch))
            {
                if (sb.Length == 0 || sb[^1] != '_')
                    sb.Append('_');
                continue;
            }

            if (ch == '_' && sb.Length > 0 && sb[^1] == '_')
                continue;

            sb.Append(ch);
        }

        var result = sb.ToString().Trim(' ', '.', '_');
        if (result.Length == 0 || result is "." or "..")
            return "ca";

        if (result.Length > maxLength)
            result = result[..maxLength];

        if (CallsignValidator.IsReservedWindowsName(result))
            result = "_" + result;

        return result;
    }

    // Deliberately different from AuthArchive.SanitizeCallsign: CA names are
    // display names, so case is preserved and '.' is kept for names like
    // "ca.example". The archive sanitizer uppercases callsigns instead.
    private static bool IsAllowed(char ch) =>
        ch is >= 'A' and <= 'Z'
            or >= 'a' and <= 'z'
            or >= '0' and <= '9'
            or '-' or '_' or '.';
}
