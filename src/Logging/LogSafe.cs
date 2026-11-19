using System.Text;

namespace Sas.Logging;

public static class LogSafe
{
    /// <summary>
    /// Escapes control characters and limits length before writing untrusted values to a plain-text log.
    /// </summary>
    public static string Format(string? value, int maxLength = 64)
    {
        if (string.IsNullOrEmpty(value))
            return "-";

        if (maxLength < 1)
            maxLength = 1;

        var truncated = value.Length > maxLength;
        var budget = truncated ? maxLength - 1 : maxLength;
        var sb = new StringBuilder(Math.Min(value.Length, maxLength));

        for (var i = 0; i < value.Length;)
        {
            var ch = value[i];
            var width = char.IsHighSurrogate(ch) &&
                        i + 1 < value.Length &&
                        char.IsLowSurrogate(value[i + 1])
                ? 2
                : 1;

            if (sb.Length + width > budget)
                break;

            var escape = char.IsControl(ch)
                         || (char.IsSurrogate(ch) && width == 1)
                         || ch is '\u2028' or '\u2029' or '\u202E';

            if (escape)
            {
                sb.Append('?');
            }
            else
            {
                sb.Append(ch);
                if (width == 2)
                    sb.Append(value[i + 1]);
            }

            i += width;
        }

        if (truncated)
            sb.Append('…');

        return sb.ToString();
    }
}
