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

        var sb = new StringBuilder(Math.Min(value.Length, maxLength));
        foreach (var ch in value)
        {
            if (sb.Length >= maxLength)
            {
                sb.Append('…');
                break;
            }

            if (char.IsControl(ch) || ch is '\u2028' or '\u2029' or '\u202E')
                sb.Append('?');
            else
                sb.Append(ch);
        }

        return sb.ToString();
    }
}
