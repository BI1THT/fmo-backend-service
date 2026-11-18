using System.Text;

namespace Sas.Auth;

public static class CallsignValidator
{
    public const int MaxBytes = 32;

    private static readonly HashSet<string> ReservedWindowsNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
    };

    /// <summary>
    /// Validates an untrusted callsign and returns its canonical uppercase form.
    /// Maximum length is 32 UTF-8 bytes; only A-Z, 0-9, '/' and '-' are allowed.
    /// </summary>
    public static bool TryNormalize(string? input, out string normalized, out string error)
    {
        normalized = "";
        error = "";

        if (string.IsNullOrWhiteSpace(input))
        {
            error = "empty callsign";
            return false;
        }

        if (input.Length > MaxBytes || Encoding.UTF8.GetByteCount(input) > MaxBytes)
        {
            error = "callsign too long";
            return false;
        }

        var sb = new StringBuilder(input.Length);
        foreach (var ch in input)
        {
            if (ch > 0x7F)
            {
                error = "invalid callsign character";
                return false;
            }

            var c = char.ToUpperInvariant(ch);
            if (c is >= 'A' and <= 'Z' or >= '0' and <= '9' or '/' or '-')
                sb.Append(c);
            else
            {
                error = "invalid callsign character";
                return false;
            }
        }

        if (sb.Length == 0)
        {
            error = "empty callsign";
            return false;
        }

        normalized = sb.ToString();
        return true;
    }

    public static bool IsReservedWindowsName(string name)
    {
        var trimmed = name.TrimEnd('.', ' ');
        var baseName = trimmed.Split('.')[0];
        return ReservedWindowsNames.Contains(baseName);
    }
}
