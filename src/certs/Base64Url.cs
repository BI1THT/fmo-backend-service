namespace Sas.certs;

public static class Base64Url
{
    public static byte[] Decode(string encoded)
    {
        ArgumentNullException.ThrowIfNull(encoded);

        // The protocol requires unpadded base64url. Reject anything else up
        // front so whitespace or standard-base64 characters cannot slip
        // through Convert.FromBase64String's lenient parser.
        if (encoded.Length % 4 == 1)
            throw new FormatException("invalid base64url length");

        foreach (var c in encoded)
        {
            if (!(c is >= 'A' and <= 'Z'
                  or >= 'a' and <= 'z'
                  or >= '0' and <= '9'
                  or '-' or '_'))
            {
                throw new FormatException($"invalid base64url character: 0x{(int)c:X2}");
            }
        }

        var s = encoded.Replace('-', '+').Replace('_', '/');
        switch (s.Length % 4)
        {
            case 2: s += "=="; break;
            case 3: s += "="; break;
        }
        return Convert.FromBase64String(s);
    }

    public static string Encode(byte[] data)
    {
        return Convert.ToBase64String(data)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }
}
