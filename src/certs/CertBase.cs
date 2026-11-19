using System.Formats.Cbor;

namespace Sas.certs;

public abstract class CertBase
{
    public abstract byte[] ToTbsCbor();

    public byte[] Fingerprint()
    {
        var tbs = ToTbsCbor();
        return System.Security.Cryptography.SHA256.HashData(tbs);
    }

    /// <summary>Lowercase hex form of the certificate's SHA-256 fingerprint.</summary>
    public string FingerprintHex() => FingerprintHex(Fingerprint());

    /// <summary>Short fingerprint used in logs and cache directory names.</summary>
    public string FingerprintPrefix(int chars = 8) => HexPrefix(FingerprintHex(), chars);

    /// <summary>Converts a raw fingerprint to the canonical lowercase hex form.</summary>
    public static string FingerprintHex(byte[] fingerprint) =>
        Convert.ToHexString(fingerprint).ToLowerInvariant();

    /// <summary>
    /// Truncates a lowercase hex string for display and returns "?" when the
    /// value is missing, so callers never print an empty fingerprint.
    /// </summary>
    public static string HexPrefix(string? hex, int chars = 8) =>
        string.IsNullOrEmpty(hex) ? "?" : hex.Length <= chars ? hex : hex[..chars];

    protected static void EncodeText(CborWriter w, string s) => w.WriteTextString(s);

    protected static void EncodeInt(CborWriter w, long v) => w.WriteInt64(v);

    protected static void EncodeBytes(CborWriter w, byte[] data) => w.WriteByteString(data);

    protected static void EncodeBool(CborWriter w, bool v) => w.WriteBoolean(v);

    protected static void EncodeTextArray(CborWriter w, string?[] items)
    {
        w.WriteStartArray(items.Length);
        foreach (var item in items)
            w.WriteTextString(item ?? "");
        w.WriteEndArray();
    }

    protected static void EncodeByteArray(CborWriter w, byte[][] items)
    {
        w.WriteStartArray(items.Length);
        foreach (var item in items)
            w.WriteByteString(item);
        w.WriteEndArray();
    }
}
