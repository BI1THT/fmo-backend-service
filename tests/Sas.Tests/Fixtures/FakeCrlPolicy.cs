using Sas.certs;
using Sas.Trust;

namespace Sas.Tests.Fixtures;

/// <summary>
/// In-memory revocation policy so auth tests can flip revocation without HTTP.
/// Entries are keyed by the issuer certificate fingerprint, matching the
/// production cache keys.
/// </summary>
public sealed class FakeCrlPolicy : ICrlPolicy
{
    public bool RootCrlOutdated { get; set; }
    public CrlAvailability RootAvailability { get; set; } = CrlAvailability.Fresh;
    public CrlAvailability IntermediateAvailability { get; set; } = CrlAvailability.Fresh;
    public List<IntermediateCaCert> Registered { get; } = [];
    public HashSet<string> RevokedIntermediates { get; } = new(StringComparer.Ordinal);
    public HashSet<string> RevokedUsers { get; } = new(StringComparer.Ordinal);

    public void RegisterIntermediate(IntermediateCaCert intermediate) => Registered.Add(intermediate);

    public bool IsRootCrlOutdated(byte[] rootFingerprint, long nowUtc) => RootCrlOutdated;

    public CrlAvailability GetRootCrlAvailability(
        byte[] rootFingerprint, long rootSn, long nowUtc) => RootAvailability;

    public CrlAvailability GetIntermediateCrlAvailability(
        byte[] intermediateFingerprint, long intermediateSn, long nowUtc) =>
        IntermediateAvailability;

    public bool IsIntermediateRevoked(
        byte[] issuerRootFingerprint, long sn, byte[] fingerprint, out string? reason)
    {
        if (RevokedIntermediates.Contains(Key(issuerRootFingerprint, sn, fingerprint)))
        {
            reason = $"intermediate CA sn={sn} revoked by root CRL (rootFp={Hex(issuerRootFingerprint)[..8]})";
            return true;
        }

        reason = null;
        return false;
    }

    public bool IsUserRevoked(
        byte[] issuerIntermediateFingerprint, long uid, byte[] fingerprint, out string? reason)
    {
        if (RevokedUsers.Contains(Key(issuerIntermediateFingerprint, uid, fingerprint)))
        {
            reason = $"user cert uid={uid} revoked by intermediate CRL (issuerFp={Hex(issuerIntermediateFingerprint)[..8]})";
            return true;
        }

        reason = null;
        return false;
    }

    public void RevokeIntermediate(byte[] issuerRootFingerprint, long sn, byte[] fingerprint) =>
        RevokedIntermediates.Add(Key(issuerRootFingerprint, sn, fingerprint));

    public void RevokeUser(byte[] issuerIntermediateFingerprint, long uid, byte[] fingerprint) =>
        RevokedUsers.Add(Key(issuerIntermediateFingerprint, uid, fingerprint));

    private static string Key(byte[] issuerFingerprint, long id, byte[] fingerprint) =>
        Hex(issuerFingerprint) + ":" +
        id.ToString(System.Globalization.CultureInfo.InvariantCulture) + ":" +
        Hex(fingerprint);

    private static string Hex(byte[] bytes) => Convert.ToHexString(bytes);
}
