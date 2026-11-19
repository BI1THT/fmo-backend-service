using Sas.certs;

namespace Sas.Trust;

/// <summary>
/// Availability of a CRL for a given issuer. <see cref="Fresh"/> and
/// <see cref="Stale"/> are evaluated against the caller's clock.
/// </summary>
public enum CrlAvailability
{
    NotConfigured, // The certificate carries no crl URL.
    NotFetched,    // A URL exists but no CRL has been loaded yet.
    NotPublished,  // The URL returned 404.
    Fresh,         // A cached CRL covers the current time.
    Stale,         // A cached CRL exists but its nextUpdate has passed.
    FetchFailed    // Fetching, parsing or verifying the CRL failed.
}

/// <summary>
/// Revocation policy used by the auth pipeline. Implemented by <see cref="CrlManager"/>.
/// Cache and lookup keys use certificate fingerprints because CA serial numbers
/// are not guaranteed to be globally unique.
/// </summary>
public interface ICrlPolicy
{
    void RegisterIntermediate(IntermediateCaCert intermediate);

    bool IsRootCrlOutdated(byte[] rootFingerprint, long nowUtc);

    CrlAvailability GetRootCrlAvailability(
        byte[] rootFingerprint, long rootSn, long nowUtc);

    CrlAvailability GetIntermediateCrlAvailability(
        byte[] intermediateFingerprint, long intermediateSn, long nowUtc);

    /// <summary>
    /// Checks whether an intermediate was revoked by its issuing root.
    /// <paramref name="issuerRootFingerprint"/> must be the root that signed
    /// the intermediate so a CRL from another root cannot revoke it.
    /// </summary>
    bool IsIntermediateRevoked(
        byte[] issuerRootFingerprint, long sn, byte[] fingerprint, out string? reason);

    /// <summary>
    /// Checks whether a user certificate was revoked by its issuing
    /// intermediate. <paramref name="issuerIntermediateFingerprint"/> must be
    /// the intermediate that signed the user certificate.
    /// </summary>
    bool IsUserRevoked(
        byte[] issuerIntermediateFingerprint, long uid, byte[] fingerprint, out string? reason);
}
