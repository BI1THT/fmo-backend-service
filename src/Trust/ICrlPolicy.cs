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
/// </summary>
public interface ICrlPolicy
{
    void RegisterIntermediate(IntermediateCaCert intermediate);

    bool IsRootCrlOutdated(long rootSn, long nowUtc);

    CrlAvailability GetRootCrlAvailability(long rootSn, long nowUtc);

    CrlAvailability GetIntermediateCrlAvailability(long intermediateSn, long nowUtc);

    bool IsIntermediateRevoked(long sn, byte[] fingerprint, out string? reason);

    bool IsUserRevoked(long uid, byte[] fingerprint, out string? reason);
}
