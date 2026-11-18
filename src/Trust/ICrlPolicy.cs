using Sas.certs;

namespace Sas.Trust;

/// <summary>
/// Revocation policy used by the auth pipeline. Implemented by <see cref="CrlManager"/>.
/// </summary>
public interface ICrlPolicy
{
    void RegisterIntermediate(IntermediateCaCert intermediate);

    bool IsRootCrlOutdated(long rootSn, long nowUtc);

    bool IsIntermediateRevoked(long sn, byte[] fingerprint, out string? reason);

    bool IsUserRevoked(long uid, byte[] fingerprint, out string? reason);
}
