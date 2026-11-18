using Sas.certs;
using Sas.Trust;

namespace Sas.Tests.Fixtures;

/// <summary>
/// In-memory revocation policy so auth tests can flip revocation without HTTP.
/// </summary>
public sealed class FakeCrlPolicy : ICrlPolicy
{
    public bool RootCrlOutdated { get; set; }
    public List<IntermediateCaCert> Registered { get; } = [];
    public HashSet<string> RevokedIntermediates { get; } = new(StringComparer.Ordinal);
    public HashSet<string> RevokedUsers { get; } = new(StringComparer.Ordinal);

    public void RegisterIntermediate(IntermediateCaCert intermediate) => Registered.Add(intermediate);

    public bool IsRootCrlOutdated(long rootSn, long nowUtc) => RootCrlOutdated;

    public bool IsIntermediateRevoked(long sn, byte[] fingerprint, out string? reason)
    {
        if (RevokedIntermediates.Contains(Key(sn, fingerprint)))
        {
            reason = $"intermediate CA sn={sn} revoked by root CRL";
            return true;
        }

        reason = null;
        return false;
    }

    public bool IsUserRevoked(long uid, byte[] fingerprint, out string? reason)
    {
        if (RevokedUsers.Contains(Key(uid, fingerprint)))
        {
            reason = $"user cert uid={uid} revoked by intermediate CRL";
            return true;
        }

        reason = null;
        return false;
    }

    public void RevokeIntermediate(long sn, byte[] fingerprint) =>
        RevokedIntermediates.Add(Key(sn, fingerprint));

    public void RevokeUser(long uid, byte[] fingerprint) =>
        RevokedUsers.Add(Key(uid, fingerprint));

    private static string Key(long id, byte[] fingerprint) =>
        id.ToString(System.Globalization.CultureInfo.InvariantCulture) + ":" + Convert.ToHexString(fingerprint);
}
