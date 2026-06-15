using System.Formats.Cbor;
using Sas.certs;
using Sas.Logging;

namespace Sas.Auth;

public static class HttpProofVerifier
{
    private const int MaxTimestampDriftSec = 120;

    public static bool Verify(
        long serverUid,
        string targetCallsign,
        long targetUID,
        string targetUrl,
        int targetPort,
        byte[] serverFingerprintBytes,
        long timestamp,
        UserCert user,
        string role,
        string proofSigBase64Url)
    {
        Logger.Debug($"ProofVerifier: pubKey.length={user.PublicKey?.Length ?? 0} serverFp.length={serverFingerprintBytes?.Length ?? 0}");

        if (user.PublicKey == null || user.PublicKey.Length != 32)
        {
            Logger.Debug("ProofVerifier: FAIL - user public key is null or not 32 bytes");
            return false;
        }
        if (serverFingerprintBytes == null || serverFingerprintBytes.Length != 32)
        {
            Logger.Debug("ProofVerifier: FAIL - server fingerprint is null or not 32 bytes");
            return false;
        }

        try
        {
            var tbs = BuildTbs(serverUid, targetCallsign, targetUID,
                               targetUrl, targetPort, serverFingerprintBytes,
                               timestamp, user, role);
            var sig = Base64Url.Decode(proofSigBase64Url);

            Logger.Debug($"ProofVerifier: TBS length={tbs.Length} bytes, sig length={sig?.Length ?? 0} bytes");
            Logger.Debug($"ProofVerifier: TBS hex={Convert.ToHexString(tbs)[..Math.Min(64, tbs.Length * 2)]}...");
            Logger.Debug($"ProofVerifier: role={role} timestamp={timestamp} callsign(upper)={targetCallsign.ToUpperInvariant()}");

            if (sig == null || sig.Length != 64)
            {
                Logger.Debug($"ProofVerifier: FAIL - signature is null or not 64 bytes (got {sig?.Length ?? 0})");
                return false;
            }

            var result = Ed25519.Verify(user.PublicKey, tbs, sig);
            Logger.Debug($"ProofVerifier: Ed25519.Verify result={result}");
            return result;
        }
        catch (Exception ex)
        {
            Logger.Debug($"ProofVerifier: FAIL - exception: {ex.Message}");
            return false;
        }
    }

    public static bool IsTimestampValid(long timestamp, long nowUtc)
    {
        return Math.Abs(nowUtc - timestamp) <= MaxTimestampDriftSec;
    }

    private static byte[] BuildTbs(
        long serverUid, string targetCallsign, long targetUID,
        string targetUrl, int targetPort,
        byte[] serverFingerprintBytes,
        long timestamp, UserCert user, string role)
    {
        var csUpper = targetCallsign.ToUpperInvariant();
        var userFp = user.Fingerprint();

        var w = new CborWriter(CborConformanceMode.Lax);
        w.WriteStartArray(12);
        w.WriteTextString("FMO");
        w.WriteInt64(4);
        w.WriteTextString("serverAuthorizerReqHttp");
        w.WriteInt64(serverUid);
        w.WriteTextString(csUpper);
        w.WriteInt64(targetUID);
        w.WriteTextString(role);
        w.WriteTextString(targetUrl);
        w.WriteInt64(targetPort);
        w.WriteByteString(serverFingerprintBytes);
        w.WriteInt64(timestamp);
        w.WriteByteString(userFp);
        w.WriteEndArray();

        var buf = new byte[w.BytesWritten];
        w.Encode(buf);
        return buf;
    }
}
