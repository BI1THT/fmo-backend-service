using Sas.certs;
using Sas.Logging;

namespace Sas.Trust;

public enum VerifyResult
{
    OK = 0,
    RootSelfSignFail = -1,
    IntermediateSignFail = -2,
    UserSignFail = -3,
    IntermediateExpired = -4,
    UserExpired = -5,
    UidOutOfRange = -6,
    CountryNotAllowed = -7,
    CertRevoked = -8,
    MissingRootCA = -9,
    MissingIntermediate = -10,
    RootExpired = -11,
    RootPathLenInvalid = -12,
    IntermediateIssuerMismatch = -13,
    UserIssuerMismatch = -14,
    IntermediateIssuerKeyMismatch = -15
}

public sealed class CertVerifier
{
    public VerifyResult VerifyFullChain(
        RootCaCert root,
        IntermediateCaCert intermediate,
        UserCert user,
        long nowUtc)
    {
        if (!root.VerifySelfSignature())
        {
            Logger.Debug("  step: root self-signature FAILED");
            return VerifyResult.RootSelfSignFail;
        }
        Logger.Debug("  step: root self-signature PASSED");

        if (root.IsExpired(nowUtc))
        {
            Logger.Debug("  step: root expiry FAILED");
            return VerifyResult.RootExpired;
        }
        Logger.Debug("  step: root expiry PASSED");

        if (root.PathLen < 1)
        {
            Logger.Debug($"  step: root pathLen invalid ({root.PathLen})");
            return VerifyResult.RootPathLenInvalid;
        }
        Logger.Debug("  step: root pathLen PASSED");

        if (intermediate.IsExpired(nowUtc))
        {
            Logger.Debug("  step: intermediate expiry FAILED");
            return VerifyResult.IntermediateExpired;
        }
        Logger.Debug("  step: intermediate expiry PASSED");

        if (intermediate.PathLen != 0)
        {
            Logger.Debug($"  step: intermediate pathLen invalid ({intermediate.PathLen} != 0)");
            return VerifyResult.IntermediateSignFail;
        }
        Logger.Debug("  step: intermediate pathLen PASSED");

        if (intermediate.UidRangeStart > intermediate.UidRangeEnd)
        {
            Logger.Debug("  step: intermediate uidRange reversed");
            return VerifyResult.UidOutOfRange;
        }
        Logger.Debug("  step: intermediate uidRange order PASSED");

        if (!intermediate.VerifyBy(root))
        {
            Logger.Debug("  step: intermediate signed by root FAILED");
            return VerifyResult.IntermediateSignFail;
        }
        Logger.Debug("  step: intermediate signed by root PASSED");

        if (intermediate.IssuerSn != root.Sn)
        {
            Logger.Debug($"  step: intermediate issuerSn mismatch ({intermediate.IssuerSn} != {root.Sn})");
            return VerifyResult.IntermediateIssuerMismatch;
        }
        Logger.Debug("  step: intermediate issuerSn PASSED");

        if (!intermediate.IssuerPubKey.AsSpan().SequenceEqual(root.SubjectPubKey))
        {
            Logger.Debug("  step: intermediate issuer publicKey mismatch");
            return VerifyResult.IntermediateIssuerKeyMismatch;
        }
        Logger.Debug("  step: intermediate issuer publicKey PASSED");

        if (user.IsExpired(nowUtc))
        {
            Logger.Debug("  step: user expiry FAILED");
            return VerifyResult.UserExpired;
        }
        Logger.Debug("  step: user expiry PASSED");

        if (!intermediate.CanIssueFor(user.Uid))
        {
            Logger.Debug($"  step: UID range FAILED ({user.Uid} not in [0,0])");
            return VerifyResult.UidOutOfRange;
        }
        Logger.Debug($"  step: UID range PASSED ({user.Uid})");

        if (!user.VerifyBy(intermediate))
        {
            Logger.Debug("  step: user signed by intermediate FAILED");
            return VerifyResult.UserSignFail;
        }
        Logger.Debug("  step: user signed by intermediate PASSED");

        if (user.IssuerSn != intermediate.Sn)
        {
            Logger.Debug($"  step: user issuerSn mismatch ({user.IssuerSn} != {intermediate.Sn})");
            return VerifyResult.UserIssuerMismatch;
        }
        Logger.Debug("  step: user issuerSn PASSED");

        return VerifyResult.OK;
    }

    public static string GetMessage(VerifyResult result) => result switch
    {
        VerifyResult.OK => "ok",
        VerifyResult.RootSelfSignFail => "root CA self-signature invalid",
        VerifyResult.IntermediateSignFail => "intermediate CA signature invalid",
        VerifyResult.UserSignFail => "user certificate signature invalid",
        VerifyResult.IntermediateExpired => "intermediate CA expired",
        VerifyResult.UserExpired => "user certificate expired",
        VerifyResult.UidOutOfRange => "UID out of intermediate CA range",
        VerifyResult.CountryNotAllowed => "country not allowed",
        VerifyResult.CertRevoked => "certificate revoked",
        VerifyResult.MissingRootCA => "no trusted root CA found",
        VerifyResult.MissingIntermediate => "no matching intermediate CA",
        VerifyResult.RootExpired => "root CA expired",
        VerifyResult.RootPathLenInvalid => "root CA pathLen invalid",
        VerifyResult.IntermediateIssuerMismatch => "intermediate CA issuer mismatch",
        VerifyResult.UserIssuerMismatch => "user certificate issuer mismatch",
        VerifyResult.IntermediateIssuerKeyMismatch => "intermediate CA issuer public key mismatch",
        _ => "unknown error"
    };
}
