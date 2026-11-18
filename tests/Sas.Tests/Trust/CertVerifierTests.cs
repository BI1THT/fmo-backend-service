using Sas.certs;
using Sas.Tests.Fixtures;
using Sas.Trust;

namespace Sas.Tests.Trust;

public sealed class CertVerifierTests
{
    private const long Now = 1_700_000_000;
    private readonly CertVerifier _verifier = new();

    [Fact]
    public void VerifyFullChain_ForCompleteValidChain_ReturnsOk()
    {
        var pki = TestPki.Create();

        Assert.Equal(VerifyResult.OK, _verifier.VerifyFullChain(pki.Root, pki.Intermediate, pki.User, Now));
    }

    [Fact]
    public void VerifyFullChain_RootSelfSignatureInvalid_ReturnsRootSelfSignFail()
    {
        var pki = TestPki.Create();
        var brokenRoot = pki.RootWithSignature(new byte[64]);

        Assert.Equal(VerifyResult.RootSelfSignFail,
            _verifier.VerifyFullChain(brokenRoot, pki.Intermediate, pki.User, Now));
    }

    [Fact]
    public void VerifyFullChain_ExpiredIntermediate_ReturnsIntermediateExpired()
    {
        var pki = TestPki.Create(new TestPkiOptions { IssuerExp = Now });

        Assert.Equal(VerifyResult.IntermediateExpired,
            _verifier.VerifyFullChain(pki.Root, pki.Intermediate, pki.User, Now));
    }

    [Fact]
    public void VerifyFullChain_IntermediateWithNonZeroPathLen_ReturnsIntermediateSignFail()
    {
        var pki = TestPki.Create(new TestPkiOptions { PathLen = 1 });

        Assert.Equal(VerifyResult.IntermediateSignFail,
            _verifier.VerifyFullChain(pki.Root, pki.Intermediate, pki.User, Now));
    }

    [Fact]
    public void VerifyFullChain_ReversedUidRange_ReturnsUidOutOfRange()
    {
        var pki = TestPki.Create(new TestPkiOptions { UidRangeStart = 90_000, UidRangeEnd = 1_000 });

        Assert.Equal(VerifyResult.UidOutOfRange,
            _verifier.VerifyFullChain(pki.Root, pki.Intermediate, pki.User, Now));
    }

    [Fact]
    public void VerifyFullChain_IntermediateSignedByOtherRoot_ReturnsIntermediateSignFail()
    {
        var a = TestPki.Create(new TestPkiOptions { Seed = 10 });
        var b = TestPki.Create(new TestPkiOptions { Seed = 20 });

        Assert.Equal(VerifyResult.IntermediateSignFail,
            _verifier.VerifyFullChain(a.Root, b.Intermediate, b.User, Now));
    }

    [Fact]
    public void VerifyFullChain_ExpiredUser_ReturnsUserExpired()
    {
        var pki = TestPki.Create(new TestPkiOptions { UserExp = Now });

        Assert.Equal(VerifyResult.UserExpired,
            _verifier.VerifyFullChain(pki.Root, pki.Intermediate, pki.User, Now));
    }

    [Fact]
    public void VerifyFullChain_UserOutsideUidRange_ReturnsUidOutOfRange()
    {
        var pki = TestPki.Create(new TestPkiOptions
        {
            UidRangeStart = 1000,
            UidRangeEnd = 2000,
            UserUid = 50001
        });

        Assert.Equal(VerifyResult.UidOutOfRange,
            _verifier.VerifyFullChain(pki.Root, pki.Intermediate, pki.User, Now));
    }

    [Fact]
    public void VerifyFullChain_UserSignedByOtherIntermediate_ReturnsUserSignFail()
    {
        var a = TestPki.Create(new TestPkiOptions { Seed = 10 });
        var b = TestPki.Create(new TestPkiOptions { Seed = 20 });

        Assert.Equal(VerifyResult.UserSignFail,
            _verifier.VerifyFullChain(a.Root, a.Intermediate, b.User, Now));
    }

    [Fact]
    public void VerifyFullChain_ChecksIntermediateExpiryBeforeSignature()
    {
        var a = TestPki.Create(new TestPkiOptions { Seed = 10 });
        var expiredElsewhere = TestPki.Create(new TestPkiOptions
        {
            Seed = 20,
            IssuerExp = Now - 1
        });

        // Both "expired" and "signed by a different root" are true; the
        // documented pipeline reports expiry first.
        Assert.Equal(VerifyResult.IntermediateExpired,
            _verifier.VerifyFullChain(a.Root, expiredElsewhere.Intermediate, expiredElsewhere.User, Now));
    }

    [Theory]
    [InlineData(1, VerifyResult.OK)]
    [InlineData(0, VerifyResult.UserExpired)]
    public void VerifyFullChain_UserExpiryBoundary(long offsetFromNow, VerifyResult expected)
    {
        var pki = TestPki.Create(new TestPkiOptions { UserExp = Now + offsetFromNow });

        Assert.Equal(expected, _verifier.VerifyFullChain(pki.Root, pki.Intermediate, pki.User, Now));
    }

    [Fact]
    public void VerifyFullChain_DoesNotCheckRootExpiry_CurrentBehavior()
    {
        // Current behaviour: root exp is never evaluated by the verifier.
        var pki = TestPki.Create(new TestPkiOptions { RootExp = Now - 1 });

        Assert.Equal(VerifyResult.OK, _verifier.VerifyFullChain(pki.Root, pki.Intermediate, pki.User, Now));
    }

    [Fact]
    public void GetMessage_CoversEveryDeclaredResultUniquely()
    {
        var messages = Enum.GetValues<VerifyResult>()
            .Select(CertVerifier.GetMessage)
            .ToArray();

        Assert.All(messages, m => Assert.False(string.IsNullOrWhiteSpace(m)));
        Assert.Equal(messages.Length, messages.Distinct().Count());
        Assert.Equal("ok", CertVerifier.GetMessage(VerifyResult.OK));
    }

    [Fact]
    public void GetMessage_UnknownValue_ReturnsFallback()
    {
        Assert.Equal("unknown error", CertVerifier.GetMessage((VerifyResult)99));
    }
}
