using Sas.certs;

namespace Sas.Tests.Certs;

public sealed class Ed25519Tests
{
    private static (byte[] Public, byte[] Private) KeyPair(byte seed)
    {
        Chaos.NaCl.Ed25519.KeyPairFromSeed(out var publicKey, out var privateKey,
            Enumerable.Repeat(seed, 32).ToArray());
        return (publicKey, privateKey);
    }

    [Fact]
    public void Sign_Produces64ByteSignatureThatVerifies()
    {
        var (publicKey, privateKey) = KeyPair(1);
        var data = "hello fmo"u8.ToArray();

        var signature = Ed25519.Sign(privateKey, data);

        Assert.Equal(64, signature.Length);
        Assert.True(Ed25519.Verify(publicKey, data, signature));
    }

    [Fact]
    public void Sign_IsDeterministic()
    {
        var (_, privateKey) = KeyPair(1);
        var data = "deterministic"u8.ToArray();

        Assert.Equal(Ed25519.Sign(privateKey, data), Ed25519.Sign(privateKey, data));
    }

    [Fact]
    public void Verify_WrongPublicKey_ReturnsFalse()
    {
        var (_, privateKey) = KeyPair(1);
        var (otherPublic, _) = KeyPair(2);
        var data = "payload"u8.ToArray();

        Assert.False(Ed25519.Verify(otherPublic, data, Ed25519.Sign(privateKey, data)));
    }

    [Fact]
    public void Verify_TamperedData_ReturnsFalse()
    {
        var (publicKey, privateKey) = KeyPair(1);
        var signature = Ed25519.Sign(privateKey, "payload"u8.ToArray());

        Assert.False(Ed25519.Verify(publicKey, "payloaD"u8.ToArray(), signature));
    }

    [Fact]
    public void Verify_TamperedSignature_ReturnsFalse()
    {
        var (publicKey, privateKey) = KeyPair(1);
        var data = "payload"u8.ToArray();
        var signature = Ed25519.Sign(privateKey, data);
        signature[0] ^= 0xFF;

        Assert.False(Ed25519.Verify(publicKey, data, signature));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(31)]
    [InlineData(33)]
    public void Verify_PublicKeyWithWrongLength_ReturnsFalse(int length)
    {
        var (publicKey, privateKey) = KeyPair(1);
        var data = "payload"u8.ToArray();
        var signature = Ed25519.Sign(privateKey, data);

        Assert.False(Ed25519.Verify(new byte[length], data, signature));
        Assert.True(Ed25519.Verify(publicKey, data, signature));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(63)]
    [InlineData(65)]
    public void Verify_SignatureWithWrongLength_ReturnsFalse(int length)
    {
        var (publicKey, _) = KeyPair(1);

        Assert.False(Ed25519.Verify(publicKey, "payload"u8.ToArray(), new byte[length]));
    }
}
