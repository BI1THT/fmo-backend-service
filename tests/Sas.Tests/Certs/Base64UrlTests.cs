using Sas.certs;

namespace Sas.Tests.Certs;

public sealed class Base64UrlTests
{
    [Fact]
    public void Encode_EmptyInput_ReturnsEmptyString()
    {
        Assert.Equal("", Base64Url.Encode([]));
    }

    [Fact]
    public void Decode_EmptyInput_ReturnsEmptyArray()
    {
        Assert.Empty(Base64Url.Decode(""));
    }

    [Fact]
    public void Encode_UsesUrlSafeAlphabetWithoutPadding()
    {
        // 0xFB 0xFF 0xBF encodes to "+/+/" in standard base64.
        var encoded = Base64Url.Encode([0xFB, 0xFF, 0xBF]);

        Assert.Equal("-_-_", encoded);
        Assert.DoesNotContain('+', encoded);
        Assert.DoesNotContain('/', encoded);
        Assert.DoesNotContain('=', encoded);
    }

    [Fact]
    public void Decode_AcceptsUnpaddedInput()
    {
        Assert.Equal([1], Base64Url.Decode("AQ"));
    }

    [Fact]
    public void Decode_RejectsPadding()
    {
        Assert.Throws<FormatException>(() => Base64Url.Decode("AQ=="));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(16)]
    [InlineData(31)]
    [InlineData(32)]
    [InlineData(33)]
    [InlineData(63)]
    [InlineData(64)]
    [InlineData(100)]
    public void RoundTrip_RandomLengths(int length)
    {
        var data = new byte[length];
        new Random(length).NextBytes(data);

        var decoded = Base64Url.Decode(Base64Url.Encode(data));

        Assert.Equal(data, decoded);
    }

    [Theory]
    [InlineData("A")]
    [InlineData("AAAAA")]
    public void Decode_InvalidLength_Throws(string encoded)
    {
        Assert.Throws<FormatException>(() => Base64Url.Decode(encoded));
    }

    [Theory]
    [InlineData("****")]
    [InlineData("中文")]
    public void Decode_IllegalCharacters_Throws(string encoded)
    {
        Assert.Throws<FormatException>(() => Base64Url.Decode(encoded));
    }

    [Theory]
    [InlineData("abcd ef")]
    [InlineData("ab\tcd")]
    [InlineData("ab\rcd")]
    [InlineData("ab\ncd")]
    public void Decode_RejectsWhitespace(string encoded)
    {
        Assert.Throws<FormatException>(() => Base64Url.Decode(encoded));
    }

    [Theory]
    [InlineData("ab+d")]
    [InlineData("ab/d")]
    public void Decode_RejectsStandardBase64Characters(string encoded)
    {
        Assert.Throws<FormatException>(() => Base64Url.Decode(encoded));
    }
}
