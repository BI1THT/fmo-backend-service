using Sas.Auth;

namespace Sas.Tests.Auth;

public sealed class CallsignValidatorTests
{
    [Theory]
    [InlineData("BG6VMZ")]
    [InlineData("A")]
    [InlineData("1234567890")]
    [InlineData("BG6VMZ-7")]
    [InlineData("FMO/USER")]
    [InlineData("01234567890123456789012345678901")] // exactly 32 bytes
    public void TryNormalize_AcceptsValidCallsigns(string input)
    {
        Assert.True(CallsignValidator.TryNormalize(input, out var normalized, out var error));
        Assert.Equal("", error);
        Assert.Equal(input.ToUpperInvariant(), normalized);
    }

    [Theory]
    [InlineData("bg6vmz", "BG6VMZ")]
    [InlineData("Bg6VmZ-7", "BG6VMZ-7")]
    public void TryNormalize_UppercasesInput(string input, string expected)
    {
        Assert.True(CallsignValidator.TryNormalize(input, out var normalized, out _));
        Assert.Equal(expected, normalized);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void TryNormalize_EmptyInput_ReturnsEmptyCallsignError(string? input)
    {
        Assert.False(CallsignValidator.TryNormalize(input, out var normalized, out var error));
        Assert.Equal("", normalized);
        Assert.Equal("empty callsign", error);
    }

    [Fact]
    public void TryNormalize_TooLong_ReturnsTooLongError()
    {
        Assert.False(CallsignValidator.TryNormalize(new string('A', 33), out _, out var error));
        Assert.Equal("callsign too long", error);
    }

    [Theory]
    [InlineData("BG6 VMZ")]
    [InlineData("BG6.VMZ")]
    [InlineData("BG6_VMZ")]
    [InlineData("BG6@VMZ")]
    [InlineData("BG6+VMZ")]
    [InlineData("BG6*VMZ")]
    [InlineData("BG6#VMZ")]
    [InlineData("BG6=VMZ")]
    [InlineData("BG6\r\nX")]
    public void TryNormalize_IllegalAscii_ReturnsCharacterError(string input)
    {
        Assert.False(CallsignValidator.TryNormalize(input, out _, out var error));
        Assert.Equal("invalid callsign character", error);
    }

    [Theory]
    [InlineData("呼号")]
    [InlineData("BG6VMZé")]
    [InlineData("ＢＧ６ＶＭＺ")] // full-width
    [InlineData("BG6VMZ📻")]
    public void TryNormalize_NonAscii_ReturnsCharacterError(string input)
    {
        Assert.False(CallsignValidator.TryNormalize(input, out _, out var error));
        Assert.Equal("invalid callsign character", error);
    }

    [Theory]
    [InlineData("CON")]
    [InlineData("con")]
    [InlineData("PRN")]
    [InlineData("AUX")]
    [InlineData("NUL")]
    [InlineData("COM1")]
    [InlineData("COM9")]
    [InlineData("LPT9")]
    [InlineData("CON.txt")]
    [InlineData("con.")]
    [InlineData("CON ")]
    public void IsReservedWindowsName_ReservedNames_ReturnsTrue(string name)
    {
        Assert.True(CallsignValidator.IsReservedWindowsName(name));
    }

    [Theory]
    [InlineData("COM0")]
    [InlineData("COM10")]
    [InlineData("LPT0")]
    [InlineData("CONSOLE")]
    [InlineData("BG6VMZ")]
    [InlineData("")]
    public void IsReservedWindowsName_NormalNames_ReturnsFalse(string name)
    {
        Assert.False(CallsignValidator.IsReservedWindowsName(name));
    }
}
