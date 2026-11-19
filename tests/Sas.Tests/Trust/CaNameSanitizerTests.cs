using Sas.Trust;

namespace Sas.Tests.Trust;

public sealed class CaNameSanitizerTests
{
    [Fact]
    public void Sanitize_NormalAscii_IsUnchanged()
    {
        Assert.Equal("BG5ESN", CaNameSanitizer.Sanitize("BG5ESN"));
    }

    [Fact]
    public void Sanitize_PreservesCase()
    {
        Assert.Equal("Bg5eSn", CaNameSanitizer.Sanitize("Bg5eSn"));
    }

    [Fact]
    public void Sanitize_LeadingTrailingSpaces_AreTrimmed()
    {
        Assert.Equal("BG5ESN", CaNameSanitizer.Sanitize("  BG5ESN  "));
    }

    [Fact]
    public void Sanitize_InnerSpaces_AreReplaced()
    {
        Assert.Equal("BG_5_ESN", CaNameSanitizer.Sanitize("BG 5 ESN"));
    }

    [Fact]
    public void Sanitize_ConsecutiveInvalidCharacters_AreCollapsed()
    {
        Assert.Equal("A_B", CaNameSanitizer.Sanitize("A!!!B"));
    }

    [Fact]
    public void Sanitize_TabsNewlinesAndUnicodeWhitespace_AreReplaced()
    {
        Assert.Equal("A_B_C_D", CaNameSanitizer.Sanitize("A\tB\r\nC\u00A0D"));
    }

    [Fact]
    public void Sanitize_NonAscii_IsReplaced()
    {
        Assert.Equal("CA", CaNameSanitizer.Sanitize("中文CA"));
    }

    [Fact]
    public void Sanitize_AllNonAscii_ReturnsCa()
    {
        Assert.Equal("ca", CaNameSanitizer.Sanitize("中文"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Sanitize_EmptyOrWhitespace_ReturnsCa(string? input)
    {
        Assert.Equal("ca", CaNameSanitizer.Sanitize(input));
    }

    [Fact]
    public void Sanitize_PathSeparators_AreReplacedAndTrimmed()
    {
        Assert.Equal("evil", CaNameSanitizer.Sanitize("../evil"));
        Assert.Equal("a_b", CaNameSanitizer.Sanitize("a/b"));
        Assert.Equal("a_b", CaNameSanitizer.Sanitize(@"a\b"));
    }

    [Fact]
    public void Sanitize_DotOnly_ReturnsCa()
    {
        Assert.Equal("ca", CaNameSanitizer.Sanitize(".."));
    }

    [Fact]
    public void Sanitize_ControlCharacters_AreReplaced()
    {
        Assert.Equal("A_B", CaNameSanitizer.Sanitize("A\u0001B"));
    }

    [Theory]
    [InlineData("CON", "_CON")]
    [InlineData("nul", "_nul")]
    [InlineData("COM1", "_COM1")]
    public void Sanitize_WindowsReservedName_IsPrefixed(string input, string expected)
    {
        Assert.Equal(expected, CaNameSanitizer.Sanitize(input));
    }

    [Fact]
    public void Sanitize_LongName_TruncatedTo32()
    {
        var input = new string('A', 40);

        Assert.Equal(new string('A', 32), CaNameSanitizer.Sanitize(input));
    }

    [Fact]
    public void Sanitize_LeadingTrailingUnderscores_AreTrimmed()
    {
        Assert.Equal("A", CaNameSanitizer.Sanitize("__A__"));
    }

    [Fact]
    public void Sanitize_RespectsCustomMaxLength()
    {
        Assert.Equal("ABC", CaNameSanitizer.Sanitize("ABCDEF", maxLength: 3));
    }
}
