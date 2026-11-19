using Sas.Logging;

namespace Sas.Tests.Logging;

public sealed class LogSafeTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Format_EmptyValue_ReturnsDash(string? value)
    {
        Assert.Equal("-", LogSafe.Format(value));
    }

    [Fact]
    public void Format_PlainText_IsUnchanged()
    {
        Assert.Equal("BG6VMZ", LogSafe.Format("BG6VMZ"));
        Assert.Equal("呼号 BG6VMZ", LogSafe.Format("呼号 BG6VMZ"));
    }

    [Theory]
    [InlineData("\r")]
    [InlineData("\n")]
    [InlineData("\t")]
    [InlineData("\0")]
    [InlineData("\u001b")]
    [InlineData("\u2028")]
    [InlineData("\u2029")]
    [InlineData("\u202E")]
    public void Format_ControlCharacters_AreReplaced(string value)
    {
        Assert.Equal("?", LogSafe.Format(value));
    }

    [Fact]
    public void Format_NewlineInjection_NeverProducesLineBreaks()
    {
        var formatted = LogSafe.Format("BG6VMZ\r\nINFO fake log line");

        Assert.DoesNotContain('\r', formatted);
        Assert.DoesNotContain('\n', formatted);
        Assert.Contains('?', formatted);
    }

    [Fact]
    public void Format_TruncatesWithEllipsis()
    {
        // The ellipsis is counted inside maxLength.
        var formatted = LogSafe.Format("abcdefghij", maxLength: 5);

        Assert.Equal("abcd…", formatted);
        Assert.Equal(5, formatted.Length);
    }

    [Fact]
    public void Format_TruncationDoesNotSplitSurrogatePair()
    {
        var formatted = LogSafe.Format("📻📻", maxLength: 3);

        Assert.Equal("📻…", formatted);
        Assert.Equal(3, formatted.Length);
    }

    [Fact]
    public void Format_ExactLength_IsNotTruncated()
    {
        Assert.Equal("abcde", LogSafe.Format("abcde", maxLength: 5));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-5)]
    public void Format_NonPositiveMaxLength_BehavesLikeOne(int maxLength)
    {
        Assert.Equal("…", LogSafe.Format("abcd", maxLength));
    }

    [Fact]
    public void Format_EmojiIsPreservedWhenNotTruncated()
    {
        Assert.Equal("📻FMO", LogSafe.Format("📻FMO", maxLength: 16));
    }
}
