using System.Globalization;
using System.Text;
using System.Text.Json;
using Sas.Logging;
using Sas.Tests.Fixtures;

namespace Sas.Tests.Logging;

public sealed class AuthArchiveTests
{
    // 用中午 UTC，避免本地时区把日期推到相邻一天；期望日期仍从 FixedTimeProvider 推导。
    private static readonly DateTimeOffset BaseTime = new(2026, 3, 4, 12, 0, 0, TimeSpan.Zero);

    private static ArchiveConfig CreateConfig(string dir, Action<ArchiveConfig>? configure = null)
    {
        var config = new ArchiveConfig
        {
            Enabled = true,
            Dir = dir,
            RetentionDays = 30
        };
        configure?.Invoke(config);
        return config;
    }

    private static AuthArchiveRecord CreateRecord(
        string callsign = "BG6VMZ",
        string result = "allow",
        string? password = "secret-password") => new()
    {
        Ts = "2026-03-04T12:00:00Z",
        RequestId = "req-1",
        Callsign = callsign,
        Result = result,
        PasswordLength = password?.Length ?? 0,
        Password = password
    };

    private static string LocalDate(TimeProvider clock) =>
        clock.GetLocalNow().Date.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);

    private static string ArchiveFile(string dir, string callsign, TimeProvider clock, string? suffix = null)
    {
        var name = suffix == null
            ? $"{LocalDate(clock)}.jsonl"
            : $"{LocalDate(clock)}.{suffix}.jsonl";
        return Path.Combine(dir, callsign, name);
    }

    [Fact]
    public void EnabledFalse_WriteAndFlush_DoNotCreateDirectory()
    {
        using var temp = new TempDirectory("archive-disabled");
        var dir = temp.Combine("archive");
        var clock = new FixedTimeProvider(BaseTime);
        var archive = new AuthArchive(CreateConfig(dir, c => c.Enabled = false), clock);

        archive.Write(CreateRecord());
        archive.Flush();

        Assert.False(Directory.Exists(dir));
        Assert.Empty(ArchiveProbe.ReadFiles(dir));
    }

    [Fact]
    public void SingleRecord_WritesCamelCaseJsonLineWithoutBomAndWithLf()
    {
        using var temp = new TempDirectory("archive-single");
        var dir = temp.Combine("archive");
        var clock = new FixedTimeProvider(BaseTime);
        var archive = new AuthArchive(CreateConfig(dir), clock);

        archive.Write(CreateRecord(result: "allow", password: "pass-1"));
        archive.Flush();

        var file = ArchiveFile(dir, "BG6VMZ", clock);
        Assert.True(File.Exists(file));

        var raw = File.ReadAllBytes(file);
        Assert.False(raw.Length >= 3 && raw[0] == 0xEF && raw[1] == 0xBB && raw[2] == 0xBF);
        Assert.Equal((byte)'\n', raw[^1]);
        Assert.DoesNotContain((byte)'\r', raw);

        var text = Encoding.UTF8.GetString(raw);
        Assert.Equal(1, text.Count(ch => ch == '\n'));

        using var doc = JsonDocument.Parse(text);
        var root = doc.RootElement;
        Assert.Equal(JsonValueKind.Object, root.ValueKind);
        Assert.Equal(1, root.GetProperty("v").GetInt32());
        Assert.Equal("allow", root.GetProperty("result").GetString());
        Assert.Equal("BG6VMZ", root.GetProperty("callsign").GetString());
        Assert.Equal("req-1", root.GetProperty("requestId").GetString());
        // camelCase：PascalCase 属性不应出现。
        Assert.False(root.TryGetProperty("V", out _));
        Assert.False(root.TryGetProperty("Callsign", out _));
    }

    [Fact]
    public void MultipleRecords_AllAppendedInOrder()
    {
        using var temp = new TempDirectory("archive-multi");
        var dir = temp.Combine("archive");
        var clock = new FixedTimeProvider(BaseTime);
        var archive = new AuthArchive(CreateConfig(dir), clock);

        archive.Write(CreateRecord(result: "first"));
        archive.Write(CreateRecord(result: "second"));
        archive.Write(CreateRecord(result: "third"));
        archive.Flush();

        var file = ArchiveFile(dir, "BG6VMZ", clock);
        var lines = File.ReadAllLines(file);
        Assert.Equal(3, lines.Length);

        var results = lines
            .Select(line => JsonDocument.Parse(line).RootElement.GetProperty("result").GetString()!)
            .ToArray();
        Assert.Equal(["first", "second", "third"], results);

        Assert.Equal(3, ArchiveProbe.ReadRecords(dir).Count);
    }

    [Fact]
    public void OversizedRecord_IsStoredAsSummary()
    {
        using var temp = new TempDirectory("archive-record-limit");
        var dir = temp.Combine("archive");
        var clock = new FixedTimeProvider(BaseTime);
        var archive = new AuthArchive(CreateConfig(dir, c => c.MaxRecordBytes = 200), clock);

        var longPassword = new string('p', 500);
        archive.Write(CreateRecord(result: "deny", password: longPassword));
        archive.Flush();

        var record = Assert.Single(ArchiveProbe.ReadRecords(dir));
        Assert.Null(record.Password);
        Assert.Null(record.Payload);
        Assert.Equal("BG6VMZ", record.Callsign);
        Assert.Equal("deny", record.Result);
        Assert.Equal(500, record.PasswordLength);
        Assert.Equal(1, record.V);
    }

    [Fact]
    public void OversizedSummary_IsStoredAsMinimalRecord()
    {
        using var temp = new TempDirectory("archive-minimal");
        var dir = temp.Combine("archive");
        var clock = new FixedTimeProvider(BaseTime);
        var archive = new AuthArchive(
            CreateConfig(dir, c => c.MaxRecordBytes = 600),
            clock);

        var record = CreateRecord(result: "deny", password: new string('p', 500)) with
        {
            TargetUrl = "https://" + new string('u', 2000),
            ClaimedRole = new string('r', 200)
        };

        archive.Write(record);
        archive.Flush();

        var file = ArchiveFile(dir, "BG6VMZ", clock);
        var raw = File.ReadAllText(file).TrimEnd('\n');
        Assert.True(Encoding.UTF8.GetByteCount(raw) <= 600);

        var stored = Assert.Single(ArchiveProbe.ReadRecords(dir));
        Assert.Null(stored.Password);
        Assert.Null(stored.Payload);
        Assert.Equal("BG6VMZ", stored.Callsign);
        Assert.Equal("deny", stored.Result);
        Assert.Equal(500, stored.PasswordLength);
    }

    [Fact]
    public void FileSizeLimit_RotatesToSuffixedFile()
    {
        using var temp = new TempDirectory("archive-file-limit");
        var dir = temp.Combine("archive");
        var clock = new FixedTimeProvider(BaseTime);
        var archive = new AuthArchive(
            CreateConfig(dir, c =>
            {
                c.MaxFileBytes = 300;
                c.MaxRecordBytes = 0;
            }),
            clock);

        var password = new string('x', 200);
        archive.Write(CreateRecord(password: password));
        archive.Write(CreateRecord(password: password));
        archive.Flush();

        var first = ArchiveFile(dir, "BG6VMZ", clock);
        var second = ArchiveFile(dir, "BG6VMZ", clock, "1");
        Assert.True(File.Exists(first));
        Assert.True(File.Exists(second));
        Assert.Equal(2, ArchiveProbe.ReadFiles(dir).Count);
        Assert.Equal(2, ArchiveProbe.ReadRecords(dir).Count);
    }

    [Fact]
    public void Retention_DeletesFilesOlderThanRetentionDays()
    {
        using var temp = new TempDirectory("archive-retention");
        var dir = temp.Combine("archive");
        var oldDir = Directory.CreateDirectory(Path.Combine(dir, "OLDUSER")).FullName;
        var oldFile = Path.Combine(oldDir, "2020-01-01.jsonl");
        File.WriteAllText(oldFile, "{}\n");

        var clock = new FixedTimeProvider(BaseTime);
        var archive = new AuthArchive(CreateConfig(dir, c => c.RetentionDays = 30), clock);
        archive.Write(CreateRecord());
        archive.Flush();

        Assert.False(File.Exists(oldFile));
        // 旧文件删除后目录变空，清理逻辑会把空 callsign 目录一并删除。
        Assert.False(Directory.Exists(oldDir));
        Assert.DoesNotContain(ArchiveProbe.ReadRecords(dir), r => r.Callsign == "OLDUSER");
    }

    [Fact]
    public void RetentionZero_KeepsOldFiles()
    {
        using var temp = new TempDirectory("archive-retention-off");
        var dir = temp.Combine("archive");
        var oldDir = Directory.CreateDirectory(Path.Combine(dir, "OLDUSER")).FullName;
        var oldFile = Path.Combine(oldDir, "2020-01-01.jsonl");
        File.WriteAllText(oldFile, "{}\n");

        var clock = new FixedTimeProvider(BaseTime);
        var archive = new AuthArchive(CreateConfig(dir, c => c.RetentionDays = 0), clock);
        archive.Write(CreateRecord());
        archive.Flush();

        Assert.True(File.Exists(oldFile));
        Assert.True(Directory.Exists(oldDir));
    }

    [Fact]
    public void Cleanup_RemovesEmptyCallsignDirectories()
    {
        using var temp = new TempDirectory("archive-empty-dir");
        var dir = temp.Combine("archive");
        var emptyDir = Directory.CreateDirectory(Path.Combine(dir, "EMPTYCS")).FullName;

        var clock = new FixedTimeProvider(BaseTime);
        var archive = new AuthArchive(CreateConfig(dir, c => c.RetentionDays = 30), clock);
        archive.Write(CreateRecord());
        archive.Flush();

        Assert.False(Directory.Exists(emptyDir));
    }

    [Theory]
    [InlineData("bg6vmz", "BG6VMZ")]
    [InlineData("FMO/USER", "FMO_USER")]
    [InlineData(null, "_UNKNOWN")]
    [InlineData("", "_UNKNOWN")]
    [InlineData("   ", "_UNKNOWN")]
    [InlineData("CON", "_CON")]
    [InlineData("nul", "_NUL")]
    [InlineData("BG6VMZ\u0001X", "BG6VMZ_X")]
    [InlineData("BG6 VMZ", "BG6_VMZ")]
    public void SanitizeCallsign_NormalizesUntrustedInput(string? input, string expected)
    {
        Assert.Equal(expected, AuthArchive.SanitizeCallsign(input!));
    }

    [Fact]
    public void SanitizeCallsign_TruncatesTo32Characters()
    {
        var input = new string('A', 33);
        var result = AuthArchive.SanitizeCallsign(input);
        Assert.Equal(32, result.Length);
        Assert.Equal(new string('A', 32), result);
    }

    [Fact]
    public void ConcurrentWrites_AllRecordsPersisted()
    {
        const int threads = 8;
        const int perThread = 50;

        using var temp = new TempDirectory("archive-concurrent");
        var dir = temp.Combine("archive");
        var clock = new FixedTimeProvider(BaseTime);
        var archive = new AuthArchive(CreateConfig(dir), clock);

        Parallel.For(0, threads, _ =>
        {
            for (var i = 0; i < perThread; i++)
                archive.Write(CreateRecord(callsign: "CONCUR", result: "allow"));
        });

        archive.Flush();

        Assert.Equal(threads * perThread, ArchiveProbe.ReadRecords(dir).Count);
    }
}
