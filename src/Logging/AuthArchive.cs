using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using Sas.Auth;

namespace Sas.Logging;

public sealed class ArchiveConfig
{
    public bool Enabled { get; set; } = true;

    public string Dir { get; set; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        ".sas", "archive");

    public bool RecordDenied { get; set; } = true;

    public bool RecordDeniedPayload { get; set; } = false;

    public double DeniedPayloadSampleRate { get; set; } = 0.0;

    public int RetentionDays { get; set; } = 30;

    public long MaxFileBytes { get; set; } = 16 * 1024 * 1024;

    public int MaxRecordBytes { get; set; } = 16 * 1024;
}

public sealed record AuthArchiveRecord
{
    public int V { get; init; } = 1;
    public string Ts { get; init; } = "";
    public string RequestId { get; init; } = "";
    public string Callsign { get; init; } = "";
    public string Result { get; init; } = "";
    public string? Reason { get; init; }
    public long? RootSn { get; init; }
    public string? RootName { get; init; }
    public long? IssuerSn { get; init; }
    public string? IssuerName { get; init; }
    public long? UserUid { get; init; }
    public string? Role { get; init; }
    public string? ClaimedRole { get; init; }
    public string? TargetCallsign { get; init; }
    public long? TargetUid { get; init; }
    public string? TargetUrl { get; init; }
    public int? TargetPort { get; init; }
    public long? Timestamp { get; init; }
    public int PasswordLength { get; init; }
    public string PasswordSha256 { get; init; } = "";
    public int PayloadLength { get; init; }
    public string PayloadSha256 { get; init; } = "";
    public string? Password { get; init; }
    public JsonElement? Payload { get; init; }
}

/// <summary>
/// Writes one JSON line per authentication attempt, grouped by callsign and day.
/// All disk I/O happens on a single background worker so authentication is never blocked.
/// </summary>
public sealed class AuthArchive : IArchiveSink
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    private readonly ArchiveConfig _config;
    private readonly TimeProvider _time;
    private readonly Channel<AuthArchiveRecord> _channel;
    private readonly Task? _worker;
    private const int MaxOpenWriters = 64;

    private readonly Dictionary<string, WriterState> _writers = new(StringComparer.Ordinal);
    private int _dropLogged;
    private int _errorLogged;
    private int _truncateLogged;
    private DateTime _lastCleanupDate = DateTime.MinValue;

    private sealed class WriterState
    {
        public required StreamWriter Writer { get; init; }
        public required long Bytes { get; set; }
    }

    public AuthArchive(ArchiveConfig config, TimeProvider? time = null)
    {
        _config = config;
        _time = time ?? TimeProvider.System;
        _channel = Channel.CreateBounded<AuthArchiveRecord>(new BoundedChannelOptions(4096)
        {
            SingleReader = true,
            FullMode = BoundedChannelFullMode.DropWrite
        });

        if (!_config.Enabled)
            return;

        _worker = Task.Run(ConsumeAsync);
        Logger.Info($"Auth archive: enabled dir={_config.Dir} retention={_config.RetentionDays}d");
    }

    public void Write(AuthArchiveRecord record)
    {
        if (!_config.Enabled)
            return;

        if (!_channel.Writer.TryWrite(record) &&
            Interlocked.Exchange(ref _dropLogged, 1) == 0)
        {
            Logger.Warn("Auth archive: write queue full, dropping record(s)");
        }
    }

    public void Flush()
    {
        if (!_config.Enabled)
            return;

        _channel.Writer.TryComplete();
        try
        {
            _worker?.Wait(TimeSpan.FromSeconds(5));
        }
        catch
        {
        }
    }

    private async Task ConsumeAsync()
    {
        Cleanup();
        _lastCleanupDate = _time.GetLocalNow().Date;

        await foreach (var record in _channel.Reader.ReadAllAsync())
        {
            try
            {
                WriteRecord(record);
            }
            catch (Exception ex)
            {
                if (Interlocked.Exchange(ref _errorLogged, 1) == 0)
                    Logger.Error($"Auth archive: write failed: {ex.Message}");
            }
        }

        CloseAll();
    }

    private void WriteRecord(AuthArchiveRecord record)
    {
        var today = _time.GetLocalNow().Date;
        if (_lastCleanupDate != today)
        {
            _lastCleanupDate = today;
            Cleanup();
        }

        var date = today.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
        var callsign = SanitizeCallsign(record.Callsign);
        var dir = Path.Combine(_config.Dir, callsign);
        EnsureDirectory(dir);

        var key = callsign + "|" + date;
        if (!_writers.TryGetValue(key, out var state))
        {
            // Bound open handles when clients use many different callsigns.
            if (_writers.Count >= MaxOpenWriters)
                CloseAll();

            state = OpenWriter(dir, date);
            _writers[key] = state;
        }

        var line = JsonSerializer.Serialize(record, JsonOptions);

        if (_config.MaxRecordBytes > 0 &&
            Encoding.UTF8.GetByteCount(line) > _config.MaxRecordBytes)
        {
            var summary = record with { Password = null, Payload = null };
            line = JsonSerializer.Serialize(summary, JsonOptions);

            if (Interlocked.Exchange(ref _truncateLogged, 1) == 0)
                Logger.Warn($"Auth archive: record exceeded {_config.MaxRecordBytes} bytes, storing summary only");
        }

        var bytes = Encoding.UTF8.GetByteCount(line) + 1;

        if (_config.MaxFileBytes > 0 &&
            state.Bytes > 0 &&
            state.Bytes + bytes > _config.MaxFileBytes)
        {
            state.Writer.Dispose();
            _writers.Remove(key);
            state = OpenWriter(dir, date, rotate: true);
            _writers[key] = state;
        }

        state.Writer.WriteLine(line);
        state.Writer.Flush();
        state.Bytes += bytes;
    }

    private static WriterState OpenWriter(string dir, string date, bool rotate = false)
    {
        var path = Path.Combine(dir, $"{date}.jsonl");
        if (rotate)
        {
            for (var i = 1; ; i++)
            {
                var candidate = Path.Combine(dir, $"{date}.{i}.jsonl");
                if (!File.Exists(candidate))
                {
                    path = candidate;
                    break;
                }
            }
        }

        var stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read);
        TryRestrictFile(path);

        var writer = new StreamWriter(stream, new UTF8Encoding(false))
        {
            NewLine = "\n",
            AutoFlush = false
        };

        return new WriterState
        {
            Writer = writer,
            Bytes = stream.Length
        };
    }

    private static void EnsureDirectory(string dir)
    {
        if (Directory.Exists(dir))
            return;

        Directory.CreateDirectory(dir);
        if (!OperatingSystem.IsWindows())
        {
            try
            {
                File.SetUnixFileMode(dir,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }
            catch
            {
            }
        }
    }

    private static void TryRestrictFile(string path)
    {
        if (OperatingSystem.IsWindows())
            return;

        try
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        catch
        {
        }
    }

    private void Cleanup()
    {
        if (_config.RetentionDays <= 0 || !Directory.Exists(_config.Dir))
            return;

        var cutoff = _time.GetLocalNow().Date.AddDays(-_config.RetentionDays);

        foreach (var callsignDir in Directory.GetDirectories(_config.Dir))
        {
            try
            {
                foreach (var file in Directory.GetFiles(callsignDir, "*.jsonl"))
                {
                    var name = Path.GetFileName(file);
                    var datePart = name.Length >= 10 ? name[..10] : "";
                    if (DateTime.TryParseExact(datePart, "yyyy-MM-dd",
                            CultureInfo.InvariantCulture, DateTimeStyles.None, out var date) &&
                        date < cutoff)
                    {
                        File.Delete(file);
                    }
                }

                if (!Directory.EnumerateFileSystemEntries(callsignDir).Any())
                    Directory.Delete(callsignDir);
            }
            catch
            {
            }
        }
    }

    private void CloseAll()
    {
        foreach (var state in _writers.Values)
        {
            try
            {
                state.Writer.Dispose();
            }
            catch
            {
            }
        }

        _writers.Clear();
    }

    internal static string SanitizeCallsign(string callsign)
    {
        var upper = (callsign ?? "").Trim().ToUpperInvariant();
        var sb = new StringBuilder(upper.Length);

        foreach (var ch in upper)
        {
            if (ch is >= 'A' and <= 'Z' or >= '0' and <= '9' or '-')
                sb.Append(ch);
            else
                sb.Append('_');
        }

        var name = sb.Length == 0 ? "_UNKNOWN" : sb.ToString();
        if (name.Length > CallsignValidator.MaxBytes)
            name = name[..CallsignValidator.MaxBytes];

        // Avoid Windows reserved device names such as CON, NUL, COM1.
        if (CallsignValidator.IsReservedWindowsName(name))
            name = "_" + name;

        return name;
    }
}
