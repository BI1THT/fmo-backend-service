using System.Threading.Channels;

namespace Sas.Logging;

public enum LogLevel
{
    Debug = 0,
    Info = 1,
    Warn = 2,
    Error = 3
}

public static class Logger
{
    private static volatile LogLevel _level = LogLevel.Info;

    private static readonly object _resetLock = new();

    private static Channel<(string Line, TextWriter Writer)> _channel =
        CreateChannel();

    private static Task _consumer = StartConsumer(_channel);

    private static TextWriter _stdout = Console.Out;
    private static TextWriter _stderr = Console.Error;

    private static Channel<(string Line, TextWriter Writer)> CreateChannel() =>
        Channel.CreateUnbounded<(string, TextWriter)>(new UnboundedChannelOptions
        {
            SingleReader = true
        });

    private static Task StartConsumer(Channel<(string Line, TextWriter Writer)> channel) =>
        Task.Run(() => ConsumeAsync(channel));

    public static void SetLevel(LogLevel level) => _level = level;

    /// <summary>
    /// Test hook: replaces the output writers and re-creates the background queue,
    /// so logger behaviour can be asserted and tests stay independent.
    /// </summary>
    internal static void ResetForTests(TextWriter? stdout = null, TextWriter? stderr = null)
    {
        lock (_resetLock)
        {
            _channel.Writer.TryComplete();
            try
            {
                _consumer.Wait(TimeSpan.FromSeconds(5));
            }
            catch
            {
            }

            _stdout = stdout ?? Console.Out;
            _stderr = stderr ?? Console.Error;
            _channel = CreateChannel();
            _consumer = StartConsumer(_channel);
        }
    }

    public static void SetLevel(string level)
    {
        SetLevel(level.ToUpperInvariant() switch
        {
            "DEBUG" => LogLevel.Debug,
            "INFO" => LogLevel.Info,
            "WARN" => LogLevel.Warn,
            "ERROR" => LogLevel.Error,
            _ => LogLevel.Info
        });
    }

    public static void Debug(string message)
    {
        if (_level <= LogLevel.Debug)
            Write("DEBUG", message, _stdout);
    }

    public static void Info(string message)
    {
        if (_level <= LogLevel.Info)
            Write("INFO ", message, _stdout);
    }

    public static void Warn(string message)
    {
        if (_level <= LogLevel.Warn)
            Write("WARN ", message, _stderr);
    }

    public static void Error(string message)
    {
        if (_level <= LogLevel.Error)
            Write("ERROR", message, _stderr);
    }

    public static void Flush()
    {
        _channel.Writer.TryComplete();
        _consumer.Wait(TimeSpan.FromSeconds(5));
    }

    private static void Write(string level, string message, TextWriter writer)
    {
        var ts = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
        var line = $"[{ts}] [{level}] {message}";
        if (!_channel.Writer.TryWrite((line, writer)))
            writer.WriteLine(line);
    }

    private static async Task ConsumeAsync(Channel<(string Line, TextWriter Writer)> channel)
    {
        var reader = channel.Reader;
        await foreach (var (line, writer) in reader.ReadAllAsync())
        {
            try
            {
                writer.WriteLine(line);
                writer.Flush();
            }
            catch
            {
            }
        }
    }
}
