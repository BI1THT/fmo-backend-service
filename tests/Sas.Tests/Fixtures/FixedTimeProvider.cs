namespace Sas.Tests.Fixtures;

/// <summary>
/// Deterministic, manually advanced clock for window/expiry tests.
/// </summary>
public sealed class FixedTimeProvider : TimeProvider
{
    private DateTimeOffset _now;

    public FixedTimeProvider(DateTimeOffset now) => _now = now;

    public static FixedTimeProvider AtUnix(long seconds) =>
        new(DateTimeOffset.FromUnixTimeSeconds(seconds));

    public override DateTimeOffset GetUtcNow() => _now;

    public void Advance(TimeSpan delta) => _now += delta;

    public void AdvanceSeconds(long seconds) => _now = _now.AddSeconds(seconds);

    public void Set(DateTimeOffset value) => _now = value;
}
