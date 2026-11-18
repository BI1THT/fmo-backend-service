using System.Collections.Concurrent;
using Sas.Logging;

namespace Sas.Server;

public sealed class RateLimitConfig
{
    public bool Enabled { get; set; } = true;
    public int GlobalPerMinute { get; set; } = 600;

    public bool BreakerEnabled { get; set; } = true;
    public int BreakerFailures { get; set; } = 20;
    public int BreakerWindowSec { get; set; } = 300;
    public int BreakerBanSec { get; set; } = 600;
}

/// <summary>
/// Protects SAS from request floods and repeated failed logins.
/// Global limiting is rate-based; the breaker is keyed by the validated callsign,
/// because all requests usually arrive from the same EMQX address.
/// </summary>
public sealed class AuthRateLimiter
{
    private const int MaxTrackedCallsigns = 10_000;
    private const long OneMinuteMs = 60_000;

    private readonly RateLimitConfig _config;
    private readonly object _globalLock = new();
    private readonly ConcurrentDictionary<string, BreakerState> _states = new(StringComparer.Ordinal);

    private long _globalWindowStart;
    private int _globalCount;
    private long _lastGlobalLog;

    private sealed class BreakerState
    {
        public readonly Queue<long> Failures = new();
        public long BannedUntil;
        public long LastSeen;
        public long LastLog;
    }

    public AuthRateLimiter(RateLimitConfig config)
    {
        _config = config;
    }

    public bool TryAcquireGlobal()
    {
        if (!_config.Enabled || _config.GlobalPerMinute <= 0)
            return true;

        var now = Environment.TickCount64;

        lock (_globalLock)
        {
            if (now - _globalWindowStart >= OneMinuteMs)
            {
                _globalWindowStart = now;
                _globalCount = 0;
            }

            if (_globalCount < _config.GlobalPerMinute)
            {
                _globalCount++;
                return true;
            }

            if (now - _lastGlobalLog >= OneMinuteMs)
            {
                _lastGlobalLog = now;
                Logger.Warn($"HTTP auth: global rate limit reached ({_config.GlobalPerMinute}/min)");
            }

            return false;
        }
    }

    public bool IsBanned(string callsign, string requestId, out long retryAfterSec)
    {
        retryAfterSec = 0;

        if (!_config.BreakerEnabled || _config.BreakerFailures <= 0 || _config.BreakerBanSec <= 0)
            return false;

        if (!_states.TryGetValue(callsign, out var state))
            return false;

        var now = Environment.TickCount64;

        lock (state)
        {
            if (state.BannedUntil <= now)
                return false;

            retryAfterSec = Math.Max(1, (state.BannedUntil - now + 999) / 1000);

            if (now - state.LastLog >= OneMinuteMs)
            {
                state.LastLog = now;
                Logger.Warn($"HTTP auth: breaker active callsign={LogSafe.Format(callsign)} req={requestId} retryAfterSec={retryAfterSec}");
            }

            return true;
        }
    }

    public void RecordSuccess(string callsign)
    {
        if (_config.BreakerEnabled)
            _states.TryRemove(callsign, out _);
    }

    public void RecordFailure(string callsign, string requestId)
    {
        if (!_config.BreakerEnabled || _config.BreakerFailures <= 0)
            return;

        var now = Environment.TickCount64;
        var state = _states.GetOrAdd(callsign, _ => new BreakerState());

        lock (state)
        {
            state.LastSeen = now;
            state.Failures.Enqueue(now);

            var windowMs = Math.Max(1, _config.BreakerWindowSec) * 1000L;
            while (state.Failures.Count > 0 && now - state.Failures.Peek() > windowMs)
                state.Failures.Dequeue();

            if (state.Failures.Count >= _config.BreakerFailures)
            {
                state.BannedUntil = now + Math.Max(1, _config.BreakerBanSec) * 1000L;
                state.Failures.Clear();

                if (now - state.LastLog >= OneMinuteMs)
                {
                    state.LastLog = now;
                    Logger.Warn($"HTTP auth: breaker opened callsign={LogSafe.Format(callsign)} req={requestId} failures={_config.BreakerFailures} banSec={_config.BreakerBanSec}");
                }
            }
        }

        if (_states.Count > MaxTrackedCallsigns)
            Cleanup(now);
    }

    private void Cleanup(long now)
    {
        var expireMs = Math.Max(_config.BreakerWindowSec, _config.BreakerBanSec) * 2000L;

        foreach (var pair in _states)
        {
            var state = pair.Value;
            lock (state)
            {
                if (state.BannedUntil <= now && state.LastSeen < now - expireMs)
                    _states.TryRemove(pair.Key, out _);
            }
        }
    }
}
