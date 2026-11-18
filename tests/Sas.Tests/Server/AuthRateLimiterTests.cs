using Sas.Server;
using Sas.Tests.Fixtures;

namespace Sas.Tests.Server;

public sealed class AuthRateLimiterTests
{
    private static readonly DateTimeOffset Start = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000);

    private static RateLimitConfig CreateConfig(Action<RateLimitConfig>? configure = null)
    {
        var config = new RateLimitConfig();
        configure?.Invoke(config);
        return config;
    }

    [Theory]
    [InlineData(false, 600)]
    [InlineData(true, 0)]
    [InlineData(true, -1)]
    public void TryAcquireGlobal_AlwaysTrue_WhenDisabledOrLimitNotPositive(bool enabled, int perMinute)
    {
        var limiter = new AuthRateLimiter(
            CreateConfig(c =>
            {
                c.Enabled = enabled;
                c.GlobalPerMinute = perMinute;
            }),
            new FixedTimeProvider(Start));

        for (var i = 0; i < 100; i++)
            Assert.True(limiter.TryAcquireGlobal());
    }

    [Fact]
    public void TryAcquireGlobal_EnforcesLimitPerMinuteWindow()
    {
        var clock = new FixedTimeProvider(Start);
        var limiter = new AuthRateLimiter(CreateConfig(c => c.GlobalPerMinute = 2), clock);

        Assert.True(limiter.TryAcquireGlobal());
        Assert.True(limiter.TryAcquireGlobal());
        Assert.False(limiter.TryAcquireGlobal());

        clock.AdvanceSeconds(60);
        Assert.True(limiter.TryAcquireGlobal());
        Assert.True(limiter.TryAcquireGlobal());
        Assert.False(limiter.TryAcquireGlobal());
    }

    [Theory]
    [InlineData(false, 3, 60)]
    [InlineData(true, 0, 60)]
    [InlineData(true, 3, 0)]
    [InlineData(true, 3, -1)]
    public void IsBanned_AlwaysFalse_WhenBreakerDisabled(bool enabled, int failures, int banSec)
    {
        var limiter = new AuthRateLimiter(
            CreateConfig(c =>
            {
                c.BreakerEnabled = enabled;
                c.BreakerFailures = failures;
                c.BreakerBanSec = banSec;
            }),
            new FixedTimeProvider(Start));

        for (var i = 0; i < 10; i++)
            limiter.RecordFailure("BG6VMZ", $"req-{i}");

        Assert.False(limiter.IsBanned("BG6VMZ", "req-check", out var retryAfterSec));
        Assert.Equal(0, retryAfterSec);
    }

    [Fact]
    public void Breaker_DoesNotBanBeforeThreshold_AndBansAtThreshold()
    {
        var clock = new FixedTimeProvider(Start);
        var limiter = new AuthRateLimiter(
            CreateConfig(c =>
            {
                c.BreakerFailures = 3;
                c.BreakerWindowSec = 300;
                c.BreakerBanSec = 60;
            }),
            clock);

        limiter.RecordFailure("BG6VMZ", "req-1");
        limiter.RecordFailure("BG6VMZ", "req-2");
        Assert.False(limiter.IsBanned("BG6VMZ", "req-check", out _));

        limiter.RecordFailure("BG6VMZ", "req-3");
        Assert.True(limiter.IsBanned("BG6VMZ", "req-check", out var retryAfterSec));
        Assert.True(retryAfterSec > 0);
        Assert.InRange(retryAfterSec, 1, 60);
    }

    [Fact]
    public void Breaker_IgnoresFailuresOutsideWindow()
    {
        var clock = new FixedTimeProvider(Start);
        var limiter = new AuthRateLimiter(
            CreateConfig(c =>
            {
                c.BreakerFailures = 3;
                c.BreakerWindowSec = 300;
                c.BreakerBanSec = 60;
            }),
            clock);

        limiter.RecordFailure("BG6VMZ", "req-1");
        limiter.RecordFailure("BG6VMZ", "req-2");

        clock.AdvanceSeconds(301);

        limiter.RecordFailure("BG6VMZ", "req-3");
        limiter.RecordFailure("BG6VMZ", "req-4");

        Assert.False(limiter.IsBanned("BG6VMZ", "req-check", out _));
    }

    [Fact]
    public void Breaker_BanExpiresAfterBanSeconds()
    {
        var clock = new FixedTimeProvider(Start);
        var limiter = new AuthRateLimiter(
            CreateConfig(c =>
            {
                c.BreakerFailures = 3;
                c.BreakerWindowSec = 300;
                c.BreakerBanSec = 60;
            }),
            clock);

        for (var i = 0; i < 3; i++)
            limiter.RecordFailure("BG6VMZ", $"req-{i}");

        Assert.True(limiter.IsBanned("BG6VMZ", "req-check", out _));

        clock.AdvanceSeconds(60);
        Assert.False(limiter.IsBanned("BG6VMZ", "req-check", out var retryAfterSec));
        Assert.Equal(0, retryAfterSec);
    }

    [Fact]
    public void RecordSuccess_ClearsBreakerState()
    {
        var clock = new FixedTimeProvider(Start);
        var limiter = new AuthRateLimiter(
            CreateConfig(c =>
            {
                c.BreakerFailures = 3;
                c.BreakerWindowSec = 300;
                c.BreakerBanSec = 60;
            }),
            clock);

        for (var i = 0; i < 3; i++)
            limiter.RecordFailure("BG6VMZ", $"req-{i}");
        Assert.True(limiter.IsBanned("BG6VMZ", "req-check", out _));

        limiter.RecordSuccess("BG6VMZ");
        Assert.False(limiter.IsBanned("BG6VMZ", "req-check", out _));

        // 状态被清除后重新计数，单次失败不应立即封禁。
        limiter.RecordFailure("BG6VMZ", "req-after-success");
        Assert.False(limiter.IsBanned("BG6VMZ", "req-check", out _));
    }

    [Fact]
    public void Breaker_KeyIsCaseSensitive()
    {
        var clock = new FixedTimeProvider(Start);
        var limiter = new AuthRateLimiter(
            CreateConfig(c =>
            {
                c.BreakerFailures = 3;
                c.BreakerWindowSec = 300;
                c.BreakerBanSec = 60;
            }),
            clock);

        for (var i = 0; i < 3; i++)
            limiter.RecordFailure("bg6vmz", $"req-{i}");

        Assert.True(limiter.IsBanned("bg6vmz", "req-check", out _));
        Assert.False(limiter.IsBanned("BG6VMZ", "req-check", out _));
    }

    [Fact]
    public void TryAcquireGlobal_IsThreadSafe()
    {
        var limiter = new AuthRateLimiter(
            CreateConfig(c => c.GlobalPerMinute = 50),
            new FixedTimeProvider(Start));

        var allowed = 0;
        Parallel.For(0, 200, _ =>
        {
            if (limiter.TryAcquireGlobal())
                Interlocked.Increment(ref allowed);
        });

        Assert.Equal(50, allowed);
    }
}
