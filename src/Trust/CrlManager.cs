using System.Collections.Concurrent;
using System.Net;
using System.Text.Encodings.Web;
using System.Text.Json;
using Sas.certs;
using Sas.Logging;

namespace Sas.Trust;

public sealed class CrlManager : ICrlPolicy, IDisposable
{
    private readonly string _crlDir;
    private readonly int _refreshSec;
    private readonly HttpClient _http;
    private readonly bool _ownsHttpClient;

    private RootCaCert[] _roots = [];
    private readonly ConcurrentDictionary<string, RootCaCert> _rootsByFp = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, RootCrl> _rootCrls = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, IntermediateCrl> _intermediateCrls = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, IntermediateCaCert> _knownIntermediates = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, Task> _pendingFetches = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, CrlAvailability> _rootState = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, CrlAvailability> _intermediateState = new(StringComparer.Ordinal);

    private static readonly JsonSerializerOptions MetaJsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    private Timer? _timer;
    private int _refreshing;

    public CrlManager(string rootsDir, int refreshSec = 14400, HttpClient? http = null)
    {
        _refreshSec = refreshSec;
        _crlDir = Path.Combine(Path.GetDirectoryName(rootsDir)!, "crl");
        _http = http ?? new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        _ownsHttpClient = http == null;
    }

    internal static string FingerprintKey(byte[] fingerprint) =>
        CertBase.FingerprintHex(fingerprint);

    internal static string CacheDirectoryName(string type, string? name, byte[] fingerprint)
    {
        var key = FingerprintKey(fingerprint);
        return $"{type}-{CaNameSanitizer.Sanitize(name)}-{CertBase.HexPrefix(key, 16)}";
    }

    public void Initialize(RootCaCert[] roots)
    {
        _roots = roots;
        _rootsByFp.Clear();
        _rootCrls.Clear();
        _rootState.Clear();
        _knownIntermediates.Clear();
        _intermediateCrls.Clear();
        _intermediateState.Clear();
        _pendingFetches.Clear();

        foreach (var root in roots)
        {
            var key = FingerprintKey(root.Fingerprint());
            _rootsByFp[key] = root;
            _rootState[key] = string.IsNullOrWhiteSpace(root.Crl)
                ? CrlAvailability.NotConfigured
                : CrlAvailability.NotFetched;
            WriteMeta("root", root.SubjectName, root.Sn, root.Fingerprint(), root.Crl);
        }

        LoadCachedCrls();

        if (_refreshSec <= 0)
        {
            Logger.Info($"CRL manager started: {_roots.Length} root(s), background refresh disabled");
            return;
        }

        _ = RefreshAllAsync().ContinueWith(t =>
            Logger.Warn($"CRL initial refresh error: {t.Exception?.InnerException?.Message}"),
            TaskContinuationOptions.OnlyOnFaulted);

        _timer = new Timer(_ => _ = OnTimerTickAsync(), null,
            TimeSpan.FromSeconds(_refreshSec),
            TimeSpan.FromSeconds(_refreshSec));
        Logger.Info($"CRL manager started: {_roots.Length} root(s), refresh every {_refreshSec}s");
    }

    public void RegisterIntermediate(IntermediateCaCert intermediate)
    {
        var key = FingerprintKey(intermediate.Fingerprint());

        if (_knownIntermediates.TryAdd(key, intermediate))
            WriteMeta("intermediate", intermediate.SubjectName, intermediate.Sn,
                intermediate.Fingerprint(), intermediate.Crl);

        if (string.IsNullOrWhiteSpace(intermediate.Crl))
        {
            SetIntermediateState(intermediate, CrlAvailability.NotConfigured);
            return;
        }

        if (_intermediateCrls.ContainsKey(key))
        {
            SetIntermediateState(intermediate, CrlAvailability.Fresh);
            return;
        }

        var cachePath = GetIntermediateCachePath(intermediate);
        if (File.Exists(cachePath))
        {
            try
            {
                var cachedJson = File.ReadAllText(cachePath);
                var doc = JsonDocument.Parse(cachedJson).RootElement;
                if (!doc.TryGetProperty("issuerSn", out _) || !doc.TryGetProperty("entries", out _))
                    throw new InvalidDataException("incomplete CRL cache");
                var crl = IntermediateCrl.FromJson(doc);
                if (crl.VerifyBy(intermediate) && crl.IssuerSn == intermediate.Sn)
                {
                    _intermediateCrls.TryAdd(key, crl);
                    SetIntermediateState(intermediate, CrlAvailability.Fresh);
                    Logger.Info($"Loaded cached intermediate CRL: sn={intermediate.Sn} fp={CertBase.HexPrefix(key)} crlNumber={crl.CrlNumber}");
                    return;
                }
            }
            catch (Exception ex)
            {
                Logger.Warn($"Failed to load cached intermediate CRL for sn={intermediate.Sn} fp={CertBase.HexPrefix(key)}: {ex.Message}");
            }
        }

        _pendingFetches.GetOrAdd(key, _key =>
        {
            var fetchTask = RefreshIntermediateCrlAsync(intermediate);
            fetchTask.ContinueWith(t =>
            {
                _pendingFetches.TryRemove(key, out _);
                if (t.IsFaulted)
                    Logger.Warn($"Background CRL fetch failed for sn={intermediate.Sn} fp={CertBase.HexPrefix(key)}: {t.Exception?.InnerException?.Message}");
            });
            return fetchTask;
        });
    }

    public bool IsIntermediateRevoked(
        byte[] issuerRootFingerprint, long sn, byte[] fingerprint, out string? reason)
    {
        reason = null;

        // Only the root that signed this intermediate may revoke it. Looking at
        // every cached root CRL would let any trusted root revoke another
        // root's intermediates.
        var key = FingerprintKey(issuerRootFingerprint);
        if (!_rootCrls.TryGetValue(key, out var crl) ||
            !crl.IsRevoked(sn, fingerprint))
        {
            return false;
        }

        reason = $"intermediate CA sn={sn} revoked by root CRL (rootFp={CertBase.HexPrefix(key)})";
        return true;
    }

    public bool IsUserRevoked(
        byte[] issuerIntermediateFingerprint, long uid, byte[] fingerprint, out string? reason)
    {
        reason = null;

        // Only the intermediate that signed this user certificate may revoke
        // it, otherwise a compromised intermediate could deny service to users
        // issued by a different CA.
        var key = FingerprintKey(issuerIntermediateFingerprint);
        if (!_intermediateCrls.TryGetValue(key, out var crl) ||
            !crl.IsRevoked(uid, fingerprint))
        {
            return false;
        }

        reason = $"user cert uid={uid} revoked by intermediate CRL (issuerFp={CertBase.HexPrefix(key)})";
        return true;
    }

    public bool IsRootCrlOutdated(byte[] rootFingerprint, long nowUtc)
    {
        var key = FingerprintKey(rootFingerprint);
        if (_rootCrls.TryGetValue(key, out var crl))
            return crl.IsOutdated(nowUtc);
        return false;
    }

    public CrlAvailability GetRootCrlAvailability(
        byte[] rootFingerprint, long rootSn, long nowUtc)
    {
        var key = FingerprintKey(rootFingerprint);
        if (!_rootsByFp.TryGetValue(key, out var root) ||
            root.Sn != rootSn ||
            string.IsNullOrWhiteSpace(root.Crl))
        {
            return CrlAvailability.NotConfigured;
        }

        if (_rootCrls.TryGetValue(key, out var crl))
            return crl.IsOutdated(nowUtc) ? CrlAvailability.Stale : CrlAvailability.Fresh;

        return _rootState.GetValueOrDefault(key, CrlAvailability.NotFetched);
    }

    public CrlAvailability GetIntermediateCrlAvailability(
        byte[] intermediateFingerprint, long intermediateSn, long nowUtc)
    {
        var key = FingerprintKey(intermediateFingerprint);
        if (!_knownIntermediates.TryGetValue(key, out var intermediate) ||
            intermediate.Sn != intermediateSn ||
            string.IsNullOrWhiteSpace(intermediate.Crl))
        {
            return CrlAvailability.NotConfigured;
        }

        if (_intermediateCrls.TryGetValue(key, out var crl))
            return crl.IsOutdated(nowUtc) ? CrlAvailability.Stale : CrlAvailability.Fresh;

        return _intermediateState.GetValueOrDefault(key, CrlAvailability.NotFetched);
    }

    private void SetRootState(RootCaCert root, CrlAvailability state)
    {
        var key = FingerprintKey(root.Fingerprint());
        if (_rootState.TryGetValue(key, out var previous) && previous == state)
            return;

        _rootState[key] = state;
        if (state == CrlAvailability.FetchFailed)
            Logger.Warn($"Root CRL unavailable: sn={root.Sn} fp={CertBase.HexPrefix(key)} (fetch failed)");
    }

    private void SetIntermediateState(IntermediateCaCert intermediate, CrlAvailability state)
    {
        var key = FingerprintKey(intermediate.Fingerprint());
        if (_intermediateState.TryGetValue(key, out var previous) && previous == state)
            return;

        _intermediateState[key] = state;
        if (state == CrlAvailability.FetchFailed)
            Logger.Warn($"Intermediate CRL unavailable: sn={intermediate.Sn} fp={CertBase.HexPrefix(key)} (fetch failed)");
    }

    public void Dispose()
    {
        _timer?.Dispose();

        // Let in-flight fetches finish before the HTTP client and the cache
        // directory go away; failures are already logged by the continuation.
        var pending = _pendingFetches.Values.ToArray();
        if (pending.Length > 0)
        {
            try
            {
                Task.WaitAll(pending, TimeSpan.FromSeconds(5));
            }
            catch (AggregateException)
            {
            }
        }

        if (_ownsHttpClient)
            _http?.Dispose();
    }

    private async Task OnTimerTickAsync()
    {
        if (Interlocked.Exchange(ref _refreshing, 1) == 1)
            return;
        try
        {
            Logger.Debug("CRL refresh cycle started");
            await RefreshAllAsync();
            Logger.Debug("CRL refresh cycle completed");
        }
        catch (Exception ex)
        {
            Logger.Warn($"CRL refresh cycle error: {ex.Message}");
        }
        finally
        {
            Interlocked.Exchange(ref _refreshing, 0);
        }
    }

    private async Task RefreshAllAsync()
    {
        var rootTasks = _roots.Select(RefreshRootCrlAsync);
        var intTasks = _knownIntermediates.Values.Select(RefreshIntermediateCrlAsync);
        await Task.WhenAll(rootTasks.Concat(intTasks));
    }

    private async Task RefreshRootCrlAsync(RootCaCert root)
    {
        if (string.IsNullOrWhiteSpace(root.Crl))
            return;

        var key = FingerprintKey(root.Fingerprint());

        try
        {
            var json = await _http.GetStringAsync(root.Crl);
            var doc = JsonDocument.Parse(json).RootElement;

            if (!doc.TryGetProperty("issuerSn", out _) || !doc.TryGetProperty("entries", out _))
            {
                Logger.Info($"Root CRL not published yet: {root.Crl}");
                if (!_rootCrls.ContainsKey(key))
                    SetRootState(root, CrlAvailability.NotPublished);
                return;
            }

            var crl = RootCrl.FromJson(doc);

            if (!crl.VerifyBy(root))
            {
                Logger.Error($"Root CRL signature invalid: {root.Crl}");
                if (!_rootCrls.ContainsKey(key))
                    SetRootState(root, CrlAvailability.FetchFailed);
                return;
            }

            if (crl.IssuerSn != root.Sn)
            {
                Logger.Error($"Root CRL issuerSn mismatch: crl.issuerSn={crl.IssuerSn} root.sn={root.Sn}");
                if (!_rootCrls.ContainsKey(key))
                    SetRootState(root, CrlAvailability.FetchFailed);
                return;
            }

            var updated = false;
            _rootCrls.AddOrUpdate(key,
                _ => { updated = true; return crl; },
                (_, existing) =>
                {
                    if (crl.CrlNumber > existing.CrlNumber) { updated = true; return crl; }
                    return existing;
                });

            if (updated)
            {
                SaveCachedRootCrl(root, json);
                Logger.Info($"Root CRL updated: sn={root.Sn} fp={CertBase.HexPrefix(key)} crlNumber={crl.CrlNumber}");
            }

            SetRootState(root, CrlAvailability.Fresh);
        }
        catch (HttpRequestException ex) when (ex.StatusCode == HttpStatusCode.NotFound)
        {
            Logger.Info($"No root CRL available for {root.Crl} (404 Not Found)");
            if (!_rootCrls.ContainsKey(key))
                SetRootState(root, CrlAvailability.NotPublished);
        }
        catch (Exception ex)
        {
            Logger.Warn($"Failed to refresh root CRL ({root.Crl}): {ex.Message}");
            if (!_rootCrls.ContainsKey(key))
                SetRootState(root, CrlAvailability.FetchFailed);
        }
    }

    private async Task RefreshIntermediateCrlAsync(IntermediateCaCert issuer)
    {
        if (string.IsNullOrWhiteSpace(issuer.Crl))
            return;

        var key = FingerprintKey(issuer.Fingerprint());

        try
        {
            var json = await _http.GetStringAsync(issuer.Crl);
            var doc = JsonDocument.Parse(json).RootElement;

            if (!doc.TryGetProperty("issuerSn", out _) || !doc.TryGetProperty("entries", out _))
            {
                Logger.Info($"Intermediate CRL not published yet: {issuer.Crl}");
                if (!_intermediateCrls.ContainsKey(key))
                    SetIntermediateState(issuer, CrlAvailability.NotPublished);
                return;
            }

            var crl = IntermediateCrl.FromJson(doc);

            if (!crl.VerifyBy(issuer))
            {
                Logger.Error($"Intermediate CRL signature invalid: {issuer.Crl}");
                if (!_intermediateCrls.ContainsKey(key))
                    SetIntermediateState(issuer, CrlAvailability.FetchFailed);
                return;
            }

            if (crl.IssuerSn != issuer.Sn)
            {
                Logger.Error($"Intermediate CRL issuerSn mismatch: crl.issuerSn={crl.IssuerSn} issuer.sn={issuer.Sn}");
                if (!_intermediateCrls.ContainsKey(key))
                    SetIntermediateState(issuer, CrlAvailability.FetchFailed);
                return;
            }

            var updated = false;
            _intermediateCrls.AddOrUpdate(key,
                _ => { updated = true; return crl; },
                (_, existing) =>
                {
                    if (crl.CrlNumber > existing.CrlNumber) { updated = true; return crl; }
                    return existing;
                });

            if (updated)
            {
                SaveCachedIntermediateCrl(issuer, json);
                Logger.Info($"Intermediate CRL loaded: sn={issuer.Sn} fp={CertBase.HexPrefix(key)} crlNumber={crl.CrlNumber}");
            }

            SetIntermediateState(issuer, CrlAvailability.Fresh);
        }
        catch (HttpRequestException ex) when (ex.StatusCode == HttpStatusCode.NotFound)
        {
            Logger.Info($"No intermediate CRL available for {issuer.Crl} (404 Not Found)");
            if (!_intermediateCrls.ContainsKey(key))
                SetIntermediateState(issuer, CrlAvailability.NotPublished);
        }
        catch (Exception ex)
        {
            Logger.Warn($"Failed to refresh intermediate CRL ({issuer.Crl}): {ex.Message}");
            if (!_intermediateCrls.ContainsKey(key))
                SetIntermediateState(issuer, CrlAvailability.FetchFailed);
        }
    }

    private void LoadCachedCrls()
    {
        if (!Directory.Exists(_crlDir))
            return;

        foreach (var root in _roots)
        {
            var key = FingerprintKey(root.Fingerprint());
            var rootCachePath = GetRootCachePath(root);

            if (!File.Exists(rootCachePath))
            {
                var legacyPath = Path.Combine(_crlDir, root.Sn.ToString(), "root.json");
                if (File.Exists(legacyPath))
                    Logger.Info($"Ignoring legacy CRL cache for sn={root.Sn} fp={CertBase.HexPrefix(key)}; fingerprint-based cache is required");
                continue;
            }

            try
            {
                var json = File.ReadAllText(rootCachePath);
                var doc = JsonDocument.Parse(json).RootElement;
                if (!doc.TryGetProperty("issuerSn", out _) || !doc.TryGetProperty("entries", out _))
                    continue;
                var crl = RootCrl.FromJson(doc);
                if (crl.VerifyBy(root) && crl.IssuerSn == root.Sn)
                {
                    _rootCrls.TryAdd(key, crl);
                    SetRootState(root, CrlAvailability.Fresh);
                    Logger.Info($"Loaded cached root CRL: sn={root.Sn} fp={CertBase.HexPrefix(key)} crlNumber={crl.CrlNumber}");
                }
            }
            catch (Exception ex)
            {
                Logger.Warn($"Failed to load cached root CRL for sn={root.Sn} fp={CertBase.HexPrefix(key)}: {ex.Message}");
            }
        }

        // Intermediate CRLs are loaded on-demand in RegisterIntermediate
        // because _knownIntermediates is empty at startup.
    }

    private string GetRootCacheDirectory(RootCaCert root) =>
        Path.Combine(_crlDir, CacheDirectoryName("root", root.SubjectName, root.Fingerprint()));

    private string GetRootCachePath(RootCaCert root) =>
        Path.Combine(GetRootCacheDirectory(root), "root.json");

    private string GetIntermediateCacheDirectory(IntermediateCaCert intermediate) =>
        Path.Combine(_crlDir,
            CacheDirectoryName("intermediate", intermediate.SubjectName, intermediate.Fingerprint()));

    private string GetIntermediateCachePath(IntermediateCaCert intermediate) =>
        Path.Combine(GetIntermediateCacheDirectory(intermediate), "intermediate.json");

    private void SaveCachedRootCrl(RootCaCert root, string rawJson)
    {
        try
        {
            var dir = GetRootCacheDirectory(root);
            Directory.CreateDirectory(dir);
            File.WriteAllText(GetRootCachePath(root), rawJson);
            WriteMeta("root", root.SubjectName, root.Sn, root.Fingerprint(), root.Crl);
        }
        catch (Exception ex)
        {
            Logger.Warn($"Failed to cache root CRL for sn={root.Sn}: {ex.Message}");
        }
    }

    private void SaveCachedIntermediateCrl(IntermediateCaCert intermediate, string rawJson)
    {
        try
        {
            var dir = GetIntermediateCacheDirectory(intermediate);
            Directory.CreateDirectory(dir);
            File.WriteAllText(GetIntermediateCachePath(intermediate), rawJson);
            WriteMeta("intermediate", intermediate.SubjectName, intermediate.Sn,
                intermediate.Fingerprint(), intermediate.Crl);
        }
        catch (Exception ex)
        {
            Logger.Warn($"Failed to cache intermediate CRL for sn={intermediate.Sn}: {ex.Message}");
        }
    }

    private void WriteMeta(string type, string name, long sn, byte[] fingerprint, string crl)
    {
        try
        {
            var dir = type == "root"
                ? Path.Combine(_crlDir, CacheDirectoryName("root", name, fingerprint))
                : Path.Combine(_crlDir, CacheDirectoryName("intermediate", name, fingerprint));

            var metaPath = Path.Combine(dir, "meta.json");
            Directory.CreateDirectory(dir);
            if (File.Exists(metaPath))
                return;

            var meta = new CrlCacheMeta
            {
                Type = type,
                Name = name,
                Sn = sn,
                Fingerprint = FingerprintKey(fingerprint),
                Crl = crl
            };

            File.WriteAllText(metaPath, JsonSerializer.Serialize(meta, MetaJsonOptions));
        }
        catch (Exception ex)
        {
            Logger.Warn($"Failed to write CRL metadata for {type} sn={sn}: {ex.Message}");
        }
    }

    private sealed class CrlCacheMeta
    {
        public string Type { get; init; } = "";
        public string Name { get; init; } = "";
        public long Sn { get; init; }
        public string Fingerprint { get; init; } = "";
        public string Crl { get; init; } = "";
    }
}
