using System.Globalization;
using System.Text;
using System.Text.Json;
using Sas.certs;
using Sas.Logging;
using Sas.Messages;
using Sas.Trust;

namespace Sas.Auth;

internal sealed class HttpAuthHandler : IAuthHandler
{
    private readonly Config _config;
    private readonly RootCaStore _rootStore;
    private readonly CertVerifier _verifier;
    private readonly ICrlPolicy _crlManager;
    private readonly AclStore _aclStore;
    private readonly IArchiveSink _archive;
    private readonly TimeProvider _time;
    private readonly Random _random;

    public HttpAuthHandler(Config config, RootCaStore rootStore,
        CertVerifier verifier, ICrlPolicy crlManager, AclStore aclStore,
        IArchiveSink archive, TimeProvider? time = null, Random? random = null)
    {
        _config = config;
        _rootStore = rootStore;
        _verifier = verifier;
        _crlManager = crlManager;
        _aclStore = aclStore;
        _archive = archive;
        _time = time ?? TimeProvider.System;
        _random = random ?? Random.Shared;
    }

    private sealed record ServerIdentity(long Uid, string Callsign, string MqttHost, int MqttPort, string CertFingerprint);

    private ServerIdentity? FindMatchingServer(string targetCallsign, long targetUid, string targetUrl, int targetPort)
    {
        if (string.Equals(targetCallsign, _config.Server.Callsign, StringComparison.OrdinalIgnoreCase)
            && targetUid == _config.Server.Uid
            && string.Equals(targetUrl, _config.Mqtt.Host, StringComparison.OrdinalIgnoreCase)
            && targetPort == _config.Mqtt.Port)
        {
            return new ServerIdentity(_config.Server.Uid, _config.Server.Callsign,
                _config.Mqtt.Host, _config.Mqtt.Port, _config.Server.CertFingerprint);
        }

        foreach (var c in _config.Mqtt.Clusters)
        {
            if (string.Equals(targetCallsign, c.Callsign, StringComparison.OrdinalIgnoreCase)
                && targetUid == c.Uid
                && string.Equals(targetUrl, c.MqttHost, StringComparison.OrdinalIgnoreCase)
                && targetPort == c.MqttPort)
            {
                return new ServerIdentity(c.Uid, c.Callsign, c.MqttHost, c.MqttPort, c.CertFingerprint);
            }
        }

        return null;
    }

    public AuthResult Process(string username, string password, string requestId)
    {
        var ctx = new AuthRequestContext(username, password, requestId);

        Logger.Debug($"HTTP auth: >>> start processing callsign={LogSafe.Format(username, CallsignValidator.MaxBytes)} req={requestId}");

        HttpPasswordPayload payload;
        try
        {
            var passwordJson = Encoding.UTF8.GetString(
                Base64Url.Decode(password));

            using var doc = JsonDocument.Parse(passwordJson);
            ctx.SetDecodedPayload(passwordJson, doc.RootElement.Clone());

            payload = doc.RootElement.Deserialize<HttpPasswordPayload>()
                ?? throw new InvalidOperationException("null payload");
        }
        catch (Exception ex)
        {
            Logger.Debug($"HTTP auth: failed to parse password payload: {ex.Message} req={requestId}");
            throw Deny(ctx, "invalid password format");
        }

        var certPackage = payload.CertPackage ?? new CertPackage();
        var serverFpText = payload.ServerFingerprint ?? "";
        var proofSignature = payload.Proof?.Signature ?? "";
        var claimedRole = payload.Role ?? "";

        ctx.ClaimedRole = claimedRole;
        ctx.TargetCallsign = payload.TargetCallsign;
        ctx.TargetUid = payload.TargetUID;
        ctx.TargetUrl = payload.TargetUrl;
        ctx.TargetPort = payload.TargetPort;
        ctx.Timestamp = payload.Timestamp;

        Logger.Debug($"HTTP auth: payload: targetCallsign={LogSafe.Format(payload.TargetCallsign)} targetUID={payload.TargetUID} targetUrl={LogSafe.Format(payload.TargetUrl)} targetPort={payload.TargetPort} timestamp={payload.Timestamp} role={LogSafe.Format(claimedRole)}");
        Logger.Debug($"HTTP auth: payload: serverFingerprint={LogSafe.Format(serverFpText, 8)}...");

        // Fast checks that do not depend on the certificate chain.
        var server = FindMatchingServer(payload.TargetCallsign, payload.TargetUID, payload.TargetUrl, payload.TargetPort);
        if (server == null)
        {
            throw Deny(ctx,
                $"server identity mismatch: target={LogSafe.Format(payload.TargetCallsign)}/{payload.TargetUID} {LogSafe.Format(payload.TargetUrl)}:{payload.TargetPort}");
        }

        var now = _time.GetUtcNow().ToUnixTimeSeconds();
        Logger.Debug($"HTTP auth: server time (UTC unix)={now}");

        if (serverFpText.Length != 43)
            throw Deny(ctx, "invalid server fingerprint");

        if (!HttpProofVerifier.IsTimestampValid(payload.Timestamp, now))
            throw Deny(ctx, "timestamp expired");

        IntermediateCaCert intermediate;
        UserCert user;
        try
        {
            intermediate = IntermediateCaCert.FromJson(certPackage.IntermediateCert);
            user = UserCert.FromJson(certPackage.UserCert);
        }
        catch (Exception ex)
        {
            Logger.Debug($"HTTP auth: failed to parse cert package: {ex.Message} req={requestId}");
            throw Deny(ctx, "invalid certificate format");
        }

        if (!CallsignValidator.TryNormalize(user.Callsign, out var certCallsign, out var certCallsignError))
            throw Deny(ctx, $"invalid certificate callsign: {certCallsignError}");

        ctx.Callsign = certCallsign;
        ctx.UserUid = user.Uid;
        ctx.IssuerSn = intermediate.Sn;
        ctx.IssuerName = intermediate.SubjectName;

        Logger.Debug($"HTTP auth: intermediate: sn={intermediate.Sn} issuerSn={intermediate.IssuerSn} subject={LogSafe.Format(intermediate.SubjectName)}");
        Logger.Debug($"HTTP auth: user: callsign={LogSafe.Format(user.Callsign)} uid={user.Uid} publicKey.length={user.PublicKey?.Length ?? 0}");

        var root = _rootStore.FindIssuer(intermediate);
        if (root == null)
            throw Deny(ctx, "chain invalid: no trusted root");

        ctx.RootSn = root.Sn;
        ctx.RootName = root.SubjectName;
        Logger.Debug($"HTTP auth: matched root: sn={root.Sn} subject={LogSafe.Format(root.SubjectName)}");

        var vr = _verifier.VerifyFullChain(root, intermediate, user, now);
        if (vr != VerifyResult.OK)
            throw Deny(ctx, $"chain invalid: {CertVerifier.GetMessage(vr)}");

        Logger.Debug("HTTP auth: certificate chain verification passed");

        // Only failures from a caller who proved possession of this callsign's
        // certificate may affect the per-callsign breaker. Early failures are
        // not attributable and are covered by the global rate limit instead.
        ctx.BreakerKey = certCallsign;

        if (!string.Equals(username, certCallsign, StringComparison.OrdinalIgnoreCase))
        {
            throw Deny(ctx,
                $"username mismatch: request={LogSafe.Format(username, CallsignValidator.MaxBytes)} cert={LogSafe.Format(certCallsign, CallsignValidator.MaxBytes)}");
        }

        if (_config.Trust.AllowIssuerSn.Length > 0 &&
            !_config.Trust.AllowIssuerSn.Contains(intermediate.Sn))
        {
            throw Deny(ctx, $"intermediate not trusted: sn={intermediate.Sn}");
        }

        _crlManager.RegisterIntermediate(intermediate);

        var rootCrlAvailability = _crlManager.GetRootCrlAvailability(root.Sn, now);
        var intermediateCrlAvailability =
            _crlManager.GetIntermediateCrlAvailability(intermediate.Sn, now);

        if (_config.Crl.Mode == "strict" &&
            (rootCrlAvailability is not CrlAvailability.Fresh ||
             intermediateCrlAvailability is not CrlAvailability.Fresh))
        {
            throw Deny(ctx,
                $"CRL unavailable: root={rootCrlAvailability} intermediate={intermediateCrlAvailability}");
        }

        if (rootCrlAvailability != CrlAvailability.Fresh ||
            intermediateCrlAvailability != CrlAvailability.Fresh)
        {
            Logger.Debug($"HTTP auth: CRL not fresh root={rootCrlAvailability} " +
                         $"intermediate={intermediateCrlAvailability} req={requestId}");
        }

        var rootOutdated = _crlManager.IsRootCrlOutdated(root.Sn, now);
        if (rootOutdated)
        {
            Logger.Warn($"HTTP auth: root CRL outdated rootSn={root.Sn} rootName={LogSafe.Format(root.SubjectName)} callsign={LogSafe.Format(certCallsign)} req={requestId}");
        }

        if (_crlManager.IsIntermediateRevoked(intermediate.Sn, intermediate.Fingerprint(), out var intReason))
            throw Deny(ctx, $"intermediate revoked: {LogSafe.Format(intReason, 128)}");

        if (_crlManager.IsUserRevoked(user.Uid, user.Fingerprint(), out var userReason))
            throw Deny(ctx, $"user revoked: {LogSafe.Format(userReason, 128)}");

        var role = DetermineRole(user, server);
        ctx.Role = role;
        if (!string.IsNullOrEmpty(claimedRole) &&
            !string.Equals(claimedRole, role, StringComparison.OrdinalIgnoreCase))
        {
            throw Deny(ctx, $"role mismatch: claimed={LogSafe.Format(claimedRole)} actual={role}");
        }

        byte[] serverFpBytes;
        try
        {
            serverFpBytes = Base64Url.Decode(serverFpText);
        }
        catch
        {
            throw Deny(ctx, "invalid server fingerprint");
        }

        if (string.IsNullOrEmpty(server.CertFingerprint))
            throw Deny(ctx, "server cert fingerprint not configured");

        byte[] expectedFp;
        try
        {
            expectedFp = Base64Url.Decode(server.CertFingerprint);
        }
        catch
        {
            throw Deny(ctx, "server cert fingerprint not configured: invalid base64url");
        }

        if (expectedFp.Length != 32 || !serverFpBytes.AsSpan().SequenceEqual(expectedFp))
            throw Deny(ctx, "server fingerprint mismatch");

        Logger.Debug($"HTTP auth: checking timestamp: payload={payload.Timestamp} server={now} drift={Math.Abs(now - payload.Timestamp)}s");

        Logger.Debug($"HTTP auth: verifying proof: serverUid={server.Uid} targetCallsign={server.Callsign} mqttHost={server.MqttHost} mqttPort={server.MqttPort}");
        var proofOk = HttpProofVerifier.Verify(
            server.Uid, server.Callsign, server.Uid,
            server.MqttHost, server.MqttPort, serverFpBytes,
            payload.Timestamp, user, claimedRole, proofSignature);

        if (!proofOk)
            throw Deny(ctx, "proof invalid");

        var isSuperuser = role == "super";
        var (allDefs, pubDefs, subDefs) = _aclStore.GetPermissions(role);

        var allTopics = _aclStore.ResolveForUid(allDefs, user.Uid);
        var pubTopics = _aclStore.ResolveForUid(pubDefs, user.Uid);
        var subTopics = _aclStore.ResolveForUid(subDefs, user.Uid);

        const int ttlJitterSec = 60;
        var maxJitter = Math.Min(ttlJitterSec, Math.Max(1, _config.Http.TtlSec / 2));
        var exp = now + _config.Http.TtlSec + _random.NextInt64(-maxJitter, maxJitter + 1);

        Logger.Info($"HTTP auth: allow {Scope(ctx)} uid={user.Uid} role={LogSafe.Format(role, 16)} target={LogSafe.Format(server.Callsign)}:{server.MqttPort}");
        _archive.Write(ctx.ToRecord("allow", null, includePayload: true));

        return new AuthResult
        {
            Callsign = certCallsign,
            Uid = user.Uid,
            Role = role,
            IsSuperuser = isSuperuser,
            IssuedAt = now,
            ExpireAt = exp,
            AllTopics = allTopics,
            PubTopics = pubTopics,
            SubTopics = subTopics
        };
    }

    private AuthDeniedException Deny(AuthRequestContext ctx, string reason)
    {
        var safeReason = LogSafe.Format(reason, 512);
        Logger.Warn($"HTTP auth: deny {Scope(ctx)} reason=\"{safeReason}\"");

        if (ctx.Payload.HasValue && _config.Archive.RecordDenied)
        {
            var includePayload = _config.Archive.RecordDeniedPayload;
            var sampleRate = _config.Archive.DeniedPayloadSampleRate;

            if (sampleRate >= 1.0)
                includePayload = true;
            else if (sampleRate > 0.0)
                includePayload = _random.NextDouble() < sampleRate;

            _archive.Write(ctx.ToRecord("deny", safeReason, includePayload));
        }

        return new AuthDeniedException(reason)
        {
            BreakerKey = ctx.BreakerKey
        };
    }

    private static string Scope(AuthRequestContext ctx)
    {
        return $"callsign={LogSafe.Format(ctx.Callsign, CallsignValidator.MaxBytes)} " +
               $"rootSn={Sn(ctx.RootSn)} rootName={LogSafe.Format(ctx.RootName)} " +
               $"issuerSn={Sn(ctx.IssuerSn)} issuerName={LogSafe.Format(ctx.IssuerName)} " +
               $"payloadLen={ctx.PayloadLength} payloadSha256={ctx.PayloadHash} " +
               $"passwordLen={ctx.PasswordLength} req={ctx.RequestId}";
    }

    private static string Sn(long? value) =>
        value?.ToString(CultureInfo.InvariantCulture) ?? "?";

    private int _serverFpMismatchLogged;

    private string DetermineRole(UserCert user, ServerIdentity server)
    {
        var userFp = user.Fingerprint();

        // The server's own certificate: both UID and fingerprint must match, so
        // a different key reusing the same UID can never self-promote. Use the
        // matched identity's fingerprint so cluster nodes work the same way.
        if (user.Uid == server.Uid &&
            TryDecodeFingerprint(server.CertFingerprint, out var serverFp) &&
            serverFp.AsSpan().SequenceEqual(userFp))
        {
            return "super";
        }

        foreach (var admin in _config.Server.Admins)
        {
            if (admin.Uid != user.Uid)
                continue;

            if (!TryDecodeFingerprint(admin.CertFingerprint, out var adminFp))
            {
                Logger.Warn($"HTTP auth: ignoring admin entry uid={admin.Uid}: invalid certFingerprint");
                continue;
            }

            if (adminFp.AsSpan().SequenceEqual(userFp))
                return string.IsNullOrEmpty(admin.Role) ? "admin" : admin.Role;
        }

        // Same UID as the server but a different key: never auto-promote. Warn
        // once so a misconfigured fingerprint does not silently lose super.
        if (user.Uid == server.Uid && Interlocked.Exchange(ref _serverFpMismatchLogged, 1) == 0)
        {
            Logger.Warn($"HTTP auth: certificate for server uid={server.Uid} does not match " +
                        $"server.certFingerprint; treating as user (check config)");
        }

        return "user";
    }

    private static bool TryDecodeFingerprint(string encoded, out byte[] fingerprint)
    {
        try
        {
            fingerprint = Base64Url.Decode(encoded);
            return fingerprint.Length == 32;
        }
        catch
        {
            fingerprint = [];
            return false;
        }
    }
}

public sealed class AuthDeniedException : Exception
{
    public AuthDeniedException(string message) : base(message) { }

    public string? BreakerKey { get; init; }
}
