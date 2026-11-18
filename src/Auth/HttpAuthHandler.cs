using System.Globalization;
using System.Text;
using System.Text.Json;
using Sas.certs;
using Sas.Logging;
using Sas.Messages;
using Sas.Trust;

namespace Sas.Auth;

sealed class HttpAuthHandler
{
    private readonly Config _config;
    private readonly RootCaStore _rootStore;
    private readonly CertVerifier _verifier;
    private readonly CrlManager _crlManager;
    private readonly AclStore _aclStore;
    private readonly AuthArchive _archive;

    public HttpAuthHandler(Config config, RootCaStore rootStore,
        CertVerifier verifier, CrlManager crlManager, AclStore aclStore,
        AuthArchive archive)
    {
        _config = config;
        _rootStore = rootStore;
        _verifier = verifier;
        _crlManager = crlManager;
        _aclStore = aclStore;
        _archive = archive;
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

    public AuthResult Process(string username, string password, string requestId, string? clientIp)
    {
        var ctx = new AuthRequestContext(username, password, requestId, clientIp);

        Logger.Debug($"HTTP auth: >>> start processing username={username} req={requestId} client={clientIp ?? "-"}");

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

        ctx.ClaimedRole = payload.Role;
        ctx.TargetCallsign = payload.TargetCallsign;
        ctx.TargetUid = payload.TargetUID;
        ctx.TargetUrl = payload.TargetUrl;
        ctx.TargetPort = payload.TargetPort;
        ctx.Timestamp = payload.Timestamp;

        Logger.Debug($"HTTP auth: payload: targetCallsign={payload.TargetCallsign} targetUID={payload.TargetUID} targetUrl={payload.TargetUrl} targetPort={payload.TargetPort} timestamp={payload.Timestamp} role={payload.Role}");
        Logger.Debug($"HTTP auth: payload: serverFingerprint={payload.ServerFingerprint[..Math.Min(8, payload.ServerFingerprint.Length)]}...");

        IntermediateCaCert intermediate;
        UserCert user;
        try
        {
            intermediate = IntermediateCaCert.FromJson(payload.CertPackage.IntermediateCert);
            user = UserCert.FromJson(payload.CertPackage.UserCert);
        }
        catch (Exception ex)
        {
            Logger.Debug($"HTTP auth: failed to parse cert package: {ex.Message} req={requestId}");
            throw Deny(ctx, "invalid certificate format");
        }

        ctx.Callsign = user.Callsign;
        ctx.UserUid = user.Uid;
        ctx.IssuerSn = intermediate.Sn;
        ctx.IssuerName = intermediate.SubjectName;

        Logger.Debug($"HTTP auth: intermediate: sn={intermediate.Sn} issuerSn={intermediate.IssuerSn} subject={intermediate.SubjectName}");
        Logger.Debug($"HTTP auth: user: callsign={user.Callsign} uid={user.Uid} publicKey.length={user.PublicKey?.Length ?? 0}");

        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        Logger.Debug($"HTTP auth: server time (UTC unix)={now}");

        var root = _rootStore.FindIssuer(intermediate);
        if (root == null)
            throw Deny(ctx, "chain invalid: no trusted root");

        ctx.RootSn = root.Sn;
        ctx.RootName = root.SubjectName;
        Logger.Debug($"HTTP auth: matched root: sn={root.Sn} subject={root.SubjectName}");

        var vr = _verifier.VerifyFullChain(root, intermediate, user, now);
        if (vr != VerifyResult.OK)
            throw Deny(ctx, $"chain invalid: {CertVerifier.GetMessage(vr)}");

        Logger.Debug("HTTP auth: certificate chain verification passed");

        if (!string.Equals(username, user.Callsign, StringComparison.OrdinalIgnoreCase))
            throw Deny(ctx, $"username mismatch: request={username} cert={user.Callsign}");

        if (_config.Trust.AllowIssuerSn.Length > 0 &&
            !_config.Trust.AllowIssuerSn.Contains(intermediate.Sn))
        {
            throw Deny(ctx, $"intermediate not trusted: sn={intermediate.Sn}");
        }

        _crlManager.RegisterIntermediate(intermediate);

        var rootOutdated = _crlManager.IsRootCrlOutdated(root.Sn, now);
        if (rootOutdated)
        {
            Logger.Warn($"HTTP auth: root CRL outdated rootSn={root.Sn} rootName={root.SubjectName} callsign={user.Callsign} req={requestId}");
        }

        if (_crlManager.IsIntermediateRevoked(intermediate.Sn, intermediate.Fingerprint(), out var intReason))
            throw Deny(ctx, $"intermediate revoked: {intReason}");

        if (_crlManager.IsUserRevoked(user.Uid, user.Fingerprint(), out var userReason))
            throw Deny(ctx, $"user revoked: {userReason}");

        var server = FindMatchingServer(payload.TargetCallsign, payload.TargetUID, payload.TargetUrl, payload.TargetPort);
        if (server == null)
        {
            throw Deny(ctx,
                $"server identity mismatch: target={payload.TargetCallsign}/{payload.TargetUID} {payload.TargetUrl}:{payload.TargetPort}");
        }

        var role = DetermineRole(user, server);
        ctx.Role = role;
        if (!string.IsNullOrEmpty(payload.Role) &&
            !string.Equals(payload.Role, role, StringComparison.OrdinalIgnoreCase))
        {
            throw Deny(ctx, $"role mismatch: claimed={payload.Role} actual={role}");
        }

        byte[] serverFpBytes;
        try
        {
            serverFpBytes = Base64Url.Decode(payload.ServerFingerprint);
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
        if (!HttpProofVerifier.IsTimestampValid(payload.Timestamp, now))
            throw Deny(ctx, "timestamp expired");

        Logger.Debug($"HTTP auth: verifying proof: serverUid={server.Uid} targetCallsign={server.Callsign} mqttHost={server.MqttHost} mqttPort={server.MqttPort}");
        var proofOk = HttpProofVerifier.Verify(
            server.Uid, server.Callsign, server.Uid,
            server.MqttHost, server.MqttPort, serverFpBytes,
            payload.Timestamp, user, payload.Role, payload.Proof.Signature);

        if (!proofOk)
            throw Deny(ctx, "proof invalid");

        var isSuperuser = role == "super";
        var (allDefs, pubDefs, subDefs) = _aclStore.GetPermissions(role);

        var allTopics = _aclStore.ResolveForUid(allDefs, user.Uid);
        var pubTopics = _aclStore.ResolveForUid(pubDefs, user.Uid);
        var subTopics = _aclStore.ResolveForUid(subDefs, user.Uid);

        const int ttlJitterSec = 60;
        var maxJitter = Math.Min(ttlJitterSec, Math.Max(1, _config.Http.TtlSec / 2));
        var exp = now + _config.Http.TtlSec + Random.Shared.NextInt64(-maxJitter, maxJitter + 1);

        Logger.Info($"HTTP auth: allow {Scope(ctx)} uid={user.Uid} role={role} target={server.Callsign}:{server.MqttPort}");
        _archive.Write(ctx.ToRecord("allow", null));

        return new AuthResult
        {
            Callsign = user.Callsign,
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
        Logger.Warn($"HTTP auth: deny {Scope(ctx)} reason=\"{reason}\"");

        if (ctx.Payload.HasValue && _config.Archive.RecordDenied)
            _archive.Write(ctx.ToRecord("deny", reason));

        return new AuthDeniedException(reason);
    }

    private static string Scope(AuthRequestContext ctx)
    {
        return $"callsign={ctx.Callsign} rootSn={Sn(ctx.RootSn)} rootName={ctx.RootName ?? "-"} " +
               $"issuerSn={Sn(ctx.IssuerSn)} issuerName={ctx.IssuerName ?? "-"} " +
               $"payloadLen={ctx.PayloadLength} payloadSha256={ctx.PayloadHash} " +
               $"req={ctx.RequestId} client={ctx.ClientIp ?? "-"}";
    }

    private static string Sn(long? value) =>
        value?.ToString(CultureInfo.InvariantCulture) ?? "?";

    private string DetermineRole(UserCert user, ServerIdentity server)
    {
        if (_config.Server.Admins.Length == 0)
            return user.Uid == server.Uid ? "super" : "user";

        var userFp = user.Fingerprint();
        foreach (var admin in _config.Server.Admins)
        {
            if (admin.Uid != user.Uid)
                continue;

            byte[] adminFp;
            try { adminFp = Base64Url.Decode(admin.CertFingerprint); }
            catch { continue; }

            if (adminFp.AsSpan().SequenceEqual(userFp))
                return string.IsNullOrEmpty(admin.Role) ? "admin" : admin.Role;
        }

        return user.Uid == server.Uid ? "super" : "user";
    }
}

public sealed class AuthDeniedException : Exception
{
    public AuthDeniedException(string message) : base(message) { }
}
