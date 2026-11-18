using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Sas.Logging;

namespace Sas.Auth;

/// <summary>
/// Per-request state shared by the auth pipeline, the structured log line,
/// and the archive record.
/// </summary>
public sealed class AuthRequestContext
{
    public AuthRequestContext(string username, string password, string requestId)
    {
        Username = username;
        Callsign = username;
        PasswordRaw = password;
        RequestId = requestId;
        PasswordHash = Hash(password);
    }

    public string RequestId { get; }
    public string Username { get; }
    public string Callsign { get; set; }
    public string PasswordRaw { get; }
    public int PasswordLength => PasswordRaw.Length;
    public string PasswordHash { get; }

    public string? PayloadJson { get; set; }
    public JsonElement? Payload { get; set; }
    public string PayloadHash { get; set; } = "-";
    public int PayloadLength => PayloadJson?.Length ?? 0;

    public long? RootSn { get; set; }
    public string? RootName { get; set; }
    public long? IssuerSn { get; set; }
    public string? IssuerName { get; set; }
    public long? UserUid { get; set; }
    public string? Role { get; set; }
    public string? BreakerKey { get; set; }
    public string? ClaimedRole { get; set; }
    public string? TargetCallsign { get; set; }
    public long? TargetUid { get; set; }
    public string? TargetUrl { get; set; }
    public int? TargetPort { get; set; }
    public long? Timestamp { get; set; }

    public void SetDecodedPayload(string json, JsonElement payload)
    {
        PayloadJson = json;
        Payload = payload;
        PayloadHash = Hash(json);
    }

    public AuthArchiveRecord ToRecord(string result, string? reason, bool includePayload)
    {
        return new AuthArchiveRecord
        {
            Ts = DateTimeOffset.Now.ToString("yyyy-MM-ddTHH:mm:ss.fffzzz", CultureInfo.InvariantCulture),
            RequestId = RequestId,
            Callsign = Callsign,
            Result = result,
            Reason = reason,
            RootSn = RootSn,
            RootName = RootName,
            IssuerSn = IssuerSn,
            IssuerName = IssuerName,
            UserUid = UserUid,
            Role = Role,
            ClaimedRole = ClaimedRole,
            TargetCallsign = TargetCallsign,
            TargetUid = TargetUid,
            TargetUrl = TargetUrl,
            TargetPort = TargetPort,
            Timestamp = Timestamp,
            PasswordLength = PasswordLength,
            PasswordSha256 = PasswordHash,
            PayloadLength = PayloadLength,
            PayloadSha256 = PayloadHash,
            Password = includePayload ? PasswordRaw : null,
            Payload = includePayload ? Payload : null
        };
    }

    public static string Hash(string value)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexString(bytes)[..16].ToLowerInvariant();
    }
}
