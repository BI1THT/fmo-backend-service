using System.Text.RegularExpressions;
using Sas.Logging;
using Sas.Tests.Fixtures;

namespace Sas.Tests.Auth;

[Collection("GlobalState")]
public sealed class HttpAuthHandlerLoggingTests
{
    [Fact]
    public void ServerUidMismatch_LogsWarningOnlyOnce()
    {
        var writer = new StringWriter();
        Logger.ResetForTests(stdout: writer, stderr: writer);
        try
        {
            using var env = new AuthTestEnvironment(pki: new TestPkiOptions
            {
                UserUid = TestConfig.DefaultServerUid
            });
            var otherFp = TestPki.RandomFingerprint(0x99);
            env.Config.Server.CertFingerprint = otherFp;

            var password = env.Pki.BuildPassword(env.Config.Server.Uid, env.Config.Server.Callsign,
                env.Config.Server.Uid, env.Config.Mqtt.Host, env.Config.Mqtt.Port,
                otherFp, env.Now, "user");

            env.Handler.Process(env.Username, password, "req-1");
            env.Handler.Process(env.Username, password, "req-2");

            Logger.Flush();
            var output = writer.ToString();

            Assert.Contains("does not match", output);
            Assert.Single(Regex.Matches(output, "does not match"));
        }
        finally
        {
            Logger.ResetForTests();
        }
    }
}
