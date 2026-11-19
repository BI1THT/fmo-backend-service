using System.Text.Json;
using System.Text.Json.Nodes;
using Sas.certs;
using Sas.Tests.Fixtures;
using Sas.Trust;

namespace Sas.Tests.Trust;

public sealed class RootCaStoreTests
{
    private static TestPki CreatePki(byte seed = 1, long rootSn = 1) =>
        TestPki.Create(new TestPkiOptions { Seed = seed, RootSn = rootSn });

    /// <summary>
    /// 生产实现会从 AppContext.BaseDirectory/builtin/roots 播种内置根。
    /// 为了让断言只统计测试写入的根，这里先用同名无效文件占位，阻止播种。
    /// </summary>
    private static string CreateIsolatedRootsDir(TempDirectory temp)
    {
        var dir = temp.CreateSubdirectory("roots");
        var builtinDir = Path.Combine(AppContext.BaseDirectory, "builtin", "roots");
        if (Directory.Exists(builtinDir))
        {
            foreach (var file in Directory.GetFiles(builtinDir, "*.json"))
                File.WriteAllText(Path.Combine(dir, Path.GetFileName(file)), "{}");
        }
        return dir;
    }

    private static void WriteFile(string dir, string name, string content) =>
        File.WriteAllText(Path.Combine(dir, name), content);

    private static int CountValidBuiltinRoots()
    {
        var builtinDir = Path.Combine(AppContext.BaseDirectory, "builtin", "roots");
        if (!Directory.Exists(builtinDir))
            return 0;

        var count = 0;
        foreach (var file in Directory.GetFiles(builtinDir, "*.json"))
        {
            try
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(file));
                if (RootCaCert.FromJson(doc.RootElement).VerifySelfSignature())
                    count++;
            }
            catch
            {
                // 忽略无法解析的内置文件。
            }
        }
        return count;
    }

    [Fact]
    public void MissingDirectory_DoesNotThrow()
    {
        using var temp = new TempDirectory("roots-missing");
        var dir = temp.Combine("does-not-exist");

        var store = new RootCaStore(dir);

        // 现状：构造时会创建目录并播种内置根，因此不能断言为空。
        // 这里断言只包含输出目录中的合法内置根。
        Assert.Equal(CountValidBuiltinRoots(), store.AllRoots.Count);
        Assert.True(Directory.Exists(dir));
    }

    [Fact]
    public void SingleRootJson_IsLoaded()
    {
        using var temp = new TempDirectory("roots-single");
        var dir = CreateIsolatedRootsDir(temp);
        var pki = CreatePki();
        WriteFile(dir, "root.json", pki.RootJson);

        var store = new RootCaStore(dir);

        var root = Assert.Single(store.AllRoots);
        Assert.Equal(1, root.Sn);
        Assert.Equal(pki.Root.SubjectName, root.SubjectName);
        Assert.True(root.VerifySelfSignature());
    }

    [Fact]
    public void MultipleDistinctRoots_AreAllLoaded()
    {
        using var temp = new TempDirectory("roots-multi");
        var dir = CreateIsolatedRootsDir(temp);
        var first = CreatePki(seed: 10, rootSn: 11);
        var second = CreatePki(seed: 20, rootSn: 22);
        WriteFile(dir, "first.json", first.RootJson);
        WriteFile(dir, "second.json", second.RootJson);

        var store = new RootCaStore(dir);

        Assert.Equal(2, store.AllRoots.Count);
        Assert.Contains(store.AllRoots, r => r.Sn == 11);
        Assert.Contains(store.AllRoots, r => r.Sn == 22);
    }

    [Fact]
    public void InvalidJsonFile_IsSkipped_ValidRootStillLoads()
    {
        using var temp = new TempDirectory("roots-invalid");
        var dir = CreateIsolatedRootsDir(temp);
        var pki = CreatePki();
        WriteFile(dir, "broken.json", "{ definitely not json");
        WriteFile(dir, "root.json", pki.RootJson);

        var store = new RootCaStore(dir);

        var root = Assert.Single(store.AllRoots);
        Assert.Equal(pki.Root.Sn, root.Sn);
    }

    [Fact]
    public void TamperedSignature_IsRejected()
    {
        using var temp = new TempDirectory("roots-tampered");
        var dir = CreateIsolatedRootsDir(temp);
        var pki = CreatePki();

        var node = JsonNode.Parse(pki.RootJson)!.AsObject();
        var fakeSignature = Base64Url.Decode(TestPki.RandomFingerprint(0x11))
            .Concat(Base64Url.Decode(TestPki.RandomFingerprint(0x22)))
            .ToArray();
        node["signature"] = Base64Url.Encode(fakeSignature);
        WriteFile(dir, "tampered.json", node.ToJsonString());

        var store = new RootCaStore(dir);

        Assert.Empty(store.AllRoots);
    }

    [Fact]
    public void FindIssuer_IgnoresIntermediateWithMismatchedIssuerSn()
    {
        using var temp = new TempDirectory("roots-issuer-mismatch");
        var dir = CreateIsolatedRootsDir(temp);
        var pki = CreatePki();
        var forged = TestPki.Create(new TestPkiOptions
        {
            Seed = 1,
            RootSn = 1,
            IssuerSn = 1001,
            IntermediateIssuerSn = 999
        });
        WriteFile(dir, "root.json", pki.RootJson);

        var store = new RootCaStore(dir);

        Assert.Null(store.FindIssuer(forged.Intermediate));
    }

    [Fact]
    public void FindIssuer_WithDuplicateRootSn_SelectsByIssuerKeyAndSignature()
    {
        using var temp = new TempDirectory("roots-duplicate-sn");
        var dir = CreateIsolatedRootsDir(temp);
        var a = TestPki.Create(new TestPkiOptions { Seed = 70, RootSn = 1, RootName = "ca-a" });
        var b = TestPki.Create(new TestPkiOptions { Seed = 80, RootSn = 1, RootName = "ca-b" });
        WriteFile(dir, "a.json", a.RootJson);
        WriteFile(dir, "b.json", b.RootJson);

        var store = new RootCaStore(dir);

        Assert.Equal(2, store.AllRoots.Count);
        var foundA = store.FindIssuer(a.Intermediate);
        var foundB = store.FindIssuer(b.Intermediate);
        Assert.NotNull(foundA);
        Assert.NotNull(foundB);
        Assert.Equal(a.Root.SubjectPubKey, foundA!.SubjectPubKey);
        Assert.Equal(b.Root.SubjectPubKey, foundB!.SubjectPubKey);
    }

    [Fact]
    public void FindIssuer_IgnoresIntermediateWithMismatchedIssuerKey()
    {
        using var temp = new TempDirectory("roots-issuer-key-mismatch");
        var dir = CreateIsolatedRootsDir(temp);
        var pki = CreatePki();
        var other = TestPki.Create(new TestPkiOptions { Seed = 20 });
        var forged = TestPki.Create(new TestPkiOptions
        {
            Seed = 1,
            RootSn = 1,
            IssuerSn = 1001,
            IntermediateIssuerPubKey = other.Root.SubjectPubKey
        });
        WriteFile(dir, "root.json", pki.RootJson);

        var store = new RootCaStore(dir);

        Assert.Null(store.FindIssuer(forged.Intermediate));
    }

    [Fact]
    public void FindIssuer_MatchesOnlyTheSigningRoot()
    {
        using var temp = new TempDirectory("roots-issuer");
        var dir = CreateIsolatedRootsDir(temp);
        var ours = CreatePki(seed: 30, rootSn: 1);
        var other = CreatePki(seed: 40, rootSn: 2);
        WriteFile(dir, "ours.json", ours.RootJson);

        var store = new RootCaStore(dir);

        var issuer = store.FindIssuer(ours.Intermediate);
        Assert.NotNull(issuer);
        Assert.Equal(ours.Root.Sn, issuer!.Sn);

        Assert.Null(store.FindIssuer(other.Intermediate));
    }
}
