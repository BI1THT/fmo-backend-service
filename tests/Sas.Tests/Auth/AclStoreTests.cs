using System.Text.Json;
using Sas.Auth;
using Sas.Tests.Fixtures;

namespace Sas.Tests.Auth;

public sealed class AclStoreTests
{
    [Fact]
    public void EmptyRolesDirectory_ProvidesBuiltinRoles()
    {
        using var temp = new TempDirectory("acl-builtin");
        var store = new AclStore(temp.CreateSubdirectory("roles"));

        var super = store.GetPermissions("super");
        var admin = store.GetPermissions("admin");
        var user = store.GetPermissions("user");

        Assert.NotEmpty(super.pub);
        Assert.NotEmpty(super.sub);
        Assert.Contains("FMO/MUTELIST", super.pub);

        Assert.DoesNotContain("FMO/MUTELIST", user.pub);
        Assert.Contains("FMO/QSO/UID/{uid}", user.sub);
        Assert.Contains("FMO/PROFILE", user.sub);

        Assert.Contains("FMO/MUTELIST", admin.pub);
        Assert.Contains("FMO/PROFILE", admin.sub);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("no-such-role")]
    public void UnknownOrEmptyRole_FallsBackToUser(string? role)
    {
        using var temp = new TempDirectory("acl-fallback");
        var store = new AclStore(temp.CreateSubdirectory("roles"));

        var user = store.GetPermissions("user");
        var actual = store.GetPermissions(role!);

        Assert.Equal(user.all, actual.all);
        Assert.Equal(user.pub, actual.pub);
        Assert.Equal(user.sub, actual.sub);
    }

    [Fact]
    public void ResolveForUid_ReplacesEveryPlaceholder()
    {
        using var temp = new TempDirectory("acl-resolve");
        var store = new AclStore(temp.CreateSubdirectory("roles"));

        var resolved = store.ResolveForUid(
            ["FMO/QSO/UID/{uid}", "FMO/LATE/UID_V1/{uid}", "FMO/STATIC", "FMO/X/{uid}/Y/{uid}"],
            5001);

        Assert.Equal(
            ["FMO/QSO/UID/5001", "FMO/LATE/UID_V1/5001", "FMO/STATIC", "FMO/X/5001/Y/5001"],
            resolved);
    }

    [Fact]
    public void CustomRole_IsLoaded_WithCaseInsensitivePropertyNames()
    {
        using var temp = new TempDirectory("acl-custom");
        var rolesDir = temp.CreateSubdirectory("roles");
        File.WriteAllText(Path.Combine(rolesDir, "custom.json"), """
            {
              "ROLE": "custom",
              "ALL": ["FMO/RAW"],
              "PUB": ["FMO/CUSTOM/PUB"],
              "SUB": ["FMO/CUSTOM/SUB"]
            }
            """);

        var store = new AclStore(rolesDir);
        var acl = store.GetPermissions("custom");

        Assert.Equal(["FMO/RAW"], acl.all);
        Assert.Equal(["FMO/CUSTOM/PUB"], acl.pub);
        Assert.Equal(["FMO/CUSTOM/SUB"], acl.sub);
        // 自定义角色不影响内置角色的可用性。
        Assert.Contains("FMO/MUTELIST", store.GetPermissions("super").pub);
    }

    [Fact]
    public void InvalidJsonFile_IsIgnored_OtherRolesStillWork()
    {
        using var temp = new TempDirectory("acl-invalid");
        var rolesDir = temp.CreateSubdirectory("roles");
        File.WriteAllText(Path.Combine(rolesDir, "broken.json"), "{ this is not json");
        File.WriteAllText(Path.Combine(rolesDir, "custom.json"), """
            {"role": "custom", "pub": ["FMO/CUSTOM/PUB"], "sub": ["FMO/CUSTOM/SUB"]}
            """);

        var store = new AclStore(rolesDir);

        Assert.Contains("FMO/CUSTOM/PUB", store.GetPermissions("custom").pub);
        Assert.Contains("FMO/MUTELIST", store.GetPermissions("admin").pub);
        Assert.NotEmpty(store.GetPermissions("user").sub);
    }

    [Fact]
    public void EmptyRoleNameInJson_IsIgnored_AndFallsBackToUser()
    {
        using var temp = new TempDirectory("acl-empty-role");
        var rolesDir = temp.CreateSubdirectory("roles");
        File.WriteAllText(Path.Combine(rolesDir, "empty-role.json"), """
            {"role": "", "pub": ["FMO/SHOULD_NOT_LOAD"], "sub": ["FMO/SHOULD_NOT_LOAD"]}
            """);

        var store = new AclStore(rolesDir);

        var user = store.GetPermissions("user");
        var fallback = store.GetPermissions("empty-role");

        Assert.Equal(user.pub, fallback.pub);
        Assert.Equal(user.sub, fallback.sub);
        Assert.DoesNotContain("FMO/SHOULD_NOT_LOAD", fallback.pub);
    }

    [Fact]
    public void HardcodedDefaults_MatchEmbeddedRoleJson()
    {
        using var temp = new TempDirectory("acl-embedded");
        var store = new AclStore(temp.CreateSubdirectory("roles"));

        var embedded = new[]
        {
            store.GetPermissions("super"),
            store.GetPermissions("admin"),
            store.GetPermissions("user")
        };

        store.LoadHardcodedDefaults();

        var hardcoded = new[]
        {
            store.GetPermissions("super"),
            store.GetPermissions("admin"),
            store.GetPermissions("user")
        };

        for (var i = 0; i < embedded.Length; i++)
        {
            Assert.Equal(embedded[i].all, hardcoded[i].all);
            Assert.Equal(embedded[i].pub, hardcoded[i].pub);
            Assert.Equal(embedded[i].sub, hardcoded[i].sub);
        }
    }

    [Fact]
    public void SeededBuiltinRoles_MatchBuiltinJsonFiles()
    {
        using var temp = new TempDirectory("acl-seeded");
        var rolesDir = temp.CreateSubdirectory("roles");

        var store = new AclStore(rolesDir);

        // 构造时会把内置 roles/*.json 播种到空目录。
        Assert.NotEmpty(Directory.GetFiles(rolesDir, "*.json"));

        var builtinAdmin = Path.Combine(AppContext.BaseDirectory, "builtin", "roles", "admin.json");
        Assert.True(File.Exists(builtinAdmin));

        using var doc = JsonDocument.Parse(File.ReadAllText(builtinAdmin));
        var expectedPub = doc.RootElement.GetProperty("pub").EnumerateArray()
            .Select(e => e.GetString()!).ToArray();
        var expectedSub = doc.RootElement.GetProperty("sub").EnumerateArray()
            .Select(e => e.GetString()!).ToArray();

        var admin = store.GetPermissions("admin");
        Assert.Equal(expectedPub, admin.pub);
        Assert.Equal(expectedSub, admin.sub);
        Assert.Contains("FMO/PROFILE", admin.sub);
    }
}
