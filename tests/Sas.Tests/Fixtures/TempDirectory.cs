namespace Sas.Tests.Fixtures;

/// <summary>
/// Isolated scratch directory inside the OS temp folder. Never touches ~/.sas.
/// </summary>
public sealed class TempDirectory : IDisposable
{
    public string Path { get; }

    public TempDirectory(string? prefix = null)
    {
        var name = (prefix ?? "sas") + "-" + Guid.NewGuid().ToString("N")[..12];
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "sas-tests", name);
        Directory.CreateDirectory(Path);
    }

    public string Combine(params string[] parts) =>
        System.IO.Path.Combine(new[] { Path }.Concat(parts).ToArray());

    public string CreateSubdirectory(params string[] parts)
    {
        var dir = Combine(parts);
        Directory.CreateDirectory(dir);
        return dir;
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(Path))
                Directory.Delete(Path, recursive: true);
        }
        catch
        {
            // Best effort: a leaked temp directory must never fail a test.
        }
    }
}
