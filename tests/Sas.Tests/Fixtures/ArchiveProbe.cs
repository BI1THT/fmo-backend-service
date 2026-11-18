using System.Text.Json;
using Sas.Logging;

namespace Sas.Tests.Fixtures;

public static class ArchiveProbe
{
    public static IReadOnlyList<string> ReadFiles(string dir) =>
        Directory.Exists(dir)
            ? Directory.GetFiles(dir, "*.jsonl", SearchOption.AllDirectories)
                .OrderBy(f => f, StringComparer.Ordinal)
                .ToArray()
            : [];

    public static IReadOnlyList<JsonElement> ReadAll(string dir)
    {
        var records = new List<JsonElement>();

        foreach (var file in ReadFiles(dir))
        {
            foreach (var line in File.ReadAllLines(file))
            {
                if (string.IsNullOrWhiteSpace(line))
                    continue;

                using var doc = JsonDocument.Parse(line);
                records.Add(doc.RootElement.Clone());
            }
        }

        return records;
    }

    public static IReadOnlyList<AuthArchiveRecord> ReadRecords(string dir)
    {
        var records = new List<AuthArchiveRecord>();

        foreach (var file in ReadFiles(dir))
        {
            foreach (var line in File.ReadAllLines(file))
            {
                if (string.IsNullOrWhiteSpace(line))
                    continue;

                var record = JsonSerializer.Deserialize<AuthArchiveRecord>(line,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                if (record != null)
                    records.Add(record);
            }
        }

        return records;
    }
}
