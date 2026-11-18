namespace Sas.Logging;

/// <summary>
/// Destination for authentication archive records. Implemented by <see cref="AuthArchive"/>.
/// </summary>
public interface IArchiveSink
{
    void Write(AuthArchiveRecord record);
}
