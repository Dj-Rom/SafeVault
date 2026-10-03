namespace SafeVault.Tests;

/// <summary>A temporary SQLite database file that is deleted after the test.</summary>
public sealed class TestDb : IDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), $"safevault-{Guid.NewGuid():N}.db");

    public string ConnectionString => $"Data Source={_path};Pooling=False";

    public void Dispose()
    {
        try { File.Delete(_path); } catch (IOException) { /* ignore */ }
    }
}
