namespace Xilent.VaultAgent.Infrastructure;

public static class Logger
{
    private static readonly object Sync = new();
    private static readonly string LogPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Xilent", "VaultAgent", "vault-agent.log");

    public static void Write(string message)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(LogPath)!);
            lock (Sync)
            {
                File.AppendAllText(LogPath, $"{DateTimeOffset.UtcNow:O} {message}{Environment.NewLine}");
            }
        }
        catch (IOException)
        {
            // Logging must never interrupt the application.
        }
        catch (UnauthorizedAccessException)
        {
            // Logging must never interrupt the application.
        }
    }
}
