using System.Text;
using System.Text.Json;
using Xilent.VaultAgent.Models;

namespace Xilent.VaultAgent.Services;

public sealed class ConfigurationService
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };
    public string ConfigPath { get; } = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Xilent", "VaultAgent", "config.json");

    public async Task<AppSettings> LoadAsync(CancellationToken cancellationToken = default)
    {
        if (!File.Exists(ConfigPath))
        {
            return new AppSettings();
        }
        try
        {
            await using FileStream stream = new(ConfigPath, FileMode.Open, FileAccess.Read, FileShare.Read);
            AppSettings? settings = await JsonSerializer.DeserializeAsync<AppSettings>(stream, JsonOptions, cancellationToken);
            if (settings is null || settings.Version != AppSettings.CurrentVersion)
            {
                throw new InvalidDataException("The configuration file has an unsupported version.");
            }
            Validate(settings);
            return settings;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("The configuration file is malformed.", exception);
        }
    }

    public async Task SaveAsync(AppSettings settings, CancellationToken cancellationToken = default)
    {
        Validate(settings);
        Directory.CreateDirectory(Path.GetDirectoryName(ConfigPath)!);
        string temporaryPath = ConfigPath + ".tmp";
        await using (FileStream stream = new(temporaryPath, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            await JsonSerializer.SerializeAsync(stream, settings, JsonOptions, cancellationToken);
        }
        File.Move(temporaryPath, ConfigPath, true);
    }

    public static string EncodePath(string path) => Convert.ToBase64String(Encoding.UTF8.GetBytes(path));

    public static string DecodePath(string encodedPath)
    {
        try
        {
            string path = Encoding.UTF8.GetString(Convert.FromBase64String(encodedPath));
            if (string.IsNullOrWhiteSpace(path) || path.IndexOfAny(Path.GetInvalidPathChars()) >= 0)
            {
                throw new InvalidDataException("The configured path is invalid.");
            }
            return path;
        }
        catch (FormatException exception)
        {
            throw new InvalidDataException("The configured path is not valid Base64.", exception);
        }
    }

    public static void Validate(AppSettings settings)
    {
        if (settings.Version != AppSettings.CurrentVersion)
        {
            throw new InvalidDataException("The configuration file has an unsupported version.");
        }
        if (settings.VaultMountLetter.Length != 1 || !char.IsAsciiLetter(settings.VaultMountLetter[0]))
        {
            throw new InvalidDataException("Mount letter must be one letter from A to Z.");
        }
        if (settings.ClipboardTimeoutSeconds is < 5 or > 300)
        {
            throw new InvalidDataException("Clipboard timeout must be between 5 and 300 seconds.");
        }
        if (settings.MountPollingTimeoutSeconds is < 10 or > 300)
        {
            throw new InvalidDataException("Mount timeout must be between 10 and 300 seconds.");
        }
        if (string.IsNullOrWhiteSpace(settings.MkfRelativeDirectory) || Path.IsPathRooted(settings.MkfRelativeDirectory))
        {
            throw new InvalidDataException("MKF relative directory must be a relative path.");
        }
        if (string.IsNullOrWhiteSpace(settings.VaultMarkerFile) || Path.IsPathRooted(settings.VaultMarkerFile) || string.IsNullOrWhiteSpace(settings.VaultMarkerValue))
        {
            throw new InvalidDataException("Vault marker configuration is invalid.");
        }
        if (settings.VaultContainerPathBase64 is not null) _ = DecodePath(settings.VaultContainerPathBase64);
        if (settings.Nf1PathBase64 is not null) _ = DecodePath(settings.Nf1PathBase64);
    }
}
