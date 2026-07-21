using Xilent.VaultAgent.Models;

namespace Xilent.VaultAgent.Services;

public sealed class VaultService
{
    public VaultState GetState(AppSettings settings)
    {
        string root = $"{char.ToUpperInvariant(settings.VaultMountLetter[0])}:\\";
        if (!Directory.Exists(root)) return VaultState.Locked;
        try
        {
            string markerPath = Path.Combine(root, settings.VaultMarkerFile);
            if (!File.Exists(markerPath)) return VaultState.WrongVolume;
            string marker = File.ReadAllText(markerPath);
            return string.Equals(marker, settings.VaultMarkerValue, StringComparison.Ordinal) ? VaultState.Mounted : VaultState.WrongVolume;
        }
        catch (IOException) { return VaultState.Error; }
        catch (UnauthorizedAccessException) { return VaultState.Error; }
    }

    public string GetMkfDirectory(AppSettings settings) => Path.Combine($"{char.ToUpperInvariant(settings.VaultMountLetter[0])}:\\", settings.MkfRelativeDirectory);
}
