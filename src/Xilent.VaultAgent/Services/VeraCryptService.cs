using System.Diagnostics;
using Microsoft.Win32;
using Xilent.VaultAgent.Models;

namespace Xilent.VaultAgent.Services;

public sealed class VeraCryptService(VaultService vaultService)
{
    public string? DiscoverExecutable(AppSettings settings)
    {
        IEnumerable<string?> candidates =
        [
            settings.VeraCryptExecutablePath,
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "VeraCrypt", "VeraCrypt.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "VeraCrypt", "VeraCrypt.exe"),
            Path.Combine(AppContext.BaseDirectory, "VeraCrypt.exe"),
            Path.Combine(AppContext.BaseDirectory, "VeraCrypt", "VeraCrypt.exe")
        ];
        return candidates
            .Concat(GetRegistryCandidates())
            .Concat(GetPathCandidates())
            .FirstOrDefault(IsExistingExecutable);
    }

    public bool HasUsableMountConfiguration(AppSettings settings)
    {
        try
        {
            ValidateConfiguration(settings);
            return true;
        }
        catch (InvalidDataException)
        {
            return false;
        }
    }

    public bool HasUsableExecutable(AppSettings settings) => DiscoverExecutable(settings) is not null;

    public void ValidateConfiguration(AppSettings settings)
    {
        ConfigurationService.Validate(settings);
        if (DiscoverExecutable(settings) is null) throw new InvalidDataException("VeraCrypt executable was not found.");
        if (string.IsNullOrWhiteSpace(settings.VaultContainerPathBase64) || !File.Exists(ConfigurationService.DecodePath(settings.VaultContainerPathBase64))) throw new InvalidDataException("Vault container was not found.");
        if (string.IsNullOrWhiteSpace(settings.Nf1PathBase64) || !File.Exists(ConfigurationService.DecodePath(settings.Nf1PathBase64))) throw new InvalidDataException("NF1 keyfile was not found.");
    }

    public async Task<VaultState> MountAsync(AppSettings settings, CancellationToken cancellationToken)
    {
        VaultState current = vaultService.GetState(settings);
        if (current == VaultState.Mounted) return current;
        if (current == VaultState.WrongVolume) throw new InvalidOperationException($"Drive {char.ToUpperInvariant(settings.VaultMountLetter[0])}: is already in use by another volume.");
        ValidateConfiguration(settings);
        string executable = DiscoverExecutable(settings)!;
        string container = ConfigurationService.DecodePath(settings.VaultContainerPathBase64!);
        string keyfile = ConfigurationService.DecodePath(settings.Nf1PathBase64!);
        ProcessStartInfo startInfo = new(executable) { UseShellExecute = false, CreateNoWindow = false };
        startInfo.ArgumentList.Add("/volume"); startInfo.ArgumentList.Add(container);
        startInfo.ArgumentList.Add("/letter"); startInfo.ArgumentList.Add(char.ToUpperInvariant(settings.VaultMountLetter[0]).ToString());
        startInfo.ArgumentList.Add("/keyfile"); startInfo.ArgumentList.Add(keyfile);
        startInfo.ArgumentList.Add("/tryemptypass"); startInfo.ArgumentList.Add("n");
        startInfo.ArgumentList.Add("/cache"); startInfo.ArgumentList.Add("n");
        startInfo.ArgumentList.Add("/history"); startInfo.ArgumentList.Add("n");
        startInfo.ArgumentList.Add("/quit");
        using Process? process = Process.Start(startInfo) ?? throw new InvalidOperationException("VeraCrypt could not be started.");
        DateTimeOffset until = DateTimeOffset.UtcNow.AddSeconds(settings.MountPollingTimeoutSeconds);
        while (DateTimeOffset.UtcNow < until)
        {
            cancellationToken.ThrowIfCancellationRequested();
            VaultState state = vaultService.GetState(settings);
            if (state != VaultState.Locked) return state;
            await Task.Delay(TimeSpan.FromSeconds(2), cancellationToken);
        }
        throw new TimeoutException("Vault mount timed out. Confirm the password dialog was completed.");
    }

    public async Task UnmountAsync(AppSettings settings, CancellationToken cancellationToken)
    {
        string? executable = DiscoverExecutable(settings);
        if (executable is null) throw new InvalidDataException("VeraCrypt executable was not found.");
        ProcessStartInfo startInfo = new(executable) { UseShellExecute = false, CreateNoWindow = false };
        startInfo.ArgumentList.Add("/unmount"); startInfo.ArgumentList.Add(char.ToUpperInvariant(settings.VaultMountLetter[0]).ToString());
        startInfo.ArgumentList.Add("/quit"); startInfo.ArgumentList.Add("/wipecache");
        using Process process = Process.Start(startInfo) ?? throw new InvalidOperationException("VeraCrypt could not be started.");
        await process.WaitForExitAsync(cancellationToken);
        if (vaultService.GetState(settings) == VaultState.Mounted) throw new InvalidOperationException("The Vault could not be unmounted because one or more files are still in use.");
    }

    private static bool IsExistingExecutable(string? path) =>
        !string.IsNullOrWhiteSpace(path) && string.Equals(Path.GetFileName(path), "VeraCrypt.exe", StringComparison.OrdinalIgnoreCase) && File.Exists(path);

    private static IEnumerable<string> GetRegistryCandidates()
    {
        foreach (string keyPath in new[]
        {
            @"SOFTWARE\VeraCrypt",
            @"SOFTWARE\WOW6432Node\VeraCrypt",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VeraCrypt"
        })
        {
            using RegistryKey? key = Registry.LocalMachine.OpenSubKey(keyPath);
            if (key is null) continue;
            foreach (string valueName in new[] { "InstallDir", "InstallLocation", "DisplayIcon" })
            {
                if (key.GetValue(valueName) is not string value || string.IsNullOrWhiteSpace(value)) continue;
                string candidate = value.Trim().Trim('"').Split(',')[0];
                yield return Path.GetFileName(candidate).Equals("VeraCrypt.exe", StringComparison.OrdinalIgnoreCase)
                    ? candidate
                    : Path.Combine(candidate, "VeraCrypt.exe");
            }
        }
    }

    private static IEnumerable<string> GetPathCandidates()
    {
        string? pathValue = Environment.GetEnvironmentVariable("PATH");
        if (string.IsNullOrWhiteSpace(pathValue)) yield break;
        foreach (string directory in pathValue.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            yield return Path.Combine(directory, "VeraCrypt.exe");
        }
    }
}
