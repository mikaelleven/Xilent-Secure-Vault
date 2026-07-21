namespace Xilent.VaultAgent.Models;

public sealed class AppSettings
{
    public const int CurrentVersion = 1;
    public int Version { get; set; } = CurrentVersion;
    public string? VeraCryptExecutablePath { get; set; }
    public string? VaultContainerPathBase64 { get; set; }
    public string? Nf1PathBase64 { get; set; }
    public string VaultMountLetter { get; set; } = "Q";
    public string MkfRelativeDirectory { get; set; } = "Keys";
    public string VaultMarkerFile { get; set; } = ".Xilent-vault";
    public string VaultMarkerValue { get; set; } = "Xilent-VAULT-1";
    public int ClipboardTimeoutSeconds { get; set; } = 15;
    public int MountPollingTimeoutSeconds { get; set; } = 60;
    public bool StartWithWindows { get; set; }
    public bool ShowMountInformation { get; set; } = true;
    public string? LastSelectedMkfFile { get; set; }
}
