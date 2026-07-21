using System.ComponentModel;
using System.Drawing.Drawing2D;
using Xilent.VaultAgent.Forms;
using Xilent.VaultAgent.Infrastructure;
using Xilent.VaultAgent.Models;
using Xilent.VaultAgent.Services;

namespace Xilent.VaultAgent;

public sealed class VaultAgentApplicationContext : ApplicationContext
{
    private readonly ConfigurationService _configurationService = new();
    private readonly VaultService _vaultService = new();
    private readonly ClipboardService _clipboardService = new();
    private readonly NotifyIcon _notifyIcon;
    private readonly System.Windows.Forms.Timer _stateTimer;
    private readonly VeraCryptService _veraCryptService;
    private readonly SynchronizationContext _uiContext;
    private readonly Icon _lockedIcon;
    private readonly Icon _mountedIcon;
    private readonly Icon _warningIcon;
    private AppSettings _settings = new();
    private KeyDeriverForm? _keyDeriverForm;
    private VaultState? _lastVaultState;
    private bool _exiting;

    public VaultAgentApplicationContext()
    {
        _uiContext = SynchronizationContext.Current ?? new WindowsFormsSynchronizationContext();
        _veraCryptService = new VeraCryptService(_vaultService);
        _lockedIcon = CreateTrayIcon(Color.Firebrick);
        _mountedIcon = CreateTrayIcon(Color.ForestGreen);
        _warningIcon = CreateTrayIcon(Color.Goldenrod);
        _notifyIcon = new NotifyIcon { Visible = true, Text = "Xilent Vault Agent" };
        _notifyIcon.DoubleClick += async (_, _) => await ShowOrMountAsync();
        _notifyIcon.ContextMenuStrip = BuildMenu();
        _stateTimer = new System.Windows.Forms.Timer { Interval = 3000 };
        _stateTimer.Tick += (_, _) => MonitorVault();
        _stateTimer.Start();
        _ = InitializeAsync();
    }

    public void HandleCommand(string command)
    {
        if (_exiting) return;
        _uiContext.Post(_ => _ = command.ToLowerInvariant() switch
        {
            "--mount" => MountAsync(false),
            "--unmount" => UnmountAsync(),
            "--settings" => OpenSettingsAsync(),
            _ => ShowOrMountAsync()
        }, null);
    }

    private async Task InitializeAsync()
    {
        try { _settings = await _configurationService.LoadAsync(); }
        catch (InvalidDataException exception) { ShowWarning(exception.Message); }
        MonitorVault();
    }

    private ContextMenuStrip BuildMenu()
    {
        ContextMenuStrip menu = new();
        menu.Items.Add("Unlock Data Key", null, async (_, _) => await ShowOrMountAsync());
        menu.Items.Add("Mount Vault", null, async (_, _) => await MountAsync(true));
        menu.Items.Add("Unmount Vault", null, async (_, _) => await UnmountAsync());
        menu.Items.Add("Open Vault Folder", null, (_, _) => OpenVaultFolder());
        menu.Items.Add("Settings", null, async (_, _) => await OpenSettingsAsync());
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Exit", null, (_, _) => Exit());
        return menu;
    }

    private async Task ShowOrMountAsync()
    {
        if (_vaultService.GetState(_settings) == VaultState.Mounted) ShowDeriver();
        else await MountAsync(false);
    }

    private async Task MountAsync(bool showOnly)
    {
        try
        {
            if (_settings.ShowMountInformation) ShowInformation("VeraCrypt will request the Vault password. Paste H1 into the VeraCrypt password dialog.");
            Logger.Write("Vault mount requested.");
            VaultState state = await _veraCryptService.MountAsync(_settings, CancellationToken.None);
            MonitorVault();
            if (state == VaultState.Mounted)
            {
                Logger.Write("Vault mounted successfully.");
                if (!showOnly) ShowDeriver();
            }
            else ShowWarning("The configured drive contains a different volume.");
        }
        catch (Exception exception) when (exception is InvalidDataException or InvalidOperationException or TimeoutException or Win32Exception)
        {
            Logger.Write("Vault mount failed.");
            ShowWarning(exception.Message);
        }
    }

    private async Task UnmountAsync()
    {
        try { await _veraCryptService.UnmountAsync(_settings, CancellationToken.None); MonitorVault(); }
        catch (Exception exception) when (exception is InvalidDataException or InvalidOperationException or Win32Exception) { ShowWarning(exception.Message); }
    }

    private async Task OpenSettingsAsync()
    {
        using SettingsForm form = new(_settings, _veraCryptService);
        if (form.ShowDialog() == DialogResult.OK)
        {
            StartupService.Apply(_settings.StartWithWindows);
            await _configurationService.SaveAsync(_settings);
            MonitorVault();
        }
    }

    private void ShowDeriver()
    {
        _keyDeriverForm ??= new KeyDeriverForm(() => _settings, SaveSettingsAsync, _vaultService, _clipboardService);
        _keyDeriverForm.PrepareForDisplay();
    }

    private async Task SaveSettingsAsync(AppSettings settings) => await _configurationService.SaveAsync(settings);

    private void OpenVaultFolder()
    {
        if (_vaultService.GetState(_settings) != VaultState.Mounted) return;
        string directory = _vaultService.GetMkfDirectory(_settings);
        if (Directory.Exists(directory)) System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("explorer.exe", $"\"{directory}\"") { UseShellExecute = true });
    }

    private void MonitorVault()
    {
        VaultState state = _vaultService.GetState(_settings);
        if (_lastVaultState == state) return;

        _notifyIcon.Icon = state switch
        {
            VaultState.Mounted => _mountedIcon,
            VaultState.WrongVolume or VaultState.Error => _warningIcon,
            _ => _lockedIcon
        };
        _notifyIcon.Text = state switch { VaultState.Mounted => "Xilent Vault Agent - Vault mounted", VaultState.WrongVolume => "Xilent Vault Agent - Wrong volume", _ => "Xilent Vault Agent - Vault locked" };

        // Only hide and clear the form when a previously validated Vault disappears.
        if (_lastVaultState == VaultState.Mounted && state != VaultState.Mounted)
        {
            _keyDeriverForm?.VaultRemoved();
        }
        _lastVaultState = state;
    }

    private void Exit()
    {
        _exiting = true;
        _stateTimer.Stop();
        _keyDeriverForm?.ClearSensitiveFields();
        _clipboardService.ClearIfUnchanged();
        _clipboardService.Dispose();
        _notifyIcon.Visible = false;
        _notifyIcon.Dispose();
        _lockedIcon.Dispose();
        _mountedIcon.Dispose();
        _warningIcon.Dispose();
        _stateTimer.Dispose();
        ExitThread();
    }

    private static Icon CreateTrayIcon(Color color)
    {
        using Bitmap bitmap = new(32, 32);
        using Graphics graphics = Graphics.FromImage(bitmap);
        graphics.SmoothingMode = SmoothingMode.AntiAlias;
        using Pen pen = new(color, 4);
        using Brush brush = new SolidBrush(color);
        graphics.DrawArc(pen, 8, 3, 16, 16, 180, 180);
        graphics.FillRectangle(brush, 6, 14, 20, 14);
        return Icon.FromHandle(bitmap.GetHicon());
    }

    private void ShowWarning(string message) => MessageBox.Show(message, "Xilent Vault Agent", MessageBoxButtons.OK, MessageBoxIcon.Warning);
    private void ShowInformation(string message) => MessageBox.Show(message, "Xilent Vault Agent", MessageBoxButtons.OK, MessageBoxIcon.Information);
}
