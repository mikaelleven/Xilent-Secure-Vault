using System.Security.Cryptography;
using Xilent.KeyDeriver.Core;
using Xilent.VaultAgent.Models;
using Xilent.VaultAgent.Services;

namespace Xilent.VaultAgent.Forms;

public sealed class KeyDeriverForm : Form
{
    private readonly Func<AppSettings> _getSettings;
    private readonly Func<AppSettings, Task> _saveSettings;
    private readonly VaultService _vaultService;
    private readonly ClipboardService _clipboardService;
    private readonly ComboBox _keyFiles = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 300 };
    private readonly TextBox _memorySecret = new() { UseSystemPasswordChar = true, AutoCompleteMode = AutoCompleteMode.None, AutoCompleteSource = AutoCompleteSource.None, Width = 390 };
    private readonly TextBox _info = new() { Width = 390 };
    private readonly Label _status = new() { AutoSize = true, ForeColor = Color.DarkGreen };
    private readonly Button _derive = new() { Text = "Derive and Copy", AutoSize = true };

    public KeyDeriverForm(Func<AppSettings> getSettings, Func<AppSettings, Task> saveSettings, VaultService vaultService, ClipboardService clipboardService)
    {
        _getSettings = getSettings;
        _saveSettings = saveSettings;
        _vaultService = vaultService;
        _clipboardService = clipboardService;
        Text = "Xilent Vault Agent";
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        ShowInTaskbar = true;
        StartPosition = FormStartPosition.CenterScreen;
        AutoSize = true;
        AutoSizeMode = AutoSizeMode.GrowAndShrink;
        KeyPreview = true;

        Button browse = new() { Text = "Browse", AutoSize = true };
        browse.Click += (_, _) => Browse();
        _derive.Click += async (_, _) => await DeriveAsync();
        AcceptButton = _derive;
        CancelButton = new Button { DialogResult = DialogResult.Cancel, Visible = false };
        KeyDown += (_, eventArgs) =>
        {
            if (eventArgs.KeyCode == Keys.Escape) { ClearSensitiveFields(); Hide(); }
        };
        FormClosing += (_, eventArgs) => { eventArgs.Cancel = true; ClearSensitiveFields(); Hide(); };

        TableLayoutPanel layout = new() { AutoSize = true, Padding = new Padding(14), ColumnCount = 3, RowCount = 5 };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        layout.Controls.Add(new Label { Text = "&Key file:", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 0);
        layout.Controls.Add(_keyFiles, 1, 0); layout.Controls.Add(browse, 2, 0);
        layout.Controls.Add(new Label { Text = "&Memory secret:", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 1);
        layout.Controls.Add(_memorySecret, 1, 1); layout.SetColumnSpan(_memorySecret, 2);
        layout.Controls.Add(new Label { Text = "&Info string:", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 2);
        layout.Controls.Add(_info, 1, 2); layout.SetColumnSpan(_info, 2);
        Label warning = new() { Text = "The info string is case-sensitive and must match the value originally used.", AutoSize = true, ForeColor = Color.DarkGoldenrod };
        layout.Controls.Add(warning, 1, 3); layout.SetColumnSpan(warning, 2);
        FlowLayoutPanel buttons = new() { AutoSize = true, FlowDirection = FlowDirection.RightToLeft, Dock = DockStyle.Fill };
        buttons.Controls.Add(_derive);
        layout.Controls.Add(buttons, 1, 4); layout.SetColumnSpan(buttons, 2);
        layout.Controls.Add(_status, 0, 5); layout.SetColumnSpan(_status, 3);
        Controls.Add(layout);
    }

    public void PrepareForDisplay()
    {
        RefreshKeyFileList();
        Show(); WindowState = FormWindowState.Normal; BringToFront(); Activate();
        BeginInvoke(() =>
        {
            Control initialFocus = _keyFiles.SelectedItem is null ? _keyFiles : _memorySecret;
            initialFocus.Focus();
        });
    }

    public void RefreshKeyFileList()
    {
        string? previous = (_keyFiles.SelectedItem as FileSelection)?.Path ?? _getSettings().LastSelectedMkfFile;
        _keyFiles.Items.Clear();
        AppSettings settings = _getSettings();
        if (_vaultService.GetState(settings) != VaultState.Mounted) return;
        string directory = _vaultService.GetMkfDirectory(settings);
        try
        {
            if (!Directory.Exists(directory)) return;
            List<string> files = Directory.EnumerateFiles(directory, "*", SearchOption.TopDirectoryOnly)
                .Where(path => string.Equals(Path.GetExtension(path), ".mkf", StringComparison.OrdinalIgnoreCase))
                .OrderBy(Path.GetFileName, NaturalStringComparer.Instance).ToList();
            foreach (string path in files) _keyFiles.Items.Add(new FileSelection(path));
            if (previous is not null)
            {
                int index = files.FindIndex(path => string.Equals(Path.GetFileName(path), previous, StringComparison.OrdinalIgnoreCase) || string.Equals(path, previous, StringComparison.OrdinalIgnoreCase));
                if (index >= 0) _keyFiles.SelectedIndex = index;
            }
        }
        catch (IOException) { _status.Text = "The configured MKF directory could not be read."; }
        catch (UnauthorizedAccessException) { _status.Text = "The configured MKF directory could not be read."; }
    }

    public void VaultRemoved()
    {
        ClearSensitiveFields();
        _keyFiles.Items.Clear();
        _status.ForeColor = Color.DarkRed;
        _status.Text = "The Vault is no longer available.";
        Hide();
    }

    public void ClearSensitiveFields()
    {
        _memorySecret.Clear();
        _info.Clear();
    }

    private void Browse()
    {
        using OpenFileDialog dialog = new() { Filter = "MKF files (*.mkf)|*.mkf|All files (*.*)|*.*", CheckFileExists = true, Multiselect = false };
        if (dialog.ShowDialog(this) == DialogResult.OK)
        {
            FileSelection? existing = _keyFiles.Items.OfType<FileSelection>().FirstOrDefault(item => string.Equals(item.Path, dialog.FileName, StringComparison.OrdinalIgnoreCase));
            if (existing is null) { existing = new FileSelection(dialog.FileName); _keyFiles.Items.Add(existing); }
            _keyFiles.SelectedItem = existing;
        }
    }

    private async Task DeriveAsync()
    {
        string? path = (_keyFiles.SelectedItem as FileSelection)?.Path;
        if (string.IsNullOrEmpty(path)) { ShowError("Select an MKF file first."); return; }
        if (string.IsNullOrEmpty(_memorySecret.Text)) { ShowError("Memory secret must not be empty."); return; }
        string secret = _memorySecret.Text;
        string info = _info.Text;
        _memorySecret.Clear();
        _derive.Enabled = false;
        try
        {
            using MkfFile mkf = await MkfFileReader.ReadAsync(path);
            string derived = await Task.Run(() => KeyDerivationService.Derive(mkf, secret, info));
            try
            {
                if (!_clipboardService.Copy(derived, _getSettings().ClipboardTimeoutSeconds)) throw new InvalidOperationException("Clipboard access failed.");
            }
            finally
            {
                // The only managed copy is required for the clipboard API and is released promptly.
                derived = string.Empty;
            }
            AppSettings settings = _getSettings();
            settings.LastSelectedMkfFile = Path.GetFileName(path);
            await _saveSettings(settings);
            _status.ForeColor = Color.DarkGreen;
            _status.Text = $"Derived key copied to the clipboard. It will be cleared in {_getSettings().ClipboardTimeoutSeconds} seconds.";
        }
        catch (Exception exception) when (exception is InvalidDataException or ArgumentException or IOException or UnauthorizedAccessException or CryptographicException or InvalidOperationException)
        {
            ShowError(exception.Message);
        }
        finally
        {
            secret = string.Empty;
            _memorySecret.Clear();
            _derive.Enabled = true;
        }
    }

    private void ShowError(string message)
    {
        _status.ForeColor = Color.DarkRed;
        _status.Text = message;
        MessageBox.Show(this, message, "Xilent Vault Agent", MessageBoxButtons.OK, MessageBoxIcon.Warning);
    }

    private sealed record FileSelection(string Path)
    {
        public override string ToString() => System.IO.Path.GetFileName(Path);
    }
}
