using Xilent.VaultAgent.Models;
using Xilent.VaultAgent.Services;

namespace Xilent.VaultAgent.Forms;

public sealed class SettingsForm : Form
{
    private readonly AppSettings _settings;
    private readonly VeraCryptService _veraCryptService;
    private readonly TextBox _veraCrypt = new() { Width = 390 };
    private readonly TextBox _container = new() { Width = 390 };
    private readonly TextBox _nf1 = new() { Width = 390 };
    private readonly TextBox _letter = new() { Width = 50, MaxLength = 1 };
    private readonly TextBox _mkfDirectory = new() { Width = 180 };
    private readonly NumericUpDown _clipboardTimeout = new() { Minimum = 5, Maximum = 300, Width = 80 };
    private readonly CheckBox _startup = new() { Text = "Start with Windows", AutoSize = true };

    public SettingsForm(AppSettings settings, VeraCryptService veraCryptService)
    {
        _settings = settings;
        _veraCryptService = veraCryptService;
        Text = "Vault Agent Settings";
        FormBorderStyle = FormBorderStyle.FixedDialog;
        StartPosition = FormStartPosition.CenterParent;
        MaximizeBox = false; MinimizeBox = false; AutoSize = true; AutoSizeMode = AutoSizeMode.GrowAndShrink;
        _veraCrypt.Text = veraCryptService.DiscoverExecutable(settings) ?? settings.VeraCryptExecutablePath ?? string.Empty;
        _container.Text = settings.VaultContainerPathBase64 is null ? string.Empty : ConfigurationService.DecodePath(settings.VaultContainerPathBase64);
        _nf1.Text = settings.Nf1PathBase64 is null ? string.Empty : ConfigurationService.DecodePath(settings.Nf1PathBase64);
        _letter.Text = settings.VaultMountLetter;
        _mkfDirectory.Text = settings.MkfRelativeDirectory;
        _clipboardTimeout.Value = settings.ClipboardTimeoutSeconds;
        _startup.Checked = settings.StartWithWindows;
        TableLayoutPanel layout = new() { AutoSize = true, Padding = new Padding(14), ColumnCount = 3 };
        AddPathRow(layout, 0, "&VeraCrypt executable:", _veraCrypt, "Executable files (*.exe)|*.exe", false);
        AddPathRow(layout, 1, "&Vault container:", _container, "All files (*.*)|*.*", false);
        AddPathRow(layout, 2, "&NF1 keyfile:", _nf1, "All files (*.*)|*.*", false);
        layout.Controls.Add(new Label { Text = "&Mount letter:", AutoSize = true }, 0, 3); layout.Controls.Add(_letter, 1, 3);
        layout.Controls.Add(new Label { Text = "&MKF relative directory:", AutoSize = true }, 0, 4); layout.Controls.Add(_mkfDirectory, 1, 4);
        layout.Controls.Add(new Label { Text = "&Clipboard timeout (seconds):", AutoSize = true }, 0, 5); layout.Controls.Add(_clipboardTimeout, 1, 5);
        layout.Controls.Add(_startup, 1, 6);
        Button save = new() { Text = "Save", DialogResult = DialogResult.OK, AutoSize = true };
        Button cancel = new() { Text = "Cancel", DialogResult = DialogResult.Cancel, AutoSize = true };
        Button test = new() { Text = "Test Vault Configuration", AutoSize = true };
        test.Click += (_, _) => TestConfiguration();
        FlowLayoutPanel buttons = new() { AutoSize = true, FlowDirection = FlowDirection.RightToLeft };
        buttons.Controls.Add(save); buttons.Controls.Add(cancel); buttons.Controls.Add(test);
        layout.Controls.Add(buttons, 1, 7); layout.SetColumnSpan(buttons, 2);
        Controls.Add(layout);
        AcceptButton = save; CancelButton = cancel;
        FormClosing += (_, eventArgs) =>
        {
            if (DialogResult != DialogResult.OK) return;
            try { ApplyToSettings(); }
            catch (Exception exception) when (exception is InvalidDataException or ArgumentException)
            {
                eventArgs.Cancel = true;
                MessageBox.Show(this, exception.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        };
    }

    private static void AddPathRow(TableLayoutPanel layout, int row, string label, TextBox box, string filter, bool folder)
    {
        layout.Controls.Add(new Label { Text = label, AutoSize = true }, 0, row);
        layout.Controls.Add(box, 1, row);
        Button browse = new() { Text = "Browse", AutoSize = true };
        browse.Click += (_, _) =>
        {
            using OpenFileDialog dialog = new() { Filter = filter, CheckFileExists = !folder };
            if (dialog.ShowDialog() == DialogResult.OK) box.Text = dialog.FileName;
        };
        layout.Controls.Add(browse, 2, row);
    }

    private void ApplyToSettings()
    {
        _settings.VeraCryptExecutablePath = NullIfEmpty(_veraCrypt.Text);
        _settings.VaultContainerPathBase64 = EncodeOptional(_container.Text);
        _settings.Nf1PathBase64 = EncodeOptional(_nf1.Text);
        _settings.VaultMountLetter = _letter.Text;
        _settings.MkfRelativeDirectory = _mkfDirectory.Text;
        _settings.ClipboardTimeoutSeconds = decimal.ToInt32(_clipboardTimeout.Value);
        _settings.StartWithWindows = _startup.Checked;
        ConfigurationService.Validate(_settings);
    }

    private void TestConfiguration()
    {
        try
        {
            AppSettings candidate = new()
            {
                VeraCryptExecutablePath = NullIfEmpty(_veraCrypt.Text),
                VaultContainerPathBase64 = EncodeOptional(_container.Text),
                Nf1PathBase64 = EncodeOptional(_nf1.Text),
                VaultMountLetter = _letter.Text,
                MkfRelativeDirectory = _mkfDirectory.Text,
                ClipboardTimeoutSeconds = decimal.ToInt32(_clipboardTimeout.Value),
                StartWithWindows = _startup.Checked
            };
            _veraCryptService.ValidateConfiguration(candidate);
            MessageBox.Show(this, "Vault configuration is valid. It was not mounted.", Text, MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        catch (Exception exception) when (exception is InvalidDataException or ArgumentException)
        {
            MessageBox.Show(this, exception.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    private static string? NullIfEmpty(string value) => string.IsNullOrWhiteSpace(value) ? null : value;
    private static string? EncodeOptional(string value) => string.IsNullOrWhiteSpace(value) ? null : ConfigurationService.EncodePath(value);
}
