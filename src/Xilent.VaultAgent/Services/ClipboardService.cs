using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text;
using Xilent.VaultAgent.Infrastructure;

namespace Xilent.VaultAgent.Services;

public sealed class ClipboardService : IDisposable
{
    private byte[]? _copiedDigest;
    private System.Windows.Forms.Timer? _timer;

    public bool Copy(string value, int timeoutSeconds)
    {
        try
        {
            DataObject data = new();
            data.SetData(DataFormats.UnicodeText, value);
            data.SetData("ExcludeClipboardContentFromMonitorProcessing", false);
            data.SetData("CanIncludeInClipboardHistory", false);
            data.SetData("CanUploadToCloudClipboard", false);
            System.Windows.Forms.Clipboard.SetDataObject(data, true);
            ClearTrackedValue();
            _copiedDigest = SHA256.HashData(Encoding.UTF8.GetBytes(value));
            _timer = new System.Windows.Forms.Timer { Interval = checked(timeoutSeconds * 1000) };
            _timer.Tick += (_, _) => ClearIfUnchanged();
            _timer.Start();
            return true;
        }
        catch (ExternalException)
        {
            Logger.Write("Clipboard copy failed.");
            return false;
        }
    }

    public void ClearIfUnchanged()
    {
        if (_copiedDigest is null) return;
        try
        {
            if (!System.Windows.Forms.Clipboard.ContainsText(TextDataFormat.UnicodeText)) return;
            string current = System.Windows.Forms.Clipboard.GetText(TextDataFormat.UnicodeText);
            byte[] currentDigest = SHA256.HashData(Encoding.UTF8.GetBytes(current));
            try
            {
                if (CryptographicOperations.FixedTimeEquals(_copiedDigest, currentDigest))
                {
                    System.Windows.Forms.Clipboard.Clear();
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(currentDigest);
            }
        }
        catch (ExternalException)
        {
            Logger.Write("Clipboard clear failed.");
        }
        finally
        {
            ClearTrackedValue();
        }
    }

    public void Dispose() => ClearTrackedValue();

    private void ClearTrackedValue()
    {
        if (_timer is not null)
        {
            _timer.Stop();
            _timer.Dispose();
            _timer = null;
        }
        if (_copiedDigest is not null)
        {
            CryptographicOperations.ZeroMemory(_copiedDigest);
            _copiedDigest = null;
        }
    }

}
