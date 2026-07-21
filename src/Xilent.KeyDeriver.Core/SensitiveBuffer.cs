using System.Security.Cryptography;

namespace Xilent.KeyDeriver.Core;

public sealed class SensitiveBuffer(byte[] value) : IDisposable
{
    private byte[]? _value = value ?? throw new ArgumentNullException(nameof(value));

    public byte[] Value => _value ?? throw new ObjectDisposedException(nameof(SensitiveBuffer));

    public void Dispose()
    {
        if (_value is not null)
        {
            CryptographicOperations.ZeroMemory(_value);
            _value = null;
        }
    }
}
