namespace Xilent.KeyDeriver.Core;

public sealed class MkfFile(byte[] keyMaterial, byte[] salt) : IDisposable
{
    public SensitiveBuffer KeyMaterial { get; } = new(keyMaterial);
    public SensitiveBuffer Salt { get; } = new(salt);

    public void Dispose()
    {
        KeyMaterial.Dispose();
        Salt.Dispose();
    }
}
