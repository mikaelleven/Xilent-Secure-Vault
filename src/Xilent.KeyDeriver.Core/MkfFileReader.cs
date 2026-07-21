namespace Xilent.KeyDeriver.Core;

public static class MkfFileReader
{
    public const int KeyMaterialLength = 32;
    public const int SaltLength = 16;
    public const int ExpectedLength = KeyMaterialLength + SaltLength;

    public static async Task<MkfFile> ReadAsync(string path, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        try
        {
            await using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.SequentialScan);
            if (stream.Length != ExpectedLength)
            {
                throw new InvalidDataException($"The selected MKF file is invalid. Expected exactly {ExpectedLength} bytes but found {stream.Length} bytes.");
            }

            byte[] bytes = GC.AllocateUninitializedArray<byte>(ExpectedLength);
            try
            {
                int offset = 0;
                while (offset < bytes.Length)
                {
                    int count = await stream.ReadAsync(bytes.AsMemory(offset), cancellationToken);
                    if (count == 0)
                    {
                        throw new InvalidDataException("The selected MKF file could not be read completely.");
                    }
                    offset += count;
                }

                byte[] keyMaterial = bytes[..KeyMaterialLength];
                byte[] salt = bytes[KeyMaterialLength..];
                return new MkfFile(keyMaterial, salt);
            }
            finally
            {
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes);
            }
        }
        catch (InvalidDataException)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (IOException exception)
        {
            throw new InvalidDataException("The selected MKF file could not be read.", exception);
        }
        catch (UnauthorizedAccessException exception)
        {
            throw new InvalidDataException("The selected MKF file could not be read.", exception);
        }
    }
}
