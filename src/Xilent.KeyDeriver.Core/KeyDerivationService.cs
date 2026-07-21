using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Xilent.KeyDeriver.Core;

public static partial class KeyDerivationService
{
    public const string AlgorithmVersion = "XILENT-KEY-V1";
    public const int Pbkdf2Iterations = 600_000;
    private static readonly byte[] PasswordSaltPrefix = "XILENT-PBKDF2-V1\0"u8.ToArray();
    private static readonly byte[] HkdfSaltPrefix = "XILENT-HKDF-V1\0"u8.ToArray();
    private static readonly byte[] HkdfInfoPrefix = "XILENT-KEY-V1\0"u8.ToArray();

    public static string Derive(MkfFile mkfFile, string memorySecret, string info)
    {
        ArgumentNullException.ThrowIfNull(mkfFile);
        if (string.IsNullOrEmpty(memorySecret))
        {
            throw new ArgumentException("Memory secret must not be empty.", nameof(memorySecret));
        }

        byte[] encodedInfo = ValidateInfoString(info);
        byte[] normalizedSecret = Encoding.UTF8.GetBytes(memorySecret.Normalize(NormalizationForm.FormC));
        byte[] passwordSalt = Combine(PasswordSaltPrefix, mkfFile.Salt.Value);
        byte[]? memoryKey = null;
        byte[]? inputKeyMaterial = null;
        byte[]? hkdfSalt = null;
        byte[]? hkdfInfo = null;
        byte[]? finalKey = null;
        try
        {
            memoryKey = Rfc2898DeriveBytes.Pbkdf2(normalizedSecret, passwordSalt, Pbkdf2Iterations, HashAlgorithmName.SHA256, 32);
            inputKeyMaterial = Combine(mkfFile.KeyMaterial.Value, memoryKey);
            hkdfSalt = Combine(HkdfSaltPrefix, mkfFile.Salt.Value);
            hkdfInfo = Combine(HkdfInfoPrefix, encodedInfo);
            finalKey = HkdfSha256(inputKeyMaterial, hkdfSalt, hkdfInfo, 32);
            return Convert.ToHexStringLower(finalKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encodedInfo);
            CryptographicOperations.ZeroMemory(normalizedSecret);
            CryptographicOperations.ZeroMemory(passwordSalt);
            Clear(memoryKey);
            Clear(inputKeyMaterial);
            Clear(hkdfSalt);
            Clear(hkdfInfo);
            Clear(finalKey);
        }
    }

    public static byte[] ValidateInfoString(string info)
    {
        ArgumentNullException.ThrowIfNull(info);
        if (!InfoPattern().IsMatch(info))
        {
            throw new ArgumentException("Info string must match lowercase ASCII: a-z, 0-9, colon, dot, underscore, or hyphen.", nameof(info));
        }
        return Encoding.ASCII.GetBytes(info);
    }

    public static byte[] HkdfSha256(ReadOnlySpan<byte> secret, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> info, int length)
    {
        if (length < 0 || length > 255 * 32)
        {
            throw new ArgumentOutOfRangeException(nameof(length), "Requested HKDF output length is invalid.");
        }

        byte[] prk = HMACSHA256.HashData(salt, secret);
        byte[] output = GC.AllocateUninitializedArray<byte>(length);
        byte[] previous = [];
        try
        {
            int written = 0;
            for (byte counter = 1; written < length; counter++)
            {
                byte[] input = GC.AllocateUninitializedArray<byte>(previous.Length + info.Length + 1);
                try
                {
                    previous.CopyTo(input, 0);
                    info.CopyTo(input.AsSpan(previous.Length));
                    input[^1] = counter;
                    byte[] next = HMACSHA256.HashData(prk, input);
                    CryptographicOperations.ZeroMemory(previous);
                    previous = next;
                    int count = Math.Min(previous.Length, length - written);
                    previous.AsSpan(0, count).CopyTo(output.AsSpan(written));
                    written += count;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(input);
                }
            }
            return output;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(output);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(prk);
            CryptographicOperations.ZeroMemory(previous);
        }
    }

    private static byte[] Combine(ReadOnlySpan<byte> first, ReadOnlySpan<byte> second)
    {
        byte[] output = GC.AllocateUninitializedArray<byte>(first.Length + second.Length);
        first.CopyTo(output);
        second.CopyTo(output.AsSpan(first.Length));
        return output;
    }

    private static void Clear(byte[]? value)
    {
        if (value is not null)
        {
            CryptographicOperations.ZeroMemory(value);
        }
    }

    [GeneratedRegex("^[a-z0-9][a-z0-9:._-]{0,127}$", RegexOptions.CultureInvariant)]
    private static partial Regex InfoPattern();
}
