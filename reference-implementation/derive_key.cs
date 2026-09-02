// XILENT-KEY-V1 standalone C# reference implementation.
//
// This file intentionally keeps the complete derivation in one small program.
// It is written to be read during interoperability work or recovery, rather
// than as a reusable library or a hardened secret-handling application.
//
// Run directly as a file-based C# app with the .NET 10 SDK, for example:
//   dotnet run derive_key.cs -- path\to\master-key.mkf object:backup:v1
//
// Or verify the public interoperability vector:
//   dotnet run derive_key.cs -- --verify-test-vector

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

internal static class Program
{
    // These values are the complete XILENT-KEY-V1 compatibility contract.
    // Changing any one changes every subsequently derived key.
    private const int Pbkdf2IterationCount = 600_000;
    private const int MasterKeyFileLengthBytes = 48;
    private const int MasterKeyMaterialLengthBytes = 32;
    private const int MasterKeySaltLengthBytes = 16;
    private const int DerivedKeyLengthBytes = 32;

    // The trailing zero byte is intentional domain separation, not a C# string
    // terminator. The strings are ASCII, so UTF-8 produces these exact bytes.
    private static readonly byte[] PasswordSaltPrefix = Encoding.UTF8.GetBytes("XILENT-PBKDF2-V1\0");
    private static readonly byte[] HkdfSaltPrefix = Encoding.UTF8.GetBytes("XILENT-HKDF-V1\0");
    private static readonly byte[] HkdfInfoPrefix = Encoding.UTF8.GetBytes("XILENT-KEY-V1\0");

    // The info string is an identifier, rather than free-form user text. This
    // restricted ASCII form prevents encoding ambiguity in recovery records.
    private static readonly Regex InfoStringPattern = new(
        "^[a-z0-9][a-z0-9:._-]{0,127}$",
        RegexOptions.CultureInvariant);

    private static int Main(string[] commandLineArguments)
    {
        // This test mode is self-contained and does not read a real key file or
        // prompt for a memorized secret.
        if (commandLineArguments.Length == 1 && commandLineArguments[0] == "--verify-test-vector")
        {
            return VerifyPublicTestVector() ? 0 : 1;
        }

        // Normal use needs exactly the path to the 48-byte .mkf and its object
        // identifier. Reject incomplete commands rather than guessing intent.
        if (commandLineArguments.Length != 2)
        {
            Console.Error.WriteLine("Usage: derive_key <master-key.mkf> <info-string>");
            Console.Error.WriteLine("       derive_key --verify-test-vector");
            return 2;
        }

        try
        {
            // Read the master-key file as raw binary. It is not text and has no
            // header or metadata: the first 32 bytes are material, next 16 salt.
            byte[] masterKeyFileContents = File.ReadAllBytes(commandLineArguments[0]);
            string infoString = commandLineArguments[1];

            Console.Write("Memorized secret: ");
            string memorizedSecret = ReadSecretWithoutEcho();
            Console.WriteLine();

            // Validate all inputs before slices or cryptographic operations make
            // an invalid key file layout or identifier appear meaningful.
            if (masterKeyFileContents.Length != MasterKeyFileLengthBytes)
            {
                throw new ArgumentException(
                    "The master-key file must contain exactly 48 bytes: 32 bytes " +
                    "of key material followed by 16 bytes of salt.");
            }

            // Whitespace is meaningful and deliberately not trimmed; only the
            // truly empty secret is invalid because it lacks the second factor.
            if (memorizedSecret.Length == 0)
            {
                throw new ArgumentException("The memorized secret must not be empty.");
            }

            if (!InfoStringPattern.IsMatch(infoString))
            {
                throw new ArgumentException(
                    "The info string must be 1-128 lowercase ASCII characters, start " +
                    "with a-z or 0-9, and otherwise use only a-z, 0-9, :, ., _, or -.");
            }

            // Copy the fixed file regions explicitly. Their order is part of the
            // algorithm: material is an HKDF input; salt labels both KDF stages.
            byte[] masterKeyMaterial = masterKeyFileContents[..MasterKeyMaterialLengthBytes];
            byte[] masterKeySalt = masterKeyFileContents[MasterKeyMaterialLengthBytes..];

            // Normalize equivalent Unicode spellings before UTF-8 encoding. No
            // trimming or case folding is performed, so those remain significant.
            byte[] normalizedMemorizedSecretBytes = Encoding.UTF8.GetBytes(
                memorizedSecret.Normalize(NormalizationForm.FormC));

            // PBKDF2 converts the memorized secret to a fixed 32-byte key. The
            // prefix labels this salt use and separates it from the HKDF salt.
            byte[] passwordDerivationSalt = CombineBytes(PasswordSaltPrefix, masterKeySalt);
            byte[] memorizedSecretKey = Rfc2898DeriveBytes.Pbkdf2(
                normalizedMemorizedSecretBytes,
                passwordDerivationSalt,
                Pbkdf2IterationCount,
                HashAlgorithmName.SHA256,
                DerivedKeyLengthBytes);

            // HKDF receives the two secret inputs in this exact order. The info
            // string is valid ASCII by the earlier validation and is a context label.
            byte[] hkdfInputKeyMaterial = CombineBytes(masterKeyMaterial, memorizedSecretKey);
            byte[] hkdfSalt = CombineBytes(HkdfSaltPrefix, masterKeySalt);
            byte[] hkdfInfo = CombineBytes(HkdfInfoPrefix, Encoding.ASCII.GetBytes(infoString));
            byte[] finalKeyBytes = HkdfSha256(
                hkdfInputKeyMaterial,
                hkdfSalt,
                hkdfInfo,
                DerivedKeyLengthBytes);

            // Lowercase hexadecimal is the portable output: 32 bytes become 64
            // characters. Convert.ToHexString is uppercase, hence ToLowerInvariant.
            Console.WriteLine(Convert.ToHexString(finalKeyBytes).ToLowerInvariant());
            return 0;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException)
        {
            Console.Error.WriteLine($"Error: {exception.Message}");
            return 1;
        }
    }

    private static byte[] HkdfSha256(byte[] inputKeyMaterial, byte[] salt, byte[] info, int outputLengthBytes)
    {
        // RFC 5869 permits no more than 255 SHA-256 digest blocks.
        const int Sha256DigestLengthBytes = 32;
        if (outputLengthBytes < 0 || outputLengthBytes > 255 * Sha256DigestLengthBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(outputLengthBytes), "The requested HKDF output length is invalid.");
        }

        // Extract uses the salt as its HMAC key to turn the combined inputs into
        // a fixed-size pseudorandom key.
        byte[] pseudorandomKey;
        using (HMACSHA256 extractHmac = new(salt))
        {
            pseudorandomKey = extractHmac.ComputeHash(inputKeyMaterial);
        }

        // Expand makes one block at a time: previous block || info || counter.
        // XILENT-KEY-V1 requests 32 bytes, so it returns after the first block.
        byte[] output = new byte[outputLengthBytes];
        byte[] previousBlock = Array.Empty<byte>();
        int outputBytesWritten = 0;
        for (byte blockCounter = 1; blockCounter != 0; blockCounter++)
        {
            byte[] blockInput = CombineBytes(previousBlock, info, new[] { blockCounter });
            using HMACSHA256 expandHmac = new(pseudorandomKey);
            previousBlock = expandHmac.ComputeHash(blockInput);

            int bytesToCopyFromThisBlock = Math.Min(previousBlock.Length, outputLengthBytes - outputBytesWritten);
            Array.Copy(previousBlock, 0, output, outputBytesWritten, bytesToCopyFromThisBlock);
            outputBytesWritten += bytesToCopyFromThisBlock;

            if (outputBytesWritten == outputLengthBytes)
            {
                return output;
            }
        }

        // The requested-length validation makes reaching this point impossible.
        throw new InvalidOperationException("HKDF expansion exceeded its maximum block count.");
    }

    private static bool VerifyPublicTestVector()
    {
        // This public test data is shared with the Python reference. It checks
        // the exact prefixes, byte order, Unicode handling, PBKDF2, and HKDF.
        byte[] publicTestMasterKeyFileContents = Convert.FromHexString(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
            "000102030405060708090a0b0c0d0e0f");
        const string publicTestMemorizedSecret = "public test memory secret";
        const string publicTestInfoString = "cryptotest:test:v1";
        const string expectedDerivedKey = "75f76fdedf2d5384a93c94440c9f6a731ecb72ea896970811be909a7a61a3a37";

        // Repeat the compact derivation here so the test remains easy to audit
        // and does not hide the reference computation behind a call chain.
        byte[] masterKeyMaterial = publicTestMasterKeyFileContents[..MasterKeyMaterialLengthBytes];
        byte[] masterKeySalt = publicTestMasterKeyFileContents[MasterKeyMaterialLengthBytes..];
        byte[] normalizedMemorizedSecretBytes = Encoding.UTF8.GetBytes(
            publicTestMemorizedSecret.Normalize(NormalizationForm.FormC));
        byte[] memorizedSecretKey = Rfc2898DeriveBytes.Pbkdf2(
            normalizedMemorizedSecretBytes,
            CombineBytes(PasswordSaltPrefix, masterKeySalt),
            Pbkdf2IterationCount,
            HashAlgorithmName.SHA256,
            DerivedKeyLengthBytes);
        byte[] finalKeyBytes = HkdfSha256(
            CombineBytes(masterKeyMaterial, memorizedSecretKey),
            CombineBytes(HkdfSaltPrefix, masterKeySalt),
            CombineBytes(HkdfInfoPrefix, Encoding.ASCII.GetBytes(publicTestInfoString)),
            DerivedKeyLengthBytes);
        string actualDerivedKey = Convert.ToHexString(finalKeyBytes).ToLowerInvariant();

        bool passed = CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(actualDerivedKey),
            Encoding.ASCII.GetBytes(expectedDerivedKey));
        Console.WriteLine($"{(passed ? "PASS" : "FAIL")} {publicTestInfoString}: {actualDerivedKey}");
        return passed;
    }

    private static byte[] CombineBytes(params byte[][] byteArrays)
    {
        // This tiny helper makes byte concatenation visible at every derivation
        // step without obscuring the important operands with buffer arithmetic.
        int combinedLength = 0;
        foreach (byte[] byteArray in byteArrays)
        {
            combinedLength += byteArray.Length;
        }

        byte[] combinedBytes = new byte[combinedLength];
        int nextWritePosition = 0;
        foreach (byte[] byteArray in byteArrays)
        {
            Array.Copy(byteArray, 0, combinedBytes, nextWritePosition, byteArray.Length);
            nextWritePosition += byteArray.Length;
        }

        return combinedBytes;
    }

    private static string ReadSecretWithoutEcho()
    {
        // Console.ReadKey intercepts each keypress so the terminal does not echo
        // the secret. Like the Python reference, C# strings cannot be reliably
        // erased afterwards; this is a readable recovery tool, not a vault app.
        StringBuilder enteredSecret = new();
        ConsoleKeyInfo pressedKey;
        while ((pressedKey = Console.ReadKey(intercept: true)).Key != ConsoleKey.Enter)
        {
            if (pressedKey.Key == ConsoleKey.Backspace)
            {
                if (enteredSecret.Length > 0)
                {
                    enteredSecret.Length--;
                }
            }
            else if (!char.IsControl(pressedKey.KeyChar))
            {
                enteredSecret.Append(pressedKey.KeyChar);
            }
        }

        return enteredSecret.ToString();
    }
}
