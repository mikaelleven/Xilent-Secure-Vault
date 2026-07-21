using System.Text.Json;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Xilent.KeyDeriver.Core;

namespace Xilent.KeyDeriver.Tests;

[TestClass]
public sealed class KeyDerivationTests
{
    [TestMethod]
    public void PublicPrototypeVectorsMatchByteForByte()
    {
        string json = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "TestVectors", "derivation-vectors.json"));
        foreach (DerivationVector vector in JsonSerializer.Deserialize<List<DerivationVector>>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true })!)
        {
            byte[] bytes = Convert.FromHexString(vector.MkfHex);
            using MkfFile mkf = new(bytes[..32], bytes[32..]);
            Assert.AreEqual(vector.Expected, KeyDerivationService.Derive(mkf, vector.MemorySecret, vector.Info));
        }
    }

    [TestMethod]
    public void NfcEquivalentMemorySecretsMatch()
    {
        byte[] bytes = Enumerable.Range(0, 48).Select(value => (byte)value).ToArray();
        using MkfFile first = new(bytes[..32], bytes[32..]);
        using MkfFile second = new(bytes[..32], bytes[32..]);
        Assert.AreEqual(KeyDerivationService.Derive(first, "caf\u00e9", "backup:unicode:v1"), KeyDerivationService.Derive(second, "cafe\u0301", "backup:unicode:v1"));
    }

    [TestMethod]
    public void InfoValidationRejectsChangesThatThePrototypeRejects()
    {
        foreach (string value in new[] { "", "Uppercase", "leading space", "info/with-slash", new string('a', 129) })
        {
            Assert.ThrowsException<ArgumentException>(() => KeyDerivationService.ValidateInfoString(value));
        }
    }

    private sealed class DerivationVector
    {
        public string MkfHex { get; set; } = string.Empty;
        public string MemorySecret { get; set; } = string.Empty;
        public string Info { get; set; } = string.Empty;
        public string Expected { get; set; } = string.Empty;
    }
}
