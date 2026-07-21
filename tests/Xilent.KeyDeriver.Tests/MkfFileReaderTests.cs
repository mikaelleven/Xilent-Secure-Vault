using Microsoft.VisualStudio.TestTools.UnitTesting;
using Xilent.KeyDeriver.Core;

namespace Xilent.KeyDeriver.Tests;

[TestClass]
public sealed class MkfFileReaderTests
{
    [DataTestMethod]
    [DataRow(0)]
    [DataRow(47)]
    [DataRow(49)]
    [DataRow(4096)]
    public async Task InvalidSizesAreRejected(int length)
    {
        string path = Path.GetTempFileName();
        try
        {
            await File.WriteAllBytesAsync(path, new byte[length]);
            InvalidDataException exception = await Assert.ThrowsExceptionAsync<InvalidDataException>(() => MkfFileReader.ReadAsync(path));
            StringAssert.Contains(exception.Message, "Expected exactly 48 bytes");
        }
        finally { File.Delete(path); }
    }

    [TestMethod]
    public async Task ValidFileSplitsTheExactBinaryLayout()
    {
        string path = Path.GetTempFileName();
        try
        {
            await File.WriteAllBytesAsync(path, Enumerable.Range(0, 48).Select(value => (byte)value).ToArray());
            using MkfFile mkf = await MkfFileReader.ReadAsync(path);
            CollectionAssert.AreEqual(Enumerable.Range(0, 32).Select(value => (byte)value).ToArray(), mkf.KeyMaterial.Value);
            CollectionAssert.AreEqual(Enumerable.Range(32, 16).Select(value => (byte)value).ToArray(), mkf.Salt.Value);
        }
        finally { File.Delete(path); }
    }

    [TestMethod]
    public async Task MissingFileIsRejected()
    {
        await Assert.ThrowsExceptionAsync<InvalidDataException>(() => MkfFileReader.ReadAsync(Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".mkf")));
    }
}
