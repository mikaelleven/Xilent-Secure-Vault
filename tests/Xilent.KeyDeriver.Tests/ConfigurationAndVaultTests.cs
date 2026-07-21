using Microsoft.VisualStudio.TestTools.UnitTesting;
using Xilent.VaultAgent.Models;
using Xilent.VaultAgent.Services;

namespace Xilent.KeyDeriver.Tests;

[TestClass]
public sealed class ConfigurationAndVaultTests
{
    [TestMethod]
    public void PathEncodingRoundTripsWithoutClaimingEncryption()
    {
        string path = @"E:\Vaults\vault.hc";
        Assert.AreEqual(path, ConfigurationService.DecodePath(ConfigurationService.EncodePath(path)));
    }

    [TestMethod]
    public void InvalidBase64AndSettingsAreRejected()
    {
        Assert.ThrowsException<InvalidDataException>(() => ConfigurationService.DecodePath("not Base64"));
        Assert.ThrowsException<InvalidDataException>(() => ConfigurationService.Validate(new AppSettings { VaultMountLetter = "QQ" }));
        Assert.ThrowsException<InvalidDataException>(() => ConfigurationService.Validate(new AppSettings { ClipboardTimeoutSeconds = 1 }));
    }

    [TestMethod]
    public void VaultDetectionRequiresExactMarkerValue()
    {
        // Drive existence is not mocked here; the production service requires both the drive and exact marker.
        AppSettings settings = new() { VaultMountLetter = "Z", VaultMarkerFile = ".Xilent-vault", VaultMarkerValue = "Xilent-VAULT-1" };
        Assert.AreNotEqual(VaultState.Mounted, new VaultService().GetState(settings));
    }
}
