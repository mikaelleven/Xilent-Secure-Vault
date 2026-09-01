# Xilent Vault Agent

Windows-only vault helper for a VeraCrypt Vault and Xilent Key Deriver V1. It reads an existing 48-byte binary `.mkf` file, combines its 32-byte key material and 16-byte salt with a manually entered Hx memory secret and info string, then copies the resulting 64-character lowercase hexadecimal key to the clipboard.

## Requirements

- Windows 10 or later.
- .NET 10 Desktop Runtime (SDK for building).
- VeraCrypt installed or selected in Settings.
- A VeraCrypt container, a locally trusted NF1 VeraCrypt keyfile, and the H1 password held separately.

## Initial Vault setup

1. Create the marker file at the root of the mounted Vault, for example `<drive>:\.Xilent-vault`.
2. Its entire content must be exactly `Xilent-VAULT-1`, with no added newline.
3. Put the binary 48-byte `.mkf` files in `<drive>:\Keys` or change the relative directory in Settings.
4. Open Settings from the tray icon and select VeraCrypt, the container, and NF1. The application stores those two paths as Base64 UTF-8 only; this is obfuscation, not encryption.
5. Keep H1 out of the application. VeraCrypt prompts for it normally and you paste it manually.

## Use

Alpha 1 functionality works with a manually mounted Vault: open the form, choose an `.mkf`, enter Hx and the exact info string, then press Enter or **Derive and Copy**. The Hx field is cleared immediately. Clipboard cleanup is described below.

Alpha 2 runs in the system tray. Double-clicking the icon or choosing **Unlock Data Key** mounts the Vault when needed, waits for its exact marker file, then opens the derivation form. The tray menu also mounts, unmounts, opens the MKF directory, opens Settings, and exits. Red means locked, green means validated mounted Vault, and yellow means an error or another volume at the configured drive letter.

## Development and publishing

The repository includes a local .NET 10 SDK in `.tools/dotnet`. In PowerShell, activate it once per shell; the default launch profile then opens the derivation form:

```powershell
. .\scripts\Use-LocalDotNet.ps1
dotnet run --project .\src\Xilent.VaultAgent
```

If the current PowerShell session cannot resolve the local SDK, use it directly once:

```powershell
& .\.tools\dotnet\dotnet.exe run --project .\src\Xilent.VaultAgent
```

Build the solution with:

```powershell
dotnet build .\Xilent.VaultAgent.sln -c Release
```

Three single-file publishing profiles are available:

| Profile | Purpose | Command |
| --- | --- | --- |
| `SizeOptimizedSingleFile` | Smallest output and lowest practical baseline memory use. Requires .NET 10 Windows Desktop Runtime. | `dotnet publish .\src\Xilent.VaultAgent -p:PublishProfile=SizeOptimizedSingleFile -o .\publish\size` |
| `ColdStartSingleFile` | Faster cold start through ReadyToRun. Requires .NET 10 Windows Desktop Runtime and produces a larger file. | `dotnet publish .\src\Xilent.VaultAgent -p:PublishProfile=ColdStartSingleFile -o .\publish\cold-start` |
| `SelfContainedSingleFile` | Simplest distribution: no separately installed .NET Desktop Runtime. Produces the largest file. | `dotnet publish .\src\Xilent.VaultAgent -p:PublishProfile=SelfContainedSingleFile -o .\publish\self-contained` |

For example, create the compact profile with:

```powershell
dotnet publish .\src\Xilent.VaultAgent -p:PublishProfile=SizeOptimizedSingleFile -o .\publish\size
```

The framework-dependent profiles avoid bundling a private runtime, which keeps output and per-process memory use lower than the self-contained profile. Do not enable trimming for this WinForms application without a dedicated compatibility pass.

## Commands

```text
Xilent.VaultAgent.exe
Xilent.VaultAgent.exe --show
Xilent.VaultAgent.exe --mount
Xilent.VaultAgent.exe --unmount
Xilent.VaultAgent.exe --settings
```

Only one instance runs. Later launches send the selected action to it, which makes normal shortcuts, Start Menu, Flow Launcher, and PowerToys Command Palette suitable launch points.

## Keyboard use

- `Alt+K`, `Alt+M`, `Alt+I` focus key file, Hx, and info fields.
- `Tab` / `Shift+Tab` move between controls.
- Arrow keys and typing navigate the key-file list.
- `Enter` derives and copies.
- `Escape` clears Hx and info then hides the form.

## Security limits

The app does not store H1, Hx, info strings, `.mkf` contents, final keys, or clipboard plaintext after copying. A fully compromised trusted computer is outside this tool's protection model.

### VeraCrypt command-line handling

The application deliberately does not call VeraCrypt with H1, NF1, or any other secret or sensitive information as command-line arguments. Process arguments can be captured by diagnostic tools, crash reports, process monitoring, shell history, or security and audit logs. Those logs may be retained or scanned by other software, so passing a secret on the command line would create an unnecessary copy outside VeraCrypt's protected password dialog. VeraCrypt prompts for H1 normally, and the user enters it there.

### Clipboard cleanup

After copying a derived key, the application requests Windows clipboard metadata that discourages clipboard-history and cloud-sync processing where supported. It records only a SHA-256 digest of the copied value, not the value itself, and starts the configured cleanup timer. When the timer expires, it reads the current Unicode clipboard text and clears the clipboard only when its digest still matches the copied key. This avoids deleting newer content that the user or another application placed on the clipboard. The tracked digest and timer state are then discarded and the digest buffer is zeroed.

This reduces exposure but is not a perfect or guaranteed erasure mechanism. Clipboard managers, history, cloud synchronization, screenshots, other processes, memory snapshots, or failures while the clipboard is locked may retain the key. Disable clipboard history, cloud clipboard, and third-party clipboard managers where possible, and treat the clipboard as exposed while the key is present.

See [Architecture](docs/Architecture.md), [Security model](docs/SecurityModel.md), and [Alpha 3 design](docs/Alpha3.md).

## Existing-prototype assumptions

The existing Python Xilent Key Deriver is the source of truth. This implementation preserves `XILENT-KEY-V1`, NFC UTF-8 Hx encoding, PBKDF2-HMAC-SHA-256 with 600000 iterations, the exact versioned PBKDF2/HKDF prefixes, HKDF-SHA-256, lowercase hexadecimal output, and the lowercase ASCII info pattern. The original prototype's `.mkf` representation was text; this Vault Agent follows this request's explicit binary 48-byte `.mkf` format and passes its first 32 and next 16 bytes to the unchanged derivation algorithm.

## Manual VeraCrypt test

1. Configure paths and use **Test Vault Configuration**.
2. Verify the configured letter is unused, or mount the correct Vault and marker manually.
3. Choose **Mount Vault**, paste H1 in VeraCrypt's own dialog, and confirm the tray turns green.
4. Derive a key using a public test `.mkf` first, then verify a real target manually.
5. Choose **Unmount Vault** with no Vault files in use. The application does not force unmount.
