# Xilent Vault Agent

Windows-only personal vault helper for a VeraCrypt Vault and Xilent Key Deriver V1. It reads an existing 48-byte binary `.mkf` file, combines its 32-byte key material and 16-byte salt with a manually entered Hx memory secret and info string, then copies the resulting 64-character lowercase hexadecimal key to the clipboard.

## Requirements

- Windows 10 or later.
- .NET 10 Desktop Runtime (SDK for building).
- VeraCrypt installed or selected in Settings.
- A VeraCrypt container, a locally trusted NF1 VeraCrypt keyfile, and the H1 password held separately.

## Initial Vault setup

1. Create the marker file at the root of the mounted Vault, for example `Q:\.Xilent-vault`.
2. Its entire content must be exactly `Xilent-VAULT-1`, with no added newline.
3. Put the binary 48-byte `.mkf` files in `Q:\Keys` or change the relative directory in Settings.
4. Open Settings from the tray icon and select VeraCrypt, the container, and NF1. The application stores those two paths as Base64 UTF-8 only; this is obfuscation, not encryption.
5. Keep H1 out of the application. VeraCrypt prompts for it normally and you paste it manually.

## Use

Alpha 1 functionality works with a manually mounted Vault: open the form, choose an `.mkf`, enter Hx and the exact info string, then press Enter or **Derive and Copy**. The Hx field is cleared immediately. The application clears the clipboard only if it still contains the same copied key after the configured timeout.

Alpha 2 runs in the system tray. Double-clicking the icon or choosing **Unlock Data Key** mounts the Vault when needed, waits for its exact marker file, then opens the derivation form. The tray menu also mounts, unmounts, opens the MKF directory, opens Settings, and exits. Red means locked, green means validated mounted Vault, and yellow means an error or another volume at the configured drive letter.

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

The app does not store H1, Hx, info strings, `.mkf` contents, final keys, or clipboard plaintext after copying. It does not use a VeraCrypt password command-line argument. Clipboard exposure is reduced, not eliminated; disable clipboard history, cloud clipboard, and third-party clipboard managers where possible. A fully compromised trusted computer is outside this tool's protection model.

See [Architecture](docs/Architecture.md), [Security model](docs/SecurityModel.md), and [Alpha 3 design](docs/Alpha3.md).

## Existing-prototype assumptions

The existing Python Xilent Key Deriver is the source of truth. This implementation preserves `XILENT-KEY-V1`, NFC UTF-8 Hx encoding, PBKDF2-HMAC-SHA-256 with 600000 iterations, the exact versioned PBKDF2/HKDF prefixes, HKDF-SHA-256, lowercase hexadecimal output, and the lowercase ASCII info pattern. The original prototype's `.mkf` representation was text; this Vault Agent follows this request's explicit binary 48-byte `.mkf` format and passes its first 32 and next 16 bytes to the unchanged derivation algorithm.

## Manual VeraCrypt test

1. Configure paths and use **Test Vault Configuration**.
2. Verify the configured letter is unused, or mount the correct Vault and marker manually.
3. Choose **Mount Vault**, paste H1 in VeraCrypt's own dialog, and confirm the tray turns green.
4. Derive a key using a public test `.mkf` first, then verify a real target manually.
5. Choose **Unmount Vault** with no Vault files in use. The application does not force unmount.
