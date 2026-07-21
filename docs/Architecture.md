# Architecture

`Xilent.KeyDeriver.Core` contains only binary MKF parsing, the fixed Xilent V1 derivation, and sensitive byte-buffer disposal. `Xilent.VaultAgent` contains WinForms UI, tray lifetime, settings, clipboard handling, VeraCrypt process launching, vault-marker validation, and local single-instance IPC.

The UI never parses `.mkf` content or implements cryptography. A selected file is only opened when the user derives a key, read with read-only access, required to be exactly 48 bytes, then disposed and zeroed. The mount service invokes VeraCrypt using `ProcessStartInfo.ArgumentList`; H1 is intentionally absent from all arguments.

Vault status is not inferred from a drive letter. The configured drive must exist and its configured marker file must contain the configured exact value. The tray checks that state every three seconds. The named mutex prevents duplicate instances and the named pipe forwards `--show`, `--mount`, `--unmount`, and `--settings` to the running process.
