# Security model

Each `.mkf` is exactly 48 binary bytes: 32 bytes of key material followed by 16 bytes of salt. It contains no Hx, info string, derived key, display name, metadata, or JSON. Hx and info are entered manually and are not persisted in the Vault or application configuration.

H1 is entered only in VeraCrypt's normal password dialog. This application does not retrieve it, cache it, automate it, put it on the command line, or use Bitwarden CLI. NF1 remains a local VeraCrypt keyfile on trusted computers.

Container and NF1 paths can be Base64 encoded in the local configuration. Base64 is not encryption and provides only light obfuscation against obvious plaintext path searches. It is not protection against a local attacker.

The app minimizes secret lifetime using `CryptographicOperations.ZeroMemory` for owned byte arrays and clears the Hx UI field after use, errors, hiding, and exit. Managed strings, swap files, crash dumps, and the Windows clipboard prevent a claim of complete erasure. Clipboard exclusion formats are requested where available, then the clipboard is conditionally cleared by its SHA-256 digest. Clipboard contents remain exposed to software with sufficient user access.

A mounted VeraCrypt Vault is available to software with sufficient user access. Malware, keyloggers, screen capture, memory inspection, and a fully compromised trusted computer are outside the effective threat model.
