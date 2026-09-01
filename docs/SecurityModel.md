# Security model

Each `.mkf` is exactly 48 binary bytes: 32 bytes of key material followed by 16 bytes of salt. It contains no Hx, info string, derived key, display name, metadata, or JSON. Hx and info are entered manually and are not persisted in the Vault or application configuration.

H1 is entered only in VeraCrypt's normal password dialog. This application does not retrieve it, cache it, automate it, or put it on the command line. Secrets and sensitive values are never passed to VeraCrypt as command-line arguments because process arguments can be captured by diagnostic tools, process monitors, crash reports, shell history, or logs that may be scanned by other software. NF1 remains a local VeraCrypt keyfile on the trusted computer.

Container and NF1 paths can be Base64 encoded in the local configuration. Base64 is not encryption and provides only light obfuscation against obvious plaintext path searches. It is not protection against a local attacker.

The app minimizes secret lifetime using `CryptographicOperations.ZeroMemory` for owned byte arrays and clears the Hx UI field after use, errors, hiding, and exit. Managed strings, swap files, crash dumps, and the Windows clipboard prevent a claim of complete erasure. After copying, the app requests Windows clipboard-history and cloud-sync exclusion formats where available. It retains only a SHA-256 digest, waits for the configured timeout, and clears the clipboard only if the current Unicode text still matches that digest; this avoids overwriting newer clipboard content. The digest and timer state are then discarded and the digest buffer is zeroed.

Clipboard cleanup is best-effort, not guaranteed erasure. Clipboard managers, history, cloud synchronization, screenshots, other processes, clipboard locks, and memory snapshots may retain the value. Clipboard contents remain exposed to software with sufficient user access.

A mounted VeraCrypt Vault is available to software with sufficient user access. Malware, keyloggers, screen capture, memory inspection, and a fully compromised trusted computer are outside the effective threat model.
