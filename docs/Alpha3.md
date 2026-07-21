# Alpha 3 design notes

Not implemented in Alpha 1 or Alpha 2:

- A configurable global hotkey such as `Ctrl+Alt+K`, implemented with `RegisterHotKey` and released with `UnregisterHotKey`. It must detect conflicts and never open duplicate forms during a modal operation.
- Better removable-media identification using a non-secret marker, volume label/serial number, and a relative container path. Drive letters remain only a starting point.
- Versioned configuration migration from Base64 path obfuscation to optional per-user DPAPI protection. DPAPI is still not protection from malware running as the same user.
- Optional normal unmount policies for inactivity, Windows lock, sleep, hibernation, or exit. No automatic force-unmount.
- An optional Secure Desktop workflow. Practical mode remains default because the designed H1 workflow requires normal clipboard paste.
