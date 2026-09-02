# XILENT-KEY-V1 derived-key reference walkthrough

## Purpose and scope

This document specifies how XILENT-KEY-V1 recreates a derived key from one
master-key file, a memorized secret, and an info string. It is written for
recovery and interoperability: an independent implementation that follows this
document and [`derived-key-pseudocode.md`](derived-key-pseudocode.md) must
produce the same 64-character lowercase hexadecimal key.

The adjacent [`derive_key.py`](derive_key.py) is intentionally a single,
readable reference program. It is **not** a hardened secret-handling tool.
Python immutable strings and byte objects cannot be reliably erased from memory.
Use the XVault application for normal use where its platform protections are
appropriate.

## Inputs and control variables

| Name | Value / rule | Why it matters |
|---|---|---|
| Master-key file (`.mkf`) | Exactly 48 binary bytes | Defines the unambiguous file format. |
| Master-key material | Bytes `0..31` (32 bytes) | First secret input to HKDF. |
| Master-key salt | Bytes `32..47` (16 bytes) | Binds the PBKDF2 and HKDF stages to this key file. |
| Memorized secret | Non-empty Unicode text | Second secret input; normalize as Unicode NFC, then UTF-8 encode. Do not trim whitespace. |
| Info string | `^[a-z0-9][a-z0-9:._-]{0,127}$` | Stable, case-sensitive object identifier and HKDF context. It is ASCII encoded. |
| PBKDF2 iteration count | `600000` | The work factor for deriving the memorized-secret key. |
| PBKDF2 PRF | HMAC-SHA-256 | Fixed algorithm; output is 32 bytes. |
| HKDF hash | SHA-256 | Fixed extract-and-expand algorithm; output is 32 bytes. |
| Output representation | Lowercase hex, 64 characters | Portable text form of the 32-byte final key. |

Every item in this table is part of the compatibility contract. Altering a
prefix, encoding, byte order, iteration count, hash, validation rule, or output
case defines a different algorithm and produces a different key.

## The derivation, step by step

### 1. Validate and split the master-key file

Read the `.mkf` as binary data. Reject every length except 48 bytes. The first
32 bytes are `masterKeyMaterial`; the remaining 16 bytes are `masterKeySalt`.
The file has no header, text encoding, metadata, info string, or memorized
secret.

### 2. Prepare the human inputs exactly

The memorized secret must be non-empty. Normalize it with Unicode NFC before
UTF-8 encoding. NFC makes canonically equivalent spelling forms derive the same
result: for example, a precomposed `é` and `e` followed by a combining accent.
No trimming or case conversion occurs, so leading/trailing spaces and letter
case remain meaningful.

The info string is deliberately more restrictive. It must be 1–128 lowercase
ASCII characters, begin with `a-z` or `0-9`, and otherwise contain only
`a-z`, `0-9`, colon (`:`), period (`.`), underscore (`_`), or hyphen (`-`).
It is case-sensitive and encoded as ASCII. Record it exactly if future recovery
is required.

### 3. Turn the memorized secret into a key with PBKDF2

Construct this byte string:

```text
passwordDerivationSalt = "XILENT-PBKDF2-V1" || 00 || masterKeySalt
```

Then calculate:

```text
memorizedSecretKey = PBKDF2-HMAC-SHA-256(
    UTF8(NFC(memorizedSecret)),
    passwordDerivationSalt,
    600000 iterations,
    32 bytes
)
```

The fixed prefix is domain separation: it labels this use of the file salt so
that the same salt is not used ambiguously by another stage.

### 4. Combine both secret inputs with HKDF

Create the exact inputs below. `||` means byte concatenation, never text
concatenation with a separator.

```text
hkdfInputKeyMaterial = masterKeyMaterial || memorizedSecretKey
hkdfSalt = "XILENT-HKDF-V1" || 00 || masterKeySalt
hkdfInfo = "XILENT-KEY-V1" || 00 || ASCII(infoString)
```

HKDF-SHA-256 first extracts a pseudorandom key:

```text
prk = HMAC-SHA-256(key = hkdfSalt, message = hkdfInputKeyMaterial)
```

It then expands the first 32-byte output block:

```text
finalKeyBytes = HMAC-SHA-256(key = prk, message = hkdfInfo || 01)
```

The full HKDF loop is specified in the pseudo-code for completeness. This
algorithm requests 32 bytes, exactly one SHA-256 block, so only counter `01` is
needed.

### 5. Encode the result

Convert `finalKeyBytes` to hexadecimal lowercase text. The result is 64 ASCII
characters. This is the derived key supplied to the protected object.

## Compact flow

```text
48-byte .mkf ──split──> 32-byte material ────────┐
                         16-byte salt ──┬────────┼──> labeled PBKDF2/HKDF salts
memorized secret ─NFC + UTF-8─> PBKDF2 ─┘        │
info string ─validate + ASCII────────────────────┼──> HKDF-SHA-256 ─> 32 bytes
                                                  │                       │
                                                  └───────────────────────┘
                                                                      lowercase hex
```

## Reference test vector

The following values are public test data only; never use them as a real key.

| Field | Value |
|---|---|
| `.mkf` bytes (hex) | `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000102030405060708090a0b0c0d0e0f` |
| Memorized secret | `public test memory secret` |
| Info string | `cryptotest:test:v1` |
| Expected derived key | `75f76fdedf2d5384a93c94440c9f6a731ecb72ea896970811be909a7a61a3a37` |

Run `python derive_key.py --verify-test-vector` from this folder to check the
Python implementation against this vector.

## Operational notes

- Keep the master-key file, memorized secret, and exact info string available
  through your planned recovery process. Losing any of them prevents recreation.
- Do not use the master-key bytes directly as a password.
- A changed control variable deliberately creates a different key; do not
  “upgrade” the versioned constants for an existing protected object.
- The Python script reads the real `.mkf` only when asked and does not save the
  secret or output. Nevertheless, terminal scrollback, clipboard use, process
  state, backups, and a compromised computer can expose sensitive material.
