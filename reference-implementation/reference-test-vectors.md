# XILENT-KEY-V1 Reference Test Vectors

Generated from `tests/Xilent.KeyDeriver.Tests/TestVectors/derivation-vectors.json`.
These are public interoperability vectors; the memorized secrets are test data only.

| # | Master-key bytes (hex) | Memorized secret | Info | Expected derived key |
|---:|---|---|---|---|
| 1 | `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000102030405060708090a0b0c0d0e0f` | `public test memory secret` | `cryptotest:test:v1` | `75f76fdedf2d5384a93c94440c9f6a731ecb72ea896970811be909a7a61a3a37` |
| 2 | `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000102030405060708090a0b0c0d0e0f` | `café` | `backup:unicode:v1` | `ccf82bb35d3199fa640611c784bc9a6e72f12ea866e2754660e4c094c24a20a4` |
| 3 | `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000102030405060708090a0b0c0d0e0f` | ` memory secret ` | `data:leading-trailing:v1` | `d48efd8f7cb04e56796ba710ddef01f072b5930b1af457b0afb340a4450e92e8` |

## Algorithm parameters

- PBKDF2 iterations: `600000`
- Master-key material length: `32` bytes
- Master-key salt length: `16` bytes
- Derived key length: `32` bytes
- Password/PBKDF2 salt prefix: `b'XILENT-PBKDF2-V1\x00'`
- HKDF salt prefix: `b'XILENT-HKDF-V1\x00'`
- HKDF info prefix: `b'XILENT-KEY-V1\x00'`
