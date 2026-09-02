# XILENT-KEY-V1 derived-key pseudo-code

This is a direct, language-neutral description of the derivation. All byte
concatenations preserve the written order.

```text
CONSTANT PBKDF2_ITERATIONS = 600000
CONSTANT OUTPUT_LENGTH = 32 bytes
CONSTANT PASSWORD_SALT_PREFIX = UTF-8 bytes of "XILENT-PBKDF2-V1" followed by 00
CONSTANT HKDF_SALT_PREFIX = UTF-8 bytes of "XILENT-HKDF-V1" followed by 00
CONSTANT HKDF_INFO_PREFIX = UTF-8 bytes of "XILENT-KEY-V1" followed by 00

FUNCTION DeriveKey(mkfFileBytes, memorizedSecret, infoString):
    REQUIRE length(mkfFileBytes) equals 48 bytes
    REQUIRE memorizedSecret is not empty
    REQUIRE infoString matches ^[a-z0-9][a-z0-9:._-]{0,127}$

    masterKeyMaterial = mkfFileBytes[0 through 31]
    masterKeySalt = mkfFileBytes[32 through 47]

    normalizedSecret = NormalizeUnicodeNFC(memorizedSecret)
    normalizedSecretBytes = UTF8Encode(normalizedSecret)
    infoStringBytes = ASCIIEncode(infoString)

    passwordDerivationSalt = PASSWORD_SALT_PREFIX || masterKeySalt
    memorizedSecretKey = PBKDF2-HMAC-SHA-256(
        password = normalizedSecretBytes,
        salt = passwordDerivationSalt,
        iterations = PBKDF2_ITERATIONS,
        outputLength = 32 bytes
    )

    hkdfInputKeyMaterial = masterKeyMaterial || memorizedSecretKey
    hkdfSalt = HKDF_SALT_PREFIX || masterKeySalt
    hkdfInfo = HKDF_INFO_PREFIX || infoStringBytes

    finalKeyBytes = HKDF-SHA-256(
        inputKeyMaterial = hkdfInputKeyMaterial,
        salt = hkdfSalt,
        info = hkdfInfo,
        outputLength = OUTPUT_LENGTH
    )

    RETURN LowercaseHexEncode(finalKeyBytes)


FUNCTION HKDF-SHA-256(inputKeyMaterial, salt, info, outputLength):
    REQUIRE outputLength is between 0 and 255 * 32 bytes

    pseudorandomKey = HMAC-SHA-256(key = salt, message = inputKeyMaterial)
    previousBlock = empty bytes
    output = empty bytes

    FOR counter FROM 1 TO 255:
        previousBlock = HMAC-SHA-256(
            key = pseudorandomKey,
            message = previousBlock || info || OneByte(counter)
        )
        output = output || previousBlock

        IF length(output) is at least outputLength:
            RETURN first outputLength bytes of output
```

For the 32-byte output used by XILENT-KEY-V1, HKDF expansion produces only its
first SHA-256 block (`counter = 1`). The loop remains in the pseudo-code so the
standard HKDF construction is clear.
