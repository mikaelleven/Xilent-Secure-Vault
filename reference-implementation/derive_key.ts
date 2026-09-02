#!/usr/bin/env tsx
/**
 * A small, standalone TypeScript reference implementation of XILENT-KEY-V1.
 *
 * This intentionally keeps the complete derivation in one readable file. It
 * uses Node.js built-in modules only, so it can serve as recovery documentation.
 *
 * Usage:
 *   npx tsx derive_key.ts path/to/master-key.mkf object:backup:v1
 *   npx tsx derive_key.ts --verify-test-vector
 *   npx tsx derive_key.ts --write-test-vector-markdown vectors.json vectors.md
 *   npx tsx derive_key.ts --verify-test-vectors vectors.json
 */

// Node.js built-in modules provide the cryptographic primitives, file access,
// and command-line input. No third-party package is required by this script.
import {
    createHmac,
    pbkdf2Sync,
    timingSafeEqual,
} from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { basename } from "node:path";
import { createInterface } from "node:readline/promises";
import { stdin, stdout } from "node:process";

// This section defines the complete, versioned algorithm contract. Do not
// change any value here if a key must remain compatible with XILENT-KEY-V1.
const PBKDF2_ITERATION_COUNT: number = 600_000;
const MASTER_KEY_FILE_LENGTH_BYTES: number = 48;
const MASTER_KEY_MATERIAL_LENGTH_BYTES: number = 32;
const MASTER_KEY_SALT_LENGTH_BYTES: number = 16;
const DERIVED_KEY_LENGTH_BYTES: number = 32;
const PASSWORD_SALT_PREFIX: Buffer = Buffer.from("XILENT-PBKDF2-V1\0", "utf8");
const HKDF_SALT_PREFIX: Buffer = Buffer.from("XILENT-HKDF-V1\0", "utf8");
const HKDF_INFO_PREFIX: Buffer = Buffer.from("XILENT-KEY-V1\0", "utf8");
const INFO_STRING_PATTERN: RegExp = /^[a-z0-9][a-z0-9:._-]{0,127}$/;

/** One shared XILENT-KEY-V1 interoperability vector. */
class TestVector {
    public readonly masterKeyFileHex: string;
    public readonly memorizedSecret: string;
    public readonly infoString: string;
    public readonly expectedDerivedKey: string;

    public constructor(
        masterKeyFileHex: string,
        memorizedSecret: string,
        infoString: string,
        expectedDerivedKey: string,
    ) {
        this.masterKeyFileHex = masterKeyFileHex;
        this.memorizedSecret = memorizedSecret;
        this.infoString = infoString;
        this.expectedDerivedKey = expectedDerivedKey;
    }
}

/** The JSON shape shared with the C# test project. */
type RawTestVector = {
    mkfHex: string;
    memorySecret: string;
    info: string;
    expected: string;
};

/** Read the shared JSON vectors into named values. */
function loadTestVectors(vectorPath: string): TestVector[] {
    const fileText: string = readFileSync(vectorPath, "utf8");
    const rawVectors: RawTestVector[] = JSON.parse(fileText) as RawTestVector[];
    const vectors: TestVector[] = [];

    for (const rawVector of rawVectors) {
        const vector: TestVector = new TestVector(
            rawVector.mkfHex,
            rawVector.memorySecret,
            rawVector.info,
            rawVector.expected,
        );
        vectors.push(vector);
    }

    return vectors;
}

/** Read one .mkf file and return its 64-character lowercase hexadecimal key. */
function deriveKeyFromMasterKeyFile(
    masterKeyFilePath: string,
    memorizedSecret: string,
    infoString: string,
): string {
    // An .mkf contains 32 bytes of master-key material followed by 16 bytes of
    // salt. Reading it here makes the command-line flow explicit.
    const masterKeyFileContents: Buffer = readFileSync(masterKeyFilePath);
    return deriveKeyFromMasterKeyBytes(
        masterKeyFileContents,
        memorizedSecret,
        infoString,
    );
}

/** Derive a key from the 48-byte .mkf contents and two user inputs. */
function deriveKeyFromMasterKeyBytes(
    masterKeyFileContents: Buffer,
    memorizedSecret: string,
    infoString: string,
): string {
    // Reject malformed key files before splitting them, so their layout never
    // becomes ambiguous.
    if (masterKeyFileContents.length !== MASTER_KEY_FILE_LENGTH_BYTES) {
        throw new Error(
            "The master-key file must contain exactly 48 bytes: " +
            "32 bytes of key material followed by 16 bytes of salt.",
        );
    }

    // A blank secret provides no second factor and is invalid. Whitespace is
    // significant, so it is deliberately not trimmed.
    if (memorizedSecret.length === 0) {
        throw new Error("The memorized secret must not be empty.");
    }

    // The info string is an identifier, not free-form text. Its restricted ASCII
    // form avoids encoding ambiguity and makes recovery records predictable.
    if (!INFO_STRING_PATTERN.test(infoString)) {
        throw new Error(
            "The info string must be 1-128 lowercase ASCII characters, start " +
            "with a-z or 0-9, and otherwise use only a-z, 0-9, :, ., _, or -.",
        );
    }

    // Split the fixed file layout. These slices are the two binary inputs stored
    // in the .mkf file and must be used in this order.
    const masterKeyMaterial: Buffer = masterKeyFileContents.subarray(
        0,
        MASTER_KEY_MATERIAL_LENGTH_BYTES,
    );
    const masterKeySalt: Buffer = masterKeyFileContents.subarray(
        MASTER_KEY_MATERIAL_LENGTH_BYTES,
        MASTER_KEY_FILE_LENGTH_BYTES,
    );

    // Normalize equivalent Unicode spellings before UTF-8 encodes the secret.
    const normalizedMemorizedSecret: string = memorizedSecret.normalize("NFC");
    const normalizedMemorizedSecretBytes: Buffer = Buffer.from(
        normalizedMemorizedSecret,
        "utf8",
    );

    // PBKDF2 turns the memorized secret into a 32-byte key. Prefixing the file
    // salt labels this use of the salt and separates it from the HKDF use below.
    const passwordDerivationSalt: Buffer = Buffer.concat([
        PASSWORD_SALT_PREFIX,
        masterKeySalt,
    ]);
    const memorizedSecretKey: Buffer = pbkdf2Sync(
        normalizedMemorizedSecretBytes,
        passwordDerivationSalt,
        PBKDF2_ITERATION_COUNT,
        DERIVED_KEY_LENGTH_BYTES,
        "sha256",
    );

    // HKDF receives both independent secret inputs in a fixed order: stored
    // master-key material first, then the PBKDF2 result.
    const hkdfInputKeyMaterial: Buffer = Buffer.concat([
        masterKeyMaterial,
        memorizedSecretKey,
    ]);
    const hkdfSalt: Buffer = Buffer.concat([HKDF_SALT_PREFIX, masterKeySalt]);
    const infoStringBytes: Buffer = Buffer.from(infoString, "ascii");
    const hkdfInfo: Buffer = Buffer.concat([HKDF_INFO_PREFIX, infoStringBytes]);
    const derivedKeyBytes: Buffer = hkdfSha256(
        hkdfInputKeyMaterial,
        hkdfSalt,
        hkdfInfo,
        DERIVED_KEY_LENGTH_BYTES,
    );

    // Lowercase hexadecimal is the portable output representation. Thirty-two
    // bytes therefore become 64 characters.
    return derivedKeyBytes.toString("hex");
}

/** Implement RFC 5869 HKDF with SHA-256 using explicit Extract and Expand. */
function hkdfSha256(
    inputKeyMaterial: Buffer,
    salt: Buffer,
    info: Buffer,
    outputLengthBytes: number,
): Buffer {
    // SHA-256 has a 32-byte digest, and HKDF permits at most 255 digest blocks.
    const sha256DigestLengthBytes: number = 32;
    const maximumOutputLengthBytes: number = 255 * sha256DigestLengthBytes;
    if (outputLengthBytes < 0 || outputLengthBytes > maximumOutputLengthBytes) {
        throw new Error("The requested HKDF output length is invalid.");
    }

    // Extract: use the salt as the HMAC key to produce a pseudorandom key.
    const pseudorandomKey: Buffer = hmacSha256(salt, inputKeyMaterial);

    // Expand: each block incorporates the preceding block, context-specific
    // info bytes, and a one-byte counter. This derivation needs one block.
    let output: Buffer = Buffer.alloc(0);
    let previousBlock: Buffer = Buffer.alloc(0);
    for (let blockCounter: number = 1; blockCounter <= 255; blockCounter += 1) {
        const counterByte: Buffer = Buffer.from([blockCounter]);
        const blockInput: Buffer = Buffer.concat([
            previousBlock,
            info,
            counterByte,
        ]);
        previousBlock = hmacSha256(pseudorandomKey, blockInput);
        output = Buffer.concat([output, previousBlock]);

        if (output.length >= outputLengthBytes) {
            return output.subarray(0, outputLengthBytes);
        }
    }

    // The range check above makes this unreachable; it documents the invariant.
    throw new Error("HKDF expansion exceeded its maximum block count.");
}

/** Calculate one HMAC-SHA-256 value with explicit key and message names. */
function hmacSha256(key: Buffer, message: Buffer): Buffer {
    const hmac = createHmac("sha256", key);
    hmac.update(message);
    return hmac.digest();
}

/** Compare equal-length public strings using Node's timing-safe comparison. */
function stringsMatch(actual: string, expected: string): boolean {
    const actualBytes: Buffer = Buffer.from(actual, "utf8");
    const expectedBytes: Buffer = Buffer.from(expected, "utf8");
    return actualBytes.length === expectedBytes.length &&
        timingSafeEqual(actualBytes, expectedBytes);
}

/** Create public test bytes containing 00, 01, 02, through the requested length. */
function createSequentialTestBytes(length: number): Buffer {
    const bytes: Buffer = Buffer.alloc(length);
    for (let index: number = 0; index < length; index += 1) {
        bytes[index] = index;
    }
    return bytes;
}

/** Verify the original single interoperability vector. */
function verifyPublicTestVector(): void {
    const masterKeyMaterial: Buffer = createSequentialTestBytes(32);
    const masterKeySalt: Buffer = createSequentialTestBytes(16);
    const masterKeyFileContents: Buffer = Buffer.concat([
        masterKeyMaterial,
        masterKeySalt,
    ]);
    const expectedDerivedKey: string =
        "75f76fdedf2d5384a93c94440c9f6a731ecb72ea896970811be909a7a61a3a37";
    const actualDerivedKey: string = deriveKeyFromMasterKeyBytes(
        masterKeyFileContents,
        "public test memory secret",
        "cryptotest:test:v1",
    );

    if (!stringsMatch(actualDerivedKey, expectedDerivedKey)) {
        throw new Error("The public test vector did not match.");
    }

    console.log(`PASS cryptotest:test:v1: ${actualDerivedKey}`);
}

/** Export shared JSON vectors as readable, non-secret Markdown documentation. */
function writeTestVectorsMarkdown(vectorPath: string, markdownPath: string): void {
    const vectors: TestVector[] = loadTestVectors(vectorPath);
    const lines: string[] = [
        "# XILENT-KEY-V1 Reference Test Vectors",
        "",
        "Generated from `tests/Xilent.KeyDeriver.Tests/TestVectors/derivation-vectors.json`.",
        "These are public interoperability vectors; memorized secrets are test data only.",
        "",
        "| # | Master-key bytes (hex) | Memorized secret | Info | Expected derived key |",
        "|---:|---|---|---|---|",
    ];

    for (let index: number = 0; index < vectors.length; index += 1) {
        const vector: TestVector = vectors[index];
        const vectorNumber: number = index + 1;
        lines.push(
            `| ${vectorNumber} | \`${vector.masterKeyFileHex}\` | ` +
            `\`${vector.memorizedSecret}\` | \`${vector.infoString}\` | ` +
            `\`${vector.expectedDerivedKey}\` |`,
        );
    }

    lines.push(
        "",
        "## Algorithm parameters",
        "",
        `- PBKDF2 iterations: \`${PBKDF2_ITERATION_COUNT}\``,
        `- Master-key material length: \`${MASTER_KEY_MATERIAL_LENGTH_BYTES}\` bytes`,
        `- Master-key salt length: \`${MASTER_KEY_SALT_LENGTH_BYTES}\` bytes`,
        `- Derived key length: \`${DERIVED_KEY_LENGTH_BYTES}\` bytes`,
        `- Password/PBKDF2 salt prefix: \`XILENT-PBKDF2-V1\\0\``,
        `- HKDF salt prefix: \`XILENT-HKDF-V1\\0\``,
        `- HKDF info prefix: \`XILENT-KEY-V1\\0\``,
        "",
    );

    writeFileSync(markdownPath, lines.join("\n"), "utf8");
    console.log(`Test vectors copied to ${markdownPath}`);
}

/** Verify every vector shared with the C# test project. */
function verifyTestVectors(vectorPath: string): boolean {
    const vectors: TestVector[] = loadTestVectors(vectorPath);
    console.log("=== XILENT-KEY-V1 Reference Verification ===");
    console.log("Expected derived key: listed per vector below.");
    console.log("Prefixes: pws=XILENT-PBKDF2-V1\\0, hkdf=XILENT-HKDF-V1\\0, info=XILENT-KEY-V1\\0");
    console.log(`Parameters: iterations=${PBKDF2_ITERATION_COUNT}, key length=${MASTER_KEY_MATERIAL_LENGTH_BYTES} bytes, salt length=${MASTER_KEY_SALT_LENGTH_BYTES} bytes`);
    console.log(`Context: ${vectors.length} shared C# test vectors from ${vectorPath}`);
    console.log();

    let allPassed: boolean = true;
    for (let index: number = 0; index < vectors.length; index += 1) {
        const vector: TestVector = vectors[index];
        const masterKeyFileContents: Buffer = Buffer.from(vector.masterKeyFileHex, "hex");
        const actualDerivedKey: string = deriveKeyFromMasterKeyBytes(
            masterKeyFileContents,
            vector.memorizedSecret,
            vector.infoString,
        );
        const passed: boolean = stringsMatch(actualDerivedKey, vector.expectedDerivedKey);
        if (!passed) {
            allPassed = false;
        }

        const result: string = passed ? "PASS" : "FAIL";
        console.log(`${result} vector ${index + 1} (${vector.infoString})`);
        console.log(`  expected derived key: ${vector.expectedDerivedKey}`);
        console.log(`  generated derived key: ${actualDerivedKey}`);
    }

    console.log(`\nOverall result: ${allPassed ? "PASS" : "FAIL"}`);
    return allPassed;
}

/** Display the intentionally small command-line interface. */
function printUsage(): void {
    const executableName: string = basename(process.argv[1] ?? "derive_key.ts");
    console.error("Usage:");
    console.error(`  npx tsx ${executableName} <master-key-file> <info-string>`);
    console.error(`  npx tsx ${executableName} --verify-test-vector`);
    console.error(`  npx tsx ${executableName} --verify-test-vectors <vectors.json>`);
    console.error(`  npx tsx ${executableName} --write-test-vector-markdown <vectors.json> <vectors.md>`);
}

/** Prompt for a secret without writing it to disk. */
async function readMemorizedSecret(): Promise<string> {
    // Node's standard readline prompt echoes input. This script is reference
    // documentation rather than a hardened secret-entry tool; use XVault for
    // normal use where its platform protections are appropriate.
    const terminal = createInterface({ input: stdin, output: stdout });
    const memorizedSecret: string = await terminal.question("Memorized secret: ");
    terminal.close();
    return memorizedSecret;
}

/** Parse the small CLI and either verify vectors or derive one key. */
async function main(): Promise<void> {
    const arguments_: string[] = process.argv.slice(2);

    if (arguments_.length === 1 && arguments_[0] === "--verify-test-vector") {
        verifyPublicTestVector();
        return;
    }

    if (arguments_.length === 2 && arguments_[0] === "--verify-test-vectors") {
        const vectorsPassed: boolean = verifyTestVectors(arguments_[1]);
        process.exitCode = vectorsPassed ? 0 : 1;
        return;
    }

    if (
        arguments_.length === 3 &&
        arguments_[0] === "--write-test-vector-markdown"
    ) {
        writeTestVectorsMarkdown(arguments_[1], arguments_[2]);
        return;
    }

    // Require both positional values together so a partial command cannot run.
    if (arguments_.length !== 2) {
        printUsage();
        process.exitCode = 2;
        return;
    }

    const masterKeyFilePath: string = arguments_[0];
    const infoString: string = arguments_[1];
    const memorizedSecret: string = await readMemorizedSecret();
    const derivedKey: string = deriveKeyFromMasterKeyFile(
        masterKeyFilePath,
        memorizedSecret,
        infoString,
    );
    console.log(derivedKey);
}

// Report errors consistently while retaining a non-zero process exit status.
main().catch((error: unknown) => {
    const message: string = error instanceof Error ? error.message : String(error);
    console.error(`Error: ${message}`);
    process.exitCode = 1;
});
