#!/usr/bin/env python3
"""A small, standalone reference implementation of the XILENT-KEY-V1 derivation.

This program intentionally keeps the full derivation in one readable file. It
uses only Python's standard library, so it can also serve as a recovery aid.

Usage:
    python derive_key.py path/to/master-key.mkf object:backup:v1
    python derive_key.py --verify-test-vector
    python derive_key.py --write-test-vector-markdown vectors.json vectors.md
    python derive_key.py --verify-test-vectors vectors.json
"""

# Standard-library modules provide the cryptographic primitives and command-line
# interface. No third-party package is required.
import argparse
import hashlib
import json
import hmac
import re
import secrets
import unicodedata
from getpass import getpass
from pathlib import Path


# This section defines the complete, versioned algorithm contract. Do not change
# any value here if a key must remain compatible with XILENT-KEY-V1.
PBKDF2_ITERATION_COUNT = 600_000
MASTER_KEY_FILE_LENGTH_BYTES = 48
MASTER_KEY_MATERIAL_LENGTH_BYTES = 32
MASTER_KEY_SALT_LENGTH_BYTES = 16
DERIVED_KEY_LENGTH_BYTES = 32
PASSWORD_SALT_PREFIX = b"XILENT-PBKDF2-V1\0"
HKDF_SALT_PREFIX = b"XILENT-HKDF-V1\0"
HKDF_INFO_PREFIX = b"XILENT-KEY-V1\0"
INFO_STRING_PATTERN = re.compile(r"^[a-z0-9][a-z0-9:._-]{0,127}$", re.ASCII)


def derive_key_from_master_key_file(
    master_key_file_path: Path,
    memorized_secret: str,
    info_string: str,
) -> str:
    """Read one .mkf file and return its 64-character lowercase hex key."""

    # An .mkf contains exactly 32 bytes of master-key material followed by 16
    # bytes of salt. Reading it here makes the command-line flow explicit.
    master_key_file_contents = master_key_file_path.read_bytes()
    return derive_key_from_master_key_bytes(
        master_key_file_contents,
        memorized_secret,
        info_string,
    )


def derive_key_from_master_key_bytes(
    master_key_file_contents: bytes,
    memorized_secret: str,
    info_string: str,
) -> str:
    """Derive a key from the 48-byte .mkf contents and the two user inputs."""

    # Reject malformed key files before splitting them, so their layout never
    # becomes ambiguous.
    if len(master_key_file_contents) != MASTER_KEY_FILE_LENGTH_BYTES:
        raise ValueError(
            "The master-key file must contain exactly 48 bytes: "
            "32 bytes of key material followed by 16 bytes of salt."
        )

    # A blank secret provides no second factor and is invalid. Whitespace is
    # significant, so it is deliberately not stripped.
    if not memorized_secret:
        raise ValueError("The memorized secret must not be empty.")

    # The info string is an identifier, not free-form text. Its restricted ASCII
    # form avoids encoding ambiguity and makes recovery records predictable.
    if not INFO_STRING_PATTERN.fullmatch(info_string):
        raise ValueError(
            "The info string must be 1-128 lowercase ASCII characters, start "
            "with a-z or 0-9, and otherwise use only a-z, 0-9, :, ., _, or -."
        )

    # Split the fixed file layout. These slices are the two binary inputs stored
    # in the .mkf file and must be used in this order.
    master_key_material = master_key_file_contents[:MASTER_KEY_MATERIAL_LENGTH_BYTES]
    master_key_salt = master_key_file_contents[MASTER_KEY_MATERIAL_LENGTH_BYTES:]

    # Normalize equivalent Unicode spellings (for example, café entered as one
    # code point or as e plus an accent) before UTF-8 encodes the secret.
    normalized_memorized_secret_bytes = unicodedata.normalize(
        "NFC", memorized_secret
    ).encode("utf-8")

    # PBKDF2 turns the memorized secret into a 32-byte key. Prefixing the file
    # salt labels this use of the salt and separates it from the HKDF use below.
    password_derivation_salt = PASSWORD_SALT_PREFIX + master_key_salt
    memorized_secret_key = hashlib.pbkdf2_hmac(
        "sha256",
        normalized_memorized_secret_bytes,
        password_derivation_salt,
        PBKDF2_ITERATION_COUNT,
        dklen=DERIVED_KEY_LENGTH_BYTES,
    )

    # HKDF receives both independent secret inputs in a fixed order: the stored
    # 32-byte master-key material first, then the PBKDF2 result.
    hkdf_input_key_material = master_key_material + memorized_secret_key
    hkdf_salt = HKDF_SALT_PREFIX + master_key_salt
    hkdf_info = HKDF_INFO_PREFIX + info_string.encode("ascii")
    derived_key_bytes = hkdf_sha256(
        hkdf_input_key_material,
        hkdf_salt,
        hkdf_info,
        DERIVED_KEY_LENGTH_BYTES,
    )

    # Lowercase hexadecimal is the portable output representation and is what
    # the application returns. Thirty-two bytes therefore become 64 characters.
    return derived_key_bytes.hex()


def hkdf_sha256(
    input_key_material: bytes,
    salt: bytes,
    info: bytes,
    output_length_bytes: int,
) -> bytes:
    """Implement RFC 5869 HKDF with SHA-256 using explicit Extract and Expand."""

    # SHA-256 has a 32-byte digest, and HKDF permits at most 255 digest blocks.
    sha256_digest_length_bytes = hashlib.sha256().digest_size
    if not 0 <= output_length_bytes <= 255 * sha256_digest_length_bytes:
        raise ValueError("The requested HKDF output length is invalid.")

    # Extract: use the salt as the HMAC key to convert input material into a
    # fixed-length pseudorandom key (PRK).
    pseudorandom_key = hmac.digest(salt, input_key_material, "sha256")

    # Expand: each block incorporates the preceding block, the context-specific
    # info bytes, and a one-byte counter. This derivation needs only one block.
    output = bytearray()
    previous_block = b""
    for block_counter in range(1, 256):
        previous_block = hmac.digest(
            pseudorandom_key,
            previous_block + info + bytes([block_counter]),
            "sha256",
        )
        output.extend(previous_block)
        if len(output) >= output_length_bytes:
            return bytes(output[:output_length_bytes])

    # The range check above makes this unreachable; it documents the invariant.
    raise AssertionError("HKDF expansion exceeded its maximum block count.")


def verify_public_test_vector() -> None:
    """Verify the original single interoperability vector."""

    public_test_master_key_file_contents = bytes(range(32)) + bytes(range(16))
    expected_derived_key = (
        "75f76fdedf2d5384a93c94440c9f6a731ecb72ea896970811be909a7a61a3a37"
    )
    actual_derived_key = derive_key_from_master_key_bytes(
        public_test_master_key_file_contents,
        "public test memory secret",
        "cryptotest:test:v1",
    )
    if not secrets.compare_digest(actual_derived_key, expected_derived_key):
        raise AssertionError("The public test vector did not match.")
    print(f"PASS cryptotest:test:v1: {actual_derived_key}")


def write_test_vectors_markdown(vector_path: Path, markdown_path: Path) -> None:
    """Export the shared JSON vectors as readable, non-secret documentation."""

    vectors = json.loads(vector_path.read_text(encoding="utf-8"))
    lines = [
        "# XILENT-KEY-V1 Reference Test Vectors",
        "",
        "Generated from `tests/Xilent.KeyDeriver.Tests/TestVectors/derivation-vectors.json`.",
        "These are public interoperability vectors; the memorized secrets are test data only.",
        "",
        "| # | Master-key bytes (hex) | Memorized secret | Info | Expected derived key |",
        "|---:|---|---|---|---|",
    ]
    for index, vector in enumerate(vectors, start=1):
        lines.append(
            f"| {index} | `{vector['mkfHex']}` | "
            f"`{vector['memorySecret']}` | `{vector['info']}` | "
            f"`{vector['expected']}` |"
        )
    lines.extend([
        "",
        "## Algorithm parameters",
        "",
        f"- PBKDF2 iterations: `{PBKDF2_ITERATION_COUNT}`",
        f"- Master-key material length: `{MASTER_KEY_MATERIAL_LENGTH_BYTES}` bytes",
        f"- Master-key salt length: `{MASTER_KEY_SALT_LENGTH_BYTES}` bytes",
        f"- Derived key length: `{DERIVED_KEY_LENGTH_BYTES}` bytes",
        f"- Password/PBKDF2 salt prefix: `{PASSWORD_SALT_PREFIX!r}`",
        f"- HKDF salt prefix: `{HKDF_SALT_PREFIX!r}`",
        f"- HKDF info prefix: `{HKDF_INFO_PREFIX!r}`",
        "",
    ])
    markdown_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"Test vectors copied to {markdown_path}")


def verify_test_vectors(vector_path: Path) -> bool:
    """Verify every vector shared with the C# test project."""

    vectors = json.loads(vector_path.read_text(encoding="utf-8"))
    print("=== XILENT-KEY-V1 Reference Verification ===")
    print("Expected derived key: listed per vector below.")
    print(f"Prefixes: pws={PASSWORD_SALT_PREFIX!r}, hkdf={HKDF_SALT_PREFIX!r}, info={HKDF_INFO_PREFIX!r}")
    print(f"Parameters: iterations={PBKDF2_ITERATION_COUNT}, key length={MASTER_KEY_MATERIAL_LENGTH_BYTES} bytes, salt length={MASTER_KEY_SALT_LENGTH_BYTES} bytes")
    print(f"Context: {len(vectors)} shared C# test vectors from {vector_path}")
    print()
    all_passed = True
    for index, vector in enumerate(vectors, start=1):
        actual = derive_key_from_master_key_bytes(
            bytes.fromhex(vector["mkfHex"]), vector["memorySecret"], vector["info"]
        )
        passed = secrets.compare_digest(actual, vector["expected"])
        all_passed = all_passed and passed
        result = "PASS" if passed else "FAIL"
        print(f"{result} vector {index} ({vector['info']})")
        print(f"  expected derived key: {vector['expected']}")
        print(f"  generated derived key: {actual}")
    print(f"\nOverall result: {'PASS' if all_passed else 'FAIL'}")
    return all_passed


def main() -> None:
    """Parse the intentionally small command-line interface and derive a key."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("master_key_file", type=Path, nargs="?")
    parser.add_argument("info_string", nargs="?")
    parser.add_argument("--verify-test-vector", action="store_true")
    parser.add_argument("--verify-test-vectors", type=Path)
    parser.add_argument("--write-test-vector-markdown", nargs=2, metavar=("JSON", "MARKDOWN"), type=Path)
    arguments = parser.parse_args()

    if arguments.write_test_vector_markdown:
        write_test_vectors_markdown(*arguments.write_test_vector_markdown)
        return

    # The test-vector modes need no key file and never process user secrets.
    if arguments.verify_test_vectors is not None:
        raise SystemExit(0 if verify_test_vectors(arguments.verify_test_vectors) else 1)
    if arguments.verify_test_vector:
        verify_public_test_vector()
        return

    # Require both positional values together so a partial command cannot run.
    if arguments.master_key_file is None or arguments.info_string is None:
        parser.error("master_key_file and info_string are required unless verifying.")

    # getpass prevents the secret from being echoed. The secret is never written
    # to disk by this program, although Python cannot guarantee memory erasure.
    memorized_secret = getpass("Memorized secret: ")
    print(
        derive_key_from_master_key_file(
            arguments.master_key_file,
            memorized_secret,
            arguments.info_string,
        )
    )


if __name__ == "__main__":
    main()
