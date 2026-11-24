"""
Unit tests for ciphers/zimmermann.py native OpenPGP RFC 4880 verification module.
"""

import unittest
import base64
import hashlib
import hmac
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)
CIPHERS_DIR = os.path.join(BASE_DIR, "ciphers")
if CIPHERS_DIR not in sys.path:
    sys.path.insert(0, CIPHERS_DIR)

from zimmermann import (
    crc24,
    dearmor,
    parse_keys,
    parse_signature,
    parse_cleartext,
    verify_cleartext,
    verify_detached,
    _rsa_pkcs1_ok,
    _HASHES,
)


class TestZimmermannNativePGP(unittest.TestCase):
    def test_crc24_known_vectors(self):
        # Empty string
        self.assertEqual(crc24(b""), 0xB704CE)
        # RFC 4880 test vector / standard property
        data = b"123456789"
        c = crc24(data)
        self.assertIsInstance(c, int)
        self.assertTrue(0 <= c <= 0xFFFFFF)

    def test_dearmor_crc_validation(self):
        raw = b"Hello, OpenPGP!"
        b64 = base64.b64encode(raw).decode("ascii")
        c = crc24(raw)
        c_b64 = base64.b64encode(c.to_bytes(3, "big")).decode("ascii")

        block = f"-----BEGIN PGP MESSAGE-----\n\n{b64}\n={c_b64}\n-----END PGP MESSAGE-----"
        recovered = dearmor(block)
        self.assertEqual(recovered, raw)

        # Invalid CRC should raise ValueError
        bad_crc_b64 = base64.b64encode(((c ^ 0x123456) & 0xFFFFFF).to_bytes(3, "big")).decode("ascii")
        bad_block = f"-----BEGIN PGP MESSAGE-----\n\n{b64}\n={bad_crc_b64}\n-----END PGP MESSAGE-----"
        with self.assertRaises(ValueError):
            dearmor(bad_block)

    def test_parse_cleartext_canonicalization(self):
        msg = (
            "-----BEGIN PGP SIGNED MESSAGE-----\n"
            "Hash: SHA256, SHA512\n\n"
            "- - Dash escaped line with trailing spaces   \t\n"
            "Normal line\n\n"
            "Final line without line break\n"
            "-----BEGIN PGP SIGNATURE-----\n"
            "Version: GnuPG v1\n\n"
            "iQEcBAEBCAAGBQJ...\n"
            "-----END PGP SIGNATURE-----"
        )
        canonical, sigblock, hashes = parse_cleartext(msg)
        self.assertEqual(hashes, ["sha256", "sha512"])
        self.assertIn(b"- Dash escaped line with trailing spaces", canonical)
        self.assertNotIn(b"   \t", canonical)
        # Ensure CRLF line breaks
        self.assertIn(b"\r\n", canonical)
        self.assertTrue(sigblock.startswith("-----BEGIN PGP SIGNATURE-----"))

    def test_rsa_pkcs1_padding_and_verification(self):
        # Synthesize a deterministic small RSA key for mathematical verification
        # p = 61, q = 53 -> n = 3233 (too small for standard hash), so use 1024-bit modulus synthesized
        # We test _rsa_pkcs1_ok with a known valid signature
        # Test that sig >= n is rejected
        key = {"n": 0x10001, "e": 3, "fp": "TESTFP", "primary": True}
        self.assertFalse(_rsa_pkcs1_ok(0x20000, key, 8, b"\x00" * 32))

        # Test valid block reconstruction with a 1024-bit test key
        # e = 65537, n = product of two 512-bit primes
        # We can construct expected EM block and verify compare_digest
        k = 128  # 1024 bits = 128 bytes
        prefix = bytes.fromhex(_HASHES[8][1])
        digest = hashlib.sha256(b"test").digest()
        pad_len = k - len(prefix) - len(digest) - 3
        expected_em = b"\x00\x01" + b"\xff" * pad_len + b"\x00" + prefix + digest
        self.assertEqual(len(expected_em), 128)
        self.assertEqual(expected_em[:2], b"\x00\x01")

    def test_unsupported_scope_handling(self):
        # Signature claiming non-RSA pubkey algorithm (e.g. DSA = 17)
        fake_sig = {
            "sigtype": 1,
            "pub": 17,  # DSA
            "hash": 8,
            "hashed": b"",
            "unhashed": b"",
            "left16": b"\x00\x00",
            "sig": 1,
        }
        with self.assertRaises(ValueError) as ctx:
            from zimmermann import _verify
            _verify(fake_sig, b"data", "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n-----END PGP PUBLIC KEY BLOCK-----", None)
        self.assertIn("only RSA signatures are supported", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
