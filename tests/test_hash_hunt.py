"""
Unit tests for ciphers/hash_hunt.py local hash hunting normalization lattice.
"""

import unittest
import hashlib
import tempfile
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from ciphers.hash_hunt import (
    generate_normalization_lattice,
    check_candidate_bytes,
    scan_local_text,
    scan_local_file,
)


class TestHashHunt(unittest.TestCase):
    def test_normalization_lattice_generation(self):
        sample = "Line 1\r\nLine 2 \n"
        lattice = generate_normalization_lattice(sample)
        self.assertGreater(len(lattice), 5)
        labels = [lbl for lbl, _ in lattice]
        self.assertTrue(any("utf-8" in l for l in labels))
        self.assertTrue(any("utf-16le" in l for l in labels))

    def test_check_candidate_bytes_match(self):
        data = b"The sacred primes and totients"
        target_sha512 = hashlib.sha512(data).hexdigest()
        match = check_candidate_bytes(data, target_hex=target_sha512)
        self.assertIsNotNone(match)
        self.assertEqual(match[0], "sha512")
        self.assertEqual(match[1], target_sha512)

    def test_scan_local_text_detects_normalized_variant(self):
        base_text = "Welcome Pilgrims"
        # Compute hash of LF-normalized UTF-8 version
        target_hash = hashlib.sha3_512(base_text.encode("utf-8")).hexdigest()

        # Input has CRLF and trailing spaces
        input_text = "   " + base_text + "\r\n\r\n"
        res = scan_local_text(input_text, target_hex=target_hash)
        self.assertIsNotNone(res)
        self.assertTrue(res["matched"])
        self.assertEqual(res["algorithm"], "sha3_512")

    def test_scan_local_file(self):
        temp_dir = tempfile.TemporaryDirectory()
        try:
            path = os.path.join(temp_dir.name, "candidate.txt")
            payload = "A test candidate string\n"
            target_hash = hashlib.blake2b(payload.encode("utf-8")).hexdigest()
            with open(path, "w", encoding="utf-8") as f:
                f.write(payload)

            res = scan_local_file(path, target_hex=target_hash)
            self.assertTrue(res["matched"])
            self.assertEqual(res["algorithm"], "blake2b")
        finally:
            temp_dir.cleanup()


if __name__ == "__main__":
    unittest.main()
