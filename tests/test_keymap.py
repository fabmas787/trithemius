"""
Unit tests for ciphers/keymap.py canonical byte-to-Z29 mapping pipeline.
"""

import unittest
import random
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from ciphers.keymap import (
    REJECT_LIMIT,
    map_mod,
    map_reject,
    map_base29,
    screen,
    screen_byte_source,
)


class TestKeyMap(unittest.TestCase):
    def test_rejection_limit_constant(self):
        self.assertEqual(REJECT_LIMIT, 232)
        self.assertEqual(REJECT_LIMIT % 29, 0)

    def test_mapping_functions(self):
        # Bytes [0, 28, 29, 231, 232, 255]
        test_bytes = bytes([0, 28, 29, 231, 232, 255])
        mod_mapped = map_mod(test_bytes)
        self.assertEqual(mod_mapped, [0, 28, 0, 231 % 29, 232 % 29, 255 % 29])

        # map_reject should drop 232 and 255
        reject_mapped = map_reject(test_bytes)
        self.assertEqual(len(reject_mapped), 4)
        self.assertEqual(reject_mapped, [0, 28, 0, 231 % 29])

        # map_base29 of single byte 28
        self.assertEqual(map_base29(bytes([28])), [28])
        # map_base29 of 29 (1 * 29 + 0)
        self.assertEqual(map_base29(bytes([29])), [1, 0])

    def test_recovery_of_planted_key(self):
        rng = random.Random(42)
        # Generate English-like plaintext (skewed IoC)
        plain = ([0] * 50 + [1] * 30 + [2] * 20 + list(range(3, 29))) * 5  # length ~630

        # Create byte stream with bytes spanning 0..255 (so rejection sampling drops bytes >= 232)
        key_bytes = bytes([rng.randrange(256) for _ in range(len(plain) * 2)])
        key_z29 = map_reject(key_bytes)[:len(plain)]

        # Encrypt: c = (p + k) mod 29
        cipher = [(p + k) % 29 for p, k in zip(plain, key_z29)]

        # Screening with the exact source bytes must identify reject232 as the top score
        res = screen_byte_source(cipher, key_bytes)
        self.assertEqual(res["best_mapping"], "reject232")
        self.assertEqual(res["best_config"], ("raw", 1))
        self.assertGreater(res["best_score"], 1.5)


if __name__ == "__main__":
    unittest.main()
