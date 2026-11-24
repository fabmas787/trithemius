"""
Unit test suite for ciphers/interrupter.py and dynamic keystream mutation.
Verifies canonical 29-rune alphabet integrity, mathematical key shifts (DIVINITY, FIRFUMFERENFE),
bidirectional encode/decode consistency across all 5 interrupt modes, and historical Liber Primus benchmarks.
"""

import unittest
import os
import sys

# Ensure repository root is on sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from ciphers.agrippa import (
    RUNE_TABLE, INDEX_BY_RUNE, latin_to_rune, decode_runes, index_to_rune
)
from ciphers.interrupter import (
    InterrupterConfig, InterruptMode,
    rune_vigenere_decode_dynamic, rune_vigenere_encode_dynamic,
    canonical_key_shifts, divinity_shifts, firfumferenfe_shifts,
    validate_canonical_alphabet
)
from ciphers.kasiski import rune_vigenere_decode, rune_vigenere_encode


class TestDynamicInterrupterEngine(unittest.TestCase):
    """Test suite covering the dynamic interrupter engine and errata corrections."""

    def test_canonical_alphabet_integrity(self):
        """Verify the 29-rune Futhorc table is uncorrupted and contains Y, IA, EA."""
        res = validate_canonical_alphabet()
        self.assertTrue(res["valid"])
        self.assertEqual(res["total_runes"], 29)
        self.assertEqual(res["primes_range"], (2, 109))
        self.assertTrue(res["has_terminal_runes"])

        # Check exact terminal runes
        self.assertEqual(INDEX_BY_RUNE["ᚣ"], 26)  # Y
        self.assertEqual(INDEX_BY_RUNE["ᛡ"], 27)  # IA / IO
        self.assertEqual(INDEX_BY_RUNE["ᛠ"], 28)  # EA

        # Confirm no duplicate runes exist
        all_runes = [r[0] for r in RUNE_TABLE]
        self.assertEqual(len(all_runes), len(set(all_runes)))

    def test_divinity_canonical_shifts(self):
        """Verify canonical DIVINITY shifts and additive inverse decryption shifts."""
        enc, dec = divinity_shifts()
        # D=23, I=10, V=1, I=10, N=9, I=10, T=16, Y=26
        self.assertEqual(enc, [23, 10, 1, 10, 9, 10, 16, 26])
        # Inverses modulo 29: (29 - enc) % 29
        self.assertEqual(dec, [6, 19, 28, 19, 20, 19, 13, 3])

    def test_firfumferenfe_canonical_shifts(self):
        """Verify canonical FIRFUMFERENFE shifts and additive inverse decryption shifts."""
        enc, dec = firfumferenfe_shifts()
        # F=0, I=10, R=4, F=0, U=1, M=19, F=0, E=18, R=4, E=18, N=9, F=0, E=18
        self.assertEqual(enc, [0, 10, 4, 0, 1, 19, 0, 18, 4, 18, 9, 0, 18])
        self.assertEqual(dec, [0, 19, 25, 0, 28, 10, 0, 11, 25, 11, 20, 0, 11])

    def test_bidirectional_standard_vigenere(self):
        """Verify standard Vigenère bidirectional encode/decode without interrupts."""
        pt = latin_to_rune("WELCOME PILGRIMS TO THE SACRED PATH")
        key = "DIVINITY"
        ct = rune_vigenere_encode_dynamic(pt, key)
        recovered = rune_vigenere_decode_dynamic(ct, key)
        self.assertEqual(decode_runes(recovered), decode_runes(pt))

    def test_fehu_skip_pause_key(self):
        """Verify Mode 1: Fehu skip pass-through with key pointer pause."""
        pt = latin_to_rune("FIND THE DIVINITY WITHIN FOR ALL IS SACRED")
        cfg = InterrupterConfig.from_rune_positions(pt, {"ᚠ"}, pause_key=True, pass_through=True)
        key = "DIVINITY"

        ct = rune_vigenere_encode_dynamic(pt, key, config=cfg)
        recovered = rune_vigenere_decode_dynamic(ct, key, config=cfg)
        self.assertEqual(decode_runes(recovered), decode_runes(pt))

        # Ensure all Fehu characters are preserved as Fehu
        pt_fehu_count = pt.count("ᚠ")
        ct_fehu_count = ct.count("ᚠ")
        self.assertGreaterEqual(ct_fehu_count, pt_fehu_count)

    def test_fehu_skip_advance_key(self):
        """Verify Mode 2: Fehu skip pass-through with key pointer advance (03.jpg pattern)."""
        pt = latin_to_rune("FIND THE DIVINITY WITHIN FOR ALL IS SACRED")
        cfg = InterrupterConfig.from_rune_positions(pt, {"ᚠ"}, pause_key=False, pass_through=True)
        key = "DIVINITY"

        ct = rune_vigenere_encode_dynamic(pt, key, config=cfg)
        recovered = rune_vigenere_decode_dynamic(ct, key, config=cfg)
        self.assertEqual(decode_runes(recovered), decode_runes(pt))

    def test_key_pointer_reset_mode(self):
        """Verify Mode 3: Key pointer resets to index 0 on interrupt trigger."""
        pt = latin_to_rune("A WARNING TO PILGRIMS WHO SEEK KNOWLEDGE")
        cfg = InterrupterConfig(interrupt_positions={4, 12, 20}, reset_on_interrupt=True)
        key = "DIVINITY"

        ct = rune_vigenere_encode_dynamic(pt, key, config=cfg)
        recovered = rune_vigenere_decode_dynamic(ct, key, config=cfg)
        self.assertEqual(decode_runes(recovered), decode_runes(pt))

    def test_positional_mask_mode(self):
        """Verify Mode 4: Positional index masks trigger dynamic actions."""
        cfg = InterrupterConfig(
            interrupt_positions={3, 8, 14},
            pause_on_interrupt=True,
            pass_through=False
        )
        pt = latin_to_rune("ALL THINGS SHOULD BE ENCRYPTED")
        key = "DIVINITY"

        ct = rune_vigenere_encode_dynamic(pt, key, config=cfg)
        recovered = rune_vigenere_decode_dynamic(ct, key, config=cfg)
        self.assertEqual(decode_runes(recovered), decode_runes(pt))

    def test_modular_offset_step_mode(self):
        """Verify Mode 5: Modular block offset step applied upon positional interrupt."""
        cfg = InterrupterConfig(
            interrupt_positions={5, 12},
            offset_step=7,
            pause_on_interrupt=False,
            pass_through=False
        )
        pt = latin_to_rune("THE TOTIENT FUNCTION IS SACRED")
        key = "DIVINITY"

        ct = rune_vigenere_encode_dynamic(pt, key, config=cfg)
        recovered = rune_vigenere_decode_dynamic(ct, key, config=cfg)
        self.assertEqual(decode_runes(recovered), decode_runes(pt))

    def test_kasiski_backward_compatibility(self):
        """Verify kasiski.py functions support both legacy and interrupter calls seamlessly."""
        pt = latin_to_rune("TESTING BACKWARD COMPATIBILITY")
        key = "DIVINITY"

        # Legacy periodic calls without interrupter config
        ct_legacy = rune_vigenere_encode(pt, key)
        rec_legacy = rune_vigenere_decode(ct_legacy, key)
        self.assertEqual(decode_runes(rec_legacy), decode_runes(pt))

        # Enhanced calls via interrupter_config
        cfg = InterrupterConfig(interrupt_positions={2, 8}, pause_on_interrupt=True)
        ct_dynamic = rune_vigenere_encode(pt, key, interrupter_config=cfg)
        rec_dynamic = rune_vigenere_decode(ct_dynamic, key, interrupter_config=cfg)
        self.assertEqual(decode_runes(rec_dynamic), decode_runes(pt))

        # Enhanced calls via keyword arguments
        ct_kwargs = rune_vigenere_encode(pt, key, interrupt_positions={2, 8}, pause_on_interrupt=True)
        rec_kwargs = rune_vigenere_decode(ct_kwargs, key, interrupt_positions={2, 8}, pause_on_interrupt=True)
        self.assertEqual(decode_runes(rec_kwargs), decode_runes(pt))

    def test_liber_primus_historical_welcome(self):
        """Benchmark: Page 03-04 header 'ᚢᛠᛝᛋᛇᚠᚳ' decodes to 'WELCOME' using DIVINITY."""
        ct_header = "ᚢᛠᛝᛋᛇᚠᚳ"
        key = "DIVINITY"
        dec = rune_vigenere_decode(ct_header, key)
        latin = decode_runes(dec)
        self.assertEqual(latin, "WELCOME")


if __name__ == "__main__":
    unittest.main()
