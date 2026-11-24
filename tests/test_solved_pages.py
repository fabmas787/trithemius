"""
Tests for Liber Primus Canonical Solved Pages & Cipher Verification Suite.
Verifies exact reproduction of all 6 documented cipher methods across all 9 canonical solved pages:
1. Atbash in F_29 (Page 00 'A warning')
2. Atbash + Caesar shift (+3) in F_29 (Koan 1, Chunks 4-7)
3. Modulo-29 Vigenère key 'DIVINITY' with cleartext F-skips (Welcome, Chunks 1-2)
4. Modulo-29 Vigenère key 'FIRFUMFERENFE' with cleartext F-skips (Koan 2, Chunks 12-13)
5. Prime Totient Stream Cipher in F_29 (Page 71 / 56.jpg 'An end')
6. Direct translation / transliteration (Some wisdom, Loss of divinity, An instruction, Parable)
"""

import io
import os
import sys
import unittest
from unittest.mock import patch

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)
for sub in ("ciphers", "scripts"):
    subpath = os.path.join(BASE_DIR, sub)
    if subpath not in sys.path:
        sys.path.insert(0, subpath)

from ciphers.agrippa import (
    INDEX_BY_RUNE,
    decode_runes,
    direct_translation,
    index_to_rune,
    latin_to_rune,
    rune_atbash,
    rune_atbash_shift,
)
from ciphers.interrupter import (
    KOAN2_F_SKIP_POSITIONS,
    WELCOME_F_SKIP_POSITIONS,
    rune_vigenere_decode_f_skip,
    rune_vigenere_encode_f_skip,
    verify_f_skip_alignment,
)
from ciphers.kasiski import (
    generate_prime_totients,
    prime_totient_stream_decode,
    prime_totient_stream_encode,
    rune_vigenere_decode,
    rune_vigenere_encode,
)
from ciphers.solved_pages import (
    SOLVED_PAGES_REGISTRY,
    CanonicalSolvedPage,
    _normalize_latin_for_comparison,
    load_solved_page_transcript,
    resolve_solved_page,
    solve_page,
    verify_all_solved_pages,
)
from trithemius import TerminalWorkstation, main


class TestCanonicalSolvedPagesVerification(unittest.TestCase):
    """Test the complete verification suite and registry of canonical solved pages."""

    def test_verify_all_nine_solved_pages(self):
        """All 9 canonical pages must be 100% verified with zero failures."""
        report = verify_all_solved_pages()
        self.assertEqual(report["total"], 9)
        self.assertEqual(report["verified"], 9)
        self.assertEqual(report["failed"], 0)
        self.assertTrue(report["all_passed"])

        for pid, page_res in report["results"].items():
            self.assertTrue(page_res["verified"], f"Page '{pid}' failed verification.")
            self.assertEqual(
                len(page_res["missing_fragments"]),
                0,
                f"Page '{pid}' has missing fragments: {page_res['missing_fragments']}",
            )
            self.assertGreater(len(page_res["matched_fragments"]), 0)

    def test_solve_page_each_individual_page(self):
        """Each canonical solved page must be individually solvable and verified."""
        for page in SOLVED_PAGES_REGISTRY:
            res = solve_page(page.id)
            self.assertTrue(res["verified"], f"Page '{page.id}' individual solve failed.")
            self.assertEqual(res["id"], page.id)
            self.assertIn(page.title, res["title"])
            self.assertGreater(res["rune_count"], 0)
            self.assertTrue(len(res["plaintext_latin"]) > 0)
            self.assertEqual(res["missing_fragments"], [])

    def test_resolve_solved_page_by_various_identifiers(self):
        """Pages should be resolvable by id, title, chunk, image, or page number."""
        # By ID
        p0 = resolve_solved_page("page_00")
        self.assertIsNotNone(p0)
        self.assertEqual(p0.id, "page_00")

        # By chunk number (int and str)
        p_chunk0 = resolve_solved_page(0)
        self.assertEqual(p_chunk0.id, "page_00")
        p_chunk71 = resolve_solved_page("71")
        self.assertEqual(p_chunk71.id, "an_end")

        # By common title
        p_welc = resolve_solved_page("welcome")
        self.assertEqual(p_welc.id, "welcome")
        p_koan1 = resolve_solved_page("koan 1")
        self.assertEqual(p_koan1.id, "koan_1")

        # By image reference
        p_img56 = resolve_solved_page("56.jpg")
        self.assertEqual(p_img56.id, "an_end")

    def test_invalid_page_identifier_raises(self):
        """Unknown page identifier must raise ValueError."""
        with self.assertRaises(ValueError):
            solve_page("page_9999_nonexistent")


class TestMethod1AtbashF29(unittest.TestCase):
    """Method 1: Atbash in F_29: decimal[i] = (28 - decimal[i]) % 29."""

    def test_atbash_f29_involution(self):
        """Atbash in F_29 is an involution (applying twice yields identity)."""
        runes = "ᚠᚢᚦᚩᚱᚳᚷᚹᚻᚾᛁᛄᛇᛈᛉᛋᛏᛒᛖᛗᛚᛝᛟᛞᚪᚫᚣᛡᛠ"
        reflected = rune_atbash(runes)
        self.assertNotEqual(reflected, runes)
        double_reflected = rune_atbash(reflected)
        self.assertEqual(double_reflected, runes)

    def test_atbash_f29_boundary_runes(self):
        """Check exact boundary mappings in F_29."""
        # Fehu (0) <-> EA (28)
        self.assertEqual(rune_atbash("ᚠ"), "ᛠ")
        self.assertEqual(rune_atbash("ᛠ"), "ᚠ")
        # Ur (1) <-> IA (27)
        self.assertEqual(rune_atbash("ᚢ"), "ᛡ")
        self.assertEqual(rune_atbash("ᛡ"), "ᚢ")
        # Thorn (2) <-> Y (26)
        self.assertEqual(rune_atbash("ᚦ"), "ᚣ")
        self.assertEqual(rune_atbash("ᚣ"), "ᚦ")

    def test_page_00_a_warning_reproduction(self):
        """Page 00 'A warning' decrypted with Atbash matches authentic canonical text."""
        res = solve_page("page_00")
        norm = _normalize_latin_for_comparison(res["plaintext_latin"])
        self.assertIn(_normalize_latin_for_comparison("A WARNING"), norm)
        self.assertIn(_normalize_latin_for_comparison("BELIEVE NOTHING FROM THIS BOOK"), norm)
        self.assertIn(_normalize_latin_for_comparison("EXCEPT WHAT YOU KNOW TO BE TRUE"), norm)
        self.assertIn(_normalize_latin_for_comparison("TEST THE KNOWLEDGE"), norm)
        self.assertIn(_normalize_latin_for_comparison("FIND YOUR TRUTH"), norm)
        self.assertIn(_normalize_latin_for_comparison("EXPERIENCE YOUR DEATH"), norm)
        self.assertIn(_normalize_latin_for_comparison("DO NOT EDIT OR CHANGE THIS BOOK"), norm)
        self.assertIn(_normalize_latin_for_comparison("FOR ALL IS SACRED"), norm)


class TestMethod2AtbashCaesarShift(unittest.TestCase):
    """Method 2: Atbash followed by Caesar shift of +3 in F_29 (Koan 1)."""

    def test_atbash_shift_involution(self):
        """In F_29, ((28 - (28 - x + 3)) + 3) = x mod 29 (self-inverse)."""
        runes = "ᚪ᛫ᚳᚩᚪᚾ᛬ᚪ᛫ᛗᚪᚾ᛫ᛞᛖᚳᛁᛞᛖᛞ"
        enc = rune_atbash_shift(runes, shift=3)
        self.assertNotEqual(enc, runes)
        dec = rune_atbash_shift(enc, shift=3)
        self.assertEqual(dec, runes)

    def test_shift_zero_matches_standard_atbash(self):
        """Shift 0 should match standard Atbash."""
        runes = "ᚹᛖᛚᚳᚩᛗᛖ᛫ᛈᛁᛚᚷᚱᛁᛗᛋ"
        self.assertEqual(rune_atbash_shift(runes, shift=0), rune_atbash(runes))

    def test_koan_1_reproduction(self):
        """Koan 1 chunks 4-7 decrypted with Atbash + 3 reproduce authentic text."""
        res = solve_page("koan_1")
        norm = _normalize_latin_for_comparison(res["plaintext_latin"])
        self.assertIn(_normalize_latin_for_comparison("A KOAN"), norm)
        self.assertIn(_normalize_latin_for_comparison("A MAN DECIDED TO GO AND STUDY WITH A MASTER"), norm)
        self.assertIn(_normalize_latin_for_comparison("WHO ARE YOU WHO WISHES TO STUDY HERE ASKED THE MASTER"), norm)
        self.assertIn(_normalize_latin_for_comparison("I AM A CONSCIAUSNESS INHABITING AN ARBITRARY BODY"), norm)
        self.assertIn(_normalize_latin_for_comparison("DO FOUR UNREASONABLE THINGS EACH DAY"), norm)


class TestMethod3VigenereDivinityFSkip(unittest.TestCase):
    """Method 3: Modulo-29 Vigenère key 'DIVINITY' with cleartext F-skips (Welcome)."""

    def test_welcome_f_skip_alignment(self):
        """Verify the 11 canonical skip positions align with cleartext Fehu."""
        raw_runes = load_solved_page_transcript(resolve_solved_page("welcome"))
        dec_runes = rune_vigenere_decode_f_skip(raw_runes, "DIVINITY", skip_indices=WELCOME_F_SKIP_POSITIONS)
        self.assertTrue(verify_f_skip_alignment(dec_runes, WELCOME_F_SKIP_POSITIONS))

    def test_welcome_decode_reproduction(self):
        """Welcome decrypted with DIVINITY and F-skips reproduces authentic text."""
        res = solve_page("welcome")
        norm = _normalize_latin_for_comparison(res["plaintext_latin"])
        self.assertIn(_normalize_latin_for_comparison("WELCOME"), norm)
        self.assertIn(_normalize_latin_for_comparison("WELCOME PILGRIM TO THE GREAT JOURNEY"), norm)
        self.assertIn(_normalize_latin_for_comparison("TOWARD THE END OF ALL THINGS"), norm)
        self.assertIn(_normalize_latin_for_comparison("EACH INTELLIGENCE IS HOLY"), norm)
        self.assertIn(_normalize_latin_for_comparison("AN INSTRUCTIAN COMMAND YOUR OWN SELF"), norm)

    def test_vigenere_f_skip_encode_decode_roundtrip(self):
        """Roundtrip test for cleartext F-skip Vigenère encoding and decoding."""
        pt = latin_to_rune("FIND THE DIVINITY WITHIN FOR ALL IS SACRED")
        ct, detected_skips = rune_vigenere_encode_f_skip(pt, "DIVINITY")
        self.assertIn(0, detected_skips)  # First rune is 'F' (Fehu)
        recovered = rune_vigenere_decode_f_skip(ct, "DIVINITY", skip_indices=detected_skips)
        self.assertEqual(decode_runes(recovered), decode_runes(pt))


class TestMethod4VigenereFirfumferenfeFSkip(unittest.TestCase):
    """Method 4: Modulo-29 Vigenère key 'FIRFUMFERENFE' with cleartext F-skips (Koan 2)."""

    def test_koan2_f_skip_alignment(self):
        """Verify the 2 canonical skip positions align with cleartext Fehu."""
        raw_runes = load_solved_page_transcript(resolve_solved_page("koan_2"))
        dec_runes = rune_vigenere_decode_f_skip(raw_runes, "FIRFUMFERENFE", skip_indices=KOAN2_F_SKIP_POSITIONS)
        self.assertTrue(verify_f_skip_alignment(dec_runes, KOAN2_F_SKIP_POSITIONS))

    def test_koan2_decode_reproduction(self):
        """Koan 2 decrypted with FIRFUMFERENFE and F-skips reproduces authentic text."""
        res = solve_page("koan_2")
        norm = _normalize_latin_for_comparison(res["plaintext_latin"])
        self.assertIn(_normalize_latin_for_comparison("A KOAN"), norm)
        self.assertIn(_normalize_latin_for_comparison("DURING A LESSON THE MASTER EXPLAINED THE I"), norm)
        self.assertIn(_normalize_latin_for_comparison("THE I IS THE VOICE OF THE CIRCUMFERENCE"), norm)
        self.assertIn(_normalize_latin_for_comparison("AND THE STUDENTS WERE ENLIGHTENED"), norm)


class TestMethod5PrimeTotientStream(unittest.TestCase):
    """Method 5: Prime Totient Stream Cipher: decimal[i] = (decimal[i] - (primes[i] - 1)) % 29."""

    def test_totient_keystream_values(self):
        """Totients of prime numbers must equal p - 1 mod 29."""
        totients = generate_prime_totients(10, offset=0)
        # Primes: [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
        # Totients: [1, 2, 4, 6, 10, 12, 16, 18, 22, 28] mod 29
        expected = [1, 2, 4, 6, 10, 12, 16, 18, 22, 28]
        self.assertEqual(totients, expected)

    def test_prime_totient_stream_roundtrip(self):
        """Bidirectional encode/decode roundtrip with and without F-skip."""
        pt = latin_to_rune("AN END WITHIN THE DEEP WEB FIND YOUR PATH")
        ct, detected_skips = prime_totient_stream_encode(pt, offset=0, f_skip=True)
        recovered = prime_totient_stream_decode(ct, offset=0, skip_indices=detected_skips)
        self.assertEqual(decode_runes(recovered), decode_runes(pt))

    def test_page_71_an_end_reproduction(self):
        """Page 71 ('An end', 56.jpg) decrypted with Prime Totients reproduces authentic text."""
        res = solve_page("an_end")
        norm = _normalize_latin_for_comparison(res["plaintext_latin"])
        self.assertIn(_normalize_latin_for_comparison("AN END"), norm)
        self.assertIn(_normalize_latin_for_comparison("WITHIN THE DEEP WEB"), norm)
        self.assertIn("36367763ab", res["plaintext_latin"])
        clean_latin = "".join(res["plaintext_latin"].split())
        self.assertIn("36367763ab73783c7af284446c59466b4cd653239a311cb7116d4618dee09a8425893dc7500b464fdaf1672d7bef5e891c6e2274568926a49fb4f45132c2a8b4", clean_latin)
        self.assertIn(_normalize_latin_for_comparison("IT IS THE DUTY OF EVERY PILGRIM TO SEEK OUT THIS PAGE"), norm)


class TestMethod6DirectTranslation(unittest.TestCase):
    """Method 6: Direct Gematria Primus transliteration (no encryption)."""

    def test_direct_translation_behavior(self):
        """Direct translation identity cipher preserves runes unaltered."""
        runes = "ᚦᛖ᛫ᛈᚱᛁᛗᛖᛋ᛫ᚪᚱᛖ᛫ᛋᚪᚳᚱᛖᛞ᛬"
        trans = direct_translation(runes)
        self.assertEqual(trans, runes)
        self.assertIn("THE PRIMES ARE SACRED", decode_runes(trans))

    def test_some_wisdom_chunk_3_reproduction(self):
        """Chunk 3 'Some wisdom' reproduces authentic sacred text."""
        res = solve_page("some_wisdom")
        norm = _normalize_latin_for_comparison(res["plaintext_latin"])
        self.assertIn(_normalize_latin_for_comparison("SOME WISDOM"), norm)
        self.assertIn(_normalize_latin_for_comparison("THE PRIMES ARE SACRED"), norm)
        self.assertIn(_normalize_latin_for_comparison("THE TOTIENT FUNCTIAN IS SACRED"), norm)
        self.assertIn(_normalize_latin_for_comparison("ALL THINGS SHOULD BE ENCRYPTED"), norm)

    def test_the_loss_of_divinity_reproduction(self):
        """Chunks 8-11 'The loss of divinity' reproduces authentic text."""
        res = solve_page("loss_of_divinity")
        norm = _normalize_latin_for_comparison(res["plaintext_latin"])
        self.assertIn(_normalize_latin_for_comparison("THE LOSS OF DIVINITY"), norm)
        self.assertIn(_normalize_latin_for_comparison("CIRCUMFERENCE"), norm)
        self.assertIn(_normalize_latin_for_comparison("CONSUMPTIAN"), norm)

    def test_an_instruction_reproduction(self):
        """Chunk 14 'An instruction' reproduces authentic text."""
        res = solve_page("instruction")
        norm = _normalize_latin_for_comparison(res["plaintext_latin"])
        self.assertIn(_normalize_latin_for_comparison("AN INSTRUCTIAN"), norm)
        self.assertIn(_normalize_latin_for_comparison("QUESTION ALL THINGS"), norm)
        self.assertIn(_normalize_latin_for_comparison("DISCOVER TRUTH INSIDE YOURSELF"), norm)

    def test_parable_reproduction(self):
        """Chunk 72 'Parable' reproduces authentic text."""
        res = solve_page("parable")
        norm = _normalize_latin_for_comparison(res["plaintext_latin"])
        self.assertIn(_normalize_latin_for_comparison("PARABLE"), norm)
        self.assertIn(_normalize_latin_for_comparison("LIKE THE INSTAR"), norm)
        self.assertIn(_normalize_latin_for_comparison("TUNNELING TO THE SURFACE"), norm)
        self.assertIn(_normalize_latin_for_comparison("WE MUST SHED OUR OWN CIRCUMFERENCES"), norm)
        self.assertIn(_normalize_latin_for_comparison("FIND THE DIVINITY WITHIN AND EMERGE"), norm)


class TestWorkstationCipherMethods(unittest.TestCase):
    """Test TerminalWorkstation methods and CLI execution."""

    def setUp(self):
        self.ws = TerminalWorkstation(model_key="spark")

    def test_workstation_run_atbash(self):
        """ws.run_atbash produces valid data and plausible gatekeeper verdict."""
        res = self.ws.run_atbash("00")
        self.assertIn("A WARNING", res["decoded_latin"])
        self.assertEqual(res["metrics"]["verdict"], "PLAUSIBLE")

        # Koan 1 with shift 3
        res3 = self.ws.run_atbash("04", shift=3)
        self.assertIn("A COAN", res3["decoded_latin"])
        self.assertEqual(res3["metrics"]["verdict"], "PLAUSIBLE")

    def test_workstation_run_totient_and_stream(self):
        """ws.run_totient and ws.run_totient_stream both decode Page 71."""
        res1 = self.ws.run_totient("dec", "71", offset=0, f_skip=True)
        self.assertIn("36367763ab", res1["decoded_latin"])
        self.assertEqual(res1["metrics"]["verdict"], "PLAUSIBLE")

        res2 = self.ws.run_totient_stream("dec", "71", offset=0, f_skip=True)
        self.assertEqual(res1["decoded_latin"], res2["decoded_latin"])

    def test_workstation_run_solve(self):
        """ws.run_solve supports 'all' and individual pages."""
        all_res = self.ws.run_solve("all")
        self.assertTrue(all_res["all_passed"])
        self.assertEqual(all_res["verified"], 9)

        page_res = self.ws.run_solve("welcome")
        self.assertTrue(page_res["verified"])
        self.assertIn("WELCOME", page_res["plaintext_latin"])

    def test_workstation_run_vigenere_f_skip(self):
        """ws.run_vigenere with f_skip decodes Welcome."""
        res = self.ws.run_vigenere("dec", "01", "DIVINITY", f_skip=True)
        self.assertIn("WELCOME", res["decoded_latin"])

    def test_cli_subcommands_dispatch(self):
        """CLI main([subcommand, ...]) runs smoothly without errors."""
        trap = io.StringIO()
        with patch("sys.stdout", trap):
            main(["atbash", "00"])
            main(["totient", "dec", "71", "--f-skip"])
            main(["solve", "welcome"])
        out = trap.getvalue()
        self.assertIn("ATBASH REFLECTION (F_29)", out)
        self.assertIn("PRIME TOTIENT STREAM CIPHER", out)
        self.assertIn("CANONICAL SOLVED PAGE: WELCOME", out)


class TestEdgeCasesAndBoundaryConditions(unittest.TestCase):
    """Test boundary values, empty inputs, and robustness."""

    def test_empty_string_input(self):
        """Empty input returns empty without exceptions."""
        self.assertEqual(rune_atbash(""), "")
        self.assertEqual(rune_atbash_shift("", shift=3), "")
        self.assertEqual(direct_translation(""), "")
        self.assertEqual(prime_totient_stream_decode("", offset=0), "")
        enc_res, skips = prime_totient_stream_encode("", offset=0)
        self.assertEqual(enc_res, "")
        self.assertEqual(skips, set())

    def test_pure_punctuation_input(self):
        """Pure punctuation strings are preserved without crashing."""
        punct = "᛫ ᛬ ᛭ \n : ."
        self.assertEqual(rune_atbash(punct), punct)
        self.assertEqual(rune_atbash_shift(punct, shift=3), punct)
        self.assertEqual(prime_totient_stream_decode(punct, offset=0), punct)
        trans = direct_translation(punct)
        self.assertTrue(isinstance(trans, str))

    def test_single_rune_roundtrips(self):
        """Single rune transforms execute correctly."""
        for r in INDEX_BY_RUNE.keys():
            # Atbash
            self.assertEqual(rune_atbash(rune_atbash(r)), r)
            # Atbash + 3
            self.assertEqual(rune_atbash_shift(rune_atbash_shift(r, shift=3), shift=3), r)

    def test_negative_and_large_atbash_shifts(self):
        """Caesar shifts mod 29 handle negative and large values identically."""
        runes = "ᚹᛖᛚᚳᚩᛗᛖ"
        # +3 is congruent to +32 and -26 mod 29
        r1 = rune_atbash_shift(runes, shift=3)
        r2 = rune_atbash_shift(runes, shift=32)
        r3 = rune_atbash_shift(runes, shift=-26)
        self.assertEqual(r1, r2)
        self.assertEqual(r1, r3)

    def test_prime_stream_arbitrary_offset(self):
        """Prime totient stream cipher handles non-zero offsets gracefully."""
        pt = latin_to_rune("PILGRIM")
        ct, _ = prime_totient_stream_encode(pt, offset=12, f_skip=False)
        rec = prime_totient_stream_decode(ct, offset=12, f_skip=False)
        self.assertEqual(decode_runes(rec), decode_runes(pt))


if __name__ == "__main__":
    unittest.main()
