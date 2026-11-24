"""
Unit test suite for canonical solved pages of the Liber Primus and their cryptanalytic primitives.
Covers:
1. All 9 canonical solved pages reproduced from the Uncovering Cicada wiki with 100% verification.
2. Atbash in F_29 and Atbash + Caesar (+3) self-inverting algebraic properties.
3. Prime Totient Stream Cipher (phi(p) = p - 1 mod 29) encode/decode roundtrips and offsets.
4. Modulo-29 Vigenère with cleartext Fehu keystream pauses (F-skips).
5. TerminalWorkstation and CLI integration in trithemius.py.
"""

from io import StringIO
import os
import sys
import unittest
from unittest.mock import patch

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from ciphers.agrippa import (
    INDEX_BY_RUNE,
    decode_runes,
    direct_translation,
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
    _normalize_latin_for_comparison,
    load_chunk_transcript,
    resolve_solved_page,
    solve_page,
    verify_all_solved_pages,
)
import trithemius


class TestCanonicalSolvedPagesSuite(unittest.TestCase):
    """Test suite covering the 9 canonical solved pages of the Liber Primus."""

    def test_all_nine_solved_pages_pass_verification(self):
        """Execute verification across all 9 canonical pages and assert 100% pass rate."""
        report = verify_all_solved_pages()
        self.assertEqual(report["total"], 9)
        self.assertEqual(report["verified"], 9)
        self.assertEqual(report["failed"], 0)
        self.assertTrue(report["all_passed"])

    def test_page_00_warning_atbash(self):
        """Page 00 ('A warning', 01.jpg): Atbash in F_29."""
        res = solve_page("page_00")
        self.assertTrue(res["verified"])
        self.assertEqual(res["method"], "Atbash in F_29")
        norm = _normalize_latin_for_comparison(res["plaintext_latin"])
        self.assertIn(_normalize_latin_for_comparison("A WARNNG"), norm)
        self.assertIn(_normalize_latin_for_comparison("BELIEVE NOTHNG FROM THIS BOOC"), norm)
        self.assertIn(_normalize_latin_for_comparison("EXCEPT WHAT YOV CNOW TO BE TRVE"), norm)
        self.assertIn(_normalize_latin_for_comparison("FOR ALL IS SACRED"), norm)

    def test_welcome_vigenere_divinity_f_skip(self):
        """Welcome (03.jpg - 04.jpg, Chunks 1-2): Vigenère DIVINITY with cleartext F-skips."""
        res = solve_page("welcome")
        self.assertTrue(res["verified"])
        self.assertEqual(res["key"], "DIVINITY")
        norm = _normalize_latin_for_comparison(res["plaintext_latin"])
        self.assertIn(_normalize_latin_for_comparison("WELCOME PILGRIM TO THE GREAT JOVRNEY"), norm)
        self.assertIn(_normalize_latin_for_comparison("TOWARD THE END OF ALL THNGS"), norm)
        self.assertIn(_normalize_latin_for_comparison("EACH INTELLIGENCE IS HOLY"), norm)
        self.assertIn(_normalize_latin_for_comparison("AN INSTRVCTIAN COMMAND YOVR OWN SELF"), norm)

    def test_some_wisdom_direct_transliteration(self):
        """Some wisdom (05.jpg, Chunk 3): Direct transliteration."""
        res = solve_page("some_wisdom")
        self.assertTrue(res["verified"])
        self.assertEqual(res["method"], "Direct translation")
        norm = _normalize_latin_for_comparison(res["plaintext_latin"])
        self.assertIn(_normalize_latin_for_comparison("SOME WISDOM"), norm)
        self.assertIn(_normalize_latin_for_comparison("THE PRIMES ARE SACRED"), norm)
        self.assertIn(_normalize_latin_for_comparison("THE TOTIENT FVNCTIAN IS SACRED"), norm)
        self.assertIn(_normalize_latin_for_comparison("ALL THNGS SHOVLD BE ENCRYPTED"), norm)

    def test_koan_1_atbash_caesar_shift_3(self):
        """Koan 1 (06.jpg - 09.jpg, Chunks 4-7): Atbash followed by Caesar shift of +3 in F_29."""
        res = solve_page("koan_1")
        self.assertTrue(res["verified"])
        self.assertEqual(res["key"], "Atbash+3")
        norm = _normalize_latin_for_comparison(res["plaintext_latin"])
        self.assertIn(_normalize_latin_for_comparison("A COAN"), norm)
        self.assertIn(_normalize_latin_for_comparison("A MAN DECIDED TO GO AND STVDY WITH A MASTER"), norm)
        self.assertIn(_normalize_latin_for_comparison("I AM A PROFESSOR"), norm)
        self.assertIn(_normalize_latin_for_comparison("DO FOVR VNREASONABLE THNGS EACH DAY"), norm)

    def test_loss_of_divinity_direct_transliteration(self):
        """The loss of divinity (10.jpg - 13.jpg, Chunks 8-11): Direct transliteration."""
        res = solve_page("loss_of_divinity")
        self.assertTrue(res["verified"])
        self.assertEqual(res["method"], "Direct translation")
        norm = _normalize_latin_for_comparison(res["plaintext_latin"])
        self.assertIn(_normalize_latin_for_comparison("THE LOSS OF DIVINITY"), norm)
        self.assertIn(_normalize_latin_for_comparison("THE CIRCVMFERENCE PRACTICES THREE BEHAVIARS"), norm)
        self.assertIn(_normalize_latin_for_comparison("CONSVMPTIAN"), norm)
        self.assertIn(_normalize_latin_for_comparison("PROGRAM YOVR MIND"), norm)

    def test_koan_2_vigenere_firfumferenfe_f_skip(self):
        """Koan 2 (14.jpg - 15.jpg, Chunks 12-13): Vigenère FIRFUMFERENFE with cleartext F-skips."""
        res = solve_page("koan_2")
        self.assertTrue(res["verified"])
        self.assertEqual(res["key"], "FIRFUMFERENFE")
        norm = _normalize_latin_for_comparison(res["plaintext_latin"])
        self.assertIn(_normalize_latin_for_comparison("A COAN"), norm)
        self.assertIn(_normalize_latin_for_comparison("DVRNG A LESSON THE MASTER EXPLAINED THE I"), norm)
        self.assertIn(_normalize_latin_for_comparison("THE I IS THE VOICE OF THE CIRCVMFERENCE HE SAID"), norm)
        self.assertIn(_normalize_latin_for_comparison("AND THE STVDENTS WERE ENLIGHTENED"), norm)

    def test_instruction_direct_transliteration(self):
        """An instruction (16.jpg, Chunk 14): Direct transliteration."""
        res = solve_page("instruction")
        self.assertTrue(res["verified"])
        norm = _normalize_latin_for_comparison(res["plaintext_latin"])
        self.assertIn(_normalize_latin_for_comparison("AN INSTRVCTIAN"), norm)
        self.assertIn(_normalize_latin_for_comparison("CWESTIAN ALL THNGS"), norm)
        self.assertIn(_normalize_latin_for_comparison("DISCOVER TRVTH INSIDE YOVRSELF"), norm)
        self.assertIn(_normalize_latin_for_comparison("IMPOSE NOTHNG ON OTHERS"), norm)

    def test_an_end_totient_stream(self):
        """An end (56.jpg in original dump / 73.jpg, Chunk 71): Prime Totient Stream Cipher."""
        res = solve_page("an_end")
        self.assertTrue(res["verified"])
        norm = _normalize_latin_for_comparison(res["plaintext_latin"])
        self.assertIn(_normalize_latin_for_comparison("AN END"), norm)
        self.assertIn(_normalize_latin_for_comparison("WITHIN THE DEEP WEB"), norm)
        self.assertIn(_normalize_latin_for_comparison("THERE EXISTS A PAGE THAT HASHES TO"), norm)
        self.assertIn(_normalize_latin_for_comparison("36367763ab73783c7af284446c59466b4cd653239a311cb7116d4618dee09a8425893dc7500b464fdaf1672d7bef5e891c6e2274568926a49fb4f45132c2a8b4"), norm)
        self.assertIn(_normalize_latin_for_comparison("IT IS THE DVTY OF EVERY PILGRIM TO SEEC OVT THIS PAGE"), norm)

    def test_parable_direct_transliteration(self):
        """Parable (57.jpg in original dump, Chunk 72): Direct transliteration."""
        res = solve_page("parable")
        self.assertTrue(res["verified"])
        norm = _normalize_latin_for_comparison(res["plaintext_latin"])
        self.assertIn(_normalize_latin_for_comparison("PARABLE"), norm)
        self.assertIn(_normalize_latin_for_comparison("LICE THE INSTAR"), norm)
        self.assertIn(_normalize_latin_for_comparison("TVNNELNG TO THE SVRFACE"), norm)
        self.assertIn(_normalize_latin_for_comparison("WE MVST SHED OVR OWN CIRCVMFERENCES"), norm)

    def test_resolution_aliases(self):
        """Ensure resolve_solved_page handles various aliases, numbers, and images."""
        self.assertEqual(resolve_solved_page(0).id, "page_00")
        self.assertEqual(resolve_solved_page("00").id, "page_00")
        self.assertEqual(resolve_solved_page("01.jpg").id, "page_00")
        self.assertEqual(resolve_solved_page("welcome").id, "welcome")
        self.assertEqual(resolve_solved_page(1).id, "welcome")
        self.assertEqual(resolve_solved_page("03.jpg").id, "welcome")
        self.assertEqual(resolve_solved_page("koan1").id, "koan_1")
        self.assertEqual(resolve_solved_page("koan 1").id, "koan_1")
        self.assertEqual(resolve_solved_page(4).id, "koan_1")
        self.assertEqual(resolve_solved_page(56).id, "an_end")
        self.assertEqual(resolve_solved_page(71).id, "an_end")
        self.assertEqual(resolve_solved_page("73.jpg").id, "an_end")
        self.assertEqual(resolve_solved_page("parable").id, "parable")
        self.assertEqual(resolve_solved_page(72).id, "parable")


class TestAtbashShiftMathematicalProperties(unittest.TestCase):
    """Test algebraic correctness of Atbash and Atbash + Caesar shift in F_29."""

    def test_rune_atbash_is_involutive(self):
        """Atbash is an involution: A(A(x)) == x for all inputs."""
        sample_text = "ᚠᚢᚦᚩᚱᚳᚷᚹᚻᚾᛁᛄᛇᛈᛉᛋᛏᛒᛖᛗᛚᛝᛟᛞᚪᚫᚣᛡᛠ"
        enc = rune_atbash(sample_text)
        dec = rune_atbash(enc)
        self.assertEqual(dec, sample_text)

    def test_rune_atbash_shift_self_inverse_in_f29(self):
        """Atbash + Shift in F_29 is self-inverse: A_s(A_s(x)) == x for any shift s."""
        sample_text = "ᚹᛖᛚᚳᚩᛗᛖ᛫ᛈᛁᛚᚷᚱᛁᛗᛋ᛬ᚳᚾᚩᚹ᛫ᚦᛁᛋ"
        for s in range(29):
            enc = rune_atbash_shift(sample_text, shift=s)
            dec = rune_atbash_shift(enc, shift=s)
            self.assertEqual(dec, sample_text, f"Failed self-inverse property for shift {s}")

    def test_atbash_specific_values(self):
        """Verify boundary character mappings in F_29."""
        # 0 (Fehu ᚠ) -> (28 - 0) = 28 (Ear ᛠ)
        self.assertEqual(rune_atbash("ᚠ"), "ᛠ")
        self.assertEqual(rune_atbash("ᛠ"), "ᚠ")
        # Shift +3: 0 -> ((28 - 0) + 3) mod 29 = 31 mod 29 = 2 (Thurisaz ᚦ)
        self.assertEqual(rune_atbash_shift("ᚠ", shift=3), "ᚦ")
        # Inversion check: 2 -> ((28 - 2) + 3) mod 29 = 29 mod 29 = 0 (Fehu ᚠ)
        self.assertEqual(rune_atbash_shift("ᚦ", shift=3), "ᚠ")


class TestPrimeTotientStreamCipher(unittest.TestCase):
    """Test mathematical correctness and round-trips of Prime Totient Stream Cipher."""

    def test_generate_prime_totients(self):
        """First primes are 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31..."""
        # phi(p) mod 29 = (p - 1) mod 29
        # phi(2)=1, phi(3)=2, phi(5)=4, phi(7)=6, phi(11)=10, phi(13)=12, phi(17)=16, phi(19)=18, phi(23)=22, phi(29)=28, phi(31)=30%29=1
        totients = generate_prime_totients(11, offset=0)
        expected = [1, 2, 4, 6, 10, 12, 16, 18, 22, 28, 1]
        self.assertEqual(totients, expected)

    def test_prime_totient_roundtrip_without_f_skip(self):
        """Encode then decode recovers original plaintext without skips."""
        pt = "ᚹᛖᛚᚳᚩᛗᛖ᛫ᛏᚩ᛫ᚦᛖ᛫ᛖᚾᛞ"
        ct, _ = prime_totient_stream_encode(pt, offset=0, f_skip=False)
        rec = prime_totient_stream_decode(ct, offset=0, f_skip=False)
        self.assertEqual(rec, pt)

    def test_prime_totient_roundtrip_with_offsets(self):
        """Roundtrip holds across arbitrary prime sequence offsets."""
        pt = "ᚦᛖ᛫ᛈᚱᛁᛗᛖᛋ᛫ᚪᚱᛖ᛫ᛋᚪᚳᚱᛖᛞ"
        for offset in (0, 1, 5, 17, 42, 100):
            ct, _ = prime_totient_stream_encode(pt, offset=offset)
            rec = prime_totient_stream_decode(ct, offset=offset)
            self.assertEqual(rec, pt)

    def test_prime_totient_fehu_skip_clocking(self):
        """Cleartext Fehu pauses keystream pointer and passes through unencrypted."""
        # 'ᚠ' is index 0
        pt = "ᚹᛖᛚᚠᚳᚩᛗᛖ"  # Contains 'ᚠ' at index 3
        ct, skips = prime_totient_stream_encode(pt, offset=0, f_skip=True)
        self.assertIn(3, skips)
        self.assertEqual(ct[3], "ᚠ")  # Passes through unencrypted

        rec = prime_totient_stream_decode(ct, offset=0, skip_indices=skips)
        self.assertEqual(rec, pt)


class TestVigenereFSkipMechanisms(unittest.TestCase):
    """Test cleartext Fehu keystream pause mechanism on Vigenère mod 29."""

    def test_vigenere_f_skip_roundtrip(self):
        """Encode with f_skip and decode with detected skip indices recovers plaintext."""
        pt = "ᚹᛖᛚᚳᚩᛗᛖ᛫ᚠᚱᛁᛖᚾᛞ᛫ᚠᛁᚾᛞ᛫ᚣᚩᚢᚱ᛫ᛏᚱᚢᚦ"
        key = "DIVINITY"
        ct, skips = rune_vigenere_encode_f_skip(pt, key=key)
        self.assertTrue(len(skips) > 0)
        rec = rune_vigenere_decode_f_skip(ct, key=key, skip_indices=skips)
        self.assertEqual(rec, pt)

    def test_welcome_f_skip_alignment(self):
        """Assert that all 11 indices in WELCOME_F_SKIP_POSITIONS are strictly Fehu in Welcome plaintext."""
        page = resolve_solved_page("welcome")
        res = solve_page(page)
        pt_runes = [c for c in res["decrypted_runes"] if c in INDEX_BY_RUNE]
        for idx in WELCOME_F_SKIP_POSITIONS:
            self.assertLess(idx, len(pt_runes))
            self.assertEqual(INDEX_BY_RUNE[pt_runes[idx]], 0, f"Index {idx} is not Fehu (0)")

        self.assertTrue(verify_f_skip_alignment(res["decrypted_runes"], WELCOME_F_SKIP_POSITIONS))

    def test_koan2_f_skip_alignment(self):
        """Assert that indices in KOAN2_F_SKIP_POSITIONS are Fehu in Koan 2 plaintext."""
        page = resolve_solved_page("koan_2")
        res = solve_page(page)
        pt_runes = [c for c in res["decrypted_runes"] if c in INDEX_BY_RUNE]
        for idx in KOAN2_F_SKIP_POSITIONS:
            self.assertLess(idx, len(pt_runes))
            self.assertEqual(INDEX_BY_RUNE[pt_runes[idx]], 0, f"Index {idx} is not Fehu (0)")

        self.assertTrue(verify_f_skip_alignment(res["decrypted_runes"], KOAN2_F_SKIP_POSITIONS))


class TestTerminalWorkstationAndCLIIntegration(unittest.TestCase):
    """Test TerminalWorkstation methods and direct CLI main execution."""

    def setUp(self):
        self.ws = trithemius.TerminalWorkstation()

    def test_workstation_run_atbash(self):
        """TerminalWorkstation.run_atbash produces valid result dictionary."""
        res = self.ws.run_atbash("00")
        self.assertIn("A WARNING", res["decoded_latin"])
        self.assertGreater(res["ioc"], 0.05)
        self.assertEqual(res["metrics"]["verdict"], "PLAUSIBLE")

    def test_workstation_run_atbash_shifted(self):
        """TerminalWorkstation.run_atbash with shift 3 reproduces Koan 1 chunk 4."""
        res = self.ws.run_atbash("04", shift=3)
        self.assertIn("A COAN", res["decoded_latin"])
        self.assertEqual(res["shift"], 3)
        self.assertEqual(res["metrics"]["verdict"], "PLAUSIBLE")

    def test_workstation_run_totient_stream(self):
        """TerminalWorkstation.run_totient_stream decodes chunk 71."""
        res = self.ws.run_totient_stream("dec", "71", f_skip=True)
        self.assertIn("AN END", res["decoded_latin"])
        self.assertIn("36367763ab", res["decoded_latin"])

    def test_workstation_run_solve_all(self):
        """TerminalWorkstation.run_solve('all') verifies all 9 pages."""
        res = self.ws.run_solve("all")
        self.assertEqual(res["total"], 9)
        self.assertTrue(res["all_passed"])

    def test_workstation_run_solve_single(self):
        """TerminalWorkstation.run_solve('welcome') verifies welcome page."""
        res = self.ws.run_solve("welcome")
        self.assertTrue(res["verified"])
        self.assertEqual(res["id"], "welcome")

    def test_cli_solve_subcommand(self):
        """CLI: trithemius.py solve"""
        buf = StringIO()
        with patch("sys.stdout", buf):
            trithemius.main(["solve"])
        output = buf.getvalue()
        self.assertIn("ALL 9 PAGES VERIFIED", output)

    def test_cli_atbash_subcommand(self):
        """CLI: trithemius.py atbash 00"""
        buf = StringIO()
        with patch("sys.stdout", buf):
            trithemius.main(["atbash", "00"])
        output = buf.getvalue()
        self.assertIn("A WARNING", output)
        self.assertIn("ATBASH REFLECTION", output)

    def test_cli_totient_stream_subcommand(self):
        """CLI: trithemius.py totient-stream dec 71 --f-skip"""
        buf = StringIO()
        with patch("sys.stdout", buf):
            trithemius.main(["totient-stream", "dec", "71", "--f-skip"])
        output = buf.getvalue()
        self.assertIn("AN END", output)
        self.assertIn("PRIME TOTIENT STREAM CIPHER", output)

    def test_cli_vigenere_f_skip_subcommand(self):
        """CLI: trithemius.py vigenere dec 01 DIVINITY --f-skip"""
        buf = StringIO()
        with patch("sys.stdout", buf):
            trithemius.main(["vigenere", "dec", "01", "DIVINITY", "--f-skip"])
        output = buf.getvalue()
        self.assertIn("WELCOME", output)
        self.assertIn("Fehu (F) Skip:   ENABLED", output)

    def test_vigenere_f_skip_custom_text_roundtrip_autodetect(self):
        """Verify that novel custom messages with cleartext Fehu roundtrip correctly with f_skip=True."""
        pt = "FIND YOUR FAITH AND BELIEVE"
        enc_res = self.ws.run_vigenere("enc", pt, "DIVINITY", f_skip=True)
        self.assertIn("Modulo-29", enc_res["alphabet"])
        self.assertIsNotNone(enc_res["skip_indices"])
        self.assertIn(0, enc_res["skip_indices"])  # 'F' in FIND

        dec_res = self.ws.run_vigenere("dec", enc_res["result"], "DIVINITY", f_skip=True)
        self.assertIn("FIND", dec_res["decoded_latin"])
        self.assertIn("FAITH", dec_res["decoded_latin"])

    def test_totient_stream_custom_text_roundtrip_autodetect(self):
        """Verify Prime Totient Stream Cipher roundtrips custom messages with Fehu skips."""
        pt = "FIND THE SACRED END"
        enc_res = self.ws.run_totient_stream("enc", pt, offset=0, f_skip=True)
        self.assertIsNotNone(enc_res["skip_indices"])
        self.assertIn(0, enc_res["skip_indices"])

        dec_res = self.ws.run_totient_stream("dec", enc_res["result_runes"], offset=0, f_skip=True)
        self.assertIn("FIND", dec_res["decoded_latin"])
        self.assertIn("END", dec_res["decoded_latin"])

    def test_malformed_skip_indices_handled_safely(self):
        """Verify malformed and out-of-bounds skip indices do not crash CLI or functions."""
        buf = StringIO()
        with patch("sys.stdout", buf):
            trithemius.main(["vigenere", "dec", "01", "DIVINITY", "--skip-indices", "abc, -5, 48, xyz, 9999"])
        out = buf.getvalue()
        self.assertIn("VIGENERE CRYPTANALYSIS", out)

    def test_solve_page_custom_external_transcript_file(self):
        """Verify solve_page handles transcript files located outside corpus/."""
        import tempfile
        page_warning = resolve_solved_page("page_00")
        raw_text = load_chunk_transcript(0)
        with tempfile.NamedTemporaryFile(suffix=".txt", mode="w+", delete=False) as tmp:
            tmp.write(f"# Custom External Transcript\n<!-- cicada:chunk_index=0 -->\n## Rune Transcription\n{raw_text}\n")
            tmp_path = tmp.name

        try:
            resolved = resolve_solved_page(tmp_path)
            self.assertIsNotNone(resolved)
            self.assertEqual(resolved.id, "page_00")
            res = solve_page(tmp_path)
            self.assertTrue(res["verified"])
            self.assertEqual(res["method"], "Atbash in F_29")
            self.assertIn(_normalize_latin_for_comparison("A WARNING"), _normalize_latin_for_comparison(res["plaintext_latin"]))
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_atbash_and_shift_on_latin_input(self):
        """Verify rune_atbash and rune_atbash_shift work directly on Latin strings."""
        atb_res = rune_atbash("A WARNING")
        self.assertTrue(any(c in INDEX_BY_RUNE for c in atb_res))
        back = rune_atbash(atb_res)
        self.assertEqual(decode_runes(back), "A WARNING")

        shift_res = rune_atbash_shift("A KOAN", shift=3)
        self.assertTrue(any(c in INDEX_BY_RUNE for c in shift_res))
        shift_back = rune_atbash_shift(shift_res, shift=3)
        self.assertEqual(decode_runes(shift_back), "A COAN")


if __name__ == "__main__":
    unittest.main()
