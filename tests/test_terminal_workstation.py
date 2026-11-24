"""
Terminal Workstation Comprehensive Test Suite.
Verifies all unified terminal capabilities, CLI dispatchers, and cipher optimizations.
"""

import io
import os
import sys
import unittest
from unittest.mock import patch, MagicMock

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)
sys.path.insert(0, os.path.join(BASE_DIR, "ciphers"))
sys.path.insert(0, os.path.join(BASE_DIR, "scripts"))

from trithemius import TerminalWorkstation
import ciphers.agrippa as agrippa
import ciphers.kasiski as kasiski
import ciphers.al_kindi as al_kindi
import ciphers.opsec as opsec
import ciphers.entropy as entropy
import scripts.porta as porta


class TestTerminalWorkstationGematria(unittest.TestCase):
    def setUp(self):
        self.ws = TerminalWorkstation(model_key="spark")

    def test_gematria_rune_input(self):
        res = self.ws.run_gematria("ᚹᛖᛚᚳᚩᛗᛖ")
        self.assertEqual(res["decoded_latin"], "WELCOME")
        self.assertEqual(res["prime_sum"], 317)
        self.assertTrue(res["is_prime"])
        self.assertEqual(res["totient"], 316)
        self.assertEqual(res["prime_factors"], [317])
        self.assertEqual(res["atbash_latin"], "INGIHDAENI")

    def test_gematria_latin_input(self):
        res = self.ws.run_gematria("WELCOME")
        self.assertEqual(res["runes"], "ᚹᛖᛚᚳᚩᛗᛖ")
        self.assertEqual(res["prime_sum"], 317)
        self.assertTrue(res["is_prime"])

    def test_gematria_word_sums(self):
        res = self.ws.run_gematria("ᚹᛖᛚᚳᚩᛗᛖ᛫ᛈᛁᛚᚷᚱᛁᛗᛋ")
        self.assertEqual(len(res["word_sums"]), 2)
        self.assertEqual(res["word_sums"][0][1], 317)
        self.assertEqual(res["word_sums"][1][1], 330)


class TestTerminalWorkstationVigenere(unittest.TestCase):
    def setUp(self):
        self.ws = TerminalWorkstation(model_key="spark")

    def test_vigenere_runes_mod29_roundtrip(self):
        pt = "ᚹᛖᛚᚳᚩᛗᛖ᛫ᛈᛁᛚᚷᚱᛁᛗᛋ"
        key = "DIVINITY"
        enc = self.ws.run_vigenere("enc", pt, key)
        self.assertEqual(enc["alphabet"], "Modulo-29 (Futhorc Runes)")
        dec = self.ws.run_vigenere("dec", enc["result"], key)
        self.assertEqual(dec["decoded_latin"], "WELCOME PILGRIMS")
        self.assertEqual(dec["metrics"]["verdict"], "PLAUSIBLE")

    def test_vigenere_latin_mod26_roundtrip(self):
        pt = "WELCOME PILGRIMS ON THE PATH"
        key = "CICADA"
        enc = self.ws.run_vigenere("enc", pt, key)
        self.assertEqual(enc["alphabet"], "Modulo-26 (Classical Latin A-Z)")
        dec = self.ws.run_vigenere("dec", enc["result"], key)
        self.assertIn("WELCOME", dec["result"])
        self.assertEqual(dec["metrics"]["verdict"], "PLAUSIBLE")

    def test_vigenere_with_corpus_filepath(self):
        page_path = os.path.join(BASE_DIR, "corpus", "page_56_runes.md")
        res = self.ws.run_vigenere("dec", page_path, "DIVINITY")
        self.assertEqual(res["source_file"], "page_56_runes.md")
        self.assertEqual(res["extraction_mode"], "Rune Transcription section")
        self.assertEqual(res["rune_count"], 273)
        self.assertEqual(res["alphabet"], "Modulo-29 (Futhorc Runes)")
        self.assertIn("DIVINITY", res["key"])

    def test_vigenere_with_page_number_identifier(self):
        res = self.ws.run_vigenere("dec", "56", "DIVINITY")
        self.assertEqual(res["source_file"], "page_56_runes.md")
        self.assertEqual(res["rune_count"], 273)
        self.assertEqual(res["alphabet"], "Modulo-29 (Futhorc Runes)")


class TestTerminalWorkstationOpsec(unittest.TestCase):
    def setUp(self):
        self.ws = TerminalWorkstation(model_key="spark")

    def test_opsec_with_corpus_file(self):
        page_path = os.path.join(BASE_DIR, "corpus", "page_73_an_end.md")
        res = self.ws.run_opsec(page_path)
        self.assertTrue(res["is_file"])
        self.assertFalse(res["pgp"]["is_official_key"])
        self.assertGreater(res["features"]["entropy"], 5.0)

    def test_opsec_with_official_cicada_pgp(self):
        signed_text = (
            "-----BEGIN PGP SIGNED MESSAGE-----\n"
            "Hash: SHA512\n\n"
            "Beware false paths. Always verify the signature from 7A35090F.\n"
            "-----BEGIN PGP SIGNATURE-----\n"
            "Version: GnuPG v1.4.11\n\n"
            "iQIcBAEBCgAGBQJP7...\n"
            "-----END PGP SIGNATURE-----"
        )
        res = self.ws.run_opsec(signed_text)
        self.assertTrue(res["pgp"]["has_pgp_block"])
        self.assertTrue(res["pgp"]["is_official_key"])
        self.assertEqual(res["pgp"]["key_id_found"], "7A35090F")
        self.assertEqual(res["pgp"]["verdict"], "AUTHENTIC_CICADA_KEY_REFERENCED")


class TestOptimizations(unittest.TestCase):
    def test_agrippa_lru_cache_and_correctness(self):
        # Verify prime checking
        self.assertTrue(agrippa.is_prime(2))
        self.assertTrue(agrippa.is_prime(3301))
        self.assertFalse(agrippa.is_prime(3300))
        self.assertFalse(agrippa.is_prime(1))

        # Verify totient
        self.assertEqual(agrippa.euler_totient(3301), 3300)
        self.assertEqual(agrippa.euler_totient(9), 6)
        self.assertEqual(agrippa.euler_totient(1), 1)

        # Verify prime factors
        self.assertEqual(agrippa.prime_factors(3300), [2, 2, 3, 5, 5, 11])

        # Verify latin_to_rune compiled regex
        self.assertEqual(agrippa.latin_to_rune("THE"), "ᚦᛖ")
        self.assertEqual(agrippa.latin_to_rune("ING"), "ᛝ")

    def test_kasiski_crack_caesar_shift(self):
        # Encrypt with shift of 3 (Caesar 'D')
        pt = "THIS IS A TEST OF THE EMERGENCY BROADCAST SYSTEM AND ENGLISH LANGUAGE"
        shift_key = 3
        ct = "".join(chr((ord(c) - 65 + shift_key) % 26 + 65) for c in pt if c.isalpha())
        recovered_shift = kasiski.crack_caesar_shift(ct)
        self.assertEqual(recovered_shift, shift_key)

    def test_al_kindi_clean_and_word_ratio(self):
        text = "WELCOME TO THE SACRED PRIMES"
        self.assertEqual(al_kindi.clean(text), "WELCOMETOTHESACREDPRIMES")
        ratio = al_kindi.english_word_ratio(text)
        self.assertGreaterEqual(ratio, 0.7)

    def test_porta_file_sha256_caching(self):
        page_path = os.path.join(BASE_DIR, "corpus", "page_00_welcome.md")
        h1 = porta.file_sha256(page_path)
        h2 = porta.file_sha256(page_path)
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)


class TestTerminalWorkstationStatusAndPage(unittest.TestCase):
    def setUp(self):
        self.ws = TerminalWorkstation(model_key="spark")

    def test_status_output(self):
        stdout_trap = io.StringIO()
        with patch("sys.stdout", stdout_trap):
            self.ws.run_status()
        out = stdout_trap.getvalue()
        self.assertIn("TRITHEMIUS SYSTEM TELEMETRY", out)
        self.assertIn("Active Model:", out)
        self.assertIn("Official PGP:    7A35090F", out)

    def test_page_output(self):
        stdout_trap = io.StringIO()
        with patch("sys.stdout", stdout_trap):
            self.ws.run_page("56")
        out = stdout_trap.getvalue()
        self.assertIn("LIBER PRIMUS PAGE 56", out)
        self.assertIn("page_56_loss_of_innocence.md", out)

    def test_status_cloud_and_low_spec(self):
        ws_cloud = TerminalWorkstation(provider="groq", low_spec=True)
        stdout_trap = io.StringIO()
        with patch("sys.stdout", stdout_trap):
            ws_cloud.run_status()
        out = stdout_trap.getvalue()
        self.assertIn("Active Provider: GROQ", out)
        self.assertIn("LOW-SPEC", out)
        self.assertIn("Context Window:  2048 tokens", out)

class TestTerminalWorkstationUIAndBoost(unittest.TestCase):
    def setUp(self):
        self.ws = TerminalWorkstation(model_key="spark")
        if "TRITHEMIUS_BOOST" in os.environ:
            del os.environ["TRITHEMIUS_BOOST"]

    def tearDown(self):
        if "TRITHEMIUS_BOOST" in os.environ:
            del os.environ["TRITHEMIUS_BOOST"]

    def test_print_command_list_displays_all_commands(self):
        stdout_trap = io.StringIO()
        with patch("sys.stdout", stdout_trap):
            self.ws.print_command_list()
        out = stdout_trap.getvalue()
        self.assertIn("COMMANDS REFERENCE:", out)
        self.assertIn("[CRYPTANALYSIS]", out)
        self.assertIn("[KNOWLEDGE]", out)
        self.assertIn("[AI ENGINE]", out)
        self.assertIn("[SYSTEM]", out)
        self.assertIn("/ask", out)
        self.assertIn("/web", out)
        self.assertIn("/page", out)
        self.assertIn("/gematria", out)
        self.assertIn("/vigenere", out)
        self.assertIn("/opsec", out)
        self.assertIn("/organize", out)
        self.assertIn("/ingest", out)
        self.assertIn("/status", out)
        self.assertIn("/think", out)
        self.assertIn("/boost", out)
        self.assertIn("/provider", out)
        self.assertIn("/model", out)
        self.assertIn("/key", out)
        self.assertIn("/host", out)
        self.assertIn("/profile", out)
        self.assertIn("/cache", out)
        self.assertIn("/bench", out)
        self.assertIn("/help", out)
        self.assertIn("/exit", out)

    def test_print_help_full_manual(self):
        stdout_trap = io.StringIO()
        with patch("sys.stdout", stdout_trap):
            self.ws.print_help()
        out = stdout_trap.getvalue()
        self.assertIn("TRITHEMIUS WORKSTATION — COMPLETE COMMAND REFERENCE MANUAL", out)
        self.assertIn("1. RAG & KNOWLEDGE RETRIEVAL", out)
        self.assertIn("2. CRYPTANALYSIS & SACRED NUMEROLOGY", out)
        self.assertIn("3. CORPUS MANAGEMENT & INGESTION", out)
        self.assertIn("4. MODEL, ENGINE & HARDWARE CONFIGURATION", out)
        self.assertIn("5. TELEMETRY, BENCHMARKING & SYSTEM", out)
        self.assertIn("/gematria", out)
        self.assertIn("/boost", out)
        self.assertIn("/bench", out)

    def test_print_help_specific_command(self):
        stdout_trap = io.StringIO()
        with patch("sys.stdout", stdout_trap):
            self.ws.print_help("gematria")
        out = stdout_trap.getvalue()
        self.assertIn("[HELP: /gematria]", out)
        self.assertIn("Syntax:      /gematria <runes_or_latin>", out)
        self.assertIn("Agrippan occult philosophy", out)
        self.assertIn("Examples:", out)

    def test_print_help_boost_command(self):
        stdout_trap = io.StringIO()
        with patch("sys.stdout", stdout_trap):
            self.ws.print_help("/boost")
        out = stdout_trap.getvalue()
        self.assertIn("[HELP: /boost]", out)
        self.assertIn("Syntax:      /boost [on|off", out)
        self.assertIn("Deep Cryptanalytic Retrieval", out)

    def test_print_help_unknown_command(self):
        stdout_trap = io.StringIO()
        with patch("sys.stdout", stdout_trap):
            self.ws.print_help("nonexistent_cipher")
        out = stdout_trap.getvalue()
        self.assertIn("[!] Unknown command 'nonexistent_cipher'", out)

    def test_boost_flag_and_status(self):
        ws_boost = TerminalWorkstation(boost=True)
        self.assertTrue(ws_boost.boost)
        self.assertEqual(os.environ.get("TRITHEMIUS_BOOST"), "on")

        stdout_trap = io.StringIO()
        with patch("sys.stdout", stdout_trap):
            ws_boost.run_status()
        out = stdout_trap.getvalue()
        self.assertIn("Retrieval Boost: ENABLED", out)

    def test_run_boost_modes_and_preservation(self):
        ws = TerminalWorkstation(boost=False)
        self.assertFalse(ws.boost)

        # Enable
        ws.run_boost("on")
        self.assertTrue(ws.boost)
        self.assertEqual(os.environ.get("TRITHEMIUS_BOOST"), "on")

        # Status check must NOT disable boost
        ws.run_boost("status")
        self.assertTrue(ws.boost)
        self.assertEqual(os.environ.get("TRITHEMIUS_BOOST"), "on")

        # Disable
        ws.run_boost("off")
        self.assertFalse(ws.boost)
        self.assertEqual(os.environ.get("TRITHEMIUS_BOOST"), "off")

        # Toggle
        ws.run_boost("toggle")
        self.assertTrue(ws.boost)

        # No arg toggle
        ws.run_boost()
        self.assertFalse(ws.boost)

        # Invalid mode should not mutate state
        ws.run_boost("invalid_mode")
        self.assertFalse(ws.boost)

    def test_boost_explicit_false_overrides_env(self):
        os.environ["TRITHEMIUS_BOOST"] = "on"
        ws_disabled = TerminalWorkstation(boost=False)
        self.assertFalse(ws_disabled.boost)
        self.assertEqual(os.environ.get("TRITHEMIUS_BOOST"), "off")

    def test_command_list_max_line_length_and_alignment(self):
        stdout_trap = io.StringIO()
        with patch("sys.stdout", stdout_trap):
            self.ws.print_command_list()
        lines = stdout_trap.getvalue().splitlines()
        for idx, line in enumerate(lines):
            self.assertLessEqual(len(line), 78, f"Line {idx} exceeds 78 chars: '{line}' ({len(line)} chars)")

    def test_full_manual_max_line_length(self):
        stdout_trap = io.StringIO()
        with patch("sys.stdout", stdout_trap):
            self.ws.print_help()
        lines = stdout_trap.getvalue().splitlines()
        for idx, line in enumerate(lines):
            self.assertLessEqual(len(line), 78, f"Help manual line {idx} exceeds 78 chars: '{line}' ({len(line)} chars)")

    def test_cli_subcommands_boost_help_web(self):
        from trithemius import main
        # Test CLI boost status
        stdout_trap = io.StringIO()
        with patch("sys.stdout", stdout_trap):
            main(["boost", "status"])
        self.assertIn("Deep Cryptanalytic Retrieval & Boost:", stdout_trap.getvalue())

        # Test CLI help subcommand
        stdout_trap = io.StringIO()
        with patch("sys.stdout", stdout_trap):
            main(["help", "gematria"])
        self.assertIn("[HELP: /gematria]", stdout_trap.getvalue())

        # Test CLI web subcommand
        with patch.object(TerminalWorkstation, "run_ask") as mock_ask:
            main(["web", "Cicada puzzle"])
            mock_ask.assert_called_once_with("Cicada puzzle", use_web=True)

    def test_ask_retrieve_boost_mode_expansion(self):
        import scripts.ask as ask
        os.environ["TRITHEMIUS_BOOST"] = "on"
        # Test bm25_retrieve with default k=TOP_K
        results = ask.bm25_retrieve("welcome", k=ask.TOP_K)
        # Should return up to 10 candidates under boost
        self.assertLessEqual(len(results), 10)

    def test_boost_multiplier_calculation(self):
        from scripts.ask import _calculate_relevance_boost
        doc = "ᚹᛖᛚᚳᚩᛗᛖ welcome pilgrims to page 56"
        meta = {"has_runes": True, "is_pgp_signed": True}
        query = "rune welcome"
        query_runes = ["ᚹ", "ᛖ"]

        os.environ["TRITHEMIUS_BOOST"] = "off"
        score_normal = _calculate_relevance_boost(doc, meta, query, query_runes)

        os.environ["TRITHEMIUS_BOOST"] = "on"
        score_boosted = _calculate_relevance_boost(doc, meta, query, query_runes)

        self.assertAlmostEqual(score_boosted, score_normal * 2.0)

    def test_run_bench_method(self):
        stdout_trap = io.StringIO()
        with patch("sys.stdout", stdout_trap):
            self.ws.run_bench(skip_vector=True, include_llm=False)
        out = stdout_trap.getvalue()
        self.assertIn("TRITHEMIUS PERFORMANCE BENCHMARK", out)

    def test_repl_loop_displays_command_list_every_prompt(self):
        # Provide sequence of inputs: "/boost", "/help vigenere", "clear", "/exit"
        inputs = ["/boost", "/help vigenere", "clear", "/exit"]
        input_mock = MagicMock(side_effect=inputs)
        stdout_trap = io.StringIO()

        with patch("builtins.input", input_mock), patch("sys.stdout", stdout_trap), patch("os.system") as mock_sys:
            self.ws.repl()
            mock_sys.assert_called_once()

        out = stdout_trap.getvalue()
        # Verify print_command_list ran before each input prompt (4 times)
        cmd_ref_count = out.count("COMMANDS REFERENCE:")
        self.assertGreaterEqual(cmd_ref_count, 4)
        self.assertIn("[*] Deep Cryptanalytic Retrieval & Boost: ENABLED", out)
        self.assertIn("[HELP: /vigenere]", out)
        self.assertIn("Modulo-29 (Futhorc) or Modulo-26", out)
        self.assertIn("[*] Workstation session terminated.", out)

    def test_run_key_section_display(self):
        stdout_trap = io.StringIO()
        with patch("sys.stdout", stdout_trap):
            self.ws.run_key_section()
        out = stdout_trap.getvalue()
        self.assertIn("[AI API KEYS & CLOUD PROVIDERS]", out)
        self.assertIn("GROQ", out)
        self.assertIn("OPENAI", out)
        self.assertIn("GEMINI", out)
        self.assertIn("ANTHROPIC", out)
        self.assertIn("OPENROUTER", out)
        self.assertIn("OLLAMA", out)
        self.assertIn("/key <provider> <api_key>", out)

    def test_run_key_section_set_and_clear(self):
        # Set key
        stdout_trap = io.StringIO()
        with patch("sys.stdout", stdout_trap):
            self.ws.run_key_section(["groq", "gsk_test123456789abc"])
        out = stdout_trap.getvalue()
        self.assertIn("Successfully saved and persisted API key for GROQ", out)

        # Clear key
        stdout_trap = io.StringIO()
        with patch("sys.stdout", stdout_trap):
            self.ws.run_key_section(["clear", "groq"])
        out = stdout_trap.getvalue()
        self.assertIn("Successfully removed API key for GROQ", out)

    def test_cli_key_subcommand(self):
        from trithemius import main
        stdout_trap = io.StringIO()
        with patch("sys.stdout", stdout_trap):
            main(["key"])
        out = stdout_trap.getvalue()
        self.assertIn("[AI API KEYS & CLOUD PROVIDERS]", out)


if __name__ == "__main__":
    unittest.main()



