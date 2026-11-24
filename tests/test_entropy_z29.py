import math
import random
import unittest
from ciphers.entropy import (
    shannon_entropy,
    miller_madow_entropy,
    normalized_entropy,
    detect_alphabet_size,
    extract_signal_features,
)


class TestEntropyZ29(unittest.TestCase):
    def test_detect_alphabet_size_and_separators(self):
        runes_with_separators = "ᚹᛖᛚᚳᚩᛗᛖ᛫ᛈᛁᛚᚷᚱᛁᛗᛋ᛬ᛏᚩ᛭ᚦᛁᛋ"
        latin = "WELCOME PILGRIMS TO THIS JOURNEY"
        raw_hex = "4a5f89c2b1e47d039f826194ac52e01b3301a74d"
        self.assertEqual(detect_alphabet_size(runes_with_separators), 29)
        self.assertEqual(detect_alphabet_size(latin), 26)
        self.assertEqual(detect_alphabet_size(raw_hex), 16)

    def test_separators_do_not_inflate_runic_symbol_count(self):
        # 6 distinct runes + separators: unique count m should be strictly 6
        runic = "ᚠ᛫ᚢ᛬ᚦ᛭ᚩ᛫ᚱ᛬ᚳ"
        h_mm = miller_madow_entropy(runic, alphabet_size=29)
        self.assertLessEqual(h_mm, math.log2(29))

    def test_miller_madow_short_sample_clamped(self):
        # 29 distinct runes -> H_MM must not exceed log2(29)
        all_runes = "ᚠᚢᚦᚩᚱᚳᚷᚹᚺᚾᛁᛄᛇᛈᛉᛋᛏᛒᛖᛗᛚᛜᛞᛟᚪᚫᚣᛡᛠ"
        h1 = shannon_entropy(all_runes, alphabet_size=29)
        h_mm = miller_madow_entropy(all_runes, alphabet_size=29)
        self.assertAlmostEqual(h1, math.log2(29), places=3)
        self.assertAlmostEqual(h_mm, math.log2(29), places=3)

    def test_runic_otp_vs_natural_classification(self):
        rng = random.Random(3301)
        runes_list = list("ᚠᚢᚦᚩᚱᚳᚷᚹᚺᚾᛁᛄᛇᛈᛉᛋᛏᛒᛖᛗᛚᛜᛞᛟᚪᚫᚣᛡᛠ")
        otp_sample = "".join(rng.choice(runes_list) for _ in range(400))
        feat_otp = extract_signal_features(otp_sample)
        self.assertIn(feat_otp["classification"], ("high_entropy_runic_stream", "runic_payload"))
        self.assertGreater(feat_otp["normalized_entropy"], 0.95)


if __name__ == "__main__":
    unittest.main()
