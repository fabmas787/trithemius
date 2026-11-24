import unittest
from ciphers.al_kindi import (
    reduced_chi_squared,
    kl_divergence_english,
    chi_squared_p_value,
    is_plausible_english,
)


class TestAlKindiStatisticalRigor(unittest.TestCase):
    def test_kl_divergence_non_negative_and_invariant(self):
        english_short = "WELCOME PILGRIMS ON THE SACRED PATH OF WISDOM AND TRUTH"
        english_long = english_short * 15
        kl_short = kl_divergence_english(english_short)
        kl_long = kl_divergence_english(english_long)
        self.assertGreaterEqual(kl_short, 0.0)
        self.assertGreaterEqual(kl_long, 0.0)
        self.assertAlmostEqual(kl_short, kl_long, places=3)
        self.assertLess(kl_short, 0.45)

    def test_reduced_chi_squared(self):
        english = "WELCOME PILGRIMS ON THE SACRED PATH OF WISDOM AND TRUTH"
        chi2_red = reduced_chi_squared(english)
        self.assertLess(chi2_red, 5.0)

    def test_wilson_hilferty_p_value(self):
        p_mid = chi_squared_p_value(25.0, df=25)
        self.assertGreater(p_mid, 0.40)
        self.assertLess(p_mid, 0.60)
        p_extreme = chi_squared_p_value(200.0, df=25)
        self.assertLess(p_extreme, 1e-5)

    def test_composite_gatekeeper_verdict(self):
        valid = "THE PRESERVATION OF ALL THINGS IS ROOTED IN THE DIVINE PRIMES"
        gibberish = "XQZJVKWPLMBNFGHTYUIOPAZXCVBNMQ"
        passed_v, met_v = is_plausible_english(valid)
        passed_g, met_g = is_plausible_english(gibberish)
        self.assertTrue(passed_v)
        self.assertEqual(met_v["verdict"], "PLAUSIBLE")
        self.assertFalse(passed_g)
        self.assertIn(met_g["verdict"], ("REJECT", "IMPLAUSIBLE"))

    def test_long_text_not_rejected_by_chi2_scaling(self):
        sample = "WELCOME PILGRIMS TO THIS GREAT JOURNEY A WARNING BELIEVE NOTHING FROM THIS BOOK EXCEPT WHAT YOU KNOW TO BE TRUE " * 15
        self.assertGreater(len(sample), 800)
        passed, metrics = is_plausible_english(sample)
        self.assertTrue(passed)
        self.assertEqual(metrics["verdict"], "PLAUSIBLE")


if __name__ == "__main__":
    unittest.main()
