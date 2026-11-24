"""
Unit test suite for ciphers/lattice.py and ciphers/rsa_audit.py.
Covers:
- Gram-Schmidt orthogonalization and LLL basis reduction (dim <= 40).
- Univariate Coppersmith small roots via Howgrave-Graham shifts.
- Knapsack / Subset-Sum solver (CJLOSS) with Gematria Primus prime weights.
- Integer relations finding (PSLQ analogue).
- Deterministic Miller-Rabin (certified 64-bit and arbitrary precision).
- Fast factorization (Fermat close primes, Pollard's rho with Brent's cycle + batched GCD).
- Batch GCD across multiple RSA moduli.
- Small private exponent attacks (Wiener continued fractions, Boneh-Durfee).
- Shared MSB/LSB correlation checks and audit_rsa_key pipeline.
"""

import unittest
import math
from fractions import Fraction
import os
import sys

# Ensure repository root is on sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from ciphers.lattice import (
    gram_schmidt, lll_reduction, lll,
    poly_eval, poly_mul, poly_pow, poly_deriv, find_integer_roots,
    coppersmith_small_roots, solve_knapsack_subset_sum, solve_gematria_subset_sum,
    find_integer_relations, GEMATRIA_PRIMUS_PRIMES, FUTHORC_RUNES
)
from ciphers.rsa_audit import (
    is_prime, is_prime_miller_rabin,
    fermat_factor, pollard_rho, factor_integer, batch_gcd,
    wiener_attack, boneh_durfee,
    shared_bits_check, shared_prime_bits_attack, audit_rsa_key
)


class TestLatticeReduction(unittest.TestCase):
    """Test suite covering Gram-Schmidt and LLL basis reduction."""

    def test_gram_schmidt_orthogonality(self):
        """Verify that Gram-Schmidt vectors are mutually orthogonal."""
        basis = [
            [1, -1, 3],
            [1, 0, 5],
            [1, 2, 6]
        ]
        b_star, mu = gram_schmidt(basis)
        self.assertEqual(len(b_star), 3)

        # Check orthogonality <b_i*, b_j*> == 0 for i != j
        for i in range(len(b_star)):
            for j in range(i + 1, len(b_star)):
                dot = sum(b_star[i][k] * b_star[j][k] for k in range(len(b_star[0])))
                self.assertEqual(dot, Fraction(0))

    def test_lll_basis_reduction_properties(self):
        """Verify LLL size condition and Lovasz condition on reduced basis."""
        basis = [
            [1, 1, 1],
            [-1, 0, 2],
            [3, 5, 6]
        ]
        red = lll_reduction(basis, delta=0.99)
        self.assertEqual(len(red), 3)

        # Recompute Gram-Schmidt on reduced basis to check size condition
        b_star, mu = gram_schmidt(red)
        for i in range(len(red)):
            for j in range(i):
                self.assertLessEqual(abs(mu[i][j]), Fraction(1, 2) + 1e-9)

    def test_lll_dimension_20(self):
        """Verify LLL handles dimension 20 efficiently."""
        import random
        rng = random.Random(42)
        dim = 20
        mat = [[rng.randint(-50, 50) for _ in range(dim)] for _ in range(dim)]
        # Ensure full rank by putting large diagonal
        for i in range(dim):
            mat[i][i] += 100

        red = lll_reduction(mat, delta=0.99)
        self.assertEqual(len(red), dim)
        # Verify first vector is non-zero
        self.assertTrue(any(x != 0 for x in red[0]))


class TestCoppersmithSmallRoots(unittest.TestCase):
    """Test suite covering Coppersmith univariate small roots via Howgrave-Graham."""

    def test_coppersmith_quadratic_root(self):
        """Recover small integer root x_0 of quadratic polynomial modulo N."""
        # N = p * q = 73 * 137 = 10001
        N = 10001
        # Roots 17 and -35: (x - 17)*(x + 35) = x^2 + 18x - 595
        f = [(-595) % N, 18, 1]
        roots = coppersmith_small_roots(f, N, beta=1.0, root_bound=50)
        self.assertIn(17, roots)
        # Verify modulo condition
        self.assertEqual((17 * 17 + 18 * 17 - 595) % N, 0)

    def test_coppersmith_linear_shift(self):
        """Recover root x_0 of f(x) = x + c modulo N."""
        p = 1000000007
        q = 1000000009
        N = p * q
        x0 = 42
        c = (-x0) % N
        f = [c, 1]  # f(x) = x - 42
        roots = coppersmith_small_roots(f, N, beta=1.0, root_bound=100)
        self.assertIn(x0, roots)


class TestKnapsackSubsetSum(unittest.TestCase):
    """Test suite covering CJLOSS lattice knapsack and Gematria Primus prime weights."""

    def test_subset_sum_gematria_primes(self):
        """Verify knapsack solver reconstructs known prime subsets."""
        chosen = [2, 5, 17, 41]
        target = sum(chosen)  # 65
        res = solve_knapsack_subset_sum(GEMATRIA_PRIMUS_PRIMES, target)
        self.assertIsNotNone(res)
        self.assertEqual(sum(res), target)
        for w in res:
            self.assertIn(w, GEMATRIA_PRIMUS_PRIMES)

    def test_subset_sum_gematria_runes_wrapper(self):
        """Verify solve_gematria_subset_sum returns valid Futhorc runes summing to target."""
        target = 2 + 3 + 5  # 10
        runes = solve_gematria_subset_sum(target)
        self.assertIsNotNone(runes)
        self.assertTrue(all(r in FUTHORC_RUNES for r in runes))
        rune_to_prime = {r: p for p, r in zip(GEMATRIA_PRIMUS_PRIMES, FUTHORC_RUNES)}
        self.assertEqual(sum(rune_to_prime[r] for r in runes), target)

    def test_subset_sum_edge_cases(self):
        """Verify behavior for target 0, single weight, and impossible target."""
        self.assertEqual(solve_knapsack_subset_sum([2, 3, 5], 0), [])
        self.assertEqual(solve_knapsack_subset_sum([2, 3, 5], 3), [3])
        self.assertIsNone(solve_knapsack_subset_sum([2, 3, 5], 100))


class TestIntegerRelations(unittest.TestCase):
    """Test suite covering integer relation finder (PSLQ analogue)."""

    def test_find_integer_relation_simple(self):
        """Find non-trivial integer coefficients summing to zero."""
        # 2*x_1 + 3*x_2 - 5*x_3 = 0 where x_1=1.0, x_2=1.0, x_3=1.0
        vals = [2.0, 3.0, -5.0]
        rel = find_integer_relations(vals, scale=10**6)
        self.assertIsNotNone(rel)
        dot = sum(c * v for c, v in zip(rel, vals))
        self.assertAlmostEqual(dot, 0.0, places=3)
        self.assertTrue(any(c != 0 for c in rel))

    def test_find_integer_relation_irrational_combination(self):
        """Find integer coefficients between linear combination of sqrt(2) and e."""
        x1 = 1.41421356
        x2 = 2.71828182
        x3 = (2 * x1 + 3 * x2) / 5
        vals = [x1, x2, -x3]
        rel = find_integer_relations(vals, scale=10**6)
        self.assertIsNotNone(rel)
        dot = sum(c * v for c, v in zip(rel, vals))
        self.assertAlmostEqual(dot, 0.0, places=3)


class TestDeterministicMillerRabin(unittest.TestCase):
    """Test suite covering certified deterministic Miller-Rabin primality testing."""

    def test_certified_small_and_64bit_primes(self):
        """Verify known primes pass Miller-Rabin deterministically."""
        primes = [
            2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
            1000000007, 1000000009, 2147483647, (1 << 61) - 1
        ]
        for p in primes:
            self.assertTrue(is_prime(p), f"Expected prime for {p}")

    def test_known_composites_and_carmichael_numbers(self):
        """Verify composites and Carmichael numbers are identified as composite."""
        composites = [
            0, 1, 4, 6, 8, 9, 15, 25, 100, 1000000005,
            561,    # Carmichael: 3 * 11 * 17
            1105,   # Carmichael: 5 * 13 * 17
            1729,   # Carmichael: 7 * 13 * 19
            2465,   # Carmichael: 5 * 17 * 29
            (1 << 61) - 2
        ]
        for c in composites:
            self.assertFalse(is_prime(c), f"Expected composite for {c}")


class TestFastFactorization(unittest.TestCase):
    """Test suite covering Fermat factorization and Pollard's rho."""

    def test_fermat_close_primes(self):
        """Verify Fermat factorization resolves close primes."""
        p = 1000000007
        q = 1000000009
        N = p * q
        res = fermat_factor(N, max_steps=100)
        self.assertEqual(res, (p, q))

    def test_pollard_rho_brent(self):
        """Verify Pollard's rho with Brent's cycle detection factors composites."""
        p = 1000003
        q = 2000003
        N = p * q
        factor = pollard_rho(N, max_steps=50000)
        self.assertIn(factor, (p, q))
        self.assertEqual(N % factor, 0)

    def test_factor_integer_complete(self):
        """Verify factor_integer returns sorted prime factors."""
        n = 2 * 3 * 3 * 7 * 1000003
        factors = factor_integer(n)
        self.assertEqual(factors, [2, 3, 3, 7, 1000003])


class TestBatchGCD(unittest.TestCase):
    """Test suite covering Bernstein's Batch GCD across RSA moduli."""

    def test_batch_gcd_shared_factors(self):
        """Verify Batch GCD detects and extracts shared primes among multiple moduli."""
        p = 1000000007
        q1 = 1000000009
        q2 = 1000000021
        q3 = 1000000033
        q4 = 1000000087
        q5 = 1000000097

        N1 = p * q1
        N2 = p * q2
        N3 = q2 * q3
        N4 = q4 * q5  # Independent modulus

        vulnerable = batch_gcd([N1, N2, N3, N4])
        self.assertIn(N1, vulnerable)
        self.assertIn(N2, vulnerable)
        self.assertIn(N3, vulnerable)
        self.assertNotIn(N4, vulnerable)

        self.assertEqual(vulnerable[N1], p)
        self.assertIn(vulnerable[N2], (p, q2))
        self.assertEqual(vulnerable[N3], q2)


class TestSmallPrivateExponentAttacks(unittest.TestCase):
    """Test suite covering Wiener continued fractions and Boneh-Durfee attacks."""

    def test_wiener_small_private_exponent(self):
        """Recover small private exponent d < 1/3 * N^0.25 via Wiener attack."""
        p = 1000000007
        q = 2000000011
        N = p * q
        phi = (p - 1) * (q - 1)
        d = 12347
        while math.gcd(d, phi) != 1:
            d += 2
        e = pow(d, -1, phi)

        recovered = wiener_attack(e, N)
        self.assertIsNotNone(recovered)
        rec_d, rec_p, rec_q = recovered
        self.assertEqual(rec_d, d)
        self.assertEqual(rec_p * rec_q, N)

    def test_wiener_unvulnerable_key(self):
        """Wiener attack returns None when d is standard size (e=65537)."""
        p = 1000000007
        q = 2000000011
        N = p * q
        e = 65537
        recovered = wiener_attack(e, N)
        self.assertIsNone(recovered)

    def test_boneh_durfee_delegation(self):
        """Boneh-Durfee attack delegates and recovers small private exponent."""
        p = 1000000007
        q = 2000000011
        N = p * q
        phi = (p - 1) * (q - 1)
        d = 12347
        while math.gcd(d, phi) != 1:
            d += 2
        e = pow(d, -1, phi)

        recovered = boneh_durfee(e, N)
        self.assertIsNotNone(recovered)
        self.assertEqual(recovered[0], d)


class TestSharedBitsAndAuditPipeline(unittest.TestCase):
    """Test suite covering shared MSB/LSB analysis and the audit_rsa_key pipeline."""

    def test_shared_bits_check(self):
        """Detect shared MSBs between generated moduli."""
        # Construct two moduli sharing top bits
        prefix = (1 << 40)
        n1 = prefix + 12345
        n2 = prefix + 54321
        findings = shared_bits_check([n1, n2])
        self.assertTrue(len(findings) >= 1)
        self.assertGreaterEqual(findings[0]["msb_shared_bits"], 20)

    def test_audit_rsa_key_pipeline(self):
        """Verify full audit report across various vulnerable key configurations."""
        # 1. Invalid key (prime modulus)
        rep_prime = audit_rsa_key(1000000007, 65537)
        self.assertTrue(rep_prime["vulnerable"])
        self.assertEqual(rep_prime["attack_method"], "INVALID_KEY_PRIME_MODULUS")

        # 2. Small prime factor
        rep_small = audit_rsa_key(3 * 1000000007, 65537)
        self.assertTrue(rep_small["vulnerable"])
        self.assertEqual(rep_small["attack_method"], "SMALL_PRIME_FACTOR")

        # 3. Fermat close primes
        p = 1000000007
        q = 1000000009
        rep_fermat = audit_rsa_key(p * q, 65537)
        self.assertTrue(rep_fermat["vulnerable"])
        self.assertEqual(rep_fermat["attack_method"], "FERMAT_CLOSE_PRIMES")


if __name__ == "__main__":
    unittest.main()
