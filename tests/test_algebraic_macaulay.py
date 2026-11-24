"""
Unit tests for ciphers/algebraic.py.
Covers multivariate polynomials, DegRevLex ordering, Macaulay matrices,
Gaussian elimination over F_29 to RREF, NLFSR recurrence detection, and SageMath script export.
"""

import os
import random
import sys
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from ciphers.algebraic import (
    DEFAULT_MODULUS,
    Monomial,
    MultivariatePolynomial,
    var,
    vars,
    constant_poly,
    parse_polynomial,
    enumerate_monomials,
    build_macaulay_matrix,
    MacaulayResult,
    gaussian_elimination,
    rref,
    solve_linear_system,
    detect_nonlinear_recurrence,
    export_groebner_script,
    should_export_groebner,
)


class TestMonomialAndDegRevLex(unittest.TestCase):
    def test_monomial_creation_and_degree(self):
        m0 = Monomial.constant()
        self.assertEqual(m0.degree, 0)
        self.assertEqual(m0.total_degree(), 0)
        self.assertEqual(repr(m0), "1")
        self.assertEqual(m0.exponents, {})

        m1 = Monomial({"x0": 2, "x1": 1})
        self.assertEqual(m1.degree, 3)
        self.assertEqual(m1.get("x0"), 2)
        self.assertEqual(m1.get("x1"), 1)
        self.assertEqual(m1.get("x2"), 0)
        self.assertEqual(m1.variables(), {"x0", "x1"})

    def test_degrevlex_ordering(self):
        # Order: x > y > z
        # DegRevLex sequence for degree <= 2:
        # x^2 > xy > y^2 > xz > yz > z^2 > x > y > z > 1
        var_order = ["x", "y", "z"]
        monomials = [
            Monomial.constant(),
            Monomial({"x": 1}),
            Monomial({"y": 1}),
            Monomial({"z": 1}),
            Monomial({"x": 2}),
            Monomial({"x": 1, "y": 1}),
            Monomial({"y": 2}),
            Monomial({"x": 1, "z": 1}),
            Monomial({"y": 1, "z": 1}),
            Monomial({"z": 2}),
        ]

        # Shuffle and sort using degrevlex descending
        shuffled = list(monomials)
        rng = random.Random(42)
        rng.shuffle(shuffled)
        shuffled.sort(key=lambda m: m.degrevlex_key(var_order), reverse=True)

        expected_order_reprs = ["x^2", "x*y", "y^2", "x*z", "y*z", "z^2", "x", "y", "z", "1"]
        actual_order_reprs = [repr(m) for m in shuffled]
        self.assertEqual(actual_order_reprs, expected_order_reprs)

    def test_monomial_arithmetic_and_evaluation(self):
        m1 = Monomial({"x0": 2, "x1": 1})
        m2 = Monomial({"x1": 2, "x2": 1})

        # Product: x0^2 * x1^3 * x2
        m_prod = m1 * m2
        self.assertEqual(m_prod.exponents, {"x0": 2, "x1": 3, "x2": 1})

        # Division
        self.assertEqual(m_prod.divide(m1), m2)
        self.assertEqual(m_prod.divide(m2), m1)
        # Non-divisor returns None
        self.assertIsNone(m1.divide(m2))

        # Evaluation mod 29: x0=3, x1=5 -> 3^2 * 5 = 45 = 16 mod 29
        pt = {"x0": 3, "x1": 5}
        self.assertEqual(m1.evaluate(pt, 29), (9 * 5) % 29)


class TestMultivariatePolynomial(unittest.TestCase):
    def test_polynomial_arithmetic(self):
        x0, x1 = vars("x0", "x1", modulus=29)

        # Addition and subtraction
        p1 = x0 + 2 * x1 + 5
        p2 = 2 * x0 + 27 * x1 + 24  # 27 = -2 mod 29, 24 = -5 mod 29
        p_sum = p1 + p2
        self.assertEqual(p_sum, 3 * x0)

        # Multiplication
        # (x0 + x1) * (x0 - x1) = x0^2 - x1^2 = x0^2 + 28*x1^2 mod 29
        p_prod = (x0 + x1) * (x0 - x1)
        expected = x0**2 + 28 * (x1**2)
        self.assertEqual(p_prod, expected)

        # Powers
        p_sq = (x0 + 1) ** 2
        self.assertEqual(p_sq, x0**2 + 2 * x0 + 1)

    def test_lead_term_and_evaluation(self):
        x, y, z = vars("x", "y", "z", modulus=29)
        # In order x > y > z:
        # poly = y^2 + 5*x^2 + 3*x*y + 7
        # Lead term should be 5*x^2
        poly = y**2 + 5 * (x**2) + 3 * x * y + 7
        coeff, lead_mon = poly.lead_term(["x", "y", "z"])
        self.assertEqual(coeff, 5)
        self.assertEqual(lead_mon, Monomial({"x": 2}))

        # Evaluate at x=2, y=3, z=4:
        # 3^2 + 5*(2^2) + 3*(2*3) + 7 = 9 + 20 + 18 + 7 = 54 = 25 mod 29
        val = poly.evaluate({"x": 2, "y": 3, "z": 4})
        self.assertEqual(val, 54 % 29)

    def test_parse_polynomial(self):
        poly_str = "x0^2 + 3*x0*x1 - 5*x1 + 7"
        p = parse_polynomial(poly_str, modulus=29)
        x0, x1 = vars("x0", "x1", modulus=29)
        expected = x0**2 + 3 * x0 * x1 + 24 * x1 + 7
        self.assertEqual(p, expected)


class TestMacaulayMatrix(unittest.TestCase):
    def test_build_macaulay_matrix(self):
        x0, x1 = vars("x0", "x1", modulus=29)
        # System:
        # f1 = x0^2 + x1 + 1
        # f2 = x1^2 + 3
        # Target degree D = 3
        # Shifts of f1 (deg 2): shifts of deg <= 1 -> 1, x0, x1 (3 shifts)
        # Shifts of f2 (deg 2): shifts of deg <= 1 -> 1, x0, x1 (3 shifts)
        # Total rows = 6
        f1 = x0**2 + x1 + 1
        f2 = x1**2 + 3
        macaulay = build_macaulay_matrix([f1, f2], target_degree=3, modulus=29, var_order=["x0", "x1"])

        self.assertIsInstance(macaulay, MacaulayResult)
        self.assertEqual(len(macaulay.matrix), 6)
        self.assertEqual(len(macaulay.row_shifts), 6)

        # Monomials in 2 variables of degree <= 3:
        # Deg 0: 1
        # Deg 1: 2
        # Deg 2: 3
        # Deg 3: 4
        # Total distinct monomials = 10
        self.assertEqual(len(macaulay.column_monomials), 10)

        # Verify degrevlex descending order of columns
        var_order = ["x0", "x1"]
        col_keys = [m.degrevlex_key(var_order) for m in macaulay.column_monomials]
        self.assertEqual(col_keys, sorted(col_keys, reverse=True))

        # Check that row entries correctly reflect shifted polynomials
        for r_idx, (t, f_idx) in enumerate(macaulay.row_shifts):
            poly = [f1, f2][f_idx] * t
            for c_idx, m in enumerate(macaulay.column_monomials):
                self.assertEqual(macaulay.matrix[r_idx][c_idx], poly.coeff_of(m))


class TestGaussianEliminationAndRREF(unittest.TestCase):
    def test_rref_over_f29(self):
        # Solvable linear system:
        # 2*x + 3*y = 7 mod 29
        # 5*x + 4*y = 1 mod 29
        mat = [
            [2, 3, 7],
            [5, 4, 1],
        ]
        m_rref, pivots = gaussian_elimination(mat, modulus=29)
        self.assertEqual(pivots, [0, 1])
        # In RREF, pivots are 1 and columns eliminated
        self.assertEqual(m_rref[0][0], 1)
        self.assertEqual(m_rref[0][1], 0)
        self.assertEqual(m_rref[1][0], 0)
        self.assertEqual(m_rref[1][1], 1)

        x_val = m_rref[0][2]
        y_val = m_rref[1][2]
        self.assertEqual((2 * x_val + 3 * y_val) % 29, 7)
        self.assertEqual((5 * x_val + 4 * y_val) % 29, 1)

    def test_solve_linear_system(self):
        A = [
            [1, 2, 3],
            [4, 5, 6],
            [7, 8, 10],
        ]
        b = [1, 2, 3]
        sol = solve_linear_system(A, b, modulus=29)
        self.assertIsNotNone(sol)
        for r in range(3):
            computed = sum(A[r][c] * sol[c] for c in range(3)) % 29
            self.assertEqual(computed, b[r] % 29)

        # Inconsistent system:
        # x + y = 1
        # x + y = 2
        A_incon = [[1, 1], [1, 1]]
        b_incon = [1, 2]
        self.assertIsNone(solve_linear_system(A_incon, b_incon, modulus=29))


class TestNonlinearRecurrenceDetection(unittest.TestCase):
    def test_detect_quadratic_nlfsr(self):
        # Generate sequence via quadratic recurrence:
        # s[t+2] = s[t+1]^2 + 3*s[t] + 5 mod 29
        p = 29
        seq = [3, 7]
        for _ in range(25):
            nxt = (seq[-1] ** 2 + 3 * seq[-2] + 5) % p
            seq.append(nxt)

        res = detect_nonlinear_recurrence(seq, max_lag=3, max_degree=2, modulus=29)
        self.assertTrue(res["detected"])
        self.assertEqual(res["lag"], 2)
        self.assertEqual(res["degree"], 2)
        self.assertIn("s[t+2] = ", res["formula"])
        self.assertGreaterEqual(res["num_samples_verified"], 15)

    def test_detect_cubic_nlfsr(self):
        # Generate sequence via cubic recurrence:
        # s[t+2] = 2*s[t+1]^3 + s[t] + 7 mod 29
        p = 29
        seq = [2, 5]
        for _ in range(35):
            nxt = (2 * pow(seq[-1], 3, p) + seq[-2] + 7) % p
            seq.append(nxt)

        res = detect_nonlinear_recurrence(seq, max_lag=2, max_degree=3, modulus=29)
        self.assertTrue(res["detected"])
        self.assertEqual(res["lag"], 2)
        self.assertEqual(res["degree"], 3)

    def test_detect_linear_lfsr(self):
        # Linear recurrence:
        # s[t+3] = 5*s[t+2] + 2*s[t] mod 29
        p = 29
        seq = [1, 2, 4]
        for _ in range(20):
            nxt = (5 * seq[-1] + 2 * seq[-3]) % p
            seq.append(nxt)

        res = detect_nonlinear_recurrence(seq, max_lag=4, max_degree=1, modulus=29)
        self.assertTrue(res["detected"])
        self.assertEqual(res["lag"], 3)
        self.assertEqual(res["degree"], 1)

    def test_random_sequence_no_false_positive(self):
        # Random sequence without short recurrence should not be detected
        rng = random.Random(1337)
        seq = [rng.randint(0, 28) for _ in range(35)]
        res = detect_nonlinear_recurrence(seq, max_lag=2, max_degree=2, modulus=29, min_validation_samples=5)
        self.assertFalse(res["detected"])


class TestGroebnerScriptExporter(unittest.TestCase):
    def test_export_groebner_script(self):
        x0, x1 = vars("x0", "x1", modulus=29)
        p1 = x0**2 + 3 * x0 * x1 + 2
        p2 = x1**2 + 5
        script = export_groebner_script([p1, p2], ["x0", "x1"], modulus=29, target="sage")

        self.assertIn("GF(29)", script)
        self.assertIn("PolynomialRing", script)
        self.assertIn("order='degrevlex'", script)
        self.assertIn("f4", script)
        self.assertIn("fglm", script)
        self.assertIn("variety", script)

    def test_should_export_groebner(self):
        self.assertFalse(should_export_groebner(target_degree=2, col_count=100))
        self.assertFalse(should_export_groebner(target_degree=3, col_count=1500))
        self.assertTrue(should_export_groebner(target_degree=4, col_count=100))
        self.assertTrue(should_export_groebner(target_degree=2, col_count=2001))


if __name__ == "__main__":
    unittest.main()
