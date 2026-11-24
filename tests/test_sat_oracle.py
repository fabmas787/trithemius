"""
Unit test suite for ciphers/sat_oracle.py and constraint oracles in ciphers/interrupter.py.
Covers:
- Pure-Python DPLL/CDCL SAT solver with two-watched-literals (2WL).
- Unit propagation, conflict analysis, and backtracking/backjumping.
- Clause tracking (original, learned, blocking clauses).
- Programmatic oracle callbacks returning dynamic blocking clauses.
- Model enumeration via solve_all.
- Binary Fehu interrupt placement solver (solve_fehu_interrupts_sat).
- Ambiguous glyph candidate solver (solve_ambiguous_glyphs_sat).
"""

import unittest
import os
import sys

# Ensure repository root is on sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from ciphers.sat_oracle import SATSolver
from ciphers.interrupter import (
    FehuInterruptOracle, AmbiguousGlyphOracle,
    solve_fehu_interrupts_sat, solve_ambiguous_glyphs_sat,
    rune_vigenere_encode_f_skip, rune_vigenere_decode_f_skip,
    rune_vigenere_decode_dynamic, InterrupterConfig
)


class TestSATSolverCore(unittest.TestCase):
    """Test suite covering the core DPLL/CDCL SAT solver and watched literals."""

    def test_simple_satisfiable_formula(self):
        """Solve a satisfiable 3-variable formula."""
        solver = SATSolver(num_vars=3)
        # (v1 or v2) and (not v1 or v3) and (not v2 or not v3)
        solver.add_clause([1, 2])
        solver.add_clause([-1, 3])
        solver.add_clause([-2, -3])

        sat, model = solver.solve()
        self.assertTrue(sat)
        self.assertIsNotNone(model)

        # Verify model satisfies all clauses
        for clause in solver.original_clauses:
            self.assertTrue(any((lit > 0 and model[abs(lit)]) or (lit < 0 and not model[abs(lit)]) for lit in clause))

    def test_simple_unsatisfiable_formula(self):
        """Detect unsatisfiable contradiction: (v1) and (not v1)."""
        solver = SATSolver(num_vars=1)
        solver.add_clause([1])
        solver.add_clause([-1])

        sat, model = solver.solve()
        self.assertFalse(sat)
        self.assertIsNone(model)

    def test_unit_propagation_without_decisions(self):
        """Verify that pure unit chains are resolved via unit propagation."""
        solver = SATSolver(num_vars=3)
        # Unit clause: 1=True
        solver.add_clause([1])
        # Clause (-1 or 2): forces 2=True
        solver.add_clause([-1, 2])
        # Clause (-2 or 3): forces 3=True
        solver.add_clause([-2, 3])

        sat, model = solver.solve()
        self.assertTrue(sat)
        self.assertEqual(model, {1: True, 2: True, 3: True})
        stats = solver.get_statistics()
        # Should require 0 decisions because all are unit-propagated at level 0
        self.assertEqual(stats["decisions"], 0)
        self.assertGreaterEqual(stats["propagations"], 3)

    def test_model_enumeration_solve_all(self):
        """Enumerate all 4 satisfying assignments for 2 unconstrained variables."""
        solver = SATSolver(num_vars=2)
        models = solver.solve_all()
        self.assertEqual(len(models), 4)

        # Check all unique assignments are present
        tuples = {(m[1], m[2]) for m in models}
        self.assertEqual(tuples, {(True, True), (True, False), (False, True), (False, False)})

    def test_tautology_and_duplicate_literals(self):
        """Solver handles clauses with tautologies and duplicate literals cleanly."""
        solver = SATSolver(num_vars=2)
        # Tautology: (1 or -1)
        solver.add_clause([1, -1])
        # Duplicate literal: (2 or 2) -> unit clause 2
        solver.add_clause([2, 2])

        sat, model = solver.solve()
        self.assertTrue(sat)
        self.assertTrue(model[2])


class TestProgrammaticOracle(unittest.TestCase):
    """Test suite covering the programmatic oracle hook and dynamic blocking clauses."""

    def test_dynamic_blocking_clause_injection(self):
        """Oracle blocks a specific assignment, forcing backjumping to an alternate model."""
        solver = SATSolver(num_vars=3)
        solver.add_clause([1, 2])

        # Oracle forbids {1: True, 2: True}
        def oracle_block_both_true(partial):
            if partial.get(1) is True and partial.get(2) is True:
                # Return blocking clause: not 1 or not 2
                return [-1, -2]
            return None

        sat, model = solver.solve(oracle_fn=oracle_block_both_true)
        self.assertTrue(sat)
        # Verify not both 1 and 2 are True
        self.assertFalse(model[1] and model[2])
        # Verify blocking clause was recorded
        stats = solver.get_statistics()
        self.assertGreaterEqual(stats["blocking_clauses"], 1)
        self.assertIn([-1, -2], solver.blocking_clauses)

    def test_oracle_triggers_unsat(self):
        """Oracle that blocks all models leads to verified UNSAT."""
        solver = SATSolver(num_vars=1)

        # Oracle blocks any assignment
        def oracle_block_all(partial):
            if 1 in partial:
                return [-1] if partial[1] else [1]
            return None

        sat, model = solver.solve(oracle_fn=oracle_block_all)
        self.assertFalse(sat)
        self.assertIsNone(model)


class TestInterrupterConstraintOracles(unittest.TestCase):
    """Test suite covering FehuInterruptOracle and AmbiguousGlyphOracle in ciphers/interrupter.py."""

    def test_fehu_interrupt_schedule_recovery(self):
        """Recover exact Fehu skip schedule using solve_fehu_interrupts_sat."""
        plaintext = "ᚠᛁᚱᚠᚢᛗ"  # FIRFUM
        key = "DIVINITY"
        ciphertext, known_skips = rune_vigenere_encode_f_skip(plaintext, key)

        # Validator checks exact plaintext match
        def validator(candidate):
            return candidate == plaintext

        solutions = solve_fehu_interrupts_sat(
            ciphertext=ciphertext,
            key=key,
            validator=validator,
            max_solutions=5
        )

        self.assertEqual(len(solutions), 1)
        self.assertEqual(solutions[0]["plaintext"], plaintext)
        self.assertEqual(solutions[0]["schedule"], known_skips)

    def test_fehu_interrupt_forbidden_ngram_pruning(self):
        """Forbidden n-gram in oracle prunes invalid schedules."""
        plaintext = "ᚠᛁᚱᚠᚢᛗ"
        key = "DIVINITY"
        ciphertext, known_skips = rune_vigenere_encode_f_skip(plaintext, key)

        # Forbid the corrupt decoding that occurs when Fehu is advanced instead of skipped
        # Running with forbidden n-gram prunes without needing full validator
        solutions = solve_fehu_interrupts_sat(
            ciphertext=ciphertext,
            key=key,
            forbidden_ngrams={"ᚢᚠ"},
            max_solutions=10
        )
        for s in solutions:
            self.assertNotIn("ᚢᚠ", s["plaintext"])

    def test_ambiguous_glyphs_sat_resolution(self):
        """Resolve ambiguous runic glyph candidates using solve_ambiguous_glyphs_sat."""
        plaintext = "ᚠᛁᚱᚠᚢᛗ"
        key = "DIVINITY"
        ciphertext, skips = rune_vigenere_encode_f_skip(plaintext, key)

        # Introduce ambiguity at ciphertext index 1: candidate can be correct 'ᚱ' or incorrect 'ᛄ'
        amb_map = {1: ["ᚱ", "ᛄ"]}
        corrupted_ct = ciphertext[0] + "ᛄ" + ciphertext[2:]

        cfg = InterrupterConfig(
            interrupt_positions=skips,
            pause_on_interrupt=True,
            pass_through=True,
        )

        def validator(candidate):
            return candidate == plaintext

        solutions = solve_ambiguous_glyphs_sat(
            ciphertext=corrupted_ct,
            ambiguous_map=amb_map,
            key=key,
            validator=validator,
            config=cfg,
            max_solutions=5
        )

        self.assertEqual(len(solutions), 1)
        self.assertEqual(solutions[0]["plaintext"], plaintext)
        self.assertEqual(solutions[0]["selections"][1], "ᚱ")


if __name__ == "__main__":
    unittest.main()
