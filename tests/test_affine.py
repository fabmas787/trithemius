"""
Unit tests for ciphers/affine.py group closures and semantic canonical normal forms.
"""

import unittest
import random
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from ciphers.affine import (
    MOD,
    ATBASH,
    IDENTITY,
    shift,
    affine_map,
    compose,
    canonical,
    apply,
    invert,
    closure,
)


class TestAffineGroup(unittest.TestCase):
    def test_atbash_is_involution(self):
        # Atbash composed with itself is Identity
        comp = compose(ATBASH, ATBASH)
        self.assertEqual(comp, IDENTITY)
        for x in range(MOD):
            self.assertEqual(apply(comp, x), x)
            self.assertEqual(apply(ATBASH, apply(ATBASH, x)), x)

    def test_shift_group_order(self):
        # All 28 shifts generate cyclic group C29 of size 29
        shifts = [shift(b) for b in range(1, MOD)]
        self.assertEqual(closure(shifts), 29)

    def test_dihedral_group_d29_order(self):
        # Atbash + all shifts generate dihedral group D29 of size 58
        generators = [ATBASH] + [shift(b) for b in range(1, MOD)]
        self.assertEqual(closure(generators), 58)

    def test_canonical_pipeline_equivalence(self):
        rng = random.Random(42)
        all_gens = [ATBASH] + [shift(b) for b in range(MOD)]

        # Generate random 4-stage pipeline
        pipeline = [rng.choice(all_gens) for _ in range(4)]
        norm_form = canonical(pipeline)

        # Normal form must produce identical result for all 29 symbols
        for x in range(MOD):
            y_pipe = x
            for g in pipeline:
                y_pipe = apply(g, y_pipe)
            y_norm = apply(norm_form, x)
            self.assertEqual(y_pipe, y_norm)

    def test_inverse_mapping(self):
        m = affine_map(7, 13)
        m_inv = invert(m)
        self.assertEqual(compose(m_inv, m), IDENTITY)
        self.assertEqual(compose(m, m_inv), IDENTITY)


if __name__ == "__main__":
    unittest.main()
