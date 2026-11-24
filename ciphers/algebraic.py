"""
Algebraic Cryptanalysis via Macaulay Matrices, XL, and NLFSR Recurrence Recovery over F_29.
Standard library only: math, itertools, typing, collections. Zero external dependencies.

Features:
- Multivariate polynomials in F_p[x_1, ..., x_n] with DEGREVLEX monomial ordering and sparse exponent dicts.
- Macaulay matrix construction: monomial shifts up to target degree D with degrevlex column ordering.
- Gaussian elimination over F_p to Reduced Row Echelon Form (RREF) using a modular inverse table.
- Nonlinear recurrence detection (NLFSR): recovers quadratic/cubic feedback polynomials from sequence data.
- SageMath / FGLM Gröbner script exporter when D > 3 or Macaulay matrix columns > 2000.
"""

from __future__ import annotations

import itertools
import math
import re
from typing import Any, Dict, FrozenSet, Iterator, List, Mapping, NamedTuple, Optional, Sequence, Set, Tuple, Union

DEFAULT_MODULUS = 29

# Precomputed modular inverse table for F_29
_INV_29 = [0] * 29
for _i in range(1, 29):
    _INV_29[_i] = pow(_i, 27, 29)


def get_inv_table(modulus: int) -> List[int]:
    """Get or compute inverse table for F_p."""
    if modulus == 29:
        return _INV_29
    table = [0] * modulus
    for i in range(1, modulus):
        table[i] = pow(i, modulus - 2, modulus)
    return table


# =====================================================================
# Monomial Class with Sparse Exponents & DegRevLex Ordering
# =====================================================================

class Monomial:
    """
    Sparse representation of a multivariate monomial.
    Stored internally as a canonical tuple of (var_name, exponent) pairs with exponent > 0.
    """

    __slots__ = ("_exponents", "_degree", "_hash")

    def __init__(self, exponents: Optional[Union[Mapping[str, int], Sequence[Tuple[str, int]]]] = None):
        if exponents is None:
            self._exponents: Tuple[Tuple[str, int], ...] = ()
            self._degree: int = 0
        elif isinstance(exponents, dict):
            cleaned = tuple(sorted((k, v) for k, v in exponents.items() if v > 0))
            self._exponents = cleaned
            self._degree = sum(v for _, v in cleaned)
        elif isinstance(exponents, (list, tuple)):
            cleaned = tuple(sorted((k, v) for k, v in exponents if v > 0))
            self._exponents = cleaned
            self._degree = sum(v for _, v in cleaned)
        else:
            raise TypeError(f"Invalid exponents type: {type(exponents)}")

        self._hash: int = hash(self._exponents)

    @classmethod
    def constant(cls) -> Monomial:
        """Return the constant monomial 1."""
        return cls()

    @classmethod
    def single_var(cls, var_name: str, exp: int = 1) -> Monomial:
        """Return a single variable monomial var_name^exp."""
        if exp <= 0:
            return cls.constant()
        return cls({var_name: exp})

    @property
    def exponents(self) -> Dict[str, int]:
        """Return sparse exponent dict."""
        return dict(self._exponents)

    @property
    def degree(self) -> int:
        """Total degree (sum of exponents)."""
        return self._degree

    def total_degree(self) -> int:
        """Total degree (sum of exponents)."""
        return self._degree

    def get(self, var_name: str, default: int = 0) -> int:
        """Get exponent for a specific variable."""
        for k, v in self._exponents:
            if k == var_name:
                return v
        return default

    def variables(self) -> Set[str]:
        """Set of variable names with non-zero exponents."""
        return {k for k, _ in self._exponents}

    def degrevlex_key(self, var_order: Sequence[str]) -> Tuple[int, Tuple[int, ...]]:
        """
        DegRevLex comparison key for sorting in descending order:
        Total degree D is primary;
        Tie-breaker: reverse variable exponents negated, so smaller exponent at
        later variables produces a larger key (hence sorts earlier).
        """
        exp_dict = dict(self._exponents)
        rev_neg = tuple(-exp_dict.get(v, 0) for v in reversed(var_order))
        return (self._degree, rev_neg)

    def multiply(self, other: Monomial) -> Monomial:
        """Multiply two monomials: add exponents."""
        d1 = dict(self._exponents)
        for k, v in other._exponents:
            d1[k] = d1.get(k, 0) + v
        return Monomial(d1)

    def __mul__(self, other: Monomial) -> Monomial:
        if not isinstance(other, Monomial):
            return NotImplemented
        return self.multiply(other)

    def divide(self, other: Monomial) -> Optional[Monomial]:
        """Divide self by other. Returns quotient Monomial if other divides self, else None."""
        d1 = dict(self._exponents)
        for k, v in other._exponents:
            curr = d1.get(k, 0)
            if curr < v:
                return None
            if curr == v:
                del d1[k]
            else:
                d1[k] = curr - v
        return Monomial(d1)

    def evaluate(self, point: Mapping[str, int], modulus: int = DEFAULT_MODULUS) -> int:
        """Evaluate monomial at point mod p."""
        res = 1
        for k, v in self._exponents:
            val = point.get(k, 0) % modulus
            res = (res * pow(val, v, modulus)) % modulus
        return res

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Monomial):
            return False
        return self._exponents == other._exponents

    def __hash__(self) -> int:
        return self._hash

    def __repr__(self) -> str:
        if not self._exponents:
            return "1"
        parts = []
        for k, v in self._exponents:
            if v == 1:
                parts.append(k)
            else:
                parts.append(f"{k}^{v}")
        return "*".join(parts)


# =====================================================================
# Multivariate Polynomial in F_p[x_1, ..., x_n]
# =====================================================================

class MultivariatePolynomial:
    """
    Multivariate polynomial over F_p represented as a sparse map: Monomial -> coefficient.
    Non-zero coefficients are kept reduced modulo p in {1, ..., p-1}.
    """

    def __init__(
        self,
        terms: Optional[Mapping[Union[Monomial, str, Dict[str, int]], int]] = None,
        modulus: int = DEFAULT_MODULUS,
    ):
        self.modulus: int = modulus
        self._terms: Dict[Monomial, int] = {}

        if terms:
            for m_key, coeff in terms.items():
                if isinstance(m_key, Monomial):
                    mon = m_key
                elif isinstance(m_key, str):
                    mon = Monomial({m_key: 1})
                elif isinstance(m_key, dict):
                    mon = Monomial(m_key)
                else:
                    raise TypeError(f"Invalid monomial key type: {type(m_key)}")

                c_mod = coeff % modulus
                if c_mod != 0:
                    self._terms[mon] = (self._terms.get(mon, 0) + c_mod) % modulus
                    if self._terms[mon] == 0:
                        del self._terms[mon]

    @property
    def terms(self) -> Dict[Monomial, int]:
        """Return shallow copy of terms dict."""
        return dict(self._terms)

    def is_zero(self) -> bool:
        """Check if polynomial is the zero polynomial."""
        return len(self._terms) == 0

    def total_degree(self) -> int:
        """Return total degree of polynomial, or 0 if zero polynomial."""
        if not self._terms:
            return 0
        return max(m.degree for m in self._terms.keys())

    def variables(self) -> Set[str]:
        """Return all variable names appearing in polynomial."""
        res: Set[str] = set()
        for m in self._terms.keys():
            res.update(m.variables())
        return res

    def lead_term(self, var_order: Sequence[str]) -> Tuple[int, Monomial]:
        """Return (coefficient, lead_monomial) according to degrevlex ordering."""
        if not self._terms:
            return (0, Monomial.constant())
        best_mon = max(self._terms.keys(), key=lambda m: m.degrevlex_key(var_order))
        return (self._terms[best_mon], best_mon)

    def lead_monomial(self, var_order: Sequence[str]) -> Monomial:
        """Return lead monomial according to degrevlex ordering."""
        return self.lead_term(var_order)[1]

    def lead_coeff(self, var_order: Sequence[str]) -> int:
        """Return lead coefficient according to degrevlex ordering."""
        return self.lead_term(var_order)[0]

    def coeff_of(self, monomial: Monomial) -> int:
        """Return coefficient of given monomial."""
        return self._terms.get(monomial, 0)

    def evaluate(self, point: Mapping[str, int]) -> int:
        """Evaluate polynomial at point mod p."""
        total = 0
        for m, c in self._terms.items():
            total = (total + c * m.evaluate(point, self.modulus)) % self.modulus
        return total

    # Arithmetic operations
    def __add__(self, other: Union[MultivariatePolynomial, int]) -> MultivariatePolynomial:
        if isinstance(other, int):
            new_terms = dict(self._terms)
            c_mon = Monomial.constant()
            new_terms[c_mon] = (new_terms.get(c_mon, 0) + other) % self.modulus
            return MultivariatePolynomial(new_terms, modulus=self.modulus)

        if not isinstance(other, MultivariatePolynomial):
            return NotImplemented

        if self.modulus != other.modulus:
            raise ValueError(f"Mismatched moduli: {self.modulus} vs {other.modulus}")

        new_terms = dict(self._terms)
        for m, c in other._terms.items():
            new_terms[m] = (new_terms.get(m, 0) + c) % self.modulus
        return MultivariatePolynomial(new_terms, modulus=self.modulus)

    def __radd__(self, other: int) -> MultivariatePolynomial:
        return self.__add__(other)

    def __sub__(self, other: Union[MultivariatePolynomial, int]) -> MultivariatePolynomial:
        if isinstance(other, int):
            return self.__add__(-other)

        if not isinstance(other, MultivariatePolynomial):
            return NotImplemented

        if self.modulus != other.modulus:
            raise ValueError(f"Mismatched moduli: {self.modulus} vs {other.modulus}")

        new_terms = dict(self._terms)
        for m, c in other._terms.items():
            new_terms[m] = (new_terms.get(m, 0) - c) % self.modulus
        return MultivariatePolynomial(new_terms, modulus=self.modulus)

    def __rsub__(self, other: int) -> MultivariatePolynomial:
        return (-self).__add__(other)

    def __neg__(self) -> MultivariatePolynomial:
        new_terms = {m: (self.modulus - c) % self.modulus for m, c in self._terms.items()}
        return MultivariatePolynomial(new_terms, modulus=self.modulus)

    def __mul__(self, other: Union[MultivariatePolynomial, Monomial, int]) -> MultivariatePolynomial:
        if isinstance(other, int):
            c_mod = other % self.modulus
            if c_mod == 0:
                return MultivariatePolynomial({}, modulus=self.modulus)
            new_terms = {m: (c * c_mod) % self.modulus for m, c in self._terms.items()}
            return MultivariatePolynomial(new_terms, modulus=self.modulus)

        if isinstance(other, Monomial):
            new_terms = {m * other: c for m, c in self._terms.items()}
            return MultivariatePolynomial(new_terms, modulus=self.modulus)

        if isinstance(other, MultivariatePolynomial):
            if self.modulus != other.modulus:
                raise ValueError(f"Mismatched moduli: {self.modulus} vs {other.modulus}")
            new_terms: Dict[Monomial, int] = {}
            for m1, c1 in self._terms.items():
                for m2, c2 in other._terms.items():
                    m_prod = m1 * m2
                    prod_coeff = (c1 * c2) % self.modulus
                    new_terms[m_prod] = (new_terms.get(m_prod, 0) + prod_coeff) % self.modulus
            return MultivariatePolynomial(new_terms, modulus=self.modulus)

        return NotImplemented

    def __rmul__(self, other: Union[int, Monomial]) -> MultivariatePolynomial:
        return self.__mul__(other)

    def __pow__(self, exponent: int) -> MultivariatePolynomial:
        if exponent < 0:
            raise ValueError("Negative exponents not supported for polynomials")
        if exponent == 0:
            return MultivariatePolynomial({Monomial.constant(): 1}, modulus=self.modulus)

        result = MultivariatePolynomial({Monomial.constant(): 1}, modulus=self.modulus)
        base = self
        e = exponent
        while e > 0:
            if e % 2 == 1:
                result = result * base
            base = base * base
            e //= 2
        return result

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, MultivariatePolynomial):
            return False
        return self.modulus == other.modulus and self._terms == other._terms

    def format(self, var_order: Optional[Sequence[str]] = None) -> str:
        """Format polynomial in degrevlex order."""
        if not self._terms:
            return "0"

        order = list(var_order) if var_order else sorted(self.variables())
        sorted_mons = sorted(self._terms.keys(), key=lambda m: m.degrevlex_key(order), reverse=True)

        parts = []
        for m in sorted_mons:
            c = self._terms[m]
            m_str = repr(m)
            if m_str == "1":
                parts.append(str(c))
            elif c == 1:
                parts.append(m_str)
            else:
                parts.append(f"{c}*{m_str}")
        return " + ".join(parts)

    def __repr__(self) -> str:
        return self.format()


# =====================================================================
# Factory Constructors
# =====================================================================

def var(name: str, modulus: int = DEFAULT_MODULUS) -> MultivariatePolynomial:
    """Create a single-variable polynomial x."""
    return MultivariatePolynomial({Monomial.single_var(name): 1}, modulus=modulus)


def vars(*names: str, modulus: int = DEFAULT_MODULUS) -> Tuple[MultivariatePolynomial, ...]:
    """Create multiple variable polynomials."""
    return tuple(var(n, modulus=modulus) for n in names)


def constant_poly(c: int, modulus: int = DEFAULT_MODULUS) -> MultivariatePolynomial:
    """Create a constant polynomial."""
    return MultivariatePolynomial({Monomial.constant(): c}, modulus=modulus)


def parse_polynomial(expr: str, modulus: int = DEFAULT_MODULUS) -> MultivariatePolynomial:
    """
    Parse a polynomial expression like 'x0^2 + 3*x0*x1 - 2*x1 + 7'.
    """
    # Clean up whitespace and standardize signs
    cleaned = expr.replace(" ", "").replace("-", "+-")
    tokens = [t for t in cleaned.split("+") if t]

    poly = MultivariatePolynomial({}, modulus=modulus)
    for tok in tokens:
        # Match sign and coefficient
        m = re.match(r"^([+-]?\d+)?(?:\*)?(.*)$", tok)
        if not m:
            continue
        coeff_str, var_part = m.groups()
        if not coeff_str or coeff_str == "+":
            coeff = 1
        elif coeff_str == "-":
            coeff = -1
        else:
            coeff = int(coeff_str)

        if not var_part:
            # Constant term
            poly = poly + coeff
            continue

        # Parse factors in var_part: e.g. x0^2*x1
        factor_tokens = var_part.split("*")
        exp_dict: Dict[str, int] = {}
        for f in factor_tokens:
            if "^" in f:
                v_name, exp_s = f.split("^", 1)
                exp_dict[v_name] = exp_dict.get(v_name, 0) + int(exp_s)
            else:
                exp_dict[f] = exp_dict.get(f, 0) + 1

        term_poly = MultivariatePolynomial({Monomial(exp_dict): coeff}, modulus=modulus)
        poly = poly + term_poly

    return poly


# =====================================================================
# Monomial Enumerator
# =====================================================================

def enumerate_monomials(
    variables: Sequence[str],
    max_degree: int,
    var_order: Optional[Sequence[str]] = None,
) -> List[Monomial]:
    """
    Generate all monomials in given variables up to max_degree,
    ordered in descending DEGREVLEX order.
    """
    order = list(var_order) if var_order else list(variables)
    monomials: List[Monomial] = [Monomial.constant()]

    for d in range(1, max_degree + 1):
        for combo in itertools.combinations_with_replacement(order, d):
            exp_dict: Dict[str, int] = {}
            for v in combo:
                exp_dict[v] = exp_dict.get(v, 0) + 1
            monomials.append(Monomial(exp_dict))

    # Sort descending by degrevlex
    monomials.sort(key=lambda m: m.degrevlex_key(order), reverse=True)
    return monomials


# =====================================================================
# Macaulay Matrix Construction
# =====================================================================

class MacaulayResult(NamedTuple):
    matrix: List[List[int]]
    column_monomials: List[Monomial]
    row_shifts: List[Tuple[Monomial, int]]
    row_polynomials: List[MultivariatePolynomial]
    target_degree: int
    modulus: int
    var_order: List[str]


def build_macaulay_matrix(
    polynomials: Sequence[MultivariatePolynomial],
    target_degree: int,
    modulus: int = DEFAULT_MODULUS,
    var_order: Optional[Sequence[str]] = None,
) -> MacaulayResult:
    """
    Construct the Macaulay matrix for a system of polynomials up to target_degree D:
    1. For each polynomial f_i of degree d_i <= D:
       Generate all monomial shifts t * f_i for deg(t) <= D - d_i.
    2. Collect all distinct monomials appearing across all shifted polynomials.
    3. Order columns in descending DEGREVLEX ordering.
    4. Fill matrix entries with polynomial coefficients mod p.
    """
    if not polynomials:
        return MacaulayResult([], [], [], [], target_degree, modulus, [])

    # Collect variables
    all_vars: Set[str] = set()
    for p in polynomials:
        all_vars.update(p.variables())

    if var_order:
        vars_ordered = list(var_order)
        for v in sorted(all_vars):
            if v not in vars_ordered:
                vars_ordered.append(v)
    else:
        vars_ordered = sorted(all_vars)

    # Generate shifts
    shifted_polys: List[MultivariatePolynomial] = []
    row_shifts: List[Tuple[Monomial, int]] = []

    for i, poly in enumerate(polynomials):
        d_poly = poly.total_degree()
        if d_poly > target_degree:
            continue
        max_shift_deg = target_degree - d_poly
        shift_monomials = enumerate_monomials(vars_ordered, max_shift_deg, vars_ordered)
        for t in shift_monomials:
            shifted = poly * t
            if not shifted.is_zero():
                shifted_polys.append(shifted)
                row_shifts.append((t, i))

    # Collect all unique monomials present in shifted polynomials
    unique_monomials: Set[Monomial] = set()
    for sp in shifted_polys:
        unique_monomials.update(sp.terms.keys())

    # Sort columns in descending DEGREVLEX order
    col_monomials = sorted(unique_monomials, key=lambda m: m.degrevlex_key(vars_ordered), reverse=True)
    mon_to_col = {m: idx for idx, m in enumerate(col_monomials)}

    # Build matrix
    matrix: List[List[int]] = []
    num_cols = len(col_monomials)
    for sp in shifted_polys:
        row = [0] * num_cols
        for m, c in sp.terms.items():
            row[mon_to_col[m]] = c
        matrix.append(row)

    return MacaulayResult(
        matrix=matrix,
        column_monomials=col_monomials,
        row_shifts=row_shifts,
        row_polynomials=shifted_polys,
        target_degree=target_degree,
        modulus=modulus,
        var_order=vars_ordered,
    )


# =====================================================================
# Gaussian Elimination over F_p to RREF
# =====================================================================

def gaussian_elimination(
    matrix: Sequence[Sequence[int]],
    modulus: int = DEFAULT_MODULUS,
) -> Tuple[List[List[int]], List[int]]:
    """
    Compute Reduced Row Echelon Form (RREF) over F_p.
    Returns:
      (rref_matrix, pivot_columns)
    """
    if not matrix or not matrix[0]:
        return ([], [])

    R = len(matrix)
    C = len(matrix[0])
    M = [[val % modulus for val in row] for row in matrix]
    inv_table = get_inv_table(modulus)

    pivot_row = 0
    pivots: List[int] = []

    for c in range(C):
        # Find pivot in column c at or below pivot_row
        pivot = None
        for r in range(pivot_row, R):
            if M[r][c] != 0:
                pivot = r
                break

        if pivot is None:
            continue

        # Swap pivot row into place
        if pivot != pivot_row:
            M[pivot_row], M[pivot] = M[pivot], M[pivot_row]

        # Scale pivot row so leading entry becomes 1
        lead = M[pivot_row][c]
        lead_inv = inv_table[lead]
        for j in range(c, C):
            M[pivot_row][j] = (M[pivot_row][j] * lead_inv) % modulus

        # Eliminate all other rows (both above and below)
        for r in range(R):
            if r != pivot_row and M[r][c] != 0:
                factor = M[r][c]
                for j in range(c, C):
                    M[r][j] = (M[r][j] - factor * M[pivot_row][j]) % modulus

        pivots.append(c)
        pivot_row += 1
        if pivot_row == R:
            break

    return (M, pivots)


rref = gaussian_elimination


def solve_linear_system(
    A: Sequence[Sequence[int]],
    b: Sequence[int],
    modulus: int = DEFAULT_MODULUS,
) -> Optional[List[int]]:
    """
    Solve linear system A * x == b (mod p).
    Returns particular solution vector x if consistent, else None.
    """
    if not A or not A[0]:
        return None

    R = len(A)
    C = len(A[0])
    # Build augmented matrix [A | b]
    aug = [list(A[r]) + [b[r] % modulus] for r in range(R)]
    M_rref, pivots = gaussian_elimination(aug, modulus=modulus)

    # Check consistency: if any row is [0, 0, ..., 0 | non-zero], inconsistent
    for row in M_rref:
        if all(v == 0 for v in row[:-1]) and row[-1] != 0:
            return None

    # Extract particular solution (setting free variables to 0)
    sol = [0] * C
    for r, c in enumerate(pivots):
        if c < C:
            sol[c] = M_rref[r][-1]

    return sol


# =====================================================================
# Nonlinear Recurrence Detection (NLFSR Sequences)
# =====================================================================

def detect_nonlinear_recurrence(
    sequence: Sequence[int],
    max_lag: int = 4,
    max_degree: int = 3,
    modulus: int = DEFAULT_MODULUS,
    min_validation_samples: int = 5,
) -> Dict[str, Any]:
    """
    Detect whether sequence is generated by an NLFSR of order L <= max_lag
    and feedback degree d <= max_degree:
        s[t+L] = g(s[t+L-1], ..., s[t]) mod p.

    Returns dict with detection status, lag, degree, polynomial, and formula.
    """
    n_seq = len(sequence)

    # Search in increasing order of degree and lag for minimal recurrence
    for deg in range(1, max_degree + 1):
        for lag in range(1, max_lag + 1):
            if n_seq <= lag:
                continue

            # State variables: x0 = s[t], x1 = s[t+1], ..., x_{L-1} = s[t+L-1]
            var_names = [f"x{i}" for i in range(lag)]
            monomials = enumerate_monomials(var_names, deg, var_names)
            num_monomials = len(monomials)

            num_transitions = n_seq - lag
            if num_transitions < num_monomials + min_validation_samples:
                continue

            # Split transitions into training and validation
            train_count = num_monomials + 2
            val_count = num_transitions - train_count

            # Build A and b
            A: List[List[int]] = []
            b: List[int] = []
            for t in range(train_count):
                pt = {f"x{i}": sequence[t + i] for i in range(lag)}
                row = [m.evaluate(pt, modulus) for m in monomials]
                A.append(row)
                b.append(sequence[t + lag] % modulus)

            sol = solve_linear_system(A, b, modulus=modulus)
            if sol is None:
                continue

            # Construct candidate polynomial
            terms = {monomials[idx]: sol[idx] for idx in range(num_monomials) if sol[idx] != 0}
            poly = MultivariatePolynomial(terms, modulus=modulus)

            # Validate against all remaining transitions
            valid = True
            for t in range(train_count, num_transitions):
                pt = {f"x{i}": sequence[t + i] for i in range(lag)}
                predicted = poly.evaluate(pt)
                actual = sequence[t + lag] % modulus
                if predicted != actual:
                    valid = False
                    break

            if valid:
                # Format formula string
                # Map x_i to s[t+i]
                formula_terms = []
                for m in sorted(poly.terms.keys(), key=lambda m: m.degrevlex_key(var_names), reverse=True):
                    c = poly.coeff_of(m)
                    if m.degree == 0:
                        formula_terms.append(str(c))
                    else:
                        m_parts = []
                        for k, v in m.exponents.items():
                            idx = int(k[1:])
                            sym = f"s[t+{idx}]"
                            if v > 1:
                                m_parts.append(f"{sym}^{v}")
                            else:
                                m_parts.append(sym)
                        sub_str = "*".join(m_parts)
                        if c == 1:
                            formula_terms.append(sub_str)
                        else:
                            formula_terms.append(f"{c}*{sub_str}")

                formula_rhs = " + ".join(formula_terms) if formula_terms else "0"
                formula = f"s[t+{lag}] = {formula_rhs} (mod {modulus})"

                return {
                    "detected": True,
                    "lag": lag,
                    "degree": deg,
                    "polynomial": poly,
                    "formula": formula,
                    "coefficients": {repr(m): poly.coeff_of(m) for m in poly.terms.keys()},
                    "num_samples_verified": num_transitions,
                }

    return {
        "detected": False,
        "lag": None,
        "degree": None,
        "polynomial": None,
        "formula": None,
        "coefficients": {},
        "num_samples_verified": 0,
    }


# =====================================================================
# SageMath / FGLM Gröbner Basis Script Exporter
# =====================================================================

def should_export_groebner(target_degree: int, col_count: int) -> bool:
    """Return True if system exceeds Macaulay limits (D > 3 or cols > 2000)."""
    return target_degree > 3 or col_count > 2000


def export_groebner_script(
    polynomials: Sequence[MultivariatePolynomial],
    variables: Optional[Sequence[str]] = None,
    modulus: int = DEFAULT_MODULUS,
    target: str = "sage",
) -> str:
    """
    Generate a SageMath script computing Gröbner basis via F4 and FGLM conversion:
    Uses degrevlex order for fast F4 computation, followed by FGLM conversion
    to lexicographical order for zero-dimensional variety resolution.
    """
    if not polynomials:
        return "# Empty polynomial system.\n"

    # Collect variables
    all_vars: Set[str] = set()
    for p in polynomials:
        all_vars.update(p.variables())

    if variables:
        vars_list = list(variables)
        for v in sorted(all_vars):
            if v not in vars_list:
                vars_list.append(v)
    else:
        vars_list = sorted(all_vars)

    var_str = ", ".join(f"'{v}'" for v in vars_list)
    gens_str = ", ".join(vars_list)

    poly_lines = []
    for idx, poly in enumerate(polynomials):
        poly_str = poly.format(vars_list)
        poly_lines.append(f"    f{idx} = {poly_str}")

    ideal_gens = ", ".join(f"f{idx}" for idx in range(len(polynomials)))

    script = f"""# SageMath Gröbner Basis & FGLM Solver Script
# Target Modulus: {modulus}
# Variables: {', '.join(vars_list)}
# Generated by Trithemius Cicada Algebraic Cryptanalysis Engine

from sage.all import GF, PolynomialRing

p = {modulus}
var_names = [{var_str}]

# 1. Polynomial Ring with DegRevLex Monomial Ordering (optimal for F4)
R_degrevlex = PolynomialRing(GF({modulus}), names=var_names, order='degrevlex')
{gens_str} = R_degrevlex.gens()

# 2. Generator Polynomials
{chr(10).join(poly_lines)}

ideal_degrevlex = R_degrevlex.ideal([{ideal_gens}])

# 3. Fast Gröbner Basis via F4
print("[*] Computing DegRevLex Gröbner basis via F4 algorithm...")
gb_degrevlex = ideal_degrevlex.groebner_basis(algorithm='f4')
print(f"[+] DegRevLex basis contains {{len(gb_degrevlex)}} polynomials.")

# 4. FGLM Conversion to Lexicographical Order
print("[*] Performing FGLM conversion to Lexicographical order...")
R_lex = PolynomialRing(GF(p), names=var_names, order='lex')
ideal_lex = ideal_degrevlex.change_ring(R_lex)
gb_lex = ideal_lex.transformed_basis('fglm')
print(f"[+] Lexicographical basis contains {{len(gb_lex)}} polynomials:")
for g in gb_lex:
    print(f"    {{g}}")

# 5. Extract Zero-Dimensional Variety Solutions
try:
    sols = ideal_degrevlex.variety()
    print(f"[+] Found {{len(sols)}} exact solutions in GF({{p}})^{{len(var_names)}}:")
    for sol in sols:
        print(f"    {{sol}}")
except Exception as e:
    print(f"[!] Variety extraction note: {{e}}")
"""
    return script
