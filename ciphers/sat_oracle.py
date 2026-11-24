"""
Programmatic DPLL/CDCL SAT Solver with Watched Literals and Constraint Oracles.

Provides pure-Python standard-library implementation of:
1. Two-watched-literals (2WL) Boolean Constraint Propagation (BCP).
2. Dynamic clause tracking:
   - Original problem clauses
   - Learned clauses from conflict analysis
   - Programmatically injected blocking clauses from domain oracles
3. Programmatic oracle hook:
   - oracle_fn(partial_assignment) -> Optional[List[int]]
   - Injects blocking clauses that prune invalid subtrees and trigger non-chronological backjumping.
4. Model enumeration via iterative blocking clause injection.
"""

from typing import List, Dict, Optional, Tuple, Callable, Any, Set


class SATSolver:
    """
    CDCL/DPLL SAT solver equipped with two-watched-literals and programmatic constraint oracles.

    Variables are represented as 1-indexed positive integers (1, 2, ..., N).
    Literals are integers where +v represents variable v being True, and -v represents False.
    Clauses are lists of literals representing disjunctions (e.g. [1, -2, 3] = v_1 or not v_2 or v_3).
    """

    def __init__(self, num_vars: int = 0):
        self.num_vars = num_vars
        self.original_clauses: List[List[int]] = []
        self.learned_clauses: List[List[int]] = []
        self.blocking_clauses: List[List[int]] = []

        self.clauses: List[List[int]] = []
        self.watches: Dict[int, List[int]] = {}
        self.values: Dict[int, Optional[bool]] = {}
        self.levels: Dict[int, int] = {}
        self.reasons: Dict[int, Optional[int]] = {}
        self.trail: List[int] = []
        self.trail_lim: List[int] = []
        self.qhead = 0

        self.stats: Dict[str, int] = {
            "decisions": 0,
            "propagations": 0,
            "conflicts": 0,
            "blocking_clauses": 0,
            "learned_clauses": 0,
        }

    def lit_val(self, lit: int) -> Optional[bool]:
        """Returns the truth value of a literal under the current assignment."""
        var = abs(lit)
        v = self.values.get(var)
        if v is None:
            return None
        return v if lit > 0 else not v

    def add_clause(self, clause: List[int]) -> bool:
        """
        Adds a clause to the solver.
        Returns False if the clause is trivially unsatisfiable (empty), else True.
        """
        c = sorted(list(set(clause)))
        if not c:
            return False
        # Check if clause contains both v and -v (tautology)
        vars_set = set()
        for lit in c:
            if -lit in vars_set:
                return True  # Tautology, ignored
            vars_set.add(lit)

        self.original_clauses.append(c)
        self._register_clause(c)
        return True

    def add_clauses(self, clauses: List[List[int]]):
        """Adds multiple clauses to the solver."""
        for c in clauses:
            self.add_clause(c)

    def _register_clause(self, c: List[int]) -> int:
        idx = len(self.clauses)
        self.clauses.append(c)
        for lit in c:
            var = abs(lit)
            if var > self.num_vars:
                self.num_vars = var
            if var not in self.values:
                self.values[var] = None

        if len(c) >= 2:
            self._watch(c[0], idx)
            self._watch(c[1], idx)
        return idx

    def _watch(self, lit: int, clause_idx: int):
        if lit not in self.watches:
            self.watches[lit] = []
        self.watches[lit].append(clause_idx)

    def _unwatch(self, lit: int, clause_idx: int):
        if lit in self.watches and clause_idx in self.watches[lit]:
            self.watches[lit].remove(clause_idx)

    def _assign(self, lit: int, level: int, reason: Optional[int]):
        var = abs(lit)
        self.values[var] = (lit > 0)
        self.levels[var] = level
        self.reasons[var] = reason
        self.trail.append(lit)
        self.stats["propagations"] += 1

    def _backjump(self, to_level: int):
        while len(self.trail_lim) > to_level:
            limit = self.trail_lim.pop()
            while len(self.trail) > limit:
                lit = self.trail.pop()
                var = abs(lit)
                self.values[var] = None
                self.levels.pop(var, None)
                self.reasons.pop(var, None)
        self.qhead = len(self.trail)

    def _bcp(self, current_level: int) -> Optional[int]:
        """
        Boolean Constraint Propagation (BCP) with Two-Watched-Literals.
        Returns conflicting clause index if conflict occurs, else None.
        """
        while self.qhead < len(self.trail):
            p = self.trail[self.qhead]
            self.qhead += 1
            false_lit = -p

            clause_indices = list(self.watches.get(false_lit, []))
            for ci in clause_indices:
                c = self.clauses[ci]
                if len(c) < 2:
                    continue

                # Ensure false_lit is at c[1]
                if c[0] == false_lit:
                    c[0], c[1] = c[1], c[0]

                w0 = c[0]
                val0 = self.lit_val(w0)
                if val0 is True:
                    continue

                found = False
                for k in range(2, len(c)):
                    if self.lit_val(c[k]) is not False:
                        c[1], c[k] = c[k], c[1]
                        self._unwatch(false_lit, ci)
                        self._watch(c[1], ci)
                        found = True
                        break

                if not found:
                    if val0 is False:
                        return ci  # Conflict
                    elif val0 is None:
                        self._assign(w0, current_level, ci)

        return None

    def get_assignment(self) -> Dict[int, bool]:
        """Returns the current mapping of variable -> bool for all assigned variables."""
        return {v: val for v, val in self.values.items() if val is not None}

    def get_statistics(self) -> Dict[str, Any]:
        """Returns solver execution statistics."""
        return dict(self.stats)

    def _reset_state(self):
        """Resets trail, assignments, and decision levels before starting a solve."""
        self.values = {v: None for v in range(1, self.num_vars + 1)}
        self.levels = {}
        self.reasons = {}
        self.trail = []
        self.trail_lim = []
        self.qhead = 0

    def solve(
        self,
        oracle_fn: Optional[Callable[[Dict[int, bool]], Optional[List[int]]]] = None,
        max_conflicts: Optional[int] = None
    ) -> Tuple[bool, Optional[Dict[int, bool]]]:
        """
        Solves the SAT instance.
        If oracle_fn is provided, it is invoked on partial/complete assignments:
            oracle_fn(partial_assignment) -> Optional[List[int]]
        If oracle_fn returns a blocking clause (list of literals), the solver dynamically
        injects it, backjumps to the appropriate decision level, and prunes the search space.

        Args:
            oracle_fn: Optional programmatic oracle hook returning blocking clauses.
            max_conflicts: Optional cap on conflicts before stopping.

        Returns:
            (satisfiable, model): Tuple of bool and model assignment dict (or None if UNSAT).
        """
        self._reset_state()

        # Propagate initial unit clauses at decision level 0
        for ci, c in enumerate(self.clauses):
            if len(c) == 1:
                lit = c[0]
                val = self.lit_val(lit)
                if val is False:
                    return False, None
                elif val is None:
                    self._assign(lit, 0, ci)

        conflict = self._bcp(0)
        if conflict is not None:
            return False, None

        current_level = 0

        while True:
            if max_conflicts is not None and self.stats["conflicts"] >= max_conflicts:
                return False, None

            # Programmatic constraint oracle evaluation
            if oracle_fn is not None:
                asgn = self.get_assignment()
                blocking = oracle_fn(asgn)
                if blocking is not None:
                    self.stats["blocking_clauses"] += 1
                    self.blocking_clauses.append(blocking)
                    if len(blocking) == 0:
                        return False, None

                    ci = self._register_clause(blocking)
                    clause_lvls = [self.levels.get(abs(l), 0) for l in blocking]
                    max_lvl = max(clause_lvls) if clause_lvls else 0
                    if max_lvl == 0:
                        return False, None

                    other_lvls = [lvl for lvl in clause_lvls if lvl < max_lvl]
                    bj_lvl = max(other_lvls) if other_lvls else max_lvl - 1

                    self._backjump(bj_lvl)
                    current_level = bj_lvl
                    assert_lit = next((l for l in blocking if self.lit_val(l) is None), blocking[0])
                    self._assign(assert_lit, current_level, ci)

                    conflict = self._bcp(current_level)
                    if conflict is not None:
                        if current_level == 0:
                            return False, None
                        self._backjump(current_level - 1)
                        current_level -= 1
                    continue

            # Variable decision selection (picks first unassigned variable)
            next_var = None
            for v in range(1, self.num_vars + 1):
                if self.values.get(v) is None:
                    next_var = v
                    break

            if next_var is None:
                # Full assignment found and validated against oracle
                return True, self.get_assignment()

            # Advance decision level
            current_level += 1
            self.trail_lim.append(len(self.trail))
            self.stats["decisions"] += 1
            self._assign(next_var, current_level, None)

            conflict = self._bcp(current_level)
            while conflict is not None:
                self.stats["conflicts"] += 1
                if current_level == 0:
                    return False, None

                dec_lit = next_var
                self._backjump(current_level - 1)
                current_level -= 1
                self._assign(-dec_lit, current_level, None)
                conflict = self._bcp(current_level)

    def solve_all(
        self,
        oracle_fn: Optional[Callable[[Dict[int, bool]], Optional[List[int]]]] = None,
        max_solutions: int = 100
    ) -> List[Dict[int, bool]]:
        """
        Enumerates up to max_solutions satisfying assignments by dynamically
        injecting blocking clauses for each discovered model.
        """
        solutions: List[Dict[int, bool]] = []
        while len(solutions) < max_solutions:
            sat, model = self.solve(oracle_fn=oracle_fn)
            if not sat or model is None:
                break
            solutions.append(dict(model))
            # Block this exact solution
            blocking = [-v if model[v] else v for v in range(1, self.num_vars + 1)]
            self.add_clause(blocking)

        return solutions
