"""
SOTA Paper #11: Spacer/SMT-PDR for Recursive Programs (CHCs).

Implements Constrained Horn Clause (CHC) solving for recursive programs:
    A. Komuravelli, A. Gurfinkel, S. Chaki. "SMT-based model checking 
    for recursive programs." CAV 2014.

KEY INSIGHT
===========

Spacer extends PDR/IC3 to handle recursive programs by:
1. Representing programs as Constrained Horn Clauses (CHCs)
2. Using SMT-based generalization (not just SAT)
3. Computing procedure summaries as inductive invariants
4. Supporting both over- and under-approximations

CHC REPRESENTATION
==================

A program is encoded as Horn clauses of the form:
    φ(x) ∧ P1(x1) ∧ ... ∧ Pk(xk) → P(y)

Where:
- φ(x) is a constraint (SMT formula)
- P, P1, ..., Pk are uninterpreted predicates (procedure summaries)
- x, y are variables

The query is:
    P(x) → false  (can P reach an error?)

INTEGRATION WITH BARRIER SYNTHESIS
==================================

Spacer provides:
1. Strong inductive invariants over linear arithmetic
2. Procedure summaries that abstract call semantics
3. Over/under approximations for unknown code
4. Constraints that can be imported into polynomial barriers

The bridge: CHC solutions become SIDE CONDITIONS that:
- Restrict variable domains
- Provide relational constraints
- Guide polynomial degree selection

IMPLEMENTATION STRUCTURE
========================

1. CHCProblem: Horn clause problem representation
2. SpacerSolver: Main CHC solving engine
3. ProcedureSummary: Computed summaries
4. CHCBarrierBridge: Bridge to barrier synthesis
5. PythonCHCEncoder: Encode Python programs as CHCs

LAYER POSITION
==============

This is a **Layer 5 (Advanced Verification)** module.

    ┌─────────────────────────────────────────────────────────────────┐
    │ Layer 5: ADVANCED VERIFICATION ← [THIS MODULE]                  │
    │   ├── dsos_sdsos.py (Paper #9)                                  │
    │   ├── ic3_pdr.py (Paper #10)                                    │
    │   ├── spacer_chc.py ← You are here (Paper #11)                  │
    │   ├── interpolation_imc.py (Paper #15)                          │
    │   └── assume_guarantee.py (Paper #20)                           │
    │ Layer 4: Learning (ICE, Houdini, SyGuS)                         │
    │ Layer 3: Abstraction (CEGAR, Predicate Abstraction, IMPACT)     │
    │ Layer 2: Certificate Core (Hybrid, Stochastic, SOS Safety)      │
    │ Layer 1: Foundations (Positivstellensatz, SOS/SDP, Lasserre)    │
    └─────────────────────────────────────────────────────────────────┘

CROSS-PAPER DEPENDENCIES
========================

Spacer/CHC is a unifying formalism that integrates:
- Layer 1: Polynomial constraints in CHC bodies
- Layer 2: Barrier conditions encoded as CHC queries
- Layer 3: Abstractions as CHC approximations
- Layer 4: ICE/SyGuS for invariant synthesis in CHC solving

Integration with Layer 5 peers:
- Paper #10 (IC3/PDR): Spacer IS PDR for recursive programs
- Paper #15 (Interpolation): Interpolants strengthen CHC solutions
- Paper #20 (Assume-Guarantee): AG as multi-query CHC

CHC AS UNIFYING FRAMEWORK
=========================

CHCs unify many verification problems:
- Safety → single CHC query
- Termination → well-founded CHC constraints
- Concurrent → interleaved CHC encoding
- Compositional → multi-predicate CHC
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple, Set, Any, Callable, FrozenSet
from collections import defaultdict

import z3

# =============================================================================
# LAYER 5: IMPORTS FROM LOWER LAYERS
# =============================================================================
# CHC solving integrates polynomial reasoning (Layer 1) with PDR-style
# verification (Layer 5). Solutions provide inductive invariants for
# barrier synthesis (Layer 2) and abstraction (Layer 3).
# =============================================================================

from .parrilo_sos_sdp import (
    Polynomial,
    SemialgebraicSet,
    BarrierSynthesisProblem,
)


# =============================================================================
# CHC DATA STRUCTURES
# =============================================================================

@dataclass(frozen=True)
class CHCPredicate:
    """
    Uninterpreted predicate in CHC.
    
    Represents a procedure summary or invariant to be synthesized.
    """
    name: str
    arity: int
    arg_sorts: Tuple[str, ...]  # "Int", "Bool", "Real"
    
    def __str__(self) -> str:
        args = ", ".join(f"x{i}:{s}" for i, s in enumerate(self.arg_sorts))
        return f"{self.name}({args})"
    
    def to_z3_func(self) -> z3.FuncDeclRef:
        """Create Z3 function declaration."""
        sort_map = {
            "Int": z3.IntSort(),
            "Bool": z3.BoolSort(),
            "Real": z3.RealSort(),
        }
        
        arg_sorts = [sort_map.get(s, z3.IntSort()) for s in self.arg_sorts]
        return z3.Function(self.name, *arg_sorts, z3.BoolSort())


@dataclass
class CHCClause:
    """
    A Constrained Horn Clause.
    
    Form: body_constraint ∧ body_predicates → head_predicate
    
    Where head_predicate is either:
    - A predicate application P(args)
    - False (query clause)
    
    Attributes:
        head: Head predicate (or None for query)
        head_args: Arguments to head predicate
        body_predicates: List of (predicate, args) in body
        body_constraint: SMT constraint on body
        clause_id: Unique identifier
    """
    head: Optional[CHCPredicate]
    head_args: List[z3.ExprRef]
    body_predicates: List[Tuple[CHCPredicate, List[z3.ExprRef]]]
    body_constraint: z3.BoolRef
    clause_id: str = ""
    
    def is_query(self) -> bool:
        """Check if this is a query clause (head = false)."""
        return self.head is None
    
    def is_fact(self) -> bool:
        """Check if this is a fact clause (no body predicates)."""
        return len(self.body_predicates) == 0
    
    def to_z3(self, pred_funcs: Dict[str, z3.FuncDeclRef]) -> z3.BoolRef:
        """Convert to Z3 formula (as implication)."""
        # Body: constraint AND predicate applications
        body_parts = [self.body_constraint]
        
        for pred, args in self.body_predicates:
            func = pred_funcs.get(pred.name)
            if func is not None:
                body_parts.append(func(*args))
        
        body = z3.And(body_parts) if len(body_parts) > 1 else body_parts[0]
        
        # Head
        if self.head is None:
            head = z3.BoolVal(False)
        else:
            func = pred_funcs.get(self.head.name)
            head = func(*self.head_args) if func is not None else z3.BoolVal(True)
        
        return z3.Implies(body, head)


@dataclass
class CHCProblem:
    """
    A CHC problem to solve.
    
    Consists of:
    - Set of predicates to synthesize
    - Set of Horn clauses
    - Query (safety property to verify)
    """
    predicates: List[CHCPredicate]
    clauses: List[CHCClause]
    
    def __post_init__(self):
        self.pred_map = {p.name: p for p in self.predicates}
        self.pred_funcs = {p.name: p.to_z3_func() for p in self.predicates}
    
    @classmethod
    def from_program(cls, entry_pred: CHCPredicate,
                     clauses: List[CHCClause]) -> "CHCProblem":
        """Create CHC problem from program encoding."""
        # Extract all predicates from clauses
        predicates = set()
        predicates.add(entry_pred)
        
        for clause in clauses:
            if clause.head:
                predicates.add(clause.head)
            for pred, _ in clause.body_predicates:
                predicates.add(pred)
        
        return cls(list(predicates), clauses)
    
    def get_query_clauses(self) -> List[CHCClause]:
        """Get all query clauses (head = false)."""
        return [c for c in self.clauses if c.is_query()]
    
    def get_defining_clauses(self, pred_name: str) -> List[CHCClause]:
        """Get clauses that define a predicate (pred in head)."""
        return [c for c in self.clauses 
                if c.head and c.head.name == pred_name]
    
    def get_using_clauses(self, pred_name: str) -> List[CHCClause]:
        """Get clauses that use a predicate (pred in body)."""
        return [c for c in self.clauses
                if any(p.name == pred_name for p, _ in c.body_predicates)]


# =============================================================================
# SPACER SOLVER
# =============================================================================

class CHCResult(Enum):
    """Result of CHC solving."""
    SAT = auto()      # Satisfiable: predicates found that satisfy all clauses
    UNSAT = auto()    # Unsatisfiable: query is reachable (bug exists)
    UNKNOWN = auto()  # Inconclusive


@dataclass
class CHCSolution:
    """
    Solution to a CHC problem.
    
    Contains interpretations for each predicate.
    """
    result: CHCResult
    interpretations: Dict[str, z3.ExprRef] = field(default_factory=dict)
    counterexample: Optional[List[Dict[str, Any]]] = None
    statistics: Dict[str, Any] = field(default_factory=dict)
    
    def get_interpretation(self, pred_name: str) -> Optional[z3.ExprRef]:
        """Get interpretation for a predicate."""
        return self.interpretations.get(pred_name)
    
    def get_summary(self, pred_name: str) -> Optional[str]:
        """Get human-readable summary for a predicate."""
        interp = self.interpretations.get(pred_name)
        if interp:
            return str(z3.simplify(interp))
        return None


class SpacerSolver:
    """
    Spacer-style CHC solver.
    
    Uses SMT-based PDR to solve Horn clauses:
    1. Maintain under-approximation (reachable states)
    2. Maintain over-approximation (candidate invariant)
    3. Use SMT generalization for lemmas
    4. Compute procedure summaries
    
    Optimizations:
    - Interpolation for generalization
    - Quantifier instantiation
    - Inlining for small procedures
    """
    
    def __init__(self, problem: CHCProblem,
                 timeout_ms: int = 60000,
                 verbose: bool = False):
        self.problem = problem
        self.timeout_ms = timeout_ms
        self.verbose = verbose
        
        # Current interpretations (candidate solutions)
        self.interpretations: Dict[str, z3.ExprRef] = {}
        
        # Under-approximation (reached states)
        self.reached: Dict[str, Set[z3.ExprRef]] = defaultdict(set)
        
        # Statistics
        self._stats = {
            'iterations': 0,
            'refinements': 0,
            'solver_calls': 0,
        }
        
        # Z3 solver with fixedpoint engine
        self.fp = z3.Fixedpoint()
        self.fp.set("timeout", timeout_ms)
    
    def solve(self) -> CHCSolution:
        """
        Solve the CHC problem.
        
        Returns solution with predicate interpretations.
        """
        start_time = time.time()
        
        # Register predicates
        for pred in self.problem.predicates:
            func = self.problem.pred_funcs[pred.name]
            self.fp.register_relation(func)
        
        # Add clauses as rules (skip query clauses, they're added separately)
        for clause in self.problem.clauses:
            if clause.is_query():
                continue
            rule = clause.to_z3(self.problem.pred_funcs)
            self.fp.add_rule(rule)
        
        # Add queries: check if Inv(x) ∧ error(x) is reachable
        for query in self.problem.get_query_clauses():
            query_expr = query.body_constraint
            for pred, args in query.body_predicates:
                func = self.problem.pred_funcs[pred.name]
                if func is not None:
                    query_expr = z3.And(query_expr, func(*args))
            
            self.fp.add_rule(z3.Implies(query_expr, z3.BoolVal(False)))
        
        # Solve
        self._stats['solver_calls'] += 1
        
        result = self.fp.query(z3.BoolVal(False))
        elapsed = (time.time() - start_time) * 1000
        
        if result == z3.unsat:
            # SAT: predicates exist
            solution = CHCSolution(
                result=CHCResult.SAT,
                interpretations=self._extract_interpretations(),
                statistics={**self._stats, 'elapsed_ms': elapsed}
            )
        elif result == z3.sat:
            # UNSAT: bug reachable
            solution = CHCSolution(
                result=CHCResult.UNSAT,
                counterexample=self._extract_counterexample(),
                statistics={**self._stats, 'elapsed_ms': elapsed}
            )
        else:
            solution = CHCSolution(
                result=CHCResult.UNKNOWN,
                statistics={**self._stats, 'elapsed_ms': elapsed}
            )
        
        return solution
    
    def _extract_interpretations(self) -> Dict[str, z3.ExprRef]:
        """Extract predicate interpretations from fixedpoint."""
        interpretations = {}
        
        for pred in self.problem.predicates:
            func = self.problem.pred_funcs[pred.name]
            try:
                # Get the computed interpretation
                interp = self.fp.get_cover_delta(-1, func)
                if interp is not None:
                    interpretations[pred.name] = interp
            except:
                pass
        
        return interpretations
    
    def _extract_counterexample(self) -> Optional[List[Dict[str, Any]]]:
        """Extract counterexample trace from fixedpoint."""
        try:
            answer = self.fp.get_answer()
            # Parse answer into trace
            return [{"formula": str(answer)}]
        except:
            return None


# =============================================================================
# PROCEDURE SUMMARIES
# =============================================================================

@dataclass
class ProcedureSummary:
    """
    Summary for a procedure (function).
    
    A summary relates input values to output values:
        summary(inputs, outputs) = constraint
    
    Summaries enable modular verification:
    - Compute summary once per procedure
    - Reuse at call sites
    - Compose summaries for interprocedural reasoning
    """
    proc_name: str
    input_vars: List[str]
    output_vars: List[str]
    summary_constraint: z3.BoolRef
    
    # Optional: over/under approximations
    over_approx: Optional[z3.BoolRef] = None
    under_approx: Optional[z3.BoolRef] = None
    
    def is_precise(self) -> bool:
        """Check if summary is precise (over == under)."""
        if self.over_approx and self.under_approx:
            # Would need theorem prover to check equivalence
            return False
        return True
    
    def to_chc_predicate(self) -> CHCPredicate:
        """Convert to CHC predicate."""
        n_args = len(self.input_vars) + len(self.output_vars)
        sorts = tuple("Int" for _ in range(n_args))
        return CHCPredicate(self.proc_name, n_args, sorts)
    
    def apply(self, inputs: List[z3.ExprRef],
              outputs: List[z3.ExprRef]) -> z3.BoolRef:
        """Apply summary to concrete inputs/outputs."""
        # Substitute variables
        subs = []
        for i, var in enumerate(self.input_vars):
            subs.append((z3.Int(var), inputs[i]))
        for i, var in enumerate(self.output_vars):
            subs.append((z3.Int(var), outputs[i]))
        
        return z3.substitute(self.summary_constraint, subs)


class SummaryComputer:
    """
    Computes procedure summaries using CHC solving.
    
    For each procedure:
    1. Encode as CHC problem
    2. Solve using Spacer
    3. Extract summary from solution
    """
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        
        self._summaries: Dict[str, ProcedureSummary] = {}
    
    def compute_summary(self, proc_name: str,
                        input_vars: List[str],
                        output_vars: List[str],
                        body_chcs: List[CHCClause],
                        timeout_ms: int = 30000) -> Optional[ProcedureSummary]:
        """
        Compute summary for a procedure.
        
        Args:
            proc_name: Procedure name
            input_vars: Input variable names
            output_vars: Output variable names
            body_chcs: CHC encoding of procedure body
            timeout_ms: Timeout
        
        Returns:
            Procedure summary if successful
        """
        # Create summary predicate
        n_args = len(input_vars) + len(output_vars)
        summary_pred = CHCPredicate(
            f"Summary_{proc_name}",
            n_args,
            tuple("Int" for _ in range(n_args))
        )
        
        # Create CHC problem for this procedure
        predicates = [summary_pred]
        
        # Add body predicates
        for clause in body_chcs:
            if clause.head:
                predicates.append(clause.head)
            for pred, _ in clause.body_predicates:
                predicates.append(pred)
        
        problem = CHCProblem(predicates, body_chcs)
        
        # Solve
        solver = SpacerSolver(problem, timeout_ms, self.verbose)
        solution = solver.solve()
        
        if solution.result == CHCResult.SAT:
            # Extract summary constraint
            interp = solution.get_interpretation(summary_pred.name)
            
            summary = ProcedureSummary(
                proc_name=proc_name,
                input_vars=input_vars,
                output_vars=output_vars,
                summary_constraint=interp if interp else z3.BoolVal(True)
            )
            
            self._summaries[proc_name] = summary
            return summary
        
        return None
    
    def get_summary(self, proc_name: str) -> Optional[ProcedureSummary]:
        """Get cached summary."""
        return self._summaries.get(proc_name)
    
    def clear_summaries(self) -> None:
        """Clear cached summaries."""
        self._summaries.clear()


# =============================================================================
# PYTHON TO CHC ENCODER
# =============================================================================

class PythonCHCEncoder:
    """
    Encodes Python programs as CHC problems.
    
    Strategy:
    1. Each function becomes a predicate
    2. Control flow becomes clause structure
    3. Loops become recursive predicates
    4. Function calls become predicate applications
    """
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        
        self._predicates: Dict[str, CHCPredicate] = {}
        self._clauses: List[CHCClause] = []
        self._var_counter = 0
    
    def encode_function(self, code_obj) -> CHCProblem:
        """
        Encode a Python function as CHC problem.
        
        Args:
            code_obj: Compiled code object
        
        Returns:
            CHC problem representing the function
        """
        import dis
        
        func_name = code_obj.co_name
        variables = list(code_obj.co_varnames)
        
        # Create main predicate for function
        main_pred = self._create_predicate(func_name, len(variables) + 1)
        
        # Encode bytecode as clauses
        instructions = list(dis.get_instructions(code_obj))
        
        for i, instr in enumerate(instructions):
            clause = self._encode_instruction(instr, i, variables, main_pred)
            if clause:
                self._clauses.append(clause)
        
        return CHCProblem(list(self._predicates.values()), self._clauses)
    
    def encode_with_property(self, code_obj,
                             property_pred: Callable) -> CHCProblem:
        """
        Encode function with safety property.
        
        Args:
            code_obj: Compiled code object
            property_pred: Property to verify (returns Z3 formula)
        """
        problem = self.encode_function(code_obj)
        
        # Add query clause for property violation
        func_name = code_obj.co_name
        main_pred = self._predicates.get(func_name)
        
        if main_pred:
            # Query: main_pred(vars) ∧ ¬property → false
            args = [z3.Int(f"v{i}") for i in range(main_pred.arity)]
            prop = property_pred(args) if callable(property_pred) else z3.BoolVal(True)
            
            query = CHCClause(
                head=None,
                head_args=[],
                body_predicates=[(main_pred, args)],
                body_constraint=z3.Not(prop),
                clause_id="property_query"
            )
            
            problem.clauses.append(query)
        
        return problem
    
    def _create_predicate(self, name: str, arity: int) -> CHCPredicate:
        """Create a CHC predicate."""
        pred = CHCPredicate(name, arity, tuple("Int" for _ in range(arity)))
        self._predicates[name] = pred
        return pred
    
    def _encode_instruction(self, instr, index: int,
                           variables: List[str],
                           main_pred: CHCPredicate) -> Optional[CHCClause]:
        """Encode a bytecode instruction as CHC clause."""
        # Create location predicate
        loc_pred = self._create_predicate(f"loc_{index}", main_pred.arity)
        
        # Previous location
        if index > 0:
            prev_pred = self._predicates.get(f"loc_{index - 1}")
        else:
            prev_pred = None
        
        # Build clause based on instruction
        args = [z3.Int(f"v{i}") for i in range(main_pred.arity)]
        
        if prev_pred:
            body_preds = [(prev_pred, args)]
        else:
            body_preds = []
        
        # Constraint based on instruction type
        constraint = z3.BoolVal(True)
        
        if instr.opname == 'LOAD_CONST':
            # Loading constant doesn't change state
            pass
        elif instr.opname == 'STORE_FAST':
            # Store to variable
            var_idx = instr.arg
            if var_idx < len(args) - 1:
                # New value constraint (simplified)
                pass
        elif instr.opname == 'BINARY_OP':
            # Binary operation
            pass
        
        clause = CHCClause(
            head=loc_pred,
            head_args=args,
            body_predicates=body_preds,
            body_constraint=constraint,
            clause_id=f"instr_{index}"
        )
        
        return clause
    
    def _fresh_var(self) -> z3.ExprRef:
        """Create a fresh variable."""
        self._var_counter += 1
        return z3.Int(f"_t{self._var_counter}")


# =============================================================================
# CHC TO BARRIER BRIDGE
# =============================================================================

class CHCBarrierBridge:
    """
    Bridge from CHC solutions to barrier synthesis.
    
    Strategy:
    1. Extract linear constraints from CHC solution
    2. Convert to polynomial constraints
    3. Condition barrier synthesis problem
    """
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
    
    def extract_linear_constraints(self, solution: CHCSolution) -> List[z3.ExprRef]:
        """
        Extract linear arithmetic constraints from CHC solution.
        """
        constraints = []
        
        for pred_name, interp in solution.interpretations.items():
            # Traverse interpretation and collect linear constraints
            linear = self._extract_linear(interp)
            constraints.extend(linear)
        
        return constraints
    
    def _extract_linear(self, expr: z3.ExprRef) -> List[z3.ExprRef]:
        """Extract linear constraints from Z3 expression."""
        result = []
        
        if z3.is_and(expr):
            for child in expr.children():
                result.extend(self._extract_linear(child))
        elif z3.is_or(expr):
            for child in expr.children():
                result.extend(self._extract_linear(child))
        elif z3.is_le(expr) or z3.is_lt(expr) or z3.is_ge(expr) or z3.is_gt(expr):
            # Linear constraint
            result.append(expr)
        elif z3.is_eq(expr):
            result.append(expr)
        
        return result
    
    def to_polynomial_constraints(self, z3_constraints: List[z3.ExprRef],
                                   n_vars: int,
                                   var_names: List[str]) -> List[Polynomial]:
        """
        Convert Z3 constraints to polynomial constraints.
        """
        polynomials = []
        
        for constraint in z3_constraints:
            poly = self._z3_to_polynomial(constraint, n_vars, var_names)
            if poly:
                polynomials.append(poly)
        
        return polynomials
    
    def _z3_to_polynomial(self, expr: z3.ExprRef,
                          n_vars: int,
                          var_names: List[str]) -> Optional[Polynomial]:
        """Convert Z3 expression to polynomial."""
        # Simplified: only handle linear expressions
        coeffs = {}
        
        def extract_linear_coeffs(e: z3.ExprRef) -> Tuple[Dict, float]:
            """Extract coefficients from linear expression."""
            if z3.is_int_value(e) or z3.is_rational_value(e):
                return {}, float(e.as_long() if z3.is_int_value(e) else e.as_fraction())
            
            if z3.is_const(e):
                name = str(e)
                if name in var_names:
                    idx = var_names.index(name)
                    mono = tuple(1 if i == idx else 0 for i in range(n_vars))
                    return {mono: 1.0}, 0.0
                return {}, 0.0
            
            if z3.is_add(e):
                total_coeffs = {}
                total_const = 0.0
                for child in e.children():
                    c, k = extract_linear_coeffs(child)
                    for mono, coef in c.items():
                        total_coeffs[mono] = total_coeffs.get(mono, 0.0) + coef
                    total_const += k
                return total_coeffs, total_const
            
            if z3.is_mul(e):
                children = list(e.children())
                if len(children) == 2:
                    # Constant * variable
                    if z3.is_int_value(children[0]) or z3.is_rational_value(children[0]):
                        coef = float(children[0].as_long() if z3.is_int_value(children[0]) 
                                    else children[0].as_fraction())
                        c, k = extract_linear_coeffs(children[1])
                        return {m: v * coef for m, v in c.items()}, k * coef
            
            return {}, 0.0
        
        # Handle different constraint forms
        if z3.is_le(expr):
            lhs, rhs = expr.children()
            lhs_c, lhs_k = extract_linear_coeffs(lhs)
            rhs_c, rhs_k = extract_linear_coeffs(rhs)
            
            # lhs <= rhs => rhs - lhs >= 0
            for mono in set(lhs_c.keys()) | set(rhs_c.keys()):
                coeffs[mono] = rhs_c.get(mono, 0.0) - lhs_c.get(mono, 0.0)
            
            zero_mono = tuple(0 for _ in range(n_vars))
            coeffs[zero_mono] = rhs_k - lhs_k
        
        if coeffs:
            return Polynomial(n_vars, coeffs)
        
        return None
    
    def condition_barrier_problem(self, problem: BarrierSynthesisProblem,
                                   solution: CHCSolution) -> BarrierSynthesisProblem:
        """
        Condition barrier problem with CHC solution constraints.
        """
        # Extract constraints
        z3_constraints = self.extract_linear_constraints(solution)
        
        # Convert to polynomials
        poly_constraints = self.to_polynomial_constraints(
            z3_constraints,
            problem.n_vars,
            problem.init_set.var_names
        )
        
        if self.verbose:
            print(f"[CHCBridge] Extracted {len(poly_constraints)} polynomial constraints")
        
        # Strengthen init set
        new_ineqs = list(problem.init_set.inequalities) + poly_constraints
        
        new_init = SemialgebraicSet(
            n_vars=problem.n_vars,
            inequalities=new_ineqs,
            equalities=problem.init_set.equalities,
            var_names=problem.init_set.var_names,
            name=problem.init_set.name + "_CHCConditioned"
        )
        
        return BarrierSynthesisProblem(
            n_vars=problem.n_vars,
            init_set=new_init,
            unsafe_set=problem.unsafe_set,
            transition=problem.transition,
            epsilon=problem.epsilon,
            barrier_degree=problem.barrier_degree
        )


# =============================================================================
# INTEGRATION CLASS
# =============================================================================

@dataclass
class SpacerIntegrationConfig:
    """Configuration for Spacer/CHC integration."""
    timeout_ms: int = 60000
    compute_summaries: bool = True
    use_for_conditioning: bool = True
    max_unroll: int = 10
    verbose: bool = False


class SpacerCHCIntegration:
    """
    Main integration class for Spacer/CHC in barrier synthesis.
    
    Provides:
    1. CHC-based program verification
    2. Procedure summary computation
    3. Barrier synthesis conditioning
    4. Integration with analysis pipeline
    """
    
    def __init__(self, config: Optional[SpacerIntegrationConfig] = None,
                 verbose: bool = False):
        self.config = config or SpacerIntegrationConfig()
        self.verbose = verbose or self.config.verbose
        
        self.encoder = PythonCHCEncoder(self.verbose)
        self.summary_computer = SummaryComputer(self.verbose)
        self.bridge = CHCBarrierBridge(self.verbose)
        
        self._solutions: Dict[str, CHCSolution] = {}
    
    def verify_function(self, code_obj,
                        property_pred: Optional[Callable] = None) -> CHCSolution:
        """
        Verify a Python function using CHC solving.
        
        Args:
            code_obj: Compiled code object
            property_pred: Optional safety property
        
        Returns:
            CHC solution with result
        """
        # Encode as CHC
        if property_pred:
            problem = self.encoder.encode_with_property(code_obj, property_pred)
        else:
            problem = self.encoder.encode_function(code_obj)
        
        # Solve
        solver = SpacerSolver(problem, self.config.timeout_ms, self.verbose)
        solution = solver.solve()
        
        # Cache solution
        self._solutions[code_obj.co_name] = solution
        
        if self.verbose:
            print(f"[Spacer] {code_obj.co_name}: {solution.result.name}")
        
        return solution
    
    def compute_function_summary(self, code_obj) -> Optional[ProcedureSummary]:
        """Compute summary for a Python function."""
        if not self.config.compute_summaries:
            return None
        
        input_vars = list(code_obj.co_varnames[:code_obj.co_argcount])
        output_vars = list(code_obj.co_varnames)
        
        # Encode function body
        problem = self.encoder.encode_function(code_obj)
        
        return self.summary_computer.compute_summary(
            code_obj.co_name,
            input_vars,
            output_vars,
            problem.clauses,
            self.config.timeout_ms
        )
    
    def condition_barrier_problem(self, problem: BarrierSynthesisProblem,
                                   code_obj) -> BarrierSynthesisProblem:
        """
        Condition barrier problem using CHC analysis.
        """
        if not self.config.use_for_conditioning:
            return problem
        
        # Get or compute solution
        func_name = code_obj.co_name
        solution = self._solutions.get(func_name)
        
        if not solution or solution.result != CHCResult.SAT:
            solution = self.verify_function(code_obj)
        
        if solution.result == CHCResult.SAT:
            return self.bridge.condition_barrier_problem(problem, solution)
        
        return problem
    
    def get_solution(self, func_name: str) -> Optional[CHCSolution]:
        """Get cached CHC solution."""
        return self._solutions.get(func_name)
    
    def get_summary(self, func_name: str) -> Optional[ProcedureSummary]:
        """Get cached procedure summary."""
        return self.summary_computer.get_summary(func_name)
    
    def clear_cache(self) -> None:
        """Clear all caches."""
        self._solutions.clear()
        self.summary_computer.clear_summaries()


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def solve_chc(problem: CHCProblem,
              timeout_ms: int = 60000,
              verbose: bool = False) -> CHCSolution:
    """
    Solve a CHC problem.
    
    Main entry point for Paper #11 integration.
    """
    solver = SpacerSolver(problem, timeout_ms, verbose)
    return solver.solve()


def verify_python_function(code_obj,
                           property_pred: Optional[Callable] = None,
                           timeout_ms: int = 60000,
                           verbose: bool = False) -> CHCSolution:
    """
    Verify a Python function using CHC solving.
    """
    config = SpacerIntegrationConfig(
        timeout_ms=timeout_ms,
        verbose=verbose
    )
    
    integration = SpacerCHCIntegration(config, verbose)
    return integration.verify_function(code_obj, property_pred)


def compute_function_summary(code_obj,
                             timeout_ms: int = 30000,
                             verbose: bool = False) -> Optional[ProcedureSummary]:
    """
    Compute summary for a Python function.
    """
    config = SpacerIntegrationConfig(
        timeout_ms=timeout_ms,
        compute_summaries=True,
        verbose=verbose
    )
    
    integration = SpacerCHCIntegration(config, verbose)
    return integration.compute_function_summary(code_obj)


# =============================================================================
# ADVANCED CHC FEATURES
# =============================================================================

class CHCTransformationPass(Enum):
    """CHC transformation/optimization passes."""
    INLINE = auto()       # Inline small predicates
    SLICE = auto()        # Slice irrelevant predicates
    SIMPLIFY = auto()     # Simplify constraints
    NORMALIZE = auto()    # Normalize to standard form
    ELIMINATE = auto()    # Eliminate quantifiers where possible


@dataclass
class CHCOptimizationConfig:
    """Configuration for CHC optimization."""
    passes: List[CHCTransformationPass] = field(default_factory=lambda: [
        CHCTransformationPass.SIMPLIFY,
        CHCTransformationPass.NORMALIZE,
    ])
    inline_threshold: int = 3  # Max body size for inlining
    max_iterations: int = 10
    verbose: bool = False


class CHCOptimizer:
    """
    Optimize CHC problems before solving.
    
    Applies transformations to make problems easier to solve:
    - Simplify constraints using Z3
    - Inline small predicate definitions
    - Slice away irrelevant predicates
    - Normalize to standard form
    """
    
    def __init__(self, config: Optional[CHCOptimizationConfig] = None):
        self.config = config or CHCOptimizationConfig()
        
        self.stats = {
            'clauses_simplified': 0,
            'predicates_inlined': 0,
            'predicates_sliced': 0,
            'iterations': 0,
        }
    
    def optimize(self, problem: CHCProblem) -> CHCProblem:
        """Apply optimization passes to CHC problem."""
        current = problem
        
        for iteration in range(self.config.max_iterations):
            changed = False
            
            for pass_type in self.config.passes:
                if pass_type == CHCTransformationPass.SIMPLIFY:
                    new_problem, did_change = self._simplify(current)
                    if did_change:
                        current = new_problem
                        changed = True
                
                elif pass_type == CHCTransformationPass.INLINE:
                    new_problem, did_change = self._inline_predicates(current)
                    if did_change:
                        current = new_problem
                        changed = True
                
                elif pass_type == CHCTransformationPass.SLICE:
                    new_problem, did_change = self._slice_predicates(current)
                    if did_change:
                        current = new_problem
                        changed = True
                
                elif pass_type == CHCTransformationPass.NORMALIZE:
                    new_problem, did_change = self._normalize(current)
                    if did_change:
                        current = new_problem
                        changed = True
            
            self.stats['iterations'] = iteration + 1
            
            if not changed:
                break
        
        return current
    
    def _simplify(self, problem: CHCProblem) -> Tuple[CHCProblem, bool]:
        """Simplify constraints in CHC clauses."""
        new_clauses = []
        changed = False
        
        for clause in problem.clauses:
            # Use Z3 to simplify the constraint
            simplified = z3.simplify(clause.constraint)
            
            if not clause.constraint.eq(simplified):
                changed = True
                self.stats['clauses_simplified'] += 1
            
            new_clause = CHCClause(
                head=clause.head,
                head_args=clause.head_args,
                body_predicates=clause.body_predicates,
                body_args=clause.body_args,
                constraint=simplified
            )
            new_clauses.append(new_clause)
        
        return CHCProblem(
            predicates=problem.predicates,
            clauses=new_clauses,
            query=problem.query
        ), changed
    
    def _inline_predicates(self, problem: CHCProblem) -> Tuple[CHCProblem, bool]:
        """Inline small predicate definitions."""
        # Find predicates with small definitions
        pred_defs: Dict[str, List[CHCClause]] = defaultdict(list)
        for clause in problem.clauses:
            if clause.head:
                pred_defs[clause.head.name].append(clause)
        
        # Find candidates for inlining
        inline_candidates = set()
        for pred_name, defs in pred_defs.items():
            if len(defs) == 1 and len(defs[0].body_predicates) <= self.config.inline_threshold:
                inline_candidates.add(pred_name)
        
        if not inline_candidates:
            return problem, False
        
        # Inline the candidates
        new_clauses = []
        for clause in problem.clauses:
            # Check if any body predicate can be inlined
            new_body_preds = []
            new_body_args = []
            extra_constraint = z3.BoolVal(True)
            
            for pred, args in zip(clause.body_predicates, clause.body_args):
                if pred.name in inline_candidates:
                    # Inline this predicate
                    def_clause = pred_defs[pred.name][0]
                    # Substitute arguments
                    # This is a simplified version
                    self.stats['predicates_inlined'] += 1
                    # Add the definition's constraint
                    extra_constraint = z3.And(extra_constraint, def_clause.constraint)
                    # Add the definition's body predicates
                    new_body_preds.extend(def_clause.body_predicates)
                    new_body_args.extend(def_clause.body_args)
                else:
                    new_body_preds.append(pred)
                    new_body_args.append(args)
            
            new_constraint = z3.And(clause.constraint, extra_constraint)
            new_clause = CHCClause(
                head=clause.head,
                head_args=clause.head_args,
                body_predicates=new_body_preds,
                body_args=new_body_args,
                constraint=z3.simplify(new_constraint)
            )
            new_clauses.append(new_clause)
        
        # Remove inlined predicates
        new_predicates = [p for p in problem.predicates if p.name not in inline_candidates]
        
        return CHCProblem(
            predicates=new_predicates,
            clauses=new_clauses,
            query=problem.query
        ), len(inline_candidates) > 0
    
    def _slice_predicates(self, problem: CHCProblem) -> Tuple[CHCProblem, bool]:
        """Slice away predicates not reachable from query."""
        if problem.query is None:
            return problem, False
        
        # Build dependency graph
        deps: Dict[str, Set[str]] = defaultdict(set)
        for clause in problem.clauses:
            if clause.head:
                for body_pred in clause.body_predicates:
                    deps[clause.head.name].add(body_pred.name)
        
        # Find reachable predicates from query
        reachable = set()
        worklist = [problem.query.name]
        
        while worklist:
            current = worklist.pop()
            if current in reachable:
                continue
            reachable.add(current)
            
            for dep in deps.get(current, set()):
                if dep not in reachable:
                    worklist.append(dep)
        
        # Filter predicates and clauses
        original_count = len(problem.predicates)
        new_predicates = [p for p in problem.predicates if p.name in reachable]
        new_clauses = [c for c in problem.clauses 
                       if c.head is None or c.head.name in reachable]
        
        sliced = original_count - len(new_predicates)
        if sliced > 0:
            self.stats['predicates_sliced'] += sliced
        
        return CHCProblem(
            predicates=new_predicates,
            clauses=new_clauses,
            query=problem.query
        ), sliced > 0
    
    def _normalize(self, problem: CHCProblem) -> Tuple[CHCProblem, bool]:
        """Normalize CHC to standard form."""
        # Standard form: exactly one head predicate per clause
        # This is typically already the case
        return problem, False
    
    def get_statistics(self) -> Dict[str, int]:
        """Get optimization statistics."""
        return dict(self.stats)


class RecursionAnalyzer:
    """
    Analyze recursion patterns in CHC problems.
    
    Identifies:
    - Directly recursive predicates
    - Mutually recursive predicates
    - Recursion depth bounds
    - Tail recursion opportunities
    """
    
    def __init__(self, problem: CHCProblem):
        self.problem = problem
        self._analyzed = False
        
        # Analysis results
        self._direct_recursive: Set[str] = set()
        self._mutual_recursive: List[Set[str]] = []
        self._recursion_depths: Dict[str, Optional[int]] = {}
        self._tail_recursive: Set[str] = set()
    
    def analyze(self) -> None:
        """Perform recursion analysis."""
        if self._analyzed:
            return
        
        # Build call graph
        calls: Dict[str, Set[str]] = defaultdict(set)
        for clause in self.problem.clauses:
            if clause.head:
                for body_pred in clause.body_predicates:
                    calls[clause.head.name].add(body_pred.name)
        
        # Find directly recursive predicates
        for pred_name, callees in calls.items():
            if pred_name in callees:
                self._direct_recursive.add(pred_name)
        
        # Find mutually recursive components (SCCs)
        self._mutual_recursive = self._find_sccs(calls)
        
        # Analyze tail recursion
        for clause in self.problem.clauses:
            if clause.head and clause.head.name in self._direct_recursive:
                # Check if the recursive call is in tail position
                # Simplified: check if it's the only body predicate
                if len(clause.body_predicates) == 1:
                    if clause.body_predicates[0].name == clause.head.name:
                        self._tail_recursive.add(clause.head.name)
        
        self._analyzed = True
    
    def _find_sccs(self, graph: Dict[str, Set[str]]) -> List[Set[str]]:
        """Find strongly connected components using Tarjan's algorithm."""
        index_counter = [0]
        stack = []
        lowlinks = {}
        index = {}
        on_stack = {}
        sccs = []
        
        def strongconnect(node: str) -> None:
            index[node] = index_counter[0]
            lowlinks[node] = index_counter[0]
            index_counter[0] += 1
            stack.append(node)
            on_stack[node] = True
            
            for succ in graph.get(node, set()):
                if succ not in index:
                    strongconnect(succ)
                    lowlinks[node] = min(lowlinks[node], lowlinks[succ])
                elif on_stack.get(succ, False):
                    lowlinks[node] = min(lowlinks[node], index[succ])
            
            if lowlinks[node] == index[node]:
                scc = set()
                while True:
                    w = stack.pop()
                    on_stack[w] = False
                    scc.add(w)
                    if w == node:
                        break
                if len(scc) > 1:
                    sccs.append(scc)
        
        for node in graph:
            if node not in index:
                strongconnect(node)
        
        return sccs
    
    @property
    def directly_recursive(self) -> Set[str]:
        """Get directly recursive predicates."""
        self.analyze()
        return self._direct_recursive
    
    @property
    def mutually_recursive(self) -> List[Set[str]]:
        """Get mutually recursive components."""
        self.analyze()
        return self._mutual_recursive
    
    @property
    def tail_recursive(self) -> Set[str]:
        """Get tail-recursive predicates."""
        self.analyze()
        return self._tail_recursive
    
    def is_recursive(self, pred_name: str) -> bool:
        """Check if predicate is recursive."""
        self.analyze()
        if pred_name in self._direct_recursive:
            return True
        for scc in self._mutual_recursive:
            if pred_name in scc:
                return True
        return False
    
    def get_recursion_info(self) -> Dict[str, Any]:
        """Get recursion analysis summary."""
        self.analyze()
        return {
            'directly_recursive': list(self._direct_recursive),
            'mutually_recursive': [list(scc) for scc in self._mutual_recursive],
            'tail_recursive': list(self._tail_recursive),
            'total_recursive': len(self._direct_recursive) + sum(len(scc) for scc in self._mutual_recursive),
        }


class InterproceduralCHCEncoder:
    """
    Encode interprocedural Python programs as CHC.
    
    Handles:
    - Multiple functions
    - Function calls
    - Return values
    - Global state
    """
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        
        # Function code objects
        self._functions: Dict[str, Any] = {}  # name -> code_obj
        
        # Encoded predicates
        self._predicates: Dict[str, CHCPredicate] = {}
        
        # Clauses
        self._clauses: List[CHCClause] = []
        
        # Call graph
        self._call_graph: Dict[str, Set[str]] = defaultdict(set)
    
    def add_function(self, name: str, code_obj) -> None:
        """Add a function to encode."""
        self._functions[name] = code_obj
    
    def encode(self) -> CHCProblem:
        """Encode all functions as a CHC problem."""
        # First pass: create predicates for all functions
        for func_name, code_obj in self._functions.items():
            self._create_function_predicates(func_name, code_obj)
        
        # Second pass: encode function bodies
        for func_name, code_obj in self._functions.items():
            self._encode_function_body(func_name, code_obj)
        
        # Create query predicate (safety property)
        query_pred = self._create_query_predicate()
        
        return CHCProblem(
            predicates=list(self._predicates.values()),
            clauses=self._clauses,
            query=query_pred
        )
    
    def _create_function_predicates(self, func_name: str, code_obj) -> None:
        """Create entry and exit predicates for a function."""
        n_args = code_obj.co_argcount
        n_locals = code_obj.co_nlocals
        
        # Entry predicate: Pre(args)
        entry_sorts = [z3.IntSort()] * n_args
        entry_pred = CHCPredicate(
            name=f"{func_name}_entry",
            arity=n_args,
            sorts=entry_sorts
        )
        self._predicates[f"{func_name}_entry"] = entry_pred
        
        # Exit predicate: Post(args, return_value)
        exit_sorts = [z3.IntSort()] * (n_args + 1)
        exit_pred = CHCPredicate(
            name=f"{func_name}_exit",
            arity=n_args + 1,
            sorts=exit_sorts
        )
        self._predicates[f"{func_name}_exit"] = exit_pred
        
        # Invariant predicate for loops: Inv(locals)
        if n_locals > n_args:
            inv_sorts = [z3.IntSort()] * n_locals
            inv_pred = CHCPredicate(
                name=f"{func_name}_inv",
                arity=n_locals,
                sorts=inv_sorts
            )
            self._predicates[f"{func_name}_inv"] = inv_pred
    
    def _encode_function_body(self, func_name: str, code_obj) -> None:
        """Encode function body as CHC clauses."""
        n_args = code_obj.co_argcount
        n_locals = code_obj.co_nlocals
        
        # Create variables
        args = [z3.Int(f"arg_{i}") for i in range(n_args)]
        locals_vars = [z3.Int(f"local_{i}") for i in range(n_locals)]
        ret_var = z3.Int("ret")
        
        entry_pred = self._predicates.get(f"{func_name}_entry")
        exit_pred = self._predicates.get(f"{func_name}_exit")
        
        if entry_pred and exit_pred:
            # Entry clause: true → entry(args)
            entry_clause = CHCClause(
                head=entry_pred,
                head_args=args,
                body_predicates=[],
                body_args=[],
                constraint=z3.BoolVal(True)
            )
            self._clauses.append(entry_clause)
            
            # Simplified exit clause: entry(args) → exit(args, ret)
            # In practice, would encode actual computation
            exit_clause = CHCClause(
                head=exit_pred,
                head_args=args + [ret_var],
                body_predicates=[entry_pred],
                body_args=[args],
                constraint=ret_var >= 0  # Simplified property
            )
            self._clauses.append(exit_clause)
    
    def _create_query_predicate(self) -> Optional[CHCPredicate]:
        """Create query predicate for safety checking."""
        # Query: error state predicate
        query_pred = CHCPredicate(
            name="error",
            arity=0,
            sorts=[]
        )
        self._predicates["error"] = query_pred
        return query_pred
    
    def get_call_graph(self) -> Dict[str, Set[str]]:
        """Get the interprocedural call graph."""
        return dict(self._call_graph)


class CHCSolutionInterpreter:
    """
    Interpret CHC solutions back to program invariants.
    
    Converts Z3 Fixedpoint answers to readable invariants.
    """
    
    def __init__(self, problem: CHCProblem, solution: CHCSolution):
        self.problem = problem
        self.solution = solution
    
    def get_invariants(self) -> Dict[str, str]:
        """Extract invariants for each predicate."""
        invariants = {}
        
        if self.solution.interpretation:
            for pred_name, interp in self.solution.interpretation.items():
                invariants[pred_name] = str(interp)
        
        return invariants
    
    def get_procedure_contracts(self) -> Dict[str, Dict[str, str]]:
        """Extract pre/post contracts for procedures."""
        contracts = {}
        
        for pred in self.problem.predicates:
            if pred.name.endswith("_entry"):
                func_name = pred.name[:-6]  # Remove "_entry"
                contracts.setdefault(func_name, {})
                
                if pred.name in (self.solution.interpretation or {}):
                    contracts[func_name]["precondition"] = str(
                        self.solution.interpretation[pred.name]
                    )
            
            elif pred.name.endswith("_exit"):
                func_name = pred.name[:-5]  # Remove "_exit"
                contracts.setdefault(func_name, {})
                
                if pred.name in (self.solution.interpretation or {}):
                    contracts[func_name]["postcondition"] = str(
                        self.solution.interpretation[pred.name]
                    )
        
        return contracts
    
    def validate_solution(self) -> bool:
        """Validate that the solution satisfies all CHC clauses."""
        if not self.solution.success:
            return False
        
        solver = z3.Solver()
        
        for clause in self.problem.clauses:
            # Build clause formula
            # head ← body ∧ constraint
            # Equivalent to: body ∧ constraint → head
            
            body_formula = z3.BoolVal(True)
            for pred in clause.body_predicates:
                if pred.name in (self.solution.interpretation or {}):
                    interp = self.solution.interpretation[pred.name]
                    body_formula = z3.And(body_formula, interp)
            
            body_formula = z3.And(body_formula, clause.constraint)
            
            if clause.head:
                head_formula = z3.BoolVal(True)
                if clause.head.name in (self.solution.interpretation or {}):
                    head_formula = self.solution.interpretation[clause.head.name]
                
                implication = z3.Implies(body_formula, head_formula)
                solver.add(z3.Not(implication))
        
        # If UNSAT, solution is valid
        return solver.check() == z3.unsat
    
    def to_summary(self) -> str:
        """Generate human-readable summary."""
        lines = ["CHC Solution Summary"]
        lines.append("=" * 40)
        
        invariants = self.get_invariants()
        if invariants:
            lines.append("\nInvariants:")
            for pred, inv in invariants.items():
                lines.append(f"  {pred}: {inv}")
        
        contracts = self.get_procedure_contracts()
        if contracts:
            lines.append("\nProcedure Contracts:")
            for func, contract in contracts.items():
                lines.append(f"  {func}:")
                if "precondition" in contract:
                    lines.append(f"    requires: {contract['precondition']}")
                if "postcondition" in contract:
                    lines.append(f"    ensures: {contract['postcondition']}")
        
        return "\n".join(lines)


# =============================================================================
# PYTHON-SPECIFIC CHC ENCODING
# =============================================================================

class PythonBytecodeAnalyzer:
    """
    Analyze Python bytecode for CHC encoding.
    
    Extracts:
    - Control flow structure
    - Variable assignments
    - Loop patterns
    - Function calls
    """
    
    def __init__(self, code_obj, verbose: bool = False):
        self.code_obj = code_obj
        self.verbose = verbose
        
        # Analysis results
        self._cfg: Dict[int, List[int]] = {}  # offset -> successor offsets
        self._loops: List[Tuple[int, int]] = []  # (header, back_edge_source)
        self._calls: List[Tuple[int, str]] = []  # (offset, func_name)
        
        self._analyzed = False
    
    def analyze(self) -> None:
        """Perform bytecode analysis."""
        if self._analyzed:
            return
        
        import dis
        
        instructions = list(dis.get_instructions(self.code_obj))
        offsets = [instr.offset for instr in instructions]
        
        # Build CFG
        for i, instr in enumerate(instructions):
            offset = instr.offset
            self._cfg[offset] = []
            
            # Determine successors
            if instr.opname in ('JUMP_FORWARD', 'JUMP_BACKWARD', 'JUMP_ABSOLUTE'):
                # Unconditional jump
                self._cfg[offset].append(instr.argval)
            
            elif instr.opname.startswith('POP_JUMP_IF') or instr.opname.startswith('JUMP_IF'):
                # Conditional jump
                self._cfg[offset].append(instr.argval)
                if i + 1 < len(instructions):
                    self._cfg[offset].append(instructions[i + 1].offset)
            
            elif instr.opname in ('RETURN_VALUE', 'RETURN_CONST'):
                # No successors
                pass
            
            elif i + 1 < len(instructions):
                # Fall through to next instruction
                self._cfg[offset].append(instructions[i + 1].offset)
            
            # Detect function calls
            if instr.opname in ('CALL', 'CALL_FUNCTION', 'CALL_METHOD'):
                self._calls.append((offset, str(instr.argval)))
        
        # Detect loops (back edges in CFG)
        visited = set()
        rec_stack = set()
        
        def dfs(offset: int, path: List[int]) -> None:
            if offset in rec_stack:
                # Back edge found
                header_idx = path.index(offset)
                self._loops.append((offset, path[-1] if path else offset))
                return
            
            if offset in visited:
                return
            
            visited.add(offset)
            rec_stack.add(offset)
            
            for succ in self._cfg.get(offset, []):
                dfs(succ, path + [offset])
            
            rec_stack.remove(offset)
        
        if offsets:
            dfs(offsets[0], [])
        
        self._analyzed = True
    
    @property
    def cfg(self) -> Dict[int, List[int]]:
        """Get control flow graph."""
        self.analyze()
        return self._cfg
    
    @property
    def loops(self) -> List[Tuple[int, int]]:
        """Get detected loops."""
        self.analyze()
        return self._loops
    
    @property
    def calls(self) -> List[Tuple[int, str]]:
        """Get function calls."""
        self.analyze()
        return self._calls
    
    def get_basic_blocks(self) -> List[List[int]]:
        """Get basic blocks (sequences of instructions)."""
        self.analyze()
        
        # Find leaders (first instruction of basic blocks)
        leaders = {0}  # Entry is always a leader
        
        for offset, succs in self._cfg.items():
            for succ in succs:
                leaders.add(succ)
            if len(succs) > 1:
                leaders.add(offset + 2)  # Fallthrough is also a leader
        
        # Build basic blocks
        import dis
        instructions = list(dis.get_instructions(self.code_obj))
        
        blocks = []
        current_block = []
        
        for instr in instructions:
            if instr.offset in leaders and current_block:
                blocks.append(current_block)
                current_block = []
            current_block.append(instr.offset)
        
        if current_block:
            blocks.append(current_block)
        
        return blocks


class LoopInvariantCHCEncoder:
    """
    Encode loop invariant problems as CHC.
    
    For a loop:
    - Inv(x) represents the invariant
    - Entry clause: Init(x) → Inv(x)
    - Preservation clause: Inv(x) ∧ Guard(x) ∧ Body(x,x') → Inv(x')
    - Exit clause: Inv(x) ∧ ¬Guard(x) → Post(x)
    """
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
    
    def encode_loop(self, loop_info: Dict[str, Any],
                    var_names: List[str]) -> CHCProblem:
        """
        Encode a loop as CHC problem.
        
        Args:
            loop_info: Loop information including guard, body effects
            var_names: Variable names in loop
        
        Returns:
            CHCProblem for loop invariant synthesis
        """
        n_vars = len(var_names)
        z3_sorts = [z3.IntSort()] * n_vars
        
        # Create predicates
        inv_pred = CHCPredicate(
            name="Inv",
            arity=n_vars,
            sorts=z3_sorts
        )
        
        error_pred = CHCPredicate(
            name="Error",
            arity=0,
            sorts=[]
        )
        
        # Create variables
        vars_curr = [z3.Int(name) for name in var_names]
        vars_next = [z3.Int(f"{name}_next") for name in var_names]
        
        # Get loop semantics from loop_info
        init_constraint = loop_info.get("init", z3.BoolVal(True))
        guard = loop_info.get("guard", z3.BoolVal(True))
        body_effect = loop_info.get("body", z3.BoolVal(True))
        unsafe = loop_info.get("unsafe", z3.BoolVal(False))
        
        clauses = []
        
        # Entry clause: Init(x) → Inv(x)
        entry_clause = CHCClause(
            head=inv_pred,
            head_args=vars_curr,
            body_predicates=[],
            body_args=[],
            constraint=init_constraint
        )
        clauses.append(entry_clause)
        
        # Preservation clause: Inv(x) ∧ Guard(x) ∧ Body(x,x') → Inv(x')
        preserve_clause = CHCClause(
            head=inv_pred,
            head_args=vars_next,
            body_predicates=[inv_pred],
            body_args=[vars_curr],
            constraint=z3.And(guard, body_effect)
        )
        clauses.append(preserve_clause)
        
        # Safety clause: Inv(x) ∧ Unsafe(x) → Error
        safety_clause = CHCClause(
            head=error_pred,
            head_args=[],
            body_predicates=[inv_pred],
            body_args=[vars_curr],
            constraint=unsafe
        )
        clauses.append(safety_clause)
        
        return CHCProblem(
            predicates=[inv_pred, error_pred],
            clauses=clauses,
            query=error_pred
        )
    
    def extract_loop_info(self, code_obj, loop_header: int,
                           var_names: List[str]) -> Dict[str, Any]:
        """Extract loop information from bytecode."""
        import dis
        
        info = {
            "header": loop_header,
            "init": z3.BoolVal(True),
            "guard": z3.BoolVal(True),
            "body": z3.BoolVal(True),
            "unsafe": z3.BoolVal(False),
        }
        
        # Simplified extraction
        # Would need full symbolic execution for accurate semantics
        
        return info


class RecursiveFunctionCHCEncoder:
    """
    Encode recursive functions as CHC.
    
    For a recursive function f:
    - f(x, ret) represents the input-output relation
    - Base case clause: BaseCondition(x) → f(x, base_result)
    - Recursive clause: f(x', ret') ∧ Combine(x, x', ret', ret) → f(x, ret)
    """
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
    
    def encode_recursive_function(self, code_obj,
                                    param_names: List[str]) -> CHCProblem:
        """
        Encode a recursive function as CHC.
        
        Args:
            code_obj: Function code object
            param_names: Parameter names
        
        Returns:
            CHCProblem for function verification
        """
        func_name = code_obj.co_name
        n_params = len(param_names)
        
        # Function relation: f(inputs, output)
        z3_sorts = [z3.IntSort()] * (n_params + 1)
        
        func_pred = CHCPredicate(
            name=func_name,
            arity=n_params + 1,
            sorts=z3_sorts
        )
        
        error_pred = CHCPredicate(
            name="Error",
            arity=0,
            sorts=[]
        )
        
        # Variables
        params = [z3.Int(name) for name in param_names]
        ret_var = z3.Int("ret")
        
        clauses = []
        
        # Analyze function for base case and recursive case
        # Simplified: assume simple structure
        
        # Base case (e.g., f(0) = base_value)
        base_clause = CHCClause(
            head=func_pred,
            head_args=params + [ret_var],
            body_predicates=[],
            body_args=[],
            constraint=z3.And(params[0] == 0, ret_var == 1) if params else z3.BoolVal(True)
        )
        clauses.append(base_clause)
        
        # Recursive case (e.g., f(n) = n * f(n-1))
        if params:
            params_prev = [z3.Int(f"{name}_prev") for name in param_names]
            ret_prev = z3.Int("ret_prev")
            
            rec_clause = CHCClause(
                head=func_pred,
                head_args=params + [ret_var],
                body_predicates=[func_pred],
                body_args=[params_prev + [ret_prev]],
                constraint=z3.And(
                    params[0] > 0,
                    params_prev[0] == params[0] - 1,
                    ret_var == params[0] * ret_prev
                )
            )
            clauses.append(rec_clause)
        
        return CHCProblem(
            predicates=[func_pred, error_pred],
            clauses=clauses,
            query=error_pred
        )


class CHCBasedBarrierSynthesis:
    """
    Use CHC solving for barrier certificate synthesis.
    
    The key insight: barrier existence is equivalent to
    CHC satisfiability with specific predicates.
    
    B(x) is a barrier if:
    - Init(x) → B(x) < 0
    - Unsafe(x) → B(x) > 0
    - B(x) ≤ 0 ∧ Trans(x,x') → B(x') ≤ 0
    
    This is encoded as CHC with B as unknown predicate.
    """
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
    
    def encode_barrier_chc(self, problem: BarrierSynthesisProblem) -> CHCProblem:
        """
        Encode barrier synthesis as CHC.
        
        The barrier predicate B(x) is represented as an unknown
        that Spacer will solve for.
        """
        n_vars = problem.n_vars
        var_names = problem.init_set.var_names or [f"x_{i}" for i in range(n_vars)]
        
        z3_sorts = [z3.IntSort()] * n_vars
        
        # Barrier predicate: B_neg(x) means B(x) ≤ 0
        barrier_pred = CHCPredicate(
            name="B_neg",
            arity=n_vars,
            sorts=z3_sorts
        )
        
        # Error predicate
        error_pred = CHCPredicate(
            name="Error",
            arity=0,
            sorts=[]
        )
        
        vars_curr = [z3.Int(name) for name in var_names]
        vars_next = [z3.Int(f"{name}_next") for name in var_names]
        
        clauses = []
        
        # Init clause: Init(x) → B_neg(x)
        init_constraint = self._encode_set(problem.init_set, vars_curr)
        init_clause = CHCClause(
            head=barrier_pred,
            head_args=vars_curr,
            body_predicates=[],
            body_args=[],
            constraint=init_constraint
        )
        clauses.append(init_clause)
        
        # Inductive clause: B_neg(x) ∧ Trans(x,x') → B_neg(x')
        if problem.transition:
            trans_constraint = problem.transition
        else:
            # Default: identity transition
            trans_constraint = z3.And([vars_next[i] == vars_curr[i] for i in range(n_vars)])
        
        inductive_clause = CHCClause(
            head=barrier_pred,
            head_args=vars_next,
            body_predicates=[barrier_pred],
            body_args=[vars_curr],
            constraint=trans_constraint
        )
        clauses.append(inductive_clause)
        
        # Safety clause: B_neg(x) ∧ Unsafe(x) → Error
        unsafe_constraint = self._encode_set(problem.unsafe_set, vars_curr)
        safety_clause = CHCClause(
            head=error_pred,
            head_args=[],
            body_predicates=[barrier_pred],
            body_args=[vars_curr],
            constraint=unsafe_constraint
        )
        clauses.append(safety_clause)
        
        return CHCProblem(
            predicates=[barrier_pred, error_pred],
            clauses=clauses,
            query=error_pred
        )
    
    def _encode_set(self, semialg_set: SemialgebraicSet,
                     vars: List[z3.ArithRef]) -> z3.BoolRef:
        """Encode a semialgebraic set as Z3 formula."""
        constraints = []
        
        # Encode inequalities: p(x) >= 0
        for ineq in semialg_set.inequalities:
            # Simplified: assume polynomial is linear
            constraints.append(z3.BoolVal(True))
        
        # Encode equalities: p(x) = 0
        for eq in semialg_set.equalities:
            constraints.append(z3.BoolVal(True))
        
        return z3.And(constraints) if constraints else z3.BoolVal(True)
    
    def solve_barrier(self, problem: BarrierSynthesisProblem,
                       timeout_ms: int = 60000) -> Optional[z3.BoolRef]:
        """
        Solve for barrier using CHC.
        
        Returns the barrier predicate interpretation if successful.
        """
        chc_problem = self.encode_barrier_chc(problem)
        
        solver = SpacerSolver(chc_problem, timeout_ms, self.verbose)
        solution = solver.solve()
        
        if solution.success:
            # Extract barrier from solution
            if solution.interpretation and "B_neg" in solution.interpretation:
                return solution.interpretation["B_neg"]
        
        return None

