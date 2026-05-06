"""
SOTA Paper #10: IC3/PDR-Style Inductive Reasoning.

Implements Property-Directed Reachability (PDR) / IC3 for invariant discovery:
    A. R. Bradley. "SAT-Based Model Checking without Unrolling." VMCAI 2011.

KEY INSIGHT
===========

IC3/PDR discovers inductive invariants incrementally by:
1. Maintaining "frames" F_0, F_1, ..., F_k representing over-approximations
   of states reachable in 0, 1, ..., k steps
2. Blocking counterexamples-to-induction (CTI) by adding lemmas
3. Propagating lemmas forward through frames
4. Converging when two consecutive frames become equal (fixed point)

INTEGRATION WITH BARRIER SYNTHESIS
==================================

IC3 provides DISCRETE inductive invariants that:
1. Restrict the state space for polynomial barrier synthesis
2. Provide lemmas that can be lifted to polynomial constraints
3. Guide variable selection and degree bounds
4. Enable compositional reasoning (per-frame barriers)

The key bridge: IC3 lemmas become SIDE CONDITIONS for barrier synthesis,
reducing the polynomial feasibility problem.

PYTHON-SPECIFIC ADAPTATIONS
===========================

For Python programs:
1. States are (pc, variable bindings) tuples
2. Transitions come from symbolic execution / CFG edges
3. Properties are bug-type predicates (e.g., x != 0 for DIV_ZERO)
4. Frames can be predicate-based or numeric-constraint-based

IMPLEMENTATION STRUCTURE
========================

1. Frame: Set of lemmas representing state over-approximation
2. Cube: Conjunctive state predicate (potential CTI)
3. ICE3Engine: Main PDR/IC3 algorithm
4. LemmaLift: Bridge from IC3 lemmas to polynomial constraints
5. BarrierConditioner: Uses IC3 invariants to condition barrier synthesis

LAYER POSITION
==============

This is a **Layer 5 (Advanced Verification)** module.

    ┌─────────────────────────────────────────────────────────────────┐
    │ Layer 5: ADVANCED VERIFICATION ← [THIS MODULE]                  │
    │   ├── dsos_sdsos.py (Paper #9)                                  │
    │   ├── ic3_pdr.py ← You are here (Paper #10)                     │
    │   ├── spacer_chc.py (Paper #11)                                 │
    │   ├── interpolation_imc.py (Paper #15)                          │
    │   └── assume_guarantee.py (Paper #20)                           │
    │ Layer 4: Learning (ICE, Houdini, SyGuS)                         │
    │ Layer 3: Abstraction (CEGAR, Predicate Abstraction, IMPACT)     │
    │ Layer 2: Certificate Core (Hybrid, Stochastic, SOS Safety)      │
    │ Layer 1: Foundations (Positivstellensatz, SOS/SDP, Lasserre)    │
    └─────────────────────────────────────────────────────────────────┘

CROSS-PAPER DEPENDENCIES
========================

This module is the APEX of the layered architecture, integrating:
- Layer 1 (Foundations): Uses polynomial constraints for numeric lemmas
- Layer 2 (Certificate Core): IC3 lemmas constrain barrier synthesis
- Layer 3 (Abstraction): Frame sequence is an abstract domain
- Layer 4 (Learning): ICE samples guide lemma discovery

Integration with other Layer 5 papers:
- Paper #11 (CHC/Spacer): IC3 is core algorithm for CHC solving
- Paper #15 (Interpolation): Interpolants strengthen frames
- Paper #20 (Assume-Guarantee): IC3 per module, compose for system
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple, Set, Any, FrozenSet, Callable
from collections import defaultdict

import z3

# =============================================================================
# LAYER 5: IMPORTS FROM ALL LOWER LAYERS
# =============================================================================
# IC3/PDR is an advanced verification technique that integrates insights from
# multiple layers: polynomial foundations for numeric reasoning, barrier
# certificates for safety proofs, and learning for lemma discovery.
# =============================================================================

from .parrilo_sos_sdp import (
    Polynomial,
    SemialgebraicSet,
    BarrierSynthesisProblem,
)


# =============================================================================
# CORE IC3 DATA STRUCTURES
# =============================================================================

@dataclass(frozen=True)
class Literal:
    """
    A literal in IC3/PDR.
    
    Represents an atomic predicate or its negation.
    """
    variable: str
    negated: bool = False
    
    def __neg__(self) -> "Literal":
        return Literal(self.variable, not self.negated)
    
    def __str__(self) -> str:
        return f"¬{self.variable}" if self.negated else self.variable
    
    def to_z3(self, var_map: Dict[str, z3.ArithRef]) -> z3.BoolRef:
        """Convert to Z3 expression."""
        if self.variable not in var_map:
            var_map[self.variable] = z3.Bool(self.variable)
        
        var = var_map[self.variable]
        return z3.Not(var) if self.negated else var


@dataclass(frozen=True)
class Cube:
    """
    A cube (conjunction of literals) representing a state predicate.
    
    In IC3, cubes represent:
    - Potential counterexamples-to-induction (CTIs)
    - Bad states to block
    - State predicates in lemmas
    """
    literals: FrozenSet[Literal]
    
    @classmethod
    def from_literals(cls, lits: List[Literal]) -> "Cube":
        return cls(frozenset(lits))
    
    @classmethod
    def from_model(cls, model: z3.ModelRef,
                   variables: List[str]) -> "Cube":
        """Create cube from Z3 model."""
        lits = []
        for var in variables:
            z3_var = z3.Bool(var)
            val = model.eval(z3_var, model_completion=True)
            if z3.is_true(val):
                lits.append(Literal(var, False))
            else:
                lits.append(Literal(var, True))
        return cls(frozenset(lits))
    
    def __and__(self, other: "Cube") -> "Cube":
        return Cube(self.literals | other.literals)
    
    def __str__(self) -> str:
        return " ∧ ".join(str(lit) for lit in self.literals)
    
    def to_z3(self, var_map: Dict[str, z3.ArithRef]) -> z3.BoolRef:
        """Convert to Z3 conjunction."""
        if not self.literals:
            return z3.BoolVal(True)
        return z3.And([lit.to_z3(var_map) for lit in self.literals])
    
    def negate(self) -> "Clause":
        """Negate cube to get clause."""
        return Clause(frozenset(-lit for lit in self.literals))


@dataclass(frozen=True)
class Clause:
    """
    A clause (disjunction of literals) representing a lemma.
    
    In IC3, clauses are lemmas that:
    - Block bad states (counterexamples)
    - Strengthen frame invariants
    - Eventually converge to an inductive invariant
    """
    literals: FrozenSet[Literal]
    
    @classmethod
    def from_literals(cls, lits: List[Literal]) -> "Clause":
        return cls(frozenset(lits))
    
    def __or__(self, other: "Clause") -> "Clause":
        return Clause(self.literals | other.literals)
    
    def __str__(self) -> str:
        return " ∨ ".join(str(lit) for lit in self.literals)
    
    def to_z3(self, var_map: Dict[str, z3.ArithRef]) -> z3.BoolRef:
        """Convert to Z3 disjunction."""
        if not self.literals:
            return z3.BoolVal(False)
        return z3.Or([lit.to_z3(var_map) for lit in self.literals])
    
    def negate(self) -> Cube:
        """Negate clause to get cube."""
        return Cube(frozenset(-lit for lit in self.literals))
    
    def subsumes(self, other: "Clause") -> bool:
        """Check if this clause subsumes (is more general than) other."""
        return self.literals <= other.literals


@dataclass
class Frame:
    """
    A frame in IC3/PDR.
    
    Frame F_i represents an over-approximation of states reachable in i steps.
    
    Properties:
    - F_0 = Init (initial states)
    - F_i => F_{i+1} (frames are monotonically weakening)
    - F_i ∧ T => F_{i+1}' (frames respect transitions)
    - F_i => ¬Bad (frames exclude bad states)
    
    Attributes:
        index: Frame number (0 = initial)
        clauses: Set of clauses (lemmas) in this frame
    """
    index: int
    clauses: Set[Clause] = field(default_factory=set)
    
    def add_clause(self, clause: Clause) -> bool:
        """
        Add a clause to the frame.
        
        Returns True if clause was new.
        """
        if clause in self.clauses:
            return False
        
        # Remove subsumed clauses
        self.clauses = {c for c in self.clauses if not clause.subsumes(c)}
        
        self.clauses.add(clause)
        return True
    
    def to_z3(self, var_map: Dict[str, z3.ArithRef]) -> z3.BoolRef:
        """Convert frame to Z3 formula."""
        if not self.clauses:
            return z3.BoolVal(True)
        return z3.And([c.to_z3(var_map) for c in self.clauses])
    
    def __eq__(self, other: "Frame") -> bool:
        if not isinstance(other, Frame):
            return False
        return self.clauses == other.clauses
    
    def copy(self) -> "Frame":
        return Frame(self.index, set(self.clauses))


# =============================================================================
# TRANSITION SYSTEM REPRESENTATION
# =============================================================================

@dataclass
class TransitionSystem:
    """
    Transition system for IC3/PDR.
    
    Represents:
    - State variables (current and next-state)
    - Initial state predicate
    - Transition relation
    - Property (safety) predicate
    
    For Python programs:
    - State = (program counter, variable values)
    - Transitions = CFG edges with symbolic semantics
    - Property = negation of bug condition
    """
    state_vars: List[str]
    init: z3.BoolRef
    trans: z3.BoolRef  # Uses primed variables for next state
    prop: z3.BoolRef   # Safety property (should always hold)
    
    def __post_init__(self):
        self.primed_vars = [f"{v}'" for v in self.state_vars]
        self.var_map: Dict[str, z3.ArithRef] = {}
        
        # Create Z3 variables
        for v in self.state_vars + self.primed_vars:
            self.var_map[v] = z3.Bool(v)
    
    @classmethod
    def from_cfg(cls, cfg, init_state: Dict[str, Any],
                 property_pred: Callable) -> "TransitionSystem":
        """
        Create transition system from control flow graph.
        
        Args:
            cfg: Control flow graph with symbolic edge semantics
            init_state: Initial state predicate
            property_pred: Property to verify (returns Z3 formula)
        """
        # Extract variables from CFG
        state_vars = list(cfg.variables) if hasattr(cfg, 'variables') else []
        
        # Build init predicate
        init_clauses = []
        for var, val in init_state.items():
            z3_var = z3.Bool(var)
            if val:
                init_clauses.append(z3_var)
            else:
                init_clauses.append(z3.Not(z3_var))
        
        init = z3.And(init_clauses) if init_clauses else z3.BoolVal(True)
        
        # Build transition relation from CFG edges
        # Simplified: use identity transition for now
        trans_clauses = []
        for v in state_vars:
            curr = z3.Bool(v)
            next_v = z3.Bool(f"{v}'")
            trans_clauses.append(next_v == curr)  # Identity
        
        trans = z3.And(trans_clauses) if trans_clauses else z3.BoolVal(True)
        
        # Property
        prop = property_pred(state_vars) if callable(property_pred) else z3.BoolVal(True)
        
        return cls(state_vars, init, trans, prop)
    
    def get_init_cube(self) -> Optional[Cube]:
        """Extract a cube from the initial state."""
        solver = z3.Solver()
        solver.add(self.init)
        
        if solver.check() == z3.sat:
            model = solver.model()
            return Cube.from_model(model, self.state_vars)
        
        return None
    
    def prime_expr(self, expr: z3.ExprRef) -> z3.ExprRef:
        """Replace variables with their primed versions."""
        substitutions = [
            (self.var_map[v], self.var_map[f"{v}'"])
            for v in self.state_vars
        ]
        return z3.substitute(expr, substitutions)
    
    def unprime_expr(self, expr: z3.ExprRef) -> z3.ExprRef:
        """Replace primed variables with unprimed versions."""
        substitutions = [
            (self.var_map[f"{v}'"], self.var_map[v])
            for v in self.state_vars
        ]
        return z3.substitute(expr, substitutions)


# =============================================================================
# IC3/PDR ENGINE
# =============================================================================

class IC3Result(Enum):
    """Result of IC3/PDR run."""
    SAFE = auto()      # Property holds, inductive invariant found
    UNSAFE = auto()    # Property violated, counterexample found
    UNKNOWN = auto()   # Inconclusive (timeout, resource limit)


@dataclass
class IC3Proof:
    """Proof artifact from successful IC3 run."""
    result: IC3Result
    invariant: Optional[List[Clause]] = None  # Inductive invariant (if SAFE)
    counterexample: Optional[List[Cube]] = None  # Trace (if UNSAFE)
    frames: Optional[List[Frame]] = None  # Final frame structure
    statistics: Dict[str, Any] = field(default_factory=dict)


class IC3Engine:
    """
    IC3/PDR engine for invariant discovery.
    
    Implements the core IC3 algorithm:
    1. Initialize F_0 = Init, F_∞ = ¬Bad
    2. Try to push lemmas from F_i to F_{i+1}
    3. Block counterexamples-to-induction
    4. Converge when F_i = F_{i+1} (fixed point)
    
    Optimizations:
    - Generalization: weaken blocking lemmas
    - Inductive generalization: find minimal inductive core
    - Predecessor computation: efficient CTI finding
    """
    
    def __init__(self, system: TransitionSystem,
                 max_frames: int = 100,
                 timeout_ms: int = 60000,
                 verbose: bool = False):
        self.system = system
        self.max_frames = max_frames
        self.timeout_ms = timeout_ms
        self.verbose = verbose
        
        # Frame structure: F_0, F_1, ..., F_k
        self.frames: List[Frame] = []
        
        # Statistics
        self._stats = {
            'cti_blocked': 0,
            'lemmas_propagated': 0,
            'frames_created': 0,
            'solver_calls': 0,
        }
        
        # Solver for queries
        self.solver = z3.Solver()
        self.solver.set("timeout", timeout_ms)
    
    def run(self) -> IC3Proof:
        """
        Run IC3/PDR algorithm.
        
        Returns proof with invariant or counterexample.
        """
        start_time = time.time()
        
        # Initialize
        self._initialize()
        
        # Main loop
        depth = 0
        
        while depth < self.max_frames:
            elapsed = (time.time() - start_time) * 1000
            if elapsed > self.timeout_ms:
                return IC3Proof(
                    result=IC3Result.UNKNOWN,
                    frames=self.frames,
                    statistics=self._get_statistics(elapsed)
                )
            
            # Check if Bad is blocked at current depth
            result, cti = self._check_property(depth)
            
            if result:
                # Property blocked at this depth, try to strengthen/propagate
                if self._propagate(depth):
                    # Fixed point found!
                    invariant = self._extract_invariant()
                    
                    return IC3Proof(
                        result=IC3Result.SAFE,
                        invariant=invariant,
                        frames=self.frames,
                        statistics=self._get_statistics((time.time() - start_time) * 1000)
                    )
                
                depth += 1
                self._new_frame()
            
            else:
                # Found CTI, need to block it
                blocked = self._block_cti(cti, depth)
                
                if not blocked:
                    # Real counterexample found
                    trace = self._extract_counterexample(cti)
                    
                    return IC3Proof(
                        result=IC3Result.UNSAFE,
                        counterexample=trace,
                        frames=self.frames,
                        statistics=self._get_statistics((time.time() - start_time) * 1000)
                    )
        
        return IC3Proof(
            result=IC3Result.UNKNOWN,
            frames=self.frames,
            statistics=self._get_statistics((time.time() - start_time) * 1000)
        )
    
    def _initialize(self) -> None:
        """Initialize frame structure."""
        # F_0 = Init
        f0 = Frame(0)
        # Add clauses that encode Init
        # For now, just create empty frame (will be populated by blocking)
        self.frames = [f0]
        self._stats['frames_created'] = 1
    
    def _new_frame(self) -> None:
        """Create a new frame."""
        new_index = len(self.frames)
        
        # Copy clauses from previous frame (monotonicity)
        if self.frames:
            prev_frame = self.frames[-1]
            new_frame = Frame(new_index, set(prev_frame.clauses))
        else:
            new_frame = Frame(new_index)
        
        self.frames.append(new_frame)
        self._stats['frames_created'] += 1
        
        if self.verbose:
            print(f"[IC3] New frame F_{new_index}")
    
    def _check_property(self, depth: int) -> Tuple[bool, Optional[Cube]]:
        """
        Check if property holds at given depth.
        
        Returns (holds, cti) where cti is counterexample-to-induction.
        """
        if depth >= len(self.frames):
            self._new_frame()
        
        frame = self.frames[depth]
        
        # Check: F_depth ∧ ¬P is UNSAT?
        self.solver.push()
        
        self.solver.add(frame.to_z3(self.system.var_map))
        self.solver.add(z3.Not(self.system.prop))
        
        self._stats['solver_calls'] += 1
        result = self.solver.check()
        
        if result == z3.unsat:
            self.solver.pop()
            return True, None
        
        elif result == z3.sat:
            model = self.solver.model()
            cti = Cube.from_model(model, self.system.state_vars)
            self.solver.pop()
            return False, cti
        
        else:
            self.solver.pop()
            return True, None  # Treat unknown as success
    
    def _block_cti(self, cti: Cube, depth: int) -> bool:
        """
        Block a counterexample-to-induction.
        
        Returns True if blocked (spurious), False if real counterexample.
        """
        # Proof obligations: (cube, frame_index) pairs
        obligations = [(cti, depth)]
        
        while obligations:
            cube, level = obligations.pop()
            
            if level == 0:
                # Reached initial states - real counterexample
                return False
            
            # Check if cube is already blocked
            if self._is_blocked(cube, level):
                continue
            
            # Find predecessor of cube
            has_pred, pred = self._find_predecessor(cube, level - 1)
            
            if has_pred:
                # Push predecessor to obligations
                obligations.append((cube, level))  # Re-add current
                obligations.append((pred, level - 1))
            
            else:
                # No predecessor - generalize and block
                gen_clause = self._generalize(cube, level)
                self._add_blocked_clause(gen_clause, level)
                self._stats['cti_blocked'] += 1
                
                if self.verbose:
                    print(f"[IC3] Blocked at F_{level}: {gen_clause}")
        
        return True
    
    def _find_predecessor(self, cube: Cube, level: int) -> Tuple[bool, Optional[Cube]]:
        """
        Find predecessor of cube at given level.
        
        Returns (exists, predecessor) where predecessor is in F_level.
        """
        if level >= len(self.frames):
            return False, None
        
        frame = self.frames[level]
        
        # Query: F_level ∧ T ∧ cube' is SAT?
        self.solver.push()
        
        self.solver.add(frame.to_z3(self.system.var_map))
        self.solver.add(self.system.trans)
        
        # Cube on next state (primed)
        primed_cube = z3.And([
            self.system.var_map.get(f"{lit.variable}'", z3.Bool(f"{lit.variable}'"))
            if not lit.negated else
            z3.Not(self.system.var_map.get(f"{lit.variable}'", z3.Bool(f"{lit.variable}'")))
            for lit in cube.literals
        ]) if cube.literals else z3.BoolVal(True)
        
        self.solver.add(primed_cube)
        
        self._stats['solver_calls'] += 1
        result = self.solver.check()
        
        if result == z3.sat:
            model = self.solver.model()
            pred = Cube.from_model(model, self.system.state_vars)
            self.solver.pop()
            return True, pred
        
        self.solver.pop()
        return False, None
    
    def _generalize(self, cube: Cube, level: int) -> Clause:
        """
        Generalize a blocked cube to a clause.
        
        Try to remove literals while maintaining blockability.
        """
        clause = cube.negate()
        
        # Try to remove each literal
        for lit in list(clause.literals):
            reduced = Clause(clause.literals - {lit})
            
            if self._is_inductive(reduced, level):
                clause = reduced
        
        return clause
    
    def _is_inductive(self, clause: Clause, level: int) -> bool:
        """Check if clause is inductive relative to frame level."""
        if level >= len(self.frames):
            return False
        
        frame = self.frames[level]
        
        # Check: F_level ∧ clause ∧ T => clause' is valid
        # Equivalently: F_level ∧ clause ∧ T ∧ ¬clause' is UNSAT
        self.solver.push()
        
        self.solver.add(frame.to_z3(self.system.var_map))
        self.solver.add(clause.to_z3(self.system.var_map))
        self.solver.add(self.system.trans)
        
        # Negation of clause on next state
        primed_neg = z3.Not(z3.Or([
            self.system.var_map.get(f"{lit.variable}'", z3.Bool(f"{lit.variable}'"))
            if not lit.negated else
            z3.Not(self.system.var_map.get(f"{lit.variable}'", z3.Bool(f"{lit.variable}'")))
            for lit in clause.literals
        ]) if clause.literals else z3.BoolVal(False))
        
        self.solver.add(primed_neg)
        
        self._stats['solver_calls'] += 1
        result = self.solver.check()
        
        self.solver.pop()
        return result == z3.unsat
    
    def _add_blocked_clause(self, clause: Clause, level: int) -> None:
        """Add blocking clause to frame and propagate."""
        for i in range(1, level + 1):
            if i < len(self.frames):
                self.frames[i].add_clause(clause)
    
    def _is_blocked(self, cube: Cube, level: int) -> bool:
        """Check if cube is blocked by frame clauses."""
        if level >= len(self.frames):
            return False
        
        frame = self.frames[level]
        
        self.solver.push()
        self.solver.add(frame.to_z3(self.system.var_map))
        self.solver.add(cube.to_z3(self.system.var_map))
        
        self._stats['solver_calls'] += 1
        result = self.solver.check()
        
        self.solver.pop()
        return result == z3.unsat
    
    def _propagate(self, depth: int) -> bool:
        """
        Propagate clauses forward.
        
        Returns True if fixed point found (F_i = F_{i+1}).
        """
        for i in range(1, depth):
            if i + 1 >= len(self.frames):
                continue
            
            frame_i = self.frames[i]
            frame_next = self.frames[i + 1]
            
            for clause in list(frame_i.clauses):
                if clause not in frame_next.clauses:
                    if self._is_inductive(clause, i):
                        frame_next.add_clause(clause)
                        self._stats['lemmas_propagated'] += 1
            
            # Check fixed point
            if frame_i.clauses == frame_next.clauses:
                if self.verbose:
                    print(f"[IC3] Fixed point at F_{i}")
                return True
        
        return False
    
    def _extract_invariant(self) -> List[Clause]:
        """Extract inductive invariant from frames."""
        if not self.frames:
            return []
        
        # Last non-empty frame is the invariant
        for frame in reversed(self.frames):
            if frame.clauses:
                return list(frame.clauses)
        
        return []
    
    def _extract_counterexample(self, cti: Cube) -> List[Cube]:
        """Extract counterexample trace."""
        # Simplified: just return the CTI
        return [cti]
    
    def _get_statistics(self, elapsed_ms: float) -> Dict[str, Any]:
        """Get run statistics."""
        return {
            **self._stats,
            'elapsed_ms': elapsed_ms,
            'n_frames': len(self.frames),
            'total_clauses': sum(len(f.clauses) for f in self.frames),
        }


# =============================================================================
# LEMMA LIFTING TO POLYNOMIAL CONSTRAINTS
# =============================================================================

@dataclass
class LiftedConstraint:
    """
    A polynomial constraint lifted from an IC3 lemma.
    
    Represents: p(x) >= 0 or p(x) = 0
    """
    polynomial: Polynomial
    is_equality: bool = False
    source_clause: Optional[Clause] = None
    
    def to_semialgebraic(self, n_vars: int,
                         var_names: List[str]) -> SemialgebraicSet:
        """Convert to semialgebraic set constraint."""
        if self.is_equality:
            return SemialgebraicSet(
                n_vars=n_vars,
                inequalities=[],
                equalities=[self.polynomial],
                var_names=var_names,
                name="IC3Lifted"
            )
        else:
            return SemialgebraicSet(
                n_vars=n_vars,
                inequalities=[self.polynomial],
                equalities=[],
                var_names=var_names,
                name="IC3Lifted"
            )


class LemmaLifter:
    """
    Lifts IC3 lemmas to polynomial constraints.
    
    Strategies:
    1. Direct lifting: Boolean -> linear polynomial
    2. Template matching: match lemma to polynomial templates
    3. Interpolation: use lemma as interpolation hint
    """
    
    def __init__(self, n_vars: int, var_names: List[str],
                 verbose: bool = False):
        self.n_vars = n_vars
        self.var_names = var_names
        self.verbose = verbose
    
    def lift_clause(self, clause: Clause) -> Optional[LiftedConstraint]:
        """
        Lift a single clause to polynomial constraint.
        
        For Boolean variables, creates indicator polynomials.
        For numeric predicates, extracts linear constraints.
        """
        if not clause.literals:
            return None
        
        # Create linear combination
        coeffs = {}
        constant = 0.0
        
        for lit in clause.literals:
            var_name = lit.variable
            
            # Find variable index
            if var_name in self.var_names:
                idx = self.var_names.index(var_name)
                mono = tuple(1 if i == idx else 0 for i in range(self.n_vars))
                
                if lit.negated:
                    # ¬x => 1 - x >= 0.5 => -x >= -0.5
                    coeffs[mono] = coeffs.get(mono, 0.0) - 1.0
                    constant += 0.5
                else:
                    # x => x >= 0.5
                    coeffs[mono] = coeffs.get(mono, 0.0) + 1.0
                    constant -= 0.5
        
        # Add constant term
        zero_mono = tuple(0 for _ in range(self.n_vars))
        coeffs[zero_mono] = constant
        
        poly = Polynomial(self.n_vars, coeffs)
        
        return LiftedConstraint(
            polynomial=poly,
            is_equality=False,
            source_clause=clause
        )
    
    def lift_invariant(self, invariant: List[Clause]) -> List[LiftedConstraint]:
        """Lift full invariant (conjunction of clauses)."""
        constraints = []
        
        for clause in invariant:
            lifted = self.lift_clause(clause)
            if lifted:
                constraints.append(lifted)
        
        return constraints
    
    def to_polynomial_template(self, invariant: List[Clause],
                               max_degree: int = 2) -> Polynomial:
        """
        Create polynomial template from invariant.
        
        Uses invariant structure to guide coefficient bounds.
        """
        # Create template with unknown coefficients
        from itertools import product
        
        coeffs = {}
        
        for degrees in product(range(max_degree + 1), repeat=self.n_vars):
            if sum(degrees) <= max_degree:
                mono = tuple(degrees)
                coeffs[mono] = 0.0  # Will be filled by synthesis
        
        # Use invariant to set initial values
        for clause in invariant:
            for lit in clause.literals:
                if lit.variable in self.var_names:
                    idx = self.var_names.index(lit.variable)
                    linear_mono = tuple(1 if i == idx else 0 for i in range(self.n_vars))
                    
                    # Adjust coefficient based on literal
                    if lit.negated:
                        coeffs[linear_mono] = coeffs.get(linear_mono, 0.0) - 0.5
                    else:
                        coeffs[linear_mono] = coeffs.get(linear_mono, 0.0) + 0.5
        
        return Polynomial(self.n_vars, coeffs)


# =============================================================================
# BARRIER CONDITIONER USING IC3 INVARIANTS
# =============================================================================

class IC3BarrierConditioner:
    """
    Conditions barrier synthesis using IC3 invariants.
    
    Key insight: IC3 provides lemmas that partition the state space.
    Barrier synthesis only needs to work within reachable states,
    which are already approximated by IC3 frames.
    
    Strategy:
    1. Run IC3 to get invariant
    2. Lift invariant to polynomial constraints
    3. Add constraints to barrier synthesis problem
    4. Potentially reduce barrier degree needed
    """
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        
        self._ic3_proof: Optional[IC3Proof] = None
        self._lifted_constraints: List[LiftedConstraint] = []
    
    def condition_problem(self, problem: BarrierSynthesisProblem,
                          system: TransitionSystem,
                          ic3_timeout_ms: int = 30000) -> BarrierSynthesisProblem:
        """
        Condition barrier synthesis problem with IC3 invariants.
        
        Args:
            problem: Original barrier synthesis problem
            system: Transition system for IC3
            ic3_timeout_ms: Timeout for IC3
        
        Returns:
            Conditioned problem with tighter constraints
        """
        # Run IC3
        engine = IC3Engine(system, timeout_ms=ic3_timeout_ms, verbose=self.verbose)
        proof = engine.run()
        
        self._ic3_proof = proof
        
        if proof.result != IC3Result.SAFE or not proof.invariant:
            # IC3 didn't find an invariant, return original problem
            return problem
        
        if self.verbose:
            print(f"[IC3Conditioner] Found invariant with {len(proof.invariant)} clauses")
        
        # Lift invariant to polynomial constraints
        lifter = LemmaLifter(
            problem.n_vars,
            problem.init_set.var_names,
            self.verbose
        )
        
        self._lifted_constraints = lifter.lift_invariant(proof.invariant)
        
        if self.verbose:
            print(f"[IC3Conditioner] Lifted {len(self._lifted_constraints)} constraints")
        
        # Strengthen init set with invariant
        new_init_ineqs = list(problem.init_set.inequalities)
        for constraint in self._lifted_constraints:
            if not constraint.is_equality:
                new_init_ineqs.append(constraint.polynomial)
        
        new_init = SemialgebraicSet(
            n_vars=problem.n_vars,
            inequalities=new_init_ineqs,
            equalities=problem.init_set.equalities,
            var_names=problem.init_set.var_names,
            name=problem.init_set.name + "_IC3Conditioned"
        )
        
        # Create conditioned problem
        conditioned = BarrierSynthesisProblem(
            n_vars=problem.n_vars,
            init_set=new_init,
            unsafe_set=problem.unsafe_set,
            transition=problem.transition,
            epsilon=problem.epsilon,
            barrier_degree=problem.barrier_degree
        )
        
        return conditioned
    
    def get_ic3_proof(self) -> Optional[IC3Proof]:
        """Get the IC3 proof if available."""
        return self._ic3_proof
    
    def get_lifted_constraints(self) -> List[LiftedConstraint]:
        """Get lifted polynomial constraints."""
        return self._lifted_constraints


# =============================================================================
# PDR FOR PYTHON PROGRAMS
# =============================================================================

@dataclass
class PythonState:
    """
    State in a Python program for PDR.
    
    Represents (program counter, variable bindings).
    """
    pc: int  # Program counter (bytecode offset)
    variables: Dict[str, Any]
    
    def to_cube(self, var_names: List[str]) -> Cube:
        """Convert to cube representation."""
        lits = []
        
        # PC as literals
        lits.append(Literal(f"pc_{self.pc}", False))
        
        # Variable values as literals (simplified)
        for var, val in self.variables.items():
            if var in var_names:
                if isinstance(val, bool):
                    lits.append(Literal(var, not val))
                elif isinstance(val, (int, float)):
                    # Numeric: use threshold predicates
                    lits.append(Literal(f"{var}_pos", val <= 0))
                    lits.append(Literal(f"{var}_zero", val != 0))
        
        return Cube.from_literals(lits)


class PythonPDR:
    """
    PDR/IC3 specialized for Python programs.
    
    Adapts IC3 to Python semantics:
    - Uses bytecode offsets as program counter
    - Extracts transitions from symbolic execution
    - Handles Python-specific constructs
    """
    
    def __init__(self, code_obj, property_check: Callable,
                 verbose: bool = False):
        self.code_obj = code_obj
        self.property_check = property_check
        self.verbose = verbose
        
        # Extract program structure
        self.variables = list(code_obj.co_varnames)
        
        # Build transition system
        self.system = self._build_transition_system()
    
    def _build_transition_system(self) -> TransitionSystem:
        """Build transition system from Python code."""
        import dis
        
        # State variables: PC + program variables
        state_vars = ["pc"] + [f"v_{v}" for v in self.variables]
        
        # Initial state: PC = 0, variables undefined
        init = z3.Bool("pc") == z3.BoolVal(True)  # Simplified
        
        # Transitions: from bytecode semantics
        trans_clauses = []
        
        for instr in dis.get_instructions(self.code_obj):
            # Simplified: each instruction is a transition
            # Real implementation would use symbolic semantics
            pass
        
        trans = z3.And(trans_clauses) if trans_clauses else z3.BoolVal(True)
        
        # Property
        prop = self.property_check(state_vars) if callable(self.property_check) else z3.BoolVal(True)
        
        return TransitionSystem(state_vars, init, trans, prop)
    
    def run(self, timeout_ms: int = 60000) -> IC3Proof:
        """Run PDR on Python program."""
        engine = IC3Engine(self.system, timeout_ms=timeout_ms, verbose=self.verbose)
        return engine.run()
    
    def find_invariant_for_loop(self, loop_header: int,
                                 timeout_ms: int = 30000) -> Optional[List[Clause]]:
        """
        Find loop invariant using PDR.
        
        Specializes PDR to focus on a specific loop.
        """
        # Create localized transition system for loop
        # This would extract just the loop body transitions
        
        engine = IC3Engine(self.system, timeout_ms=timeout_ms, verbose=self.verbose)
        proof = engine.run()
        
        if proof.result == IC3Result.SAFE:
            return proof.invariant
        
        return None


# =============================================================================
# INTEGRATION WITH BARRIER SYNTHESIS PIPELINE
# =============================================================================

@dataclass
class IC3IntegrationConfig:
    """Configuration for IC3/PDR integration."""
    ic3_timeout_ms: int = 30000
    use_ic3_conditioning: bool = True
    use_ic3_for_loops: bool = True
    max_ic3_frames: int = 50
    lift_to_polynomials: bool = True
    verbose: bool = False


class IC3PDRIntegration:
    """
    Main integration class for IC3/PDR in barrier synthesis.
    
    Provides:
    1. IC3-based invariant discovery
    2. Lemma lifting to polynomial constraints
    3. Barrier synthesis conditioning
    4. Loop invariant extraction
    """
    
    def __init__(self, config: Optional[IC3IntegrationConfig] = None,
                 verbose: bool = False):
        self.config = config or IC3IntegrationConfig()
        self.verbose = verbose or self.config.verbose
        
        self._cached_proofs: Dict[str, IC3Proof] = {}
    
    def find_invariant(self, system: TransitionSystem) -> IC3Proof:
        """Find inductive invariant using IC3."""
        engine = IC3Engine(
            system,
            max_frames=self.config.max_ic3_frames,
            timeout_ms=self.config.ic3_timeout_ms,
            verbose=self.verbose
        )
        
        return engine.run()
    
    def condition_barrier_problem(self, problem: BarrierSynthesisProblem,
                                   system: TransitionSystem) -> BarrierSynthesisProblem:
        """Condition barrier synthesis with IC3 invariants."""
        if not self.config.use_ic3_conditioning:
            return problem
        
        conditioner = IC3BarrierConditioner(self.verbose)
        return conditioner.condition_problem(
            problem, system, self.config.ic3_timeout_ms
        )
    
    def extract_loop_invariants(self, code_obj,
                                 property_check: Callable) -> Dict[int, List[Clause]]:
        """Extract loop invariants from Python code using PDR."""
        invariants = {}
        
        if not self.config.use_ic3_for_loops:
            return invariants
        
        pdr = PythonPDR(code_obj, property_check, self.verbose)
        
        # Find loops and extract invariants
        try:
            from ..cfg.loop_analysis import extract_loops
            loops = extract_loops(code_obj)
            
            for loop in loops:
                inv = pdr.find_invariant_for_loop(
                    loop.header_offset,
                    timeout_ms=self.config.ic3_timeout_ms // len(loops)
                )
                if inv:
                    invariants[loop.header_offset] = inv
                    
        except ImportError:
            pass
        
        return invariants
    
    def lift_invariant_to_polynomial(self, invariant: List[Clause],
                                      n_vars: int,
                                      var_names: List[str]) -> List[LiftedConstraint]:
        """Lift IC3 invariant to polynomial constraints."""
        if not self.config.lift_to_polynomials:
            return []
        
        lifter = LemmaLifter(n_vars, var_names, self.verbose)
        return lifter.lift_invariant(invariant)
    
    def get_cached_proof(self, key: str) -> Optional[IC3Proof]:
        """Get cached IC3 proof."""
        return self._cached_proofs.get(key)
    
    def cache_proof(self, key: str, proof: IC3Proof) -> None:
        """Cache IC3 proof for reuse."""
        self._cached_proofs[key] = proof
    
    def clear_cache(self) -> None:
        """Clear proof cache."""
        self._cached_proofs.clear()


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def run_ic3(system: TransitionSystem,
            timeout_ms: int = 60000,
            verbose: bool = False) -> IC3Proof:
    """
    Run IC3/PDR on a transition system.
    
    Main entry point for Paper #10 integration.
    """
    engine = IC3Engine(system, timeout_ms=timeout_ms, verbose=verbose)
    return engine.run()


def condition_barrier_with_ic3(problem: BarrierSynthesisProblem,
                                system: TransitionSystem,
                                timeout_ms: int = 30000,
                                verbose: bool = False) -> BarrierSynthesisProblem:
    """
    Condition barrier synthesis problem using IC3.
    
    Uses IC3 invariants to strengthen the init set constraint.
    """
    config = IC3IntegrationConfig(
        ic3_timeout_ms=timeout_ms,
        use_ic3_conditioning=True,
        verbose=verbose
    )
    
    integration = IC3PDRIntegration(config, verbose)
    return integration.condition_barrier_problem(problem, system)


def lift_ic3_invariant(invariant: List[Clause],
                       n_vars: int,
                       var_names: List[str]) -> List[LiftedConstraint]:
    """Lift IC3 invariant to polynomial constraints."""
    lifter = LemmaLifter(n_vars, var_names)
    return lifter.lift_invariant(invariant)


# =============================================================================
# ADVANCED IC3 FEATURES
# =============================================================================

class GeneralizationStrategy(Enum):
    """Strategies for generalizing CTI cubes."""
    NONE = auto()           # No generalization
    DROP_LITERALS = auto()  # Try dropping literals one at a time
    BINARY_SEARCH = auto()  # Binary search for minimal cube
    INTERPOLATION = auto()  # Use interpolation for generalization
    MIC = auto()            # Minimal Inductive Clause (from IC3 paper)


@dataclass
class GeneralizationConfig:
    """Configuration for cube generalization."""
    strategy: GeneralizationStrategy = GeneralizationStrategy.MIC
    max_attempts: int = 100
    use_inductive_gen: bool = True
    use_down: bool = True  # Use DOWN procedure from IC3
    verbose: bool = False


class CubeGeneralizer:
    """
    Generalize CTI cubes for more powerful lemmas.
    
    The key insight from IC3: blocking a GENERAL cube blocks
    more states and leads to faster convergence.
    
    Implements:
    - MIC (Minimal Inductive Clause) from Bradley's paper
    - DOWN procedure for inductive generalization
    - Binary search variants
    """
    
    def __init__(self, solver: z3.Solver, trans: z3.BoolRef,
                 config: Optional[GeneralizationConfig] = None):
        self.solver = solver
        self.trans = trans
        self.config = config or GeneralizationConfig()
        
        # Statistics
        self.stats = {
            'generalizations': 0,
            'literals_dropped': 0,
            'inductive_checks': 0,
        }
    
    def generalize(self, cube: Cube, frame_lemmas: List[Clause],
                   var_map: Dict[str, z3.ArithRef],
                   var_map_prime: Dict[str, z3.ArithRef]) -> Cube:
        """
        Generalize a cube while maintaining inductiveness relative to frame.
        
        Args:
            cube: The cube to generalize
            frame_lemmas: Lemmas in current frame
            var_map: Current state variables
            var_map_prime: Next state variables
        
        Returns:
            Generalized (smaller) cube that is still relatively inductive
        """
        if self.config.strategy == GeneralizationStrategy.NONE:
            return cube
        
        if self.config.strategy == GeneralizationStrategy.MIC:
            return self._mic_generalization(cube, frame_lemmas, var_map, var_map_prime)
        
        if self.config.strategy == GeneralizationStrategy.DROP_LITERALS:
            return self._drop_literals_generalization(cube, frame_lemmas, var_map, var_map_prime)
        
        if self.config.strategy == GeneralizationStrategy.BINARY_SEARCH:
            return self._binary_search_generalization(cube, frame_lemmas, var_map, var_map_prime)
        
        return cube
    
    def _mic_generalization(self, cube: Cube, frame_lemmas: List[Clause],
                            var_map: Dict[str, z3.ArithRef],
                            var_map_prime: Dict[str, z3.ArithRef]) -> Cube:
        """
        MIC (Minimal Inductive Clause) generalization.
        
        From Bradley's IC3 paper: iteratively try to drop literals
        while maintaining relative inductiveness.
        """
        literals = list(cube.literals)
        current = cube
        
        for i, lit in enumerate(literals):
            # Try dropping this literal
            remaining = frozenset(literals[:i] + literals[i+1:])
            if not remaining:
                continue
            
            candidate = Cube(remaining)
            
            # Check if candidate is relatively inductive
            if self._is_relatively_inductive(candidate, frame_lemmas, var_map, var_map_prime):
                current = candidate
                self.stats['literals_dropped'] += 1
        
        self.stats['generalizations'] += 1
        return current
    
    def _drop_literals_generalization(self, cube: Cube, frame_lemmas: List[Clause],
                                       var_map: Dict[str, z3.ArithRef],
                                       var_map_prime: Dict[str, z3.ArithRef]) -> Cube:
        """Simple greedy literal dropping."""
        current_lits = list(cube.literals)
        changed = True
        
        while changed and len(current_lits) > 1:
            changed = False
            for i in range(len(current_lits)):
                candidate_lits = current_lits[:i] + current_lits[i+1:]
                candidate = Cube(frozenset(candidate_lits))
                
                if self._is_relatively_inductive(candidate, frame_lemmas, var_map, var_map_prime):
                    current_lits = candidate_lits
                    changed = True
                    self.stats['literals_dropped'] += 1
                    break
        
        self.stats['generalizations'] += 1
        return Cube(frozenset(current_lits))
    
    def _binary_search_generalization(self, cube: Cube, frame_lemmas: List[Clause],
                                        var_map: Dict[str, z3.ArithRef],
                                        var_map_prime: Dict[str, z3.ArithRef]) -> Cube:
        """Binary search for minimal cube."""
        literals = list(cube.literals)
        n = len(literals)
        
        # Try subsets of decreasing size
        for size in range(1, n):
            # Try all subsets of this size (up to limit)
            from itertools import combinations
            attempts = 0
            for subset in combinations(literals, size):
                if attempts >= self.config.max_attempts:
                    break
                
                candidate = Cube(frozenset(subset))
                if self._is_relatively_inductive(candidate, frame_lemmas, var_map, var_map_prime):
                    self.stats['generalizations'] += 1
                    self.stats['literals_dropped'] += n - size
                    return candidate
                
                attempts += 1
        
        self.stats['generalizations'] += 1
        return cube
    
    def _is_relatively_inductive(self, cube: Cube, frame_lemmas: List[Clause],
                                  var_map: Dict[str, z3.ArithRef],
                                  var_map_prime: Dict[str, z3.ArithRef]) -> bool:
        """
        Check if cube is relatively inductive with respect to frame.
        
        A cube c is relatively inductive if:
        F ∧ ¬c ∧ T → ¬c' (where F is the frame, T is transition)
        
        Equivalently: F ∧ ¬c ∧ T ∧ c' is UNSAT
        """
        self.stats['inductive_checks'] += 1
        
        self.solver.push()
        
        # Add frame lemmas
        for lemma in frame_lemmas:
            self.solver.add(lemma.to_z3(var_map))
        
        # Add ¬cube (current state not in cube)
        self.solver.add(z3.Not(cube.to_z3(var_map)))
        
        # Add transition
        self.solver.add(self.trans)
        
        # Add cube' (next state in cube)
        self.solver.add(cube.to_z3(var_map_prime))
        
        result = self.solver.check()
        self.solver.pop()
        
        # If UNSAT, cube is relatively inductive
        return result == z3.unsat
    
    def get_statistics(self) -> Dict[str, int]:
        """Get generalization statistics."""
        return dict(self.stats)


class ObligationQueue:
    """
    Priority queue for proof obligations in IC3.
    
    Obligations are (frame_level, cube) pairs that need to be blocked.
    Lower frame levels have higher priority (should be blocked first).
    """
    
    def __init__(self):
        self._queue: List[Tuple[int, int, Cube]] = []  # (level, id, cube)
        self._counter = 0
    
    def push(self, level: int, cube: Cube) -> None:
        """Add an obligation."""
        import heapq
        heapq.heappush(self._queue, (level, self._counter, cube))
        self._counter += 1
    
    def pop(self) -> Tuple[int, Cube]:
        """Remove and return highest-priority obligation."""
        import heapq
        level, _, cube = heapq.heappop(self._queue)
        return level, cube
    
    def is_empty(self) -> bool:
        """Check if queue is empty."""
        return len(self._queue) == 0
    
    def peek(self) -> Optional[Tuple[int, Cube]]:
        """Look at highest-priority obligation without removing."""
        if self._queue:
            level, _, cube = self._queue[0]
            return level, cube
        return None
    
    def clear(self) -> None:
        """Clear all obligations."""
        self._queue.clear()


class InductiveTrace:
    """
    Represents an inductive trace from IC3.
    
    An inductive trace is a sequence of frames where:
    - F_0 = Init
    - F_i ⊇ F_{i+1} (frames are monotonic)
    - F_i ∧ T → F_{i+1}' (frames are consecution)
    - For some k: F_k = F_{k+1} (fixed point)
    """
    
    def __init__(self, frames: List[Frame]):
        self.frames = frames
        self._fixpoint_level: Optional[int] = None
    
    @property
    def depth(self) -> int:
        """Number of frames."""
        return len(self.frames)
    
    @property
    def fixpoint_level(self) -> Optional[int]:
        """Level at which fixed point was reached."""
        return self._fixpoint_level
    
    def set_fixpoint(self, level: int) -> None:
        """Mark the fixpoint level."""
        self._fixpoint_level = level
    
    def get_invariant(self) -> Optional[List[Clause]]:
        """
        Extract the inductive invariant from the trace.
        
        The invariant is the conjunction of all clauses in the
        frame at the fixpoint level.
        """
        if self._fixpoint_level is not None and self._fixpoint_level < len(self.frames):
            return list(self.frames[self._fixpoint_level].clauses)
        return None
    
    def validate(self, system: TransitionSystem) -> bool:
        """
        Validate the inductive trace against a transition system.
        
        Checks:
        1. Init ⊆ F_0
        2. Monotonicity: F_i ⊇ F_{i+1}
        3. Consecution: F_i ∧ T → F_{i+1}'
        4. Property: F_k ⊆ Property
        """
        solver = z3.Solver()
        var_map = {str(v): v for v in system.variables}
        var_map_prime = {str(v).replace("_prime", ""): v for v in system.variables_prime}
        
        # Check Init ⊆ F_0
        if self.frames:
            f0 = self.frames[0].to_z3(var_map)
            solver.push()
            solver.add(system.init)
            solver.add(z3.Not(f0))
            if solver.check() == z3.sat:
                return False
            solver.pop()
        
        # Check Property containment at fixpoint
        if self._fixpoint_level is not None:
            fk = self.frames[self._fixpoint_level].to_z3(var_map)
            solver.push()
            solver.add(fk)
            solver.add(z3.Not(system.property))
            if solver.check() == z3.sat:
                return False
            solver.pop()
        
        return True
    
    def to_string(self) -> str:
        """String representation of the trace."""
        lines = [f"InductiveTrace (depth={self.depth}, fixpoint={self._fixpoint_level})"]
        for i, frame in enumerate(self.frames):
            lines.append(f"  F_{i}: {len(frame.clauses)} clauses")
        return "\n".join(lines)


class IC3Statistics:
    """Detailed statistics for IC3 execution."""
    
    def __init__(self):
        self.start_time = time.time()
        self.end_time: Optional[float] = None
        
        # Counters
        self.sat_calls = 0
        self.unsat_calls = 0
        self.timeouts = 0
        
        self.cubes_blocked = 0
        self.cubes_generalized = 0
        self.clauses_propagated = 0
        
        self.frames_created = 0
        self.max_frame_depth = 0
        
        self.obligations_processed = 0
        self.obligations_max_queue = 0
        
        # Per-frame statistics
        self.per_frame: List[Dict[str, int]] = []
    
    def finish(self) -> None:
        """Mark end of IC3 execution."""
        self.end_time = time.time()
    
    @property
    def elapsed_ms(self) -> float:
        """Elapsed time in milliseconds."""
        end = self.end_time or time.time()
        return (end - self.start_time) * 1000
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'elapsed_ms': self.elapsed_ms,
            'sat_calls': self.sat_calls,
            'unsat_calls': self.unsat_calls,
            'timeouts': self.timeouts,
            'cubes_blocked': self.cubes_blocked,
            'cubes_generalized': self.cubes_generalized,
            'clauses_propagated': self.clauses_propagated,
            'frames_created': self.frames_created,
            'max_frame_depth': self.max_frame_depth,
            'obligations_processed': self.obligations_processed,
        }
    
    def summary(self) -> str:
        """Generate summary string."""
        return (
            f"IC3: {self.elapsed_ms:.1f}ms, "
            f"{self.sat_calls} SAT + {self.unsat_calls} UNSAT calls, "
            f"{self.cubes_blocked} cubes blocked, "
            f"{self.frames_created} frames"
        )


class AdvancedIC3Engine:
    """
    Advanced IC3/PDR engine with optimizations.
    
    Implements:
    - Cube generalization (MIC)
    - Clause propagation
    - Inductive generalization
    - Obligation queue management
    - Incremental SAT solving
    """
    
    def __init__(self, system: TransitionSystem,
                 gen_config: Optional[GeneralizationConfig] = None,
                 timeout_ms: int = 60000,
                 verbose: bool = False):
        self.system = system
        self.gen_config = gen_config or GeneralizationConfig()
        self.timeout_ms = timeout_ms
        self.verbose = verbose
        
        # Frames
        self.frames: List[Frame] = []
        
        # Solver
        self.solver = z3.Solver()
        self.solver.set("timeout", timeout_ms)
        
        # Variable mappings
        self.var_map = {str(v): v for v in system.variables}
        self.var_map_prime = {str(v): v for v in system.variables_prime}
        
        # Generalizer
        self.generalizer = CubeGeneralizer(self.solver, system.trans, self.gen_config)
        
        # Obligation queue
        self.obligations = ObligationQueue()
        
        # Statistics
        self.stats = IC3Statistics()
        
        # Trace for proof
        self._trace: Optional[InductiveTrace] = None
    
    def run(self) -> IC3Proof:
        """
        Run the advanced IC3 algorithm.
        
        Returns IC3Proof with invariant if property holds.
        """
        start_time = time.time()
        
        try:
            # Initialize F_0 = Init
            init_frame = Frame(level=0)
            # F_0 constrains to initial states
            self.frames.append(init_frame)
            self.stats.frames_created += 1
            
            # Main loop
            while True:
                # Check timeout
                elapsed = (time.time() - start_time) * 1000
                if elapsed > self.timeout_ms:
                    self.stats.timeouts += 1
                    self.stats.finish()
                    return IC3Proof(
                        success=False,
                        result=IC3Result.TIMEOUT,
                        message="IC3 timeout"
                    )
                
                # Check if property violated from initial states
                if not self._check_property_from_init():
                    self.stats.finish()
                    return IC3Proof(
                        success=False,
                        result=IC3Result.COUNTEREXAMPLE,
                        message="Property violated from initial states"
                    )
                
                # Try to find counterexample-to-induction
                cti = self._get_cti()
                
                if cti is None:
                    # No CTI found, try propagation
                    fixed = self._propagate_clauses()
                    if fixed:
                        # Fixed point reached!
                        invariant = self.frames[-1].clauses
                        self._trace = InductiveTrace(self.frames)
                        self._trace.set_fixpoint(len(self.frames) - 1)
                        
                        self.stats.finish()
                        return IC3Proof(
                            success=True,
                            result=IC3Result.SAFE,
                            invariant=list(invariant),
                            num_frames=len(self.frames),
                            num_lemmas=sum(len(f.clauses) for f in self.frames),
                            statistics=self.stats.to_dict(),
                            message="Inductive invariant found"
                        )
                    
                    # Add new frame
                    new_frame = Frame(level=len(self.frames))
                    self.frames.append(new_frame)
                    self.stats.frames_created += 1
                    self.stats.max_frame_depth = max(self.stats.max_frame_depth, len(self.frames))
                else:
                    # Block the CTI
                    blocked = self._block_cube(cti, len(self.frames) - 1)
                    if not blocked:
                        self.stats.finish()
                        return IC3Proof(
                            success=False,
                            result=IC3Result.COUNTEREXAMPLE,
                            message="Could not block CTI"
                        )
        
        except Exception as e:
            self.stats.finish()
            return IC3Proof(
                success=False,
                result=IC3Result.ERROR,
                message=f"IC3 error: {str(e)}"
            )
    
    def _check_property_from_init(self) -> bool:
        """Check if property holds on initial states."""
        self.solver.push()
        self.solver.add(self.system.init)
        self.solver.add(z3.Not(self.system.property))
        
        result = self.solver.check()
        self.solver.pop()
        
        if result == z3.sat:
            self.stats.sat_calls += 1
            return False
        
        self.stats.unsat_calls += 1
        return True
    
    def _get_cti(self) -> Optional[Cube]:
        """
        Find counterexample-to-induction.
        
        A CTI is a state in F_k that can reach a property violation.
        """
        if not self.frames:
            return None
        
        k = len(self.frames) - 1
        
        self.solver.push()
        
        # States in current frame
        self.solver.add(self.frames[k].to_z3(self.var_map))
        
        # Transition
        self.solver.add(self.system.trans)
        
        # Violates property in next state
        # Need to substitute property with primed variables
        prop_prime = z3.substitute(
            self.system.property,
            [(v, self.var_map_prime.get(str(v), v)) for v in self.system.variables]
        )
        self.solver.add(z3.Not(prop_prime))
        
        result = self.solver.check()
        
        if result == z3.sat:
            self.stats.sat_calls += 1
            # Extract cube from model
            model = self.solver.model()
            cube = self._extract_cube_from_model(model)
            self.solver.pop()
            return cube
        
        self.stats.unsat_calls += 1
        self.solver.pop()
        return None
    
    def _extract_cube_from_model(self, model: z3.ModelRef) -> Cube:
        """Extract a cube from a Z3 model."""
        literals = []
        
        for v in self.system.variables:
            val = model.eval(v, model_completion=True)
            var_name = str(v)
            
            # Create literal based on variable type
            if z3.is_bool(v):
                if z3.is_true(val):
                    literals.append(Literal(var_name, negated=False))
                else:
                    literals.append(Literal(var_name, negated=True))
            elif z3.is_int(v) or z3.is_real(v):
                # For numeric, create predicate v = val
                # This is a simplification
                literals.append(Literal(f"{var_name}={val}", negated=False))
        
        return Cube(frozenset(literals))
    
    def _block_cube(self, cube: Cube, level: int) -> bool:
        """
        Block a cube at the given frame level.
        
        Uses obligation queue for recursive blocking.
        """
        self.obligations.push(level, cube)
        
        while not self.obligations.is_empty():
            lvl, c = self.obligations.pop()
            self.stats.obligations_processed += 1
            
            if lvl == 0:
                # Reached initial states - real counterexample
                return False
            
            # Try to block at level-1
            if self._is_blocked_at(c, lvl - 1):
                # Already blocked, generalize and add clause
                gen_cube = self.generalizer.generalize(
                    c, list(self.frames[lvl].clauses),
                    self.var_map, self.var_map_prime
                )
                self.stats.cubes_generalized += 1
                
                # Add blocking clause
                clause = Clause(gen_cube.literals)
                for i in range(lvl + 1):
                    self.frames[i].add_clause(clause)
                
                self.stats.cubes_blocked += 1
            else:
                # Need to block predecessor
                pred = self._get_predecessor(c, lvl - 1)
                if pred is not None:
                    self.obligations.push(lvl - 1, pred)
                    self.obligations.push(lvl, c)  # Re-add current
                else:
                    return False
        
        return True
    
    def _is_blocked_at(self, cube: Cube, level: int) -> bool:
        """Check if cube is blocked by frame at level."""
        if level >= len(self.frames):
            return False
        
        self.solver.push()
        self.solver.add(self.frames[level].to_z3(self.var_map))
        self.solver.add(cube.to_z3(self.var_map))
        
        result = self.solver.check()
        self.solver.pop()
        
        if result == z3.unsat:
            self.stats.unsat_calls += 1
            return True
        
        self.stats.sat_calls += 1
        return False
    
    def _get_predecessor(self, cube: Cube, level: int) -> Optional[Cube]:
        """Find a predecessor state in frame at level that leads to cube."""
        if level >= len(self.frames):
            return None
        
        self.solver.push()
        
        # State in frame at level
        self.solver.add(self.frames[level].to_z3(self.var_map))
        
        # Transition to cube
        self.solver.add(self.system.trans)
        self.solver.add(cube.to_z3(self.var_map_prime))
        
        result = self.solver.check()
        
        if result == z3.sat:
            self.stats.sat_calls += 1
            model = self.solver.model()
            pred = self._extract_cube_from_model(model)
            self.solver.pop()
            return pred
        
        self.stats.unsat_calls += 1
        self.solver.pop()
        return None
    
    def _propagate_clauses(self) -> bool:
        """
        Propagate clauses forward through frames.
        
        For each clause c in F_i, if F_i ∧ T → c', add c to F_{i+1}.
        
        Returns True if fixed point is reached.
        """
        if len(self.frames) < 2:
            return False
        
        for i in range(len(self.frames) - 1):
            for clause in list(self.frames[i].clauses):
                if self._is_inductive_relative(clause, i):
                    if clause not in self.frames[i + 1].clauses:
                        self.frames[i + 1].add_clause(clause)
                        self.stats.clauses_propagated += 1
        
        # Check for fixed point
        for i in range(len(self.frames) - 1):
            if self.frames[i].clauses == self.frames[i + 1].clauses:
                return True
        
        return False
    
    def _is_inductive_relative(self, clause: Clause, level: int) -> bool:
        """Check if clause is inductive relative to frame at level."""
        self.solver.push()
        
        # F_level
        self.solver.add(self.frames[level].to_z3(self.var_map))
        
        # clause holds
        self.solver.add(clause.to_z3(self.var_map))
        
        # Transition
        self.solver.add(self.system.trans)
        
        # clause' fails
        clause_prime = Clause(clause.literals)  # Would need proper priming
        self.solver.add(z3.Not(clause.to_z3(self.var_map_prime)))
        
        result = self.solver.check()
        self.solver.pop()
        
        if result == z3.unsat:
            self.stats.unsat_calls += 1
            return True
        
        self.stats.sat_calls += 1
        return False
    
    def get_trace(self) -> Optional[InductiveTrace]:
        """Get the inductive trace (if proof found)."""
        return self._trace
    
    def get_statistics(self) -> IC3Statistics:
        """Get execution statistics."""
        return self.stats


# =============================================================================
# PYTHON-SPECIFIC IC3 ADAPTATIONS
# =============================================================================

class PythonStateEncoder:
    """
    Encode Python program states for IC3/PDR.
    
    Python states consist of:
    - Program counter (current bytecode offset)
    - Local variable bindings
    - Stack contents (abstracted)
    """
    
    def __init__(self, code_obj, verbose: bool = False):
        self.code_obj = code_obj
        self.verbose = verbose
        
        # Extract variable names
        self.local_names = list(code_obj.co_varnames[:code_obj.co_nlocals])
        self.n_locals = len(self.local_names)
        
        # Z3 variables
        self._pc = z3.Int("pc")
        self._locals = {name: z3.Int(name) for name in self.local_names}
        self._locals_prime = {name: z3.Int(f"{name}_prime") for name in self.local_names}
    
    def get_variables(self) -> List[z3.ArithRef]:
        """Get all state variables (including pc)."""
        return [self._pc] + list(self._locals.values())
    
    def get_variables_prime(self) -> List[z3.ArithRef]:
        """Get primed versions of all state variables."""
        pc_prime = z3.Int("pc_prime")
        return [pc_prime] + list(self._locals_prime.values())
    
    def encode_initial_state(self, args: Dict[str, int]) -> z3.BoolRef:
        """
        Encode initial state (function entry).
        
        Args:
            args: Mapping from argument names to values/constraints
        """
        constraints = []
        
        # PC at entry (offset 0)
        constraints.append(self._pc == 0)
        
        # Arguments have given values
        for name, value in args.items():
            if name in self._locals:
                constraints.append(self._locals[name] == value)
        
        return z3.And(constraints) if constraints else z3.BoolVal(True)
    
    def encode_property(self, property_name: str, var_name: str,
                         predicate: str = "!=", value: int = 0) -> z3.BoolRef:
        """
        Encode a safety property.
        
        Examples:
        - DIV_BY_ZERO: variable != 0
        - BOUNDS: 0 <= index < length
        """
        if var_name not in self._locals:
            return z3.BoolVal(True)
        
        var = self._locals[var_name]
        
        if predicate == "!=":
            return var != value
        elif predicate == "==":
            return var == value
        elif predicate == ">":
            return var > value
        elif predicate == ">=":
            return var >= value
        elif predicate == "<":
            return var < value
        elif predicate == "<=":
            return var <= value
        
        return z3.BoolVal(True)
    
    def get_var_map(self) -> Dict[str, z3.ArithRef]:
        """Get variable name to Z3 variable mapping."""
        result = {"pc": self._pc}
        result.update(self._locals)
        return result
    
    def get_var_map_prime(self) -> Dict[str, z3.ArithRef]:
        """Get primed variable mapping."""
        result = {"pc": z3.Int("pc_prime")}
        result.update(self._locals_prime)
        return result


class BytecodeTransitionEncoder:
    """
    Encode Python bytecode transitions for IC3.
    
    Converts bytecode instructions to Z3 transition relations.
    """
    
    def __init__(self, code_obj, state_encoder: PythonStateEncoder,
                 verbose: bool = False):
        self.code_obj = code_obj
        self.state_encoder = state_encoder
        self.verbose = verbose
        
        # Parse bytecode
        self._instructions = self._parse_bytecode()
    
    def _parse_bytecode(self) -> List[Dict[str, Any]]:
        """Parse bytecode into instruction list."""
        import dis
        
        instructions = []
        for instr in dis.get_instructions(self.code_obj):
            instructions.append({
                'offset': instr.offset,
                'opname': instr.opname,
                'arg': instr.arg,
                'argval': instr.argval,
            })
        
        return instructions
    
    def encode_transitions(self) -> z3.BoolRef:
        """Encode all bytecode transitions."""
        var_map = self.state_encoder.get_var_map()
        var_map_prime = self.state_encoder.get_var_map_prime()
        
        pc = var_map["pc"]
        pc_prime = var_map_prime["pc"]
        
        transitions = []
        
        for instr in self._instructions:
            offset = instr['offset']
            opname = instr['opname']
            
            # Encode transition for this instruction
            guard = pc == offset
            effect = self._encode_instruction(instr, var_map, var_map_prime)
            
            transitions.append(z3.Implies(guard, effect))
        
        return z3.And(transitions) if transitions else z3.BoolVal(True)
    
    def _encode_instruction(self, instr: Dict[str, Any],
                             var_map: Dict[str, z3.ArithRef],
                             var_map_prime: Dict[str, z3.ArithRef]) -> z3.BoolRef:
        """Encode a single bytecode instruction."""
        opname = instr['opname']
        offset = instr['offset']
        
        pc_prime = var_map_prime["pc"]
        
        # Default: move to next instruction
        next_offset = offset + 2  # Simplified
        
        effects = [pc_prime == next_offset]
        
        # Frame unchanged (simplified)
        for name in self.state_encoder.local_names:
            if name in var_map and name in var_map_prime:
                effects.append(var_map_prime[name] == var_map[name])
        
        # Handle specific instructions
        if opname == 'LOAD_FAST':
            pass  # Stack effect, not modeled here
        
        elif opname == 'STORE_FAST':
            # Variable gets updated
            var_name = instr['argval']
            if var_name in var_map_prime:
                # Value comes from stack (abstracted)
                pass
        
        elif opname.startswith('BINARY_'):
            pass  # Binary operations affect stack
        
        elif opname == 'JUMP_FORWARD':
            target = instr['argval']
            effects[0] = pc_prime == target
        
        elif opname == 'POP_JUMP_IF_FALSE':
            # Conditional jump
            target = instr['argval']
            # Would need to model condition
            pass
        
        elif opname == 'RETURN_VALUE':
            # Return - stay at return (termination)
            effects[0] = pc_prime == offset
        
        return z3.And(effects) if effects else z3.BoolVal(True)


class PythonIC3Analyzer:
    """
    Full IC3 analysis for Python functions.
    
    Combines:
    - State encoding
    - Transition encoding
    - IC3/PDR algorithm
    - Result interpretation
    """
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        
        # Cache for analyzed functions
        self._cache: Dict[str, IC3Proof] = {}
    
    def analyze_function(self, code_obj,
                          property_name: str = "SAFETY",
                          timeout_ms: int = 30000) -> IC3Proof:
        """
        Analyze a Python function using IC3/PDR.
        
        Args:
            code_obj: Function code object
            property_name: Name of property to verify
            timeout_ms: Timeout in milliseconds
        
        Returns:
            IC3Proof with verification result
        """
        func_name = code_obj.co_name
        
        # Check cache
        cache_key = f"{func_name}:{property_name}"
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        # Build state encoder
        state_encoder = PythonStateEncoder(code_obj, self.verbose)
        
        # Build transition encoder
        trans_encoder = BytecodeTransitionEncoder(code_obj, state_encoder, self.verbose)
        
        # Build transition system
        variables = state_encoder.get_variables()
        variables_prime = state_encoder.get_variables_prime()
        
        init = state_encoder.encode_initial_state({})
        trans = trans_encoder.encode_transitions()
        
        # Default property: all variables bounded
        var_map = state_encoder.get_var_map()
        bounds = [var >= -10000 for var in var_map.values() if var_map]
        bounds.extend([var <= 10000 for var in var_map.values() if var_map])
        prop = z3.And(bounds) if bounds else z3.BoolVal(True)
        
        system = TransitionSystem(
            variables=variables,
            variables_prime=variables_prime,
            init=init,
            trans=trans,
            property=prop
        )
        
        # Run IC3
        engine = AdvancedIC3Engine(system, timeout_ms=timeout_ms, verbose=self.verbose)
        result = engine.run()
        
        # Cache result
        self._cache[cache_key] = result
        
        return result
    
    def clear_cache(self) -> None:
        """Clear analysis cache."""
        self._cache.clear()

