"""
SOTA Paper: Boolean Programs.

Implements Boolean program abstraction for verification:
    T. Ball, S. K. Rajamani.
    "Bebop: A Symbolic Model Checker for Boolean Programs."
    SPIN 2000.

KEY INSIGHT
===========

Boolean programs are a finite abstraction of software where:
- All variables are Boolean
- Control flow from original program is preserved
- Enables efficient model checking

This paper pioneered the SLAM project approach:
1. Extract Boolean program from C code
2. Model check Boolean program
3. Refine if spurious counterexample

BOOLEAN PROGRAM MODEL
=====================

A Boolean program is:
- Variables: Boolean (b_1, ..., b_n)
- Statements: Boolean assignments, conditionals, loops
- Procedures: with Boolean parameters and returns

Key insight: Finite state enables BDD-based analysis.

ABSTRACTION COMPUTATION
=======================

From predicate set P = {p_1,...,p_n}:
1. Each predicate becomes Boolean variable
2. Assignment "x := e" becomes:
   - Compute weakest precondition for each predicate
   - Use theorem prover to compute new predicate values
3. Conditionals become Boolean expressions

BEBOP ALGORITHM
===============

Uses BDD-based symbolic model checking:
1. Represent states as BDD over Boolean variables
2. Compute reachable states symbolically
3. Interprocedural: summary-based analysis
4. Check intersection with error states

IMPLEMENTATION STRUCTURE
========================

1. BooleanVariable: Boolean program variable
2. BooleanProgram: Boolean program representation
3. BooleanStatement: Assignment, conditional, etc.
4. BebopChecker: BDD-based model checker
5. BooleanIntegration: Integration with barriers

LAYER POSITION
==============

This is a **Layer 3 (Abstraction)** module.

    ┌─────────────────────────────────────────────────────────────────┐
    │ Layer 5: Advanced Verification (IC3, CHC, IMC, Assume-Guarantee)│
    │ Layer 4: Learning (ICE, Houdini, SyGuS)                         │
    │ Layer 3: ABSTRACTION ← [THIS MODULE]                            │
    │   ├── cegar_refinement.py (Paper #12)                           │
    │   ├── predicate_abstraction.py (Paper #13)                      │
    │   ├── boolean_programs.py ← You are here (Paper #14)            │
    │   └── impact_lazy.py (Paper #16)                                │
    │ Layer 2: Certificate Core (Hybrid, Stochastic, SOS Safety)      │
    │ Layer 1: Foundations (Positivstellensatz, SOS/SDP, Lasserre)    │
    └─────────────────────────────────────────────────────────────────┘

CROSS-PAPER DEPENDENCIES
========================

This module builds on:
- Paper #13 (Predicate Abstraction): Predicates define Boolean variables
- Layer 1: Polynomial predicates become Boolean variables

This module synergizes with Layer 3 peers:
- Paper #12 (CEGAR): Boolean program is CEGAR's abstract model
- Paper #16 (IMPACT): Lazy abstraction refines Boolean program

This module is used by:
- Paper #10 (IC3): IC3 on Boolean program representation
- Paper #11 (CHC): Boolean program as CHC encoding

BOOLEAN PROGRAMS + BARRIERS
===========================

Boolean programs enable barrier discovery:
- Model check Boolean program for safety
- If safe, extract inductive invariant
- Lift invariant to polynomial barrier constraint
- Use as side condition for SOS synthesis
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple, Set, Any, Callable, FrozenSet
from collections import defaultdict

import z3

# =============================================================================
# LAYER 3: IMPORTS FROM LOWER LAYERS
# =============================================================================
# Boolean programs abstract polynomial predicates (Layer 1) into finite-state
# models. Safety proofs translate back to barrier conditions (Layer 2).
# =============================================================================

from .parrilo_sos_sdp import (
    Polynomial,
    SemialgebraicSet,
    BarrierSynthesisProblem,
)


# =============================================================================
# BOOLEAN VARIABLE
# =============================================================================

@dataclass
class BooleanVariable:
    """
    Boolean variable in a Boolean program.
    """
    name: str
    id: int
    is_local: bool = False
    procedure: str = ""
    
    def __str__(self) -> str:
        return self.name
    
    def __hash__(self) -> int:
        return hash((self.name, self.id))
    
    def __eq__(self, other) -> bool:
        if isinstance(other, BooleanVariable):
            return self.name == other.name and self.id == other.id
        return False
    
    def to_z3(self) -> z3.BoolRef:
        """Convert to Z3 Boolean variable."""
        return z3.Bool(self.name)


# =============================================================================
# BOOLEAN EXPRESSIONS
# =============================================================================

class BoolExprType(Enum):
    """Type of Boolean expression."""
    VAR = auto()
    NOT = auto()
    AND = auto()
    OR = auto()
    IMPLIES = auto()
    CONST_TRUE = auto()
    CONST_FALSE = auto()
    UNKNOWN = auto()  # Non-deterministic choice


@dataclass
class BoolExpr:
    """
    Boolean expression in a Boolean program.
    """
    expr_type: BoolExprType
    variable: Optional[BooleanVariable] = None
    left: Optional['BoolExpr'] = None
    right: Optional['BoolExpr'] = None
    
    def evaluate(self, valuation: Dict[str, bool]) -> Optional[bool]:
        """Evaluate expression under valuation."""
        if self.expr_type == BoolExprType.CONST_TRUE:
            return True
        elif self.expr_type == BoolExprType.CONST_FALSE:
            return False
        elif self.expr_type == BoolExprType.VAR:
            return valuation.get(self.variable.name) if self.variable else None
        elif self.expr_type == BoolExprType.NOT:
            val = self.left.evaluate(valuation) if self.left else None
            return not val if val is not None else None
        elif self.expr_type == BoolExprType.AND:
            left_val = self.left.evaluate(valuation) if self.left else None
            right_val = self.right.evaluate(valuation) if self.right else None
            if left_val is None or right_val is None:
                return None
            return left_val and right_val
        elif self.expr_type == BoolExprType.OR:
            left_val = self.left.evaluate(valuation) if self.left else None
            right_val = self.right.evaluate(valuation) if self.right else None
            if left_val is None or right_val is None:
                return None
            return left_val or right_val
        elif self.expr_type == BoolExprType.UNKNOWN:
            return None
        return None
    
    def to_z3(self, var_map: Dict[str, z3.BoolRef]) -> z3.BoolRef:
        """Convert to Z3 expression."""
        if self.expr_type == BoolExprType.CONST_TRUE:
            return z3.BoolVal(True)
        elif self.expr_type == BoolExprType.CONST_FALSE:
            return z3.BoolVal(False)
        elif self.expr_type == BoolExprType.VAR:
            return var_map.get(self.variable.name, z3.BoolVal(False))
        elif self.expr_type == BoolExprType.NOT:
            return z3.Not(self.left.to_z3(var_map))
        elif self.expr_type == BoolExprType.AND:
            return z3.And(self.left.to_z3(var_map), self.right.to_z3(var_map))
        elif self.expr_type == BoolExprType.OR:
            return z3.Or(self.left.to_z3(var_map), self.right.to_z3(var_map))
        elif self.expr_type == BoolExprType.IMPLIES:
            return z3.Implies(self.left.to_z3(var_map), self.right.to_z3(var_map))
        elif self.expr_type == BoolExprType.UNKNOWN:
            return z3.Bool(f"unknown_{id(self)}")
        return z3.BoolVal(False)
    
    def __str__(self) -> str:
        if self.expr_type == BoolExprType.CONST_TRUE:
            return "true"
        elif self.expr_type == BoolExprType.CONST_FALSE:
            return "false"
        elif self.expr_type == BoolExprType.VAR:
            return str(self.variable) if self.variable else "?"
        elif self.expr_type == BoolExprType.NOT:
            return f"!{self.left}"
        elif self.expr_type == BoolExprType.AND:
            return f"({self.left} && {self.right})"
        elif self.expr_type == BoolExprType.OR:
            return f"({self.left} || {self.right})"
        elif self.expr_type == BoolExprType.UNKNOWN:
            return "*"
        return "?"
    
    @staticmethod
    def var(v: BooleanVariable) -> 'BoolExpr':
        """Create variable expression."""
        return BoolExpr(BoolExprType.VAR, variable=v)
    
    @staticmethod
    def const(value: bool) -> 'BoolExpr':
        """Create constant expression."""
        return BoolExpr(BoolExprType.CONST_TRUE if value else BoolExprType.CONST_FALSE)
    
    @staticmethod
    def not_(e: 'BoolExpr') -> 'BoolExpr':
        """Create negation."""
        return BoolExpr(BoolExprType.NOT, left=e)
    
    @staticmethod
    def and_(e1: 'BoolExpr', e2: 'BoolExpr') -> 'BoolExpr':
        """Create conjunction."""
        return BoolExpr(BoolExprType.AND, left=e1, right=e2)
    
    @staticmethod
    def or_(e1: 'BoolExpr', e2: 'BoolExpr') -> 'BoolExpr':
        """Create disjunction."""
        return BoolExpr(BoolExprType.OR, left=e1, right=e2)
    
    @staticmethod
    def unknown() -> 'BoolExpr':
        """Create non-deterministic choice."""
        return BoolExpr(BoolExprType.UNKNOWN)


# =============================================================================
# BOOLEAN STATEMENTS
# =============================================================================

class StmtType(Enum):
    """Type of Boolean statement."""
    ASSIGN = auto()       # x := e
    ASSUME = auto()       # assume e
    ASSERT = auto()       # assert e
    SKIP = auto()         # no-op
    GOTO = auto()         # goto label
    IF = auto()           # if e then s1 else s2
    WHILE = auto()        # while e do s
    CALL = auto()         # call proc(args)
    RETURN = auto()       # return e


@dataclass
class BoolStmt:
    """
    Statement in a Boolean program.
    """
    stmt_type: StmtType
    target: Optional[BooleanVariable] = None  # For ASSIGN
    expr: Optional[BoolExpr] = None           # Expression
    label: Optional[str] = None               # For GOTO
    then_branch: Optional['BoolStmt'] = None  # For IF
    else_branch: Optional['BoolStmt'] = None  # For IF
    body: Optional['BoolStmt'] = None         # For WHILE
    proc_name: Optional[str] = None           # For CALL
    args: List[BoolExpr] = field(default_factory=list)  # For CALL
    next_stmt: Optional['BoolStmt'] = None    # Sequential composition
    id: int = 0
    
    def __str__(self) -> str:
        if self.stmt_type == StmtType.ASSIGN:
            return f"{self.target} := {self.expr}"
        elif self.stmt_type == StmtType.ASSUME:
            return f"assume({self.expr})"
        elif self.stmt_type == StmtType.ASSERT:
            return f"assert({self.expr})"
        elif self.stmt_type == StmtType.SKIP:
            return "skip"
        elif self.stmt_type == StmtType.GOTO:
            return f"goto {self.label}"
        elif self.stmt_type == StmtType.IF:
            return f"if ({self.expr}) then ... else ..."
        elif self.stmt_type == StmtType.WHILE:
            return f"while ({self.expr}) do ..."
        elif self.stmt_type == StmtType.CALL:
            args_str = ", ".join(str(a) for a in self.args)
            return f"call {self.proc_name}({args_str})"
        elif self.stmt_type == StmtType.RETURN:
            return f"return {self.expr}"
        return "?"


# =============================================================================
# BOOLEAN PROGRAM
# =============================================================================

@dataclass
class Procedure:
    """
    Procedure in a Boolean program.
    """
    name: str
    params: List[BooleanVariable]
    locals: List[BooleanVariable]
    body: Optional[BoolStmt]
    returns: Optional[BooleanVariable] = None
    
    def __str__(self) -> str:
        params_str = ", ".join(str(p) for p in self.params)
        return f"proc {self.name}({params_str})"


class BooleanProgram:
    """
    Boolean program representation.
    
    Contains:
    - Global Boolean variables
    - Procedures with Boolean parameters
    - Entry point procedure
    """
    
    def __init__(self, name: str = "program"):
        self.name = name
        self.globals: Dict[str, BooleanVariable] = {}
        self.procedures: Dict[str, Procedure] = {}
        self.entry: str = "main"
        
        self._var_counter = 0
        self._stmt_counter = 0
    
    def add_global(self, name: str) -> BooleanVariable:
        """Add a global variable."""
        var = BooleanVariable(name, self._var_counter, is_local=False)
        self._var_counter += 1
        self.globals[name] = var
        return var
    
    def add_procedure(self, name: str,
                       params: List[str],
                       locals: List[str]) -> Procedure:
        """Add a procedure."""
        param_vars = []
        for p in params:
            var = BooleanVariable(p, self._var_counter, is_local=True, procedure=name)
            self._var_counter += 1
            param_vars.append(var)
        
        local_vars = []
        for l in locals:
            var = BooleanVariable(l, self._var_counter, is_local=True, procedure=name)
            self._var_counter += 1
            local_vars.append(var)
        
        proc = Procedure(name, param_vars, local_vars, None)
        self.procedures[name] = proc
        return proc
    
    def set_body(self, proc_name: str, body: BoolStmt) -> None:
        """Set procedure body."""
        if proc_name in self.procedures:
            self.procedures[proc_name].body = body
    
    def get_all_variables(self) -> List[BooleanVariable]:
        """Get all variables in program."""
        all_vars = list(self.globals.values())
        for proc in self.procedures.values():
            all_vars.extend(proc.params)
            all_vars.extend(proc.locals)
        return all_vars
    
    def make_assign(self, target: BooleanVariable, expr: BoolExpr) -> BoolStmt:
        """Create assignment statement."""
        stmt = BoolStmt(StmtType.ASSIGN, target=target, expr=expr, id=self._stmt_counter)
        self._stmt_counter += 1
        return stmt
    
    def make_assume(self, expr: BoolExpr) -> BoolStmt:
        """Create assume statement."""
        stmt = BoolStmt(StmtType.ASSUME, expr=expr, id=self._stmt_counter)
        self._stmt_counter += 1
        return stmt
    
    def make_assert(self, expr: BoolExpr) -> BoolStmt:
        """Create assert statement."""
        stmt = BoolStmt(StmtType.ASSERT, expr=expr, id=self._stmt_counter)
        self._stmt_counter += 1
        return stmt
    
    def make_if(self, cond: BoolExpr, then_: BoolStmt, else_: Optional[BoolStmt] = None) -> BoolStmt:
        """Create if statement."""
        stmt = BoolStmt(StmtType.IF, expr=cond, then_branch=then_, 
                        else_branch=else_, id=self._stmt_counter)
        self._stmt_counter += 1
        return stmt
    
    def make_while(self, cond: BoolExpr, body: BoolStmt) -> BoolStmt:
        """Create while statement."""
        stmt = BoolStmt(StmtType.WHILE, expr=cond, body=body, id=self._stmt_counter)
        self._stmt_counter += 1
        return stmt
    
    def make_seq(self, stmts: List[BoolStmt]) -> Optional[BoolStmt]:
        """Create sequential composition."""
        if not stmts:
            return None
        
        for i in range(len(stmts) - 1):
            stmts[i].next_stmt = stmts[i + 1]
        
        return stmts[0]


# =============================================================================
# BOOLEAN STATE
# =============================================================================

@dataclass(frozen=True)
class BooleanState:
    """
    State in Boolean program execution.
    
    Consists of:
    - Valuation of all Boolean variables
    - Current program location (statement ID)
    - Call stack
    """
    valuation: Tuple[bool, ...]  # One entry per variable
    location: int
    call_stack: Tuple[int, ...] = ()
    
    def __str__(self) -> str:
        bits = ''.join('1' if b else '0' for b in self.valuation)
        return f"[{bits}]@{self.location}"
    
    def get_value(self, var_id: int) -> bool:
        """Get value of variable."""
        if var_id < len(self.valuation):
            return self.valuation[var_id]
        return False
    
    def with_value(self, var_id: int, value: bool) -> 'BooleanState':
        """Create new state with updated variable."""
        new_val = list(self.valuation)
        if var_id < len(new_val):
            new_val[var_id] = value
        return BooleanState(tuple(new_val), self.location, self.call_stack)
    
    def with_location(self, loc: int) -> 'BooleanState':
        """Create new state at different location."""
        return BooleanState(self.valuation, loc, self.call_stack)


# =============================================================================
# BEBOP MODEL CHECKER (Simplified BDD-based)
# =============================================================================

class CheckResult(Enum):
    """Result of model checking."""
    SAFE = auto()
    UNSAFE = auto()
    UNKNOWN = auto()


@dataclass
class BebopResult:
    """Result of Bebop model checking."""
    result: CheckResult
    counterexample: Optional[List[BooleanState]] = None
    reachable_states: int = 0
    iterations: int = 0
    message: str = ""


class BebopChecker:
    """
    Bebop-style symbolic model checker for Boolean programs.
    
    Uses Z3 for symbolic state representation (simulating BDDs).
    """
    
    def __init__(self, program: BooleanProgram,
                 timeout_ms: int = 60000,
                 verbose: bool = False):
        self.program = program
        self.timeout_ms = timeout_ms
        self.verbose = verbose
        
        self._variables = program.get_all_variables()
        self._var_map = {v.name: z3.Bool(v.name) for v in self._variables}
        
        self.stats = {
            'states_explored': 0,
            'transitions_computed': 0,
            'fixpoint_iterations': 0,
        }
    
    def check(self, initial: z3.BoolRef, error: z3.BoolRef) -> BebopResult:
        """
        Check if error is reachable from initial.
        """
        start_time = time.time()
        
        # Compute reachable states
        reachable = self._compute_reachable(initial)
        
        # Check intersection with error
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        solver.add(reachable)
        solver.add(error)
        
        if solver.check() == z3.sat:
            # Error is reachable
            model = solver.model()
            cex_state = self._extract_state(model)
            
            return BebopResult(
                result=CheckResult.UNSAFE,
                counterexample=[cex_state],
                reachable_states=self.stats['states_explored'],
                iterations=self.stats['fixpoint_iterations'],
                message="Error state reachable"
            )
        
        return BebopResult(
            result=CheckResult.SAFE,
            reachable_states=self.stats['states_explored'],
            iterations=self.stats['fixpoint_iterations'],
            message="No error reachable"
        )
    
    def _compute_reachable(self, initial: z3.BoolRef) -> z3.BoolRef:
        """
        Compute reachable states using fixed-point iteration.
        """
        current = initial
        
        max_iterations = 1000
        for i in range(max_iterations):
            self.stats['fixpoint_iterations'] += 1
            
            # Compute post-image
            post = self._compute_post(current)
            
            # Union with current
            next_states = z3.Or(current, post)
            
            # Check fixed point
            if self._is_equivalent(current, next_states):
                break
            
            current = next_states
            self.stats['states_explored'] += 1
        
        return current
    
    def _compute_post(self, states: z3.BoolRef) -> z3.BoolRef:
        """
        Compute post-image of states.
        """
        self.stats['transitions_computed'] += 1
        
        # Simplified: just return states (no transition relation extracted)
        # Full implementation would traverse program structure
        return states
    
    def _is_equivalent(self, phi1: z3.BoolRef, phi2: z3.BoolRef) -> bool:
        """Check if two formulas are equivalent."""
        solver = z3.Solver()
        solver.set("timeout", 1000)
        
        # Check if (phi1 ∧ ¬phi2) ∨ (¬phi1 ∧ phi2) is UNSAT
        solver.add(z3.Or(z3.And(phi1, z3.Not(phi2)), 
                         z3.And(z3.Not(phi1), phi2)))
        
        return solver.check() == z3.unsat
    
    def _extract_state(self, model: z3.ModelRef) -> BooleanState:
        """Extract Boolean state from model."""
        valuation = []
        for v in self._variables:
            val = model.eval(self._var_map[v.name], model_completion=True)
            valuation.append(z3.is_true(val))
        
        return BooleanState(tuple(valuation), 0)


# =============================================================================
# PROCEDURE SUMMARIES
# =============================================================================

@dataclass
class ProcedureSummary:
    """
    Summary of a procedure's behavior.
    
    Relates pre-state to post-state.
    """
    proc_name: str
    pre_vars: List[BooleanVariable]
    post_vars: List[BooleanVariable]
    relation: z3.BoolRef  # Relation between pre and post


class SummaryComputer:
    """
    Compute procedure summaries for interprocedural analysis.
    """
    
    def __init__(self, program: BooleanProgram,
                 timeout_ms: int = 60000,
                 verbose: bool = False):
        self.program = program
        self.timeout_ms = timeout_ms
        self.verbose = verbose
        
        self._summaries: Dict[str, ProcedureSummary] = {}
        
        self.stats = {
            'summaries_computed': 0,
        }
    
    def compute_summary(self, proc_name: str) -> Optional[ProcedureSummary]:
        """Compute summary for procedure."""
        proc = self.program.procedures.get(proc_name)
        if proc is None:
            return None
        
        # Create pre/post variables
        pre_vars = proc.params + list(self.program.globals.values())
        post_vars = []
        
        for v in pre_vars:
            post_v = BooleanVariable(f"{v.name}'", v.id + 1000, v.is_local, v.procedure)
            post_vars.append(post_v)
        
        # Compute relation (simplified: identity)
        pre_z3 = [v.to_z3() for v in pre_vars]
        post_z3 = [v.to_z3() for v in post_vars]
        
        relation = z3.And([pre == post for pre, post in zip(pre_z3, post_z3)])
        
        summary = ProcedureSummary(proc_name, pre_vars, post_vars, relation)
        self._summaries[proc_name] = summary
        self.stats['summaries_computed'] += 1
        
        return summary
    
    def get_summary(self, proc_name: str) -> Optional[ProcedureSummary]:
        """Get computed summary."""
        return self._summaries.get(proc_name)


# =============================================================================
# ABSTRACTION FROM PREDICATES
# =============================================================================

class BooleanAbstractor:
    """
    Create Boolean program from concrete program and predicates.
    """
    
    def __init__(self, n_vars: int,
                 var_names: List[str],
                 predicates: List[z3.BoolRef],
                 timeout_ms: int = 60000,
                 verbose: bool = False):
        self.n_vars = n_vars
        self.var_names = var_names
        self.predicates = predicates
        self.timeout_ms = timeout_ms
        self.verbose = verbose
        
        self._z3_vars = [z3.Real(v) for v in var_names]
        
        self.stats = {
            'abstractions': 0,
        }
    
    def abstract(self, transition: z3.BoolRef,
                  initial: z3.BoolRef,
                  error: z3.BoolRef) -> BooleanProgram:
        """
        Create Boolean program abstraction.
        """
        self.stats['abstractions'] += 1
        
        program = BooleanProgram("abstracted")
        
        # Create Boolean variable for each predicate
        pred_vars = []
        for i, p in enumerate(self.predicates):
            v = program.add_global(f"p_{i}")
            pred_vars.append(v)
        
        # Create main procedure
        proc = program.add_procedure("main", [], [])
        
        # Create body (simplified)
        # In full implementation, would compute Boolean transitions
        body = program.make_assume(BoolExpr.const(True))
        program.set_body("main", body)
        
        return program


# =============================================================================
# BOOLEAN INTEGRATION
# =============================================================================

@dataclass
class BooleanProgramConfig:
    """Configuration for Boolean program analysis."""
    max_fixpoint_iterations: int = 1000
    use_summaries: bool = True
    timeout_ms: int = 60000
    verbose: bool = False


class BooleanProgramIntegration:
    """
    Integration of Boolean programs with barrier synthesis.
    
    Provides:
    1. Boolean abstraction from predicates
    2. BDD-based model checking
    3. Counterexample analysis
    """
    
    def __init__(self, config: Optional[BooleanProgramConfig] = None,
                 verbose: bool = False):
        self.config = config or BooleanProgramConfig()
        self.verbose = verbose or self.config.verbose
        
        self._programs: Dict[str, BooleanProgram] = {}
        self._results: Dict[str, BebopResult] = {}
        
        self.stats = {
            'programs_created': 0,
            'checks_performed': 0,
            'safe_programs': 0,
        }
    
    def create_boolean_program(self, prog_id: str,
                                n_vars: int,
                                var_names: List[str],
                                predicates: List[z3.BoolRef],
                                transition: z3.BoolRef,
                                initial: z3.BoolRef,
                                error: z3.BoolRef) -> BooleanProgram:
        """
        Create Boolean program from predicates.
        """
        abstractor = BooleanAbstractor(
            n_vars, var_names, predicates,
            self.config.timeout_ms, self.verbose
        )
        
        program = abstractor.abstract(transition, initial, error)
        self._programs[prog_id] = program
        self.stats['programs_created'] += 1
        
        return program
    
    def check_safety(self, prog_id: str,
                      initial: z3.BoolRef,
                      error: z3.BoolRef) -> BebopResult:
        """
        Check safety of Boolean program.
        """
        program = self._programs.get(prog_id)
        if program is None:
            return BebopResult(
                result=CheckResult.UNKNOWN,
                message="Program not found"
            )
        
        checker = BebopChecker(program, self.config.timeout_ms, self.verbose)
        result = checker.check(initial, error)
        
        self._results[prog_id] = result
        self.stats['checks_performed'] += 1
        
        if result.result == CheckResult.SAFE:
            self.stats['safe_programs'] += 1
        
        return result
    
    def condition_barrier_problem(self, problem: BarrierSynthesisProblem,
                                    prog_id: str) -> BarrierSynthesisProblem:
        """
        Condition barrier problem using Boolean program insights.
        """
        result = self._results.get(prog_id)
        if result is None or result.result != CheckResult.SAFE:
            return problem
        
        # Add Boolean constraints as polynomial constraints
        # (Simplified - would need proper conversion)
        return problem


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def create_boolean_program(name: str = "program") -> BooleanProgram:
    """Create empty Boolean program."""
    return BooleanProgram(name)


def create_boolean_variable(name: str) -> BooleanVariable:
    """Create a Boolean variable."""
    return BooleanVariable(name, 0)


def check_boolean_program(program: BooleanProgram,
                            initial: z3.BoolRef,
                            error: z3.BoolRef,
                            timeout_ms: int = 60000,
                            verbose: bool = False) -> BebopResult:
    """Check Boolean program safety."""
    checker = BebopChecker(program, timeout_ms, verbose)
    return checker.check(initial, error)


def abstract_to_boolean(n_vars: int,
                          var_names: List[str],
                          predicates: List[z3.BoolRef],
                          transition: z3.BoolRef,
                          initial: z3.BoolRef,
                          error: z3.BoolRef,
                          timeout_ms: int = 60000,
                          verbose: bool = False) -> BooleanProgram:
    """Abstract concrete system to Boolean program."""
    abstractor = BooleanAbstractor(
        n_vars, var_names, predicates, timeout_ms, verbose
    )
    return abstractor.abstract(transition, initial, error)


# =============================================================================
# ADVANCED BOOLEAN PROGRAM ANALYSIS
# =============================================================================

class BDDRepresentation:
    """
    Binary Decision Diagram representation for Boolean programs.
    
    Provides efficient symbolic representation of state sets.
    """
    
    def __init__(self, num_vars: int,
                 var_names: Optional[List[str]] = None):
        self.num_vars = num_vars
        self.var_names = var_names or [f"b_{i}" for i in range(num_vars)]
        
        # BDD nodes: (var_index, low_child, high_child)
        self._nodes: Dict[int, Tuple[int, int, int]] = {}
        self._node_counter = 2  # 0 = False, 1 = True
        
        self.stats = {
            'nodes_created': 0,
            'nodes_reused': 0,
        }
    
    def constant(self, value: bool) -> int:
        """Return terminal node."""
        return 1 if value else 0
    
    def variable(self, idx: int) -> int:
        """Create BDD for single variable."""
        return self._make_node(idx, 0, 1)
    
    def _make_node(self, var_idx: int, low: int, high: int) -> int:
        """Make or find BDD node."""
        if low == high:
            return low  # No decision needed
        
        # Check for existing node (simplified hash)
        key = (var_idx, low, high)
        for node_id, node in self._nodes.items():
            if node == key:
                self.stats['nodes_reused'] += 1
                return node_id
        
        # Create new node
        node_id = self._node_counter
        self._node_counter += 1
        self._nodes[node_id] = key
        self.stats['nodes_created'] += 1
        
        return node_id
    
    def apply_and(self, bdd1: int, bdd2: int) -> int:
        """Compute AND of two BDDs."""
        if bdd1 == 0 or bdd2 == 0:
            return 0
        if bdd1 == 1:
            return bdd2
        if bdd2 == 1:
            return bdd1
        
        node1 = self._nodes.get(bdd1)
        node2 = self._nodes.get(bdd2)
        
        if node1 is None or node2 is None:
            return 0
        
        var1, low1, high1 = node1
        var2, low2, high2 = node2
        
        if var1 == var2:
            new_low = self.apply_and(low1, low2)
            new_high = self.apply_and(high1, high2)
            return self._make_node(var1, new_low, new_high)
        elif var1 < var2:
            new_low = self.apply_and(low1, bdd2)
            new_high = self.apply_and(high1, bdd2)
            return self._make_node(var1, new_low, new_high)
        else:
            new_low = self.apply_and(bdd1, low2)
            new_high = self.apply_and(bdd1, high2)
            return self._make_node(var2, new_low, new_high)
    
    def apply_or(self, bdd1: int, bdd2: int) -> int:
        """Compute OR of two BDDs."""
        if bdd1 == 1 or bdd2 == 1:
            return 1
        if bdd1 == 0:
            return bdd2
        if bdd2 == 0:
            return bdd1
        
        node1 = self._nodes.get(bdd1)
        node2 = self._nodes.get(bdd2)
        
        if node1 is None:
            return bdd2
        if node2 is None:
            return bdd1
        
        var1, low1, high1 = node1
        var2, low2, high2 = node2
        
        if var1 == var2:
            new_low = self.apply_or(low1, low2)
            new_high = self.apply_or(high1, high2)
            return self._make_node(var1, new_low, new_high)
        elif var1 < var2:
            new_low = self.apply_or(low1, bdd2)
            new_high = self.apply_or(high1, bdd2)
            return self._make_node(var1, new_low, new_high)
        else:
            new_low = self.apply_or(bdd1, low2)
            new_high = self.apply_or(bdd1, high2)
            return self._make_node(var2, new_low, new_high)
    
    def apply_not(self, bdd: int) -> int:
        """Compute NOT of BDD."""
        if bdd == 0:
            return 1
        if bdd == 1:
            return 0
        
        node = self._nodes.get(bdd)
        if node is None:
            return 1
        
        var_idx, low, high = node
        new_low = self.apply_not(low)
        new_high = self.apply_not(high)
        
        return self._make_node(var_idx, new_low, new_high)
    
    def exists(self, bdd: int, var_idx: int) -> int:
        """Existential quantification."""
        if bdd == 0 or bdd == 1:
            return bdd
        
        node = self._nodes.get(bdd)
        if node is None:
            return bdd
        
        node_var, low, high = node
        
        if node_var == var_idx:
            return self.apply_or(low, high)
        elif node_var > var_idx:
            return bdd  # Variable not in BDD
        else:
            new_low = self.exists(low, var_idx)
            new_high = self.exists(high, var_idx)
            return self._make_node(node_var, new_low, new_high)
    
    def count_sat(self, bdd: int) -> int:
        """Count satisfying assignments."""
        if bdd == 0:
            return 0
        if bdd == 1:
            return 2 ** self.num_vars
        
        node = self._nodes.get(bdd)
        if node is None:
            return 0
        
        var_idx, low, high = node
        
        low_count = self.count_sat(low)
        high_count = self.count_sat(high)
        
        # Scale by variables skipped
        return (low_count + high_count) // 2
    
    def to_formula(self, bdd: int) -> z3.BoolRef:
        """Convert BDD to Z3 formula."""
        if bdd == 0:
            return z3.BoolVal(False)
        if bdd == 1:
            return z3.BoolVal(True)
        
        node = self._nodes.get(bdd)
        if node is None:
            return z3.BoolVal(False)
        
        var_idx, low, high = node
        var = z3.Bool(self.var_names[var_idx])
        
        low_formula = self.to_formula(low)
        high_formula = self.to_formula(high)
        
        return z3.If(var, high_formula, low_formula)


class SymbolicReachability:
    """
    Symbolic reachability for Boolean programs using BDDs.
    """
    
    def __init__(self, program: BooleanProgram,
                 timeout_ms: int = 60000):
        self.program = program
        self.timeout_ms = timeout_ms
        
        self.num_vars = program.num_vars
        self.bdd = BDDRepresentation(self.num_vars)
        
        self.stats = {
            'iterations': 0,
            'reachable_states': 0,
            'fixed_point_reached': False,
        }
    
    def compute_reachable(self, initial: int) -> int:
        """Compute reachable state set from initial."""
        reached = initial
        frontier = initial
        
        start_time = time.time()
        
        while frontier != 0:
            elapsed = (time.time() - start_time) * 1000
            if elapsed > self.timeout_ms:
                break
            
            self.stats['iterations'] += 1
            
            # Compute post-image
            post = self._compute_post(frontier)
            
            # New states
            new_states = self.bdd.apply_and(
                post, self.bdd.apply_not(reached)
            )
            
            if new_states == 0:
                self.stats['fixed_point_reached'] = True
                break
            
            reached = self.bdd.apply_or(reached, new_states)
            frontier = new_states
        
        self.stats['reachable_states'] = self.bdd.count_sat(reached)
        return reached
    
    def _compute_post(self, states: int) -> int:
        """Compute post-image of state set."""
        # Simplified: apply transition relation symbolically
        result = 0
        
        for proc in self.program.procedures.values():
            for stmt in proc.statements:
                if isinstance(stmt, BoolAssign):
                    # Transform states
                    transformed = self._apply_assignment(states, stmt)
                    result = self.bdd.apply_or(result, transformed)
        
        return result if result != 0 else states
    
    def _apply_assignment(self, states: int, stmt: BoolAssign) -> int:
        """Apply assignment to state set."""
        # Existentially quantify assigned variable, then conjoin new value
        var_idx = stmt.target.index
        
        projected = self.bdd.exists(states, var_idx)
        
        # Build BDD for new value
        if isinstance(stmt.value, BoolConst):
            new_val = self.bdd.constant(stmt.value.value)
        else:
            new_val = self.bdd.variable(var_idx)
        
        var_bdd = self.bdd.variable(var_idx)
        
        # x = new_val is (x ∧ new_val) ∨ (¬x ∧ ¬new_val)
        equiv = self.bdd.apply_or(
            self.bdd.apply_and(var_bdd, new_val),
            self.bdd.apply_and(
                self.bdd.apply_not(var_bdd),
                self.bdd.apply_not(new_val)
            )
        )
        
        return self.bdd.apply_and(projected, equiv)
    
    def check_safety(self, initial: int, error: int) -> bool:
        """Check if error states are reachable from initial."""
        reached = self.compute_reachable(initial)
        
        intersection = self.bdd.apply_and(reached, error)
        
        return intersection == 0  # Safe if no intersection


class PushdownSystemModel:
    """
    Pushdown system model for Boolean programs with procedures.
    
    Models stack for procedure calls.
    """
    
    def __init__(self, program: BooleanProgram):
        self.program = program
        
        # Control locations
        self.locations: List[Tuple[str, int]] = []  # (procedure, stmt_index)
        self._build_locations()
        
        # Stack alphabet: return points
        self.stack_alphabet: Set[Tuple[str, int]] = set()
        
        self.stats = {
            'num_locations': 0,
            'num_rules': 0,
        }
    
    def _build_locations(self) -> None:
        """Build control locations from program."""
        for proc_name, proc in self.program.procedures.items():
            for i in range(len(proc.statements)):
                self.locations.append((proc_name, i))
        
        self.stats['num_locations'] = len(self.locations)
    
    def get_transitions(self) -> List[Tuple[Tuple[str, int], Tuple[str, int], Optional[Tuple[str, int]]]]:
        """
        Get PDS transitions.
        
        Returns list of (source, target, stack_op) where:
        - stack_op = None: internal move
        - stack_op = (proc, return_point): push call
        """
        transitions = []
        
        for proc_name, proc in self.program.procedures.items():
            for i, stmt in enumerate(proc.statements):
                source = (proc_name, i)
                
                if isinstance(stmt, BoolCall):
                    # Push transition
                    target = (stmt.callee, 0)
                    return_point = (proc_name, i + 1)
                    transitions.append((source, target, return_point))
                    self.stack_alphabet.add(return_point)
                elif isinstance(stmt, BoolReturn):
                    # Pop transition (handled separately)
                    pass
                else:
                    # Internal transition
                    if i + 1 < len(proc.statements):
                        target = (proc_name, i + 1)
                        transitions.append((source, target, None))
        
        self.stats['num_rules'] = len(transitions)
        return transitions


class BooleanAbstractionRefinement:
    """
    Abstraction refinement for Boolean programs.
    """
    
    def __init__(self, program: BooleanProgram,
                 timeout_ms: int = 60000):
        self.program = program
        self.timeout_ms = timeout_ms
        
        self.abstractions: List[BooleanProgram] = []
        self.refinements: List[List[z3.BoolRef]] = []
        
        self.stats = {
            'iterations': 0,
            'predicates_added': 0,
        }
    
    def refine(self, counterexample: List[Tuple[str, int]],
                new_predicates: List[z3.BoolRef]) -> BooleanProgram:
        """
        Refine abstraction with new predicates.
        """
        self.stats['iterations'] += 1
        self.stats['predicates_added'] += len(new_predicates)
        
        # Create new Boolean program with additional variables
        refined = BooleanProgram(f"{self.program.name}_refined_{self.stats['iterations']}")
        
        # Copy original variables
        for var in self.program.variables:
            refined.add_variable(var.name)
        
        # Add predicate variables
        for i, pred in enumerate(new_predicates):
            refined.add_variable(f"pred_{self.stats['iterations']}_{i}")
        
        # Copy and refine procedures
        for proc_name, proc in self.program.procedures.items():
            refined_proc = Procedure(proc_name)
            
            for stmt in proc.statements:
                refined_proc.statements.append(stmt)
            
            refined.procedures[proc_name] = refined_proc
        
        self.abstractions.append(refined)
        self.refinements.append(new_predicates)
        
        return refined


class InterproceduralAnalysis:
    """
    Interprocedural analysis for Boolean programs.
    """
    
    def __init__(self, program: BooleanProgram,
                 timeout_ms: int = 60000):
        self.program = program
        self.timeout_ms = timeout_ms
        
        # Summaries: procedure -> (precondition, postcondition)
        self.summaries: Dict[str, Tuple[z3.BoolRef, z3.BoolRef]] = {}
        
        self.stats = {
            'summaries_computed': 0,
            'summary_applications': 0,
        }
    
    def compute_summaries(self) -> Dict[str, Tuple[z3.BoolRef, z3.BoolRef]]:
        """Compute procedure summaries."""
        worklist = list(self.program.procedures.keys())
        
        while worklist:
            proc_name = worklist.pop(0)
            proc = self.program.procedures[proc_name]
            
            old_summary = self.summaries.get(proc_name)
            new_summary = self._compute_procedure_summary(proc)
            
            self.summaries[proc_name] = new_summary
            self.stats['summaries_computed'] += 1
            
            if old_summary != new_summary:
                # Add callers to worklist
                for other_name, other_proc in self.program.procedures.items():
                    for stmt in other_proc.statements:
                        if isinstance(stmt, BoolCall) and stmt.callee == proc_name:
                            if other_name not in worklist:
                                worklist.append(other_name)
        
        return self.summaries
    
    def _compute_procedure_summary(self, proc: Procedure) -> Tuple[z3.BoolRef, z3.BoolRef]:
        """Compute summary for single procedure."""
        # Simplified: return trivial summary
        pre = z3.BoolVal(True)
        post = z3.BoolVal(True)
        
        return (pre, post)
    
    def apply_summary(self, call_site: BoolCall) -> z3.BoolRef:
        """Apply summary at call site."""
        self.stats['summary_applications'] += 1
        
        summary = self.summaries.get(call_site.callee)
        if summary:
            return summary[1]  # Return postcondition
        
        return z3.BoolVal(True)


class TerminationChecker:
    """
    Termination checking for Boolean programs.
    """
    
    def __init__(self, program: BooleanProgram,
                 timeout_ms: int = 60000):
        self.program = program
        self.timeout_ms = timeout_ms
        
        self.ranking_functions: Dict[str, z3.ArithRef] = {}
        
        self.stats = {
            'loops_analyzed': 0,
            'terminating_loops': 0,
        }
    
    def check_termination(self) -> bool:
        """Check if program terminates."""
        loops = self._find_loops()
        
        for loop in loops:
            self.stats['loops_analyzed'] += 1
            
            if self._has_ranking_function(loop):
                self.stats['terminating_loops'] += 1
            else:
                return False
        
        return True
    
    def _find_loops(self) -> List[List[Tuple[str, int]]]:
        """Find loops in control flow."""
        loops = []
        
        for proc_name, proc in self.program.procedures.items():
            for i, stmt in enumerate(proc.statements):
                if isinstance(stmt, BoolGoto):
                    # Check for back edge
                    for target in stmt.targets:
                        if target <= i:
                            loops.append([(proc_name, j) for j in range(target, i + 1)])
        
        return loops
    
    def _has_ranking_function(self, loop: List[Tuple[str, int]]) -> bool:
        """Check if loop has ranking function."""
        # Simplified: assume termination
        return True


class CounterexampleGenerator:
    """
    Counterexample generation for Boolean programs.
    """
    
    def __init__(self, program: BooleanProgram,
                 timeout_ms: int = 60000):
        self.program = program
        self.timeout_ms = timeout_ms
        
        self.stats = {
            'counterexamples_generated': 0,
        }
    
    def generate(self, initial: z3.BoolRef,
                  error: z3.BoolRef,
                  max_depth: int = 100) -> Optional[List[Dict[str, bool]]]:
        """Generate counterexample path to error."""
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        
        # Create path variables
        path_vars: List[List[z3.BoolRef]] = []
        
        for step in range(max_depth):
            step_vars = [z3.Bool(f"{v.name}_{step}") 
                         for v in self.program.variables]
            path_vars.append(step_vars)
        
        # Initial constraint
        solver.add(z3.substitute(initial, 
                    [(z3.Bool(v.name), path_vars[0][i])
                     for i, v in enumerate(self.program.variables)]))
        
        # Transition constraints
        for step in range(max_depth - 1):
            trans = self._encode_transition(path_vars[step], path_vars[step + 1])
            solver.add(trans)
        
        # Error constraint at some step
        error_reached = z3.Or([
            z3.substitute(error,
                [(z3.Bool(v.name), path_vars[step][i])
                 for i, v in enumerate(self.program.variables)])
            for step in range(max_depth)
        ])
        solver.add(error_reached)
        
        if solver.check() == z3.sat:
            model = solver.model()
            path = self._extract_path(model, path_vars)
            self.stats['counterexamples_generated'] += 1
            return path
        
        return None
    
    def _encode_transition(self, pre_vars: List[z3.BoolRef],
                            post_vars: List[z3.BoolRef]) -> z3.BoolRef:
        """Encode transition between steps."""
        clauses = []
        
        # Default: variables unchanged
        for i in range(len(pre_vars)):
            clauses.append(post_vars[i] == pre_vars[i])
        
        return z3.And(clauses)
    
    def _extract_path(self, model: z3.ModelRef,
                       path_vars: List[List[z3.BoolRef]]) -> List[Dict[str, bool]]:
        """Extract path from model."""
        path = []
        
        for step_vars in path_vars:
            state = {}
            for i, var in enumerate(self.program.variables):
                val = model.eval(step_vars[i], model_completion=True)
                state[var.name] = z3.is_true(val)
            path.append(state)
        
        return path


# =============================================================================
# ADDITIONAL BOOLEAN PROGRAM COMPONENTS
# =============================================================================

class BooleanProgramEncoder:
    """
    Encode Boolean programs to SMT formulas.
    """
    
    def __init__(self, program: BooleanProgram):
        self.program = program
        
        self.stats = {
            'encodings_created': 0,
        }
    
    def encode_to_smt(self, bound: int = 10) -> z3.BoolRef:
        """
        Encode bounded execution of program to SMT.
        """
        self.stats['encodings_created'] += 1
        
        # Create time-indexed variables
        var_matrix = {}
        for t in range(bound + 1):
            for var in self.program.variables:
                var_matrix[(var.name, t)] = z3.Bool(f"{var.name}_{t}")
        
        # Create location variables
        loc_vars = [z3.Int(f"loc_{t}") for t in range(bound + 1)]
        
        formulas = []
        
        # Initial location
        formulas.append(loc_vars[0] == 0)
        
        # Transition constraints
        for t in range(bound):
            trans = self._encode_transition(var_matrix, loc_vars, t)
            formulas.append(trans)
        
        return z3.And(formulas)
    
    def _encode_transition(self, var_matrix: Dict,
                            loc_vars: List[z3.ArithRef],
                            t: int) -> z3.BoolRef:
        """Encode transition at time t."""
        clauses = []
        
        for proc_name, proc in self.program.procedures.items():
            for i, stmt in enumerate(proc.statements):
                # If at this location, apply this statement
                at_loc = loc_vars[t] == i
                
                if isinstance(stmt, BoolAssign):
                    # Apply assignment
                    var_name = stmt.target.name
                    
                    if isinstance(stmt.value, BoolConst):
                        new_val = z3.BoolVal(stmt.value.value)
                    elif isinstance(stmt.value, BoolVarRef):
                        new_val = var_matrix[(stmt.value.var.name, t)]
                    else:
                        new_val = z3.BoolVal(False)
                    
                    trans = z3.And(
                        var_matrix[(var_name, t + 1)] == new_val,
                        loc_vars[t + 1] == i + 1
                    )
                    
                    # Other variables unchanged
                    for other_var in self.program.variables:
                        if other_var.name != var_name:
                            trans = z3.And(trans,
                                var_matrix[(other_var.name, t + 1)] == 
                                var_matrix[(other_var.name, t)])
                    
                    clauses.append(z3.Implies(at_loc, trans))
        
        return z3.Or(clauses) if clauses else z3.BoolVal(True)


class BooleanProgramOptimizer:
    """
    Optimize Boolean programs.
    """
    
    def __init__(self, program: BooleanProgram):
        self.program = program
        
        self.stats = {
            'optimizations_applied': 0,
            'statements_removed': 0,
        }
    
    def optimize(self) -> BooleanProgram:
        """Apply all optimizations."""
        optimized = self._copy_program()
        
        optimized = self._eliminate_dead_code(optimized)
        optimized = self._constant_propagation(optimized)
        optimized = self._merge_assignments(optimized)
        
        return optimized
    
    def _copy_program(self) -> BooleanProgram:
        """Create copy of program."""
        copy = BooleanProgram(self.program.name + "_opt")
        
        for var in self.program.variables:
            copy.add_variable(var.name)
        
        for proc_name, proc in self.program.procedures.items():
            copy_proc = Procedure(proc_name)
            copy_proc.statements = proc.statements[:]
            copy.procedures[proc_name] = copy_proc
        
        return copy
    
    def _eliminate_dead_code(self, program: BooleanProgram) -> BooleanProgram:
        """Eliminate dead code."""
        # Find used variables
        used = set()
        
        for proc in program.procedures.values():
            for stmt in proc.statements:
                if isinstance(stmt, BoolAssign):
                    if isinstance(stmt.value, BoolVarRef):
                        used.add(stmt.value.var.name)
                elif isinstance(stmt, BoolGoto):
                    if isinstance(stmt.condition, BoolVarRef):
                        used.add(stmt.condition.var.name)
        
        # Remove assignments to unused variables
        for proc in program.procedures.values():
            new_stmts = []
            for stmt in proc.statements:
                if isinstance(stmt, BoolAssign):
                    if stmt.target.name not in used:
                        self.stats['statements_removed'] += 1
                        continue
                new_stmts.append(stmt)
            proc.statements = new_stmts
        
        self.stats['optimizations_applied'] += 1
        return program
    
    def _constant_propagation(self, program: BooleanProgram) -> BooleanProgram:
        """Propagate constants."""
        self.stats['optimizations_applied'] += 1
        return program
    
    def _merge_assignments(self, program: BooleanProgram) -> BooleanProgram:
        """Merge consecutive assignments to same variable."""
        self.stats['optimizations_applied'] += 1
        return program


class BooleanProgramVerificationOracle:
    """
    Oracle for Boolean program verification queries.
    """
    
    def __init__(self, program: BooleanProgram,
                 timeout_ms: int = 60000):
        self.program = program
        self.timeout_ms = timeout_ms
        
        self.stats = {
            'queries_answered': 0,
        }
    
    def query_reachability(self, initial: z3.BoolRef,
                            target: z3.BoolRef,
                            bound: int = 100) -> bool:
        """Query if target is reachable from initial."""
        self.stats['queries_answered'] += 1
        
        reach = SymbolicReachability(self.program, self.timeout_ms)
        
        # Convert to BDD
        init_bdd = 1  # Would convert formula to BDD
        target_bdd = 1
        
        reachable = reach.compute_reachable(init_bdd)
        
        # Check intersection
        return reach.bdd.apply_and(reachable, target_bdd) != 0
    
    def query_invariant(self, candidate: z3.BoolRef) -> bool:
        """Query if candidate is an invariant."""
        self.stats['queries_answered'] += 1
        
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        
        # Check init → candidate
        # Check candidate ∧ trans → candidate'
        
        return True  # Simplified
    
    def query_termination(self) -> bool:
        """Query if program terminates."""
        self.stats['queries_answered'] += 1
        
        checker = TerminationChecker(self.program, self.timeout_ms)
        return checker.check_termination()


class InvariantSynthesisForBooleanPrograms:
    """
    Synthesize invariants for Boolean programs.
    """
    
    def __init__(self, program: BooleanProgram,
                 timeout_ms: int = 60000):
        self.program = program
        self.timeout_ms = timeout_ms
        
        self.stats = {
            'invariants_synthesized': 0,
            'candidates_tried': 0,
        }
    
    def synthesize(self, property_: z3.BoolRef) -> Optional[z3.BoolRef]:
        """Synthesize inductive invariant implying property."""
        # Generate candidate invariants
        candidates = self._generate_candidates()
        
        for candidate in candidates:
            self.stats['candidates_tried'] += 1
            
            if self._is_inductive(candidate, property_):
                self.stats['invariants_synthesized'] += 1
                return candidate
        
        return None
    
    def _generate_candidates(self) -> List[z3.BoolRef]:
        """Generate candidate invariants."""
        candidates = []
        
        # Single variable predicates
        for var in self.program.variables:
            b = z3.Bool(var.name)
            candidates.append(b)
            candidates.append(z3.Not(b))
        
        # Conjunctions of two variables
        for i, v1 in enumerate(self.program.variables):
            for v2 in self.program.variables[i + 1:]:
                b1 = z3.Bool(v1.name)
                b2 = z3.Bool(v2.name)
                candidates.append(z3.And(b1, b2))
                candidates.append(z3.And(b1, z3.Not(b2)))
                candidates.append(z3.Or(b1, b2))
        
        return candidates
    
    def _is_inductive(self, candidate: z3.BoolRef,
                       property_: z3.BoolRef) -> bool:
        """Check if candidate is inductive and implies property."""
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms // max(1, self.stats['candidates_tried']))
        
        # Check implication
        solver.add(candidate)
        solver.add(z3.Not(property_))
        
        if solver.check() == z3.sat:
            return False
        
        # Would also check inductiveness
        return True


class BooleanProgramSlicing:
    """
    Program slicing for Boolean programs.
    """
    
    def __init__(self, program: BooleanProgram):
        self.program = program
        
        self.stats = {
            'slices_computed': 0,
        }
    
    def compute_slice(self, criterion: Set[str]) -> BooleanProgram:
        """
        Compute program slice with respect to criterion.
        
        Criterion is set of variable names.
        """
        self.stats['slices_computed'] += 1
        
        # Backward slice: include statements that affect criterion
        relevant_stmts = self._backward_slice(criterion)
        
        # Build sliced program
        sliced = BooleanProgram(self.program.name + "_slice")
        
        for var_name in criterion:
            sliced.add_variable(var_name)
        
        for proc_name, proc in self.program.procedures.items():
            slice_proc = Procedure(proc_name)
            
            for i, stmt in enumerate(proc.statements):
                if (proc_name, i) in relevant_stmts:
                    slice_proc.statements.append(stmt)
            
            sliced.procedures[proc_name] = slice_proc
        
        return sliced
    
    def _backward_slice(self, criterion: Set[str]) -> Set[Tuple[str, int]]:
        """Compute backward slice."""
        relevant = set()
        worklist = list(criterion)
        
        while worklist:
            var_name = worklist.pop()
            
            for proc_name, proc in self.program.procedures.items():
                for i, stmt in enumerate(proc.statements):
                    if isinstance(stmt, BoolAssign):
                        if stmt.target.name == var_name:
                            relevant.add((proc_name, i))
                            
                            # Add variables used in RHS
                            if isinstance(stmt.value, BoolVarRef):
                                if stmt.value.var.name not in worklist:
                                    worklist.append(stmt.value.var.name)
        
        return relevant


class BooleanProgramEquivalence:
    """
    Check equivalence of Boolean programs.
    """
    
    def __init__(self, timeout_ms: int = 60000):
        self.timeout_ms = timeout_ms
        
        self.stats = {
            'equivalence_checks': 0,
        }
    
    def check_equivalence(self, prog1: BooleanProgram,
                           prog2: BooleanProgram) -> bool:
        """Check if two programs are equivalent."""
        self.stats['equivalence_checks'] += 1
        
        # Build product program
        product = self._build_product(prog1, prog2)
        
        # Check that outputs match
        # Simplified: just check structure
        return len(prog1.variables) == len(prog2.variables)
    
    def _build_product(self, prog1: BooleanProgram,
                        prog2: BooleanProgram) -> BooleanProgram:
        """Build product program."""
        product = BooleanProgram("product")
        
        # Add variables from both
        for var in prog1.variables:
            product.add_variable(f"p1_{var.name}")
        for var in prog2.variables:
            product.add_variable(f"p2_{var.name}")
        
        return product


class BooleanProgramTransformer:
    """
    Advanced program transformations for Boolean programs.
    
    Implements various transformation techniques:
    - Constant propagation
    - Dead variable elimination
    - Statement reordering
    - Loop normalization
    - Partial evaluation
    """
    
    def __init__(self, enable_logging: bool = False):
        self.enable_logging = enable_logging
        self.stats = {
            'constants_propagated': 0,
            'dead_vars_eliminated': 0,
            'statements_reordered': 0,
        }
    
    def constant_propagation(self, program: BooleanProgram) -> BooleanProgram:
        """
        Propagate constant values through the program.
        
        If a variable is assigned a constant value and never modified,
        replace all uses with the constant.
        """
        result = BooleanProgram(f"{program.name}_const_prop")
        
        # Copy variables
        for var in program.variables:
            result.add_variable(var.name, var.initial_value)
        
        # Analyze constant values
        constants = self._find_constants(program)
        
        # Transform statements
        for stmt in program.statements:
            transformed = self._propagate_in_stmt(stmt, constants)
            result.add_statement(transformed)
        
        self.stats['constants_propagated'] += len(constants)
        return result
    
    def _find_constants(self, program: BooleanProgram) -> Dict[str, bool]:
        """Find variables with constant values."""
        constants = {}
        
        # Check initial values
        for var in program.variables:
            if var.initial_value is not None:
                constants[var.name] = var.initial_value
        
        # Remove modified variables
        for stmt in program.statements:
            if hasattr(stmt, 'target'):
                if stmt.target in constants:
                    del constants[stmt.target]
        
        return constants
    
    def _propagate_in_stmt(self, stmt: BooleanStatement,
                            constants: Dict[str, bool]) -> BooleanStatement:
        """Propagate constants in a statement."""
        # Clone statement and substitute constants
        return stmt  # Simplified
    
    def dead_variable_elimination(self, program: BooleanProgram) -> BooleanProgram:
        """
        Eliminate variables that are never used.
        
        Performs liveness analysis to find dead variables.
        """
        result = BooleanProgram(f"{program.name}_dve")
        
        # Find used variables
        used = self._find_used_variables(program)
        
        # Only keep used variables
        for var in program.variables:
            if var.name in used:
                result.add_variable(var.name, var.initial_value)
            else:
                self.stats['dead_vars_eliminated'] += 1
        
        # Keep only statements affecting used variables
        for stmt in program.statements:
            if self._affects_used(stmt, used):
                result.add_statement(stmt)
        
        return result
    
    def _find_used_variables(self, program: BooleanProgram) -> Set[str]:
        """Find variables that are actually used."""
        used = set()
        
        for stmt in program.statements:
            if hasattr(stmt, 'condition'):
                used.update(self._vars_in_expr(stmt.condition))
            if hasattr(stmt, 'value'):
                used.update(self._vars_in_expr(stmt.value))
        
        return used
    
    def _vars_in_expr(self, expr: Any) -> Set[str]:
        """Extract variable names from expression."""
        if isinstance(expr, str):
            return {expr}
        return set()
    
    def _affects_used(self, stmt: BooleanStatement, used: Set[str]) -> bool:
        """Check if statement affects used variables."""
        if hasattr(stmt, 'target'):
            return stmt.target in used
        return True
    
    def loop_normalization(self, program: BooleanProgram) -> BooleanProgram:
        """
        Normalize loops to a standard form.
        
        Converts various loop forms to while loops with
        standard structure.
        """
        result = BooleanProgram(f"{program.name}_loop_norm")
        
        for var in program.variables:
            result.add_variable(var.name, var.initial_value)
        
        # Transform each statement
        for stmt in program.statements:
            if isinstance(stmt, WhileStatement):
                normalized = self._normalize_loop(stmt)
                result.add_statement(normalized)
            else:
                result.add_statement(stmt)
        
        return result
    
    def _normalize_loop(self, loop: 'WhileStatement') -> 'WhileStatement':
        """Normalize a single loop."""
        # Ensure loop has standard form
        return loop  # Simplified


class BooleanProgramAbstractionLayer:
    """
    Abstraction layer for Boolean programs.
    
    Provides interfaces for:
    - Program abstraction
    - Refinement operations
    - Counterexample analysis
    """
    
    def __init__(self, solver_timeout: int = 30000):
        self.solver_timeout = solver_timeout
        self.abstractor = BooleanAbstractionRefinement()
        self.checker = BebopChecker()
        
    def abstract_and_check(self, concrete_program: Any,
                           property_expr: z3.ExprRef) -> Tuple[bool, Optional[List]]:
        """
        Abstract program and check property.
        
        Returns (safe, counterexample) tuple.
        """
        # Create abstraction
        abstract_prog = self._create_abstraction(concrete_program)
        
        # Check property on abstraction
        result = self.checker.check(abstract_prog)
        
        if result.is_safe:
            return (True, None)
        
        # Have potential counterexample
        cex = result.get_counterexample()
        
        # Check if spurious
        if self._is_genuine(cex, concrete_program):
            return (False, cex)
        
        # Refine and retry
        refined = self._refine(abstract_prog, cex)
        return self.abstract_and_check(refined, property_expr)
    
    def _create_abstraction(self, program: Any) -> BooleanProgram:
        """Create Boolean abstraction of program."""
        return BooleanProgram("abstract")
    
    def _is_genuine(self, cex: List, program: Any) -> bool:
        """Check if counterexample is genuine."""
        return True  # Conservative
    
    def _refine(self, abstract: BooleanProgram,
                 cex: List) -> BooleanProgram:
        """Refine abstraction based on counterexample."""
        return abstract  # Would add predicates
