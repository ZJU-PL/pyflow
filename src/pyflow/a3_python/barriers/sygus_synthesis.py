"""
SOTA Paper: Syntax-Guided Synthesis (SyGuS).

Implements SyGuS-based invariant synthesis:
    R. Alur, R. Bodík, G. Juniwal, M. M. K. Martin, M. Raghothaman,
    S. A. Seshia, R. Singh, A. Solar-Lezama, E. Torlak, A. Udupa.
    "Syntax-Guided Synthesis." FMCAD 2013.

KEY INSIGHT
===========

SyGuS formulates synthesis as finding an expression e from a grammar G
that satisfies a semantic specification φ(e).

For invariants:
    find I from Grammar such that:
        Init(x) → I(x)               (initiation)
        I(x) ∧ T(x,x') → I(x')       (consecution)
        I(x) → Safe(x)               (safety)

The grammar constrains the SYNTACTIC form of the invariant.

SYNTHESIS FRAMEWORK
===================

Components:
1. **Grammar G**: Defines the space of candidate invariants
2. **Specification φ**: Semantic constraints (initiation, consecution, safety)
3. **Synthesizer**: Searches G for solution satisfying φ

Key insight: Grammar guides search, reducing the space dramatically.

GRAMMAR FOR BARRIERS
====================

For polynomial barriers, the grammar might be:

    B ::= Term | Term + B
    Term ::= Coef * Mono
    Coef ::= Integer
    Mono ::= 1 | Var | Var * Mono
    Var ::= x_0 | x_1 | ... | x_n

This grammar generates all multivariate polynomials.

INTEGRATION WITH BARRIERS
=========================

SyGuS provides:
1. **Template generation**: Grammar-based barrier templates
2. **Guided search**: Enumerate from grammar, verify semantics
3. **CEGIS loop**: Counterexample-guided inductive synthesis
4. **Grammar learning**: Refine grammar from failed attempts

IMPLEMENTATION STRUCTURE
========================

1. Grammar: Productions, terminals, nonterminals
2. Enumerator: Enumerate expressions from grammar
3. Verifier: Check semantic constraints
4. CEGIS: Counterexample-guided synthesis loop
5. SyGuSBarrierBridge: Connect to barrier synthesis

LAYER POSITION
==============

This is a **Layer 4 (Learning)** module.

    ┌─────────────────────────────────────────────────────────────────┐
    │ Layer 5: Advanced Verification (IC3, CHC, IMC, Assume-Guarantee)│
    │ Layer 4: LEARNING ← [THIS MODULE]                               │
    │   ├── ice_learning.py (Paper #17)                               │
    │   ├── houdini.py (Paper #18)                                    │
    │   └── sygus_synthesis.py ← You are here (Paper #19)             │
    │ Layer 3: Abstraction (CEGAR, Predicate Abstraction, IMPACT)     │
    │ Layer 2: Certificate Core (Hybrid, Stochastic, SOS Safety)      │
    │ Layer 1: Foundations (Positivstellensatz, SOS/SDP, Lasserre)    │
    └─────────────────────────────────────────────────────────────────┘

CROSS-PAPER DEPENDENCIES
========================

This module builds on:
- Layer 1: Polynomial grammar terminals from Parrilo SOS
- Layer 2: Barrier certificate semantics guide specification φ
- Layer 3: CEGAR counterexamples guide grammar refinement

This module synergizes with Layer 4 peers:
- Paper #17 (ICE): SyGuS candidates checked by ICE teacher
- Paper #18 (Houdini): Houdini conjuncts as SyGuS grammar terminals

This module is used by:
- Paper #10 (IC3): SyGuS lemma synthesis for frame strengthening
- Paper #11 (CHC): SyGuS invariant templates for CHC solving
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple, Set, Any, Callable, Union, Iterator
from collections import deque
from abc import ABC, abstractmethod
import random

import z3

# =============================================================================
# LAYER 4: IMPORTS FROM LOWER LAYERS
# =============================================================================
# SyGuS builds grammars over polynomial terms (Layer 1) and synthesizes
# barrier certificates (Layer 2). It uses counterexamples from CEGAR (Layer 3).
# =============================================================================

from .parrilo_sos_sdp import (
    Polynomial,
    SemialgebraicSet,
    BarrierSynthesisProblem,
)


# =============================================================================
# GRAMMAR REPRESENTATION
# =============================================================================

class SymbolKind(Enum):
    """Kind of grammar symbol."""
    TERMINAL = auto()
    NONTERMINAL = auto()


@dataclass
class Symbol:
    """
    Grammar symbol (terminal or nonterminal).
    """
    name: str
    kind: SymbolKind
    sort: Optional[str] = None  # Type: "Int", "Real", "Bool"
    
    def is_terminal(self) -> bool:
        return self.kind == SymbolKind.TERMINAL
    
    def is_nonterminal(self) -> bool:
        return self.kind == SymbolKind.NONTERMINAL
    
    def __str__(self) -> str:
        return self.name
    
    def __hash__(self) -> int:
        return hash(self.name)
    
    def __eq__(self, other) -> bool:
        if isinstance(other, Symbol):
            return self.name == other.name
        return False


@dataclass
class Production:
    """
    Grammar production rule.
    
    lhs -> rhs, where rhs is a sequence of symbols or
    a function application.
    """
    lhs: Symbol  # Nonterminal being defined
    rhs: Union[List[Symbol], Tuple[str, List[Symbol]]]  # Symbols or (operator, operands)
    weight: float = 1.0  # For weighted enumeration
    
    def is_operator(self) -> bool:
        """Check if RHS is an operator application."""
        return isinstance(self.rhs, tuple)
    
    def get_operator(self) -> Optional[str]:
        """Get operator name if operator production."""
        if isinstance(self.rhs, tuple):
            return self.rhs[0]
        return None
    
    def get_operands(self) -> List[Symbol]:
        """Get operand symbols."""
        if isinstance(self.rhs, tuple):
            return self.rhs[1]
        return self.rhs
    
    def __str__(self) -> str:
        if isinstance(self.rhs, tuple):
            op, operands = self.rhs
            return f"{self.lhs} -> {op}({', '.join(str(s) for s in operands)})"
        return f"{self.lhs} -> {' '.join(str(s) for s in self.rhs)}"


class Grammar:
    """
    Context-free grammar for SyGuS.
    
    Defines the syntax of candidate expressions.
    """
    
    def __init__(self, name: str = "grammar"):
        self.name = name
        self._nonterminals: Dict[str, Symbol] = {}
        self._terminals: Dict[str, Symbol] = {}
        self._productions: Dict[str, List[Production]] = {}  # nonterminal -> productions
        self._start: Optional[Symbol] = None
    
    def add_nonterminal(self, name: str, sort: str = "Int") -> Symbol:
        """Add a nonterminal symbol."""
        sym = Symbol(name, SymbolKind.NONTERMINAL, sort)
        self._nonterminals[name] = sym
        self._productions[name] = []
        return sym
    
    def add_terminal(self, name: str, sort: str = "Int") -> Symbol:
        """Add a terminal symbol."""
        sym = Symbol(name, SymbolKind.TERMINAL, sort)
        self._terminals[name] = sym
        return sym
    
    def add_production(self, lhs: Symbol, rhs: Union[List[Symbol], Tuple[str, List[Symbol]]],
                        weight: float = 1.0) -> Production:
        """Add a production rule."""
        if lhs.name not in self._nonterminals:
            raise ValueError(f"Unknown nonterminal: {lhs}")
        
        prod = Production(lhs, rhs, weight)
        self._productions[lhs.name].append(prod)
        return prod
    
    def set_start(self, symbol: Symbol) -> None:
        """Set the start symbol."""
        self._start = symbol
    
    def get_start(self) -> Optional[Symbol]:
        """Get the start symbol."""
        return self._start
    
    def get_productions(self, nonterminal: Symbol) -> List[Production]:
        """Get productions for a nonterminal."""
        return self._productions.get(nonterminal.name, [])
    
    def get_all_productions(self) -> List[Production]:
        """Get all productions."""
        return [p for prods in self._productions.values() for p in prods]
    
    def get_terminals(self) -> List[Symbol]:
        """Get all terminals."""
        return list(self._terminals.values())
    
    def get_nonterminals(self) -> List[Symbol]:
        """Get all nonterminals."""
        return list(self._nonterminals.values())
    
    def __str__(self) -> str:
        lines = [f"Grammar: {self.name}"]
        lines.append(f"  Start: {self._start}")
        for nt, prods in self._productions.items():
            for prod in prods:
                lines.append(f"  {prod}")
        return "\n".join(lines)


# =============================================================================
# EXPRESSION AST
# =============================================================================

class Expr(ABC):
    """
    Abstract expression in the SyGuS language.
    """
    
    @abstractmethod
    def to_z3(self, var_map: Dict[str, z3.ArithRef]) -> z3.ExprRef:
        """Convert to Z3 expression."""
        pass
    
    @abstractmethod
    def size(self) -> int:
        """Size of expression (number of nodes)."""
        pass
    
    @abstractmethod
    def __str__(self) -> str:
        pass
    
    @abstractmethod
    def substitute(self, mapping: Dict[str, "Expr"]) -> "Expr":
        """Substitute expressions for variables."""
        pass


@dataclass
class IntConst(Expr):
    """Integer constant."""
    value: int
    
    def to_z3(self, var_map: Dict[str, z3.ArithRef]) -> z3.ArithRef:
        return z3.IntVal(self.value)
    
    def size(self) -> int:
        return 1
    
    def __str__(self) -> str:
        return str(self.value)
    
    def substitute(self, mapping: Dict[str, Expr]) -> Expr:
        return self


@dataclass
class RealConst(Expr):
    """Real constant."""
    value: float
    
    def to_z3(self, var_map: Dict[str, z3.ArithRef]) -> z3.ArithRef:
        return z3.RealVal(self.value)
    
    def size(self) -> int:
        return 1
    
    def __str__(self) -> str:
        return str(self.value)
    
    def substitute(self, mapping: Dict[str, Expr]) -> Expr:
        return self


@dataclass
class Var(Expr):
    """Variable."""
    name: str
    
    def to_z3(self, var_map: Dict[str, z3.ArithRef]) -> z3.ArithRef:
        return var_map[self.name]
    
    def size(self) -> int:
        return 1
    
    def __str__(self) -> str:
        return self.name
    
    def substitute(self, mapping: Dict[str, Expr]) -> Expr:
        return mapping.get(self.name, self)


@dataclass
class BinOp(Expr):
    """Binary operation."""
    op: str  # "+", "-", "*", "/", "max", "min"
    left: Expr
    right: Expr
    
    def to_z3(self, var_map: Dict[str, z3.ArithRef]) -> z3.ArithRef:
        l = self.left.to_z3(var_map)
        r = self.right.to_z3(var_map)
        
        if self.op == "+":
            return l + r
        elif self.op == "-":
            return l - r
        elif self.op == "*":
            return l * r
        elif self.op == "/":
            return l / r
        elif self.op == "max":
            return z3.If(l >= r, l, r)
        elif self.op == "min":
            return z3.If(l <= r, l, r)
        else:
            raise ValueError(f"Unknown operator: {self.op}")
    
    def size(self) -> int:
        return 1 + self.left.size() + self.right.size()
    
    def __str__(self) -> str:
        return f"({self.left} {self.op} {self.right})"
    
    def substitute(self, mapping: Dict[str, Expr]) -> Expr:
        return BinOp(self.op, self.left.substitute(mapping), self.right.substitute(mapping))


@dataclass
class UnaryOp(Expr):
    """Unary operation."""
    op: str  # "neg", "abs", "sq"
    arg: Expr
    
    def to_z3(self, var_map: Dict[str, z3.ArithRef]) -> z3.ArithRef:
        a = self.arg.to_z3(var_map)
        
        if self.op == "neg":
            return -a
        elif self.op == "abs":
            return z3.If(a >= 0, a, -a)
        elif self.op == "sq":
            return a * a
        else:
            raise ValueError(f"Unknown operator: {self.op}")
    
    def size(self) -> int:
        return 1 + self.arg.size()
    
    def __str__(self) -> str:
        return f"{self.op}({self.arg})"
    
    def substitute(self, mapping: Dict[str, Expr]) -> Expr:
        return UnaryOp(self.op, self.arg.substitute(mapping))


@dataclass
class BoolExpr(Expr):
    """Boolean expression (comparison)."""
    op: str  # ">=", "<=", ">", "<", "==", "!="
    left: Expr
    right: Expr
    
    def to_z3(self, var_map: Dict[str, z3.ArithRef]) -> z3.BoolRef:
        l = self.left.to_z3(var_map)
        r = self.right.to_z3(var_map)
        
        if self.op == ">=":
            return l >= r
        elif self.op == "<=":
            return l <= r
        elif self.op == ">":
            return l > r
        elif self.op == "<":
            return l < r
        elif self.op == "==":
            return l == r
        elif self.op == "!=":
            return l != r
        else:
            raise ValueError(f"Unknown comparison: {self.op}")
    
    def size(self) -> int:
        return 1 + self.left.size() + self.right.size()
    
    def __str__(self) -> str:
        return f"({self.left} {self.op} {self.right})"
    
    def substitute(self, mapping: Dict[str, Expr]) -> Expr:
        return BoolExpr(self.op, self.left.substitute(mapping), self.right.substitute(mapping))


@dataclass
class BoolBinOp(Expr):
    """Boolean binary operation."""
    op: str  # "and", "or", "implies"
    left: Expr
    right: Expr
    
    def to_z3(self, var_map: Dict[str, z3.ArithRef]) -> z3.BoolRef:
        l = self.left.to_z3(var_map)
        r = self.right.to_z3(var_map)
        
        if self.op == "and":
            return z3.And(l, r)
        elif self.op == "or":
            return z3.Or(l, r)
        elif self.op == "implies":
            return z3.Implies(l, r)
        else:
            raise ValueError(f"Unknown Boolean op: {self.op}")
    
    def size(self) -> int:
        return 1 + self.left.size() + self.right.size()
    
    def __str__(self) -> str:
        return f"({self.left} {self.op} {self.right})"
    
    def substitute(self, mapping: Dict[str, Expr]) -> Expr:
        return BoolBinOp(self.op, self.left.substitute(mapping), self.right.substitute(mapping))


@dataclass
class BoolNot(Expr):
    """Boolean negation."""
    arg: Expr
    
    def to_z3(self, var_map: Dict[str, z3.ArithRef]) -> z3.BoolRef:
        return z3.Not(self.arg.to_z3(var_map))
    
    def size(self) -> int:
        return 1 + self.arg.size()
    
    def __str__(self) -> str:
        return f"not({self.arg})"
    
    def substitute(self, mapping: Dict[str, Expr]) -> Expr:
        return BoolNot(self.arg.substitute(mapping))


@dataclass
class Ite(Expr):
    """If-then-else."""
    cond: Expr
    then_branch: Expr
    else_branch: Expr
    
    def to_z3(self, var_map: Dict[str, z3.ArithRef]) -> z3.ExprRef:
        c = self.cond.to_z3(var_map)
        t = self.then_branch.to_z3(var_map)
        e = self.else_branch.to_z3(var_map)
        return z3.If(c, t, e)
    
    def size(self) -> int:
        return 1 + self.cond.size() + self.then_branch.size() + self.else_branch.size()
    
    def __str__(self) -> str:
        return f"ite({self.cond}, {self.then_branch}, {self.else_branch})"
    
    def substitute(self, mapping: Dict[str, Expr]) -> Expr:
        return Ite(
            self.cond.substitute(mapping),
            self.then_branch.substitute(mapping),
            self.else_branch.substitute(mapping)
        )


# =============================================================================
# GRAMMAR BUILDERS
# =============================================================================

def build_polynomial_grammar(variables: List[str], max_degree: int = 2,
                               max_terms: int = 5) -> Grammar:
    """
    Build grammar for polynomial expressions.
    
    B ::= Term | Term + B
    Term ::= Coef * Mono
    Mono ::= 1 | Var | Var * Mono (limited by degree)
    """
    g = Grammar("polynomial")
    
    # Nonterminals
    B = g.add_nonterminal("B", "Real")
    Term = g.add_nonterminal("Term", "Real")
    Mono = g.add_nonterminal("Mono", "Real")
    Coef = g.add_nonterminal("Coef", "Real")
    
    # Terminals
    one = g.add_terminal("1", "Real")
    for v in variables:
        g.add_terminal(v, "Real")
    
    # Coefficient values
    for c in [-2, -1, 0, 1, 2]:
        g.add_terminal(str(c), "Real")
    
    # Productions for B
    g.add_production(B, [Term])  # B -> Term
    g.add_production(B, ("+", [Term, B]))  # B -> Term + B
    
    # Productions for Term
    g.add_production(Term, ("*", [Coef, Mono]))  # Term -> Coef * Mono
    
    # Productions for Mono
    g.add_production(Mono, [one])  # Mono -> 1
    for v in variables:
        v_sym = g._terminals[v]
        g.add_production(Mono, [v_sym])  # Mono -> Var
        g.add_production(Mono, ("*", [v_sym, Mono]))  # Mono -> Var * Mono
    
    # Productions for Coef
    for c in [-2, -1, 0, 1, 2]:
        g.add_production(Coef, [g._terminals[str(c)]])
    
    g.set_start(B)
    return g


def build_linear_grammar(variables: List[str]) -> Grammar:
    """
    Build grammar for linear expressions.
    
    L ::= Coef | Coef + L | Coef * Var + L
    """
    g = Grammar("linear")
    
    L = g.add_nonterminal("L", "Real")
    Coef = g.add_nonterminal("Coef", "Real")
    
    # Coefficient terminals
    for c in range(-5, 6):
        g.add_terminal(str(c), "Real")
    
    # Variable terminals
    for v in variables:
        g.add_terminal(v, "Real")
    
    # Productions
    g.add_production(L, [Coef])  # L -> Coef
    g.add_production(L, ("+", [Coef, L]))  # L -> Coef + L
    
    for v in variables:
        v_sym = g._terminals[v]
        g.add_production(L, ("+", [("*", [Coef, v_sym]), L]))  # L -> Coef*Var + L
    
    # Coef productions
    for c in range(-5, 6):
        g.add_production(Coef, [g._terminals[str(c)]])
    
    g.set_start(L)
    return g


def build_boolean_grammar(variables: List[str]) -> Grammar:
    """
    Build grammar for Boolean expressions over linear arithmetic.
    
    B ::= Atom | B and B | B or B | not B
    Atom ::= L >= 0 | L > 0 | L == 0
    L ::= (linear expression)
    """
    g = Grammar("boolean")
    
    B = g.add_nonterminal("B", "Bool")
    Atom = g.add_nonterminal("Atom", "Bool")
    L = g.add_nonterminal("L", "Real")
    Coef = g.add_nonterminal("Coef", "Real")
    
    # Terminals
    zero = g.add_terminal("0", "Real")
    for c in range(-3, 4):
        g.add_terminal(str(c), "Real")
    for v in variables:
        g.add_terminal(v, "Real")
    
    # B productions
    g.add_production(B, [Atom])
    g.add_production(B, ("and", [B, B]))
    g.add_production(B, ("or", [B, B]))
    g.add_production(B, ("not", [B]))
    
    # Atom productions
    g.add_production(Atom, (">=", [L, zero]))
    g.add_production(Atom, (">", [L, zero]))
    g.add_production(Atom, ("==", [L, zero]))
    
    # L productions (simplified)
    g.add_production(L, [Coef])
    for v in variables:
        g.add_production(L, ("+", [("*", [Coef, g._terminals[v]]), L]))
    
    # Coef productions
    for c in range(-3, 4):
        g.add_production(Coef, [g._terminals[str(c)]])
    
    g.set_start(B)
    return g


# =============================================================================
# ENUMERATOR
# =============================================================================

class EnumerationStrategy(Enum):
    """Strategy for expression enumeration."""
    BFS = auto()        # Breadth-first (by size)
    RANDOM = auto()     # Random sampling
    WEIGHTED = auto()   # Weighted by production weights


class Enumerator:
    """
    Enumerate expressions from a grammar.
    
    Supports multiple enumeration strategies.
    """
    
    def __init__(self, grammar: Grammar,
                 strategy: EnumerationStrategy = EnumerationStrategy.BFS,
                 max_size: int = 20):
        self.grammar = grammar
        self.strategy = strategy
        self.max_size = max_size
        
        self._cache: Dict[Tuple[str, int], List[Expr]] = {}
    
    def enumerate(self, max_count: int = 1000) -> Iterator[Expr]:
        """Enumerate expressions from grammar."""
        if self.strategy == EnumerationStrategy.BFS:
            return self._enumerate_bfs(max_count)
        elif self.strategy == EnumerationStrategy.RANDOM:
            return self._enumerate_random(max_count)
        else:
            return self._enumerate_bfs(max_count)
    
    def _enumerate_bfs(self, max_count: int) -> Iterator[Expr]:
        """Enumerate by size (breadth-first)."""
        start = self.grammar.get_start()
        if not start:
            return
        
        count = 0
        for size in range(1, self.max_size + 1):
            for expr in self._generate_of_size(start, size):
                yield expr
                count += 1
                if count >= max_count:
                    return
    
    def _generate_of_size(self, symbol: Symbol, target_size: int) -> Iterator[Expr]:
        """Generate expressions of exactly target_size for a symbol."""
        cache_key = (symbol.name, target_size)
        
        if cache_key in self._cache:
            for expr in self._cache[cache_key]:
                yield expr
            return
        
        results = []
        
        if symbol.is_terminal():
            if target_size == 1:
                expr = self._terminal_to_expr(symbol)
                if expr:
                    results.append(expr)
                    yield expr
        else:
            for prod in self.grammar.get_productions(symbol):
                for expr in self._generate_from_production(prod, target_size):
                    results.append(expr)
                    yield expr
        
        self._cache[cache_key] = results
    
    def _generate_from_production(self, prod: Production, target_size: int) -> Iterator[Expr]:
        """Generate expressions from a production."""
        if prod.is_operator():
            op = prod.get_operator()
            operands = prod.get_operands()
            
            # Operator node takes 1 size
            remaining_size = target_size - 1
            
            if remaining_size < len(operands):
                return
            
            # Distribute size among operands
            for size_partition in self._partitions(remaining_size, len(operands)):
                for operand_exprs in self._product_iterators(operands, size_partition):
                    expr = self._build_operator_expr(op, operand_exprs)
                    if expr:
                        yield expr
        else:
            # Sequence of symbols
            rhs = prod.rhs
            if len(rhs) == 1:
                # Single symbol
                for expr in self._generate_of_size(rhs[0], target_size):
                    yield expr
    
    def _partitions(self, n: int, k: int) -> Iterator[Tuple[int, ...]]:
        """Generate partitions of n into k parts (each >= 1)."""
        if k == 1:
            yield (n,)
            return
        
        for first in range(1, n - k + 2):
            for rest in self._partitions(n - first, k - 1):
                yield (first,) + rest
    
    def _product_iterators(self, symbols: List[Symbol],
                            sizes: Tuple[int, ...]) -> Iterator[List[Expr]]:
        """Generate cartesian product of expressions for symbols with given sizes."""
        if not symbols:
            yield []
            return
        
        first = symbols[0]
        first_size = sizes[0]
        rest = symbols[1:]
        rest_sizes = sizes[1:]
        
        for first_expr in self._generate_of_size(first, first_size):
            for rest_exprs in self._product_iterators(rest, rest_sizes):
                yield [first_expr] + rest_exprs
    
    def _terminal_to_expr(self, symbol: Symbol) -> Optional[Expr]:
        """Convert terminal symbol to expression."""
        name = symbol.name
        
        # Check if it's a number
        try:
            val = int(name)
            return IntConst(val)
        except ValueError:
            pass
        
        try:
            val = float(name)
            return RealConst(val)
        except ValueError:
            pass
        
        # It's a variable
        return Var(name)
    
    def _build_operator_expr(self, op: str, operands: List[Expr]) -> Optional[Expr]:
        """Build operator expression."""
        if op in ["+", "-", "*", "/", "max", "min"]:
            if len(operands) == 2:
                return BinOp(op, operands[0], operands[1])
        elif op in ["neg", "abs", "sq"]:
            if len(operands) == 1:
                return UnaryOp(op, operands[0])
        elif op in [">=", "<=", ">", "<", "==", "!="]:
            if len(operands) == 2:
                return BoolExpr(op, operands[0], operands[1])
        elif op in ["and", "or", "implies"]:
            if len(operands) == 2:
                return BoolBinOp(op, operands[0], operands[1])
        elif op == "not":
            if len(operands) == 1:
                return BoolNot(operands[0])
        elif op == "ite":
            if len(operands) == 3:
                return Ite(operands[0], operands[1], operands[2])
        
        return None
    
    def _enumerate_random(self, max_count: int) -> Iterator[Expr]:
        """Enumerate by random sampling."""
        start = self.grammar.get_start()
        if not start:
            return
        
        for _ in range(max_count):
            expr = self._random_expr(start, self.max_size)
            if expr:
                yield expr
    
    def _random_expr(self, symbol: Symbol, max_size: int) -> Optional[Expr]:
        """Generate random expression."""
        if max_size <= 0:
            return None
        
        if symbol.is_terminal():
            return self._terminal_to_expr(symbol)
        
        prods = self.grammar.get_productions(symbol)
        if not prods:
            return None
        
        # Pick random production
        prod = random.choice(prods)
        
        if prod.is_operator():
            op = prod.get_operator()
            operands = prod.get_operands()
            
            # Generate random operands
            operand_exprs = []
            remaining = max_size - 1
            
            for i, operand in enumerate(operands):
                # Allocate size randomly
                if i == len(operands) - 1:
                    size = remaining
                else:
                    size = random.randint(1, max(1, remaining - len(operands) + i + 1))
                
                expr = self._random_expr(operand, size)
                if expr is None:
                    return None
                
                operand_exprs.append(expr)
                remaining -= expr.size()
            
            return self._build_operator_expr(op, operand_exprs)
        else:
            # Single symbol
            return self._random_expr(prod.rhs[0], max_size)


# =============================================================================
# VERIFICATION
# =============================================================================

class VerificationResult(Enum):
    """Result of verification."""
    VALID = auto()
    INVALID = auto()
    UNKNOWN = auto()


@dataclass
class Counterexample:
    """
    Counterexample to verification condition.
    """
    kind: str  # "initiation", "consecution", "safety"
    state: Dict[str, Any]
    next_state: Optional[Dict[str, Any]] = None


class SyGuSVerifier:
    """
    Verify candidate invariants against specification.
    
    Checks:
    1. Initiation: Init → I
    2. Consecution: I ∧ Trans → I'
    3. Safety: I → Property
    """
    
    def __init__(self, variables: List[str],
                 init: z3.BoolRef,
                 trans: z3.BoolRef,
                 property: z3.BoolRef,
                 timeout_ms: int = 5000,
                 verbose: bool = False):
        self.variables = variables
        self.init = init
        self.trans = trans
        self.property = property
        self.timeout_ms = timeout_ms
        self.verbose = verbose
        
        self._z3_vars = {v: z3.Int(v) for v in variables}
        self._z3_vars_prime = {v: z3.Int(f"{v}_prime") for v in variables}
        
        self._solver = z3.Solver()
        self._solver.set("timeout", timeout_ms)
    
    def verify(self, candidate: Expr) -> Tuple[VerificationResult, Optional[Counterexample]]:
        """
        Verify candidate invariant.
        
        Returns (result, counterexample) where counterexample is None if valid.
        """
        # Get Z3 formula for candidate
        try:
            inv = candidate.to_z3(self._z3_vars)
        except Exception as e:
            if self.verbose:
                print(f"  Error converting to Z3: {e}")
            return VerificationResult.UNKNOWN, None
        
        # Check initiation
        result, cex = self._check_initiation(inv)
        if result != VerificationResult.VALID:
            return result, cex
        
        # Check consecution
        result, cex = self._check_consecution(inv)
        if result != VerificationResult.VALID:
            return result, cex
        
        # Check safety
        result, cex = self._check_safety(inv)
        return result, cex
    
    def _check_initiation(self, inv: z3.ExprRef) -> Tuple[VerificationResult, Optional[Counterexample]]:
        """Check Init → I."""
        # Coerce integer invariants to boolean (polynomial >= 0)
        if z3.is_arith(inv):
            inv = inv >= 0
        self._solver.push()
        
        # Find state: Init ∧ ¬I
        self._solver.add(self.init)
        self._solver.add(z3.Not(inv))
        
        result = self._solver.check()
        
        if result == z3.sat:
            model = self._solver.model()
            state = self._model_to_dict(model)
            cex = Counterexample("initiation", state)
            self._solver.pop()
            return VerificationResult.INVALID, cex
        elif result == z3.unsat:
            self._solver.pop()
            return VerificationResult.VALID, None
        else:
            self._solver.pop()
            return VerificationResult.UNKNOWN, None
    
    def _check_consecution(self, inv: z3.ExprRef) -> Tuple[VerificationResult, Optional[Counterexample]]:
        """Check I ∧ Trans → I'."""
        # Coerce integer invariants to boolean (polynomial >= 0)
        if z3.is_arith(inv):
            inv = inv >= 0
        self._solver.push()
        
        # Build I'
        inv_prime = z3.substitute(
            inv,
            [(self._z3_vars[v], self._z3_vars_prime[v]) for v in self.variables]
        )
        
        # Find state: I ∧ Trans ∧ ¬I'
        self._solver.add(inv)
        self._solver.add(self.trans)
        self._solver.add(z3.Not(inv_prime))
        
        result = self._solver.check()
        
        if result == z3.sat:
            model = self._solver.model()
            state = self._model_to_dict(model)
            next_state = self._model_to_dict(model, prime=True)
            cex = Counterexample("consecution", state, next_state)
            self._solver.pop()
            return VerificationResult.INVALID, cex
        elif result == z3.unsat:
            self._solver.pop()
            return VerificationResult.VALID, None
        else:
            self._solver.pop()
            return VerificationResult.UNKNOWN, None
    
    def _check_safety(self, inv: z3.ExprRef) -> Tuple[VerificationResult, Optional[Counterexample]]:
        """Check I → Property."""
        # Coerce integer invariants to boolean (polynomial >= 0)
        if z3.is_arith(inv):
            inv = inv >= 0
        self._solver.push()
        
        # Find state: I ∧ ¬Property
        self._solver.add(inv)
        self._solver.add(z3.Not(self.property))
        
        result = self._solver.check()
        
        if result == z3.sat:
            model = self._solver.model()
            state = self._model_to_dict(model)
            cex = Counterexample("safety", state)
            self._solver.pop()
            return VerificationResult.INVALID, cex
        elif result == z3.unsat:
            self._solver.pop()
            return VerificationResult.VALID, None
        else:
            self._solver.pop()
            return VerificationResult.UNKNOWN, None
    
    def _model_to_dict(self, model: z3.ModelRef, prime: bool = False) -> Dict[str, Any]:
        """Convert Z3 model to dictionary."""
        vars_map = self._z3_vars_prime if prime else self._z3_vars
        
        result = {}
        for v, z3_v in vars_map.items():
            val = model.eval(z3_v, model_completion=True)
            if z3.is_int_value(val):
                result[v] = val.as_long()
            else:
                result[v] = 0
        return result


# =============================================================================
# CEGIS LOOP
# =============================================================================

class CEGISResult(Enum):
    """Result of CEGIS synthesis."""
    SUCCESS = auto()
    FAILURE = auto()
    TIMEOUT = auto()


@dataclass
class SynthesisResult:
    """
    Result of SyGuS synthesis.
    """
    result: CEGISResult
    solution: Optional[Expr] = None
    iterations: int = 0
    candidates_tried: int = 0
    counterexamples: int = 0
    statistics: Dict[str, Any] = field(default_factory=dict)
    message: str = ""


class CEGISSynthesizer:
    """
    Counterexample-Guided Inductive Synthesis.
    
    Main CEGIS loop:
    1. Enumerate candidate from grammar
    2. Verify against specification
    3. If valid, return
    4. If invalid, add counterexample to filter future candidates
    5. Repeat
    """
    
    def __init__(self, grammar: Grammar,
                 verifier: SyGuSVerifier,
                 max_iterations: int = 1000,
                 timeout_ms: int = 60000,
                 verbose: bool = False):
        self.grammar = grammar
        self.verifier = verifier
        self.max_iterations = max_iterations
        self.timeout_ms = timeout_ms
        self.verbose = verbose
        
        self._counterexamples: List[Counterexample] = []
        
        self.stats = {
            'candidates_tried': 0,
            'candidates_pruned': 0,
            'counterexamples_collected': 0,
        }
    
    def synthesize(self) -> SynthesisResult:
        """
        Run CEGIS loop.
        """
        start_time = time.time()
        
        enumerator = Enumerator(self.grammar, EnumerationStrategy.BFS)
        
        for iteration, candidate in enumerate(enumerator.enumerate(self.max_iterations)):
            # Check timeout
            elapsed = (time.time() - start_time) * 1000
            if elapsed > self.timeout_ms:
                return SynthesisResult(
                    result=CEGISResult.TIMEOUT,
                    iterations=iteration,
                    candidates_tried=self.stats['candidates_tried'],
                    counterexamples=len(self._counterexamples),
                    statistics=self.stats,
                    message="Timeout"
                )
            
            # Prune with counterexamples
            if self._is_pruned(candidate):
                self.stats['candidates_pruned'] += 1
                continue
            
            self.stats['candidates_tried'] += 1
            
            if self.verbose and self.stats['candidates_tried'] % 100 == 0:
                print(f"  Tried {self.stats['candidates_tried']} candidates, "
                      f"{len(self._counterexamples)} counterexamples")
            
            # Verify
            result, cex = self.verifier.verify(candidate)
            
            if result == VerificationResult.VALID:
                return SynthesisResult(
                    result=CEGISResult.SUCCESS,
                    solution=candidate,
                    iterations=iteration + 1,
                    candidates_tried=self.stats['candidates_tried'],
                    counterexamples=len(self._counterexamples),
                    statistics=self.stats,
                    message="Invariant found"
                )
            
            if cex:
                self._counterexamples.append(cex)
                self.stats['counterexamples_collected'] += 1
        
        return SynthesisResult(
            result=CEGISResult.FAILURE,
            iterations=self.max_iterations,
            candidates_tried=self.stats['candidates_tried'],
            counterexamples=len(self._counterexamples),
            statistics=self.stats,
            message="Max iterations reached"
        )
    
    def _is_pruned(self, candidate: Expr) -> bool:
        """Check if candidate is inconsistent with counterexamples."""
        for cex in self._counterexamples:
            try:
                var_map = {v: z3.IntVal(cex.state.get(v, 0)) 
                           for v in self.verifier.variables}
                
                val = candidate.to_z3(var_map)
                val = z3.simplify(val)
                
                if cex.kind == "initiation":
                    # Should be true on initial state
                    if z3.is_false(val):
                        return True
                elif cex.kind == "safety":
                    # Should be false on unsafe state
                    if z3.is_true(val):
                        return True
            except Exception:
                pass
        
        return False


# =============================================================================
# SYGUS-BARRIER BRIDGE
# =============================================================================

@dataclass
class SyGuSConstraint:
    """
    Constraint derived from SyGuS for barrier synthesis.
    """
    formula: z3.ExprRef
    expression: Expr
    source: str


class SyGuSBarrierBridge:
    """
    Bridge between SyGuS synthesis and barrier synthesis.
    
    Uses SyGuS-synthesized invariants to:
    1. Provide barrier templates
    2. Condition barrier search
    3. Extract polynomial constraints
    """
    
    def __init__(self, n_vars: int, var_names: Optional[List[str]] = None,
                 verbose: bool = False):
        self.n_vars = n_vars
        self.var_names = var_names or [f"x_{i}" for i in range(n_vars)]
        self.verbose = verbose
        
        self._solution: Optional[Expr] = None
        self._constraints: List[SyGuSConstraint] = []
    
    def set_synthesized_solution(self, solution: Expr) -> None:
        """Set the synthesized solution."""
        self._solution = solution
        self._extract_constraints()
    
    def _extract_constraints(self) -> None:
        """Extract constraints from synthesized expression."""
        if self._solution is None:
            return
        
        var_map = {v: z3.Real(v) for v in self.var_names}
        
        try:
            formula = self._solution.to_z3(var_map)
            
            constraint = SyGuSConstraint(
                formula=formula,
                expression=self._solution,
                source="sygus"
            )
            self._constraints.append(constraint)
        except Exception as e:
            if self.verbose:
                print(f"  Error extracting constraint: {e}")
    
    def to_polynomial(self) -> Optional[Polynomial]:
        """Convert solution to polynomial if possible."""
        if self._solution is None:
            return None
        
        return self._expr_to_polynomial(self._solution)
    
    def _expr_to_polynomial(self, expr: Expr) -> Optional[Polynomial]:
        """Convert expression to polynomial."""
        coeffs = {}
        
        def process(e: Expr, coef: int = 1) -> bool:
            if isinstance(e, IntConst):
                mono = tuple([0] * self.n_vars)
                coeffs[mono] = coeffs.get(mono, 0) + coef * e.value
                return True
            
            if isinstance(e, RealConst):
                mono = tuple([0] * self.n_vars)
                coeffs[mono] = coeffs.get(mono, 0) + coef * int(e.value)
                return True
            
            if isinstance(e, Var):
                if e.name in self.var_names:
                    idx = self.var_names.index(e.name)
                    mono = tuple(1 if i == idx else 0 for i in range(self.n_vars))
                    coeffs[mono] = coeffs.get(mono, 0) + coef
                    return True
                return False
            
            if isinstance(e, BinOp):
                if e.op == "+":
                    return process(e.left, coef) and process(e.right, coef)
                elif e.op == "-":
                    return process(e.left, coef) and process(e.right, -coef)
                elif e.op == "*":
                    # Handle coefficient * variable
                    if isinstance(e.left, (IntConst, RealConst)):
                        c = e.left.value if isinstance(e.left, IntConst) else int(e.left.value)
                        return process(e.right, coef * c)
                    return False
            
            if isinstance(e, UnaryOp):
                if e.op == "neg":
                    return process(e.arg, -coef)
            
            return False
        
        if process(expr):
            return Polynomial(self.n_vars, coeffs)
        
        return None
    
    def condition_barrier_problem(self, problem: BarrierSynthesisProblem) -> BarrierSynthesisProblem:
        """Condition barrier problem using SyGuS solution."""
        poly = self.to_polynomial()
        
        if poly is None:
            return problem
        
        # Add polynomial as constraint to init set
        new_init = SemialgebraicSet(
            n_vars=problem.init_set.n_vars,
            inequalities=problem.init_set.inequalities + [poly],
            equalities=problem.init_set.equalities,
            var_names=problem.init_set.var_names,
            name=f"{problem.init_set.name}_sygus"
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
# SYGUS INTEGRATION
# =============================================================================

@dataclass
class SyGuSIntegrationConfig:
    """Configuration for SyGuS integration."""
    grammar_type: str = "polynomial"  # "polynomial", "linear", "boolean"
    max_degree: int = 2
    max_iterations: int = 1000
    timeout_ms: int = 60000
    use_cegis: bool = True
    verbose: bool = False


class SyGuSIntegration:
    """
    Integration of SyGuS with barrier synthesis.
    
    Provides:
    1. Grammar-based invariant synthesis
    2. CEGIS-based search
    3. Template extraction for barriers
    """
    
    def __init__(self, config: Optional[SyGuSIntegrationConfig] = None,
                 verbose: bool = False):
        self.config = config or SyGuSIntegrationConfig()
        self.verbose = verbose or self.config.verbose
        
        self._solutions: Dict[str, Expr] = {}
        self._bridges: Dict[str, SyGuSBarrierBridge] = {}
        
        self.stats = {
            'synthesis_runs': 0,
            'solutions_found': 0,
            'conditioning_applications': 0,
        }
    
    def synthesize_invariant(self, variables: List[str],
                              init: z3.BoolRef,
                              trans: z3.BoolRef,
                              property: z3.BoolRef,
                              problem_id: str = "default") -> SynthesisResult:
        """
        Synthesize invariant using SyGuS.
        """
        self.stats['synthesis_runs'] += 1
        
        # Build grammar
        if self.config.grammar_type == "polynomial":
            grammar = build_polynomial_grammar(variables, self.config.max_degree)
        elif self.config.grammar_type == "linear":
            grammar = build_linear_grammar(variables)
        elif self.config.grammar_type == "boolean":
            grammar = build_boolean_grammar(variables)
        else:
            grammar = build_polynomial_grammar(variables)
        
        # Build verifier
        verifier = SyGuSVerifier(
            variables, init, trans, property,
            timeout_ms=self.config.timeout_ms // 10,
            verbose=self.verbose
        )
        
        # Run CEGIS
        synthesizer = CEGISSynthesizer(
            grammar, verifier,
            max_iterations=self.config.max_iterations,
            timeout_ms=self.config.timeout_ms,
            verbose=self.verbose
        )
        
        result = synthesizer.synthesize()
        
        if result.result == CEGISResult.SUCCESS and result.solution:
            self.stats['solutions_found'] += 1
            self._solutions[problem_id] = result.solution
            
            # Build bridge
            bridge = SyGuSBarrierBridge(len(variables), variables, self.verbose)
            bridge.set_synthesized_solution(result.solution)
            self._bridges[problem_id] = bridge
        
        return result
    
    def condition_barrier_problem(self, problem: BarrierSynthesisProblem,
                                    problem_id: str = "default") -> BarrierSynthesisProblem:
        """Condition barrier problem using SyGuS solution."""
        bridge = self._bridges.get(problem_id)
        if bridge:
            self.stats['conditioning_applications'] += 1
            return bridge.condition_barrier_problem(problem)
        return problem
    
    def get_solution(self, problem_id: str) -> Optional[Expr]:
        """Get synthesized solution."""
        return self._solutions.get(problem_id)
    
    def get_polynomial_template(self, problem_id: str) -> Optional[Polynomial]:
        """Get polynomial template from solution."""
        bridge = self._bridges.get(problem_id)
        if bridge:
            return bridge.to_polynomial()
        return None
    
    def clear_cache(self) -> None:
        """Clear all caches."""
        self._solutions.clear()
        self._bridges.clear()


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def synthesize_sygus_invariant(variables: List[str],
                                 init: z3.BoolRef,
                                 trans: z3.BoolRef,
                                 property: z3.BoolRef,
                                 grammar_type: str = "polynomial",
                                 timeout_ms: int = 60000,
                                 verbose: bool = False) -> SynthesisResult:
    """
    Synthesize invariant using SyGuS.
    
    Main entry point for SyGuS synthesis.
    """
    config = SyGuSIntegrationConfig(
        grammar_type=grammar_type,
        timeout_ms=timeout_ms,
        verbose=verbose
    )
    
    integration = SyGuSIntegration(config, verbose)
    return integration.synthesize_invariant(variables, init, trans, property)


def condition_barrier_with_sygus(problem: BarrierSynthesisProblem,
                                   init: z3.BoolRef,
                                   trans: z3.BoolRef,
                                   property: z3.BoolRef,
                                   timeout_ms: int = 30000,
                                   verbose: bool = False) -> BarrierSynthesisProblem:
    """
    Condition barrier problem using SyGuS-synthesized invariant.
    """
    variables = problem.init_set.var_names or [f"x_{i}" for i in range(problem.n_vars)]
    
    config = SyGuSIntegrationConfig(
        timeout_ms=timeout_ms,
        verbose=verbose
    )
    
    integration = SyGuSIntegration(config, verbose)
    result = integration.synthesize_invariant(variables, init, trans, property)
    
    if result.result == CEGISResult.SUCCESS:
        return integration.condition_barrier_problem(problem)
    
    return problem


# =============================================================================
# TEMPLATE-BASED SYNTHESIS
# =============================================================================

class TemplateSynthesizer:
    """
    Template-based synthesis.
    
    Uses a template with holes and fills them with CEGIS.
    """
    
    def __init__(self, variables: List[str],
                 template: Expr,
                 holes: List[str],
                 verbose: bool = False):
        self.variables = variables
        self.template = template
        self.holes = holes
        self.verbose = verbose
        
        self._z3_vars = {v: z3.Int(v) for v in variables}
        self._hole_vars = {h: z3.Int(h) for h in holes}
    
    def synthesize(self, init: z3.BoolRef,
                    trans: z3.BoolRef,
                    property: z3.BoolRef,
                    timeout_ms: int = 30000) -> Optional[Dict[str, int]]:
        """
        Synthesize hole values.
        """
        solver = z3.Solver()
        solver.set("timeout", timeout_ms)
        
        # Get template as Z3
        all_vars = {**self._z3_vars, **self._hole_vars}
        inv = self.template.to_z3(all_vars)
        
        # Primed variables
        z3_vars_prime = {v: z3.Int(f"{v}_prime") for v in self.variables}
        
        # Build I'
        subs = [(self._z3_vars[v], z3_vars_prime[v]) for v in self.variables]
        inv_prime = z3.substitute(inv, subs)
        
        # Quantify over program variables
        program_vars = list(self._z3_vars.values()) + list(z3_vars_prime.values())
        
        # Initiation: ∀x. Init(x) → I(x)
        initiation = z3.ForAll(list(self._z3_vars.values()),
                                z3.Implies(init, inv))
        solver.add(initiation)
        
        # Consecution: ∀x,x'. I(x) ∧ T(x,x') → I(x')
        consecution = z3.ForAll(program_vars,
                                 z3.Implies(z3.And(inv, trans), inv_prime))
        solver.add(consecution)
        
        # Safety: ∀x. I(x) → P(x)
        safety = z3.ForAll(list(self._z3_vars.values()),
                            z3.Implies(inv, property))
        solver.add(safety)
        
        if solver.check() == z3.sat:
            model = solver.model()
            
            result = {}
            for h, z3_h in self._hole_vars.items():
                val = model.eval(z3_h, model_completion=True)
                result[h] = val.as_long() if z3.is_int_value(val) else 0
            
            return result
        
        return None


# =============================================================================
# ADVANCED SYGUS FEATURES
# =============================================================================

class IncrementalSyGuS:
    """
    Incremental SyGuS synthesis.
    
    Supports adding specifications incrementally.
    """
    
    def __init__(self, variables: List[str],
                 grammar: Grammar,
                 verbose: bool = False):
        self.variables = variables
        self.grammar = grammar
        self.verbose = verbose
        
        self._init_constraints: List[z3.BoolRef] = []
        self._trans_constraints: List[z3.BoolRef] = []
        self._safety_constraints: List[z3.BoolRef] = []
        
        self._counterexamples: List[Counterexample] = []
        self._current_solution: Optional[Expr] = None
    
    def add_init_constraint(self, constraint: z3.BoolRef) -> None:
        """Add initiation constraint."""
        self._init_constraints.append(constraint)
        self._current_solution = None
    
    def add_trans_constraint(self, constraint: z3.BoolRef) -> None:
        """Add transition constraint."""
        self._trans_constraints.append(constraint)
        self._current_solution = None
    
    def add_safety_constraint(self, constraint: z3.BoolRef) -> None:
        """Add safety constraint."""
        self._safety_constraints.append(constraint)
        self._current_solution = None
    
    def add_counterexample(self, cex: Counterexample) -> None:
        """Add counterexample."""
        self._counterexamples.append(cex)
        self._current_solution = None
    
    def synthesize(self, timeout_ms: int = 60000) -> SynthesisResult:
        """Synthesize invariant with current constraints."""
        # Combine constraints
        init = z3.And(self._init_constraints) if self._init_constraints else z3.BoolVal(True)
        trans = z3.And(self._trans_constraints) if self._trans_constraints else z3.BoolVal(True)
        safety = z3.And(self._safety_constraints) if self._safety_constraints else z3.BoolVal(True)
        
        verifier = SyGuSVerifier(
            self.variables, init, trans, safety,
            timeout_ms=timeout_ms // 10,
            verbose=self.verbose
        )
        
        synthesizer = CEGISSynthesizer(
            self.grammar, verifier,
            timeout_ms=timeout_ms,
            verbose=self.verbose
        )
        
        # Add existing counterexamples
        synthesizer._counterexamples = list(self._counterexamples)
        
        result = synthesizer.synthesize()
        
        if result.result == CEGISResult.SUCCESS:
            self._current_solution = result.solution
            # Collect new counterexamples
            self._counterexamples = synthesizer._counterexamples
        
        return result
    
    def get_solution(self) -> Optional[Expr]:
        """Get current solution."""
        return self._current_solution


class ParallelSyGuS:
    """
    Parallel SyGuS with multiple grammars.
    
    Runs synthesis with different grammars in parallel.
    """
    
    def __init__(self, variables: List[str],
                 verbose: bool = False):
        self.variables = variables
        self.verbose = verbose
    
    def synthesize(self, init: z3.BoolRef,
                    trans: z3.BoolRef,
                    property: z3.BoolRef,
                    timeout_ms: int = 60000) -> Optional[SynthesisResult]:
        """
        Run parallel synthesis with multiple grammars.
        """
        grammars = [
            ("linear", build_linear_grammar(self.variables)),
            ("polynomial", build_polynomial_grammar(self.variables, max_degree=2)),
            ("boolean", build_boolean_grammar(self.variables)),
        ]
        
        best_result = None
        best_size = float('inf')
        
        time_per_grammar = timeout_ms // len(grammars)
        
        for name, grammar in grammars:
            if self.verbose:
                print(f"  Trying grammar: {name}")
            
            verifier = SyGuSVerifier(
                self.variables, init, trans, property,
                timeout_ms=time_per_grammar // 10,
                verbose=self.verbose
            )
            
            synthesizer = CEGISSynthesizer(
                grammar, verifier,
                timeout_ms=time_per_grammar,
                verbose=self.verbose
            )
            
            result = synthesizer.synthesize()
            
            if result.result == CEGISResult.SUCCESS and result.solution:
                size = result.solution.size()
                if size < best_size:
                    best_size = size
                    best_result = result
                    if self.verbose:
                        print(f"    Found solution of size {size}")
        
        return best_result


# =============================================================================
# ENTRY POINTS
# =============================================================================

def create_sygus_from_barrier_problem(problem: BarrierSynthesisProblem,
                                        grammar_type: str = "polynomial",
                                        verbose: bool = False) -> Tuple[Grammar, SyGuSVerifier]:
    """
    Create SyGuS components from barrier synthesis problem.
    """
    n_vars = problem.n_vars
    var_names = problem.init_set.var_names or [f"x_{i}" for i in range(n_vars)]
    
    # Build grammar
    if grammar_type == "polynomial":
        grammar = build_polynomial_grammar(var_names, max_degree=problem.barrier_degree)
    elif grammar_type == "linear":
        grammar = build_linear_grammar(var_names)
    else:
        grammar = build_boolean_grammar(var_names)
    
    # Build Z3 constraints
    z3_vars = [z3.Real(v) for v in var_names]
    
    # Init constraint
    init_constraints = [p.to_z3(z3_vars) >= 0 for p in problem.init_set.inequalities]
    init_constraints += [p.to_z3(z3_vars) == 0 for p in problem.init_set.equalities]
    init = z3.And(init_constraints) if init_constraints else z3.BoolVal(True)
    
    # Unsafe constraint (negation is safety)
    unsafe_constraints = [p.to_z3(z3_vars) >= 0 for p in problem.unsafe_set.inequalities]
    property = z3.Not(z3.And(unsafe_constraints)) if unsafe_constraints else z3.BoolVal(True)
    
    # Transition (simplified - would need more structure)
    trans = z3.BoolVal(True)  # Placeholder
    
    verifier = SyGuSVerifier(var_names, init, trans, property, verbose=verbose)
    
    return grammar, verifier


# =============================================================================
# GRAMMAR REFINEMENT
# =============================================================================

class GrammarRefiner:
    """
    Refine grammar based on synthesis feedback.
    
    Learns which productions are useful and adjusts weights.
    """
    
    def __init__(self, grammar: Grammar,
                 verbose: bool = False):
        self.grammar = grammar
        self.verbose = verbose
        
        self._production_success: Dict[str, int] = {}
        self._production_failure: Dict[str, int] = {}
        
        for prod in grammar.get_all_productions():
            key = str(prod)
            self._production_success[key] = 0
            self._production_failure[key] = 0
    
    def record_success(self, expr: Expr) -> None:
        """Record successful expression."""
        prods = self._extract_productions(expr)
        for prod_key in prods:
            self._production_success[prod_key] = self._production_success.get(prod_key, 0) + 1
    
    def record_failure(self, expr: Expr) -> None:
        """Record failed expression."""
        prods = self._extract_productions(expr)
        for prod_key in prods:
            self._production_failure[prod_key] = self._production_failure.get(prod_key, 0) + 1
    
    def _extract_productions(self, expr: Expr) -> List[str]:
        """Extract productions used in expression."""
        prods = []
        
        def traverse(e: Expr):
            if isinstance(e, BinOp):
                prods.append(f"op:{e.op}")
                traverse(e.left)
                traverse(e.right)
            elif isinstance(e, UnaryOp):
                prods.append(f"op:{e.op}")
                traverse(e.arg)
            elif isinstance(e, Var):
                prods.append(f"var:{e.name}")
            elif isinstance(e, (IntConst, RealConst)):
                prods.append(f"const:{e.value}")
        
        traverse(expr)
        return prods
    
    def update_weights(self) -> None:
        """Update production weights based on success/failure."""
        for prod in self.grammar.get_all_productions():
            key = str(prod)
            success = self._production_success.get(key, 0)
            failure = self._production_failure.get(key, 0)
            
            total = success + failure
            if total > 0:
                # Weight based on success rate
                prod.weight = 1.0 + (success - failure) / (total + 1)
            else:
                prod.weight = 1.0
    
    def prune_low_weight(self, threshold: float = 0.5) -> None:
        """Prune productions with low weight."""
        for nt in self.grammar.get_nonterminals():
            prods = self.grammar.get_productions(nt)
            high_weight = [p for p in prods if p.weight >= threshold]
            
            if high_weight:
                self.grammar._productions[nt.name] = high_weight


class AdaptiveGrammar:
    """
    Adaptive grammar that evolves during synthesis.
    """
    
    def __init__(self, variables: List[str],
                 verbose: bool = False):
        self.variables = variables
        self.verbose = verbose
        
        self._grammar = build_polynomial_grammar(variables)
        self._refiner = GrammarRefiner(self._grammar, verbose)
    
    def get_grammar(self) -> Grammar:
        """Get current grammar."""
        return self._grammar
    
    def feedback(self, expr: Expr, success: bool) -> None:
        """Provide feedback on expression."""
        if success:
            self._refiner.record_success(expr)
        else:
            self._refiner.record_failure(expr)
    
    def adapt(self) -> None:
        """Adapt grammar based on feedback."""
        self._refiner.update_weights()
    
    def expand_grammar(self, new_terms: List[str]) -> None:
        """Expand grammar with new terms."""
        for term in new_terms:
            if term not in [s.name for s in self._grammar.get_terminals()]:
                self._grammar.add_terminal(term, "Real")


# =============================================================================
# OBSERVATIONAL EQUIVALENCE
# =============================================================================

class ObservationalEquivalence:
    """
    Prune observationally equivalent expressions.
    
    Two expressions are observationally equivalent if they
    produce the same output on all inputs.
    """
    
    def __init__(self, variables: List[str],
                 num_samples: int = 10,
                 verbose: bool = False):
        self.variables = variables
        self.num_samples = num_samples
        self.verbose = verbose
        
        self._samples = self._generate_samples()
        self._equivalence_classes: Dict[Tuple, List[Expr]] = {}
    
    def _generate_samples(self) -> List[Dict[str, int]]:
        """Generate sample inputs."""
        samples = []
        
        for _ in range(self.num_samples):
            sample = {v: random.randint(-10, 10) for v in self.variables}
            samples.append(sample)
        
        return samples
    
    def signature(self, expr: Expr) -> Tuple:
        """Compute signature (outputs on samples)."""
        outputs = []
        
        for sample in self._samples:
            try:
                var_map = {v: z3.IntVal(sample[v]) for v in self.variables}
                val = expr.to_z3(var_map)
                val = z3.simplify(val)
                
                if z3.is_int_value(val):
                    outputs.append(val.as_long())
                elif z3.is_true(val):
                    outputs.append(1)
                elif z3.is_false(val):
                    outputs.append(0)
                else:
                    outputs.append(None)
            except Exception:
                outputs.append(None)
        
        return tuple(outputs)
    
    def is_redundant(self, expr: Expr) -> bool:
        """Check if expression is redundant (equivalent to existing one)."""
        sig = self.signature(expr)
        
        if sig in self._equivalence_classes:
            existing = self._equivalence_classes[sig]
            # Keep smaller expression
            if any(e.size() <= expr.size() for e in existing):
                return True
        
        return False
    
    def add(self, expr: Expr) -> bool:
        """Add expression, return True if non-redundant."""
        sig = self.signature(expr)
        
        if sig not in self._equivalence_classes:
            self._equivalence_classes[sig] = [expr]
            return True
        
        existing = self._equivalence_classes[sig]
        if all(expr.size() < e.size() for e in existing):
            self._equivalence_classes[sig] = [expr]
            return True
        
        return False


class PrunedEnumerator:
    """
    Enumerator with observational equivalence pruning.
    """
    
    def __init__(self, grammar: Grammar,
                 variables: List[str],
                 max_size: int = 20,
                 verbose: bool = False):
        self.grammar = grammar
        self.variables = variables
        self.max_size = max_size
        self.verbose = verbose
        
        self._base = Enumerator(grammar, max_size=max_size)
        self._equiv = ObservationalEquivalence(variables, verbose=verbose)
        
        self.stats = {
            'total_generated': 0,
            'pruned': 0,
            'returned': 0,
        }
    
    def enumerate(self, max_count: int = 1000) -> Iterator[Expr]:
        """Enumerate non-redundant expressions."""
        for expr in self._base.enumerate(max_count * 10):  # Over-generate
            self.stats['total_generated'] += 1
            
            if not self._equiv.is_redundant(expr):
                self._equiv.add(expr)
                self.stats['returned'] += 1
                yield expr
                
                if self.stats['returned'] >= max_count:
                    return
            else:
                self.stats['pruned'] += 1


# =============================================================================
# DIVIDE AND CONQUER SYNTHESIS
# =============================================================================

class DivideAndConquerSyGuS:
    """
    Divide and conquer approach to synthesis.
    
    Splits the synthesis problem into subproblems.
    """
    
    def __init__(self, variables: List[str],
                 verbose: bool = False):
        self.variables = variables
        self.verbose = verbose
    
    def synthesize(self, init: z3.BoolRef,
                    trans: z3.BoolRef,
                    property: z3.BoolRef,
                    timeout_ms: int = 60000) -> SynthesisResult:
        """
        Synthesize by divide and conquer.
        
        Strategy:
        1. Synthesize linear invariant first
        2. If fails, try polynomial
        3. If fails, compose multiple invariants
        """
        # Try linear first
        result = self._try_linear(init, trans, property, timeout_ms // 3)
        if result.result == CEGISResult.SUCCESS:
            return result
        
        # Try polynomial
        result = self._try_polynomial(init, trans, property, timeout_ms // 3)
        if result.result == CEGISResult.SUCCESS:
            return result
        
        # Try composition
        result = self._try_composition(init, trans, property, timeout_ms // 3)
        return result
    
    def _try_linear(self, init: z3.BoolRef,
                     trans: z3.BoolRef,
                     property: z3.BoolRef,
                     timeout_ms: int) -> SynthesisResult:
        """Try linear grammar."""
        grammar = build_linear_grammar(self.variables)
        verifier = SyGuSVerifier(self.variables, init, trans, property,
                                   timeout_ms=timeout_ms // 10, verbose=self.verbose)
        synthesizer = CEGISSynthesizer(grammar, verifier,
                                         timeout_ms=timeout_ms, verbose=self.verbose)
        return synthesizer.synthesize()
    
    def _try_polynomial(self, init: z3.BoolRef,
                         trans: z3.BoolRef,
                         property: z3.BoolRef,
                         timeout_ms: int) -> SynthesisResult:
        """Try polynomial grammar."""
        grammar = build_polynomial_grammar(self.variables, max_degree=2)
        verifier = SyGuSVerifier(self.variables, init, trans, property,
                                   timeout_ms=timeout_ms // 10, verbose=self.verbose)
        synthesizer = CEGISSynthesizer(grammar, verifier,
                                         timeout_ms=timeout_ms, verbose=self.verbose)
        return synthesizer.synthesize()
    
    def _try_composition(self, init: z3.BoolRef,
                          trans: z3.BoolRef,
                          property: z3.BoolRef,
                          timeout_ms: int) -> SynthesisResult:
        """Try composing multiple invariants."""
        # Synthesize for each variable independently
        partial_invariants = []
        
        time_per_var = timeout_ms // len(self.variables)
        
        for var in self.variables:
            # Single-variable grammar
            grammar = build_linear_grammar([var])
            verifier = SyGuSVerifier([var], init, trans, property,
                                       timeout_ms=time_per_var // 10, verbose=self.verbose)
            synthesizer = CEGISSynthesizer(grammar, verifier,
                                             timeout_ms=time_per_var, verbose=self.verbose)
            result = synthesizer.synthesize()
            
            if result.result == CEGISResult.SUCCESS:
                partial_invariants.append(result.solution)
        
        if partial_invariants:
            # Compose with conjunction
            composed = partial_invariants[0]
            for inv in partial_invariants[1:]:
                composed = BoolBinOp("and", composed, inv)
            
            # Verify composed invariant
            verifier = SyGuSVerifier(self.variables, init, trans, property,
                                       timeout_ms=timeout_ms // 10, verbose=self.verbose)
            result, _ = verifier.verify(composed)
            
            if result == VerificationResult.VALID:
                return SynthesisResult(
                    result=CEGISResult.SUCCESS,
                    solution=composed,
                    message="Composed invariant"
                )
        
        return SynthesisResult(
            result=CEGISResult.FAILURE,
            message="Composition failed"
        )


# =============================================================================
# STOCHASTIC SYNTHESIS
# =============================================================================

class StochasticSyGuS:
    """
    Stochastic synthesis using random sampling and mutation.
    """
    
    def __init__(self, grammar: Grammar,
                 verifier: SyGuSVerifier,
                 population_size: int = 100,
                 mutation_rate: float = 0.2,
                 verbose: bool = False):
        self.grammar = grammar
        self.verifier = verifier
        self.population_size = population_size
        self.mutation_rate = mutation_rate
        self.verbose = verbose
        
        self._enumerator = Enumerator(grammar, EnumerationStrategy.RANDOM)
    
    def synthesize(self, max_generations: int = 100,
                    timeout_ms: int = 60000) -> SynthesisResult:
        """Run stochastic synthesis."""
        start_time = time.time()
        
        # Initialize population
        population = list(self._enumerator.enumerate(self.population_size))
        
        for generation in range(max_generations):
            # Check timeout
            elapsed = (time.time() - start_time) * 1000
            if elapsed > timeout_ms:
                return SynthesisResult(
                    result=CEGISResult.TIMEOUT,
                    iterations=generation,
                    message="Timeout"
                )
            
            # Evaluate population
            scored = []
            for expr in population:
                score = self._fitness(expr)
                if score == 3:  # Perfect score (all checks pass)
                    return SynthesisResult(
                        result=CEGISResult.SUCCESS,
                        solution=expr,
                        iterations=generation,
                        message="Found by stochastic search"
                    )
                scored.append((score, expr))
            
            # Select top performers
            scored.sort(key=lambda x: -x[0])
            survivors = [e for _, e in scored[:self.population_size // 2]]
            
            # Generate offspring
            offspring = []
            while len(offspring) < self.population_size // 2:
                parent = random.choice(survivors)
                child = self._mutate(parent)
                if child:
                    offspring.append(child)
            
            population = survivors + offspring
        
        return SynthesisResult(
            result=CEGISResult.FAILURE,
            iterations=max_generations,
            message="Max generations reached"
        )
    
    def _fitness(self, expr: Expr) -> int:
        """Compute fitness score."""
        var_map = {v: z3.Int(v) for v in self.verifier.variables}
        
        score = 0
        
        try:
            inv = expr.to_z3(var_map)
            
            # Check initiation
            solver = z3.Solver()
            solver.add(self.verifier.init)
            solver.add(z3.Not(inv))
            if solver.check() == z3.unsat:
                score += 1
            
            # Check safety
            solver = z3.Solver()
            solver.add(inv)
            solver.add(z3.Not(self.verifier.property))
            if solver.check() == z3.unsat:
                score += 1
            
            # Check consecution (partial)
            z3_vars_prime = {v: z3.Int(f"{v}_prime") for v in self.verifier.variables}
            inv_prime = z3.substitute(
                inv,
                [(var_map[v], z3_vars_prime[v]) for v in self.verifier.variables]
            )
            
            solver = z3.Solver()
            solver.add(inv)
            solver.add(self.verifier.trans)
            solver.add(z3.Not(inv_prime))
            if solver.check() == z3.unsat:
                score += 1
        except Exception:
            pass
        
        return score
    
    def _mutate(self, expr: Expr) -> Optional[Expr]:
        """Mutate expression."""
        if random.random() > self.mutation_rate:
            return expr
        
        # Simple mutation: replace with random expression
        return next(self._enumerator.enumerate(1), None)


# =============================================================================
# CONSTRAINT-BASED SYNTHESIS
# =============================================================================

class ConstraintBasedSynthesis:
    """
    Synthesis by constraint solving.
    
    Encodes the synthesis problem as a constraint solving problem.
    """
    
    def __init__(self, variables: List[str],
                 max_coefficients: int = 5,
                 coefficient_bound: int = 10,
                 verbose: bool = False):
        self.variables = variables
        self.max_coefficients = max_coefficients
        self.coefficient_bound = coefficient_bound
        self.verbose = verbose
        
        self._z3_vars = {v: z3.Int(v) for v in variables}
    
    def synthesize_linear(self, init: z3.BoolRef,
                           trans: z3.BoolRef,
                           property: z3.BoolRef,
                           timeout_ms: int = 30000) -> Optional[Expr]:
        """
        Synthesize linear invariant using constraint solving.
        
        Finds coefficients a_i such that:
            Σ a_i * x_i + c >= 0
        is an invariant.
        """
        n = len(self.variables)
        
        solver = z3.Solver()
        solver.set("timeout", timeout_ms)
        
        # Coefficient variables
        coeffs = [z3.Int(f"coef_{i}") for i in range(n)]
        const = z3.Int("const")
        
        # Bound coefficients
        for c in coeffs:
            solver.add(c >= -self.coefficient_bound)
            solver.add(c <= self.coefficient_bound)
        solver.add(const >= -self.coefficient_bound * 10)
        solver.add(const <= self.coefficient_bound * 10)
        
        # Non-trivial
        solver.add(z3.Or([c != 0 for c in coeffs]))
        
        # Build invariant template
        z3_vars_list = list(self._z3_vars.values())
        inv_template = sum(coeffs[i] * z3_vars_list[i] for i in range(n)) + const
        inv = inv_template >= 0
        
        # Primed variables
        z3_vars_prime = [z3.Int(f"{v}_prime") for v in self.variables]
        inv_prime = sum(coeffs[i] * z3_vars_prime[i] for i in range(n)) + const >= 0
        
        # Quantify over program variables
        all_prog_vars = z3_vars_list + z3_vars_prime
        
        # Initiation: ∀x. Init(x) → I(x)
        initiation = z3.ForAll(z3_vars_list, z3.Implies(init, inv))
        solver.add(initiation)
        
        # Consecution: ∀x,x'. I(x) ∧ T(x,x') → I(x')
        consecution = z3.ForAll(all_prog_vars, z3.Implies(z3.And(inv, trans), inv_prime))
        solver.add(consecution)
        
        # Safety: ∀x. I(x) → P(x)
        safety = z3.ForAll(z3_vars_list, z3.Implies(inv, property))
        solver.add(safety)
        
        if solver.check() == z3.sat:
            model = solver.model()
            
            # Extract expression
            terms = []
            for i, v in enumerate(self.variables):
                coef = model.eval(coeffs[i], model_completion=True).as_long()
                if coef != 0:
                    terms.append(BinOp("*", IntConst(coef), Var(v)))
            
            const_val = model.eval(const, model_completion=True).as_long()
            if const_val != 0:
                terms.append(IntConst(const_val))
            
            if terms:
                result = terms[0]
                for t in terms[1:]:
                    result = BinOp("+", result, t)
                return BoolExpr(">=", result, IntConst(0))
        
        return None


# =============================================================================
# SYGUS METRICS AND VISUALIZATION
# =============================================================================

class SyGuSMetrics:
    """
    Metrics for SyGuS synthesis.
    """
    
    @staticmethod
    def expression_complexity(expr: Expr) -> Dict[str, int]:
        """Compute complexity metrics for expression."""
        metrics = {
            'size': expr.size(),
            'depth': 0,
            'num_operators': 0,
            'num_variables': 0,
            'num_constants': 0,
        }
        
        def traverse(e: Expr, depth: int):
            metrics['depth'] = max(metrics['depth'], depth)
            
            if isinstance(e, BinOp):
                metrics['num_operators'] += 1
                traverse(e.left, depth + 1)
                traverse(e.right, depth + 1)
            elif isinstance(e, UnaryOp):
                metrics['num_operators'] += 1
                traverse(e.arg, depth + 1)
            elif isinstance(e, Var):
                metrics['num_variables'] += 1
            elif isinstance(e, (IntConst, RealConst)):
                metrics['num_constants'] += 1
        
        traverse(expr, 0)
        return metrics
    
    @staticmethod
    def synthesis_efficiency(result: SynthesisResult) -> Dict[str, float]:
        """Compute synthesis efficiency metrics."""
        return {
            'candidates_per_cex': (result.candidates_tried / 
                                    max(1, result.counterexamples)),
            'success_rate': 1.0 if result.result == CEGISResult.SUCCESS else 0.0,
            'iterations_used': result.iterations,
        }


class SyGuSVisualization:
    """
    Visualization utilities for SyGuS.
    """
    
    @staticmethod
    def expression_to_tree(expr: Expr, indent: int = 0) -> str:
        """Convert expression to tree string."""
        prefix = "  " * indent
        
        if isinstance(expr, IntConst):
            return f"{prefix}Int({expr.value})"
        elif isinstance(expr, RealConst):
            return f"{prefix}Real({expr.value})"
        elif isinstance(expr, Var):
            return f"{prefix}Var({expr.name})"
        elif isinstance(expr, BinOp):
            result = f"{prefix}BinOp({expr.op})\n"
            result += SyGuSVisualization.expression_to_tree(expr.left, indent + 1) + "\n"
            result += SyGuSVisualization.expression_to_tree(expr.right, indent + 1)
            return result
        elif isinstance(expr, UnaryOp):
            result = f"{prefix}UnaryOp({expr.op})\n"
            result += SyGuSVisualization.expression_to_tree(expr.arg, indent + 1)
            return result
        else:
            return f"{prefix}Expr"
    
    @staticmethod
    def grammar_to_string(grammar: Grammar) -> str:
        """Convert grammar to readable string."""
        lines = [f"Grammar: {grammar.name}"]
        lines.append(f"  Start: {grammar.get_start()}")
        lines.append("  Productions:")
        for prod in grammar.get_all_productions():
            lines.append(f"    {prod}")
        return "\n".join(lines)


# =============================================================================
# UNIFIED SYGUS PIPELINE
# =============================================================================

class UnifiedSyGuSPipeline:
    """
    Unified SyGuS pipeline combining multiple techniques.
    """
    
    def __init__(self, variables: List[str],
                 verbose: bool = False):
        self.variables = variables
        self.verbose = verbose
        
        self.stats = {
            'technique_used': None,
            'total_time_ms': 0,
            'candidates_tried': 0,
        }
    
    def synthesize(self, init: z3.BoolRef,
                    trans: z3.BoolRef,
                    property: z3.BoolRef,
                    timeout_ms: int = 120000) -> SynthesisResult:
        """
        Run unified synthesis pipeline.
        
        Tries multiple techniques in order:
        1. Constraint-based (fast for linear)
        2. CEGIS with linear grammar
        3. CEGIS with polynomial grammar
        4. Divide and conquer
        5. Stochastic
        """
        start_time = time.time()
        time_remaining = timeout_ms
        
        # 1. Constraint-based linear
        if self.verbose:
            print("  Trying constraint-based linear synthesis...")
        
        constraint_synth = ConstraintBasedSynthesis(self.variables, verbose=self.verbose)
        result = constraint_synth.synthesize_linear(init, trans, property, time_remaining // 5)
        
        if result:
            self.stats['technique_used'] = 'constraint_linear'
            self.stats['total_time_ms'] = (time.time() - start_time) * 1000
            return SynthesisResult(
                result=CEGISResult.SUCCESS,
                solution=result,
                message="Found by constraint-based linear synthesis"
            )
        
        time_remaining -= int((time.time() - start_time) * 1000)
        
        # 2. CEGIS linear
        if time_remaining > 0:
            if self.verbose:
                print("  Trying CEGIS with linear grammar...")
            
            grammar = build_linear_grammar(self.variables)
            verifier = SyGuSVerifier(self.variables, init, trans, property,
                                       timeout_ms=time_remaining // 20, verbose=self.verbose)
            synthesizer = CEGISSynthesizer(grammar, verifier,
                                             timeout_ms=time_remaining // 5, verbose=self.verbose)
            result = synthesizer.synthesize()
            
            if result.result == CEGISResult.SUCCESS:
                self.stats['technique_used'] = 'cegis_linear'
                self.stats['total_time_ms'] = (time.time() - start_time) * 1000
                return result
            
            self.stats['candidates_tried'] += result.candidates_tried
        
        time_remaining -= int((time.time() - start_time) * 1000)
        
        # 3. CEGIS polynomial
        if time_remaining > 0:
            if self.verbose:
                print("  Trying CEGIS with polynomial grammar...")
            
            grammar = build_polynomial_grammar(self.variables, max_degree=2)
            verifier = SyGuSVerifier(self.variables, init, trans, property,
                                       timeout_ms=time_remaining // 20, verbose=self.verbose)
            synthesizer = CEGISSynthesizer(grammar, verifier,
                                             timeout_ms=time_remaining // 3, verbose=self.verbose)
            result = synthesizer.synthesize()
            
            if result.result == CEGISResult.SUCCESS:
                self.stats['technique_used'] = 'cegis_polynomial'
                self.stats['total_time_ms'] = (time.time() - start_time) * 1000
                return result
            
            self.stats['candidates_tried'] += result.candidates_tried
        
        time_remaining -= int((time.time() - start_time) * 1000)
        
        # 4. Divide and conquer
        if time_remaining > 0:
            if self.verbose:
                print("  Trying divide and conquer...")
            
            dac = DivideAndConquerSyGuS(self.variables, verbose=self.verbose)
            result = dac.synthesize(init, trans, property, time_remaining // 2)
            
            if result.result == CEGISResult.SUCCESS:
                self.stats['technique_used'] = 'divide_and_conquer'
                self.stats['total_time_ms'] = (time.time() - start_time) * 1000
                return result
        
        time_remaining -= int((time.time() - start_time) * 1000)
        
        # 5. Stochastic
        if time_remaining > 0:
            if self.verbose:
                print("  Trying stochastic synthesis...")
            
            grammar = build_polynomial_grammar(self.variables, max_degree=2)
            verifier = SyGuSVerifier(self.variables, init, trans, property,
                                       timeout_ms=time_remaining // 10, verbose=self.verbose)
            stochastic = StochasticSyGuS(grammar, verifier, verbose=self.verbose)
            result = stochastic.synthesize(max_generations=50, timeout_ms=time_remaining)
            
            if result.result == CEGISResult.SUCCESS:
                self.stats['technique_used'] = 'stochastic'
                self.stats['total_time_ms'] = (time.time() - start_time) * 1000
                return result
        
        self.stats['total_time_ms'] = (time.time() - start_time) * 1000
        
        return SynthesisResult(
            result=CEGISResult.FAILURE,
            candidates_tried=self.stats['candidates_tried'],
            message="All techniques failed"
        )
