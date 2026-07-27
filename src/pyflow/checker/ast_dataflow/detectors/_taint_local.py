"""Assembly and state initialization for local AST taint dataflow."""

from __future__ import annotations

import ast
from typing import Dict, List, Optional, Set, Tuple

from ._taint_control import _ControlFlowMixin
from ._taint_expressions import _ExpressionTaintMixin
from ._taint_state import _TaintStateMixin
from ._taint_visitors import _StatementVisitorMixin


class _LocalTaintAnalyzer(
    _StatementVisitorMixin,
    _ExpressionTaintMixin,
    _TaintStateMixin,
    _ControlFlowMixin,
    ast.NodeVisitor,
):
    """Flow-sensitive intra-procedural taint tracking."""

    def __init__(
        self,
        *,
        sources: Set[str],
        sinks: Set[str],
        sanitizers: Set[str],
        sink_positions: Dict[str, Set[int]],
        entry_tainted_params: Set[str],
        entry_tainted_param_keys: Dict[str, Set[str]],
        callee_returns_tainted: Dict[str, bool],
        callee_returns_unconditional: Dict[str, bool],
        callee_has_source: Dict[str, bool],
        callee_param_taint_outputs: Dict[str, Set[str]],
        callee_param_key_writes: Dict[str, Dict[str, Set[str]]],
        callee_param_key_taint_writes: Dict[str, Dict[str, Set[str]]],
        callee_return_param_deps: Dict[str, Set[str]],
        callee_param_names: Dict[str, List[str]],
        callee_vararg_names: Dict[str, Optional[str]],
        callee_kwarg_names: Dict[str, Optional[str]],
        callee_returns_value: Dict[str, bool],
        known_callees: Set[str],
    ):
        self.sources = sources
        self.sinks = sinks
        self.sanitizers = sanitizers
        self.sink_positions = sink_positions
        self.entry_tainted_params = entry_tainted_params
        self.entry_tainted_param_keys = entry_tainted_param_keys
        self.callee_returns_tainted = callee_returns_tainted
        self.callee_returns_unconditional = callee_returns_unconditional
        self.callee_has_source = callee_has_source
        self.callee_param_taint_outputs = callee_param_taint_outputs
        self.callee_param_key_writes = callee_param_key_writes
        self.callee_param_key_taint_writes = callee_param_key_taint_writes
        self.callee_return_param_deps = callee_return_param_deps
        self.callee_param_names = callee_param_names
        self.callee_vararg_names = callee_vararg_names
        self.callee_kwarg_names = callee_kwarg_names
        self.callee_returns_value = callee_returns_value
        self.known_callees = known_callees

        # Taint state
        self.tainted: Set[str] = set()
        self.tainted_containers: Set[str] = set()
        self.tainted_container_keys: Dict[str, Set[str]] = {}
        # Dict-key taint is distinct from value taint in
        # ``tainted_container_keys``.
        self.tainted_dict_keys: Dict[str, Set[str]] = {}
        # Special-case modelling for `array.array('u', taint_src)` benchmarks.
        self.alternating_taint_arrays: Set[str] = set()
        self.int_parity: Dict[str, int] = {}
        self.int_values: Dict[str, int] = {}
        self.const_str_values: Dict[str, Set[str]] = {}
        self.dict_key_order: Dict[str, List[str]] = {}
        self.list_lengths: Dict[str, int] = {}
        # Precise nested container modelling (constant key/index paths).
        self.tainted_paths: Set[Tuple[str, ...]] = set()
        self.paths_by_root: Dict[str, Set[Tuple[str, ...]]] = {}
        # Try/except taint propagation.
        self._try_exc_taint_stack: List[bool] = []
        self.tainted_attrs: Dict[str, Set[str]] = {}
        self.alias_parent: Dict[str, str] = {}
        self.alias_members: Dict[str, Set[str]] = {}
        self.has_source = False
        self.returns_tainted = False
        self.params_to_sink: Set[str] = set()
        self.param_taint_outputs: Set[str] = set()
        self.param_key_writes: Dict[str, Set[str]] = {}
        self.param_key_taint_writes: Dict[str, Set[str]] = {}
        self.sinks_found: Set[str] = set()
        self.tainted_sinks: Set[str] = set()
        self.tainted_sink_lines: Dict[str, Set[int]] = {}
        self.tainted_sink = False
        self.current_params: Set[str] = set()
        self.call_param_taints: Dict[str, Set[str]] = {}
        self.call_param_key_taints: Dict[str, Dict[str, Set[str]]] = {}
        self.function_depth = 0
