"""
Intraprocedural Taint Analysis for Within-Function Dataflow.

This module provides taint tracking within a single function to detect
bugs that occur through local variable dataflow, such as:
- request.POST.get('password') → local → print(local) (CLEARTEXT_LOGGING)
- user_input → local → sql_query.format(local) (SQL_INJECTION)

Architecture:
1. Analyze function bytecode for dataflow within locals
2. Track taint labels for local variables and stack values
3. Detect source calls that taint locals
4. Detect sink calls that consume tainted locals
5. Use lattice-based taint propagation (τ, κ, σ)

This complements the interprocedural analysis in interprocedural_bugs.py:
- Interprocedural: tracks param → return, call chains
- Intraprocedural: tracks locals → locals, sources → sinks within one function

Usage:
    from a3_python.semantics.intraprocedural_taint import IntraproceduralTaintAnalyzer
    
    analyzer = IntraproceduralTaintAnalyzer(code_object)
    bugs = analyzer.find_bugs()
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple, Any
from pathlib import Path
import dis
import types

from ..z3model.taint_lattice import (
    SourceType, SinkType, SanitizerType,
    TaintLabel, label_join, label_join_many,
    tau_zero, kappa_full, sigma_zero,
)
from ..contracts.security_lattice import (
    is_taint_source, is_security_sink, is_sanitizer,
    get_source_contract, get_sink_contract, get_sanitizer_contract,
    apply_source_taint, check_sink_taint, apply_sanitizer,
)
from ..unsafe.registry import UNSAFE_PREDICATES


# ============================================================================
# MODULE-LEVEL IMPORT EXTRACTION
# ============================================================================

def extract_module_imports(module_code: types.CodeType) -> Dict[str, str]:
    """
    Extract import aliases from module-level bytecode.
    
    Patterns extracted:
    - import X as Y: Y → X
    - from X import Y as Z: Z → X.Y
    - from X import Y: Y → X.Y
    
    Args:
        module_code: Compiled module code object
    
    Returns:
        Dictionary mapping alias names to full module paths
    
    Example:
        >>> code = compile("import xml.etree.ElementTree as ET\\ndef f(): pass", '<test>', 'exec')
        >>> extract_module_imports(code)
        {'ET': 'xml.etree.ElementTree'}
    """
    import_aliases: Dict[str, str] = {}
    instructions = list(dis.get_instructions(module_code))
    
    i = 0
    while i < len(instructions):
        instr = instructions[i]
        
        # Pattern: IMPORT_NAME is preceded by LOAD_CONST
        # - If LOAD_CONST arg is a tuple (e.g., ('fromstring',)), it's "from X import Y"
        # - If LOAD_CONST arg is None, it's "import X.Y.Z as A"
        if instr.opname == 'IMPORT_NAME':
            module_name = instr.argval  # The real module name
            
            # Check the preceding LOAD_CONST to distinguish import types
            is_from_import = False
            if i >= 2:
                # Look back for LOAD_CONST
                for j in range(i - 1, max(0, i - 3), -1):
                    if instructions[j].opname == 'LOAD_CONST':
                        const_val = instructions[j].argval
                        # If const is a tuple, it's "from X import ..."
                        if isinstance(const_val, tuple):
                            is_from_import = True
                        break
            
            if is_from_import:
                # Pattern: from X import Y (as Z)
                # IMPORT_NAME X
                # IMPORT_FROM Y
                # STORE_NAME Z (or Y if no alias)
                
                # Look ahead for IMPORT_FROM + STORE_NAME
                if i + 1 < len(instructions) and instructions[i + 1].opname == 'IMPORT_FROM':
                    attr_name = instructions[i + 1].argval
                    
                    # Look ahead for STORE_NAME
                    if i + 2 < len(instructions) and instructions[i + 2].opname in ('STORE_NAME', 'STORE_GLOBAL'):
                        alias_name = instructions[i + 2].argval
                        
                        # Record full path
                        full_path = f"{module_name}.{attr_name}"
                        import_aliases[alias_name] = full_path
            else:
                # Pattern: import X.Y.Z (as A)
                # IMPORT_NAME X.Y.Z
                # [IMPORT_FROM Y
                #  SWAP
                #  POP_TOP
                #  IMPORT_FROM Z]
                # STORE_NAME A
                
                # Look ahead to find the STORE_NAME (skip IMPORT_FROM sequences)
                j = i + 1
                while j < len(instructions) and j < i + 20:
                    next_instr = instructions[j]
                    
                    if next_instr.opname in ('STORE_NAME', 'STORE_GLOBAL'):
                        alias_name = next_instr.argval
                        
                        # ITERATION 535: For hierarchical imports like "import xml.sax",
                        # Python stores as "xml" but imports "xml.sax".
                        # The bytecode will naturally build "xml.sax.parseString" via:
                        #   LOAD_GLOBAL xml + LOAD_ATTR sax + LOAD_ATTR parseString
                        # So we should NOT create an alias unless it's a real alias (as X).
                        # 
                        # Only record if: alias != module AND alias != first component of module
                        first_component = module_name.split('.')[0]
                        if alias_name != module_name and alias_name != first_component:
                            import_aliases[alias_name] = module_name
                        break
                    
                    j += 1
        
        i += 1
    
    return import_aliases


# ============================================================================
# INTRAPROCEDURAL TAINT STATE
# ============================================================================

@dataclass
class LocalTaintState:
    """
    Taint state for local variables at a bytecode offset.
    
    Tracks taint labels for:
    - Local variables (locals)
    - Operand stack (stack simulation)
    - Cells/free vars (for closures, if needed later)
    """
    
    # Map from local variable index → taint label
    locals: Dict[int, TaintLabel] = field(default_factory=dict)
    
    # Operand stack (list of taint labels)
    stack: List[TaintLabel] = field(default_factory=list)
    
    # Map from name (str) → taint label (for LOAD_NAME/STORE_NAME)
    names: Dict[str, TaintLabel] = field(default_factory=dict)
    
    def copy(self) -> LocalTaintState:
        """Deep copy for branching."""
        return LocalTaintState(
            locals=self.locals.copy(),
            stack=self.stack.copy(),
            names=self.names.copy(),
        )
    
    def get_local(self, idx: int) -> TaintLabel:
        """Get taint label for local variable."""
        return self.locals.get(idx, TaintLabel.clean())
    
    def set_local(self, idx: int, label: TaintLabel):
        """Set taint label for local variable."""
        self.locals[idx] = label
    
    def get_name(self, name: str) -> TaintLabel:
        """Get taint label for named variable."""
        return self.names.get(name, TaintLabel.clean())
    
    def set_name(self, name: str, label: TaintLabel):
        """Set taint label for named variable."""
        self.names[name] = label
    
    def push(self, label: TaintLabel):
        """Push taint label onto operand stack."""
        self.stack.append(label)
    
    def pop(self) -> TaintLabel:
        """Pop taint label from operand stack."""
        if not self.stack:
            return TaintLabel.clean()
        return self.stack.pop()
    
    def peek(self) -> TaintLabel:
        """Peek at top of operand stack."""
        if not self.stack:
            return TaintLabel.clean()
        return self.stack[-1]


@dataclass
class IntraproceduralBug:
    """
    A bug found through intraprocedural analysis.
    
    Represents a taint flow from source to sink within a single function.
    """
    bug_type: str  # e.g., 'CLEARTEXT_LOGGING', 'SQL_INJECTION'
    function_name: str
    file_path: str
    line_number: int
    
    # Taint flow
    source_line: Optional[int]  # Where the taint came from
    source_description: str  # e.g., "request.POST.get('password')"
    
    sink_line: int  # Where the sink is
    sink_description: str  # e.g., "print(sql_query)"
    
    # Taint label at sink
    taint_label: TaintLabel
    
    # Reason
    reason: str
    
    # Confidence (1.0 = certain, < 1.0 = may be FP)
    confidence: float = 1.0
    
    # Whether source was inferred from name/type
    inferred_source: bool = False
    
    def __str__(self) -> str:
        loc = f"{self.file_path}:{self.line_number}"
        source_line_info = f" (line {self.source_line})" if self.source_line else ""
        confidence_str = f" [confidence: {self.confidence:.2f}]" if self.confidence < 1.0 else ""
        inferred_str = " [inferred]" if self.inferred_source else ""
        
        return (f"{self.bug_type}{confidence_str} at {loc} in {self.function_name}\n"
                f"  Source: {self.source_description}{source_line_info}{inferred_str}\n"
                f"  Sink: {self.sink_description} (line {self.sink_line})\n"
                f"  Reason: {self.reason}")


# ============================================================================
# INTRAPROCEDURAL TAINT ANALYZER
# ============================================================================

class IntraproceduralTaintAnalyzer:
    """
    Analyzes a single function for intraprocedural taint bugs.
    
    Uses abstract interpretation over the bytecode to track taint labels
    through local variables and the operand stack.
    """
    
    def __init__(self, code_obj: types.CodeType, 
                 function_name: str = "<unknown>",
                 file_path: str = "<unknown>",
                 max_iterations: int = 10000,
                 import_aliases: Optional[Dict[str, str]] = None):
        self.code_obj = code_obj
        self.function_name = function_name
        self.file_path = file_path
        self.max_iterations = max_iterations
        
        # Map from bytecode offset → LocalTaintState
        self.states: Dict[int, LocalTaintState] = {}
        
        # Worklist for fixpoint iteration
        self.worklist: Set[int] = set()
        
        # Track iteration count per offset to detect oscillation
        self.iteration_counts: Dict[int, int] = {}
        
        # Total iteration counter
        self.total_iterations = 0
        
        # Bugs found
        self.bugs: List[IntraproceduralBug] = []
        
        # Track source locations (offset → description)
        self.sources: Dict[int, str] = {}
        
        # Bytecode instructions
        self.instructions = list(dis.get_instructions(code_obj))
        
        # ITERATION 517: Track import aliases (name → real_module_name)
        # Maps aliased names to their real module paths
        # Example: "ET" → "xml.etree.ElementTree"
        # Can be provided externally (from module-level analysis) or extracted from function bytecode
        self.import_aliases: Dict[str, str] = import_aliases or {}
        if not import_aliases:
            self._extract_import_aliases()
    
    def _extract_import_aliases(self):
        """
        Extract import aliases from bytecode patterns.
        
        Pattern 1: import X as Y
            LOAD_CONST 0
            LOAD_CONST None
            IMPORT_NAME X
            STORE_FAST/STORE_NAME Y
        
        Pattern 2: from X import Y as Z
            LOAD_CONST 0
            LOAD_CONST ('Y',)
            IMPORT_NAME X
            IMPORT_FROM Y
            STORE_FAST/STORE_NAME Z
        
        This builds a mapping: alias → real_module_name
        Example: "ET" → "xml.etree.ElementTree"
        """
        i = 0
        while i < len(self.instructions):
            instr = self.instructions[i]
            
            # Pattern 1: import X as Y
            if instr.opname == 'IMPORT_NAME':
                module_name = instr.argval  # The real module name
                
                # Check if next instruction is STORE_FAST/STORE_NAME
                if i + 1 < len(self.instructions):
                    next_instr = self.instructions[i + 1]
                    if next_instr.opname in ('STORE_FAST', 'STORE_NAME', 'STORE_GLOBAL'):
                        alias_name = next_instr.argval
                        
                        # Only record if alias differs from module name
                        # (e.g., "import xml.etree.ElementTree as ET")
                        if alias_name != module_name:
                            self.import_aliases[alias_name] = module_name
            
            # Pattern 2: from X import Y (optionally as Z)
            elif instr.opname == 'IMPORT_FROM':
                attr_name = instr.argval  # The imported attribute (e.g., "fromstring")
                
                # Look back to find the IMPORT_NAME for the module
                module_name = None
                for j in range(i - 1, max(0, i - 5), -1):
                    if self.instructions[j].opname == 'IMPORT_NAME':
                        module_name = self.instructions[j].argval
                        break
                
                if module_name:
                    # Check if next instruction is STORE_FAST/STORE_NAME
                    if i + 1 < len(self.instructions):
                        next_instr = self.instructions[i + 1]
                        if next_instr.opname in ('STORE_FAST', 'STORE_NAME', 'STORE_GLOBAL'):
                            alias_name = next_instr.argval
                            
                            # Record the full path: alias → module.attr
                            full_path = f"{module_name}.{attr_name}"
                            
                            # Only record if alias differs from attr_name
                            # (e.g., "from xml.etree.ElementTree import fromstring as parse_xml")
                            if alias_name != attr_name:
                                self.import_aliases[alias_name] = full_path
                            # Also record attr_name → full_path for "from X import Y" (no alias)
                            # This helps resolve "fromstring" → "xml.etree.ElementTree.fromstring"
                            self.import_aliases[attr_name] = full_path
            
            i += 1
    
    def analyze(self) -> List[IntraproceduralBug]:
        """
        Run intraprocedural taint analysis on the function.
        
        Returns list of bugs found.
        """
        # Initialize with entry state
        entry_state = LocalTaintState()
        
        # ITERATION 468: Mark function parameters as tainted if they have suspicious names
        # This allows us to detect command injection even within a single function
        # when the parameter name suggests it comes from user input
        # ITERATION 613: Remove 'request' from patterns - only request.GET/POST etc. should be
        # tainted, not the entire request object. This prevents FPs with render(request, ...).
        param_patterns = [
            'command', 'cmd', 'input', 'query', 'sql', 'user', 'data',
            'param', 'arg', 'domain', 'url', 'path', 'filename'
            # Note: 'request' removed - use source contracts for request.GET/POST.get instead
        ]
        
        for param_idx, param_name in enumerate(self.code_obj.co_varnames[:self.code_obj.co_argcount]):
            param_lower = param_name.lower()
            if any(pattern in param_lower for pattern in param_patterns):
                # Mark this parameter as tainted from user input
                taint_label = TaintLabel.from_untrusted_source(
                    SourceType.USER_INPUT,
                    f"parameter '{param_name}'"
                )
                entry_state.set_local(param_idx, taint_label)
                # Record as a source
                self.sources[0] = f"parameter '{param_name}'"
        
        self.states[0] = entry_state
        self.worklist.add(0)
        
        # Fixpoint iteration with iteration limit
        while self.worklist and self.total_iterations < self.max_iterations:
            offset = self.worklist.pop()
            
            # Track iterations per offset to detect oscillation
            self.iteration_counts[offset] = self.iteration_counts.get(offset, 0) + 1
            
            # Apply widening if offset has been visited too many times
            # This prevents infinite loops in cyclic control flow
            if self.iteration_counts[offset] > 50:
                # Widening: stop re-analyzing this offset
                continue
            
            self.total_iterations += 1
            self._analyze_instruction(offset)
        
        # Warn if we hit the iteration limit
        if self.total_iterations >= self.max_iterations:
            # Don't fail, just return what we found
            # The bugs list may be incomplete but is still valid
            pass
        
        return self.bugs
    
    def _analyze_instruction(self, offset: int):
        """Analyze a single bytecode instruction."""
        # Find instruction
        instr = None
        for i in self.instructions:
            if i.offset == offset:
                instr = i
                break
        
        if instr is None:
            return
        
        # Get current state
        if offset not in self.states:
            return
        
        state = self.states[offset].copy()
        
        # Process instruction based on opcode
        opname = instr.opname
        
        # === LOAD instructions ===
        if opname == 'LOAD_FAST' or opname == 'LOAD_FAST_BORROW':
            label = state.get_local(instr.arg)
            state.push(label)
        
        elif opname == 'LOAD_FAST_BORROW_LOAD_FAST_BORROW':
            # Python 3.14 optimization: loads two locals at once
            # arg encodes two indices as nibbles: (idx1 << 4) | idx2
            idx1 = (instr.arg >> 4) & 0xF
            idx2 = instr.arg & 0xF
            label1 = state.get_local(idx1)
            label2 = state.get_local(idx2)
            state.push(label1)
            state.push(label2)
        
        elif opname == 'LOAD_NAME' or opname == 'LOAD_GLOBAL':
            label = state.get_name(instr.argval)
            state.push(label)
        
        elif opname == 'LOAD_CONST':
            # Constants are clean
            state.push(TaintLabel.clean())
        
        # === LOAD_ATTR (attribute access) ===
        elif opname == 'LOAD_ATTR':
            # Pop the object being accessed
            if state.stack:
                obj_label = state.pop()
            else:
                obj_label = TaintLabel.clean()
            
            # Check if this is a known tainted attribute
            # e.g., request.POST, request.GET, os.environ
            attr_name = instr.argval
            
            # Try to identify what we're accessing (look back for object name)
            obj_name = self._identify_attr_object(offset)
            full_name = f"{obj_name}.{attr_name}" if obj_name else attr_name
            
            # Check if this attribute access is a source
            if is_taint_source(full_name):
                contract = get_source_contract(full_name)
                if contract:
                    # This attribute returns tainted data
                    result_label = TaintLabel.from_untrusted_source(
                        contract.source_type, full_name
                    )
                    state.push(result_label)
                else:
                    # Attribute access propagates taint from object
                    state.push(obj_label)
            else:
                # Attribute access propagates taint from object
                state.push(obj_label)
        
        # === STORE instructions ===
        elif opname == 'STORE_FAST':
            label = state.pop()
            
            # ITERATION 464: Infer sensitivity from variable name
            # If storing to a variable name that suggests sensitive data (e.g., "passwd", "api_key"),
            # add sensitivity to the label
            var_name = self.code_obj.co_varnames[instr.arg] if instr.arg < len(self.code_obj.co_varnames) else None
            if var_name and label.has_any_taint():
                from ..semantics.security_tracker_lattice import infer_sensitivity_from_name
                inferred_source = infer_sensitivity_from_name(var_name)
                if inferred_source is not None:
                    # Add sensitivity to the label
                    old_sigma = label.sigma
                    label = label.with_sensitivity(inferred_source)
                    
                    import os
                    if os.environ.get('DEBUG_SENSITIVITY') == '1':
                        print(f"[SENSITIVITY] STORE_FAST at offset {offset}")
                        print(f"  Variable: {var_name}")
                        print(f"  Inferred source: {inferred_source}")
                        print(f"  Old sigma: {bin(old_sigma)} ({old_sigma})")
                        print(f"  New sigma: {bin(label.sigma)} ({label.sigma})")
            
            state.set_local(instr.arg, label)
        
        elif opname == 'STORE_NAME' or opname == 'STORE_GLOBAL':
            label = state.pop()
            state.set_name(instr.argval, label)
        
        # === CALL instructions ===
        elif 'CALL' in opname:
            self._handle_call(instr, state, offset)
        
        # === Binary operations ===
        elif opname.startswith('BINARY_') or opname == 'INPLACE_ADD' or opname == 'BINARY_OP':
            # Pop operands, join taint, push result
            if len(state.stack) >= 2:
                right = state.pop()
                left = state.pop()
                result = label_join(left, right)
                
                # ITERATION 534: Check if subscript is a source operation (e.g., request.GET['file'])
                # Bytecode pattern: LOAD_FAST/LOAD_GLOBAL/LOAD_ATTR ... LOAD_CONST key, BINARY_SUBSCR
                # Treat subscript as call to __getitem__ method
                is_subscript = (opname == 'BINARY_SUBSCR' or 
                               (opname == 'BINARY_OP' and instr.arg == 26))
                if is_subscript:
                    # Try to identify the container object name (e.g., "request.GET")
                    container_name = self._identify_subscript_container(offset)
                    if container_name:
                        # Check if container.__getitem__ is a source
                        getitem_name = f"{container_name}.__getitem__"
                        if is_taint_source(getitem_name):
                            contract = get_source_contract(getitem_name)
                            if contract:
                                # This subscript returns tainted data
                                result = TaintLabel.from_untrusted_source(
                                    contract.source_type, getitem_name
                                )
                                # Check for sensitivity patterns in the key
                                key_str = self._extract_constant_string(instr, offset, is_right_operand=True)
                                if key_str and contract.sensitive_arg_patterns:
                                    key_lower = key_str.lower()
                                    if any(pattern in key_lower for pattern in contract.sensitive_arg_patterns):
                                        from a3_python.z3model.taint_lattice import SourceType
                                        result = result.with_sensitivity(SourceType.PASSWORD)
                
                # ITERATION 476: Sensitivity inference for subscript operations
                # Handle both BINARY_SUBSCR (older Python) and BINARY_OP 26 (Python 3.14+)
                # If this is a subscript operation with a string key matching sensitive patterns,
                # add PASSWORD sensitivity to the result
                if is_subscript and result.has_any_taint():
                    # Try to extract the subscript key (right operand)
                    key_str = self._extract_constant_string(instr, offset, is_right_operand=True)
                    
                    import os
                    DEBUG_SENSITIVITY = os.environ.get('DEBUG_SENSITIVITY') == '1'
                    if DEBUG_SENSITIVITY:
                        print(f"[SENSITIVITY] BINARY_SUBSCR at offset {offset}")
                        print(f"  key_str={key_str}")
                        print(f"  result.tau={bin(result.tau)}, result.sigma={bin(result.sigma)}")
                    
                    if key_str:
                        # Check if key matches sensitive patterns
                        from a3_python.frontend.entry_points import SENSITIVE_PARAM_PATTERNS
                        key_lower = key_str.lower()
                        if any(pattern in key_lower for pattern in SENSITIVE_PARAM_PATTERNS):
                            # Add PASSWORD sensitivity
                            from a3_python.z3model.taint_lattice import SourceType
                            result = result.with_sensitivity(SourceType.PASSWORD)
                            if DEBUG_SENSITIVITY:
                                print(f"  MATCHED! Adding PASSWORD sensitivity")
                                print(f"  result after: tau={bin(result.tau)}, result.sigma={bin(result.sigma)}")
                        elif DEBUG_SENSITIVITY:
                            print(f"  No pattern match for key={key_str}")
                
                state.push(result)
        
        # === STORE_SUBSCR (container[key] = value) ===
        elif opname == 'STORE_SUBSCR':
            # ITERATION 606: Handle container storage to track taint in dict/list contents
            # Bytecode: container[key] = value
            # Stack layout (Python 3.14): TOS = key, TOS1 = container, TOS2 = value
            # After STORE_SUBSCR, all three are popped and container is updated
            #
            # Strategy: Update the container's taint label to reflect its contents
            # When container is later passed to a sink (e.g., json.dump(container, f)),
            # the sink check will see the joined taint of all stored values.
            if len(state.stack) >= 3:
                key_label = state.pop()        # TOS: subscript key
                container_label = state.pop()  # TOS1: container (dict/list/etc)
                value_label = state.pop()      # TOS2: value being stored
                
                # Join container's existing taint with the new value's taint
                # This way, if container was clean and value is sanitized,
                # the container becomes sanitized too
                updated_container = label_join(container_label, value_label)
                
                # Try to identify which local variable holds the container
                # Look back for LOAD_FAST/LOAD_NAME that loaded the container
                container_var_idx = self._identify_container_variable(offset)
                if container_var_idx is not None:
                    # Update the local variable's taint label
                    state.set_local(container_var_idx, updated_container)

        
        # === FORMAT_VALUE (f-strings) ===
        elif opname == 'FORMAT_VALUE':
            # Taint propagates through formatting
            if state.stack:
                value = state.pop()
                state.push(value)  # Keep taint
        
        # === BUILD instructions ===
        elif opname.startswith('BUILD_'):
            # BUILD_MAP pops 2*count items (key-value pairs)
            # Other BUILD_ instructions pop count items
            count = instr.arg
            
            if opname == 'BUILD_MAP':
                # BUILD_MAP pops 2*count items: key1, value1, key2, value2, ...
                num_items = 2 * count
            else:
                # BUILD_STRING, BUILD_LIST, BUILD_TUPLE, BUILD_SET, etc.
                num_items = count
            
            if num_items > 0 and len(state.stack) >= num_items:
                items = [state.pop() for _ in range(num_items)]
                result = label_join_many(items)
                state.push(result)
            else:
                state.push(TaintLabel.clean())
        
        # === POP_TOP ===
        elif opname == 'POP_TOP':
            state.pop()
        
        # === DUP_TOP ===
        elif opname == 'DUP_TOP':
            top = state.peek()
            state.push(top)
        
        # === RETURN_VALUE ===
        elif opname == 'RETURN_VALUE':
            # Don't propagate to next instruction
            return
        
        # === Branching instructions ===
        elif opname.startswith('POP_JUMP_IF_') or opname in ('JUMP_FORWARD', 'JUMP_BACKWARD'):
            # Handle conditional and unconditional jumps
            if opname == 'JUMP_FORWARD' or opname == 'JUMP_BACKWARD':
                # Unconditional jump - only propagate to target
                target_offset = instr.argval
                if target_offset is not None:
                    self._merge_state(target_offset, state)
            else:
                # Conditional jump - propagate to both target and fall-through
                # Pop condition from stack
                if state.stack:
                    state.pop()
                
                # Propagate to both branch target and fall-through
                target_offset = instr.argval
                if target_offset is not None:
                    self._merge_state(target_offset, state.copy())
                
                next_offset = self._get_next_offset(instr)
                if next_offset is not None:
                    self._merge_state(next_offset, state)
            return  # Don't fall through to default propagation
        
        # Propagate state to next instruction
        next_offset = self._get_next_offset(instr)
        if next_offset is not None:
            self._merge_state(next_offset, state)
    
    def _handle_call(self, instr: dis.Instruction, state: LocalTaintState, offset: int):
        """Handle CALL instructions for source/sink detection."""
        # Python 3.11+ uses PRECALL + CALL
        # Python 3.12+ uses CALL with different arg encoding
        
        # Get number of arguments
        if instr.opname == 'CALL_FUNCTION':
            nargs = instr.arg
        elif instr.opname == 'CALL' or instr.opname == 'CALL_KW':
            # In 3.11+, arg is nargs for both CALL and CALL_KW
            nargs = instr.arg
        elif instr.opname == 'PRECALL':
            # PRECALL followed by CALL
            # For now, handle in the CALL instruction
            return
        else:
            nargs = 0
        
        # Extract constant string arguments (for sensitivity inference)
        const_args = self._extract_const_args(offset, nargs)
        
        # DEBUG (ITERATION 468)
        import os
        if os.environ.get('DEBUG_CMD_INJECTION') == '1':
            print(f"[CMD_INJ] _handle_call at offset {offset}")
            print(f"  Opname: {instr.opname}, nargs: {nargs}")
            print(f"  Stack size BEFORE popping: {len(state.stack)}")
            print(f"  Stack contents: {[f'tau={bin(s.tau)}' for s in state.stack]}")
        
        # ITERATION 468: Save all stack items before popping (for sink checking workaround)
        all_stack_items_before_pop = list(state.stack)
        
        # ITERATION 473: For CALL_KW, pop kwnames tuple first
        if instr.opname == 'CALL_KW':
            if state.stack:
                kwnames_label = state.pop()  # Pop and discard kwnames tuple
        
        # Pop arguments (taint labels)
        args = []
        for i in range(nargs):
            if state.stack:
                popped = state.pop()
                args.append(popped)
                if os.environ.get('DEBUG_CMD_INJECTION') == '1':
                    print(f"  Popped arg {i}: tau={bin(popped.tau)}")
        args.reverse()
        
        if os.environ.get('DEBUG_CMD_INJECTION') == '1':
            print(f"  Args after reverse: {[f'tau={bin(a.tau)}' for a in args]}")
        
        # Pop callable
        if state.stack:
            callable_label = state.pop()
        else:
            callable_label = TaintLabel.clean()
        
        # Try to identify the call
        # Look back for LOAD_ATTR / LOAD_METHOD / LOAD_GLOBAL
        call_name = self._identify_call(offset)
        
        # DEBUG (ITERATION 468-469)
        import os
        DEBUG_SSRF = os.environ.get('DEBUG_SSRF') == '1'
        if os.environ.get('DEBUG_CMD_INJECTION') == '1' and 'subprocess' in call_name.lower():
            print(f"[CMD_INJ] Identified call: {call_name}")
            print(f"  is_security_sink: {is_security_sink(call_name)}")
            print(f"  contract exists: {get_sink_contract(call_name) is not None}")
            print(f"  args count: {len(args)}")
        if DEBUG_SSRF and 'requests' in call_name.lower():
            print(f"[SSRF] Identified call: {call_name}")
            print(f"  is_taint_source: {is_taint_source(call_name)}")
            print(f"  is_security_sink: {is_security_sink(call_name)}")
            print(f"  args count: {len(args)}")
            print(f"  args: {[f'tau={bin(a.tau)}' for a in args]}")
        
        # ITERATION 469: Check sinks BEFORE sources
        # Some functions like requests.get are both sinks (SSRF) and sources (network data).
        # We need to check if tainted input flows to the sink first, then add source taint
        # to the return value.
        is_source = is_taint_source(call_name)
        is_sink = is_security_sink(call_name)
        
        # Check if this is a sink
        if is_security_sink(call_name):
            contract = get_sink_contract(call_name)
            if contract:
                # ITERATION 468: For sinks, check ALL items on stack before popping
                # This works around complex Python 3.11+ stack layout issues with LOAD_ATTR
                # The key insight: if we're calling a dangerous sink and ANY value on the
                # stack is tainted, that's likely flowing to the sink
                
                # ITERATION 468: Extract kwargs for CALL_KW to check shell=True, etc.
                # ITERATION 605: Use bytecode inspection to extract actual constant values
                kwargs = {}
                if instr.opname == 'CALL_KW':
                    # For CALL_KW, extract keyword argument names
                    kwnames = self._extract_kwnames(offset)
                    if kwnames:
                        # CALL_KW arg is total number of args (positional + keyword)
                        # The kwnames tuple tells us which of the trailing args are keywords
                        # Example: subprocess.Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
                        #   → 4 total args, kwnames=('shell', 'stdout', 'stderr')
                        #   → args[0]=cmd (positional), args[1-3]=keywords
                        num_kwargs = len(kwnames)
                        if len(args) >= num_kwargs:
                            # Map each keyword name to its value
                            # ITERATION 605: Extract from bytecode, not from taint label
                            for i, kwname in enumerate(kwnames):
                                # Keyword args are pushed in order before the call
                                # kwarg_stack_pos counts from the most recent (last kwarg = pos 0)
                                kwarg_stack_pos = num_kwargs - 1 - i
                                kwargs[kwname] = self._extract_kwarg_const_value(offset, kwarg_stack_pos)
                
                # DEBUG (ITERATION 468)
                import os
                if os.environ.get('DEBUG_CMD_INJECTION') == '1':
                    print(f"[CMD_INJ] Checking sink: {call_name}")
                    print(f"  Opname: {instr.opname}")
                    print(f"  Args from pop: {[f'tau={bin(a.tau)}' for a in args]}")
                    print(f"  All stack items (before pop): {[f'tau={bin(s.tau)}' for s in all_stack_items_before_pop]}")
                    print(f"  Kwargs: {kwargs}")
                
                # Check using all stack items from before pop (more conservative but catches missed taints)
                # ITERATION 468: Manual check for ANY tainted value on stack (workaround for stack layout issues)
                any_tainted = any(item.has_untrusted_taint() or item.has_sensitivity() for item in all_stack_items_before_pop)
                
                # ITERATION 612: Improved shell=True detection
                # Look for LOAD_CONST True in the bytecode before the call
                shell_true = False
                if 'shell' in kwargs:
                    if kwargs.get('shell') is True:
                        shell_true = True
                    elif kwargs.get('shell') is None:
                        # kwargs extraction failed - try direct bytecode search
                        # Look for LOAD_CONST True before this CALL_KW
                        for j in range(len(self.instructions)):
                            if self.instructions[j].offset == offset:
                                # Found the call, search backward for LOAD_CONST True
                                for k in range(j-1, max(0, j-10), -1):
                                    instr = self.instructions[k]
                                    if instr.opname == 'LOAD_CONST' and instr.argval is True:
                                        shell_true = True
                                        break
                                break
                
                if any_tainted and shell_true:
                    # Found a tainted value going to a command injection sink with shell=True!
                    # Create a manual violation
                    tainted_item = next(item for item in all_stack_items_before_pop if item.has_untrusted_taint() or item.has_sensitivity())
                    
                    # Find source location
                    source_offset, source_desc = self._find_source_for_label(tainted_item, offset)
                    line = self._offset_to_line(offset)
                    
                    bug = IntraproceduralBug(
                        bug_type="COMMAND_INJECTION",
                        function_name=self.function_name,
                        file_path=self.file_path,
                        line_number=line,
                        source_line=self._offset_to_line(source_offset) if source_offset else None,
                        source_description=source_desc,
                        sink_line=line,
                        sink_description=call_name,
                        taint_label=tainted_item,
                        reason=f"Tainted data from {source_desc} flows to command injection sink {call_name} with shell=True",
                        confidence=1.0,
                        inferred_source=tainted_item.has_sensitivity(),
                    )
                    self.bugs.append(bug)
                    if os.environ.get('DEBUG_CMD_INJECTION') == '1':
                        print(f"  ✓ MANUAL BUG DETECTED: COMMAND_INJECTION")
                else:
                    # Fall back to normal check
                    # ITERATION 473: Use args for normal cases, but keep all_stack_items_before_pop
                    # for cases where stack layout is complex (e.g., BUILD_MAP with CALL_KW)
                    # The issue: BUILD_MAP changes stack depth, making arg indices unreliable
                    # Solution: Check all stack items (conservative but catches missed taints)
                    items_to_check = all_stack_items_before_pop if instr.opname == 'CALL_KW' else args
                    violations = check_sink_taint(call_name, "<intraprocedural>", items_to_check, kwargs)
                    
                    # DEBUG (ITERATION 468)
                    if os.environ.get('DEBUG_CMD_INJECTION') == '1':
                        print(f"  Violations from check_sink_taint: {len(violations)}")
                    
                    for violation in violations:
                        # Found a bug! Use bug type from violation contract
                        bug_type = violation.bug_type
                        
                        # ITERATION 464: Check all arguments and find one with sensitivity
                        # For sinks like print(a, b, c), we need to check each arg
                        tainted_arg = None
                        for arg in args:
                            if arg.has_any_taint():
                                tainted_arg = arg
                                # If this arg has sensitivity, use it
                                if arg.has_sensitivity():
                                    break
                        
                        if tainted_arg is None:
                            tainted_arg = args[0] if args else TaintLabel.clean()
                        
                        # Find source location
                        source_offset, source_desc = self._find_source_for_label(tainted_arg, offset)
                        
                        line = self._offset_to_line(offset)
                        
                        # Check if source was inferred from variable name
                        # Inferred sources are sensitivity sources (σ) like PASSWORD, API_KEY
                        inferred = tainted_arg.has_sensitivity()
                        
                        bug = IntraproceduralBug(
                            bug_type=bug_type,
                            function_name=self.function_name,
                            file_path=self.file_path,
                            line_number=line,
                            source_line=self._offset_to_line(source_offset) if source_offset else None,
                            source_description=source_desc,
                            sink_line=line,
                            sink_description=call_name,
                            taint_label=tainted_arg,
                            reason=f"Tainted data from {source_desc} flows to sink {call_name}",
                            confidence=1.0,
                            inferred_source=inferred,
                        )
                        self.bugs.append(bug)
        
        # Check if this is a sanitizer
        if is_sanitizer(call_name):
            contract = get_sanitizer_contract(call_name)
            if contract and args:
                # Apply sanitizer to first argument
                result_label = apply_sanitizer(call_name, args[0])
                state.push(result_label)
                return
        
        # ITERATION 469: Check if this is a source (after sink checks)
        # Some functions like requests.get are both sinks and sources.
        # We already checked for sinks above, now add source taint to return value.
        if is_source:
            contract = get_source_contract(call_name)
            if contract:
                # Create tainted label with sensitivity inference from constant args
                source_desc = f"{call_name}({', '.join(repr(a) for a in const_args)})" if const_args else call_name
                result_label = apply_source_taint(call_name, source_desc, const_args)
                state.push(result_label)
                
                # Record source location
                self.sources[offset] = source_desc
                return
        
        # Default: join all arguments AND the callable (for method call taint propagation)
        # ITERATION 612: For methods like str.format(), taint propagates from:
        #   1. The receiver object (e.g., the format string)
        #   2. All arguments (e.g., values being interpolated)
        # Example: "dig {}".format(domain) - if domain is tainted, result is tainted
        all_labels = list(args)  # Start with all arguments
        
        # Also consider the callable/receiver's taint
        # In Python 3.11+, for method calls, the receiver is popped as callable_label
        # but we also need to check the stack for receiver taint (method call pattern)
        # The callable_label may carry receiver taint in some cases
        if callable_label is not None and callable_label.has_any_taint():
            all_labels.append(callable_label)
        
        if all_labels:
            result_label = label_join_many(all_labels)
        else:
            result_label = TaintLabel.clean()
        state.push(result_label)
    
    def _identify_call(self, call_offset: int) -> str:
        """
        Try to identify the function being called.
        
        In Python 3.11+ bytecode, the pattern is:
            LOAD_GLOBAL module      ← Callable (index N)
            LOAD_ATTR method        ← Callable (index N+1)
            <arg1>                  ← Arguments start here
            <arg2>
            ...
            [LOAD_CONST kwnames]    ← for CALL_KW only
            CALL/CALL_KW
        
        The callable is loaded FIRST, then all arguments.
        For a given CALL, we look backward to find LOAD_ATTR + LOAD_GLOBAL pairs,
        and select the LATEST one (closest to CALL) within a reasonable range.
        This ensures we get the callable for THIS call, not an earlier unrelated call.
        
        ITERATION 472: Handle chained attribute access (e.g., request.GET.get)
        """
        # Find the call instruction
        call_idx = None
        call_instr = None
        for i, instr in enumerate(self.instructions):
            if instr.offset == call_offset:
                call_idx = i
                call_instr = instr
                break
        
        if call_idx is None:
            return "<unknown>"
        
        # Determine search range based on number of arguments
        # CALL/CALL_KW arg is the argument count
        nargs = call_instr.arg if call_instr.arg else 0
        
        # Search range: approximately 2-3 instructions per argument + callable
        # But cap it to avoid going too far back
        max_search_distance = min(nargs * 3 + 10, 30)
        
        search_start = call_idx - 1
        if call_instr.opname == 'CALL_KW':
            # Skip keyword tuple constant
            if search_start >= 0 and self.instructions[search_start].opname == 'LOAD_CONST':
                search_start -= 1
        
        search_end = max(0, search_start - max_search_distance)
        
        # ITERATION 473: Build attribute chain by walking backwards through consecutive LOAD_ATTR
        # Pattern: LOAD_FAST/LOAD_GLOBAL/LOAD_NAME followed by one or more LOAD_ATTR
        # Example: request.GET.get → LOAD_FAST request, LOAD_ATTR GET, LOAD_ATTR get
        
        # First, skip backward past all arguments to find the callable.
        # In Python 3.11+, arguments can be complex expressions with multiple instructions.
        # Strategy: Skip backward until we find a sequence like LOAD_ATTR or LOAD_GLOBAL/LOAD_NAME
        # that's NOT part of an argument expression.
        
        i = search_start
        
        # ITERATION 480: For CALL_KW, use same strategy as CALL
        # Problem: Previous logic was finding LOAD_ATTR in arguments (e.g., subprocess.PIPE)
        # instead of the callable's LOAD_ATTR (e.g., subprocess.Popen)
        # Solution: Skip back past all arguments, then find the FIRST LOAD_ATTR going forward
        if call_instr.opname == 'CALL_KW':
            # Skip backwards past arguments - use generous estimate
            # Each arg could be 1-3 instructions (simple load vs module.attr)
            # Plus account for PUSH_NULL if present
            skip_back = (nargs * 3) + 2
            i = max(search_end, call_idx - skip_back)
            
            # Now walk forward to find the callable's LOAD_ATTR or LOAD_GLOBAL
            # For chained attribute access (e.g., request.GET.get), we want the LAST LOAD_ATTR
            # before arguments start
            last_load_attr_idx = None
            
            while i < call_idx:
                instr = self.instructions[i]
                if instr.opname in ('LOAD_ATTR', 'LOAD_METHOD'):
                    # Potential callable - check if there are enough instructions after it for all args
                    # The callable must be followed by: [PUSH_NULL], arg1, arg2, ..., CALL_KW
                    # At minimum, need (nargs * 1.5) instructions after this to reach CALL_KW
                    # (accounting for complex argument expressions)
                    remaining = call_idx - i
                    if remaining >= nargs + 1:  # +1 for the CALL_KW itself
                        # This could be the callable OR part of a chain
                        # Check if next instruction is also LOAD_ATTR (means we're in a chain)
                        if i + 1 < len(self.instructions) and self.instructions[i + 1].opname in ('LOAD_ATTR', 'LOAD_METHOD'):
                            # Part of a chain, keep going to find the last LOAD_ATTR
                            last_load_attr_idx = i
                        else:
                            # This is the last/only LOAD_ATTR before args
                            last_load_attr_idx = i
                            break
                elif instr.opname in ('LOAD_GLOBAL', 'LOAD_NAME'):
                    # Check if followed by LOAD_ATTR
                    if i + 1 < len(self.instructions) and self.instructions[i + 1].opname in ('LOAD_ATTR', 'LOAD_METHOD'):
                        # Part of callable chain, will be picked up by LOAD_ATTR case
                        pass
                    else:
                        # Simple callable - but check distance
                        remaining = call_idx - i
                        if remaining >= nargs + 1:
                            break
                i += 1
            
            # If we found LOAD_ATTR in a chain, move i to the last one
            if last_load_attr_idx is not None:
                i = last_load_attr_idx
        else:
            # For regular CALL in Python 3.11+/3.14
            # Bytecode pattern: <callable> [PUSH_NULL] <arg1> <arg2> ... CALL nargs
            # 
            # ITERATION 535: Fix callable identification.
            # Key insight: PUSH_NULL marks the boundary between callable and arguments.
            # Strategy: Walk backward from CALL, and if we see PUSH_NULL, everything
            # before it is the callable. Otherwise, skip nested calls and find the
            # last LOAD_ATTR/LOAD_METHOD/LOAD_GLOBAL before arguments.
            
            # Start from instruction before CALL
            i = call_idx - 1
            found_push_null = False
            
            # First, check for PUSH_NULL nearby (it marks callable/arg boundary)
            for check_offset in range(min(nargs + 3, 15)):
                check_idx = call_idx - 1 - check_offset
                if check_idx >= 0 and self.instructions[check_idx].opname == 'PUSH_NULL':
                    found_push_null = True
                    # The callable ends just before PUSH_NULL
                    i = check_idx - 1
                    break
            
            if found_push_null:
                # Found PUSH_NULL - the callable is right before it
                # Just find the last LOAD_ATTR/LOAD_METHOD/LOAD_GLOBAL before PUSH_NULL
                while i >= 0:
                    instr = self.instructions[i]
                    if instr.opname in ('LOAD_ATTR', 'LOAD_METHOD', 'LOAD_GLOBAL', 'LOAD_NAME'):
                        # This is part of the callable
                        # Keep i here to start building the name
                        break
                    i -= 1
            else:
                # No PUSH_NULL - walk backward skipping nested calls and args
                skipped_calls = 0
                
                while i >= 0:
                    instr = self.instructions[i]
                    if instr.opname in ('CALL', 'CALL_KW', 'CALL_FUNCTION'):
                        skipped_calls += 1
                        i -= 1
                    elif skipped_calls > 0 and instr.opname in ('LOAD_GLOBAL', 'LOAD_NAME', 'LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_CONST'):
                        # This is part of a nested call argument
                        i -= 1
                    elif instr.opname in ('LOAD_ATTR', 'LOAD_METHOD'):
                        # Found a potential callable
                        break
                    elif instr.opname in ('LOAD_GLOBAL', 'LOAD_NAME'):
                        # Simple callable (not a method/attribute)
                        break
                    elif instr.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_CONST'):
                        # Argument value
                        i -= 1
                    else:
                        # Other instruction
                        i -= 1
                    
                    # Safety: don't go too far back
                    if call_idx - i > 50:
                        break
        
        # Now walk backward collecting LOAD_ATTR in reverse order
        attr_chain = []
        while i >= search_end and i >= 0:
            instr = self.instructions[i]
            
            if instr.opname in ('LOAD_ATTR', 'LOAD_METHOD'):
                # Add to chain (we'll reverse it later)
                attr_chain.append(instr.argval)
                i -= 1
            elif instr.opname in ('LOAD_GLOBAL', 'LOAD_NAME', 'LOAD_FAST', 'LOAD_FAST_BORROW'):
                # Found the base object/module
                base = instr.argval
                
                # ITERATION 517: Resolve import alias
                # If base is an aliased import, replace with real module name
                # Example: "ET" → "xml.etree.ElementTree"
                if base in self.import_aliases:
                    base = self.import_aliases[base]
                
                # Build the full name: base.attr1.attr2...
                if attr_chain:
                    attr_chain.reverse()  # We collected them backwards
                    return f"{base}.{'.'.join(attr_chain)}"
                else:
                    # Just the base name (simple call)
                    return base
            else:
                # Hit something else, might still be in arguments; keep going
                i -= 1
                if i < search_end:
                    break
        
        # Fallback: try old pattern matching (for backwards compatibility)
        candidates = []
        for i in range(search_start, search_end, -1):
            instr = self.instructions[i]
            
            if instr.opname in ('LOAD_ATTR', 'LOAD_METHOD'):
                if i > 0:
                    prev = self.instructions[i - 1]
                    if prev.opname in ('LOAD_GLOBAL', 'LOAD_NAME'):
                        # Found a callable: module.method
                        # ITERATION 517: Resolve alias
                        base = prev.argval
                        if base in self.import_aliases:
                            base = self.import_aliases[base]
                        callable_name = f"{base}.{instr.argval}"
                        candidates.append((i, callable_name))
            elif instr.opname in ('LOAD_GLOBAL', 'LOAD_NAME'):
                # Found a callable: simple function call
                # Only include if not followed by LOAD_ATTR (which would make it pattern 1)
                if i + 1 < len(self.instructions):
                    next_instr = self.instructions[i + 1]
                    if next_instr.opname not in ('LOAD_ATTR', 'LOAD_METHOD'):
                        # ITERATION 517: Resolve alias for simple calls too
                        name = instr.argval
                        if name in self.import_aliases:
                            name = self.import_aliases[name]
                        candidates.append((i, name))
                else:
                    # ITERATION 517: Resolve alias
                    name = instr.argval
                    if name in self.import_aliases:
                        name = self.import_aliases[name]
                    candidates.append((i, name))
        
        # The callable is the LATEST (highest index) candidate within our search range
        # (closest to the CALL instruction, after all arguments are loaded)
        if candidates:
            candidates.sort(key=lambda x: x[0], reverse=True)  # Sort by index, descending
            return candidates[0][1]  # Return the latest (closest to CALL)
        
        return "<unknown>"
    
    def _identify_attr_object(self, attr_offset: int) -> str:
        """
        Try to identify the object whose attribute is being accessed.
        
        Looks backward from LOAD_ATTR to find the object (LOAD_FAST, LOAD_GLOBAL, etc.).
        """
        attr_idx = None
        for i, instr in enumerate(self.instructions):
            if instr.offset == attr_offset:
                attr_idx = i
                break
        
        if attr_idx is None:
            return "<unknown>"
        
        # Look backward for the object being accessed
        for i in range(attr_idx - 1, max(0, attr_idx - 5), -1):
            instr = self.instructions[i]
            if instr.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW'):
                # Get the local variable name
                if instr.arg < len(self.code_obj.co_varnames):
                    return self.code_obj.co_varnames[instr.arg]
            elif instr.opname in ('LOAD_GLOBAL', 'LOAD_NAME'):
                # ITERATION 517: Resolve alias
                name = instr.argval
                if name in self.import_aliases:
                    name = self.import_aliases[name]
                return name
            elif instr.opname == 'LOAD_ATTR':
                # Nested attribute access - recursively identify
                return self._identify_attr_object(instr.offset) + '.' + instr.argval
        
        return "<unknown>"
    
    def _identify_subscript_container(self, subscr_offset: int) -> str:
        """
        Identify the container object being subscripted.
        
        For bytecode: LOAD_X ... LOAD_CONST key, BINARY_SUBSCR
        Returns the name of the container (e.g., "request.GET").
        
        ITERATION 534: Added to detect subscript-based source operations like request.GET['file'].
        """
        subscr_idx = None
        for i, instr in enumerate(self.instructions):
            if instr.offset == subscr_offset:
                subscr_idx = i
                break
        
        if subscr_idx is None:
            return None
        
        # Look backward past the key (should be LOAD_CONST immediately before BINARY_SUBSCR)
        # Then find the container object
        for i in range(subscr_idx - 1, max(0, subscr_idx - 10), -1):
            instr = self.instructions[i]
            
            # Skip the key load
            if instr.opname in ('LOAD_CONST',):
                continue
            
            # Found potential container
            if instr.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW'):
                # Simple variable
                if instr.arg < len(self.code_obj.co_varnames):
                    return self.code_obj.co_varnames[instr.arg]
            elif instr.opname in ('LOAD_GLOBAL', 'LOAD_NAME'):
                # Global/builtin
                name = instr.argval
                if name in self.import_aliases:
                    name = self.import_aliases[name]
                return name
            elif instr.opname == 'LOAD_ATTR':
                # Attribute access - need to reconstruct full chain
                # e.g., request.GET becomes "request.GET"
                return self._identify_attr_object(instr.offset) + '.' + instr.argval
            elif instr.opname == 'CALL':
                # Method call result being subscripted
                # Try to identify the call
                callable_name = self._identify_call(instr.offset)
                return callable_name
            else:
                # Some other operation - can't identify
                return None
        
        return None
    
    def _identify_container_variable(self, store_subscr_offset: int) -> Optional[int]:
        """
        Identify the local variable index for the container in STORE_SUBSCR.
        
        For bytecode (Python 3.14):
            LOAD_FAST value
            LOAD_FAST container
            LOAD_FAST key
            STORE_SUBSCR
        Or with optimization:
            LOAD_FAST_BORROW_LOAD_FAST_BORROW (value, container)
            LOAD_FAST_BORROW key
            STORE_SUBSCR
        
        Stack before STORE_SUBSCR: TOS=key, TOS1=container, TOS2=value
        
        ITERATION 606: Added to track container taint when items are stored.
        
        Returns:
            Local variable index if container is a local variable, None otherwise
        """
        store_idx = None
        for i, instr in enumerate(self.instructions):
            if instr.offset == store_subscr_offset:
                store_idx = i
                break
        
        if store_idx is None:
            return None
        
        # Look backward from STORE_SUBSCR to find the container load
        # Stack layout before STORE_SUBSCR: TOS = key, TOS1 = container, TOS2 = value
        
        # Pattern 1: LOAD_FAST_BORROW_LOAD_FAST_BORROW (value, container), LOAD_FAST key
        if store_idx >= 2:
            prev_instr = self.instructions[store_idx - 1]  # Should be LOAD_FAST key
            prev2_instr = self.instructions[store_idx - 2]  # Should be dual-load
            
            if (prev_instr.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW') and
                prev2_instr.opname == 'LOAD_FAST_BORROW_LOAD_FAST_BORROW'):
                # Dual-load: arg = (first_var << 4) | second_var
                # Stack after dual-load: [..., first_var, second_var]
                # After key load: [..., first_var, second_var, key]
                # For STORE_SUBSCR: TOS=key, TOS1=second_var (container), TOS2=first_var (value)
                second_var = prev2_instr.arg & 0xF
                return second_var
        
        # Pattern 2: Three separate LOAD_FAST instructions
        # LOAD_FAST value, LOAD_FAST container, LOAD_FAST key
        if store_idx >= 3:
            prev1 = self.instructions[store_idx - 1]  # key
            prev2 = self.instructions[store_idx - 2]  # container
            prev3 = self.instructions[store_idx - 3]  # value
            
            if (prev1.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW') and
                prev2.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW') and
                prev3.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW')):
                # Container is the second-to-last load
                return prev2.arg
        
        return None
    
    def _extract_const_args(self, call_offset: int, nargs: int) -> List[str]:
        """
        Extract constant string arguments to a call.
        
        Looks backward from CALL to find LOAD_CONST instructions.
        Returns list of constant strings (non-string constants are represented as their str()).
        """
        if nargs == 0:
            return []
        
        call_idx = None
        for i, instr in enumerate(self.instructions):
            if instr.offset == call_offset:
                call_idx = i
                break
        
        if call_idx is None:
            return []
        
        # Look backward for LOAD_CONST instructions
        const_args = []
        for i in range(call_idx - 1, max(0, call_idx - 20), -1):
            instr = self.instructions[i]
            if instr.opname == 'LOAD_CONST':
                # Get the constant value
                if isinstance(instr.argval, str):
                    const_args.insert(0, instr.argval)
                elif instr.argval is not None:
                    const_args.insert(0, str(instr.argval))
                
                if len(const_args) >= nargs:
                    break
        
        return const_args[:nargs]
    
    def _extract_kwnames(self, call_offset: int) -> Optional[tuple]:
        """
        Extract keyword argument names from CALL_KW instruction.
        
        For CALL_KW, the bytecode is:
            ... args ...
            LOAD_CONST (tuple of kwnames)
            CALL_KW
        
        Returns tuple of keyword names, or None if not found.
        """
        # Find the CALL_KW instruction
        call_idx = None
        for i, instr in enumerate(self.instructions):
            if instr.offset == call_offset:
                call_idx = i
                break
        
        if call_idx is None or call_idx == 0:
            return None
        
        # The previous instruction should be LOAD_CONST with the kwnames tuple
        prev = self.instructions[call_idx - 1]
        if prev.opname == 'LOAD_CONST' and isinstance(prev.argval, tuple):
            return prev.argval
        
        return None
    
    def _extract_kwarg_const_value(self, call_offset: int, kwarg_stack_pos: int) -> Any:
        """
        Extract the constant value for a keyword argument at a CALL_KW instruction.
        
        ITERATION 605: Look back through bytecode to find the LOAD_CONST instruction
        that pushed the kwarg value onto the stack.
        
        ITERATION 612: Fixed to properly handle mixed const/non-const kwargs.
        Now uses kwarg_stack_pos to determine which value we want:
        - pos 0 = most recent kwarg (last in kwnames)
        - pos N-1 = first kwarg (first in kwnames)
        
        Args:
            call_offset: Offset of the CALL_KW instruction
            kwarg_stack_pos: Stack position of the kwarg value (0 = most recent push)
        
        Returns:
            The constant value, or None if not a constant
        """
        # Find the CALL_KW instruction index
        call_idx = None
        for i, instr in enumerate(self.instructions):
            if instr.offset == call_offset:
                call_idx = i
                break
        
        if call_idx is None:
            return None
        
        # ITERATION 612: Walk backward from CALL_KW and track ALL value pushes
        # (not just LOAD_CONST) to find the correct kwarg value
        # 
        # Stack layout before CALL_KW N with kwnames ('shell', 'stdout', 'stderr'):
        #   ... callable, NULL, positional_args, kwarg_values..., kwnames_tuple
        #
        # We need to find the kwarg value at the given stack position
        # For shell (pos 2 in a 3-kwarg call), we want the THIRD-from-last push
        
        # First, find and skip the kwnames tuple
        start_idx = call_idx - 1
        if start_idx >= 0 and self.instructions[start_idx].opname == 'LOAD_CONST':
            instr = self.instructions[start_idx]
            if isinstance(instr.argval, tuple):
                start_idx -= 1  # Skip kwnames tuple
        
        # Now count back through value-pushing instructions
        # We want the (kwarg_stack_pos + 1)-th value push going backward
        pushes_found = 0
        i = start_idx
        while i >= 0 and pushes_found <= kwarg_stack_pos:
            instr = self.instructions[i]
            
            # Check if this instruction pushes a value
            # Common value-pushing opcodes:
            if instr.opname in ('LOAD_CONST', 'LOAD_FAST', 'LOAD_FAST_BORROW', 
                               'LOAD_NAME', 'LOAD_GLOBAL', 'LOAD_ATTR'):
                if pushes_found == kwarg_stack_pos:
                    # This is the value we want
                    if instr.opname == 'LOAD_CONST':
                        return instr.argval
                    else:
                        # Not a constant - return None
                        return None
                pushes_found += 1
            
            # Skip over some paired instructions (LOAD_GLOBAL + LOAD_ATTR = one value)
            # Actually LOAD_ATTR after LOAD_GLOBAL is part of the SAME value push
            # So we should NOT double-count
            # Let's use a simpler approach: count stack effect
            
            i -= 1
        
        return None
    
    def _try_extract_const_value(self, label: TaintLabel) -> Any:
        """
        Try to extract a constant value associated with a taint label.
        
        This is a heuristic: if the label is clean (no taint), it likely represents
        a constant value from a LOAD_CONST.
        
        ITERATION 605: Fixed to return None instead of True conservatively.
        We cannot reliably extract constant values without tracking the actual values
        alongside taint labels. The shell_check logic in security_lattice.py should
        handle extraction from the symbolic VM state.
        
        Returns the extracted value, or None if unknown.
        """
        # Cannot reliably extract constant without the actual value
        # Return None to indicate "unknown" rather than making assumptions
        return None
    
    def _extract_constant_string(self, instr: dis.Instruction, offset: int, is_right_operand: bool = True) -> Optional[str]:
        """
        Extract a constant string operand for a binary operation.
        
        Args:
            instr: The binary operation instruction
            offset: Offset of the instruction
            is_right_operand: If True, extract right operand (TOS); if False, extract left (TOS1)
        
        Returns:
            The string constant, or None if not a constant string
        """
        # Find instruction index
        instr_idx = None
        for i, ins in enumerate(self.instructions):
            if ins.offset == offset:
                instr_idx = i
                break
        
        if instr_idx is None:
            return None
        
        # For BINARY_SUBSCR: stack is [..., TOS1 (container), TOS (key)]
        # Right operand (key) is TOS, loaded most recently
        # Look backward for LOAD_CONST that loaded this value
        lookback = 1 if is_right_operand else 2  # How many values back on stack
        found_loads = 0
        
        for i in range(instr_idx - 1, max(0, instr_idx - 10), -1):
            ins = self.instructions[i]
            if ins.opname == 'LOAD_CONST':
                found_loads += 1
                if found_loads == lookback:
                    # This is the LOAD_CONST for the operand we want
                    if isinstance(ins.argval, str):
                        return ins.argval
                    return None
        
        return None
    
    def _sink_to_bug_type(self, sink_name: str) -> str:
        """Map sink name to bug type."""
        sink_lower = sink_name.lower()
        
        # Cleartext bugs
        if 'print' in sink_lower or 'log' in sink_lower or 'debug' in sink_lower:
            return 'CLEARTEXT_LOGGING'
        if 'write' in sink_lower or 'save' in sink_lower or 'store' in sink_lower:
            return 'CLEARTEXT_STORAGE'
        
        # Injection bugs
        if 'execute' in sink_lower or 'query' in sink_lower:
            return 'SQL_INJECTION'
        if 'eval' in sink_lower or 'exec' in sink_lower:
            return 'CODE_INJECTION'
        if 'system' in sink_lower or 'popen' in sink_lower or 'subprocess' in sink_lower:
            return 'COMMAND_INJECTION'
        
        # Default
        return 'INFO_LEAK'
    
    def _find_source_for_label(self, label: TaintLabel, current_offset: int) -> Tuple[Optional[int], str]:
        """
        Try to find the source location for a tainted label.
        
        Returns (offset, description) or (None, "unknown source").
        """
        # Check if we have recorded sources
        if self.sources:
            # Find most recent source before current offset
            recent_source = None
            for offset, desc in self.sources.items():
                if offset < current_offset:
                    if recent_source is None or offset > recent_source[0]:
                        recent_source = (offset, desc)
            
            if recent_source:
                return recent_source
        
        # Check label provenance (format nicely)
        if label.provenance:
            # Provenance is a frozenset of strings like "HTTP_PARAM@request.GET.get"
            # Format as a comma-separated list for readability
            prov_list = sorted(label.provenance)
            if len(prov_list) == 1:
                # Single source: format as "HTTP_PARAM via request.GET.get"
                prov = prov_list[0]
                if '@' in prov:
                    source_type, location = prov.split('@', 1)
                    return (None, f"{source_type} via {location}")
                return (None, prov)
            else:
                # Multiple sources: format as "HTTP_PARAM, PASSWORD via multiple sources"
                source_types = set()
                for prov in prov_list:
                    if '@' in prov:
                        source_type = prov.split('@', 1)[0]
                        source_types.add(source_type)
                if source_types:
                    return (None, f"{', '.join(sorted(source_types))} via multiple sources")
                return (None, ", ".join(prov_list))
        
        # Check untrusted sources
        sources = label.get_untrusted_sources()
        if sources:
            source_names = ", ".join(s.name for s in sources[:3])
            if len(sources) > 3:
                source_names += f" (and {len(sources) - 3} more)"
            return (None, f"untrusted source: {source_names}")
        
        # Check sensitive sources
        sensitive = label.get_sensitivity_sources()
        if sensitive:
            sensitive_names = ", ".join(s.name for s in sensitive[:3])
            if len(sensitive) > 3:
                sensitive_names += f" (and {len(sensitive) - 3} more)"
            return (None, f"sensitive data: {sensitive_names}")
        
        return (None, "unknown source")
    
    def _get_next_offset(self, instr: dis.Instruction) -> Optional[int]:
        """Get the offset of the next instruction."""
        current_idx = None
        for i, ins in enumerate(self.instructions):
            if ins.offset == instr.offset:
                current_idx = i
                break
        
        if current_idx is None or current_idx + 1 >= len(self.instructions):
            return None
        
        return self.instructions[current_idx + 1].offset
    
    def _merge_state(self, offset: int, new_state: LocalTaintState):
        """
        Merge new_state into the state at offset.
        
        If state changes, add offset to worklist.
        """
        if offset not in self.states:
            self.states[offset] = new_state
            self.worklist.add(offset)
            return
        
        old_state = self.states[offset]
        changed = False
        
        # Merge locals
        for idx, label in new_state.locals.items():
            if idx not in old_state.locals:
                old_state.locals[idx] = label
                changed = True
            else:
                merged = label_join(old_state.locals[idx], label)
                if merged != old_state.locals[idx]:
                    old_state.locals[idx] = merged
                    changed = True
        
        # Merge names
        for name, label in new_state.names.items():
            if name not in old_state.names:
                old_state.names[name] = label
                changed = True
            else:
                merged = label_join(old_state.names[name], label)
                if merged != old_state.names[name]:
                    old_state.names[name] = merged
                    changed = True
        
        # Merge stack: join element-wise if same length, else widen to clean
        if len(new_state.stack) == len(old_state.stack):
            for i in range(len(new_state.stack)):
                merged = label_join(old_state.stack[i], new_state.stack[i])
                if merged != old_state.stack[i]:
                    old_state.stack[i] = merged
                    changed = True
        elif new_state.stack != old_state.stack:
            # Different stack heights - control flow merge
            # Widen to clean stack (sound over-approximation)
            old_state.stack = []
            changed = True
        
        if changed:
            self.worklist.add(offset)
    
    def _offset_to_line(self, offset: int) -> int:
        """Convert bytecode offset to source line number."""
        # In Python 3.11+, line info is in positions.lineno, not starts_line
        for instr in self.instructions:
            if instr.offset == offset and hasattr(instr, 'positions') and instr.positions:
                return instr.positions.lineno
        
        # Fall back: find closest previous line
        best_line = 1
        for instr in self.instructions:
            if instr.offset <= offset and hasattr(instr, 'positions') and instr.positions:
                best_line = instr.positions.lineno
        
        return best_line


# ============================================================================
# PROJECT-WIDE INTRAPROCEDURAL ANALYSIS
# ============================================================================

def analyze_file_intraprocedural(file_path: Path) -> List[IntraproceduralBug]:
    """
    Analyze all functions in a file for intraprocedural taint bugs.
    
    Returns list of bugs found.
    """
    bugs = []
    
    # Read and compile file
    try:
        source = file_path.read_text()
        code = compile(source, str(file_path), 'exec')
    except Exception as e:
        return bugs
    
    # ITERATION 518: Extract module-level imports for alias resolution
    # This enables detection of security sinks through aliased imports
    # Example: "import xml.etree.ElementTree as ET" → map "ET.fromstring" to "xml.etree.ElementTree.fromstring"
    import_aliases = extract_module_imports(code)
    
    # Analyze top-level code
    analyzer = IntraproceduralTaintAnalyzer(code, "<module>", str(file_path), import_aliases=import_aliases)
    bugs.extend(analyzer.analyze())
    
    # Find all function definitions
    functions = _find_functions_in_code(code)
    for func_name, func_code in functions:
        analyzer = IntraproceduralTaintAnalyzer(func_code, func_name, str(file_path), import_aliases=import_aliases)
        bugs.extend(analyzer.analyze())
    
    return bugs


def _find_functions_in_code(code: types.CodeType) -> List[Tuple[str, types.CodeType]]:
    """
    Recursively find all function code objects in a code object.
    
    Returns list of (name, code_object) tuples.
    """
    functions = []
    
    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            functions.append((const.co_name, const))
            # Recursively search nested functions
            functions.extend(_find_functions_in_code(const))
    
    return functions


def analyze_project_intraprocedural(project_path: Path) -> List[IntraproceduralBug]:
    """
    Analyze all Python files in a project for intraprocedural taint bugs.
    
    Returns list of bugs found across all files.
    """
    bugs = []
    
    # Find all Python files
    for py_file in project_path.rglob("*.py"):
        # Skip test files and __pycache__
        if '__pycache__' in str(py_file) or 'test_' in py_file.name:
            continue
        
        file_bugs = analyze_file_intraprocedural(py_file)
        bugs.extend(file_bugs)
    
    return bugs
