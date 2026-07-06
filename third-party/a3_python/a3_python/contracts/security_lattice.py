"""
Security Contracts with Full Lattice Integration (leak_theory.md implementation).

This module defines the security-relevant behavior of library functions using
the full taint product lattice L = P(T) × P(K) × P(T):

- Sources: Functions that introduce tainted/sensitive data (set τ or σ bits)
- Sinks: Functions where tainted data causes security bugs (check τ or σ against κ)
- Sanitizers: Functions that add sink-safety (set κ bits)

All contracts are over-approximating relations: R_f ⊇ Sem_f
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, Optional, FrozenSet, List, Callable, Set
import z3

from a3_python.z3model.taint_lattice import (
    SourceType, SinkType, SanitizerType,
    TaintLabel, SymbolicTaintLabel,
    SecurityViolation, SecurityBugType, CODEQL_BUG_TYPES,
    SANITIZER_TO_SINKS,
    create_violation,
    label_join_many, symbolic_label_join_many,
    tau_zero, kappa_zero, sigma_zero,
    TAU_WIDTH, KAPPA_WIDTH, SIGMA_WIDTH,
)


# ============================================================================
# SOURCE CONTRACTS
# ============================================================================

@dataclass(frozen=True)
class SourceContract:
    """
    Contract for a taint source function.
    
    Specifies which source type bits to set in τ (untrusted) or σ (sensitive).
    """
    function_id: str              # e.g., "os.environ.__getitem__"
    source_type: SourceType       # Which source bit to set
    is_sensitive: bool = False    # If True, sets σ; else sets τ
    description: str = ""
    
    # Optional: patterns for argument-dependent sensitivity
    # e.g., os.getenv with KEY/TOKEN/SECRET in name → sensitive
    sensitive_arg_patterns: FrozenSet[str] = field(default_factory=frozenset)


# Registry of source contracts
_source_contracts: Dict[str, SourceContract] = {}


def register_source(contract: SourceContract) -> None:
    """Register a taint source contract."""
    _source_contracts[contract.function_id] = contract
    # Also register short names for common patterns
    if "." in contract.function_id:
        short_name = contract.function_id.split(".")[-1]
        if short_name not in _source_contracts:
            _source_contracts[short_name] = contract


def get_source_contract(function_id: str) -> Optional[SourceContract]:
    """
    Get source contract for a function.
    
    ITERATION 478: Fixed false positives by checking contract.function_id compatibility.
    ITERATION 479: Fixed SQL Injection regression by supporting Django placeholders.
    ITERATION 543: Added placeholder matching for ORM methods (Model.objects.get matches User.objects.get).
    
    Matching rules:
    1. Exact match: function_id == key (but check contract.function_id)
    2. Suffix match: function_id ends with ".key" (but check contract.function_id)
    3. Placeholder match: Django patterns (uses _is_compatible_function_id)
    """
    # Try exact match first
    if function_id in _source_contracts:
        contract = _source_contracts[function_id]
        # ITERATION 479: Use _is_compatible_function_id for placeholder support
        if '.' in function_id:
            if _is_compatible_function_id(function_id, contract.function_id):
                return contract
            else:
                # No match - try suffix matching below
                pass
        else:
            # Bare function name - return contract
            return contract
    
    # Try suffix match with module separator
    for key, contract in _source_contracts.items():
        if function_id.endswith('.' + key):
            # ITERATION 479: Use _is_compatible_function_id for placeholder support
            if '.' in function_id:
                if _is_compatible_function_id(function_id, contract.function_id):
                    return contract
            else:
                return contract
    
    # ITERATION 543: Try placeholder matching for ORM-style patterns
    # E.g., "User.objects.get" should match "Model.objects.get"
    # Only try this for patterns that look like ORM calls (have 2+ dots)
    if '.' in function_id and function_id.count('.') >= 2:
        for key, contract in _source_contracts.items():
            if '.' in contract.function_id and contract.function_id.count('.') >= 2:
                if _is_compatible_function_id(function_id, contract.function_id):
                    return contract
    
    return None


def is_taint_source(function_id: str) -> bool:
    """Check if function is a taint source."""
    return get_source_contract(function_id) is not None


def apply_source_taint(
    function_id: str,
    location: str,
    args: List[str] = None
) -> TaintLabel:
    """
    Apply taint from a source function.
    
    Returns a fresh TaintLabel with the appropriate τ or σ bit set.
    """
    contract = get_source_contract(function_id)
    if contract is None:
        return TaintLabel.clean()
    
    # Check for argument-dependent sensitivity
    is_sensitive = contract.is_sensitive
    arg_suggests_password = False
    if contract.sensitive_arg_patterns and args:
        for arg in args:
            if isinstance(arg, str):
                arg_upper = arg.upper()
                if any(pat in arg_upper for pat in contract.sensitive_arg_patterns):
                    is_sensitive = True
                    arg_suggests_password = True
                    break
    
    if is_sensitive:
        # ITERATION 482: For HTTP params with password/secret keys, set BOTH τ and σ
        # Example: request.POST.get('password') should be:
        #   τ = HTTP_PARAM (untrusted user input)
        #   σ = PASSWORD (sensitive data)
        if arg_suggests_password and contract.source_type in (SourceType.HTTP_PARAM, SourceType.COOKIE, SourceType.HEADER):
            # User-provided sensitive data: set both τ (untrusted) and σ (sensitive)
            base = TaintLabel.from_untrusted_source(contract.source_type, location)
            return base.with_sensitivity(SourceType.PASSWORD)
        else:
            # Pure sensitive source (not user-provided): set only σ
            return TaintLabel.from_sensitive_source(contract.source_type, location)
    else:
        return TaintLabel.from_untrusted_source(contract.source_type, location)


def apply_source_taint_symbolic(
    function_id: str
) -> SymbolicTaintLabel:
    """
    Apply symbolic taint from a source function.
    
    Returns a SymbolicTaintLabel for Z3 reasoning.
    """
    contract = get_source_contract(function_id)
    if contract is None:
        return SymbolicTaintLabel.clean()
    
    if contract.is_sensitive:
        return SymbolicTaintLabel.from_sensitive_source(contract.source_type)
    else:
        return SymbolicTaintLabel.from_untrusted_source(contract.source_type)


# ============================================================================
# SINK CONTRACTS
# ============================================================================

@dataclass(frozen=True)
class SinkContract:
    """
    Contract for a security sink function.
    
    Specifies which arguments to check and what kind of taint is dangerous.
    """
    function_id: str              # e.g., "cursor.execute"
    sink_type: SinkType           # Type of sink (determines bug type)
    bug_type: str                 # Key into CODEQL_BUG_TYPES
    tainted_arg_indices: FrozenSet[int] = field(default_factory=frozenset)  # Which args to check
    tainted_kwarg_names: FrozenSet[str] = field(default_factory=frozenset)  # Which kwargs to check (by name)
    
    # ITERATION 526: Receiver taint tracking for method calls
    check_receiver: bool = False  # If True, check if receiver (self) is tainted (for method calls)
    
    # Context-dependent safety checks
    parameterized_check: bool = False    # For SQL: safe if params provided
    shell_check: bool = False            # For subprocess: only dangerous if shell=True
    loader_check: bool = False           # For YAML: safe if SafeLoader
    entity_check: bool = False           # For XML: safe if entities disabled
    
    description: str = ""


# Registry of sink contracts (multiple contracts per function allowed)
_sink_contracts: Dict[str, List[SinkContract]] = {}


def register_sink(contract: SinkContract) -> None:
    """Register a sink contract. Multiple contracts per function are allowed."""
    # Add to main registry
    if contract.function_id not in _sink_contracts:
        _sink_contracts[contract.function_id] = []
    _sink_contracts[contract.function_id].append(contract)
    
    # Also register short name, but NOT for names that would cause false positives
    # These short names are too generic and match common variable/parameter names
    SHORT_NAME_BLACKLIST = {
        'request',  # Django request parameter
        'get',      # dict.get, QueryDict.get, etc.
        'post',     # HTTP POST checks
        'open',     # file open vs requests.Session.open
        'execute',  # cursor.execute is fine, but bare 'execute' is too broad
        'run',      # subprocess.run, but also common function name
        'call',     # common function name
        'read',     # file.read is common
        'write',    # file.write is common
        'find',     # str.find, list.find, etc.
        'update',   # dict.update is common
        'load',     # json.load vs pickle.load
        'loads',    # json.loads vs pickle.loads
        'search',   # Pattern.search vs ldap.search ambiguity
    }
    
    if "." in contract.function_id:
        short_name = contract.function_id.split(".")[-1]
        if short_name.lower() not in SHORT_NAME_BLACKLIST:
            if short_name not in _sink_contracts:
                _sink_contracts[short_name] = []
            _sink_contracts[short_name].append(contract)


def _is_compatible_function_id(call_site_id: str, contract_id: str) -> bool:
    """
    Check if a call site function_id is compatible with a contract function_id.
    
    ITERATION 479: Handle Django-style placeholders (Model, Manager, QuerySet).
    ITERATION 574: Prevent bare function names from matching module.function calls.
    
    Compatible if:
    1. Exact match: "cursor.execute" == "cursor.execute"
    2. Suffix match: "db.cursor.execute" ends with ".cursor.execute"
       - EXCEPT: bare names like "open" don't match "module.open" (prevents tarfile.open matching "open")
    3. Placeholder match: "login.objects.raw" matches "Model.objects.raw"
       - Django patterns use "Model" as placeholder for any model name
       - Contract "Model.objects.raw" should match "User.objects.raw", "login.objects.raw", etc.
    """
    if call_site_id == contract_id:
        return True
    
    # ITERATION 574: If contract_id is a bare name (no dots), only match exact or builtins.contract_id
    # This prevents "open" from matching "tarfile.open", "zipfile.open", etc.
    if '.' not in contract_id:
        # Bare contract name - only match bare call or builtins.name
        if call_site_id == contract_id:
            return True
        if call_site_id == f"builtins.{contract_id}":
            return True
        # Don't match module.name patterns for bare contract names
        return False
    
    if call_site_id.endswith('.' + contract_id):
        return True
    
    # Handle Django-style placeholders
    # Contract "Model.objects.raw" should match "login.objects.raw"
    if '.' in contract_id:
        contract_parts = contract_id.split('.')
        call_parts = call_site_id.split('.')
        
        # Check if last N parts match, allowing first parts to differ when placeholder
        if len(call_parts) == len(contract_parts):
            # Check from right to left
            for i in range(len(contract_parts) - 1, -1, -1):
                if contract_parts[i] != call_parts[i]:
                    # Mismatch - check if it's a placeholder
                    # Placeholders: Model, Manager, QuerySet (Django), Class (generic)
                    if contract_parts[i] in ('Model', 'Manager', 'QuerySet', 'Class'):
                        # Placeholder can match any identifier
                        continue
                    else:
                        # Real mismatch
                        return False
            return True
    
    return False


def get_sink_contracts(function_id: str) -> List[SinkContract]:
    """
    Get ALL sink contracts for a function.
    
    ITERATION 478: Fixed SSRF false positives by requiring module context matching.
    ITERATION 479: Fixed SQL Injection regression by supporting Django placeholders.
    
    Matching rules:
    1. Exact match: function_id == key (but filter by contract.function_id)
    2. Suffix match: function_id ends with ".key" (but filter by contract.function_id)
    3. Placeholder match: Django "Model.objects.raw" matches "login.objects.raw"
    
    The short name registry (line 178-182) registers "get" for both "requests.get" and "httpx.get".
    This means "item.get" will match via ".get" suffix. We must filter by checking if the
    contract's full function_id is compatible with function_id.
    """
    # Try exact match first
    if function_id in _sink_contracts:
        contracts = _sink_contracts[function_id]
        # ITERATION 478: Filter out contracts where function_id has module context
        # but doesn't match the contract's module context
        # E.g., "item.get" shouldn't match contracts for "requests.get"
        if '.' in function_id:
            # function_id has module context - only return contracts that match it
            filtered = []
            for c in contracts:
                # ITERATION 479: Use _is_compatible_function_id for placeholder support
                if _is_compatible_function_id(function_id, c.function_id):
                    filtered.append(c)
            return filtered
        else:
            # Bare function name - return all contracts
            return contracts
    
    # Try suffix match with module separator
    # E.g., "mymodule.requests.get" matches key "requests.get"
    for key, contracts in _sink_contracts.items():
        if function_id.endswith('.' + key):
            # ITERATION 478/479: Same filtering logic as exact match
            if '.' in function_id:
                filtered = []
                for c in contracts:
                    # ITERATION 479: Use _is_compatible_function_id for placeholder support
                    if _is_compatible_function_id(function_id, c.function_id):
                        filtered.append(c)
                if filtered:
                    return filtered
            else:
                return contracts
    
    # ITERATION 492: Method name match for file-like objects
    # Handle cases like "f.write" matching "file.write" contracts
    # This is needed because local variable names (like "f") don't carry type info
    # ITERATION 604: Also handle bare method names (e.g., "execute" -> "cursor.execute")
    method_name = function_id.split('.')[-1] if '.' in function_id else function_id
    method_contracts = {
        'write': ['file.write', 'io.TextIOWrapper.write', 'io.BufferedWriter.write'],
        'execute': ['cursor.execute', 'sqlite3.Cursor.execute'],
        'executemany': ['cursor.executemany', 'sqlite3.Cursor.executemany'],
        'extractall': ['extractall'],
        # Add more as needed
    }
    if method_name in method_contracts:
        # Try to find contracts for any of the canonical names
        for canonical_name in method_contracts[method_name]:
            if canonical_name in _sink_contracts:
                return _sink_contracts[canonical_name]
    
    return []


def get_sink_contract(function_id: str) -> Optional[SinkContract]:
    """Get first sink contract for a function (for backward compatibility)."""
    contracts = get_sink_contracts(function_id)
    return contracts[0] if contracts else None


def is_security_sink(function_id: str) -> bool:
    """Check if function is a security sink."""
    return len(get_sink_contracts(function_id)) > 0


def get_all_sink_contracts() -> List[SinkContract]:
    """
    Get all registered sink contracts (for all functions).
    
    ITERATION 605: Used to check if any sink type has context-dependent checks.
    """
    all_contracts = []
    for contracts_list in _sink_contracts.values():
        all_contracts.extend(contracts_list)
    return all_contracts


def check_sink_taint(
    function_id: str,
    location: str,
    arg_labels: List[TaintLabel],
    kwargs: Dict = None,
    receiver_label: Optional[TaintLabel] = None,
    path_validation_tracker: Optional[Any] = None,
    args: Optional[List[Any]] = None
) -> List[SecurityViolation]:
    """
    Check if calling a sink with tainted arguments is a security violation.
    
    Args:
        function_id: Name of the function being called
        location: Source location
        arg_labels: Taint labels for the arguments
        kwargs: Keyword arguments (for context-dependent checks)
        receiver_label: Taint label for the receiver object (for method calls)
        path_validation_tracker: PathValidationTracker instance (for barrier certificate checking)
        args: Original argument values (for checking path validation guards)
    
    Returns list of SecurityViolations (may be empty, may contain multiple for multi-sink functions).
    NOTE: Checks ALL registered contracts for the function (supports multiple sink types).
    """
    import os
    TAINT_DEBUG = os.environ.get('TAINT_DEBUG') == '1'
    
    contracts = get_sink_contracts(function_id)
    if not contracts:
        return []
    
    if TAINT_DEBUG:
        print(f"[SINK CHECK] check_sink_taint for {function_id}")
        print(f"             Found {len(contracts)} contracts")
        for c in contracts:
            print(f"             - {c.bug_type}: sink_type={c.sink_type}, args={c.tainted_arg_indices}, check_receiver={c.check_receiver}")
    
    kwargs = kwargs or {}
    violations = []
    
    # Check each contract (function can have multiple sink types)
    for contract in contracts:
        # Context-dependent safety checks
        if contract.parameterized_check:
            # SQL: safe if second argument (params) is provided
            # The presence of a params argument indicates parameterization,
            # which separates tainted data from the query structure
            if TAINT_DEBUG:
                print(f"[PARAMETERIZED CHECK] {function_id}: len(arg_labels)={len(arg_labels)}, contract.parameterized_check=True")
                for i, label in enumerate(arg_labels):
                    print(f"  arg[{i}]: {label}")
            if len(arg_labels) > 1:
                if TAINT_DEBUG:
                    print(f"[PARAMETERIZED CHECK] Skipping - parameterized query detected")
                continue  # Parameterized query, safe for this contract
        
        if contract.shell_check:
            # Subprocess: only dangerous if shell=True
            # ITERATION 558: Extract actual boolean value from SymbolicValue
            # BOOL values use IntVal(0) or IntVal(1) payloads, not BoolRef
            shell_value = kwargs.get('shell', False)
            
            # Handle SymbolicValue objects
            if hasattr(shell_value, 'tag') and hasattr(shell_value, 'payload'):
                from a3_python.z3model.values import ValueTag
                if shell_value.tag == ValueTag.BOOL:
                    # Extract concrete boolean from Z3 IntVal payload
                    import z3
                    
                    # BOOL payloads are IntVal(0) for False, IntVal(1) for True
                    if isinstance(shell_value.payload, (z3.IntNumRef, z3.ArithRef)):
                        try:
                            int_val = shell_value.payload.as_long() if hasattr(shell_value.payload, 'as_long') else None
                            if int_val is not None:
                                shell_value = bool(int_val)
                            else:
                                # Symbolic integer - conservatively treat as potentially True
                                # (must report bug if shell could be True)
                                shell_value = True
                        except:
                            # Can't extract concrete value - treat as potentially True
                            shell_value = True
                    elif isinstance(shell_value.payload, z3.BoolRef):
                        # Also handle BoolRef for backward compatibility
                        if z3.is_true(shell_value.payload):
                            shell_value = True
                        elif z3.is_false(shell_value.payload):
                            shell_value = False
                        else:
                            # Symbolic boolean - conservatively treat as potentially True
                            shell_value = True
                    else:
                        # Unknown payload type - conservatively treat as potentially True
                        shell_value = True
            
            # Skip this contract if shell is False or missing
            if not shell_value:
                continue  # shell=False, safe for this contract
        
        if contract.loader_check:
            # YAML: safe if Loader is SafeLoader or FullLoader
            # Loader can be in kwargs (yaml.load(data, Loader=yaml.SafeLoader))
            # or as positional arg[1] (yaml.load(data, yaml.SafeLoader))
            loader = kwargs.get('Loader')
            
            # If no Loader in kwargs but yaml.load has 2+ args, check args[1]
            # yaml.load(stream, Loader=None) signature means args[1] is the Loader
            if not loader and function_id == 'yaml.load' and len(arg_labels) >= 2:
                # Positional Loader argument - need to determine if it's safe
                # Since we can't easily determine the actual value at this point,
                # we conservatively treat it as UNSAFE unless explicitly safe
                # (this matches CodeQL's behavior: yaml.load with ANY Loader is flagged)
                # Continue means "not a violation" - so we DON'T continue here
                # (i.e., we treat positional Loader as potentially unsafe)
                pass  # Fall through to violation check
            elif loader in ('SafeLoader', 'FullLoader', 'yaml.SafeLoader'):
                continue  # Explicit safe Loader - skip this contract
        
        if contract.entity_check:
            # XML: safe if forbid_dtd=True or resolve_entities=False
            if kwargs.get('forbid_dtd') or not kwargs.get('resolve_entities', True):
                continue
        
        # ITERATION 497: Get bug type definition to check which taint type matters
        bug_type_def = CODEQL_BUG_TYPES.get(contract.bug_type)
        checks_tau = bug_type_def.checks_tau if bug_type_def else True
        checks_sigma = bug_type_def.checks_sigma if bug_type_def else False
        
        # Check tainted arguments
        for idx in contract.tainted_arg_indices:
            if idx < len(arg_labels):
                label = arg_labels[idx]
                
                # SOURCE VALIDATION (Iteration 497): Only report violations if:
                # 1. Value has the APPROPRIATE taint type (τ if checks_tau, σ if checks_sigma), AND
                # 2. Value is not safe for sink (not sanitized)
                has_relevant_taint = False
                if checks_tau and label.has_untrusted_taint():
                    has_relevant_taint = True
                if checks_sigma and label.has_sensitivity():
                    has_relevant_taint = True
                
                is_safe = label.is_safe_for_sink(contract.sink_type)
                
                if TAINT_DEBUG:
                    print(f"             Checking arg[{idx}] for {contract.bug_type}")
                    print(f"               sink_type={contract.sink_type} ({contract.sink_type.name})")
                    print(f"               checks_tau={checks_tau}, checks_sigma={checks_sigma}")
                    print(f"               label: τ={bin(label.tau)} σ={bin(label.sigma)} κ={bin(label.kappa)}")
                    print(f"               has_relevant_taint? {has_relevant_taint}")
                    print(f"               is_safe_for_sink? {is_safe}")
                
                # ITERATION 524: Require concrete taint path (provenance not empty)
                # Only report if tainted AND unsafe AND has provenance (not generic sink detection)
                has_provenance = bool(label.provenance)
                
                # ITERATION 586: Path validation guard checking for FILE_PATH sinks
                # Check if this value has a validation guard (e.g., startswith check)
                is_path_validated = False
                if contract.sink_type in (SinkType.FILE_PATH, SinkType.FILE_WRITE):
                    if path_validation_tracker is not None and args is not None and idx < len(args):
                        # Check if the actual argument value has been validated
                        arg_value = args[idx]
                        is_path_validated = path_validation_tracker.is_validated(arg_value, contract.sink_type)
                        
                        if TAINT_DEBUG and is_path_validated:
                            print(f"             Path validation guard found for arg[{idx}]!")
                            print(f"               Guard protects against {contract.sink_type.name}")
                
                if has_relevant_taint and not is_safe and has_provenance and not is_path_validated:
                    if TAINT_DEBUG:
                        print(f"             *** VIOLATION: {contract.bug_type} ***")
                        print(f"               provenance: {label.provenance}")
                    violations.append(create_violation(contract.bug_type, location, label))
                elif TAINT_DEBUG:
                    if not has_relevant_taint:
                        print(f"             No violation: no relevant taint (checks_tau={checks_tau}, checks_sigma={checks_sigma})")
                    elif not has_provenance:
                        print(f"             No violation: no concrete provenance (generic sink, no actual taint path)")
                    elif is_path_validated:
                        print(f"             No violation: path validated via guard")
                    else:
                        print(f"             No violation: sanitized (k ∈ κ)")
        
        # ITERATION 559: Check tainted kwargs (by name)
        # For functions like tarfile.extractall(path=user_input), check kwargs
        if contract.tainted_kwarg_names and kwargs:
            for kwarg_name in contract.tainted_kwarg_names:
                if kwarg_name in kwargs:
                    kwarg_value = kwargs[kwarg_name]
                    
                    # Get label for the kwarg value
                    # The caller should have converted kwargs to labels already
                    if not isinstance(kwarg_value, TaintLabel):
                        # Skip - unexpected, but fail gracefully
                        if TAINT_DEBUG:
                            print(f"             WARNING: kwarg '{kwarg_name}' is not a TaintLabel, got {type(kwarg_value)}")
                        continue
                    
                    label = kwarg_value
                    
                    # Same checks as positional args
                    has_relevant_taint = False
                    if checks_tau and label.has_untrusted_taint():
                        has_relevant_taint = True
                    if checks_sigma and label.has_sensitivity():
                        has_relevant_taint = True
                    
                    is_safe = label.is_safe_for_sink(contract.sink_type)
                    has_provenance = bool(label.provenance)
                    
                    if TAINT_DEBUG:
                        print(f"             Checking kwarg '{kwarg_name}' for {contract.bug_type}")
                        print(f"               sink_type={contract.sink_type} ({contract.sink_type.name})")
                        print(f"               checks_tau={checks_tau}, checks_sigma={checks_sigma}")
                        print(f"               label: τ={bin(label.tau)} σ={bin(label.sigma)} κ={bin(label.kappa)}")
                        print(f"               has_relevant_taint? {has_relevant_taint}")
                        print(f"               is_safe_for_sink? {is_safe}")
                        print(f"               has_provenance? {has_provenance}")
                    
                    if has_relevant_taint and not is_safe and has_provenance:
                        if TAINT_DEBUG:
                            print(f"             *** VIOLATION on kwarg '{kwarg_name}': {contract.bug_type} ***")
                            print(f"               provenance: {label.provenance}")
                        violations.append(create_violation(contract.bug_type, location, label))
                    elif TAINT_DEBUG:
                        if not has_relevant_taint:
                            print(f"             No violation: no relevant taint")
                        elif not has_provenance:
                            print(f"             No violation: no concrete provenance")
                        else:
                            print(f"             No violation: sanitized")
        
        # ITERATION 526: Check receiver taint for method calls
        # If check_receiver is True, check if the receiver object (self) is tainted
        # For method calls, receiver_label should be provided by the caller
        if contract.check_receiver and receiver_label is not None:
            # Get bug type definition to check which taint type matters
            bug_type_def = CODEQL_BUG_TYPES.get(contract.bug_type)
            checks_tau = bug_type_def.checks_tau if bug_type_def else True
            checks_sigma = bug_type_def.checks_sigma if bug_type_def else False
            
            # Check if receiver has relevant taint
            has_relevant_taint = False
            if checks_tau and receiver_label.has_untrusted_taint():
                has_relevant_taint = True
            if checks_sigma and receiver_label.has_sensitivity():
                has_relevant_taint = True
            
            is_safe = receiver_label.is_safe_for_sink(contract.sink_type)
            has_provenance = bool(receiver_label.provenance)
            
            if TAINT_DEBUG:
                print(f"             Checking RECEIVER for {contract.bug_type}")
                print(f"               sink_type={contract.sink_type} ({contract.sink_type.name})")
                print(f"               checks_tau={checks_tau}, checks_sigma={checks_sigma}")
                print(f"               receiver: τ={bin(receiver_label.tau)} σ={bin(receiver_label.sigma)} κ={bin(receiver_label.kappa)}")
                print(f"               has_relevant_taint? {has_relevant_taint}")
                print(f"               is_safe_for_sink? {is_safe}")
                print(f"               has_provenance? {has_provenance}")
            
            if has_relevant_taint and not is_safe and has_provenance:
                if TAINT_DEBUG:
                    print(f"             *** VIOLATION ON RECEIVER: {contract.bug_type} ***")
                    print(f"               provenance: {receiver_label.provenance}")
                violations.append(create_violation(contract.bug_type, location, receiver_label))
            elif TAINT_DEBUG:
                if not has_relevant_taint:
                    print(f"             No violation: receiver has no relevant taint")
                elif not has_provenance:
                    print(f"             No violation: receiver has no concrete provenance")
                else:
                    print(f"             No violation: receiver is sanitized (k ∈ κ)")
        
        # Also check if any argument is tainted (conservative)
        # NOTE: Only do this if NOT check_receiver (to avoid double-checking)
        if not contract.tainted_arg_indices and not contract.check_receiver:
            merged = label_join_many(arg_labels)
            
            # SOURCE VALIDATION (Iteration 497): Only report if has relevant taint AND unsafe
            has_relevant_taint = False
            if checks_tau and merged.has_untrusted_taint():
                has_relevant_taint = True
            if checks_sigma and merged.has_sensitivity():
                has_relevant_taint = True
            
            is_safe = merged.is_safe_for_sink(contract.sink_type)
            
            if TAINT_DEBUG:
                print(f"             Checking merged args for {contract.bug_type}")
                print(f"               sink_type={contract.sink_type} ({contract.sink_type.name})")
                print(f"               checks_tau={checks_tau}, checks_sigma={checks_sigma}")
                print(f"               merged: τ={bin(merged.tau)} σ={bin(merged.sigma)} κ={bin(merged.kappa)}")
                print(f"               has_relevant_taint? {has_relevant_taint}")
                print(f"               is_safe_for_sink? {is_safe}")
            
            # ITERATION 524: Require concrete taint path (provenance not empty)
            # Only report if tainted AND unsafe AND has provenance
            has_provenance = bool(merged.provenance)
            
            if has_relevant_taint and not is_safe and has_provenance:
                if TAINT_DEBUG:
                    print(f"             *** VIOLATION: {contract.bug_type} ***")
                    print(f"               provenance: {merged.provenance}")
                violations.append(create_violation(contract.bug_type, location, merged))
            elif TAINT_DEBUG:
                if not has_relevant_taint:
                    print(f"             No violation: no relevant taint")
                elif not has_provenance:
                    print(f"             No violation: no concrete provenance (generic sink, no actual taint path)")
                else:
                    print(f"             No violation: sanitized")
    
    return violations


def create_sink_unsafe_constraint(
    function_id: str,
    arg_labels: List[SymbolicTaintLabel]
) -> Optional[z3.BoolRef]:
    """
    Create Z3 constraint for sink unsafety (for symbolic reasoning).
    
    Returns constraint that is SAT iff the sink call is unsafe.
    NOTE: Checks ALL registered contracts for the function (supports multiple sink types).
    """
    contracts = get_sink_contracts(function_id)
    if not contracts:
        return None
    
    # Collect constraints from all contracts
    all_constraints = []
    
    for contract in contracts:
        bug_type = CODEQL_BUG_TYPES.get(contract.bug_type)
        if bug_type is None:
            continue
        
        # Get label(s) to check
        if contract.tainted_arg_indices:
            labels_to_check = [arg_labels[i] for i in contract.tainted_arg_indices if i < len(arg_labels)]
        else:
            labels_to_check = arg_labels
        
        if not labels_to_check:
            continue
        
        # Create unsafety constraint for this contract: any checked arg is unsafe
        constraints = []
        for label in labels_to_check:
            constraints.append(label.is_unsafe_for_sink_constraint(contract.sink_type))
        
        if constraints:
            all_constraints.append(z3.Or(*constraints))
    
    # Return OR of all contracts (any violation is a bug)
    return z3.Or(*all_constraints) if all_constraints else None


# ============================================================================
# SANITIZER CONTRACTS
# ============================================================================

@dataclass(frozen=True)
class SanitizerContract:
    """
    Contract for a sanitizer function.
    
    Specifies which sink types become safe after applying this sanitizer.
    """
    function_id: str              # e.g., "shlex.quote"
    sanitizer_type: SanitizerType
    applicable_sinks: FrozenSet[SinkType] = field(default_factory=frozenset)
    
    # For declassification (sensitivity sanitizers)
    clears_sensitivity: bool = False  # If True, also clears σ
    
    description: str = ""


# Registry of sanitizer contracts
_sanitizer_contracts: Dict[str, SanitizerContract] = {}


def register_sanitizer(contract: SanitizerContract) -> None:
    """Register a sanitizer contract."""
    _sanitizer_contracts[contract.function_id] = contract
    if "." in contract.function_id:
        short_name = contract.function_id.split(".")[-1]
        if short_name not in _sanitizer_contracts:
            _sanitizer_contracts[short_name] = contract


def get_sanitizer_contract(function_id: str) -> Optional[SanitizerContract]:
    """
    Get sanitizer contract for a function.
    
    ITERATION 478: Fixed false positives by checking contract.function_id compatibility.
    ITERATION 479: Fixed SQL Injection regression by supporting Django placeholders.
    
    Matching rules:
    1. Exact match: function_id == key (but check contract.function_id)
    2. Suffix match: function_id ends with ".key" (but check contract.function_id)
    3. Placeholder match: Django patterns (uses _is_compatible_function_id)
    """
    if function_id in _sanitizer_contracts:
        contract = _sanitizer_contracts[function_id]
        # ITERATION 479: Use _is_compatible_function_id for placeholder support
        if '.' in function_id:
            if _is_compatible_function_id(function_id, contract.function_id):
                return contract
            else:
                pass  # Try suffix matching below
        else:
            return contract
    
    # Try suffix match with module separator
    for key, contract in _sanitizer_contracts.items():
        if function_id.endswith('.' + key):
            # ITERATION 479: Use _is_compatible_function_id for placeholder support
            if '.' in function_id:
                if _is_compatible_function_id(function_id, contract.function_id):
                    return contract
            else:
                return contract
    
    return None


def is_sanitizer(function_id: str) -> bool:
    """Check if function is a sanitizer."""
    return get_sanitizer_contract(function_id) is not None


def apply_sanitizer(
    function_id: str,
    input_label: TaintLabel
) -> TaintLabel:
    """
    Apply a sanitizer to a tainted value.
    
    Adds the appropriate sink types to κ (sanitized set).
    """
    contract = get_sanitizer_contract(function_id)
    if contract is None:
        return input_label
    
    # Get sinks from contract or from the sanitizer type mapping
    sinks = contract.applicable_sinks
    if not sinks:
        sinks = SANITIZER_TO_SINKS.get(contract.sanitizer_type, frozenset())
    
    # Apply sanitization by setting kappa bits for the specific sinks
    new_kappa = input_label.kappa
    for sink in sinks:
        new_kappa |= (1 << sink)
    
    result = TaintLabel(
        tau=input_label.tau,
        kappa=new_kappa,
        sigma=input_label.sigma,
        provenance=input_label.provenance
    )
    
    # Handle declassification
    if contract.clears_sensitivity:
        result = TaintLabel(
            tau=result.tau,
            kappa=result.kappa,
            sigma=0,  # Clear sensitivity
            provenance=result.provenance
        )
    
    return result


def apply_sanitizer_symbolic(
    function_id: str,
    input_label: SymbolicTaintLabel
) -> SymbolicTaintLabel:
    """
    Apply a sanitizer to a symbolic tainted value.
    """
    contract = get_sanitizer_contract(function_id)
    if contract is None:
        return input_label
    
    sinks = contract.applicable_sinks
    if not sinks:
        sinks = SANITIZER_TO_SINKS.get(contract.sanitizer_type, frozenset())
    
    result = input_label.sanitize_many(sinks)
    
    if contract.clears_sensitivity:
        result = SymbolicTaintLabel(
            tau=result.tau,
            kappa=result.kappa,
            sigma=sigma_zero()
        )
    
    return result


# ============================================================================
# CONTRACT INITIALIZATION
# ============================================================================

_contracts_initialized = False


def init_security_contracts() -> None:
    """Initialize all security contracts."""
    global _contracts_initialized
    if _contracts_initialized:
        return
    
    _init_source_contracts()
    _init_sink_contracts()
    _init_sanitizer_contracts()
    _contracts_initialized = True


def _init_source_contracts() -> None:
    """Register all taint source contracts."""
    
    # ===== HTTP/Web Sources (τ) =====
    
    # Django
    # HTTP parameters with sensitivity inference from argument names
    _sensitive_param_patterns = frozenset(['PASS', 'PASSWORD', 'PWD', 'SECRET', 'TOKEN', 'KEY', 'API_KEY', 'AUTH', 'CREDENTIAL'])
    
    # Register the attribute accesses themselves (request.POST, request.GET)
    # These return tainted dictionary-like objects
    register_source(SourceContract(
        "request.GET", SourceType.HTTP_PARAM,
        description="Django GET parameters (dict-like)"
    ))
    register_source(SourceContract(
        "request.POST", SourceType.HTTP_PARAM,
        description="Django POST parameters (dict-like)"
    ))
    register_source(SourceContract(
        "request.COOKIES", SourceType.COOKIE,
        description="Django COOKIES (dict-like)"
    ))
    register_source(SourceContract(
        "request.FILES", SourceType.FILE_CONTENT,
        description="Django uploaded FILES (dict-like)"
    ))
    
    for method in ["__getitem__", "get", "getlist"]:
        register_source(SourceContract(
            f"request.GET.{method}", SourceType.HTTP_PARAM,
            description=f"Django GET parameter ({method})",
            sensitive_arg_patterns=_sensitive_param_patterns
        ))
        register_source(SourceContract(
            f"request.POST.{method}", SourceType.HTTP_PARAM,
            description=f"Django POST parameter ({method})",
            sensitive_arg_patterns=_sensitive_param_patterns
        ))
        register_source(SourceContract(
            f"request.COOKIES.{method}", SourceType.COOKIE,
            description=f"Django COOKIE value ({method})",
            sensitive_arg_patterns=_sensitive_param_patterns
        ))
        register_source(SourceContract(
            f"request.FILES.{method}", SourceType.FILE_CONTENT,
            description=f"Django uploaded FILE ({method})",
            sensitive_arg_patterns=_sensitive_param_patterns
        ))
    
    register_source(SourceContract(
        "request.body", SourceType.HTTP_PARAM,
        description="Django raw request body"
    ))
    register_source(SourceContract(
        "request.path", SourceType.HTTP_PARAM,
        description="Django request path"
    ))
    register_source(SourceContract(
        "request.META.get", SourceType.HEADER,
        description="Django request header"
    ))
    
    # Flask
    # Register the attribute accesses themselves (request.args, request.form, etc.)
    register_source(SourceContract(
        "request.args", SourceType.HTTP_PARAM,
        description="Flask query parameters (dict-like)"
    ))
    register_source(SourceContract(
        "request.form", SourceType.HTTP_PARAM,
        description="Flask form parameters (dict-like)"
    ))
    
    for method in ["__getitem__", "get", "getlist"]:
        register_source(SourceContract(
            f"request.args.{method}", SourceType.HTTP_PARAM,
            description=f"Flask query parameter ({method})",
            sensitive_arg_patterns=_sensitive_param_patterns
        ))
        register_source(SourceContract(
            f"request.form.{method}", SourceType.HTTP_PARAM,
            description=f"Flask form parameter ({method})",
            sensitive_arg_patterns=_sensitive_param_patterns
        ))
    
    register_source(SourceContract(
        "request.get_json", SourceType.HTTP_PARAM,
        description="Flask JSON body"
    ))
    register_source(SourceContract(
        "request.data", SourceType.HTTP_PARAM,
        description="Flask raw request data"
    ))
    register_source(SourceContract(
        "request.cookies.get", SourceType.COOKIE,
        description="Flask cookie value"
    ))
    register_source(SourceContract(
        "request.headers.get", SourceType.HEADER,
        description="Flask request header"
    ))
    
    # FastAPI
    register_source(SourceContract(
        "Query", SourceType.HTTP_PARAM,
        description="FastAPI query parameter"
    ))
    register_source(SourceContract(
        "Form", SourceType.HTTP_PARAM,
        description="FastAPI form parameter"
    ))
    register_source(SourceContract(
        "Body", SourceType.HTTP_PARAM,
        description="FastAPI body parameter"
    ))
    register_source(SourceContract(
        "Path", SourceType.HTTP_PARAM,
        description="FastAPI path parameter"
    ))
    register_source(SourceContract(
        "Header", SourceType.HEADER,
        description="FastAPI header parameter"
    ))
    register_source(SourceContract(
        "Cookie", SourceType.COOKIE,
        description="FastAPI cookie parameter"
    ))
    
    # FastAPI dependency injection - Request object
    register_source(SourceContract(
        "fastapi.Request.query_params", SourceType.HTTP_PARAM,
        description="FastAPI Request.query_params"
    ))
    register_source(SourceContract(
        "fastapi.Request.headers", SourceType.HEADER,
        description="FastAPI Request.headers"
    ))
    register_source(SourceContract(
        "fastapi.Request.cookies", SourceType.COOKIE,
        description="FastAPI Request.cookies"
    ))
    register_source(SourceContract(
        "fastapi.Request.body", SourceType.HTTP_PARAM,
        description="FastAPI Request.body"
    ))
    register_source(SourceContract(
        "fastapi.Request.json", SourceType.HTTP_PARAM,
        description="FastAPI Request.json"
    ))
    register_source(SourceContract(
        "fastapi.Request.form", SourceType.HTTP_PARAM,
        description="FastAPI Request.form"
    ))
    
    # Starlette (underlying FastAPI)
    register_source(SourceContract(
        "starlette.requests.Request.query_params", SourceType.HTTP_PARAM,
        description="Starlette Request.query_params"
    ))
    register_source(SourceContract(
        "starlette.requests.Request.headers", SourceType.HEADER,
        description="Starlette Request.headers"
    ))
    register_source(SourceContract(
        "starlette.requests.Request.cookies", SourceType.COOKIE,
        description="Starlette Request.cookies"
    ))
    
    # ===== Django Additional Patterns =====
    
    # Django session
    register_source(SourceContract(
        "request.session.get", SourceType.SESSION_TOKEN,
        is_sensitive=True,
        description="Django session value",
        sensitive_arg_patterns=_sensitive_param_patterns
    ))
    register_source(SourceContract(
        "request.session.__getitem__", SourceType.SESSION_TOKEN,
        is_sensitive=True,
        description="Django session value (subscript)",
        sensitive_arg_patterns=_sensitive_param_patterns
    ))
    
    # Django user input from models
    register_source(SourceContract(
        "request.user.username", SourceType.USER_INPUT,
        description="Django authenticated user username"
    ))
    register_source(SourceContract(
        "request.user.email", SourceType.USER_INPUT,
        description="Django authenticated user email"
    ))
    
    # Django QueryDict methods
    register_source(SourceContract(
        "request.GET.dict", SourceType.HTTP_PARAM,
        description="Django GET as dict"
    ))
    register_source(SourceContract(
        "request.POST.dict", SourceType.HTTP_PARAM,
        description="Django POST as dict"
    ))
    
    # ===== Flask Additional Patterns =====
    
    # Flask session
    register_source(SourceContract(
        "flask.session.get", SourceType.SESSION_TOKEN,
        is_sensitive=True,
        description="Flask session value",
        sensitive_arg_patterns=_sensitive_param_patterns
    ))
    register_source(SourceContract(
        "flask.session.__getitem__", SourceType.SESSION_TOKEN,
        is_sensitive=True,
        description="Flask session value (subscript)",
        sensitive_arg_patterns=_sensitive_param_patterns
    ))
    
    # Flask view_args (URL parameters from routing)
    register_source(SourceContract(
        "request.view_args", SourceType.HTTP_PARAM,
        description="Flask URL route parameters"
    ))
    register_source(SourceContract(
        "request.view_args.get", SourceType.HTTP_PARAM,
        description="Flask URL route parameter"
    ))
    
    # Flask file uploads
    register_source(SourceContract(
        "request.files", SourceType.FILE_CONTENT,
        description="Flask uploaded files"
    ))
    register_source(SourceContract(
        "request.files.get", SourceType.FILE_CONTENT,
        description="Flask uploaded file"
    ))
    
    # ===== Pytest Fixtures =====
    
    # Pytest fixtures that provide user input / external data
    # These are taint sources when testing web applications
    
    register_source(SourceContract(
        "pytest.fixture.request.param", SourceType.HTTP_PARAM,
        description="Pytest parametrize fixture value"
    ))
    
    # Common pytest-django fixtures
    register_source(SourceContract(
        "client.get", SourceType.HTTP_PARAM,
        description="Pytest-django test client GET"
    ))
    register_source(SourceContract(
        "client.post", SourceType.HTTP_PARAM,
        description="Pytest-django test client POST"
    ))
    
    # Pytest-flask fixtures
    register_source(SourceContract(
        "test_client.get", SourceType.HTTP_PARAM,
        description="Pytest-flask test client GET"
    ))
    register_source(SourceContract(
        "test_client.post", SourceType.HTTP_PARAM,
        description="Pytest-flask test client POST"
    ))
    
    # Environment variable fixtures (common in tests)
    register_source(SourceContract(
        "monkeypatch.setenv", SourceType.ENVIRONMENT,
        description="Pytest monkeypatch environment variable"
    ))
    
    # Temporary file fixtures (file content from tests)
    register_source(SourceContract(
        "tmp_path.read_text", SourceType.FILE_CONTENT,
        description="Pytest tmp_path file content"
    ))
    register_source(SourceContract(
        "tmp_path.read_bytes", SourceType.FILE_CONTENT,
        description="Pytest tmp_path file content"
    ))
    
    # ===== User Input Sources (τ) =====
    
    register_source(SourceContract(
        "builtins.input", SourceType.USER_INPUT,
        description="User console input"
    ))
    register_source(SourceContract(
        "input", SourceType.USER_INPUT,
        description="User console input"
    ))
    register_source(SourceContract(
        "sys.stdin.read", SourceType.USER_INPUT,
        description="Standard input read"
    ))
    register_source(SourceContract(
        "sys.stdin.readline", SourceType.USER_INPUT,
        description="Standard input readline"
    ))
    register_source(SourceContract(
        "sys.stdin.readlines", SourceType.USER_INPUT,
        description="Standard input readlines"
    ))
    
    # ===== Environment Sources (τ, but can be σ for secrets) =====
    
    register_source(SourceContract(
        "os.environ.__getitem__", SourceType.ENVIRONMENT,
        sensitive_arg_patterns=frozenset({"KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL"}),
        description="Environment variable"
    ))
    register_source(SourceContract(
        "os.environ.get", SourceType.ENVIRONMENT,
        sensitive_arg_patterns=frozenset({"KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL"}),
        description="Environment variable (with default)"
    ))
    register_source(SourceContract(
        "os.getenv", SourceType.ENVIRONMENT,
        sensitive_arg_patterns=frozenset({"KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL"}),
        description="Environment variable"
    ))
    
    # ===== Command Line Sources (τ) =====
    
    register_source(SourceContract(
        "sys.argv.__getitem__", SourceType.ARGV,
        description="Command line argument"
    ))
    register_source(SourceContract(
        "argparse.ArgumentParser.parse_args", SourceType.ARGV,
        description="Parsed command line arguments"
    ))
    
    # ===== File Content Sources (τ) =====
    
    for method in ["read", "readline", "readlines"]:
        register_source(SourceContract(
            f"file.{method}", SourceType.FILE_CONTENT,
            description=f"File content {method}"
        ))
    
    register_source(SourceContract(
        "pathlib.Path.read_text", SourceType.FILE_CONTENT,
        description="Path read_text"
    ))
    register_source(SourceContract(
        "pathlib.Path.read_bytes", SourceType.FILE_CONTENT,
        description="Path read_bytes"
    ))
    
    # ===== Network Sources (τ) =====
    
    register_source(SourceContract(
        "socket.recv", SourceType.NETWORK_RECV,
        description="Socket receive"
    ))
    register_source(SourceContract(
        "socket.recvfrom", SourceType.NETWORK_RECV,
        description="Socket receive with address"
    ))
    register_source(SourceContract(
        "urllib.request.urlopen", SourceType.NETWORK_RECV,
        description="URL content fetch"
    ))
    register_source(SourceContract(
        "requests.get", SourceType.NETWORK_RECV,
        description="HTTP GET response"
    ))
    register_source(SourceContract(
        "requests.post", SourceType.NETWORK_RECV,
        description="HTTP POST response"
    ))
    register_source(SourceContract(
        "httpx.get", SourceType.NETWORK_RECV,
        description="HTTPX GET response"
    ))
    register_source(SourceContract(
        "httpx.post", SourceType.NETWORK_RECV,
        description="HTTPX POST response"
    ))
    
    # ===== Database Sources (τ) =====
    
    for method in ["fetchone", "fetchall", "fetchmany"]:
        register_source(SourceContract(
            f"cursor.{method}", SourceType.DATABASE_RESULT,
            description=f"Database {method}"
        ))
    
    # ===== ORM Sources (τ) - Django ORM =====
    # Django QuerySet methods that return data from database
    # These inherit taint from the model/manager they're called on
    
    for method in ["all", "filter", "get", "first", "last", "earliest", "latest"]:
        register_source(SourceContract(
            f"Model.objects.{method}", SourceType.DATABASE_RESULT,
            description=f"Django ORM {method}"
        ))
        register_source(SourceContract(
            f"QuerySet.{method}", SourceType.DATABASE_RESULT,
            description=f"Django QuerySet {method}"
        ))
        register_source(SourceContract(
            f"Manager.{method}", SourceType.DATABASE_RESULT,
            description=f"Django Manager {method}"
        ))
    
    # Django QuerySet iteration and slicing
    register_source(SourceContract(
        "QuerySet.__iter__", SourceType.DATABASE_RESULT,
        description="Django QuerySet iteration"
    ))
    register_source(SourceContract(
        "QuerySet.__getitem__", SourceType.DATABASE_RESULT,
        description="Django QuerySet indexing"
    ))
    
    # Django values/values_list that return dictionaries
    for method in ["values", "values_list"]:
        register_source(SourceContract(
            f"QuerySet.{method}", SourceType.DATABASE_RESULT,
            description=f"Django QuerySet {method}"
        ))
    
    # Django aggregation methods
    for method in ["count", "aggregate", "annotate"]:
        register_source(SourceContract(
            f"QuerySet.{method}", SourceType.DATABASE_RESULT,
            description=f"Django QuerySet {method}"
        ))
    
    # ===== ORM Sources (τ) - SQLAlchemy =====
    # SQLAlchemy query execution methods
    
    for method in ["all", "first", "one", "one_or_none", "scalar", "scalars"]:
        register_source(SourceContract(
            f"Query.{method}", SourceType.DATABASE_RESULT,
            description=f"SQLAlchemy Query {method}"
        ))
    
    # SQLAlchemy session query result iteration
    register_source(SourceContract(
        "Query.__iter__", SourceType.DATABASE_RESULT,
        description="SQLAlchemy Query iteration"
    ))
    
    # SQLAlchemy Result object (v2.0 API)
    for method in ["all", "first", "one", "one_or_none", "scalar", "scalars", "fetchone", "fetchall", "fetchmany"]:
        register_source(SourceContract(
            f"Result.{method}", SourceType.DATABASE_RESULT,
            description=f"SQLAlchemy Result {method}"
        ))
    
    # SQLAlchemy session.execute returns Result
    register_source(SourceContract(
        "Session.execute", SourceType.DATABASE_RESULT,
        description="SQLAlchemy session execute"
    ))
    
    # ===== Sensitive Sources (σ) =====
    
    register_source(SourceContract(
        "getpass.getpass", SourceType.PASSWORD,
        is_sensitive=True,
        description="Password input"
    ))
    register_source(SourceContract(
        "keyring.get_password", SourceType.CREDENTIALS,
        is_sensitive=True,
        description="Keyring credential"
    ))
    register_source(SourceContract(
        "keyring.get_credential", SourceType.CREDENTIALS,
        is_sensitive=True,
        description="Keyring credential"
    ))
    register_source(SourceContract(
        "secrets.token_bytes", SourceType.CRYPTO_KEY,
        is_sensitive=True,
        description="Cryptographic secret"
    ))
    register_source(SourceContract(
        "secrets.token_hex", SourceType.CRYPTO_KEY,
        is_sensitive=True,
        description="Cryptographic secret"
    ))
    register_source(SourceContract(
        "secrets.token_urlsafe", SourceType.SESSION_TOKEN,
        is_sensitive=True,
        description="Session token"
    ))
    register_source(SourceContract(
        "cryptography.fernet.Fernet.generate_key", SourceType.CRYPTO_KEY,
        is_sensitive=True,
        description="Fernet encryption key"
    ))


def _init_sink_contracts() -> None:
    """Register all security sink contracts."""
    
    # ===== SQL Injection Sinks =====
    
    register_sink(SinkContract(
        "cursor.execute", SinkType.SQL_EXECUTE, "SQL_INJECTION",
        tainted_arg_indices=frozenset({0}),
        parameterized_check=True,
        check_receiver=True,  # ITERATION 532: Check if cursor/connection is tainted
        description="SQL query execution"
    ))
    register_sink(SinkContract(
        "cursor.executemany", SinkType.SQL_EXECUTE, "SQL_INJECTION",
        tainted_arg_indices=frozenset({0}),
        parameterized_check=True,
        check_receiver=True,  # ITERATION 532: Check if cursor is tainted
        description="SQL batch execution"
    ))
    register_sink(SinkContract(
        "connection.execute", SinkType.SQL_EXECUTE, "SQL_INJECTION",
        tainted_arg_indices=frozenset({0}),
        parameterized_check=True,
        check_receiver=True,  # ITERATION 532: Check if connection is tainted
        description="SQLAlchemy execute"
    ))
    register_sink(SinkContract(
        "engine.execute", SinkType.SQL_EXECUTE, "SQL_INJECTION",
        tainted_arg_indices=frozenset({0}),
        check_receiver=True,  # ITERATION 532: Check if engine is tainted
        description="SQLAlchemy engine execute"
    ))
    register_sink(SinkContract(
        "Model.objects.raw", SinkType.SQL_EXECUTE, "SQL_INJECTION",
        tainted_arg_indices=frozenset({0}),
        parameterized_check=True,
        check_receiver=True,  # ITERATION 532: Check if Model/Manager is tainted
        description="Django raw SQL"
    ))
    register_sink(SinkContract(
        "Model.objects.extra", SinkType.SQL_EXECUTE, "SQL_INJECTION",
        tainted_arg_indices=frozenset({0}),
        description="Django extra SQL"
    ))
    
    # ===== Command Injection Sinks =====
    
    register_sink(SinkContract(
        "os.system", SinkType.COMMAND_SHELL, "COMMAND_INJECTION",
        tainted_arg_indices=frozenset({0}),
        description="Shell command execution"
    ))
    register_sink(SinkContract(
        "os.popen", SinkType.COMMAND_SHELL, "COMMAND_INJECTION",
        tainted_arg_indices=frozenset({0}),
        description="Shell command with pipe"
    ))
    register_sink(SinkContract(
        "os.spawn", SinkType.COMMAND_SHELL, "COMMAND_INJECTION",
        tainted_arg_indices=frozenset({0}),
        description="Process spawn"
    ))
    register_sink(SinkContract(
        "subprocess.call", SinkType.COMMAND_SHELL, "COMMAND_INJECTION",
        tainted_arg_indices=frozenset({0}),
        shell_check=True,
        description="Subprocess call"
    ))
    register_sink(SinkContract(
        "subprocess.run", SinkType.COMMAND_SHELL, "COMMAND_INJECTION",
        tainted_arg_indices=frozenset({0}),
        shell_check=True,
        description="Subprocess run"
    ))
    register_sink(SinkContract(
        "subprocess.Popen", SinkType.COMMAND_SHELL, "COMMAND_INJECTION",
        tainted_arg_indices=frozenset({0}),
        shell_check=True,
        description="Subprocess Popen"
    ))
    register_sink(SinkContract(
        "subprocess.check_output", SinkType.COMMAND_SHELL, "COMMAND_INJECTION",
        tainted_arg_indices=frozenset({0}),
        shell_check=True,
        description="Subprocess check_output"
    ))
    register_sink(SinkContract(
        "subprocess.check_call", SinkType.COMMAND_SHELL, "COMMAND_INJECTION",
        tainted_arg_indices=frozenset({0}),
        shell_check=True,
        description="Subprocess check_call"
    ))
    
    # ===== Code Injection Sinks =====
    
    register_sink(SinkContract(
        "builtins.eval", SinkType.CODE_EVAL, "CODE_INJECTION",
        tainted_arg_indices=frozenset({0}),
        description="Dynamic code evaluation"
    ))
    register_sink(SinkContract(
        "eval", SinkType.CODE_EVAL, "CODE_INJECTION",
        tainted_arg_indices=frozenset({0}),
        description="Dynamic code evaluation"
    ))
    register_sink(SinkContract(
        "builtins.exec", SinkType.CODE_EVAL, "EXEC_INJECTION",
        tainted_arg_indices=frozenset({0}),
        description="Dynamic code execution"
    ))
    register_sink(SinkContract(
        "exec", SinkType.CODE_EVAL, "EXEC_INJECTION",
        tainted_arg_indices=frozenset({0}),
        description="Dynamic code execution"
    ))
    register_sink(SinkContract(
        "builtins.compile", SinkType.CODE_EVAL, "CODE_INJECTION",
        tainted_arg_indices=frozenset({0}),
        description="Dynamic code compilation"
    ))
    register_sink(SinkContract(
        "builtins.__import__", SinkType.CODE_EVAL, "CODE_INJECTION",
        tainted_arg_indices=frozenset({0}),
        description="Dynamic import"
    ))
    
    # ===== Path Injection Sinks =====
    
    register_sink(SinkContract(
        "builtins.open", SinkType.FILE_PATH, "PATH_INJECTION",
        tainted_arg_indices=frozenset({0}),
        description="File open"
    ))
    register_sink(SinkContract(
        "open", SinkType.FILE_PATH, "PATH_INJECTION",
        tainted_arg_indices=frozenset({0}),
        description="File open (bare)"
    ))
    # NOTE: Iteration 574 matching logic ensures "open" only matches bare open() or builtins.open(),
    # not module.open() patterns like tarfile.open() or zipfile.open()
    register_sink(SinkContract(
        "tarfile.open", SinkType.FILE_PATH, "PATH_INJECTION",
        tainted_arg_indices=frozenset({0}),
        description="Tarfile open (archive path)"
    ))
    register_sink(SinkContract(
        "os.remove", SinkType.FILE_PATH, "PATH_INJECTION",
        tainted_arg_indices=frozenset({0}),
        description="File removal"
    ))
    register_sink(SinkContract(
        "os.unlink", SinkType.FILE_PATH, "PATH_INJECTION",
        tainted_arg_indices=frozenset({0}),
        description="File unlink"
    ))
    register_sink(SinkContract(
        "os.rmdir", SinkType.FILE_PATH, "PATH_INJECTION",
        tainted_arg_indices=frozenset({0}),
        description="Directory removal"
    ))
    register_sink(SinkContract(
        "os.makedirs", SinkType.FILE_PATH, "PATH_INJECTION",
        tainted_arg_indices=frozenset({0}),
        description="Directory creation"
    ))
    register_sink(SinkContract(
        "shutil.copy", SinkType.FILE_PATH, "PATH_INJECTION",
        tainted_arg_indices=frozenset({0, 1}),
        description="File copy"
    ))
    register_sink(SinkContract(
        "shutil.move", SinkType.FILE_PATH, "PATH_INJECTION",
        tainted_arg_indices=frozenset({0, 1}),
        description="File move"
    ))
    register_sink(SinkContract(
        "shutil.rmtree", SinkType.FILE_PATH, "PATH_INJECTION",
        tainted_arg_indices=frozenset({0}),
        description="Recursive directory removal"
    ))
    register_sink(SinkContract(
        "pathlib.Path.open", SinkType.FILE_PATH, "PATH_INJECTION",
        description="Pathlib open"
    ))
    # ITERATION 535: Add pathlib.Path constructor and methods as sinks
    register_sink(SinkContract(
        "pathlib.Path", SinkType.FILE_PATH, "PATH_INJECTION",
        tainted_arg_indices=frozenset({0}),
        description="Pathlib Path constructor"
    ))
    register_sink(SinkContract(
        "Path", SinkType.FILE_PATH, "PATH_INJECTION",
        tainted_arg_indices=frozenset({0}),
        description="Path constructor (unqualified)"
    ))
    register_sink(SinkContract(
        "pathlib.Path.read_text", SinkType.FILE_PATH, "PATH_INJECTION",
        check_receiver=True,
        description="Pathlib read_text method"
    ))
    register_sink(SinkContract(
        "pathlib.Path.read_bytes", SinkType.FILE_PATH, "PATH_INJECTION",
        check_receiver=True,
        description="Pathlib read_bytes method"
    ))
    register_sink(SinkContract(
        "flask.send_file", SinkType.FILE_PATH, "PATH_INJECTION",
        tainted_arg_indices=frozenset({0}),
        description="Flask send_file"
    ))
    register_sink(SinkContract(
        "tarfile.extractall", SinkType.FILE_PATH, "TARSLIP",
        tainted_arg_indices=frozenset({0}),
        tainted_kwarg_names=frozenset({"path"}),  # ITERATION 559: Check path kwarg
        description="Tar extraction (TarSlip)"
    ))
    # Generic method-name fallback: local receiver variables like `tar` / `zf` lose type context.
    # Treat `*.extractall(path=...)` as a FILE_PATH sink (PATH_INJECTION) to preserve detection
    # when the receiver type cannot be resolved statically.
    register_sink(SinkContract(
        "extractall", SinkType.FILE_PATH, "PATH_INJECTION",
        tainted_arg_indices=frozenset({0}),
        tainted_kwarg_names=frozenset({"path"}),
        description="Generic extractall(path=...) sink"
    ))
    register_sink(SinkContract(
        "tarfile.TarFile.extractall", SinkType.FILE_PATH, "TARSLIP",
        tainted_arg_indices=frozenset({0}),
        tainted_kwarg_names=frozenset({"path"}),
        description="TarFile.extractall method"
    ))
    register_sink(SinkContract(
        "TarFile.extractall", SinkType.FILE_PATH, "TARSLIP",
        tainted_arg_indices=frozenset({0}),
        tainted_kwarg_names=frozenset({"path"}),
        description="TarFile.extractall method (short)"
    ))
    register_sink(SinkContract(
        "tarfile.extract", SinkType.FILE_PATH, "TARSLIP",
        tainted_arg_indices=frozenset({0, 1}),
        description="Tar member extraction"
    ))
    register_sink(SinkContract(
        "tarfile.TarFile.extract", SinkType.FILE_PATH, "TARSLIP",
        tainted_arg_indices=frozenset({0, 1}),
        description="TarFile.extract method"
    ))
    register_sink(SinkContract(
        "TarFile.extract", SinkType.FILE_PATH, "TARSLIP",
        tainted_arg_indices=frozenset({0, 1}),
        description="TarFile.extract method (short)"
    ))
    # NOTE: ZipSlip is primarily about extraction, but opening an archive path from
    # untrusted input is also a FILE_PATH sink (path traversal / arbitrary file read).
    register_sink(SinkContract(
        "zipfile.ZipFile", SinkType.FILE_PATH, "PATH_INJECTION",
        tainted_arg_indices=frozenset({0}),
        description="Zipfile open (archive path)"
    ))
    # ZIPSLIP bugs are in extractall/extract methods below.
    register_sink(SinkContract(
        "zipfile.ZipFile.extractall", SinkType.FILE_PATH, "ZIPSLIP",
        tainted_arg_indices=frozenset({0}),
        tainted_kwarg_names=frozenset({"path"}),  # ITERATION 559: Check path kwarg
        description="Zip extraction (ZipSlip)"
    ))
    register_sink(SinkContract(
        "zipfile.ZipFile.extract", SinkType.FILE_PATH, "ZIPSLIP",
        tainted_arg_indices=frozenset({0, 1}),
        description="Zip member extraction"
    ))
    
    # ===== File Write Sinks (for τ check - untrusted data in write) =====
    # Note: file.write is also registered for CLEARTEXT_STORAGE (σ check) below
    
    register_sink(SinkContract(
        "file.write", SinkType.FILE_WRITE, "UNTRUSTED_FILE_WRITE",
        tainted_arg_indices=frozenset({0}),
        description="File write operation"
    ))
    register_sink(SinkContract(
        "io.TextIOWrapper.write", SinkType.FILE_WRITE, "UNTRUSTED_FILE_WRITE",
        tainted_arg_indices=frozenset({0}),
        description="Text file write"
    ))
    register_sink(SinkContract(
        "io.BufferedWriter.write", SinkType.FILE_WRITE, "UNTRUSTED_FILE_WRITE",
        tainted_arg_indices=frozenset({0}),
        description="Buffered file write"
    ))
    
    # ===== XSS Sinks =====
    
    register_sink(SinkContract(
        "django.http.HttpResponse", SinkType.HTML_OUTPUT, "REFLECTED_XSS",
        tainted_arg_indices=frozenset({0}),
        description="Django HTTP response"
    ))
    register_sink(SinkContract(
        "flask.render_template_string", SinkType.TEMPLATE_RENDER, "TEMPLATE_INJECTION",
        tainted_arg_indices=frozenset({0}),
        description="Flask template string (dangerous!)"
    ))
    register_sink(SinkContract(
        "flask.Markup", SinkType.HTML_OUTPUT, "REFLECTED_XSS",
        tainted_arg_indices=frozenset({0}),
        description="Flask safe markup"
    ))
    register_sink(SinkContract(
        "jinja2.Template", SinkType.TEMPLATE_RENDER, "JINJA2_INJECTION",
        tainted_arg_indices=frozenset({0}),
        description="Jinja2 template from string"
    ))
    
    # ===== SSRF Sinks =====
    
    register_sink(SinkContract(
        "requests.get", SinkType.HTTP_REQUEST, "SSRF",
        tainted_arg_indices=frozenset({0}),
        description="HTTP GET request"
    ))
    register_sink(SinkContract(
        "requests.post", SinkType.HTTP_REQUEST, "SSRF",
        tainted_arg_indices=frozenset({0}),
        description="HTTP POST request"
    ))
    register_sink(SinkContract(
        "requests.put", SinkType.HTTP_REQUEST, "SSRF",
        tainted_arg_indices=frozenset({0}),
        description="HTTP PUT request"
    ))
    register_sink(SinkContract(
        "requests.delete", SinkType.HTTP_REQUEST, "SSRF",
        tainted_arg_indices=frozenset({0}),
        description="HTTP DELETE request"
    ))
    register_sink(SinkContract(
        "requests.request", SinkType.HTTP_REQUEST, "SSRF",
        tainted_arg_indices=frozenset({1}),  # Second arg is URL
        description="HTTP request"
    ))
    register_sink(SinkContract(
        "urllib.request.urlopen", SinkType.HTTP_REQUEST, "SSRF",
        tainted_arg_indices=frozenset({0}),
        description="URL open"
    ))
    register_sink(SinkContract(
        "httpx.get", SinkType.HTTP_REQUEST, "SSRF",
        tainted_arg_indices=frozenset({0}),
        description="HTTPX GET"
    ))
    register_sink(SinkContract(
        "httpx.post", SinkType.HTTP_REQUEST, "SSRF",
        tainted_arg_indices=frozenset({0}),
        description="HTTPX POST"
    ))
    
    # ===== Deserialization Sinks =====
    
    register_sink(SinkContract(
        "pickle.loads", SinkType.DESERIALIZE, "PICKLE_INJECTION",
        tainted_arg_indices=frozenset({0}),
        description="Pickle deserialization"
    ))
    register_sink(SinkContract(
        "pickle.load", SinkType.DESERIALIZE, "PICKLE_INJECTION",
        tainted_arg_indices=frozenset({0}),
        description="Pickle file deserialization"
    ))
    register_sink(SinkContract(
        "yaml.load", SinkType.DESERIALIZE, "YAML_INJECTION",
        tainted_arg_indices=frozenset({0}),
        loader_check=True,
        description="YAML load (unsafe without SafeLoader)"
    ))
    register_sink(SinkContract(
        "yaml.unsafe_load", SinkType.DESERIALIZE, "YAML_INJECTION",
        tainted_arg_indices=frozenset({0}),
        description="YAML unsafe load"
    ))
    register_sink(SinkContract(
        "marshal.loads", SinkType.DESERIALIZE, "UNSAFE_DESERIALIZATION",
        tainted_arg_indices=frozenset({0}),
        description="Marshal deserialization"
    ))
    
    # ===== XXE/XML Sinks =====
    
    register_sink(SinkContract(
        "xml.etree.ElementTree.parse", SinkType.XML_PARSE, "XXE",
        tainted_arg_indices=frozenset({0}),
        entity_check=True,
        description="XML parse"
    ))
    register_sink(SinkContract(
        "xml.etree.ElementTree.fromstring", SinkType.XML_PARSE, "XXE",
        tainted_arg_indices=frozenset({0}),
        entity_check=True,
        description="XML from string"
    ))
    register_sink(SinkContract(
        "lxml.etree.parse", SinkType.XML_PARSE, "XXE",
        tainted_arg_indices=frozenset({0}),
        entity_check=True,
        description="LXML parse"
    ))
    register_sink(SinkContract(
        "lxml.etree.fromstring", SinkType.XML_PARSE, "XXE",
        tainted_arg_indices=frozenset({0}),
        entity_check=True,
        description="LXML from string"
    ))
    register_sink(SinkContract(
        "xml.sax.parseString", SinkType.XML_PARSE, "XXE",
        tainted_arg_indices=frozenset({0}),
        entity_check=True,
        description="SAX parse string"
    ))
    register_sink(SinkContract(
        "xml.sax.parse", SinkType.XML_PARSE, "XXE",
        tainted_arg_indices=frozenset({0}),
        entity_check=True,
        description="SAX parse file"
    ))
    register_sink(SinkContract(
        "xml.dom.minidom.parseString", SinkType.XML_PARSE, "XXE",
        tainted_arg_indices=frozenset({0}),
        entity_check=True,
        description="minidom parse string"
    ))
    register_sink(SinkContract(
        "xml.dom.minidom.parse", SinkType.XML_PARSE, "XXE",
        tainted_arg_indices=frozenset({0}),
        entity_check=True,
        description="minidom parse file"
    ))
    register_sink(SinkContract(
        "xml.dom.pulldom.parseString", SinkType.XML_PARSE, "XXE",
        tainted_arg_indices=frozenset({0}),
        entity_check=True,
        description="pulldom parse string"
    ))
    register_sink(SinkContract(
        "xml.dom.pulldom.parse", SinkType.XML_PARSE, "XXE",
        tainted_arg_indices=frozenset({0}),
        entity_check=True,
        description="pulldom parse file"
    ))
    
    # XML_BOMB (CWE-776): Duplicate registrations for entity expansion detection
    # Multi-sink pattern: Same functions trigger both XXE and XML_BOMB
    register_sink(SinkContract(
        "xml.etree.ElementTree.parse", SinkType.XML_PARSE, "XML_BOMB",
        tainted_arg_indices=frozenset({0}),
        entity_check=True,
        description="XML parse (entity expansion check)"
    ))
    register_sink(SinkContract(
        "xml.etree.ElementTree.fromstring", SinkType.XML_PARSE, "XML_BOMB",
        tainted_arg_indices=frozenset({0}),
        entity_check=True,
        description="XML from string (entity expansion check)"
    ))
    register_sink(SinkContract(
        "lxml.etree.parse", SinkType.XML_PARSE, "XML_BOMB",
        tainted_arg_indices=frozenset({0}),
        entity_check=True,
        description="LXML parse (entity expansion check)"
    ))
    register_sink(SinkContract(
        "lxml.etree.fromstring", SinkType.XML_PARSE, "XML_BOMB",
        tainted_arg_indices=frozenset({0}),
        entity_check=True,
        description="LXML from string (entity expansion check)"
    ))
    register_sink(SinkContract(
        "xml.sax.parseString", SinkType.XML_PARSE, "XML_BOMB",
        tainted_arg_indices=frozenset({0}),
        entity_check=True,
        description="SAX parse string (entity expansion check)"
    ))
    register_sink(SinkContract(
        "xml.sax.parse", SinkType.XML_PARSE, "XML_BOMB",
        tainted_arg_indices=frozenset({0}),
        entity_check=True,
        description="SAX parse file (entity expansion check)"
    ))
    register_sink(SinkContract(
        "xml.dom.minidom.parseString", SinkType.XML_PARSE, "XML_BOMB",
        tainted_arg_indices=frozenset({0}),
        entity_check=True,
        description="minidom parse string (entity expansion check)"
    ))
    register_sink(SinkContract(
        "xml.dom.minidom.parse", SinkType.XML_PARSE, "XML_BOMB",
        tainted_arg_indices=frozenset({0}),
        entity_check=True,
        description="minidom parse file (entity expansion check)"
    ))
    register_sink(SinkContract(
        "xml.dom.pulldom.parseString", SinkType.XML_PARSE, "XML_BOMB",
        tainted_arg_indices=frozenset({0}),
        entity_check=True,
        description="pulldom parse string (entity expansion check)"
    ))
    register_sink(SinkContract(
        "xml.dom.pulldom.parse", SinkType.XML_PARSE, "XML_BOMB",
        tainted_arg_indices=frozenset({0}),
        entity_check=True,
        description="pulldom parse file (entity expansion check)"
    ))
    
    # ===== LDAP Injection Sinks =====
    
    register_sink(SinkContract(
        "ldap.search_s", SinkType.LDAP_QUERY, "LDAP_INJECTION",
        tainted_arg_indices=frozenset({0, 2}),
        description="LDAP search"
    ))
    register_sink(SinkContract(
        "ldap3.Connection.search", SinkType.LDAP_QUERY, "LDAP_INJECTION",
        tainted_arg_indices=frozenset({0, 1}),
        description="LDAP3 search"
    ))
    
    # ===== XPath Injection Sinks =====
    
    register_sink(SinkContract(
        "lxml.etree.XPath", SinkType.XPATH_QUERY, "XPATH_INJECTION",
        tainted_arg_indices=frozenset({0}),
        description="XPath compilation"
    ))
    register_sink(SinkContract(
        "tree.xpath", SinkType.XPATH_QUERY, "XPATH_INJECTION",
        tainted_arg_indices=frozenset({0}),
        description="XPath query"
    ))
    
    # ===== NoSQL Injection Sinks =====
    
    register_sink(SinkContract(
        "collection.find", SinkType.NOSQL_QUERY, "NOSQL_INJECTION",
        tainted_arg_indices=frozenset({0}),
        description="MongoDB find"
    ))
    register_sink(SinkContract(
        "collection.find_one", SinkType.NOSQL_QUERY, "NOSQL_INJECTION",
        tainted_arg_indices=frozenset({0}),
        description="MongoDB find_one"
    ))
    register_sink(SinkContract(
        "collection.update_one", SinkType.NOSQL_QUERY, "NOSQL_INJECTION",
        tainted_arg_indices=frozenset({0, 1}),
        description="MongoDB update_one"
    ))
    
    # ===== Regex Injection Sinks =====
    
    register_sink(SinkContract(
        "re.compile", SinkType.REGEX_PATTERN, "REGEX_INJECTION",
        tainted_arg_indices=frozenset({0}),
        description="Regex compilation"
    ))
    register_sink(SinkContract(
        "re.match", SinkType.REGEX_PATTERN, "REGEX_INJECTION",
        tainted_arg_indices=frozenset({0}),
        description="Regex match"
    ))
    register_sink(SinkContract(
        "re.search", SinkType.REGEX_PATTERN, "REGEX_INJECTION",
        tainted_arg_indices=frozenset({0}),
        description="Regex search"
    ))
    register_sink(SinkContract(
        "re.sub", SinkType.REGEX_PATTERN, "REGEX_INJECTION",
        tainted_arg_indices=frozenset({0}),
        description="Regex substitution"
    ))
    register_sink(SinkContract(
        "re.findall", SinkType.REGEX_PATTERN, "REGEX_INJECTION",
        tainted_arg_indices=frozenset({0}),
        description="Regex findall"
    ))
    register_sink(SinkContract(
        "re.fullmatch", SinkType.REGEX_PATTERN, "REGEX_INJECTION",
        tainted_arg_indices=frozenset({0}),
        description="Regex fullmatch"
    ))
    register_sink(SinkContract(
        "re.finditer", SinkType.REGEX_PATTERN, "REGEX_INJECTION",
        tainted_arg_indices=frozenset({0}),
        description="Regex finditer"
    ))
    register_sink(SinkContract(
        "re.split", SinkType.REGEX_PATTERN, "REGEX_INJECTION",
        tainted_arg_indices=frozenset({0}),
        description="Regex split"
    ))
    
    # ===== Compiled Regex Pattern Object Sinks =====
    # These handle pattern objects returned by re.compile()
    # Note: The pattern itself is NOT a sink (it's already compiled)
    # Only the METHODS that use the pattern on user data are sinks if the pattern is tainted
    
    # ITERATION 526: Use check_receiver=True to check taint on the Pattern object itself
    register_sink(SinkContract(
        "Pattern.match", SinkType.REGEX_PATTERN, "REGEX_INJECTION",
        tainted_arg_indices=frozenset(),  # Don't check explicit args
        check_receiver=True,  # Check if Pattern receiver is tainted
        description="Compiled pattern match method (pattern carries injection taint)"
    ))
    register_sink(SinkContract(
        "Pattern.search", SinkType.REGEX_PATTERN, "REGEX_INJECTION",
        tainted_arg_indices=frozenset(),
        check_receiver=True,
        description="Compiled pattern search method (pattern carries injection taint)"
    ))
    register_sink(SinkContract(
        "Pattern.findall", SinkType.REGEX_PATTERN, "REGEX_INJECTION",
        tainted_arg_indices=frozenset(),
        check_receiver=True,
        description="Compiled pattern findall method (pattern carries injection taint)"
    ))
    register_sink(SinkContract(
        "Pattern.finditer", SinkType.REGEX_PATTERN, "REGEX_INJECTION",
        tainted_arg_indices=frozenset(),
        check_receiver=True,
        description="Compiled pattern finditer method (pattern carries injection taint)"
    ))
    register_sink(SinkContract(
        "Pattern.fullmatch", SinkType.REGEX_PATTERN, "REGEX_INJECTION",
        tainted_arg_indices=frozenset(),
        check_receiver=True,
        description="Compiled pattern fullmatch method (pattern carries injection taint)"
    ))
    register_sink(SinkContract(
        "Pattern.split", SinkType.REGEX_PATTERN, "REGEX_INJECTION",
        tainted_arg_indices=frozenset(),
        check_receiver=True,
        description="Compiled pattern split method (pattern carries injection taint)"
    ))
    register_sink(SinkContract(
        "Pattern.sub", SinkType.REGEX_PATTERN, "REGEX_INJECTION",
        tainted_arg_indices=frozenset(),
        check_receiver=True,
        description="Compiled pattern sub method (pattern carries injection taint)"
    ))
    register_sink(SinkContract(
        "Pattern.subn", SinkType.REGEX_PATTERN, "REGEX_INJECTION",
        tainted_arg_indices=frozenset(),
        check_receiver=True,
        description="Compiled pattern subn method (pattern carries injection taint)"
    ))
    
    # ===== URL Redirect Sinks =====
    
    register_sink(SinkContract(
        "flask.redirect", SinkType.REDIRECT_URL, "URL_REDIRECT",
        tainted_arg_indices=frozenset({0}),
        description="Flask redirect"
    ))
    register_sink(SinkContract(
        "django.shortcuts.redirect", SinkType.REDIRECT_URL, "URL_REDIRECT",
        tainted_arg_indices=frozenset({0}),
        description="Django redirect"
    ))
    register_sink(SinkContract(
        "django.http.HttpResponseRedirect", SinkType.REDIRECT_URL, "URL_REDIRECT",
        tainted_arg_indices=frozenset({0}),
        description="Django HTTP redirect"
    ))
    
    # FastAPI response
    register_sink(SinkContract(
        "fastapi.responses.RedirectResponse", SinkType.REDIRECT_URL, "URL_REDIRECT",
        tainted_arg_indices=frozenset({0}),
        description="FastAPI redirect response"
    ))
    register_sink(SinkContract(
        "starlette.responses.RedirectResponse", SinkType.REDIRECT_URL, "URL_REDIRECT",
        tainted_arg_indices=frozenset({0}),
        description="Starlette redirect response"
    ))
    
    # Django template rendering (XSS sinks)
    register_sink(SinkContract(
        "django.template.Template.render", SinkType.TEMPLATE_RENDER, "REFLECTED_XSS",
        tainted_arg_indices=frozenset({0}),  # Context dict
        description="Django template render"
    ))
    register_sink(SinkContract(
        "django.shortcuts.render", SinkType.TEMPLATE_RENDER, "REFLECTED_XSS",
        tainted_arg_indices=frozenset({2}),  # Context is 3rd arg
        description="Django render shortcut"
    ))
    
    # Flask template rendering
    register_sink(SinkContract(
        "flask.render_template", SinkType.TEMPLATE_RENDER, "REFLECTED_XSS",
        tainted_arg_indices=frozenset(),  # kwargs
        description="Flask render_template"
    ))
    register_sink(SinkContract(
        "flask.render_template_string", SinkType.TEMPLATE_RENDER, "REFLECTED_XSS",
        tainted_arg_indices=frozenset({0}),  # Template string itself
        description="Flask render_template_string"
    ))
    
    # Jinja2 template rendering
    register_sink(SinkContract(
        "jinja2.Template.render", SinkType.TEMPLATE_RENDER, "REFLECTED_XSS",
        tainted_arg_indices=frozenset(),  # kwargs
        description="Jinja2 template render"
    ))
    register_sink(SinkContract(
        "jinja2.Environment.from_string", SinkType.TEMPLATE_RENDER, "REFLECTED_XSS",
        tainted_arg_indices=frozenset({0}),  # Template string
        description="Jinja2 from_string"
    ))
    
    # FastAPI/Starlette template rendering
    register_sink(SinkContract(
        "fastapi.templating.Jinja2Templates.TemplateResponse", SinkType.TEMPLATE_RENDER, "REFLECTED_XSS",
        tainted_arg_indices=frozenset(),  # context dict
        description="FastAPI Jinja2 template response"
    ))
    register_sink(SinkContract(
        "starlette.templating.Jinja2Templates.TemplateResponse", SinkType.TEMPLATE_RENDER, "REFLECTED_XSS",
        tainted_arg_indices=frozenset(),  # context dict
        description="Starlette Jinja2 template response"
    ))
    
    # Django HTTP response construction (header injection)
    register_sink(SinkContract(
        "django.http.HttpResponse.__init__", SinkType.HEADER_SET, "HEADER_INJECTION",
        tainted_arg_indices=frozenset({0}),  # content
        description="Django HttpResponse content"
    ))
    
    # Flask make_response (header injection)
    register_sink(SinkContract(
        "flask.make_response", SinkType.HEADER_SET, "HEADER_INJECTION",
        tainted_arg_indices=frozenset({0}),
        description="Flask make_response"
    ))
    
    # FastAPI Response (header injection)
    register_sink(SinkContract(
        "fastapi.Response.__init__", SinkType.HEADER_SET, "HEADER_INJECTION",
        tainted_arg_indices=frozenset({0}),  # content
        description="FastAPI Response content"
    ))
    
    # ===== Cookie Injection Sinks =====
    # Cookie injection occurs when untrusted data flows into the cookie VALUE,
    # which can allow header manipulation (e.g., CRLF) depending on downstream frameworks.
    # Separate detector INSECURE_COOKIE checks missing secure/httponly/samesite flags.
    
    register_sink(SinkContract(
        "response.set_cookie", SinkType.COOKIE_VALUE, "COOKIE_INJECTION",
        tainted_arg_indices=frozenset({1}),  # Second arg is the cookie value
        description="HTTP response set_cookie (check cookie value for injection)"
    ))
    register_sink(SinkContract(
        "Response.set_cookie", SinkType.COOKIE_VALUE, "COOKIE_INJECTION",
        tainted_arg_indices=frozenset({1}),  # Second arg is the cookie value
        description="Flask/Django Response set_cookie (check cookie value for injection)"
    ))
    register_sink(SinkContract(
        "HttpResponse.set_cookie", SinkType.COOKIE_VALUE, "COOKIE_INJECTION",
        tainted_arg_indices=frozenset({1}),  # Second arg is the cookie value
        description="Django HttpResponse set_cookie (check cookie value for injection)"
    ))
    
    # ===== Log Injection Sinks =====
    # NOTE: Changed from LOG_FORGING (τ check) to LOG_OUTPUT (σ check) per parity report.
    # This makes LOG_INJECTION only fire for sensitive data, not just untrusted input.
    
    register_sink(SinkContract(
        "logging.info", SinkType.LOG_OUTPUT, "LOG_INJECTION",
        tainted_arg_indices=frozenset({0}),
        description="Log info (sensitive data check)"
    ))
    register_sink(SinkContract(
        "logging.debug", SinkType.LOG_OUTPUT, "LOG_INJECTION",
        tainted_arg_indices=frozenset({0}),
        description="Log debug (sensitive data check)"
    ))
    register_sink(SinkContract(
        "logging.warning", SinkType.LOG_OUTPUT, "LOG_INJECTION",
        tainted_arg_indices=frozenset({0}),
        description="Log warning (sensitive data check)"
    ))
    register_sink(SinkContract(
        "logging.error", SinkType.LOG_OUTPUT, "LOG_INJECTION",
        tainted_arg_indices=frozenset({0}),
        description="Log error (sensitive data check)"
    ))
    
    # ===== Cleartext Logging Sinks (σ check) =====
    # NOTE: Logging functions are registered for BOTH LOG_FORGING (τ check for log injection)
    # and LOG_OUTPUT (σ check for cleartext logging). Multi-sink support via get_sink_contracts.
    
    register_sink(SinkContract(
        "logging.info", SinkType.LOG_OUTPUT, "CLEARTEXT_LOGGING",
        tainted_arg_indices=frozenset({0}),
        description="Log info (cleartext logging check)"
    ))
    register_sink(SinkContract(
        "logging.debug", SinkType.LOG_OUTPUT, "CLEARTEXT_LOGGING",
        tainted_arg_indices=frozenset({0}),
        description="Log debug (cleartext logging check)"
    ))
    register_sink(SinkContract(
        "logging.warning", SinkType.LOG_OUTPUT, "CLEARTEXT_LOGGING",
        tainted_arg_indices=frozenset({0}),
        description="Log warning (cleartext logging check)"
    ))
    register_sink(SinkContract(
        "logging.error", SinkType.LOG_OUTPUT, "CLEARTEXT_LOGGING",
        tainted_arg_indices=frozenset({0}),
        description="Log error (cleartext logging check)"
    ))
    register_sink(SinkContract(
        "logging.critical", SinkType.LOG_OUTPUT, "CLEARTEXT_LOGGING",
        tainted_arg_indices=frozenset({0}),
        description="Log critical (cleartext logging check)"
    ))
    
    # ===== Sensitive Data Sinks (σ check) =====
    
    # Print σ-taint check (LOG_INJECTION) - requires sensitivity, not just untrusted input
    register_sink(SinkContract(
        "builtins.print", SinkType.LOG_OUTPUT, "LOG_INJECTION",
        tainted_arg_indices=frozenset({0, 1, 2, 3, 4, 5, 6, 7, 8, 9}),
        description="Print output (sensitive data check)"
    ))
    register_sink(SinkContract(
        "print", SinkType.LOG_OUTPUT, "LOG_INJECTION",
        tainted_arg_indices=frozenset({0, 1, 2, 3, 4, 5, 6, 7, 8, 9}),
        description="Print output (sensitive data check)"
    ))
    
    # Print σ-taint check (CLEARTEXT_LOGGING)
    register_sink(SinkContract(
        "builtins.print", SinkType.LOG_OUTPUT, "CLEARTEXT_LOGGING",
        tainted_arg_indices=frozenset({0, 1, 2, 3, 4, 5, 6, 7, 8, 9}),  # Check all positional args
        description="Print output (σ-taint check for sensitive data)"
    ))
    register_sink(SinkContract(
        "print", SinkType.LOG_OUTPUT, "CLEARTEXT_LOGGING",
        tainted_arg_indices=frozenset({0, 1, 2, 3, 4, 5, 6, 7, 8, 9}),  # Check all positional args
        description="Print output (σ-taint check for sensitive data)"
    ))
    
    # ===== File Write Sinks for Cleartext Storage (σ check) =====
    # Note: file.write is also registered above for τ check (untrusted data)
    # Here we check σ (sensitive data) for CLEARTEXT_STORAGE
    
    register_sink(SinkContract(
        "file.write", SinkType.FILE_WRITE, "CLEARTEXT_STORAGE",
        tainted_arg_indices=frozenset({0}),
        description="File write (cleartext storage check)"
    ))
    register_sink(SinkContract(
        "io.TextIOWrapper.write", SinkType.FILE_WRITE, "CLEARTEXT_STORAGE",
        tainted_arg_indices=frozenset({0}),
        description="Text file write (cleartext storage check)"
    ))
    register_sink(SinkContract(
        "io.BufferedWriter.write", SinkType.FILE_WRITE, "CLEARTEXT_STORAGE",
        tainted_arg_indices=frozenset({0}),
        description="Buffered file write (cleartext storage check)"
    ))
    
    # JSON serialization to file - may expose sensitive data
    register_sink(SinkContract(
        "json.dump", SinkType.FILE_WRITE, "CLEARTEXT_STORAGE",
        tainted_arg_indices=frozenset({0}),
        description="JSON dump to file (cleartext storage check)"
    ))
    register_sink(SinkContract(
        "json.dumps", SinkType.FILE_WRITE, "CLEARTEXT_STORAGE",
        tainted_arg_indices=frozenset({0}),
        description="JSON dumps (cleartext storage check, often written to file)"
    ))
    
    # ===== Weak Crypto Sinks =====
    # ITERATION 564: Sensitivity-aware crypto checking
    # Only flag weak algorithms (MD5, SHA1, SHA256) when used on PASSWORD/API_KEY
    # For non-sensitive data (checksums, cache keys), these are acceptable
    # Pattern: sensitive data (passwords, keys) hashed with weak algorithms
    
    # MD5 - weak for passwords/keys, acceptable for checksums
    # ONLY flag when σ (sensitivity) taint is present
    register_sink(SinkContract(
        "hashlib.md5", SinkType.CRYPTO_WEAK, "WEAK_SENSITIVE_DATA_HASHING",
        tainted_arg_indices=frozenset({0}),
        description="MD5 hash (weak for sensitive data, OK for checksums)"
    ))
    
    # SHA1 - weak for passwords/keys, acceptable for checksums
    # ONLY flag when σ (sensitivity) taint is present
    register_sink(SinkContract(
        "hashlib.sha1", SinkType.CRYPTO_WEAK, "WEAK_SENSITIVE_DATA_HASHING",
        tainted_arg_indices=frozenset({0}),
        description="SHA1 hash (weak for sensitive data, OK for checksums)"
    ))
    
    # SHA256 - acceptable for general use but NOT ideal for password hashing
    # (needs salting and key derivation, should use bcrypt/scrypt/argon2)
    # NOTE: We don't flag SHA-256 as CRYPTO_WEAK because it's still a valid hash,
    # just not best practice for passwords. MD5/SHA1 are flagged because they're
    # cryptographically broken. For strict password policy enforcement, this could
    # be re-enabled with a separate WEAK_PASSWORD_HASH bug type.
    # register_sink(SinkContract(
    #     "hashlib.sha256", SinkType.CRYPTO_WEAK, "WEAK_SENSITIVE_DATA_HASHING",
    #     tainted_arg_indices=frozenset({0}),
    #     description="SHA256 (weak for password hashing - needs KDF, OK for general use)"
    # ))
    
    # DES - obsolete, extremely weak
    register_sink(SinkContract(
        "Crypto.Cipher.DES.new", SinkType.CRYPTO_WEAK, "WEAK_CRYPTO",
        tainted_arg_indices=frozenset({0}),
        description="DES cipher (obsolete)"
    ))
    
    # Blowfish - deprecated, 64-bit block size vulnerable to birthday attacks
    register_sink(SinkContract(
        "Crypto.Cipher.Blowfish.new", SinkType.CRYPTO_WEAK, "WEAK_CRYPTO",
        tainted_arg_indices=frozenset({0}),
        description="Blowfish cipher (deprecated)"
    ))
    
    # RC4 - broken, should never be used
    register_sink(SinkContract(
        "Crypto.Cipher.ARC4.new", SinkType.CRYPTO_WEAK, "WEAK_CRYPTO",
        tainted_arg_indices=frozenset({0}),
        description="RC4 cipher (broken)"
    ))
    
    register_sink(SinkContract(
        "random.random", SinkType.RANDOM_SEED, "WEAK_RANDOM",
        description="Non-cryptographic random"
    ))
    register_sink(SinkContract(
        "random.randint", SinkType.RANDOM_SEED, "WEAK_RANDOM",
        description="Non-cryptographic random"
    ))


def _init_sanitizer_contracts() -> None:
    """Register all sanitizer contracts."""
    
    # ===== SQL Sanitizers =====
    # Note: Parameterized queries are handled specially via sink contract
    
    # ===== Command Injection Sanitizers =====
    
    register_sanitizer(SanitizerContract(
        "shlex.quote", SanitizerType.SHELL_QUOTE,
        applicable_sinks=frozenset({SinkType.COMMAND_SHELL}),
        description="Shell argument escaping"
    ))
    register_sanitizer(SanitizerContract(
        "shlex.split", SanitizerType.ARRAY_COMMAND,
        applicable_sinks=frozenset({SinkType.COMMAND_SHELL}),
        description="Shell command parsing"
    ))
    
    # ===== Path Sanitizers =====
    
    register_sanitizer(SanitizerContract(
        "os.path.basename", SanitizerType.BASENAME,
        applicable_sinks=frozenset({SinkType.FILE_PATH}),
        description="Strip directory path"
    ))
    register_sanitizer(SanitizerContract(
        "os.path.realpath", SanitizerType.CANONICALIZE,
        applicable_sinks=frozenset({SinkType.FILE_PATH}),
        description="Canonicalize path"
    ))
    register_sanitizer(SanitizerContract(
        "werkzeug.utils.secure_filename", SanitizerType.SECURE_FILENAME,
        applicable_sinks=frozenset({SinkType.FILE_PATH}),
        description="Werkzeug filename sanitizer"
    ))
    register_sanitizer(SanitizerContract(
        "pathlib.Path.resolve", SanitizerType.CANONICALIZE,
        applicable_sinks=frozenset({SinkType.FILE_PATH}),
        description="Path resolution"
    ))
    
    # ===== XSS Sanitizers =====
    
    register_sanitizer(SanitizerContract(
        "html.escape", SanitizerType.HTML_ESCAPE,
        applicable_sinks=frozenset({SinkType.HTML_OUTPUT}),
        description="HTML escape"
    ))
    register_sanitizer(SanitizerContract(
        "markupsafe.escape", SanitizerType.HTML_ESCAPE,
        applicable_sinks=frozenset({SinkType.HTML_OUTPUT, SinkType.TEMPLATE_RENDER}),
        description="Markupsafe escape"
    ))
    register_sanitizer(SanitizerContract(
        "django.utils.html.escape", SanitizerType.HTML_ESCAPE,
        applicable_sinks=frozenset({SinkType.HTML_OUTPUT}),
        description="Django HTML escape"
    ))
    register_sanitizer(SanitizerContract(
        "bleach.clean", SanitizerType.DOM_PURIFY,
        applicable_sinks=frozenset({SinkType.HTML_OUTPUT}),
        description="Bleach HTML sanitizer"
    ))
    
    # ===== Django Template Sanitizers (Iteration 523) =====
    # Django's render() and render_to_string() apply auto-escaping by default.
    # This sanitizes HTML_OUTPUT unless |safe filter or {% autoescape off %} is used.
    
    register_sanitizer(SanitizerContract(
        "django.shortcuts.render", SanitizerType.TEMPLATE_AUTOESCAPE,
        applicable_sinks=frozenset({SinkType.HTML_OUTPUT}),
        description="Django render with auto-escape (unless |safe or autoescape=off)"
    ))
    register_sanitizer(SanitizerContract(
        "django.template.loader.render_to_string", SanitizerType.TEMPLATE_AUTOESCAPE,
        applicable_sinks=frozenset({SinkType.HTML_OUTPUT}),
        description="Django render_to_string with auto-escape (unless |safe or autoescape=off)"
    ))
    register_sanitizer(SanitizerContract(
        "django.template.Template.render", SanitizerType.TEMPLATE_AUTOESCAPE,
        applicable_sinks=frozenset({SinkType.HTML_OUTPUT}),
        description="Django template render with auto-escape (unless |safe or autoescape=off)"
    ))
    
    # Flask/Jinja2 template sanitizers
    register_sanitizer(SanitizerContract(
        "jinja2.Template.render", SanitizerType.TEMPLATE_AUTOESCAPE,
        applicable_sinks=frozenset({SinkType.HTML_OUTPUT}),
        description="Jinja2 template render with auto-escape (default in Flask)"
    ))
    register_sanitizer(SanitizerContract(
        "flask.render_template", SanitizerType.TEMPLATE_AUTOESCAPE,
        applicable_sinks=frozenset({SinkType.HTML_OUTPUT}),
        description="Flask render_template with auto-escape"
    ))
    register_sanitizer(SanitizerContract(
        "markupsafe.Markup", SanitizerType.HTML_ESCAPE,
        applicable_sinks=frozenset({SinkType.HTML_OUTPUT}),
        description="Markupsafe Markup (marks string as safe)"
    ))
    
    # FastAPI/Starlette sanitizers
    register_sanitizer(SanitizerContract(
        "fastapi.templating.Jinja2Templates.TemplateResponse", SanitizerType.TEMPLATE_AUTOESCAPE,
        applicable_sinks=frozenset({SinkType.HTML_OUTPUT}),
        description="FastAPI Jinja2 template with auto-escape"
    ))
    register_sanitizer(SanitizerContract(
        "starlette.templating.Jinja2Templates.TemplateResponse", SanitizerType.TEMPLATE_AUTOESCAPE,
        applicable_sinks=frozenset({SinkType.HTML_OUTPUT}),
        description="Starlette Jinja2 template with auto-escape"
    ))
    
    # ===== URL Sanitizers =====
    
    register_sanitizer(SanitizerContract(
        "urllib.parse.quote", SanitizerType.URL_VALIDATE,
        applicable_sinks=frozenset({SinkType.REDIRECT_URL, SinkType.HTTP_REQUEST}),
        description="URL quote"
    ))
    register_sanitizer(SanitizerContract(
        "urllib.parse.urlparse", SanitizerType.URL_PARSE_VALIDATE,
        applicable_sinks=frozenset({SinkType.REDIRECT_URL, SinkType.HTTP_REQUEST}),
        description="URL parse (for validation)"
    ))
    
    # ===== Regex Sanitizers =====
    
    register_sanitizer(SanitizerContract(
        "re.escape", SanitizerType.RE_ESCAPE,
        applicable_sinks=frozenset({SinkType.REGEX_PATTERN}),
        description="Regex metachar escape"
    ))
    
    # ===== Safe Deserializers =====
    
    register_sanitizer(SanitizerContract(
        "yaml.safe_load", SanitizerType.SAFE_LOADER,
        applicable_sinks=frozenset({SinkType.DESERIALIZE}),
        description="YAML safe loader"
    ))
    register_sanitizer(SanitizerContract(
        "json.loads", SanitizerType.JSON_PARSE,
        applicable_sinks=frozenset({SinkType.DESERIALIZE}),
        description="JSON (safe by design)"
    ))
    register_sanitizer(SanitizerContract(
        "json.load", SanitizerType.JSON_PARSE,
        applicable_sinks=frozenset({SinkType.DESERIALIZE}),
        description="JSON file (safe by design)"
    ))
    
    # ===== LDAP Sanitizers =====
    
    register_sanitizer(SanitizerContract(
        "ldap.filter.escape_filter_chars", SanitizerType.LDAP_ESCAPE,
        applicable_sinks=frozenset({SinkType.LDAP_QUERY}),
        description="LDAP filter escape"
    ))
    register_sanitizer(SanitizerContract(
        "ldap3.utils.dn.escape_rdn", SanitizerType.LDAP_ESCAPE,
        applicable_sinks=frozenset({SinkType.LDAP_QUERY}),
        description="LDAP3 RDN escape"
    ))
    
    # ===== XML Sanitizers =====
    
    register_sanitizer(SanitizerContract(
        "defusedxml.parse", SanitizerType.DEFUSED_XML,
        applicable_sinks=frozenset({SinkType.XML_PARSE}),
        description="Defused XML parse"
    ))
    register_sanitizer(SanitizerContract(
        "defusedxml.fromstring", SanitizerType.DEFUSED_XML,
        applicable_sinks=frozenset({SinkType.XML_PARSE}),
        description="Defused XML fromstring"
    ))
    
    # ===== Type Conversion Sanitizers =====
    
    register_sanitizer(SanitizerContract(
        "builtins.int", SanitizerType.TYPE_CONVERSION,
        applicable_sinks=frozenset({SinkType.SQL_EXECUTE, SinkType.FILE_PATH, SinkType.COMMAND_SHELL}),
        description="Integer conversion (validates format)"
    ))
    register_sanitizer(SanitizerContract(
        "int", SanitizerType.TYPE_CONVERSION,
        applicable_sinks=frozenset({SinkType.SQL_EXECUTE, SinkType.FILE_PATH, SinkType.COMMAND_SHELL}),
        description="Integer conversion"
    ))
    register_sanitizer(SanitizerContract(
        "builtins.float", SanitizerType.TYPE_CONVERSION,
        applicable_sinks=frozenset({SinkType.SQL_EXECUTE}),
        description="Float conversion"
    ))
    register_sanitizer(SanitizerContract(
        "uuid.UUID", SanitizerType.TYPE_CONVERSION,
        applicable_sinks=frozenset({SinkType.SQL_EXECUTE, SinkType.FILE_PATH}),
        description="UUID validation"
    ))
    
    # Boolean conversion - constrains to True/False
    register_sanitizer(SanitizerContract(
        "builtins.bool", SanitizerType.TYPE_CONVERSION,
        applicable_sinks=frozenset({SinkType.SQL_EXECUTE, SinkType.COMMAND_SHELL, SinkType.FILE_PATH}),
        description="Boolean conversion (constrains to True/False)"
    ))
    register_sanitizer(SanitizerContract(
        "bool", SanitizerType.TYPE_CONVERSION,
        applicable_sinks=frozenset({SinkType.SQL_EXECUTE, SinkType.COMMAND_SHELL, SinkType.FILE_PATH}),
        description="Boolean conversion"
    ))
    
    # String methods that sanitize by validating format
    register_sanitizer(SanitizerContract(
        "str.isdigit", SanitizerType.TYPE_CONVERSION,
        applicable_sinks=frozenset({SinkType.SQL_EXECUTE, SinkType.FILE_PATH}),
        description="Returns True only if string is all digits (validation check)"
    ))
    register_sanitizer(SanitizerContract(
        "str.isalpha", SanitizerType.TYPE_CONVERSION,
        applicable_sinks=frozenset({SinkType.SQL_EXECUTE, SinkType.FILE_PATH, SinkType.COMMAND_SHELL}),
        description="Returns True only if string is all alphabetic"
    ))
    register_sanitizer(SanitizerContract(
        "str.isalnum", SanitizerType.TYPE_CONVERSION,
        applicable_sinks=frozenset({SinkType.SQL_EXECUTE, SinkType.FILE_PATH, SinkType.COMMAND_SHELL}),
        description="Returns True only if string is alphanumeric"
    ))
    
    # Datetime parsing - validates format and constrains domain
    register_sanitizer(SanitizerContract(
        "datetime.datetime.fromisoformat", SanitizerType.TYPE_CONVERSION,
        applicable_sinks=frozenset({SinkType.SQL_EXECUTE}),
        description="Datetime from ISO format (validates structure)"
    ))
    register_sanitizer(SanitizerContract(
        "datetime.date.fromisoformat", SanitizerType.TYPE_CONVERSION,
        applicable_sinks=frozenset({SinkType.SQL_EXECUTE}),
        description="Date from ISO format"
    ))
    register_sanitizer(SanitizerContract(
        "datetime.datetime.strptime", SanitizerType.TYPE_CONVERSION,
        applicable_sinks=frozenset({SinkType.SQL_EXECUTE}),
        description="Datetime from format string (validates structure)"
    ))
    
    # Path canonicalization
    register_sanitizer(SanitizerContract(
        "pathlib.Path", SanitizerType.CANONICALIZE,
        applicable_sinks=frozenset({SinkType.FILE_PATH}),
        description="Path object creation (canonicalization)"
    ))
    register_sanitizer(SanitizerContract(
        "pathlib.Path.resolve", SanitizerType.CANONICALIZE,
        applicable_sinks=frozenset({SinkType.FILE_PATH}),
        description="Resolve path to absolute (follows symlinks)"
    ))
    
    # IP address validation - constrains to valid IP format
    register_sanitizer(SanitizerContract(
        "ipaddress.ip_address", SanitizerType.TYPE_CONVERSION,
        applicable_sinks=frozenset({SinkType.SQL_EXECUTE, SinkType.HTTP_REQUEST, SinkType.NETWORK_BIND}),
        description="IP address validation (IPv4/IPv6)"
    ))
    register_sanitizer(SanitizerContract(
        "ipaddress.IPv4Address", SanitizerType.TYPE_CONVERSION,
        applicable_sinks=frozenset({SinkType.SQL_EXECUTE, SinkType.HTTP_REQUEST, SinkType.NETWORK_BIND}),
        description="IPv4 address validation"
    ))
    register_sanitizer(SanitizerContract(
        "ipaddress.IPv6Address", SanitizerType.TYPE_CONVERSION,
        applicable_sinks=frozenset({SinkType.SQL_EXECUTE, SinkType.HTTP_REQUEST, SinkType.NETWORK_BIND}),
        description="IPv6 address validation"
    ))
    
    # Enum conversion - constrains to predefined set
    register_sanitizer(SanitizerContract(
        "enum.Enum", SanitizerType.ALLOWLIST_CHECK,
        applicable_sinks=frozenset({SinkType.SQL_EXECUTE, SinkType.COMMAND_SHELL, SinkType.FILE_PATH}),
        description="Enum lookup (constrains to predefined values)"
    ))
    
    # JSON parsing - safe for deserialization sink
    register_sanitizer(SanitizerContract(
        "json.loads", SanitizerType.JSON_PARSE,
        applicable_sinks=frozenset({SinkType.DESERIALIZE}),
        description="JSON parsing (no code execution)"
    ))
    register_sanitizer(SanitizerContract(
        "json.load", SanitizerType.JSON_PARSE,
        applicable_sinks=frozenset({SinkType.DESERIALIZE}),
        description="JSON file loading (no code execution)"
    ))
    
    # Bytes/encoding conversions that constrain domain
    register_sanitizer(SanitizerContract(
        "builtins.bytes", SanitizerType.TYPE_CONVERSION,
        applicable_sinks=frozenset({SinkType.SQL_EXECUTE}),
        description="Bytes conversion"
    ))
    register_sanitizer(SanitizerContract(
        "str.encode", SanitizerType.TYPE_CONVERSION,
        applicable_sinks=frozenset({SinkType.SQL_EXECUTE}),
        description="String encode to bytes (validates encoding)"
    ))
    register_sanitizer(SanitizerContract(
        "bytes.decode", SanitizerType.TYPE_CONVERSION,
        applicable_sinks=frozenset({SinkType.SQL_EXECUTE}),
        description="Bytes decode to string (validates encoding)"
    ))
    
    # ===== Declassification Sanitizers (for σ) =====
    
    register_sanitizer(SanitizerContract(
        "hashlib.pbkdf2_hmac", SanitizerType.HASHING,
        applicable_sinks=frozenset({SinkType.LOG_OUTPUT, SinkType.FILE_WRITE, SinkType.HASH_PASSWORD}),
        clears_sensitivity=True,
        description="PBKDF2 password hashing (declassification)"
    ))
    register_sanitizer(SanitizerContract(
        "bcrypt.hashpw", SanitizerType.HASHING,
        applicable_sinks=frozenset({SinkType.LOG_OUTPUT, SinkType.FILE_WRITE, SinkType.HASH_PASSWORD}),
        clears_sensitivity=True,
        description="bcrypt password hashing (declassification)"
    ))
    register_sanitizer(SanitizerContract(
        "argon2.PasswordHasher.hash", SanitizerType.HASHING,
        applicable_sinks=frozenset({SinkType.LOG_OUTPUT, SinkType.FILE_WRITE, SinkType.HASH_PASSWORD}),
        clears_sensitivity=True,
        description="Argon2 password hashing (declassification)"
    ))
    
    # Weak hash functions - act as sanitizers (declassify) but trigger WEAK_SENSITIVE_DATA_HASHING
    # Semantically correct: hashed data is no longer "cleartext" even if hash is weak
    register_sanitizer(SanitizerContract(
        "hashlib.sha256", SanitizerType.HASHING,
        applicable_sinks=frozenset({SinkType.LOG_OUTPUT, SinkType.FILE_WRITE, SinkType.HASH_PASSWORD}),
        clears_sensitivity=True,
        description="SHA-256 hashing (declassifies but weak for passwords)"
    ))
    register_sanitizer(SanitizerContract(
        "hashlib.sha1", SanitizerType.HASHING,
        applicable_sinks=frozenset({SinkType.LOG_OUTPUT, SinkType.FILE_WRITE, SinkType.HASH_PASSWORD}),
        clears_sensitivity=True,
        description="SHA-1 hashing (declassifies but weak for passwords)"
    ))
    register_sanitizer(SanitizerContract(
        "hashlib.md5", SanitizerType.HASHING,
        applicable_sinks=frozenset({SinkType.LOG_OUTPUT, SinkType.FILE_WRITE, SinkType.HASH_PASSWORD}),
        clears_sensitivity=True,
        description="MD5 hashing (declassifies but weak for passwords)"
    ))
    
    # Hash object methods - these should preserve sanitization from the hash object
    # ITERATION 566: Add .hexdigest() and .digest() as sanitizers to handle:
    #   hashed = hashlib.sha256(password.encode()).hexdigest()
    # The hash object from hashlib.sha256() is already sanitized, and calling
    # .hexdigest() on it should preserve that sanitization.
    register_sanitizer(SanitizerContract(
        "hexdigest", SanitizerType.HASHING,
        applicable_sinks=frozenset({SinkType.LOG_OUTPUT, SinkType.FILE_WRITE, SinkType.HASH_PASSWORD}),
        clears_sensitivity=True,
        description="Hash.hexdigest() - preserve hash sanitization"
    ))
    register_sanitizer(SanitizerContract(
        "digest", SanitizerType.HASHING,
        applicable_sinks=frozenset({SinkType.LOG_OUTPUT, SinkType.FILE_WRITE, SinkType.HASH_PASSWORD}),
        clears_sensitivity=True,
        description="Hash.digest() - preserve hash sanitization"
    ))
    
    register_sanitizer(SanitizerContract(
        "cryptography.fernet.Fernet.encrypt", SanitizerType.ENCRYPTION,
        applicable_sinks=frozenset({SinkType.LOG_OUTPUT, SinkType.FILE_WRITE, SinkType.NETWORK_SEND}),
        clears_sensitivity=True,
        description="Fernet encryption (declassification)"
    ))
    
    # ===== Regex Validation Pattern Sanitizers (Iteration 545) =====
    # 
    # These sanitizers work differently from others: they constrain the input domain
    # rather than escaping. When re.match(pattern, user_input) returns truthy AND
    # the code uses the result, the input is safe for specific sinks.
    #
    # Examples:
    #   if re.match(r'^[a-zA-Z0-9_]+$', user_input):
    #       cursor.execute(f"SELECT * FROM users WHERE id = {user_input}")  # SAFE - alphanumeric only
    #
    #   if re.match(r'^\d+$', page_num):
    #       os.system(f'process_page {page_num}')  # SAFE - digits only
    #
    # Implementation note: These are applied when the security tracker detects:
    # 1. re.match/fullmatch/search with a restrictive pattern
    # 2. Conditional branch taken when match succeeds
    # 3. Tainted value used inside that branch
    
    register_sanitizer(SanitizerContract(
        "re.match:^[a-zA-Z0-9_]+$", SanitizerType.REGEX_ALPHANUMERIC,
        applicable_sinks=frozenset({
            SinkType.SQL_EXECUTE, SinkType.FILE_PATH, SinkType.COMMAND_SHELL,
            SinkType.LDAP_QUERY, SinkType.NOSQL_QUERY
        }),
        description="Alphanumeric + underscore validation (constrains to safe charset)"
    ))
    
    register_sanitizer(SanitizerContract(
        "re.match:^[a-zA-Z0-9]+$", SanitizerType.REGEX_ALPHANUMERIC,
        applicable_sinks=frozenset({
            SinkType.SQL_EXECUTE, SinkType.FILE_PATH, SinkType.COMMAND_SHELL,
            SinkType.LDAP_QUERY, SinkType.NOSQL_QUERY
        }),
        description="Alphanumeric validation (no special chars)"
    ))
    
    register_sanitizer(SanitizerContract(
        "re.match:^\\d+$", SanitizerType.REGEX_DIGITS,
        applicable_sinks=frozenset({
            SinkType.SQL_EXECUTE, SinkType.FILE_PATH, SinkType.COMMAND_SHELL,
            SinkType.LDAP_QUERY, SinkType.NOSQL_QUERY
        }),
        description="Digits-only validation (numeric input)"
    ))
    
    register_sanitizer(SanitizerContract(
        "re.match:^[0-9]+$", SanitizerType.REGEX_DIGITS,
        applicable_sinks=frozenset({
            SinkType.SQL_EXECUTE, SinkType.FILE_PATH, SinkType.COMMAND_SHELL,
            SinkType.LDAP_QUERY, SinkType.NOSQL_QUERY
        }),
        description="Digits-only validation (alternative pattern)"
    ))
    
    register_sanitizer(SanitizerContract(
        "re.match:^[a-z0-9.-]+$", SanitizerType.REGEX_HOSTNAME,
        applicable_sinks=frozenset({
            SinkType.HTTP_REQUEST, SinkType.REDIRECT_URL, SinkType.SQL_EXECUTE,
            SinkType.FILE_PATH, SinkType.NETWORK_BIND
        }),
        description="Hostname pattern validation (DNS-safe chars)"
    ))
    
    register_sanitizer(SanitizerContract(
        "re.match:^[a-zA-Z0-9.-]+$", SanitizerType.REGEX_HOSTNAME,
        applicable_sinks=frozenset({
            SinkType.HTTP_REQUEST, SinkType.REDIRECT_URL, SinkType.SQL_EXECUTE,
            SinkType.FILE_PATH, SinkType.NETWORK_BIND
        }),
        description="Hostname pattern (case-insensitive)"
    ))
    
    register_sanitizer(SanitizerContract(
        "re.match:^[a-z0-9-]+$", SanitizerType.REGEX_SLUG,
        applicable_sinks=frozenset({
            SinkType.SQL_EXECUTE, SinkType.FILE_PATH, SinkType.HTTP_REQUEST,
            SinkType.REDIRECT_URL
        }),
        description="URL slug pattern (lowercase alphanumeric + hyphen)"
    ))
    
    register_sanitizer(SanitizerContract(
        "re.match:^[0-9a-fA-F]+$", SanitizerType.REGEX_HEX,
        applicable_sinks=frozenset({
            SinkType.SQL_EXECUTE, SinkType.FILE_PATH, SinkType.COMMAND_SHELL
        }),
        description="Hexadecimal pattern validation"
    ))
    
    register_sanitizer(SanitizerContract(
        "re.match:^[0-9a-f-]+$", SanitizerType.REGEX_UUID,
        applicable_sinks=frozenset({
            SinkType.SQL_EXECUTE, SinkType.FILE_PATH, SinkType.HTTP_REQUEST
        }),
        description="UUID pattern (lowercase hex + hyphens)"
    ))
    
    register_sanitizer(SanitizerContract(
        "re.match:^[A-Za-z0-9+/=]+$", SanitizerType.REGEX_BASE64,
        applicable_sinks=frozenset({
            SinkType.SQL_EXECUTE, SinkType.FILE_PATH
        }),
        description="Base64 pattern validation"
    ))
    
    register_sanitizer(SanitizerContract(
        "re.match:^[\\w.-]+@[\\w.-]+\\.\\w+$", SanitizerType.REGEX_EMAIL,
        applicable_sinks=frozenset({
            SinkType.SQL_EXECUTE, SinkType.EMAIL_HEADER, SinkType.LDAP_QUERY
        }),
        description="Email pattern validation (basic)"
    ))
    
    register_sanitizer(SanitizerContract(
        "re.match:^/[a-zA-Z0-9/_-]+$", SanitizerType.REGEX_URL_PATH,
        applicable_sinks=frozenset({
            SinkType.HTTP_REQUEST, SinkType.REDIRECT_URL
        }),
        description="URL path component validation (safe chars only)"
    ))
    
    register_sanitizer(SanitizerContract(
        "re.match:^[a-zA-Z0-9/_.-]+$", SanitizerType.REGEX_FILEPATH,
        applicable_sinks=frozenset({
            SinkType.FILE_PATH, SinkType.SQL_EXECUTE
        }),
        description="Safe filepath pattern (no traversal chars)"
    ))


# ============================================================================
# SUMMARY COMPUTER INTERFACE
# ============================================================================

def get_source_contracts_for_summaries() -> Dict[str, int]:
    """
    Export source contracts in format for SummaryComputer.
    
    Returns: Dict[func_name, source_type_int]
    """
    result = {}
    for func_name, contract in _source_contracts.items():
        result[func_name] = contract.source_type.value
    return result


def get_sink_contracts_for_summaries() -> Dict[str, Set[int]]:
    """
    Export sink contracts in format for SummaryComputer.
    
    For functions with multiple sinks, returns all sink types as a set.
    
    Returns: Dict[func_name, Set[sink_type_int]]
    """
    result = {}
    for func_name, contracts in _sink_contracts.items():
        if contracts:
            # Collect all sink types for multi-sink functions (e.g., print() has both LOG_FORGING and LOG_OUTPUT)
            result[func_name] = {c.sink_type.value for c in contracts}
    return result


def get_sanitizer_contracts_for_summaries() -> Dict[str, Set[int]]:
    """
    Export sanitizer contracts in format for SummaryComputer.
    
    Returns: Dict[func_name, Set[sink_type_int]]
    """
    result = {}
    for func_name, contract in _sanitizer_contracts.items():
        # Convert frozenset of SinkTypes to set of ints
        sink_ints = {sink.value for sink in contract.applicable_sinks}
        result[func_name] = sink_ints
    return result


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    # Contracts
    'SourceContract', 'SinkContract', 'SanitizerContract',
    
    # Registration
    'register_source', 'register_sink', 'register_sanitizer',
    
    # Lookup
    'get_source_contract', 'get_sink_contract', 'get_sanitizer_contract',
    'is_taint_source', 'is_security_sink', 'is_sanitizer',
    
    # Application
    'apply_source_taint', 'apply_source_taint_symbolic',
    'check_sink_taint', 'create_sink_unsafe_constraint',
    'apply_sanitizer', 'apply_sanitizer_symbolic',
    
    # Initialization
    'init_security_contracts',
    
    # Summary Computer Interface (Phase 4B)
    'get_source_contracts_for_summaries',
    'get_sink_contracts_for_summaries',
    'get_sanitizer_contracts_for_summaries',
]

# ============================================================================
# AUTO-INITIALIZATION
# ============================================================================

# Auto-initialize contracts when module is imported
# This ensures contracts are available for all analyses
init_security_contracts()
