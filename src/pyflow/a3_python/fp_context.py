"""
False Positive Context Detection and Confidence Adjustment.

This module implements context-aware FP reduction from the FALSE_POSITIVE_REDUCTION_PLAN.md.

Key contexts that reduce confidence:
1. CLI Tool Context: argparse, click, sys.argv, env vars
2. Test File Context: test_*.py, *_test.py files
3. Safe Loader Context: yaml.safe_load, ruamel.yaml(typ='safe')
4. Self-Data Context: loading data that was saved by the same codebase
5. Defense-in-Depth: call chains with mitigation functions

Each context provides a confidence multiplier that reduces false positives.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, FrozenSet, Tuple
from pathlib import Path
from enum import IntEnum, auto
import re


# ============================================================================
# FP CONTEXT CATEGORIES
# ============================================================================

class FPContext(IntEnum):
    """Context categories that affect false positive likelihood."""
    NONE = 0
    CLI_TOOL = auto()           # argparse, click, sys.argv
    ENV_VAR_CONFIG = auto()     # Environment variable for config
    TEST_FILE = auto()          # Test file (test_*.py)
    SAFE_LOADER = auto()        # yaml.safe_load, etc.
    SELF_DATA_FLOW = auto()     # Save then load own data
    DEFENSE_IN_DEPTH = auto()   # Mitigation function in call chain
    DEBUG_CODE = auto()         # Code in debug/development paths
    INTERNAL_API = auto()       # Internal library function (no attack surface)


# ============================================================================
# CONFIDENCE ADJUSTMENTS
# ============================================================================

# Multipliers for each context (applied to base confidence)
# Values < 1.0 reduce confidence (reduce FPs)
# Values > 1.0 increase confidence (should never be used)
FP_CONTEXT_MULTIPLIERS: Dict[FPContext, float] = {
    FPContext.NONE: 1.0,
    FPContext.CLI_TOOL: 0.25,          # 75% reduction for CLI tools
    FPContext.ENV_VAR_CONFIG: 0.30,    # 70% reduction for env configs
    FPContext.TEST_FILE: 0.15,         # 85% reduction for tests
    FPContext.SAFE_LOADER: 0.0,        # 100% reduction (never report)
    FPContext.SELF_DATA_FLOW: 0.30,    # 70% reduction
    FPContext.DEFENSE_IN_DEPTH: 0.40,  # 60% reduction
    FPContext.DEBUG_CODE: 0.20,        # 80% reduction
    FPContext.INTERNAL_API: 0.50,      # 50% reduction
}

# Bug types that are correctness bugs in the code itself, not security/taint issues.
# These should NOT be penalized by DEFENSE_IN_DEPTH context, because the bug IS
# in the validation/check function (e.g., missing sorted() before join).
_CORRECTNESS_BUG_TYPES = {
    'ORDER_VIOLATION',
}

# Bug types that are particularly affected by CLI context
CLI_SENSITIVE_BUG_TYPES = {
    'PATH_INJECTION', 'TARSLIP', 'ZIPSLIP',
    'COMMAND_INJECTION',  # Less reduction for this
    'PICKLE_INJECTION', 'UNSAFE_DESERIALIZATION', 'YAML_INJECTION',
}

# Crash bug types that have reduced severity in CLI context
# In CLI tools, crashes from user input are less severe (user controls input)
CLI_REDUCED_CRASH_BUGS = {
    'NULL_PTR', 'BOUNDS', 'ITERATOR_INVALID', 'DIV_ZERO', 'TYPE_CONFUSION',
}

# Bug types where CLI context should NOT reduce confidence much
CLI_STILL_RISKY_BUG_TYPES = {
    'SQL_INJECTION',  # SQL injection from CLI is still bad
    'CODE_INJECTION',  # Code injection from CLI is still bad
}


# ============================================================================
# SOURCE TYPE CLASSIFICATION
# ============================================================================

# Map source descriptions to context
CLI_SOURCE_PATTERNS = {
    'sys.argv',
    'argparse',
    'ArgumentParser',
    'parse_args',
    'click.option',
    'click.argument',
    'click.command',
    'typer.Option',
    'typer.Argument',
}

ENV_SOURCE_PATTERNS = {
    'os.environ',
    'os.getenv',
    'environ.get',
    'environ[',
}

# Safe loader function patterns (should NEVER be flagged)
SAFE_LOADER_PATTERNS = {
    'yaml.safe_load',
    'yaml.safe_load_all',
    'yaml.SafeLoader',
    'strictyaml.load',
    'strictyaml.as_document',
}

# Safe template patterns (NOT Jinja2-style, no code execution)
# Python's string.Template only supports $variable substitution, no expressions
SAFE_TEMPLATE_PATTERNS = {
    'string.Template',
    'Template.substitute',
    'Template.safe_substitute',
}

# ruamel.yaml safe types (typ parameter)
RUAMEL_SAFE_TYPES = {'safe', 'rt', 'pure'}

# Defense-in-depth mitigation function name patterns
MITIGATION_FUNCTION_PATTERNS = {
    'sanitize', 'validate', 'filter', 'escape', 'quote',
    'clean', 'normalize', 'safe_', 'secure_', 'verify',
    'check_', 'is_valid', 'is_safe', 'allowlist', 'whitelist',
    'parse_field',  # Qlib's operator prefix pattern
}


# ============================================================================
# CONTEXT DETECTOR
# ============================================================================

@dataclass
class FPContextResult:
    """Result of FP context detection."""
    contexts: Set[FPContext] = field(default_factory=set)
    confidence_multiplier: float = 1.0
    reasons: List[str] = field(default_factory=list)
    
    def add_context(self, context: FPContext, reason: str) -> None:
        """Add a detected context."""
        self.contexts.add(context)
        self.reasons.append(reason)
        # Combine multipliers (take minimum for most reduction)
        self.confidence_multiplier = min(
            self.confidence_multiplier,
            FP_CONTEXT_MULTIPLIERS[context]
        )


class FPContextDetector:
    """
    Detects FP-reducing contexts for security findings.
    
    Analyzes source types, file paths, call chains, and code patterns
    to identify contexts where false positives are likely.
    """
    
    def __init__(self):
        # Cache for file-level context (test files, etc.)
        self._file_context_cache: Dict[str, Set[FPContext]] = {}
        # Cache for file content analysis
        self._file_cli_cache: Dict[str, bool] = {}
    
    def detect_contexts(
        self,
        bug_type: str,
        tainted_sources: List[str],
        file_path: Optional[str] = None,
        call_chain: Optional[List[str]] = None,
        sink_function: Optional[str] = None,
    ) -> FPContextResult:
        """
        Detect all FP-reducing contexts for a finding.
        
        Args:
            bug_type: Type of bug (e.g., 'PATH_INJECTION')
            tainted_sources: List of source descriptions
            file_path: Path to file containing the finding
            call_chain: List of function names in call chain
            sink_function: Name of the sink function
        
        Returns:
            FPContextResult with detected contexts and confidence multiplier
        """
        result = FPContextResult()
        
        # 1. Check file-level context
        if file_path:
            self._detect_file_context(file_path, result, bug_type)
        
        # 2. Check source-level context
        self._detect_source_context(tainted_sources, bug_type, result)
        
        # 3. Check call chain for mitigations
        # Skip for correctness bugs (ORDER_VIOLATION) where the bug IS in
        # the validation/check function itself, not about missing defenses.
        if call_chain and bug_type not in _CORRECTNESS_BUG_TYPES:
            self._detect_mitigation_context(call_chain, result)
        
        # 4. Check sink function for safe patterns
        if sink_function:
            self._detect_safe_sink_context(sink_function, result)
        
        return result
    
    def _detect_file_context(self, file_path: str, result: FPContextResult, bug_type: str = None) -> None:
        """Detect file-level FP contexts."""
        # Check cache
        if file_path in self._file_context_cache:
            for ctx in self._file_context_cache[file_path]:
                result.add_context(ctx, f"File context: {ctx.name}")
            # Also check CLI tool context for path-sensitive bugs
            if bug_type in CLI_SENSITIVE_BUG_TYPES:
                if self._is_cli_tool_file(file_path):
                    result.add_context(FPContext.CLI_TOOL, f"CLI tool file: {Path(file_path).name}")
            # Also check CLI context for crash bugs (lower severity in CLI tools)
            if bug_type in CLI_REDUCED_CRASH_BUGS:
                if self._is_cli_tool_file(file_path):
                    result.add_context(FPContext.INTERNAL_API, f"CLI crash bug (lower severity): {Path(file_path).name}")
            # Also check for safe template if JINJA2/TEMPLATE bug
            if bug_type in ('JINJA2_INJECTION', 'TEMPLATE_INJECTION'):
                if self._uses_safe_string_template(file_path):
                    result.add_context(FPContext.SAFE_LOADER, f"Uses string.Template (not Jinja2): {Path(file_path).name}")
            return
        
        path = Path(file_path)
        contexts = set()
        
        # Test file detection
        if self._is_test_file(path):
            contexts.add(FPContext.TEST_FILE)
            result.add_context(FPContext.TEST_FILE, f"Test file: {path.name}")
        
        # Debug file detection
        if self._is_debug_file(path):
            contexts.add(FPContext.DEBUG_CODE)
            result.add_context(FPContext.DEBUG_CODE, f"Debug file: {path.name}")
        
        # CLI tool detection (by file content analysis)
        # For security bugs (PATH_INJECTION, etc.), CLI context means user controls input
        if bug_type in CLI_SENSITIVE_BUG_TYPES:
            if self._is_cli_tool_file(file_path):
                result.add_context(FPContext.CLI_TOOL, f"CLI tool file: {path.name}")
        
        # CLI tool detection for crash bugs
        # Crash bugs in CLI tools are lower severity (user controls input, not remote attacker)
        if bug_type in CLI_REDUCED_CRASH_BUGS:
            if self._is_cli_tool_file(file_path):
                # Use lower multiplier for crash bugs in CLI (0.5 instead of 0.25)
                result.add_context(FPContext.INTERNAL_API, f"CLI crash bug (lower severity): {path.name}")
        
        # Safe template detection for JINJA2_INJECTION/TEMPLATE_INJECTION
        # If file uses string.Template (safe) instead of jinja2.Template, it's a FP
        if bug_type in ('JINJA2_INJECTION', 'TEMPLATE_INJECTION'):
            if self._uses_safe_string_template(file_path):
                result.add_context(FPContext.SAFE_LOADER, f"Uses string.Template (not Jinja2): {path.name}")
        
        # Cache result
        self._file_context_cache[file_path] = contexts
    
    def _is_cli_tool_file(self, file_path: str) -> bool:
        """
        Check if file is a CLI tool by analyzing its content and location.
        
        Looks for:
        - Files in cli/ directories (common convention)
        - argparse.ArgumentParser
        - click.command / click.option
        - typer imports
        - if __name__ == "__main__" with sys.argv
        """
        # Check cache
        if file_path in self._file_cli_cache:
            return self._file_cli_cache[file_path]
        
        path = Path(file_path)
        
        # Check if file is in a cli/ directory (common convention)
        # e.g., graphrag/cli/initialize.py, myapp/cli/main.py
        path_parts = path.parts
        if 'cli' in path_parts:
            self._file_cli_cache[file_path] = True
            return True
        
        # Check if file is in a config/ directory (config loading is CLI-like)
        # Config files are loaded from local paths specified by CLI arguments
        # e.g., graphrag/config/load_config.py, myapp/config/settings.py
        if 'config' in path_parts or 'configs' in path_parts:
            self._file_cli_cache[file_path] = True
            return True
        
        # Check if file is in utils/ or logger/ directory (internal utilities)
        # NOTE: Do NOT treat utils/ as CLI context for crash bug reduction.
        # Utils directories contain core library code that processes data from
        # many sources — crash bugs here are real and affect all callers.
        # Only check for actual CLI-related directories (see cli_patterns below).
        # if 'utils' in path_parts or 'logger' in path_parts:
        #     self._file_cli_cache[file_path] = True
        #     return True
        
        # Also check for common CLI module names
        if path.stem in ('cli', 'main', '__main__', 'console', 'commands'):
            # Could be a CLI entry point - check content
            pass
        
        try:
            content = path.read_text()
        except Exception:
            self._file_cli_cache[file_path] = False
            return False
        
        # CLI patterns in imports and usage
        cli_patterns = [
            r'import\s+argparse',
            r'from\s+argparse\s+import',
            r'argparse\.ArgumentParser',
            r'parser\.add_argument',
            r'parser\.parse_args',
            r'import\s+click',
            r'from\s+click\s+import',
            r'@click\.command',
            r'@click\.option',
            r'@click\.argument',
            r'import\s+typer',
            r'from\s+typer\s+import',
            r'@typer\.command',
            r'sys\.argv\[',
            r'fire\.Fire\(',
        ]
        
        is_cli = any(re.search(pat, content) for pat in cli_patterns)
        
        # Additional: check for main guard with argparse/click context
        if 'if __name__' in content and ('argparse' in content or 'click' in content or 'sys.argv' in content):
            is_cli = True
        
        self._file_cli_cache[file_path] = is_cli
        return is_cli
    
    def _is_test_file(self, path: Path) -> bool:
        """Check if file is a test file."""
        name = path.name.lower()
        
        # Common test file patterns
        if name.startswith('test_') or name.endswith('_test.py'):
            return True
        if name.startswith('tests_') or name.endswith('_tests.py'):
            return True
        if name == 'conftest.py':
            return True
        
        # Check parent directories
        for part in path.parts:
            if part.lower() in ('tests', 'test', 'testing', 'spec', 'specs'):
                return True
        
        return False
    
    def _is_debug_file(self, path: Path) -> bool:
        """Check if file is debug/development code."""
        name = path.name.lower()
        
        if name.startswith('debug_') or name.endswith('_debug.py'):
            return True
        if 'scratch' in name or 'playground' in name:
            return True
        
        return False
    
    def _uses_safe_string_template(self, file_path: str) -> bool:
        """
        Check if file uses Python's safe string.Template instead of Jinja2.
        
        Python's string.Template only supports $variable substitution.
        It does NOT support expressions or code execution like Jinja2.
        """
        try:
            content = Path(file_path).read_text()
        except Exception:
            return False
        
        # Check for string.Template imports (safe)
        safe_patterns = [
            r'from\s+string\s+import\s+.*Template',
            r'import\s+string',  # Then uses string.Template
        ]
        
        # Check for jinja2 imports (not safe)
        jinja2_patterns = [
            r'from\s+jinja2\s+import',
            r'import\s+jinja2',
        ]
        
        has_safe = any(re.search(pat, content) for pat in safe_patterns)
        has_jinja2 = any(re.search(pat, content) for pat in jinja2_patterns)
        
        # If file uses string.Template and NOT jinja2, it's safe
        return has_safe and not has_jinja2
    
    def _detect_source_context(
        self,
        tainted_sources: List[str],
        bug_type: str,
        result: FPContextResult,
    ) -> None:
        """Detect source-level FP contexts."""
        for source in tainted_sources:
            source_lower = source.lower()
            
            # CLI source detection
            if any(pat.lower() in source_lower for pat in CLI_SOURCE_PATTERNS):
                # Only reduce confidence for CLI-sensitive bug types
                if bug_type in CLI_SENSITIVE_BUG_TYPES:
                    result.add_context(
                        FPContext.CLI_TOOL,
                        f"CLI source: {source}"
                    )
                elif bug_type not in CLI_STILL_RISKY_BUG_TYPES:
                    # Partial reduction for other types
                    result.add_context(
                        FPContext.CLI_TOOL,
                        f"CLI source: {source}"
                    )
            
            # Environment variable detection
            if any(pat.lower() in source_lower for pat in ENV_SOURCE_PATTERNS):
                # Config paths from env vars are usually OK
                if bug_type in {'PATH_INJECTION', 'TARSLIP', 'ZIPSLIP'}:
                    result.add_context(
                        FPContext.ENV_VAR_CONFIG,
                        f"Env var source: {source}"
                    )
    
    def _detect_mitigation_context(
        self,
        call_chain: List[str],
        result: FPContextResult,
    ) -> None:
        """Detect mitigation functions in call chain.
        
        Only checks CALLERS in the call chain, not the crash function itself
        (last element). The crash function having a name like 'verify_X' doesn't
        mean the bug is mitigated — it means the bug IS in that function.
        """
        # Skip the crash function (last element) — only check callers
        callers = call_chain[:-1] if len(call_chain) > 1 else []
        for func_name in callers:
            func_lower = func_name.lower()
            
            # Check for mitigation patterns
            for pattern in MITIGATION_FUNCTION_PATTERNS:
                if pattern in func_lower:
                    result.add_context(
                        FPContext.DEFENSE_IN_DEPTH,
                        f"Mitigation function: {func_name}"
                    )
                    return  # One mitigation is enough
    
    def _detect_safe_sink_context(
        self,
        sink_function: str,
        result: FPContextResult,
    ) -> None:
        """Detect safe sink patterns (e.g., yaml.safe_load)."""
        sink_lower = sink_function.lower()
        
        # Safe YAML loaders
        for pattern in SAFE_LOADER_PATTERNS:
            if pattern.lower() in sink_lower:
                result.add_context(
                    FPContext.SAFE_LOADER,
                    f"Safe loader: {sink_function}"
                )
                return
        
        # Safe template patterns (string.Template, not Jinja2)
        for pattern in SAFE_TEMPLATE_PATTERNS:
            if pattern.lower() in sink_lower:
                result.add_context(
                    FPContext.SAFE_LOADER,
                    f"Safe template (string.Template): {sink_function}"
                )
                return
        
        # ruamel.yaml safe mode detection would need argument analysis
        # For now, assume ruamel.yaml is safe by default (it is)
        if 'ruamel' in sink_lower and 'yaml' in sink_lower:
            result.add_context(
                FPContext.SAFE_LOADER,
                f"ruamel.yaml (safe by default): {sink_function}"
            )


def detect_source_type_from_description(source_desc: str) -> Optional[str]:
    """
    Determine the source type from a source description string.
    
    Returns 'CLI', 'ENV', 'HTTP', 'FILE', 'USER_INPUT', or None.
    """
    source_lower = source_desc.lower()
    
    # CLI sources
    if any(pat.lower() in source_lower for pat in CLI_SOURCE_PATTERNS):
        return 'CLI'
    
    # Environment variables
    if any(pat.lower() in source_lower for pat in ENV_SOURCE_PATTERNS):
        return 'ENV'
    
    # HTTP sources (high risk)
    http_patterns = {'request.', 'http_', 'flask.request', 'django.request',
                     '.get(', '.post(', 'query_params', 'form_data'}
    if any(pat in source_lower for pat in http_patterns):
        return 'HTTP'
    
    # File content
    if 'file_content' in source_lower or 'open(' in source_lower:
        return 'FILE'
    
    # User input
    if 'input(' in source_lower or 'stdin' in source_lower:
        return 'USER_INPUT'
    
    return None


def adjust_confidence_for_context(
    base_confidence: float,
    bug_type: str,
    tainted_sources: List[str],
    file_path: Optional[str] = None,
    call_chain: Optional[List[str]] = None,
    sink_function: Optional[str] = None,
) -> Tuple[float, FPContextResult]:
    """
    Convenience function to adjust confidence based on context.
    
    Returns:
        Tuple of (adjusted_confidence, context_result)
    """
    detector = FPContextDetector()
    context_result = detector.detect_contexts(
        bug_type=bug_type,
        tainted_sources=tainted_sources,
        file_path=file_path,
        call_chain=call_chain,
        sink_function=sink_function,
    )
    
    adjusted = base_confidence * context_result.confidence_multiplier
    return adjusted, context_result


def is_likely_false_positive(
    bug_type: str,
    tainted_sources: List[str],
    file_path: Optional[str] = None,
    confidence_threshold: float = 0.40,
) -> bool:
    """
    Quick check if a finding is likely a false positive.
    
    Returns True if the finding should be suppressed.
    """
    adjusted_conf, _ = adjust_confidence_for_context(
        base_confidence=1.0,  # Assume max base confidence
        bug_type=bug_type,
        tainted_sources=tainted_sources,
        file_path=file_path,
    )
    
    return adjusted_conf < confidence_threshold


# ============================================================================
# SINGLETON DETECTOR
# ============================================================================

_detector: Optional[FPContextDetector] = None

def get_fp_detector() -> FPContextDetector:
    """Get or create the global FP context detector."""
    global _detector
    if _detector is None:
        _detector = FPContextDetector()
    return _detector


# ============================================================================
# TYPE ANNOTATION GUARD FOR TYPE_CONFUSION FP SUPPRESSION
# ============================================================================

import ast as _ast
import functools as _functools


@_functools.lru_cache(maxsize=256)
def _parse_source_cached(filepath: str):
    """Parse a Python source file, returning AST tree or None."""
    try:
        source = Path(filepath).read_text(encoding="utf-8", errors="ignore")
        return _ast.parse(source, filename=filepath)
    except Exception:
        return None


def module_all_functions_type_annotated(co_filename: str) -> bool:
    """Return True if every top-level function in *co_filename* has fully annotated params + return.

    Used to suppress TYPE_CONFUSION FPs during module-level symbolic execution
    of new files where the VM cannot inline annotated function calls and
    falls back to OBJ-typed results.
    """
    tree = _parse_source_cached(co_filename)
    if tree is None:
        return False
    found_any = False
    for node in _ast.iter_child_nodes(tree):
        if not isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
            continue
        found_any = True
        args = node.args
        all_params = args.posonlyargs + args.args + args.kwonlyargs
        if not all_params:
            continue  # zero-param helper – skip, don't disqualify
        for arg in all_params:
            if arg.annotation is None:
                return False
        if node.returns is None:
            return False
    return found_any


def has_all_params_type_annotated(co_filename: str, co_name: str) -> bool:
    """Return True if every parameter of *co_name* in *co_filename* has a type annotation.

    Used to suppress TYPE_CONFUSION false positives on functions where the
    developer has provided complete type hints (the symbolic VM cannot
    leverage annotations and thus may flag type-safe operations).
    """
    tree = _parse_source_cached(co_filename)
    if tree is None:
        return False
    for node in _ast.walk(tree):
        if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)) and node.name == co_name:
            args = node.args
            all_params = args.posonlyargs + args.args + args.kwonlyargs
            if not all_params:
                return False  # no params → nothing to guard
            for arg in all_params:
                if arg.annotation is None:
                    return False
            # Also require a return annotation for higher confidence
            if node.returns is None:
                return False
            return True
    return False
