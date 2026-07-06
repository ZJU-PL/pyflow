"""
Intent Detector: Distinguishes intentional behavior from unintentional bugs.

This module provides a rigorous, multi-factor analysis to determine whether
a flagged issue is an intentional design choice or an unintentional bug.

Key insight: A "bug" requires BOTH:
  1. A semantic condition that could cause failure (e.g., division by zero)
  2. UNINTENTIONAL occurrence of that condition

Many static analysis findings fail criterion #2 - they are intentional:
  - Test code deliberately triggers edge cases
  - Validation code intentionally raises exceptions
  - Framework contracts guarantee certain invariants
  - Guard patterns prevent the condition from occurring
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
import re
import ast


class IntentCategory(Enum):
    """Categories of intentional behavior that reduce bug confidence."""
    
    # Language/Runtime Guarantees
    PYTHON_SELF_INVARIANT = auto()      # self/cls never None in methods
    PYTHON_SAFE_SLICING = auto()         # s[i:j] never raises IndexError
    PYTHON_ITERATOR_PROTOCOL = auto()    # for x in y handles empty y
    
    # Framework Guarantees
    FRAMEWORK_REQUEST_VALID = auto()     # Django/Flask request always valid
    FRAMEWORK_MANAGED_LIFECYCLE = auto() # ORM objects managed by framework
    
    # Code Intent Patterns
    INTENTIONAL_VALIDATION = auto()      # raise ValueError for invalid input
    INTENTIONAL_OPTIONAL_IMPORT = auto() # try: import x except ImportError
    GUARD_PATTERN_DETECTED = auto()      # x or default, if x is not None
    DEFAULT_PARAMETER_GUARD = auto()     # def f(x=1): ... / x won't be 0
    
    # File Context
    TEST_FILE = auto()                   # Tests intentionally trigger edge cases
    EXAMPLE_FILE = auto()                # Examples may be incomplete
    MIGRATION_FILE = auto()              # Migrations run in controlled context
    CONFIG_FILE = auto()                 # Config files have different semantics
    
    # Semantic Context
    EXCEPTION_HANDLER_CONTEXT = auto()   # Code inside except block
    ASSERTION_CONTEXT = auto()           # assert statements are debug-only
    UNREACHABLE_CODE = auto()            # Dead code after return/raise


@dataclass
class IntentSignal:
    """A single signal about the intent behind code."""
    category: IntentCategory
    confidence: float  # 0.0 to 1.0
    evidence: str      # Human-readable explanation
    

@dataclass
class IntentAnalysis:
    """Complete intent analysis for a potential bug."""
    signals: List[IntentSignal] = field(default_factory=list)
    
    @property
    def is_likely_intentional(self) -> bool:
        """True if the behavior is likely intentional, not a bug."""
        return self.unintentional_confidence < 0.5
    
    @property
    def unintentional_confidence(self) -> float:
        """
        Confidence that this is an UNINTENTIONAL bug (0.0 to 1.0).
        
        Computed as: 1.0 - max(intentional signals)
        
        A single strong intentional signal (e.g., test file) is enough
        to make the bug unlikely to be unintentional.
        """
        if not self.signals:
            return 1.0  # No signals = assume unintentional
        
        # Use probabilistic combination: P(unintentional) = ∏(1 - P(intentional_i))
        # This means multiple weak signals can combine to indicate intentional
        prob_unintentional = 1.0
        for signal in self.signals:
            prob_unintentional *= (1.0 - signal.confidence)
        
        return prob_unintentional
    
    @property
    def primary_reason(self) -> Optional[str]:
        """The strongest reason this might be intentional."""
        if not self.signals:
            return None
        strongest = max(self.signals, key=lambda s: s.confidence)
        return f"{strongest.category.name}: {strongest.evidence}"
    
    def add_signal(self, category: IntentCategory, confidence: float, evidence: str):
        """Add an intent signal."""
        self.signals.append(IntentSignal(category, confidence, evidence))


class IntentDetector:
    """
    Detects whether a flagged issue is intentional or an unintentional bug.
    
    Uses multiple signals:
    1. File context (name, path, purpose)
    2. Code patterns (guards, validation, error handling)
    3. Language semantics (Python guarantees)
    4. Framework conventions (Django, Flask, etc.)
    """
    
    # File patterns indicating test/example code
    TEST_PATTERNS = [
        r'test_.*\.py$',
        r'.*_test\.py$',
        r'.*/tests?/.*\.py$',
        r'.*_tests\.py$',
        r'conftest\.py$',
    ]
    
    EXAMPLE_PATTERNS = [
        r'.*/examples?/.*\.py$',
        r'.*/samples?/.*\.py$',
        r'.*/demo/.*\.py$',
        r'example_.*\.py$',
    ]
    
    CONFIG_PATTERNS = [
        r'.*config.*\.py$',
        r'.*settings.*\.py$',
        r'.*conf\.py$',
    ]
    
    MIGRATION_PATTERNS = [
        r'.*/migrations?/.*\.py$',
    ]
    
    # Framework request parameter patterns
    FRAMEWORK_REQUEST_PARAMS = {'request', 'req', 'http_request'}
    
    # Guard patterns in code
    GUARD_PATTERNS = [
        # or-default pattern: x or default
        r'\bor\s+\d+',           # or 1, or 0, etc.
        r'\bor\s+\[\]',          # or []
        r'\bor\s+\{\}',          # or {}
        r'\bor\s+""',            # or ""
        r'\bor\s+None\b',        # or None (for explicit handling)
        
        # Ternary guards: x if x else default
        r'if\s+\w+\s+else\s+',
        
        # Explicit None checks before use
        r'if\s+\w+\s+is\s+not\s+None',
        r'if\s+\w+\s+is\s+None.*return',
        r'if\s+not\s+\w+.*return',
    ]
    
    # Intentional exception patterns
    INTENTIONAL_EXCEPTION_PATTERNS = [
        r'raise\s+ValueError',
        r'raise\s+TypeError', 
        r'raise\s+KeyError',
        r'raise\s+AttributeError',
        r'raise\s+RuntimeError',
        r'raise\s+NotImplementedError',
    ]
    
    def __init__(self):
        self._compiled_patterns = {}
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Pre-compile regex patterns for efficiency."""
        self._compiled_patterns['test'] = [
            re.compile(p, re.IGNORECASE) for p in self.TEST_PATTERNS
        ]
        self._compiled_patterns['example'] = [
            re.compile(p, re.IGNORECASE) for p in self.EXAMPLE_PATTERNS
        ]
        self._compiled_patterns['config'] = [
            re.compile(p, re.IGNORECASE) for p in self.CONFIG_PATTERNS
        ]
        self._compiled_patterns['migration'] = [
            re.compile(p, re.IGNORECASE) for p in self.MIGRATION_PATTERNS
        ]
        self._compiled_patterns['guard'] = [
            re.compile(p) for p in self.GUARD_PATTERNS
        ]
        self._compiled_patterns['intentional_exception'] = [
            re.compile(p) for p in self.INTENTIONAL_EXCEPTION_PATTERNS
        ]
    
    def analyze(
        self,
        bug_type: str,
        file_path: str,
        function_name: str,
        variable_name: Optional[str] = None,
        source_code: Optional[str] = None,
        line_number: Optional[int] = None,
    ) -> IntentAnalysis:
        """
        Analyze a potential bug to determine if it's intentional.
        
        Args:
            bug_type: Type of bug (NULL_PTR, DIV_ZERO, BOUNDS, etc.)
            file_path: Path to the file containing the bug
            function_name: Name of the function containing the bug
            variable_name: Variable involved in the bug (if applicable)
            source_code: Source code of the function (if available)
            line_number: Line number of the bug (if available)
            
        Returns:
            IntentAnalysis with signals and confidence scores
        """
        analysis = IntentAnalysis()
        
        # File-based signals
        self._analyze_file_context(analysis, file_path)
        
        # Language semantic signals
        self._analyze_python_semantics(analysis, bug_type, variable_name, function_name)
        
        # Framework signals
        self._analyze_framework_context(analysis, bug_type, variable_name, function_name)
        
        # Code pattern signals
        if source_code:
            self._analyze_code_patterns(analysis, bug_type, source_code, line_number, function_name)
        
        # Bug-type specific analysis
        self._analyze_bug_type_context(analysis, bug_type, variable_name)
        
        return analysis
    
    def _analyze_file_context(self, analysis: IntentAnalysis, file_path: str):
        """Analyze file path for intent signals."""
        import os
        path_str = str(file_path)
        basename = os.path.basename(path_str)
        
        # Test files - match basename for name patterns, full path for dir patterns
        for pattern in self._compiled_patterns['test']:
            pat_str = pattern.pattern
            # Patterns that match directory structure use full path
            if '/' in pat_str:
                match_str = path_str
            else:
                match_str = basename
            if pattern.search(match_str):
                analysis.add_signal(
                    IntentCategory.TEST_FILE,
                    0.95,  # Very high confidence - tests are intentional
                    f"File matches test pattern: {pattern.pattern}"
                )
                break
        
        # Example files
        for pattern in self._compiled_patterns['example']:
            if pattern.search(path_str):
                analysis.add_signal(
                    IntentCategory.EXAMPLE_FILE,
                    0.7,  # High confidence - examples may be incomplete
                    f"File matches example pattern: {pattern.pattern}"
                )
                break
        
        # Config files
        for pattern in self._compiled_patterns['config']:
            if pattern.search(path_str):
                analysis.add_signal(
                    IntentCategory.CONFIG_FILE,
                    0.6,  # Medium confidence
                    f"File matches config pattern: {pattern.pattern}"
                )
                break
        
        # Migration files
        for pattern in self._compiled_patterns['migration']:
            if pattern.search(path_str):
                analysis.add_signal(
                    IntentCategory.MIGRATION_FILE,
                    0.8,  # High confidence - migrations run in controlled context
                    f"File matches migration pattern: {pattern.pattern}"
                )
                break
    
    def _analyze_python_semantics(
        self, 
        analysis: IntentAnalysis, 
        bug_type: str, 
        variable_name: Optional[str],
        function_name: str
    ):
        """Analyze Python language semantics for intent signals."""
        
        # self/cls never None in methods
        if bug_type == 'NULL_PTR' and variable_name:
            base_var = variable_name.split('.')[0].split('[')[0]
            # Only suppress when the variable IS 'self'/'cls' itself,
            # not 'self.attr' (attribute may legitimately be None)
            if base_var in ('self', 'cls') and '.' not in variable_name:
                analysis.add_signal(
                    IntentCategory.PYTHON_SELF_INVARIANT,
                    0.99,  # Extremely high - Python guarantees this
                    f"'{base_var}' is never None in a bound method"
                )
        
        # Check for method patterns (likely has self)
        if bug_type == 'NULL_PTR' and variable_name == 'param_0':
            # param_0 in a method starting with __ or common method names
            if function_name.startswith('__') or '.' in function_name:
                analysis.add_signal(
                    IntentCategory.PYTHON_SELF_INVARIANT,
                    0.9,
                    f"param_0 in method '{function_name}' is likely 'self'"
                )
        
        # Note: slicing (s[i:j]) never raises IndexError, but BOUNDS bugs
        # detected by bytecode analysis are actual index operations (s[i]),
        # not slices. Don't blanket-suppress BOUNDS findings here.
    
    def _analyze_framework_context(
        self,
        analysis: IntentAnalysis,
        bug_type: str,
        variable_name: Optional[str],
        function_name: str
    ):
        """Analyze framework conventions for intent signals."""
        
        # Django/Flask request objects are always valid
        if bug_type == 'NULL_PTR' and variable_name:
            base_var = variable_name.split('.')[0].split('[')[0]
            if base_var.lower() in self.FRAMEWORK_REQUEST_PARAMS:
                analysis.add_signal(
                    IntentCategory.FRAMEWORK_REQUEST_VALID,
                    0.95,
                    f"'{base_var}' is a framework-provided request object"
                )
            
            # param_0 in view functions is often request
            if variable_name == 'param_0':
                view_indicators = ['view', 'handler', 'endpoint', 'route', 'api']
                if any(ind in function_name.lower() for ind in view_indicators):
                    analysis.add_signal(
                        IntentCategory.FRAMEWORK_REQUEST_VALID,
                        0.8,
                        f"param_0 in '{function_name}' is likely a request object"
                    )
    
    def _analyze_code_patterns(
        self,
        analysis: IntentAnalysis,
        bug_type: str,
        source_code: str,
        line_number: Optional[int],
        function_name: Optional[str] = None,
    ):
        """Analyze source code for guard patterns and intentional behavior."""
        
        # Scope guard pattern search to the containing function body,
        # not the entire file.  Searching the whole file causes false
        # matches on unrelated code (e.g. a ternary in a helper function
        # does not guard the variable in the function under analysis).
        guard_search_code = self._extract_function_source(
            source_code, function_name, line_number
        )
        
        # Check for guard patterns.
        # Skip for BOUNDS bugs: bytecode-level GuardAnalyzer already performs
        # precise, variable-aware guard detection.  Regex matching here is too
        # coarse (e.g. a None-check on variable A suppresses BOUNDS on variable B).
        # Skip for STALE_VALUE bugs: guard patterns like ``or {}`` are default
        # argument idioms, not guards for counter-update ordering issues.
        if bug_type not in ('BOUNDS', 'STALE_VALUE'):
            for pattern in self._compiled_patterns['guard']:
                if pattern.search(guard_search_code):
                    analysis.add_signal(
                        IntentCategory.GUARD_PATTERN_DETECTED,
                        0.7,
                        f"Guard pattern detected: {pattern.pattern}"
                    )
                    break
        
        # Check for intentional exception raising (VALUE_ERROR, etc.)
        if bug_type in ('VALUE_ERROR', 'TYPE_ERROR', 'RUNTIME_ERROR'):
            for pattern in self._compiled_patterns['intentional_exception']:
                if pattern.search(source_code):
                    analysis.add_signal(
                        IntentCategory.INTENTIONAL_VALIDATION,
                        0.9,
                        f"Intentional exception raising detected"
                    )
                    break
        
        # Check for optional import pattern
        if bug_type == 'IMPORT_ERROR':
            if 'try:' in source_code and 'import' in source_code:
                if 'except ImportError' in source_code or 'except ModuleNotFoundError' in source_code:
                    analysis.add_signal(
                        IntentCategory.INTENTIONAL_OPTIONAL_IMPORT,
                        0.95,
                        "Optional import with ImportError handling"
                    )
        
        # Check for default parameter guards
        if bug_type == 'DIV_ZERO':
            # Look for default parameters that prevent zero
            default_match = re.search(r'def\s+\w+\([^)]*=\s*[1-9][^,)]*\)', source_code)
            if default_match:
                analysis.add_signal(
                    IntentCategory.DEFAULT_PARAMETER_GUARD,
                    0.6,
                    "Non-zero default parameter may prevent division by zero"
                )
        
        # Check if we're in an exception handler
        if line_number:
            lines = source_code.split('\n')
            if line_number <= len(lines):
                # Look for 'except' before the line
                context_start = max(0, line_number - 10)
                context = '\n'.join(lines[context_start:line_number])
                if 'except' in context and 'try' in context:
                    analysis.add_signal(
                        IntentCategory.EXCEPTION_HANDLER_CONTEXT,
                        0.7,
                        "Bug location is within exception handler"
                    )
    
    def _extract_function_source(
        self,
        source_code: str,
        function_name: Optional[str],
        line_number: Optional[int],
    ) -> str:
        """Extract the source code of a specific function from the full file.

        Falls back to the full source_code if the function cannot be located.
        """
        if not function_name:
            return source_code

        # Use the simple (last) component, e.g. "verify_collections"
        simple_name = function_name.rsplit('.', 1)[-1] if '.' in function_name else function_name

        try:
            tree = ast.parse(source_code)
        except SyntaxError:
            return source_code

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name == simple_name:
                    lines = source_code.splitlines()
                    start = node.lineno - 1
                    end = node.end_lineno if hasattr(node, 'end_lineno') and node.end_lineno else len(lines)
                    return '\n'.join(lines[start:end])

        # Fallback: if function not found but we have a line number,
        # return a window around the bug line
        if line_number:
            lines = source_code.splitlines()
            start = max(0, line_number - 40)
            end = min(len(lines), line_number + 10)
            return '\n'.join(lines[start:end])

        return source_code

    def _analyze_bug_type_context(
        self,
        analysis: IntentAnalysis,
        bug_type: str,
        variable_name: Optional[str]
    ):
        """Bug-type specific analysis."""
        
        # IMPORT_ERROR in non-critical paths
        if bug_type == 'IMPORT_ERROR':
            # Import errors for optional dependencies are often intentional
            analysis.add_signal(
                IntentCategory.INTENTIONAL_OPTIONAL_IMPORT,
                0.5,  # Base confidence - may be optional
                "Import errors may be for optional dependencies"
            )
        
        # FILE_NOT_FOUND with user input
        if bug_type == 'FILE_NOT_FOUND':
            # If variable suggests user input, it's a real bug
            if variable_name and any(x in variable_name.lower() for x in ['path', 'file', 'input']):
                # This is likely a REAL bug - user input not validated
                # Don't add any intentional signals
                pass
            else:
                analysis.add_signal(
                    IntentCategory.GUARD_PATTERN_DETECTED,
                    0.3,
                    "File operations may have external validation"
                )


class EnhancedBugFilter:
    """
    Filters bugs based on intent analysis and additional heuristics.
    
    Combines multiple filtering strategies:
    1. Intent detection (is it intentional?)
    2. Semantic filtering (Python guarantees)
    3. Pattern matching (common FP patterns)
    4. Confidence thresholding
    """
    
    def __init__(self, min_unintentional_confidence: float = 0.5):
        """
        Args:
            min_unintentional_confidence: Minimum confidence that bug is unintentional
                                          to include it in results. Default 0.5.
        """
        self.intent_detector = IntentDetector()
        self.min_confidence = min_unintentional_confidence
        
        # Compile additional patterns
        self._empty_check_patterns = [
            re.compile(r'if\s+not\s+\w+:'),
            re.compile(r'if\s+len\(\w+\)\s*[=<>]'),
            re.compile(r'if\s+\w+\s+is\s+None'),
            re.compile(r'if\s+\w+:'),  # Simple truthiness check
        ]
    
    def filter_bug(
        self,
        bug_type: str,
        file_path: str,
        function_name: str,
        variable_name: Optional[str] = None,
        source_code: Optional[str] = None,
        line_number: Optional[int] = None,
        original_confidence: float = 1.0,
    ) -> Tuple[bool, float, IntentAnalysis]:
        """
        Filter a single bug.
        
        Returns:
            Tuple of (should_include, adjusted_confidence, analysis)
        """
        # Run intent analysis
        analysis = self.intent_detector.analyze(
            bug_type=bug_type,
            file_path=file_path,
            function_name=function_name,
            variable_name=variable_name,
            source_code=source_code,
            line_number=line_number,
        )
        
        # Compute adjusted confidence
        # adjusted = original * P(unintentional)
        unintentional_conf = analysis.unintentional_confidence
        adjusted_confidence = original_confidence * unintentional_conf
        
        # Determine if we should include this bug
        should_include = adjusted_confidence >= self.min_confidence
        
        return should_include, adjusted_confidence, analysis
    
    def has_guard_before_use(self, source_code: str, variable: str, use_line: int) -> bool:
        """
        Check if there's a guard check for a variable before its use.
        
        This is a lightweight check for common patterns:
        - if x is not None: use(x)
        - if x: use(x)
        - if len(x) > 0: use(x)
        """
        lines = source_code.split('\n')
        if use_line > len(lines):
            return False
        
        # Look at preceding lines for guard patterns
        for i in range(max(0, use_line - 5), use_line):
            line = lines[i]
            # Check if this line guards the variable
            if variable in line:
                for pattern in self._empty_check_patterns:
                    if pattern.search(line):
                        return True
        
        return False


def create_intent_aware_filter(threshold: float = 0.5) -> EnhancedBugFilter:
    """
    Factory function to create an intent-aware bug filter.
    
    Args:
        threshold: Minimum unintentional confidence to report a bug.
                   Higher = more conservative (fewer bugs reported).
                   Lower = more permissive (more bugs reported).
                   
    Recommended thresholds:
        0.3 - Aggressive: Report most bugs, some FPs
        0.5 - Balanced: Good FP/FN tradeoff (default)
        0.7 - Conservative: Fewer bugs, very few FPs
        0.9 - Very conservative: Only high-confidence bugs
    """
    return EnhancedBugFilter(min_unintentional_confidence=threshold)
