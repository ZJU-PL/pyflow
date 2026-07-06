"""
FP Regression Test Runner.

Runs the analyzer on all FP regression test cases and validates
that we DON'T report findings (or report LOW confidence).

This is the key testing infrastructure for the FP reduction plan.
"""

import os
import sys
from pathlib import Path
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass
import json

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from a3_python.analyzer import Analyzer, AnalysisResult
from a3_python.semantics.interprocedural_bugs import analyze_file_for_bugs, InterproceduralBug


@dataclass
class FPTestCase:
    """A false positive regression test case."""
    filepath: Path
    category: str
    expected_findings: int  # 0 = should NOT flag, -1 = any count ok if low confidence
    max_confidence: float  # Maximum allowed confidence for any finding
    description: str


@dataclass
class FPTestResult:
    """Result of running an FP test."""
    test_case: FPTestCase
    passed: bool
    actual_findings: int
    max_actual_confidence: float
    findings: List[InterproceduralBug]
    error: str = ""


class FPRegressionRunner:
    """Runs FP regression tests and reports results."""
    
    # Confidence threshold for "acceptable" findings
    # Findings below this are OK (they won't be shown to users by default)
    LOW_CONFIDENCE_THRESHOLD = 0.40
    
    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self.analyzer = Analyzer(verbose=False, enable_interprocedural=True)
        self.test_dir = Path(__file__).parent
    
    def discover_tests(self) -> List[FPTestCase]:
        """Discover all FP regression test cases."""
        tests = []
        
        for category_dir in self.test_dir.iterdir():
            if not category_dir.is_dir() or category_dir.name.startswith('_'):
                continue
            
            category = category_dir.name
            
            for test_file in category_dir.glob("*.py"):
                if test_file.name.startswith("test_") or test_file.name.startswith("_"):
                    continue
                
                # Parse expected behavior from docstring
                expected_findings, max_confidence, description = self._parse_test_file(test_file)
                
                tests.append(FPTestCase(
                    filepath=test_file,
                    category=category,
                    expected_findings=expected_findings,
                    max_confidence=max_confidence,
                    description=description,
                ))
        
        return sorted(tests, key=lambda t: (t.category, t.filepath.name))
    
    def _parse_test_file(self, filepath: Path) -> Tuple[int, float, str]:
        """Parse expected behavior from test file docstring."""
        content = filepath.read_text()
        
        # Default: expect 0 findings or low confidence
        expected_findings = 0
        max_confidence = self.LOW_CONFIDENCE_THRESHOLD
        description = filepath.stem
        
        # Extract docstring
        if '"""' in content:
            start = content.index('"""') + 3
            end = content.index('"""', start)
            docstring = content[start:end]
            
            # Get first line as description
            lines = docstring.strip().split('\n')
            if lines:
                description = lines[0].strip()
            
            # Look for "Expected:" line
            for line in lines:
                line = line.strip().lower()
                if 'expected:' in line:
                    if 'no finding' in line:
                        expected_findings = 0
                        max_confidence = 0.0  # Must be completely clean
                    elif 'low confidence' in line or 'low' in line:
                        expected_findings = -1  # Any count OK
                        max_confidence = self.LOW_CONFIDENCE_THRESHOLD
                    break
        
        return expected_findings, max_confidence, description
    
    def run_test(self, test_case: FPTestCase) -> FPTestResult:
        """Run a single FP regression test."""
        try:
            # Run interprocedural analysis (main source of FPs)
            findings = analyze_file_for_bugs(test_case.filepath)
            
            # Get max confidence
            max_conf = max((f.confidence for f in findings), default=0.0)
            
            # Check if passed
            if test_case.expected_findings == 0:
                # Must have no findings
                passed = len(findings) == 0
            elif test_case.expected_findings == -1:
                # Any count OK if confidence is low enough
                passed = max_conf <= test_case.max_confidence
            else:
                # Specific expected count
                passed = len(findings) == test_case.expected_findings
            
            return FPTestResult(
                test_case=test_case,
                passed=passed,
                actual_findings=len(findings),
                max_actual_confidence=max_conf,
                findings=findings,
            )
            
        except Exception as e:
            return FPTestResult(
                test_case=test_case,
                passed=False,
                actual_findings=0,
                max_actual_confidence=0.0,
                findings=[],
                error=str(e),
            )
    
    def run_all(self) -> List[FPTestResult]:
        """Run all FP regression tests."""
        tests = self.discover_tests()
        results = []
        
        if self.verbose:
            print(f"\n{'='*60}")
            print("FP Regression Test Suite")
            print(f"{'='*60}")
            print(f"Found {len(tests)} test cases\n")
        
        for test in tests:
            if self.verbose:
                print(f"Testing: {test.category}/{test.filepath.name}...", end=" ")
            
            result = self.run_test(test)
            results.append(result)
            
            if self.verbose:
                if result.passed:
                    print("✓ PASS")
                else:
                    print(f"✗ FAIL")
                    if result.error:
                        print(f"    Error: {result.error}")
                    else:
                        print(f"    Found {result.actual_findings} findings (expected {test.expected_findings})")
                        if result.findings:
                            for f in result.findings[:3]:
                                print(f"    - {f.bug_type}: {f.reason[:60]}... (conf={f.confidence:.2f})")
        
        return results
    
    def summary(self, results: List[FPTestResult]) -> Dict[str, Any]:
        """Generate summary statistics."""
        total = len(results)
        passed = sum(1 for r in results if r.passed)
        failed = total - passed
        
        by_category = {}
        for r in results:
            cat = r.test_case.category
            if cat not in by_category:
                by_category[cat] = {"total": 0, "passed": 0, "failed": 0}
            by_category[cat]["total"] += 1
            if r.passed:
                by_category[cat]["passed"] += 1
            else:
                by_category[cat]["failed"] += 1
        
        # Count findings by type
        finding_types = {}
        for r in results:
            for f in r.findings:
                finding_types[f.bug_type] = finding_types.get(f.bug_type, 0) + 1
        
        return {
            "total_tests": total,
            "passed": passed,
            "failed": failed,
            "pass_rate": passed / total if total > 0 else 0.0,
            "by_category": by_category,
            "finding_types": finding_types,
        }
    
    def print_summary(self, results: List[FPTestResult]) -> None:
        """Print summary to console."""
        summary = self.summary(results)
        
        print(f"\n{'='*60}")
        print("Summary")
        print(f"{'='*60}")
        print(f"Total: {summary['total_tests']}, Passed: {summary['passed']}, Failed: {summary['failed']}")
        print(f"Pass Rate: {summary['pass_rate']*100:.1f}%")
        
        print("\nBy Category:")
        for cat, stats in summary['by_category'].items():
            status = "✓" if stats['failed'] == 0 else "✗"
            print(f"  {status} {cat}: {stats['passed']}/{stats['total']}")
        
        if summary['finding_types']:
            print("\nUnexpected Finding Types:")
            for bug_type, count in sorted(summary['finding_types'].items(), key=lambda x: -x[1]):
                print(f"  - {bug_type}: {count}")


def main():
    """Run FP regression tests."""
    runner = FPRegressionRunner(verbose=True)
    results = runner.run_all()
    runner.print_summary(results)
    
    # Return exit code based on results
    failed = sum(1 for r in results if not r.passed)
    return 1 if failed > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
