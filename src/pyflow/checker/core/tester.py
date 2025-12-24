"""
Security Test Runner.

This module provides the SecurityTester class that executes security tests
on AST nodes. It manages test execution, result collection, score calculation,
and nosec (no security) comment handling.

**Test Execution Flow:**
1. Get tests for the node type from testset
2. For each test:
   - Create a Context wrapper
   - Execute the test function
   - Handle results (single Issue or list of Issues)
   - Check for nosec comments
   - Annotate issues with file/location information
   - Calculate scores
3. Return aggregated scores

**Nosec Handling:**
The tester respects # nosec comments that allow developers to suppress
specific security warnings. Nosec comments can be:
- Line-specific: # nosec B301 (suppress test B301 on this line)
- General: # nosec (suppress all tests on this line)
"""

import copy
import logging
from . import constants
from . import context as b_context
from . import utils

LOG = logging.getLogger(__name__)


class SecurityTester:
    """
    Executes security tests and collects results.
    
    The SecurityTester runs security tests registered for specific node types,
    collects issues, handles nosec comments, and calculates severity/confidence
    scores. It serves as the bridge between the AST visitor and individual
    security test functions.
    
    **Test Functions:**
    Security tests are functions that take a Context object and optionally
    a config dictionary. They return:
    - None: No issue found
    - Issue: Single issue found
    - List[Issue]: Multiple issues found
    
    **Score Calculation:**
    Scores are calculated based on issue severity and confidence levels,
    using the RANKING_VALUES point system.
    
    Attributes:
        results: List of all issues found during analysis
        testset: TestSet containing registered security tests
        last_result: Last test result (for debugging)
        debug: Whether to enable debug logging
        nosec_lines: Dictionary mapping line numbers to nosec test IDs
        metrics: Metrics collector for statistics
    """
    def __init__(self, testset, debug, nosec_lines, metrics):
        """
        Initialize a security tester.
        
        Args:
            testset: TestSet containing security tests
            debug: Whether to enable debug logging
            nosec_lines: Dictionary mapping line numbers to nosec test IDs
            metrics: Metrics collector
        """
        self.results = []
        self.testset = testset
        self.last_result = None
        self.debug = debug
        self.nosec_lines = nosec_lines
        self.metrics = metrics

    def run_tests(self, raw_context, checktype):
        """
        Run all security tests for a specific node type.
        
        Executes all tests registered for the given checktype (e.g., "Call",
        "Import", "Str"). For each test:
        1. Creates a Context wrapper
        2. Executes the test function
        3. Processes results (handles both single and multiple issues)
        4. Checks nosec comments
        5. Annotates issues with file/location information
        6. Calculates scores
        
        Args:
            raw_context: Raw context dictionary from visitor
            checktype: Node type to run tests for (e.g., "Call", "Import")
            
        Returns:
            Dictionary with "SEVERITY" and "CONFIDENCE" score arrays
        """
        scores = {
            "SEVERITY": [0] * len(constants.RANKING),
            "CONFIDENCE": [0] * len(constants.RANKING),
        }

        tests = self.testset.get_tests(checktype)
        for test in tests:
            name = test.__name__
            # Execute test with an instance of the context class
            temp_context = copy.copy(raw_context)
            context = b_context.Context(temp_context)
            try:
                if hasattr(test, "_config"):
                    result = test(context, test._config)
                else:
                    result = test(context)

                if result is not None:
                    # Handle both single issues and lists of issues
                    issues = result if isinstance(result, list) else [result]
                    
                    for issue in issues:
                        nosec_tests_to_skip = self._get_nosecs_from_contexts(
                            temp_context, test_result=issue
                        )

                        if isinstance(temp_context["filename"], bytes):
                            issue.fname = temp_context["filename"].decode("utf-8")
                        else:
                            issue.fname = temp_context["filename"]
                        issue.fdata = temp_context["file_data"]

                        if issue.lineno is None:
                            issue.lineno = temp_context["lineno"]
                        if issue.linerange == []:
                            issue.linerange = temp_context["linerange"]
                        if issue.col_offset == -1:
                            issue.col_offset = temp_context["col_offset"]
                        issue.end_col_offset = temp_context.get("end_col_offset", 0)
                        issue.test = name
                        if issue.test_id == "":
                            issue.test_id = test._test_id

                        # Don't skip the test if there was no nosec comment
                        if nosec_tests_to_skip is not None:
                            # If the set is empty then it means that nosec was
                            # used without test number -> update nosecs counter.
                            # If the test id is in the set of tests to skip,
                            # log and increment the skip by test count.
                            if not nosec_tests_to_skip:
                                LOG.debug("skipped, nosec without test number")
                                self.metrics.note_nosec()
                                continue
                            if issue.test_id in nosec_tests_to_skip:
                                LOG.debug(f"skipped, nosec for test {issue.test_id}")
                                self.metrics.note_skipped_test()
                                continue

                        self.results.append(issue)

                        LOG.debug("Issue identified by %s: %s", name, issue)
                        sev = constants.RANKING.index(issue.severity)
                        val = constants.RANKING_VALUES[issue.severity]
                        scores["SEVERITY"][sev] += val
                        con = constants.RANKING.index(issue.confidence)
                        val = constants.RANKING_VALUES[issue.confidence]
                        scores["CONFIDENCE"][con] += val
                else:
                    nosec_tests_to_skip = self._get_nosecs_from_contexts(temp_context)
                    if (
                        nosec_tests_to_skip
                        and test._test_id in nosec_tests_to_skip
                    ):
                        LOG.warning(
                            f"nosec encountered ({test._test_id}), but no "
                            f"failed test on line {temp_context['lineno']}"
                        )

            except Exception as e:
                self.report_error(name, context, e)
                if self.debug:
                    raise
        LOG.debug("Returning scores: %s", scores)
        return scores

    def _get_nosecs_from_contexts(self, context, test_result=None):
        """
        Get set of tests to skip based on nosec comments.
        
        Checks for nosec comments on both the current line (from test_result)
        and the context line. Combines both sets of tests to skip.
        
        **Nosec Comment Format:**
        - # nosec B301: Skip test B301 on this line
        - # nosec: Skip all tests on this line
        
        Args:
            context: Context dictionary
            test_result: Optional Issue object (for line number)
            
        Returns:
            Set of test IDs to skip, or None if no nosec comments found
        """
        nosec_tests_to_skip = set()
        # Get nosec tests from the issue's line number
        base_tests = (
            self.nosec_lines.get(test_result.lineno, None)
            if test_result
            else None
        )
        # Get nosec tests from the context line
        context_tests = utils.get_nosec(self.nosec_lines, context)

        # If both are none there were no comments
        if base_tests is None and context_tests is None:
            nosec_tests_to_skip = None

        # Combine tests from current line and context line
        if base_tests is not None:
            nosec_tests_to_skip.update(base_tests)
        if context_tests is not None:
            nosec_tests_to_skip.update(context_tests)

        return nosec_tests_to_skip

    @staticmethod
    def report_error(test, context, error):
        """
        Report an error that occurred during test execution.
        
        Logs detailed error information including test name, file, line number,
        and full traceback. Used for debugging test failures.
        
        Args:
            test: Test function name that failed
            context: Context object where error occurred
            error: Exception that was raised
        """
        what = "Security checker internal error running: "
        what += f"{test} "
        what += "on file %s at line %i: " % (
            context._context["filename"],
            context._context["lineno"],
        )
        what += str(error)
        import traceback
        what += traceback.format_exc()
        LOG.error(what)
