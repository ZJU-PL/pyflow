"""
Micro-benchmark runner for evaluating checker accuracy on SAST-Python3 benchmarks.

This module runs benchmarks and measures False Positives (FP) and False Negatives (FN).
"""

from __future__ import annotations

import json
import re
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

from .semantic import StaticBugFinder, BugFinderConfig, Issue
from .pattern.core.manager import SecurityManager
from .pattern.core.config import SecurityConfig


@dataclass
class TestCase:
    """Represents a test case from config.json."""

    T_file: str  # Should find bug (True Positive)
    F_file: str  # Should NOT find bug (True Negative)
    scene: str  # Scene description
    directory: Path  # Directory containing the test files


@dataclass
class TestResult:
    """Result of running a test case."""

    test_case: TestCase
    T_has_bug: bool  # Did we find a bug in T file?
    F_has_bug: bool  # Did we find a bug in F file?

    @property
    def is_tp(self) -> bool:
        """True Positive: Found bug in T file (correct)."""
        return self.T_has_bug

    @property
    def is_tn(self) -> bool:
        """True Negative: No bug in F file (correct)."""
        return not self.F_has_bug

    @property
    def is_fp(self) -> bool:
        """False Positive: Found bug in F file (incorrect)."""
        return self.F_has_bug

    @property
    def is_fn(self) -> bool:
        """False Negative: No bug in T file (incorrect)."""
        return not self.T_has_bug


@dataclass
class BenchmarkResults:
    """Aggregated results from running benchmarks."""

    total_tests: int = 0
    true_positives: int = 0
    true_negatives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    test_results: List[TestResult] = field(default_factory=list)

    def __post_init__(self):
        if self.test_results is None:
            self.test_results = []

    @property
    def precision(self) -> float:
        """Precision = TP / (TP + FP)."""
        denominator = self.true_positives + self.false_positives
        return self.true_positives / denominator if denominator > 0 else 0.0

    @property
    def recall(self) -> float:
        """Recall = TP / (TP + FN)."""
        denominator = self.true_positives + self.false_negatives
        return self.true_positives / denominator if denominator > 0 else 0.0

    @property
    def f1_score(self) -> float:
        """F1 Score = 2 * (precision * recall) / (precision + recall)."""
        p = self.precision
        r = self.recall
        return 2 * (p * r) / (p + r) if (p + r) > 0 else 0.0

    @property
    def accuracy(self) -> float:
        """
        Accuracy = Correctly handled test cases / Total test cases.

        A test case is correct when BOTH:
        - T file has bug detected (TP)
        - F file has no bug detected (TN)
        """
        if self.total_tests == 0:
            return 0.0

        # Count test cases where BOTH TP and TN are true
        correct_test_cases = sum(
            1 for result in self.test_results if result.is_tp and result.is_tn
        )
        return correct_test_cases / self.total_tests


class MicroBenchRunner:
    """Runs micro-benchmarks and evaluates checker accuracy."""

    def __init__(
        self, engine: str = "semantic", taint_engine: str = "ast", verbose: bool = False
    ):
        """
        Initialize the benchmark runner.

        Args:
            engine: "semantic" or "pattern"
            taint_engine: "ast" (local), "ipa" (interprocedural), or "both"
            verbose: Enable verbose output
        """
        self.engine = engine
        self.taint_engine = taint_engine
        self.verbose = verbose

    def parse_config(self, config_path: Path) -> List[TestCase]:
        """
        Parse a config.json file to extract test cases.

        Args:
            config_path: Path to config.json file

        Returns:
            List of TestCase objects
        """
        test_cases = []
        config_dir = config_path.parent

        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)

        # Navigate the nested structure to find scene_list
        for category_key, category_value in config.items():
            if isinstance(category_value, list):
                for item in category_value:
                    if isinstance(item, dict) and "scene_levels" in item:
                        for level in item["scene_levels"]:
                            if "scene_list" in level:
                                for scene in level["scene_list"]:
                                    compose = scene.get("compose", "")
                                    scene_name = scene.get("scene", "")

                                    # Parse compose expression like "file_T.py && !file_F.py"
                                    match = re.match(
                                        r"(\w+\.py)\s*&&\s*!(\w+\.py)", compose
                                    )
                                    if match:
                                        T_file, F_file = match.groups()
                                        test_cases.append(
                                            TestCase(
                                                T_file=T_file,
                                                F_file=F_file,
                                                scene=scene_name,
                                                directory=config_dir,
                                            )
                                        )

        return test_cases

    def run_test_file(
        self, test_file: Path, taint_engine: Optional[str] = None
    ) -> bool:
        """
        Run a test file and return True if bugs were found.

        Args:
            test_file: Path to the test file
            taint_engine: Override taint engine for this run

        Returns:
            True if bugs were found, False otherwise
        """
        engine = taint_engine or self.taint_engine
        try:
            if self.engine == "semantic":
                config = BugFinderConfig(
                    verbose=self.verbose, recursive=False, taint_engine=engine
                )
                finder = StaticBugFinder(config)
                bugs = finder.analyze([str(test_file)])
                return len(bugs) > 0
            else:
                config = SecurityConfig()
                manager = SecurityManager(
                    config=config, verbose=self.verbose, quiet=True
                )
                manager.discover_files(
                    [str(test_file)], recursive=False, excluded_paths=""
                )
                manager.run_tests()
                issues = manager.get_issue_list()
                return len(issues) > 0
        except Exception as e:
            if self.verbose:
                print(f"Error running {test_file}: {e}")
            return False

    def run_test_case(self, test_case: TestCase) -> TestResult:
        """
        Run a test case and return the result.

        Args:
            test_case: The test case to run

        Returns:
            TestResult object
        """
        T_path = test_case.directory / test_case.T_file
        F_path = test_case.directory / test_case.F_file

        if not T_path.exists() or not F_path.exists():
            if self.verbose:
                print(f"Warning: Test files not found for {test_case.scene}")
            return TestResult(test_case=test_case, T_has_bug=False, F_has_bug=False)

        T_has_bug = self.run_test_file(T_path)
        F_has_bug = self.run_test_file(F_path)

        return TestResult(test_case=test_case, T_has_bug=T_has_bug, F_has_bug=F_has_bug)

    def run_benchmark(self, benchmark_path: Path) -> BenchmarkResults:
        """
        Run benchmarks from a directory or config file.

        Args:
            benchmark_path: Path to benchmark directory or config.json file

        Returns:
            BenchmarkResults object
        """
        # Suppress RuntimeWarning about coroutines that were never awaited.
        # This is expected during static analysis since we're not actually
        # executing async code, just analyzing it statically.
        with warnings.catch_warnings():
            warnings.filterwarnings(
                "ignore",
                message=".*coroutine.*was never awaited.*",
                category=RuntimeWarning,
            )

            results = BenchmarkResults()

            # Find all config.json files
            if benchmark_path.is_file() and benchmark_path.name == "config.json":
                config_files = [benchmark_path]
            elif benchmark_path.is_dir():
                config_files = list(benchmark_path.rglob("config.json"))
            else:
                raise ValueError(f"Invalid benchmark path: {benchmark_path}")

            if not config_files:
                print(f"Warning: No config.json files found in {benchmark_path}")
                return results

            # Collect all test cases
            all_test_cases = []
            for config_file in config_files:
                test_cases = self.parse_config(config_file)
                all_test_cases.extend(test_cases)

            results.total_tests = len(all_test_cases)

            # Run each test case
            for test_case in all_test_cases:
                if self.verbose:
                    print(
                        f"Running: {test_case.scene} ({test_case.T_file} / {test_case.F_file})"
                    )

                test_result = self.run_test_case(test_case)
                results.test_results.append(test_result)

            # Calculate metrics from test results
            # Each test case should have BOTH T file (TP) and F file (TN) correct
            for test_result in results.test_results:
                # True Positive: Found bug in T file (correct)
                if test_result.T_has_bug:
                    results.true_positives += 1
                else:
                    results.false_negatives += 1

                # True Negative: No bug in F file (correct)
                if not test_result.F_has_bug:
                    results.true_negatives += 1
                else:
                    results.false_positives += 1

            return results

    def print_results(self, results: BenchmarkResults):
        """Print benchmark results in a formatted way."""
        print("\n" + "=" * 70)
        print("Micro-Benchmark Results")
        print("=" * 70)
        engine_info = self.engine
        if self.engine == "semantic":
            engine_info += f" (taint: {self.taint_engine})"
        print(f"\nEngine: {engine_info}")
        print(f"Total test cases: {results.total_tests}")
        print("\nMetrics:")
        print(f"  True Positives (TP):  {results.true_positives}")
        print(f"  True Negatives (TN):  {results.true_negatives}")
        print(f"  False Positives (FP): {results.false_positives}")
        print(f"  False Negatives (FN): {results.false_negatives}")
        print("\nPerformance:")
        print(f"  Precision:  {results.precision:.4f}")
        print(f"  Recall:     {results.recall:.4f}")
        print(f"  F1 Score:   {results.f1_score:.4f}")
        print(f"  Accuracy:   {results.accuracy:.4f}")

        # Show failing tests if any
        if results.false_positives > 0 or results.false_negatives > 0:
            print("\nFailed Tests:")
            for result in results.test_results:
                if result.is_fp or result.is_fn:
                    status = []
                    if result.is_fp:
                        status.append(f"FP: {result.test_case.F_file}")
                    if result.is_fn:
                        status.append(f"FN: {result.test_case.T_file}")
                    print(f"  {result.test_case.scene}: {', '.join(status)}")

        print("=" * 70 + "\n")
