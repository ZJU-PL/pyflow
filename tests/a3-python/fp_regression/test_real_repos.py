"""
Regression smoke test for false-positive reduction on selected repos.
"""

from collections import Counter
from pathlib import Path
import time

import pytest


REPOS_TO_TEST = [
    'py_synthetic/prog01_calculator',
    'py_synthetic/prog02_usermgmt',
    'py_synthetic/prog03_dataproc',
]

# Add real repos if available
REAL_REPOS = [
    'external_tools/FLAML',
    'external_tools/qlib',
    'external_tools/graphrag',
]


def analyze_repo(repo_path: Path, apply_fp_reduction: bool, timeout: int = 60) -> dict:
    """Analyze a repo and return results."""
    import signal
    InterproceduralBugTracker = pytest.importorskip(
        "pyflow.a3_python.semantics.interprocedural_bugs",
        reason="a3 interprocedural analysis dependencies not available",
    ).InterproceduralBugTracker

    class TimeoutError(Exception):
        pass

    def handler(signum, frame):
        raise TimeoutError("Analysis timed out")

    # Set timeout
    if hasattr(signal, 'SIGALRM'):
        signal.signal(signal.SIGALRM, handler)
        signal.alarm(timeout)

    try:
        tracker = InterproceduralBugTracker.from_project(repo_path)
        bugs = tracker.find_all_bugs(apply_fp_reduction=apply_fp_reduction)

        if hasattr(signal, 'SIGALRM'):
            signal.alarm(0)  # Cancel timeout

        return {
            'bug_count': len(bugs),
            'types': dict(Counter(b.bug_type for b in bugs)),
            'bugs': bugs,
        }
    except TimeoutError:
        return {'bug_count': -1, 'types': {}, 'bugs': [], 'timeout': True}
    except Exception as e:
        return {'bug_count': -1, 'types': {}, 'bugs': [], 'error': str(e)}
    finally:
        if hasattr(signal, 'SIGALRM'):
            signal.alarm(0)


@pytest.mark.integration
def test_fp_reduction_on_available_repos() -> None:
    all_repos = REPOS_TO_TEST + [repo for repo in REAL_REPOS if Path(repo).exists()]
    if not all_repos:
        pytest.skip("no configured regression repos available")

    analyzed_repo = False
    for repo_rel in all_repos:
        repo_path = Path(repo_rel)
        if not repo_path.exists():
            continue

        analyzed_repo = True

        start = time.time()
        result_raw = analyze_repo(repo_path, apply_fp_reduction=False, timeout=30)
        time_raw = time.time() - start
        assert not result_raw.get("timeout"), f"raw analysis timed out for {repo_rel} after {time_raw:.1f}s"
        assert not result_raw.get("error"), f"raw analysis failed for {repo_rel}: {result_raw['error']}"

        start = time.time()
        result_fp = analyze_repo(repo_path, apply_fp_reduction=True, timeout=30)
        time_fp = time.time() - start
        assert not result_fp.get("timeout"), f"FP-reduced analysis timed out for {repo_rel} after {time_fp:.1f}s"
        assert not result_fp.get("error"), f"FP-reduced analysis failed for {repo_rel}: {result_fp['error']}"
        assert result_fp["bug_count"] <= result_raw["bug_count"]

    assert analyzed_repo, "expected at least one available regression repo"
