"""
Scanning pipeline for public repository evaluation.

Workflow:
1. Clone repo (or skip if already cloned)
2. Discover Python files
3. Analyze each file with all 20 bug detectors
4. Collect findings with witness traces
5. Triage: BUG (with trace), SAFE (with proof), UNKNOWN, ERROR
6. Track false positives/negatives for refinement
"""

import json
import os
import subprocess
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional

from a3_python.evaluation.repo_list import RepoInfo, get_tier, get_all_repos
from a3_python.analyzer import analyze_file, AnalysisResult


@dataclass
class Finding:
    """A single bug finding from a file."""
    file_path: str
    bug_type: str
    verdict: str  # BUG, SAFE, UNKNOWN, ERROR
    location: Optional[str]  # Function/class context
    witness_trace: Optional[List[str]]
    proof_artifact: Optional[str]
    dse_repro: Optional[str]
    message: str
    module_init_phase: bool = False  # True if trace is in import-heavy module initialization
    import_count: int = 0  # Number of imports in the trace


@dataclass
class RepoScanResult:
    """Result of scanning an entire repository."""
    repo_name: str
    repo_url: str
    scanned_at: str
    total_files: int
    analyzed_files: int
    skipped_files: int
    findings: List[Finding]
    errors: List[Dict[str, str]]
    summary: Dict[str, int]  # verdict -> count


class RepoScanner:
    """Orchestrates scanning of public repositories."""
    
    def __init__(self, workspace_dir: str = "results/public_repos"):
        self.workspace_dir = Path(workspace_dir)
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        self.clones_dir = self.workspace_dir / "clones"
        self.clones_dir.mkdir(exist_ok=True)
        self.results_dir = self.workspace_dir / "scan_results"
        self.results_dir.mkdir(exist_ok=True)
    
    def clone_repo(self, repo: RepoInfo) -> Path:
        """Clone repository if not already present."""
        repo_path = self.clones_dir / repo.name
        if repo_path.exists():
            print(f"Repository {repo.name} already cloned at {repo_path}")
            return repo_path
        
        print(f"Cloning {repo.name} from {repo.github_url}...")
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", repo.github_url, str(repo_path)],
                check=True,
                capture_output=True,
                timeout=300,
            )
            print(f"Successfully cloned {repo.name}")
            return repo_path
        except subprocess.CalledProcessError as e:
            print(f"Failed to clone {repo.name}: {e.stderr.decode()}")
            raise
        except subprocess.TimeoutExpired:
            print(f"Timeout cloning {repo.name}")
            raise
    
    def discover_python_files(self, repo_path: Path, max_files: int = 100, exclude_tests: bool = True) -> List[Path]:
        """
        Discover Python files in repository.
        
        Excludes:
        - Virtual environments (venv, .venv, env)
        - Build/dist directories
        - Test fixtures with known errors
        - Migration scripts
        - Generated code
        - Test directories and files (if exclude_tests=True)
        """
        python_files = []
        exclude_patterns = {
            "venv", ".venv", "env", "virtualenv",
            "build", "dist", ".eggs", "*.egg-info",
            "node_modules", ".tox", ".pytest_cache",
            "__pycache__",
        }
        
        # Test-related patterns to exclude (directory components and filenames)
        test_dir_patterns = {"test", "tests", "testing", "examples", "example"}
        test_file_names = {"setup.py", "conftest.py"}
        
        for py_file in repo_path.rglob("*.py"):
            # Skip excluded directories
            if any(excluded in py_file.parts for excluded in exclude_patterns):
                continue
            
            # Skip test directories and files
            if exclude_tests:
                # Check if any part of the path starts with "test" or "example"
                if any(part.lower().startswith(tuple(test_dir_patterns)) for part in py_file.parts):
                    continue
                # Check if the filename is in the test file list
                if py_file.name in test_file_names:
                    continue
            
            # Skip very large files (likely generated)
            if py_file.stat().st_size > 500_000:  # 500KB
                continue
            
            python_files.append(py_file)
            
            if len(python_files) >= max_files:
                break
        
        return python_files
    
    def analyze_file_safe(self, file_path: Path, filter_module_init: bool = True) -> List[Finding]:
        """
        Analyze a single file, catching any errors.
        
        Args:
            file_path: Path to Python file
            filter_module_init: If True, filter module-init bugs conservatively
        
        Returns list of findings (may be empty).
        """
        findings = []
        try:
            # Read file content
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                source_code = f.read()
            
            # Run analysis with module-init filtering
            result = analyze_file(
                str(file_path), 
                source_code,
                filter_module_init_bugs=filter_module_init,
                module_init_import_threshold=3,
            )
            
            # Convert result to findings
            for bug_result in result.bugs:
                finding = Finding(
                    file_path=str(file_path),
                    bug_type=bug_result.bug_type,
                    verdict="BUG",
                    location=bug_result.location,
                    witness_trace=bug_result.witness_trace,
                    proof_artifact=None,
                    dse_repro=bug_result.dse_repro,
                    message=bug_result.message,
                    module_init_phase=bug_result.module_init_phase,
                    import_count=bug_result.import_count,
                )
                findings.append(finding)
            
            for safe_result in result.safe_proofs:
                finding = Finding(
                    file_path=str(file_path),
                    bug_type=safe_result.bug_type,
                    verdict="SAFE",
                    location=safe_result.location,
                    witness_trace=None,
                    proof_artifact=safe_result.proof_artifact,
                    dse_repro=None,
                    message=safe_result.message,
                )
                findings.append(finding)
            
            for unknown_result in result.unknowns:
                finding = Finding(
                    file_path=str(file_path),
                    bug_type=unknown_result.bug_type,
                    verdict="UNKNOWN",
                    location=unknown_result.location,
                    witness_trace=None,
                    proof_artifact=None,
                    dse_repro=None,
                    message=unknown_result.message,
                )
                findings.append(finding)
        
        except Exception as e:
            # Record analysis error
            finding = Finding(
                file_path=str(file_path),
                bug_type="ANALYSIS_ERROR",
                verdict="ERROR",
                location=None,
                witness_trace=None,
                proof_artifact=None,
                dse_repro=None,
                message=f"Analysis failed: {type(e).__name__}: {str(e)[:200]}",
            )
            findings.append(finding)
        
        return findings
    
    def scan_repo(self, repo: RepoInfo, max_files: int = 100, exclude_tests: bool = True) -> RepoScanResult:
        """Scan a repository and collect findings."""
        print(f"\n{'='*60}")
        print(f"Scanning repository: {repo.name}")
        print(f"{'='*60}")
        
        # Clone repo
        repo_path = self.clone_repo(repo)
        
        # Discover Python files
        python_files = self.discover_python_files(repo_path, max_files=max_files, exclude_tests=exclude_tests)
        test_status = " (excluding tests)" if exclude_tests else " (including tests)"
        print(f"Discovered {len(python_files)} Python files{test_status}")
        
        # Analyze each file
        all_findings = []
        errors = []
        analyzed = 0
        skipped = 0
        
        for i, py_file in enumerate(python_files, 1):
            rel_path = py_file.relative_to(repo_path)
            print(f"[{i}/{len(python_files)}] Analyzing {rel_path}...", end=" ")
            
            try:
                findings = self.analyze_file_safe(py_file)
                all_findings.extend(findings)
                analyzed += 1
                
                # Report summary for this file
                bug_count = sum(1 for f in findings if f.verdict == "BUG")
                if bug_count > 0:
                    print(f"✗ {bug_count} BUG(s)")
                else:
                    print("✓")
            
            except Exception as e:
                errors.append({
                    "file": str(rel_path),
                    "error": f"{type(e).__name__}: {str(e)[:200]}"
                })
                skipped += 1
                print(f"✗ ERROR: {e}")
        
        # Compute summary
        summary = {
            "BUG": sum(1 for f in all_findings if f.verdict == "BUG"),
            "SAFE": sum(1 for f in all_findings if f.verdict == "SAFE"),
            "UNKNOWN": sum(1 for f in all_findings if f.verdict == "UNKNOWN"),
            "ERROR": sum(1 for f in all_findings if f.verdict == "ERROR"),
        }
        
        result = RepoScanResult(
            repo_name=repo.name,
            repo_url=repo.github_url,
            scanned_at=datetime.now(timezone.utc).isoformat(),
            total_files=len(python_files),
            analyzed_files=analyzed,
            skipped_files=skipped,
            findings=all_findings,
            errors=errors,
            summary=summary,
        )
        
        # Save results
        self.save_scan_result(result)
        
        return result
    
    def save_scan_result(self, result: RepoScanResult):
        """Save scan result to JSON file."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"{result.repo_name}_{timestamp}.json"
        output_path = self.results_dir / filename
        
        # Convert to dict for JSON serialization
        result_dict = {
            "repo_name": result.repo_name,
            "repo_url": result.repo_url,
            "scanned_at": result.scanned_at,
            "total_files": result.total_files,
            "analyzed_files": result.analyzed_files,
            "skipped_files": result.skipped_files,
            "findings": [asdict(f) for f in result.findings],
            "errors": result.errors,
            "summary": result.summary,
        }
        
        with open(output_path, 'w') as f:
            json.dump(result_dict, f, indent=2)
        
        print(f"\nResults saved to: {output_path}")
        print(f"Summary: {result.summary}")
    
    def scan_tier(self, tier: int, max_files_per_repo: int = 100, exclude_tests: bool = True) -> List[RepoScanResult]:
        """Scan all repos in a tier."""
        repos = get_tier(tier)
        results = []
        
        for repo in repos:
            try:
                result = self.scan_repo(repo, max_files=max_files_per_repo, exclude_tests=exclude_tests)
                results.append(result)
            except Exception as e:
                print(f"Failed to scan {repo.name}: {e}")
        
        return results


def main():
    """CLI for repo scanning."""
    if len(sys.argv) < 2:
        print("Usage: python -m a3_python.evaluation.scanner <tier|repo_name>")
        print("  tier: 1, 2, or 3")
        print("  repo_name: specific repo from the list")
        sys.exit(1)
    
    scanner = RepoScanner()
    
    arg = sys.argv[1]
    if arg in ["1", "2", "3"]:
        # Scan entire tier
        tier = int(arg)
        print(f"Scanning tier {tier} repositories...")
        results = scanner.scan_tier(tier)
        print(f"\nCompleted scanning {len(results)} repositories")
    else:
        # Scan specific repo
        repo_name = arg
        all_repos = get_all_repos()
        repo = next((r for r in all_repos if r.name == repo_name), None)
        if not repo:
            print(f"Unknown repository: {repo_name}")
            print(f"Available repos: {[r.name for r in all_repos]}")
            sys.exit(1)
        
        result = scanner.scan_repo(repo)
        print(f"\nCompleted scanning {repo.name}")


if __name__ == "__main__":
    main()
