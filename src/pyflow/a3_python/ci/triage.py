"""
LLM triage layer for A³.

Reads a SARIF file, fetches source context for each finding, sends it to
an LLM (Claude or GPT-4), and classifies each finding as TP or FP with
confidence and rationale.  Outputs a filtered SARIF containing only the
findings the LLM considers true positives.

Usage (CLI):
    a3 triage --sarif results.sarif --output-sarif triaged.sarif

Usage (Python):
    from a3.ci.triage import triage_sarif
    filtered = triage_sarif(sarif, repo_root=Path("."))
"""

from __future__ import annotations

import ast
import json
import os
import textwrap
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class TriageVerdict:
    """Result of LLM classification for a single finding."""
    is_true_positive: bool
    confidence: float          # 0.0 – 1.0
    rationale: str
    bug_type: str = ""
    function_name: str = ""
    source_context: str = ""     # rich source context sent to the LLM
    artifact_uri: str = ""      # file path of the finding
    start_line: int = 0          # line number of the finding


@dataclass
class TriageConfig:
    """Configuration for the triage process."""
    model: str = "claude-sonnet-4-20250514"
    api_key: str = ""
    provider: str = "anthropic"   # "anthropic" | "openai" | "github"
    context_lines: int = 30       # lines of source context around the finding (legacy)
    min_confidence: float = 0.6   # only keep TPs above this confidence
    max_concurrent: int = 8
    call_depth: int = 2           # how deep to recursively gather caller/callee context
    max_context_functions: int = 10  # max functions to include in the context


# ── Source context extraction ────────────────────────────────────────────────

def _extract_function_from_ast(tree: ast.Module, qualified_name: str) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    """Find a function definition by qualified name (e.g. ClassName.method_name)."""
    parts = qualified_name.split(".")
    target_func = parts[-1]
    target_class = parts[-2] if len(parts) >= 2 else None

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name == target_func:
                # If we need a class context, check if this function is inside the right class
                if target_class:
                    for parent in ast.walk(tree):
                        if isinstance(parent, ast.ClassDef) and parent.name == target_class:
                            if node in ast.walk(parent):
                                return node
                else:
                    return node
    return None


def _get_function_source(tree: ast.Module, source_lines: list[str], func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    """Extract the source code for a function node."""
    start = func_node.lineno - 1
    end = func_node.end_lineno
    func_lines = source_lines[start:end]
    # Add line numbers
    numbered = [f"{start + i + 1:4d} | {line}" for i, line in enumerate(func_lines)]
    return "\n".join(numbered)


def _find_called_functions(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Extract all function names called within a function."""
    calls = set()
    for node in ast.walk(func_node):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                calls.add(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                # For method calls, include the attribute name
                calls.add(node.func.attr)
    return calls


def _find_callers(tree: ast.Module, target_func_name: str) -> list[str]:
    """Find all functions that call the target function."""
    callers = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            calls = _find_called_functions(node)
            if target_func_name in calls:
                callers.append(node.name)
    return callers


def _parse_project_asts(repo_root: Path) -> dict[Path, tuple[ast.Module, list[str]]]:
    """
    Parse all .py files in the project and return a dict mapping
    file paths to (AST, source_lines) tuples.  Results are cached
    on the function object so repeated calls are free.
    """
    cache_attr = "_ast_cache"
    if hasattr(_parse_project_asts, cache_attr):
        cached_root, cached = getattr(_parse_project_asts, cache_attr)
        if cached_root == repo_root:
            return cached

    result: dict[Path, tuple[ast.Module, list[str]]] = {}
    for py_file in repo_root.rglob("*.py"):
        # Skip common non-project dirs
        rel = py_file.relative_to(repo_root)
        parts = rel.parts
        if any(p.startswith(".") or p in ("node_modules", "__pycache__", ".git",
               "venv", ".venv", "env", ".tox", "build", "dist", "egg-info")
               for p in parts):
            continue
        try:
            source_text = py_file.read_text(errors="replace")
            tree = ast.parse(source_text, filename=str(py_file))
            result[py_file] = (tree, source_text.splitlines())
        except (SyntaxError, UnicodeDecodeError):
            continue

    setattr(_parse_project_asts, cache_attr, (repo_root, result))
    return result


def _find_function_across_project(
    func_name: str,
    project_asts: dict[Path, tuple[ast.Module, list[str]]],
) -> list[tuple[Path, ast.FunctionDef | ast.AsyncFunctionDef, list[str]]]:
    """
    Find all definitions of a function by simple name across all project files.
    Returns list of (file_path, func_node, source_lines).
    """
    matches = []
    for fpath, (tree, source_lines) in project_asts.items():
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == func_name:
                matches.append((fpath, node, source_lines))
    return matches


def _find_callers_across_project(
    target_func_name: str,
    project_asts: dict[Path, tuple[ast.Module, list[str]]],
) -> list[tuple[str, Path, ast.FunctionDef | ast.AsyncFunctionDef, list[str]]]:
    """
    Find all functions across the project that call the target function.
    Returns list of (caller_name, file_path, caller_node, source_lines).
    """
    callers = []
    for fpath, (tree, source_lines) in project_asts.items():
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                calls = _find_called_functions(node)
                if target_func_name in calls:
                    callers.append((node.name, fpath, node, source_lines))
    return callers


def _get_source_context_rich(
    artifact_uri: str,
    qualified_name: str,
    repo_root: Path,
    config: TriageConfig,
) -> str:
    """
    Extract rich source context for a finding:
    - The full function where the bug is
    - Functions it calls (callees) — searched across ALL project files
    - Functions that call it (callers) — searched across ALL project files
    - Recursively up to config.call_depth levels
    """
    try:
        fpath = repo_root / artifact_uri
        if not fpath.exists():
            return f"(source file not found: {artifact_uri})"
        
        source_text = fpath.read_text(errors="replace")
        source_lines = source_text.splitlines()
        
        try:
            tree = ast.parse(source_text, filename=str(fpath))
        except SyntaxError as e:
            return f"(syntax error in {artifact_uri}: {e})"

        # Parse all project files for cross-file lookup
        project_asts = _parse_project_asts(repo_root)

        # Extract just the function name (last component of qualified name)
        func_name = qualified_name.split(".")[-1]
        
        # Find the target function
        func_node = _extract_function_from_ast(tree, qualified_name)
        if not func_node:
            # Fallback: search for any function with matching name
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == func_name:
                    func_node = node
                    break
        
        if not func_node:
            return f"(function {qualified_name} not found in {artifact_uri})"

        context_parts = []
        
        # 1. Add the main function
        main_source = _get_function_source(tree, source_lines, func_node)
        context_parts.append(f"### Main function: {qualified_name}\n```python\n{main_source}\n```")
        
        # 2. Gather related functions up to call_depth levels — across all files
        # Each entry: (display_name, func_node, source_lines_for_file, relationship)
        related_funcs: list[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef, list[str], str]] = []
        explored = {func_name}
        to_explore: list[tuple[str, int]] = [(func_name, 0)]
        
        while to_explore and len(related_funcs) < config.max_context_functions:
            current_name, depth = to_explore.pop(0)
            
            if depth >= config.call_depth:
                continue
            
            # Find the current function node (in any file)
            current_matches = _find_function_across_project(current_name, project_asts)
            if not current_matches and current_name == func_name:
                # The main function — use the one we already found
                current_matches = [(fpath, func_node, source_lines)]
            
            for _, cur_node, _ in current_matches:
                # Find callees
                callees = _find_called_functions(cur_node)
                for callee in callees:
                    if callee in explored or len(related_funcs) >= config.max_context_functions:
                        continue
                    explored.add(callee)
                    
                    # Search for callee across ALL project files
                    callee_matches = _find_function_across_project(callee, project_asts)
                    if callee_matches:
                        c_path, c_node, c_lines = callee_matches[0]
                        rel_label = f"called by {func_name}" if depth == 0 else f"called by {current_name}"
                        c_file_rel = c_path.relative_to(repo_root) if c_path.is_relative_to(repo_root) else c_path
                        display = f"{c_file_rel.stem}.{callee}" if c_path != fpath else callee
                        related_funcs.append((display, c_node, c_lines, rel_label))
                        to_explore.append((callee, depth + 1))
                break  # Only process first match for current function
            
            # Find callers across ALL project files (only at depth 0)
            if depth == 0:
                all_callers = _find_callers_across_project(current_name, project_asts)
                for caller_name, caller_path, caller_node, caller_lines in all_callers[:5]:
                    if caller_name in explored or len(related_funcs) >= config.max_context_functions:
                        continue
                    explored.add(caller_name)
                    caller_rel = caller_path.relative_to(repo_root) if caller_path.is_relative_to(repo_root) else caller_path
                    display = f"{caller_rel.stem}.{caller_name}" if caller_path != fpath else caller_name
                    related_funcs.append((display, caller_node, caller_lines, f"calls {func_name}"))
        
        # 3. Add related functions
        for display_name, rel_node, rel_lines, relationship in related_funcs:
            # Build source with line numbers from the correct file
            start = rel_node.lineno - 1
            end = rel_node.end_lineno
            func_source_lines = rel_lines[start:end]
            numbered = [f"{start + i + 1:4d} | {line}" for i, line in enumerate(func_source_lines)]
            rel_source = "\n".join(numbered)
            context_parts.append(f"### Related function ({relationship}): {display_name}\n```python\n{rel_source}\n```")
        
        return "\n\n".join(context_parts)
    
    except Exception as e:
        return f"(error extracting context: {e})"


def _get_source_context(
    artifact_uri: str,
    start_line: int,
    repo_root: Path,
    context_lines: int = 30,
) -> str:
    """Read source lines around a finding (legacy fallback)."""
    try:
        fpath = repo_root / artifact_uri
        if not fpath.exists():
            return f"(source file not found: {artifact_uri})"
        lines = fpath.read_text(errors="replace").splitlines()
        lo = max(0, start_line - context_lines // 2 - 1)
        hi = min(len(lines), start_line + context_lines // 2)
        numbered = [f"{i + 1:4d} | {lines[i]}" for i in range(lo, hi)]
        return "\n".join(numbered)
    except Exception as e:
        return f"(error reading source: {e})"


# ── Classification prompt ────────────────────────────────────────────────────

_SYSTEM_PROMPT = textwrap.dedent("""\
    You are a senior Python security/reliability engineer reviewing static
    analysis findings.  For each finding you will see:

    1. The bug type (e.g. DIV_ZERO, NULL_PTR)
    2. The function where it was detected
    3. The complete source code of that function
    4. Related functions that call it or are called by it (if available)

    Your job is to classify the finding as TRUE POSITIVE or FALSE POSITIVE.

    A finding is a TRUE POSITIVE if:
    - There is a realistic execution path that triggers the bug
    - The bug is unintentional (not a deliberate raise/assert/sentinel pattern)
    - No surrounding guard (try/except, if-check, assert) prevents the crash
    - Constructor invariants or callers do not guarantee safety

    A finding is a FALSE POSITIVE if:
    - Constructor invariants guarantee the value can never be zero/None
    - The value is checked/guarded before use (in the function or callers)
    - The code path is unreachable in practice (dead code, always-true guard)
    - The pattern is intentional (e.g. sentinel, deliberate error raising)
    - Framework guarantees prevent the issue (e.g. PyTorch layer shapes)
    - Callers always pass valid values that prevent the issue

    You are provided with the full function source and related functions to make
    an informed decision. Use this context to understand:
    - How the function is called (from caller functions)
    - What the function does (from its implementation)
    - What it calls (from callee functions)

    Respond with EXACTLY this JSON (no markdown, no extra text):
    {
        "verdict": "TP" or "FP",
        "confidence": 0.0 to 1.0,
        "rationale": "one-sentence explanation"
    }
""")


def _build_user_message(
    bug_type: str,
    function_name: str,
    message: str,
    source_context: str,
) -> str:
    return textwrap.dedent(f"""\
        **Bug type:** {bug_type}
        **Function:** `{function_name}`
        **Static analysis message:** {message}

        **Source context (function + related code):**
        {source_context}

        Based on the full function implementation and related functions, classify this finding as TP or FP.
    """)


# ── LLM client ───────────────────────────────────────────────────────────────

def _classify_with_anthropic(
    user_message: str,
    config: TriageConfig,
) -> TriageVerdict:
    """Call Claude to classify a finding."""
    try:
        import anthropic
    except ImportError:
        raise ImportError(
            "anthropic package required for LLM triage. "
            "Install with: pip install a3[ci]"
        )

    client = anthropic.Anthropic(api_key=config.api_key or os.environ.get("ANTHROPIC_API_KEY", ""))
    response = client.messages.create(
        model=config.model,
        max_tokens=512,
        system=_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_message}],
    )

    return _parse_llm_response(response.content[0].text)


def _classify_with_openai(
    user_message: str,
    config: TriageConfig,
) -> TriageVerdict:
    """Call GPT-4 to classify a finding."""
    try:
        import openai
    except ImportError:
        raise ImportError(
            "openai package required for LLM triage. "
            "Install with: pip install a3[ci]"
        )

    client = openai.OpenAI(api_key=config.api_key or os.environ.get("OPENAI_API_KEY", ""))
    # max_completion_tokens=4096 gives headroom for reasoning models (o1, o3)
    # that use internal reasoning tokens before producing visible output.
    response = client.chat.completions.create(
        model=config.model,
        max_completion_tokens=4096,
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": user_message},
        ],
    )
    content = response.choices[0].message.content or ""
    return _parse_llm_response(content)


def _parse_llm_response(text: str) -> TriageVerdict:
    """Parse the JSON verdict from the LLM."""
    import re as _re

    text = text.strip()

    # Strip markdown fences (```json ... ``` or ``` ... ```)
    fence_match = _re.search(r"```(?:json)?\s*\n(.*?)```", text, _re.DOTALL)
    if fence_match:
        text = fence_match.group(1).strip()
    elif text.startswith("```"):
        text = "\n".join(text.split("\n")[1:])
        if text.endswith("```"):
            text = "\n".join(text.split("\n")[:-1])
        text = text.strip()

    # Try to extract JSON object if there's surrounding text
    if not text.startswith("{"):
        json_match = _re.search(r"\{[^{}]*\}", text, _re.DOTALL)
        if json_match:
            text = json_match.group(0)

    try:
        data = json.loads(text)
        return TriageVerdict(
            is_true_positive=data.get("verdict", "FP").upper() == "TP",
            confidence=float(data.get("confidence", 0.5)),
            rationale=data.get("rationale", ""),
        )
    except (json.JSONDecodeError, KeyError, ValueError):
        # If parsing fails, conservatively mark as TP
        return TriageVerdict(
            is_true_positive=True,
            confidence=0.5,
            rationale=f"LLM response could not be parsed: {text[:200]}",
        )


def _classify_with_github(user_message: str, config: TriageConfig) -> TriageVerdict:
    """Call GitHub Models (Copilot) to classify a finding.

    Uses the OpenAI-compatible endpoint at https://models.inference.ai.azure.com
    with a GITHUB_TOKEN for authentication.  This is the zero-config path inside
    GitHub Actions — every workflow already has $GITHUB_TOKEN.
    """
    try:
        import openai
    except ImportError:
        raise ImportError(
            "openai package required for GitHub Models triage. "
            "Install with: pip install a3[ci]"
        )

    token = config.api_key or os.environ.get("GITHUB_TOKEN", "")
    if not token:
        raise ValueError(
            "GITHUB_TOKEN is required for GitHub Models triage.  "
            "In GitHub Actions this is provided automatically via "
            "secrets.GITHUB_TOKEN."
        )

    client = openai.OpenAI(
        api_key=token,
        base_url="https://models.inference.ai.azure.com",
    )
    response = client.chat.completions.create(
        model=config.model,
        max_completion_tokens=4096,
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": user_message},
        ],
    )
    content = response.choices[0].message.content or ""
    return _parse_llm_response(content)


def _classify(user_message: str, config: TriageConfig) -> TriageVerdict:
    """Dispatch to the configured LLM provider."""
    if config.provider == "github":
        return _classify_with_github(user_message, config)
    if config.provider == "openai":
        return _classify_with_openai(user_message, config)
    return _classify_with_anthropic(user_message, config)


# ── Public API ────────────────────────────────────────────────────────────────

def triage_sarif(
    sarif: dict[str, Any],
    repo_root: Path,
    config: TriageConfig | None = None,
    *,
    verbose: bool = False,
) -> tuple[dict[str, Any], list[TriageVerdict]]:
    """
    Triage all findings in a SARIF dict via LLM.

    Returns a tuple of:
    - A new SARIF dict containing only findings classified as TP
      above the confidence threshold.
    - A list of all TriageVerdict objects (TP and FP) in original order.
    """
    if config is None:
        config = TriageConfig()

    output_sarif = json.loads(json.dumps(sarif))  # deep copy
    all_verdicts: list[TriageVerdict] = []

    for run in output_sarif.get("runs", []):
        original_results = run.get("results", [])
        kept: list[dict] = []

        # --- Phase 1: build prompts (fast, sequential) ---
        # (idx, result, bug_type, func_name, user_msg, source_context)
        work_items: list[tuple[int, dict, str, str, str, str]] = []
        for i, result in enumerate(original_results):
            bug_type = result.get("properties", {}).get("bugType", "UNKNOWN")
            func_name = result.get("properties", {}).get("qualifiedName", "unknown")
            message = result.get("message", {}).get("text", "")

            artifact_uri = ""
            locs = result.get("locations", [])
            if locs:
                phys = locs[0].get("physicalLocation", {})
                artifact_uri = phys.get("artifactLocation", {}).get("uri", "")

            source = _get_source_context_rich(
                artifact_uri, func_name, repo_root, config
            )
            user_msg = _build_user_message(bug_type, func_name, message, source)
            work_items.append((i, result, bug_type, func_name, user_msg, source))

        # --- Phase 2: classify in parallel ---
        n = len(work_items)
        verdicts: list[TriageVerdict | None] = [None] * n

        if verbose:
            print(f"  Triaging {n} findings ({config.max_concurrent} parallel)...", flush=True)

        def _do_classify(item: tuple[int, dict, str, str, str, str]) -> tuple[int, TriageVerdict]:
            idx, _result, _bug_type, _func_name, _user_msg, _source_ctx = item
            v = _classify(_user_msg, config)
            v.bug_type = _bug_type
            v.function_name = _func_name
            v.source_context = _source_ctx
            # Attach location metadata for the markdown report
            locs = _result.get("locations", [])
            if locs:
                phys = locs[0].get("physicalLocation", {})
                v.artifact_uri = phys.get("artifactLocation", {}).get("uri", "")
                v.start_line = phys.get("region", {}).get("startLine", 0)
            return idx, v

        with ThreadPoolExecutor(max_workers=config.max_concurrent) as executor:
            futures = {executor.submit(_do_classify, item): item for item in work_items}
            for future in as_completed(futures):
                idx, verdict = future.result()
                verdicts[idx] = verdict
                _, _, bug_type, func_name, _, _ = work_items[idx]
                if verbose:
                    label = "TP" if verdict.is_true_positive else "FP"
                    print(f"  [{idx + 1}/{n}] {func_name} ({bug_type}): "
                          f"{label} ({verdict.confidence:.0%}) — {verdict.rationale}")

        # --- Phase 3: collect results (preserves original order) ---
        for i, (_, result, _, _, _, _) in enumerate(work_items):
            verdict = verdicts[i]
            assert verdict is not None
            if verdict.is_true_positive and verdict.confidence >= config.min_confidence:
                result["properties"]["llmVerdict"] = {
                    "classification": "TP",
                    "confidence": verdict.confidence,
                    "rationale": verdict.rationale,
                }
                kept.append(result)
            else:
                result["properties"]["llmVerdict"] = {
                    "classification": "FP",
                    "confidence": verdict.confidence,
                    "rationale": verdict.rationale,
                }

        run["results"] = kept

        # ── Summary table (always printed) ──
        tp_count = sum(1 for v in verdicts if v and v.is_true_positive and v.confidence >= config.min_confidence)
        fp_count = n - tp_count

        print(f"\n{'─' * 72}")
        print(f"  {'#':>3}  {'Verdict':7}  {'Conf':>5}  {'Bug Type':15}  Function")
        print(f"{'─' * 72}")
        for i, (_, _, bug_type, func_name, _, _) in enumerate(work_items):
            v = verdicts[i]
            assert v is not None
            label = "✅ TP" if v.is_true_positive and v.confidence >= config.min_confidence else "❌ FP"
            # Shorten function name: keep last 2 dotted components
            short_name = ".".join(func_name.split(".")[-2:]) if "." in func_name else func_name
            if len(short_name) > 45:
                short_name = "…" + short_name[-44:]
            print(f"  {i + 1:>3}  {label:7}  {v.confidence:>4.0%}  {bug_type:15}  {short_name}")
        print(f"{'─' * 72}")
        print(f"  Kept {tp_count}/{n} findings  ({tp_count} TP, {fp_count} FP)")
        print()

        all_verdicts.extend(v for v in verdicts if v is not None)

    return output_sarif, all_verdicts


def generate_true_positives_md(
    verdicts: list[TriageVerdict],
    repo_root: Path,
    config: TriageConfig,
) -> str:
    """
    Generate a Markdown report with detailed justification for every
    true-positive finding.
    """
    tp_verdicts = [
        v for v in verdicts
        if v.is_true_positive and v.confidence >= config.min_confidence
    ]

    lines: list[str] = []
    lines.append("# True Positive Findings")
    lines.append("")
    lines.append(f"**Project:** `{repo_root.name}`  ")
    lines.append(f"**Confirmed true positives:** {len(tp_verdicts)}  ")
    lines.append(f"**Model:** `{config.model}`  ")
    lines.append(f"**Min confidence threshold:** {config.min_confidence:.0%}")
    lines.append("")
    lines.append("---")
    lines.append("")

    if not tp_verdicts:
        lines.append("_No true positives found — all findings were classified as false positives._")
        return "\n".join(lines)

    for i, v in enumerate(tp_verdicts, 1):
        # Header
        short_name = ".".join(v.function_name.split(".")[-2:]) if "." in v.function_name else v.function_name
        lines.append(f"## {i}. `{v.bug_type}` in `{short_name}`")
        lines.append("")

        # Metadata table
        lines.append("| Field | Value |")
        lines.append("|-------|-------|")
        lines.append(f"| **Bug Type** | `{v.bug_type}` |")
        lines.append(f"| **Function** | `{v.function_name}` |")
        if v.artifact_uri:
            loc = f"`{v.artifact_uri}`"
            if v.start_line:
                loc += f" line {v.start_line}"
            lines.append(f"| **Location** | {loc} |")
        lines.append(f"| **Confidence** | {v.confidence:.0%} |")
        lines.append(f"| **Verdict** | ✅ True Positive |")
        lines.append("")

        # LLM rationale
        lines.append("### Justification")
        lines.append("")
        lines.append(v.rationale)
        lines.append("")

        # Source context (the code the LLM actually reviewed)
        if v.source_context and not v.source_context.startswith("("):
            lines.append("### Source Context")
            lines.append("")
            lines.append(v.source_context)
            lines.append("")

        lines.append("---")
        lines.append("")

    return "\n".join(lines)


# ── CLI entry point ──────────────────────────────────────────────────────────

def cmd_triage(
    sarif_path: str,
    output_sarif_path: str | None,
    repo_root: Path,
    *,
    model: str = "claude-sonnet-4-20250514",
    api_key: str = "",
    provider: str = "anthropic",
    min_confidence: float = 0.6,
    verbose: bool = False,
) -> int:
    """
    ``a3 triage`` CLI entry point.

    Reads SARIF, triages via LLM, writes filtered SARIF.
    """
    from .sarif import load_sarif, write_sarif

    sarif = load_sarif(sarif_path)

    config = TriageConfig(
        model=model,
        api_key=api_key,
        provider=provider,
        min_confidence=min_confidence,
    )

    print(f"🔍 Triaging findings with {provider}/{model}...")
    filtered, all_verdicts = triage_sarif(sarif, repo_root, config, verbose=verbose)

    total_kept = sum(len(run.get("results", [])) for run in filtered.get("runs", []))
    total_original = sum(len(run.get("results", [])) for run in sarif.get("runs", []))
    print(f"✅  {total_kept}/{total_original} findings confirmed as TP")

    if output_sarif_path:
        write_sarif(filtered, output_sarif_path)
        print(f"📄  Filtered SARIF written to {output_sarif_path}")

        # Write true_positives.md alongside the SARIF
        md_path = Path(output_sarif_path).with_suffix(".md")
        md_content = generate_true_positives_md(all_verdicts, repo_root, config)
        md_path.write_text(md_content)
        print(f"📝  True positives report written to {md_path}")
    else:
        # Write to stdout
        print(json.dumps(filtered, indent=2))

    return 0
