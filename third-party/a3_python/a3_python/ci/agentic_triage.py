"""
Agentic LLM triage layer for A³.

Unlike the one-shot triage in triage.py, this module gives the LLM a set of
**tools** to explore the codebase — reading files, searching for patterns,
following imports, checking tests — and lets it reason iteratively before
classifying each finding as TP or FP.

The agent loop:
  1. Present the finding (bug type, function, initial source context)
  2. The LLM can call tools to gather more context
  3. When satisfied, the LLM calls the ``classify`` tool with its verdict
  4. We parse the verdict and move to the next finding

Usage (CLI):
    a3 triage --sarif results.sarif --output-sarif triaged.sarif --agentic

Usage (Python):
    from a3_python.ci.agentic_triage import agentic_triage_sarif
    filtered = agentic_triage_sarif(sarif, repo_root=Path("."))
"""

from __future__ import annotations

import ast
import json
import os
import re
import textwrap
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from .triage import (
    TriageConfig,
    TriageVerdict,
    _parse_project_asts,
    generate_true_positives_md,
)


def _get_lightweight_context(artifact_uri: str, qualified_name: str, repo_root: Path) -> str:
    """
    Extract just the flagged function's source — no cross-project AST walking.
    The agent will use its tools to explore callers/callees on its own.
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

        func_name = qualified_name.split(".")[-1]

        # Find the function in this file
        func_node = None
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == func_name:
                func_node = node
                break

        if not func_node:
            # Fallback: return a window around the file
            return f"(function {qualified_name} not found in {artifact_uri})"

        start = func_node.lineno - 1
        end = func_node.end_lineno or (start + 1)
        func_lines = source_lines[start:end]
        numbered = [f"{start + i + 1:4d} | {line}" for i, line in enumerate(func_lines)]
        return f"### {artifact_uri} :: {qualified_name} (lines {start + 1}-{end})\n```python\n" + "\n".join(numbered) + "\n```"
    except Exception as e:
        return f"(error extracting context: {e})"


# ─── Tool definitions (JSON Schema for function-calling) ────────────────────

_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": (
                "Read the contents of a file in the repository.  You can "
                "optionally specify a line range to read only a portion.  "
                "Use this to inspect source code, configuration, tests, etc."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Relative path from the repo root (e.g. 'src/utils.py').",
                    },
                    "start_line": {
                        "type": "integer",
                        "description": "1-based start line (inclusive).  Omit to read from the beginning.",
                    },
                    "end_line": {
                        "type": "integer",
                        "description": "1-based end line (inclusive).  Omit to read to the end.",
                    },
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_codebase",
            "description": (
                "Search the codebase for a regex pattern.  Returns matching "
                "lines with file paths and line numbers.  Use this to find "
                "usages, definitions, guard patterns, tests, etc."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Python regex pattern to search for.",
                    },
                    "file_glob": {
                        "type": "string",
                        "description": "Optional glob to restrict the search (e.g. '*.py', 'tests/**/*.py').  Default: '*.py'.",
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum matches to return (default: 30).",
                    },
                },
                "required": ["pattern"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_directory",
            "description": (
                "List the files and subdirectories in a directory.  "
                "Useful for understanding project structure."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Relative path from the repo root (e.g. 'src/' or '.').  Default: '.'.",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_function_source",
            "description": (
                "Get the full source code of a specific function or method, "
                "including its callers and callees.  The function is looked "
                "up by name across all project files."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "function_name": {
                        "type": "string",
                        "description": "Function or method name to look up (e.g. 'process_data' or 'MyClass.run').",
                    },
                    "file_path": {
                        "type": "string",
                        "description": "Optional file path hint to narrow the search.",
                    },
                },
                "required": ["function_name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_imports",
            "description": (
                "Get all import statements from a Python file.  Useful for "
                "understanding dependencies and where values come from."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Relative path to the Python file.",
                    },
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "classify",
            "description": (
                "Submit your final classification for this finding.  "
                "Call this ONLY when you have gathered enough context to "
                "make a confident decision.  This ends the investigation."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "verdict": {
                        "type": "string",
                        "enum": ["TP", "FP"],
                        "description": "TRUE POSITIVE or FALSE POSITIVE.",
                    },
                    "confidence": {
                        "type": "number",
                        "description": "Confidence from 0.0 to 1.0.",
                    },
                    "rationale": {
                        "type": "string",
                        "description": "1-3 sentence justification referencing specific code evidence.",
                    },
                },
                "required": ["verdict", "confidence", "rationale"],
            },
        },
    },
]

# Same tools formatted for Anthropic's API
_TOOLS_ANTHROPIC = [
    {
        "name": t["function"]["name"],
        "description": t["function"]["description"],
        "input_schema": t["function"]["parameters"],
    }
    for t in _TOOLS
]


# ─── Tool implementations ───────────────────────────────────────────────────

def _tool_read_file(repo_root: Path, path: str, start_line: int | None = None, end_line: int | None = None) -> str:
    """Read a file, optionally a line range."""
    fpath = repo_root / path
    if not fpath.exists():
        return f"Error: file not found: {path}"
    if not fpath.is_file():
        return f"Error: not a file: {path}"
    # Safety: don't read outside repo
    try:
        fpath.resolve().relative_to(repo_root.resolve())
    except ValueError:
        return f"Error: path escapes repository root: {path}"

    try:
        lines = fpath.read_text(errors="replace").splitlines()
    except Exception as e:
        return f"Error reading {path}: {e}"

    total = len(lines)
    lo = (start_line - 1) if start_line else 0
    hi = end_line if end_line else total
    lo = max(0, min(lo, total))
    hi = max(lo, min(hi, total))

    if hi - lo > 500:
        hi = lo + 500  # cap at 500 lines per read

    numbered = [f"{lo + i + 1:4d} | {lines[lo + i]}" for i in range(hi - lo)]
    header = f"# {path}  (lines {lo + 1}-{hi} of {total})"
    return header + "\n" + "\n".join(numbered)


def _tool_search_codebase(repo_root: Path, pattern: str, file_glob: str = "*.py", max_results: int = 30) -> str:
    """Grep the codebase for a regex pattern."""
    try:
        compiled = re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        return f"Error: invalid regex: {e}"

    matches: list[str] = []
    for py_file in repo_root.rglob(file_glob):
        # Skip non-project dirs
        rel = py_file.relative_to(repo_root)
        parts = rel.parts
        if any(p.startswith(".") or p in (
            "node_modules", "__pycache__", ".git", "venv", ".venv",
            "env", ".tox", "build", "dist",
        ) for p in parts):
            continue
        try:
            lines = py_file.read_text(errors="replace").splitlines()
            for i, line in enumerate(lines):
                if compiled.search(line):
                    matches.append(f"{rel}:{i + 1}: {line.rstrip()}")
                    if len(matches) >= max_results:
                        break
        except Exception:
            continue
        if len(matches) >= max_results:
            break

    if not matches:
        return f"No matches found for pattern: {pattern}"
    return f"Found {len(matches)} match(es):\n" + "\n".join(matches)


def _tool_list_directory(repo_root: Path, path: str = ".") -> str:
    """List directory contents."""
    dpath = repo_root / path
    if not dpath.exists():
        return f"Error: directory not found: {path}"
    if not dpath.is_dir():
        return f"Error: not a directory: {path}"
    try:
        dpath.resolve().relative_to(repo_root.resolve())
    except ValueError:
        return f"Error: path escapes repository root: {path}"

    entries: list[str] = []
    for child in sorted(dpath.iterdir()):
        if child.name.startswith(".") or child.name == "__pycache__":
            continue
        suffix = "/" if child.is_dir() else ""
        entries.append(f"  {child.name}{suffix}")

    if not entries:
        return f"{path}/ (empty)"
    return f"{path}/\n" + "\n".join(entries)


def _tool_get_function_source(repo_root: Path, function_name: str, file_path: str | None = None) -> str:
    """Find and return the full source of a function by name."""
    project_asts = _parse_project_asts(repo_root)
    func_name = function_name.split(".")[-1]

    matches: list[tuple[Path, ast.FunctionDef | ast.AsyncFunctionDef, list[str]]] = []
    for fpath, (tree, source_lines) in project_asts.items():
        if file_path:
            try:
                rel = fpath.relative_to(repo_root)
                if file_path not in str(rel):
                    continue
            except ValueError:
                continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == func_name:
                matches.append((fpath, node, source_lines))

    if not matches:
        return f"Function '{function_name}' not found in the project."

    parts: list[str] = []
    for fpath, node, source_lines in matches[:3]:  # limit to 3 matches
        rel = fpath.relative_to(repo_root)
        start = node.lineno - 1
        end = node.end_lineno or (start + 1)
        func_lines = source_lines[start:end]
        numbered = [f"{start + i + 1:4d} | {line}" for i, line in enumerate(func_lines)]
        parts.append(f"### {rel} :: {node.name} (lines {start + 1}-{end})\n" + "\n".join(numbered))

    return "\n\n".join(parts)


def _tool_get_imports(repo_root: Path, path: str) -> str:
    """Extract all import statements from a Python file."""
    fpath = repo_root / path
    if not fpath.exists():
        return f"Error: file not found: {path}"
    try:
        source = fpath.read_text(errors="replace")
        tree = ast.parse(source, filename=path)
    except (SyntaxError, UnicodeDecodeError) as e:
        return f"Error parsing {path}: {e}"

    imports: list[str] = []
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(f"import {alias.name}" + (f" as {alias.asname}" if alias.asname else ""))
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            names = ", ".join(
                a.name + (f" as {a.asname}" if a.asname else "") for a in node.names
            )
            level_dots = "." * (node.level or 0)
            imports.append(f"from {level_dots}{module} import {names}")

    if not imports:
        return f"No imports found in {path}."
    return f"Imports in {path}:\n" + "\n".join(f"  {imp}" for imp in imports)


_MAX_TOOL_OUTPUT_CHARS = 6000  # ~1500 tokens — keeps us under model limits


def _dispatch_tool(repo_root: Path, name: str, arguments: dict[str, Any]) -> str:
    """Route a tool call to the right implementation, truncating large outputs."""
    if name == "read_file":
        result = _tool_read_file(repo_root, **arguments)
    elif name == "search_codebase":
        result = _tool_search_codebase(repo_root, **arguments)
    elif name == "list_directory":
        result = _tool_list_directory(repo_root, **arguments)
    elif name == "get_function_source":
        result = _tool_get_function_source(repo_root, **arguments)
    elif name == "get_imports":
        result = _tool_get_imports(repo_root, **arguments)
    elif name == "classify":
        # Handled by the caller — should not reach here
        return json.dumps(arguments)
    else:
        return f"Error: unknown tool '{name}'"

    # Truncate long outputs to stay under token limits
    if len(result) > _MAX_TOOL_OUTPUT_CHARS:
        result = result[:_MAX_TOOL_OUTPUT_CHARS] + f"\n\n[... truncated — {len(result)} total chars]"
    return result


# ─── Agent system prompt ────────────────────────────────────────────────────

_AGENT_SYSTEM_PROMPT = textwrap.dedent("""\
    You are a senior Python security/reliability engineer investigating a
    static analysis finding.  You have access to tools that let you explore
    the codebase:

    - **read_file**: Read source code from any file
    - **search_codebase**: Grep for patterns (e.g. guard checks, tests, usages)
    - **list_directory**: Understand project structure
    - **get_function_source**: Get the full source of any function by name
    - **get_imports**: See what a file imports

    Your workflow:
    1. Review the initial finding and source context provided
    2. Investigate further using the tools above — check callers, tests,
       guard patterns, type annotations, constructor invariants, etc.
    3. When you have enough evidence, call **classify** with your verdict

    A finding is a TRUE POSITIVE (TP) if:
    - There is a realistic execution path that triggers the bug
    - The bug is unintentional (not a deliberate raise/assert/sentinel)
    - No surrounding guard prevents the crash
    - Constructor invariants or callers do not guarantee safety

    A finding is a FALSE POSITIVE (FP) if:
    - Guards, checks, or invariants prevent the issue
    - The code path is unreachable in practice
    - The pattern is intentional (sentinel, deliberate error)
    - Framework guarantees prevent the issue
    - Callers always pass safe values

    Be thorough but efficient.  Typically 2-4 tool calls suffice.
    Always call **classify** when done — do not just respond with text.
    You MUST call classify within 8 tool-use turns. If unsure, classify
    with your best guess and a lower confidence score.
""")


# ─── Agent loop per provider ────────────────────────────────────────────────

MAX_AGENT_TURNS = 10  # hard limit on tool-use turns


def _run_agent_openai(
    initial_message: str,
    config: TriageConfig,
    repo_root: Path,
    *,
    verbose: bool = False,
) -> TriageVerdict:
    """Run an agentic triage loop using OpenAI-compatible API (OpenAI or GitHub Models)."""
    try:
        import openai
    except ImportError:
        raise ImportError("openai package required. Install with: pip install a3-python[ci]")

    if config.provider == "github":
        token = config.api_key or os.environ.get("GITHUB_TOKEN", "")
        client = openai.OpenAI(api_key=token, base_url="https://models.inference.ai.azure.com")
    else:
        client = openai.OpenAI(api_key=config.api_key or os.environ.get("OPENAI_API_KEY", ""))

    model = config.model
    if model == "claude-sonnet-4-20250514":
        # gpt-4o-mini has much higher token limits on GitHub Models free tier
        # gpt-5 has only 4K input tokens which is too small for agentic use
        model = "gpt-4o-mini"

    messages: list[dict[str, Any]] = [
        {"role": "system", "content": _AGENT_SYSTEM_PROMPT},
        {"role": "user", "content": initial_message},
    ]

    for _turn in range(MAX_AGENT_TURNS):
        # On the second-to-last turn, inject a nudge to classify now
        if _turn == MAX_AGENT_TURNS - 2:
            messages.append({
                "role": "user",
                "content": "You are running low on turns. Please call the classify tool NOW with your best verdict.",
            })

        if verbose:
            print(f"    [agent turn {_turn + 1}] calling LLM...", flush=True)

        # Retry with exponential backoff for rate limits
        max_retries = 8 if config.provider == "github" else 5
        for attempt in range(max_retries):
            try:
                response = client.chat.completions.create(
                    model=model,
                    max_completion_tokens=4096,
                    messages=messages,
                    tools=_TOOLS,
                    tool_choice="auto",
                )
                break
            except Exception as e:
                err_str = str(e)
                if "429" in err_str or "RateLimitReached" in err_str or "rate" in err_str.lower():
                    # Try to extract Retry-After from the error
                    retry_after = None
                    if hasattr(e, 'response') and hasattr(e.response, 'headers'):
                        retry_after = e.response.headers.get('retry-after') or e.response.headers.get('Retry-After')
                    if retry_after:
                        try:
                            wait = int(float(retry_after)) + 1
                        except (ValueError, TypeError):
                            wait = 60
                    elif config.provider == "github":
                        wait = min(5 * (2 ** attempt), 120)  # 5, 10, 20, 40, 80, 120, 120, 120
                    else:
                        wait = 2 ** attempt  # 1, 2, 4, 8, 16 seconds
                    if verbose:
                        print(f"    [rate limited, retrying in {wait}s...] ({err_str[:80]})", flush=True)
                    time.sleep(wait)
                else:
                    raise
        else:
            # All retries exhausted
            return TriageVerdict(
                is_true_positive=True,
                confidence=0.5,
                rationale="Rate limit exceeded after retries",
            )

        choice = response.choices[0]
        msg = choice.message

        # Append the assistant message (with any tool_calls)
        messages.append(msg.to_dict() if hasattr(msg, "to_dict") else json.loads(msg.model_dump_json()))

        # If no tool calls, the model just responded with text — force classify
        if not msg.tool_calls:
            # Model decided to answer without using classify tool — parse text
            if verbose:
                print(f"    [agent turn {_turn + 1}] no tool calls, parsing text", flush=True)
            return _parse_text_verdict(msg.content or "")

        # Process each tool call
        for tc in msg.tool_calls:
            fn_name = tc.function.name
            try:
                fn_args = json.loads(tc.function.arguments)
            except json.JSONDecodeError:
                fn_args = {}

            if verbose:
                args_str = ", ".join(f"{k}={v!r}" for k, v in fn_args.items())
                print(f"    [agent turn {_turn + 1}] tool: {fn_name}({args_str})", flush=True)

            # If it's the classify tool, we're done
            if fn_name == "classify":
                return TriageVerdict(
                    is_true_positive=fn_args.get("verdict", "FP").upper() == "TP",
                    confidence=float(fn_args.get("confidence", 0.5)),
                    rationale=fn_args.get("rationale", ""),
                )

            # Execute the tool and add the result
            result = _dispatch_tool(repo_root, fn_name, fn_args)
            messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": result,
            })

    # Hit max turns — conservatively mark as TP
    return TriageVerdict(
        is_true_positive=True,
        confidence=0.5,
        rationale="Agent reached maximum investigation turns without classifying.",
    )


def _run_agent_anthropic(
    initial_message: str,
    config: TriageConfig,
    repo_root: Path,
    *,
    verbose: bool = False,
) -> TriageVerdict:
    """Run an agentic triage loop using Anthropic API."""
    try:
        import anthropic
    except ImportError:
        raise ImportError("anthropic package required. Install with: pip install a3-python[ci]")

    client = anthropic.Anthropic(api_key=config.api_key or os.environ.get("ANTHROPIC_API_KEY", ""))

    messages: list[dict[str, Any]] = [
        {"role": "user", "content": initial_message},
    ]

    for _turn in range(MAX_AGENT_TURNS):
        # On the second-to-last turn, inject a nudge to classify now
        if _turn == MAX_AGENT_TURNS - 2:
            messages.append({
                "role": "user",
                "content": "You are running low on turns. Please call the classify tool NOW with your best verdict.",
            })

        # Retry with exponential backoff for rate limits
        for attempt in range(6):
            try:
                response = client.messages.create(
                    model=config.model,
                    max_tokens=4096,
                    system=_AGENT_SYSTEM_PROMPT,
                    messages=messages,
                    tools=_TOOLS_ANTHROPIC,
                )
                break
            except Exception as e:
                if "429" in str(e) or "rate" in str(e).lower() or "overloaded" in str(e).lower():
                    wait = min(2 ** (attempt + 1), 60)  # 2, 4, 8, 16, 32, 60
                    if verbose:
                        print(f"    [rate limited, retrying in {wait}s...]", flush=True)
                    time.sleep(wait)
                else:
                    raise
        else:
            return TriageVerdict(
                is_true_positive=True,
                confidence=0.5,
                rationale="Rate limit exceeded after retries",
            )

        # Build the assistant message content
        assistant_content: list[dict[str, Any]] = []
        tool_uses: list[dict[str, Any]] = []

        for block in response.content:
            if block.type == "text":
                assistant_content.append({"type": "text", "text": block.text})
            elif block.type == "tool_use":
                assistant_content.append({
                    "type": "tool_use",
                    "id": block.id,
                    "name": block.name,
                    "input": block.input,
                })
                tool_uses.append({
                    "id": block.id,
                    "name": block.name,
                    "input": block.input,
                })

        messages.append({"role": "assistant", "content": assistant_content})

        if not tool_uses:
            # No tool calls — extract verdict from text
            text = " ".join(
                b["text"] for b in assistant_content if b.get("type") == "text"
            )
            return _parse_text_verdict(text)

        # Process tool calls
        tool_results: list[dict[str, Any]] = []
        for tu in tool_uses:
            fn_name = tu["name"]
            fn_args = tu["input"] or {}

            if fn_name == "classify":
                return TriageVerdict(
                    is_true_positive=fn_args.get("verdict", "FP").upper() == "TP",
                    confidence=float(fn_args.get("confidence", 0.5)),
                    rationale=fn_args.get("rationale", ""),
                )

            result = _dispatch_tool(repo_root, fn_name, fn_args)
            tool_results.append({
                "type": "tool_result",
                "tool_use_id": tu["id"],
                "content": result,
            })

        messages.append({"role": "user", "content": tool_results})

    return TriageVerdict(
        is_true_positive=True,
        confidence=0.5,
        rationale="Agent reached maximum investigation turns without classifying.",
    )


def _parse_text_verdict(text: str) -> TriageVerdict:
    """Fallback: parse a verdict from plain text if the model didn't use the classify tool."""
    text = text.strip()

    # Try JSON first
    json_match = re.search(r"\{[^{}]*\}", text, re.DOTALL)
    if json_match:
        try:
            data = json.loads(json_match.group(0))
            return TriageVerdict(
                is_true_positive=data.get("verdict", "FP").upper() == "TP",
                confidence=float(data.get("confidence", 0.5)),
                rationale=data.get("rationale", text[:200]),
            )
        except (json.JSONDecodeError, KeyError, ValueError):
            pass

    # Heuristic: look for TP/FP keywords
    upper = text.upper()
    if "TRUE POSITIVE" in upper or "VERDICT: TP" in upper or '"TP"' in upper:
        return TriageVerdict(is_true_positive=True, confidence=0.6, rationale=text[:200])
    if "FALSE POSITIVE" in upper or "VERDICT: FP" in upper or '"FP"' in upper:
        return TriageVerdict(is_true_positive=False, confidence=0.6, rationale=text[:200])

    # Can't determine — conservatively mark as TP
    return TriageVerdict(is_true_positive=True, confidence=0.5, rationale=f"Could not parse agent response: {text[:200]}")


def _run_agent(
    initial_message: str,
    config: TriageConfig,
    repo_root: Path,
    *,
    verbose: bool = False,
) -> TriageVerdict:
    """Dispatch to the right agent loop based on provider."""
    if config.provider in ("openai", "github"):
        return _run_agent_openai(initial_message, config, repo_root, verbose=verbose)
    return _run_agent_anthropic(initial_message, config, repo_root, verbose=verbose)


# ─── Build the initial prompt for each finding ──────────────────────────────

def _build_agent_prompt(
    bug_type: str,
    function_name: str,
    message: str,
    artifact_uri: str,
    start_line: int,
    source_context: str,
) -> str:
    """Build the initial user message that kicks off the agent investigation."""
    return textwrap.dedent(f"""\
        I need you to investigate this static analysis finding and determine
        whether it is a real bug (True Positive) or a false alarm (False Positive).

        **Bug type:** {bug_type}
        **Function:** `{function_name}`
        **File:** `{artifact_uri}` (line {start_line})
        **Static analysis message:** {message}

        **Initial source context (function + related code):**
        {source_context}

        Please investigate using the available tools.  In particular, consider:
        - Are there guards/checks that prevent this issue?
        - How is this function called?  Do callers guarantee safe values?
        - Are there tests that exercise this code path?
        - Is this pattern intentional (sentinel, deliberate error)?
        - Do type annotations or constructor invariants constrain the values?

        When you have enough evidence, call the **classify** tool with your verdict.
    """)


# ─── Public API ──────────────────────────────────────────────────────────────

def agentic_triage_sarif(
    sarif: dict[str, Any],
    repo_root: Path,
    config: TriageConfig | None = None,
    *,
    verbose: bool = False,
) -> tuple[dict[str, Any], list[TriageVerdict]]:
    """
    Agentic triage of all findings in a SARIF dict.

    Same signature as ``triage.triage_sarif`` but uses multi-turn tool-use
    instead of one-shot classification.

    Returns (filtered_sarif, all_verdicts).
    """
    if config is None:
        config = TriageConfig()

    output_sarif = json.loads(json.dumps(sarif))  # deep copy
    all_verdicts: list[TriageVerdict] = []

    for run in output_sarif.get("runs", []):
        original_results = run.get("results", [])
        kept: list[dict] = []

        # --- Phase 1: build initial prompts ---
        work_items: list[tuple[int, dict, str, str, str, str, int]] = []
        for i, result in enumerate(original_results):
            bug_type = result.get("properties", {}).get("bugType", "UNKNOWN")
            func_name = result.get("properties", {}).get("qualifiedName", "unknown")
            message = result.get("message", {}).get("text", "")
            artifact_uri = ""
            start_line = 0
            locs = result.get("locations", [])
            if locs:
                phys = locs[0].get("physicalLocation", {})
                artifact_uri = phys.get("artifactLocation", {}).get("uri", "")
                start_line = phys.get("region", {}).get("startLine", 0)

            work_items.append((i, result, bug_type, func_name, message, artifact_uri, start_line))

        # --- Phase 2: run agents (with limited parallelism) ---
        # GitHub Models free tier only allows 1 concurrent request
        n = len(work_items)
        verdicts: list[TriageVerdict | None] = [None] * n
        if config.provider == "github":
            agent_concurrency = 1  # GitHub Models rate-limits concurrent requests
        else:
            agent_concurrency = min(config.max_concurrent, 4)

        if verbose:
            print(f"  🤖 Agentic triage of {n} findings ({agent_concurrency} parallel)...", flush=True)

        def _do_agent(item: tuple[int, dict, str, str, str, str, int]) -> tuple[int, TriageVerdict]:
            idx, _result, bug_type, func_name, message, artifact_uri, start_line = item
            source = _get_lightweight_context(artifact_uri, func_name, repo_root)
            prompt = _build_agent_prompt(
                bug_type, func_name, message, artifact_uri, start_line, source,
            )
            # Add inter-request delay for GitHub Models to avoid rate limits
            if config.provider == "github" and idx > 0:
                time.sleep(2)
            v = _run_agent(prompt, config, repo_root, verbose=verbose)
            v.bug_type = bug_type
            v.function_name = func_name
            v.source_context = source
            v.artifact_uri = artifact_uri
            v.start_line = start_line
            return idx, v

        with ThreadPoolExecutor(max_workers=agent_concurrency) as executor:
            futures = {executor.submit(_do_agent, item): item for item in work_items}
            for future in as_completed(futures):
                try:
                    idx, verdict = future.result()
                except ImportError as e:
                    # Missing package — bail out immediately with a useful message
                    raise ImportError(str(e)) from e
                except Exception as e:
                    idx = futures[future][0]
                    verdict = TriageVerdict(
                        is_true_positive=True,
                        confidence=0.5,
                        rationale=f"Agent error: {e}",
                    )
                    # Always surface agent errors so users know triage degraded
                    print(f"  ⚠  Agent error for finding {idx + 1}: {e}", file=__import__('sys').stderr)
                verdicts[idx] = verdict
                _, _, bug_type, func_name, _, _, _ = work_items[idx]
                if verbose:
                    label = "TP" if verdict.is_true_positive else "FP"
                    print(f"  [{idx + 1}/{n}] {func_name} ({bug_type}): "
                          f"{label} ({verdict.confidence:.0%}) — {verdict.rationale}")

        # --- Phase 3: filter results ---
        for i, (_, result, _, _, _, _, _) in enumerate(work_items):
            verdict = verdicts[i]
            assert verdict is not None
            if verdict.is_true_positive and verdict.confidence >= config.min_confidence:
                result["properties"]["llmVerdict"] = {
                    "classification": "TP",
                    "confidence": verdict.confidence,
                    "rationale": verdict.rationale,
                    "mode": "agentic",
                }
                kept.append(result)
            else:
                result["properties"]["llmVerdict"] = {
                    "classification": "FP",
                    "confidence": verdict.confidence,
                    "rationale": verdict.rationale,
                    "mode": "agentic",
                }

        run["results"] = kept

        # ── Summary table ──
        tp_count = sum(1 for v in verdicts if v and v.is_true_positive and v.confidence >= config.min_confidence)
        fp_count = n - tp_count

        print(f"\n{'─' * 72}")
        print(f"  {'#':>3}  {'Verdict':7}  {'Conf':>5}  {'Bug Type':15}  Function")
        print(f"{'─' * 72}")
        for i, (_, _, bug_type, func_name, _, _, _) in enumerate(work_items):
            v = verdicts[i]
            assert v is not None
            label = "✅ TP" if v.is_true_positive and v.confidence >= config.min_confidence else "❌ FP"
            short_name = ".".join(func_name.split(".")[-2:]) if "." in func_name else func_name
            if len(short_name) > 45:
                short_name = "…" + short_name[-44:]
            print(f"  {i + 1:>3}  {label:7}  {v.confidence:>4.0%}  {bug_type:15}  {short_name}")
        print(f"{'─' * 72}")
        print(f"  Kept {tp_count}/{n} findings  ({tp_count} TP, {fp_count} FP)  [agentic mode]")
        print()

        all_verdicts.extend(v for v in verdicts if v is not None)

    return output_sarif, all_verdicts


# ─── CLI entry point ────────────────────────────────────────────────────────

def cmd_agentic_triage(
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
    ``a3 triage --agentic`` CLI entry point.

    Same interface as ``cmd_triage`` but uses multi-turn agentic investigation.
    """
    from .sarif import load_sarif, write_sarif

    sarif = load_sarif(sarif_path)

    config = TriageConfig(
        model=model,
        api_key=api_key,
        provider=provider,
        min_confidence=min_confidence,
    )

    print(f"🤖 Agentic triage with {provider}...")
    filtered, all_verdicts = agentic_triage_sarif(sarif, repo_root, config, verbose=verbose)

    total_kept = sum(len(run.get("results", [])) for run in filtered.get("runs", []))
    total_original = sum(len(run.get("results", [])) for run in sarif.get("runs", []))
    print(f"✅  {total_kept}/{total_original} findings confirmed as TP  [agentic]")

    if output_sarif_path:
        write_sarif(filtered, output_sarif_path)
        print(f"📄  Filtered SARIF written to {output_sarif_path}")

        md_path = Path(output_sarif_path).with_suffix(".md")
        md_content = generate_true_positives_md(all_verdicts, repo_root, config)
        md_path.write_text(md_content)
        print(f"📝  True positives report written to {md_path}")
    else:
        print(json.dumps(filtered, indent=2))

    return 0
