"""
Unified security analysis CLI — ``pyflow security``.

Dispatches to one of four engine backends:

- ``ast-scanner`` — fast AST pattern matching (Bandit-style), no analysis pipeline
- ``cpa`` — PyFlow pipeline + CPA-backed security checks on the AST
- ``ifds`` — IFDS solver over CFG supergraphs (interprocedural, flow-sensitive)
- ``cpg`` — CPG-based context-sensitive security analysis with heap-aware alias tracking
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from pyflow.checker.pattern.core.manager import SecurityManager
from pyflow.checker.pattern.core.config import SecurityConfig
from pyflow.checker.pattern.core import constants as b_constants
from pyflow.checker.semantic import BugFinderConfig, SemanticManager
from .reporting import (
    _ifds_result_to_dict,
    _nullness_result_to_dict,
    _output_results,
    _typestate_result_to_dict,
)

# ── Engine dispatchers ────────────────────────────────────────────────────


def _ifds_solver_options(args):
    from pyflow.analysis.ifds.core.solver import SolverOptions

    return SolverOptions(
        max_propagated_path_edges=getattr(args, "ifds_max_path_edges", None),
        max_seconds=getattr(args, "ifds_max_seconds", None),
        max_queue_size=getattr(args, "ifds_max_queue_size", None),
        max_incoming_records=getattr(args, "ifds_max_incoming_records", None),
        max_summary_entries=getattr(args, "ifds_max_summary_entries", None),
        max_facts_per_node=getattr(args, "ifds_max_facts_per_node", None),
        max_contexts_per_procedure=getattr(
            args, "ifds_max_contexts_per_procedure", None
        ),
        max_memory_bytes=getattr(args, "ifds_max_memory_bytes", None),
        max_call_string_depth=getattr(args, "ifds_context_depth", 3),
        trace_mode=getattr(args, "ifds_trace_mode", "findings"),
        limit_behavior="partial",
    )


_CONFIG_SCALAR_MAP: dict[str, str] = {
    "analysis": "analysis",
    "function": "function",
    "ifds_mode": "ifds_mode",
    "ifds_trace_mode": "ifds_trace_mode",
    "ifds_context_depth": "ifds_context_depth",
}

_CONFIG_LIST_MAP: dict[str, str] = {
    "frameworks": "framework",
    "sources": "sources",
    "sinks": "sinks",
    "sanitizers": "sanitizers",
    "registry_path": "registry_path",
    "typestate_protocol": "typestate_protocol",
}

_CONFIG_SOLVER_MAP: dict[str, str] = {
    "max_seconds": "ifds_max_seconds",
    "max_path_edges": "ifds_max_path_edges",
    "max_queue_size": "ifds_max_queue_size",
    "max_incoming_records": "ifds_max_incoming_records",
    "max_summary_entries": "ifds_max_summary_entries",
    "max_facts_per_node": "ifds_max_facts_per_node",
    "max_contexts_per_procedure": "ifds_max_contexts_per_procedure",
    "max_memory_bytes": "ifds_max_memory_bytes",
    "max_call_string_depth": "ifds_max_call_string_depth",
}


def _apply_ifds_config(args) -> None:
    config_path = getattr(args, "config", None)
    if config_path is None:
        return
    path = Path(config_path)
    if not path.exists():
        print(f"Error: config file not found: {config_path}", file=sys.stderr)
        raise SystemExit(2)

    try:
        config_data = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        print(f"Error: invalid JSON in config file {config_path}: {exc}",
              file=sys.stderr)
        raise SystemExit(2)

    unknown = set(config_data) - {"solver_options", "frameworks", "sources",
        "sinks", "sanitizers", "analysis", "function", "ifds_mode",
        "ifds_trace_mode", "ifds_context_depth", "registry_path",
        "typestate_protocol"}
    if unknown:
        print(f"Warning: unknown config keys: {', '.join(sorted(unknown))}",
              file=sys.stderr)

    for config_key, attr_name in _CONFIG_SCALAR_MAP.items():
        if config_key in config_data and not hasattr(args, attr_name):
            setattr(args, attr_name, config_data[config_key])

    for config_key, attr_name in _CONFIG_LIST_MAP.items():
        if config_key in config_data and not hasattr(args, attr_name):
            setattr(args, attr_name, config_data[config_key])

    solver_opts = config_data.get("solver_options")
    if isinstance(solver_opts, dict):
        for config_key, attr_name in _CONFIG_SOLVER_MAP.items():
            if config_key in solver_opts and not hasattr(args, attr_name):
                setattr(args, attr_name, solver_opts[config_key])


def _run_ast_scanner(
    targets: List[str],
    args,
    *,
    exclude: str = "",
    recursive: bool = False,
) -> SecurityManager:
    """Run the fast AST pattern-matching scanner (was 'pattern')."""
    config = SecurityConfig()
    manager = SecurityManager(
        config=config,
        debug=getattr(args, "debug", False),
        verbose=getattr(args, "verbose", False),
        quiet=False,
    )
    manager.discover_files(
        targets,
        recursive=recursive,
        excluded_paths=",".join(_parse_exclude_tuple(exclude)),
    )
    manager.run_tests()
    return manager


def _run_cpa(
    targets: List[str],
    args,
    *,
    exclude: str = "",
    recursive: bool = False,
) -> SemanticManager:
    """Run the CPA-backed semantic security analysis (was 'semantic')."""
    config = BugFinderConfig(
        verbose=getattr(args, "verbose", False),
        recursive=recursive,
        exclude=_parse_exclude_tuple(exclude),
        taint_engine=getattr(args, "taint_engine", "ast"),
        sources=tuple(getattr(args, "sources", ()) or ()),
        sinks=tuple(getattr(args, "sinks", ()) or ()),
    )
    manager = SemanticManager(
        config=config,
        debug=getattr(args, "debug", False),
        verbose=getattr(args, "verbose", False),
        quiet=False,
    )
    manager.analyze(targets)
    return manager


def _run_ifds(targets: List[str], args) -> Dict[str, Any]:
    """Run the IFDS-backed interprocedural security analysis."""
    from pyflow.analysis.ifds.api import (
        run_nullness_analysis,
        run_taint_analysis,
        run_typestate_analysis,
    )
    from pyflow.analysis.ifds.frontend.preparation import PreparationMode

    solver_options = _ifds_solver_options(args)
    preparation_mode = (
        PreparationMode.STRICT
        if getattr(args, "ifds_mode", "best-effort") == "strict"
        else PreparationMode.BEST_EFFORT
    )

    files = _discover_python_files(targets, getattr(args, "recursive", False))
    if not files:
        print("No Python files found to analyze", file=sys.stderr)
        return {
            "function": args.function or "<unknown>",
            "findings": [],
            "diagnostics": [],
            "status": "failed",
            "termination_reason": "No Python files found to analyze",
        }

    if getattr(args, "analysis", "taint") == "typestate":
        try:
            _session, typestate_result = run_typestate_analysis(
                files,
                function=args.function or "",
                enabled_protocols=_parse_typestate_protocols(args),
                registry_frameworks=getattr(args, "framework", ()) or (),
                registry_paths=getattr(args, "registry_path", []) or (),
                collection_mutator_names=getattr(args, "collection_mutators", None),
                collection_accessor_names=getattr(args, "collection_accessors", None),
                dependency_strategy=getattr(args, "dependency_strategy", "auto"),
                verbose=getattr(args, "verbose", False),
                solver_options=solver_options,
                preparation_mode=preparation_mode,
            )
        except Exception as e:
            print(f"IFDS analysis failed: {e}", file=sys.stderr)
            return {
                "function": args.function or "<unknown>",
                "analysis": "typestate",
                "findings": [],
                "diagnostics": [str(e)],
                "status": "failed",
                "termination_reason": str(e),
            }
        result = _typestate_result_to_dict(
            args.function or "<unknown>", typestate_result
        )
        return _apply_session_diagnostics(result, _session)

    if getattr(args, "analysis", "taint") == "nullness":
        try:
            _session, nullness_result = run_nullness_analysis(
                files,
                function=args.function or "",
                registry_frameworks=getattr(args, "framework", ()) or (),
                registry_paths=getattr(args, "registry_path", []) or (),
                dependency_strategy=getattr(args, "dependency_strategy", "auto"),
                verbose=getattr(args, "verbose", False),
                solver_options=solver_options,
                preparation_mode=preparation_mode,
            )
        except Exception as e:
            print(f"IFDS analysis failed: {e}", file=sys.stderr)
            return {
                "function": args.function or "<unknown>",
                "analysis": "nullness",
                "findings": [],
                "diagnostics": [str(e)],
                "status": "failed",
                "termination_reason": str(e),
            }
        result = _nullness_result_to_dict(args.function or "<unknown>", nullness_result)
        return _apply_session_diagnostics(result, _session)

    sources, sinks, sanitizers = _merge_taint_specs(args, source_files=files)

    if not sources and not sinks:
        print(
            "No sources or sinks specified. Use --sources/--sinks --framework,"
            " or --registry-path.",
            file=sys.stderr,
        )
        return {
            "function": args.function or "<unknown>",
            "findings": [],
            "diagnostics": [],
            "status": "invalid",
            "termination_reason": "No taint sources or sinks configured",
        }

    try:
        _session, taint_result, _shadow_matches = run_taint_analysis(
            files,
            function=args.function or "",
            source_names=sources,
            sink_names=sinks,
            sanitizer_names=sanitizers,
            collection_mutator_names=getattr(args, "collection_mutators", None),
            collection_accessor_names=getattr(args, "collection_accessors", None),
            conservative_unresolved_call_side_effects=getattr(
                args, "conservative_unresolved_calls", False
            ),
            dependency_strategy=getattr(args, "dependency_strategy", "auto"),
            verbose=getattr(args, "verbose", False),
            solver_options=solver_options,
            preparation_mode=preparation_mode,
        )
    except Exception as e:
        print(f"IFDS analysis failed: {e}", file=sys.stderr)
        return {
            "function": args.function or "<unknown>",
            "findings": [],
            "diagnostics": [str(e)],
            "status": "failed",
            "termination_reason": str(e),
        }

    result = _ifds_result_to_dict(args.function or "<unknown>", taint_result)
    return _apply_session_diagnostics(result, _session)


def _diagnostics_to_dicts(diagnostics) -> list[Any]:
    from dataclasses import asdict, is_dataclass

    return [
        (asdict(diagnostic) if is_dataclass(diagnostic) else str(diagnostic))
        for diagnostic in diagnostics
    ]


def _apply_session_diagnostics(result: Dict[str, Any], session) -> Dict[str, Any]:
    diagnostics = tuple(getattr(session, "diagnostics", ()))
    result["diagnostics"] = _diagnostics_to_dicts(diagnostics)
    if result.get("status") == "complete" and any(
        getattr(diagnostic, "affects_completeness", False) for diagnostic in diagnostics
    ):
        result["status"] = "partial"
        result["termination_reason"] = (
            "Analysis preparation recovered from one or more incomplete stages"
        )
    return result


def _run_cpg(targets: List[str], args) -> List[Dict[str, Any]]:
    """Run the CPG-based context-sensitive security analysis."""
    from pyflow.analysis.cpg.build import build_cpg, build_cpg_from_directory
    from pyflow.analysis.cpg.taint import CPGTaintEngine
    from pyflow.analysis.cpg.rules import load_rules, detect_frameworks

    findings: List = []

    for target in targets:
        path = Path(target)
        if not path.exists():
            print(f"Error: '{target}' not found", file=sys.stderr)
            continue

        if path.is_dir():
            cpg = build_cpg_from_directory(
                str(target), recursive=getattr(args, "recursive", False)
            )
        else:
            source = path.read_text(encoding="utf-8", errors="replace")
            cpg = build_cpg(source, filename=str(target))

        if len(cpg.functions) == 0:
            continue

        cpg.build()
        engine = CPGTaintEngine(cpg)

        for src in getattr(args, "sources", []) or []:
            engine.add_source(src)
        for snk in getattr(args, "sinks", []) or []:
            engine.add_sink(snk)
        for san in getattr(args, "sanitizers", []) or []:
            engine.add_sanitizer(san)

        frameworks: Optional[List[str]] = getattr(args, "framework", None) or None
        if frameworks is not None and len(frameworks) == 0:
            frameworks = None
        if frameworks is None and path.is_file():
            try:
                source = path.read_text(encoding="utf-8", errors="replace")
                frameworks = detect_frameworks(source)
            except OSError:
                pass
        registry_paths = getattr(args, "registry_path", []) or []
        load_rules(engine, frameworks=frameworks, custom_paths=registry_paths)

        result = engine.find_taint_paths()
        findings.extend(f.to_dict() for f in result)

    return findings


# ── Shared helpers ────────────────────────────────────────────────────────


def _parse_exclude_tuple(exclude: str) -> tuple:
    if not exclude:
        return ()
    return tuple(p.strip() for p in exclude.split(",") if p.strip())


def _discover_python_files(targets: Sequence[str], recursive: bool) -> list[Path]:
    files: list[Path] = []
    for t in targets:
        path = Path(t)
        if path.is_file():
            files.append(path)
        elif path.is_dir():
            pattern = "**/*.py" if recursive else "*.py"
            files.extend(sorted(path.glob(pattern)))
    return files


def _merge_taint_specs(
    args,
    source_files: Sequence[Path] = (),
) -> tuple[list[str], list[str], list[str]]:
    """Merge CLI-provided sources/sinks/sanitizers with --framework rule packs."""
    sources = list(getattr(args, "sources", []) or [])
    sinks = list(getattr(args, "sinks", []) or [])
    sanitizers = list(getattr(args, "sanitizers", []) or [])

    custom_paths = getattr(args, "registry_path", []) or []
    given_frameworks = getattr(args, "framework", None) or None
    if given_frameworks is not None and len(given_frameworks) == 0:
        given_frameworks = None

    # No framework or custom paths → user handles sources/sinks manually
    if given_frameworks is None and not custom_paths:
        return sources, sinks, sanitizers

    try:
        from pyflow.analysis.ifds.modeling.registry import load_registry

        registry = load_registry()
        if given_frameworks is not None:
            registry.activate(*given_frameworks, type="taint")
        else:
            if source_files:
                for path in source_files:
                    try:
                        registry.detect(
                            path.read_text(encoding="utf-8").splitlines()
                        )
                    except OSError:
                        continue
            if not registry.detected_frameworks:
                registry.activate("stdlib", type="taint")
        if custom_paths:
            registry.load_custom(*custom_paths)
        config = registry.as_config()
        sources.extend(config.source_names)
        sinks.extend(config.sink_names)
        sanitizers.extend(config.sanitizer_names)
    except ImportError:
        pass

    return (
        list(dict.fromkeys(sources)),
        list(dict.fromkeys(sinks)),
        list(dict.fromkeys(sanitizers)),
    )


def _parse_typestate_protocols(args) -> list[str]:
    raw = getattr(args, "typestate_protocol", None) or []
    protocols: list[str] = []
    for item in raw:
        for part in str(item).split(","):
            name = part.strip()
            if name:
                protocols.append(name)
    if not protocols:
        protocols.append("resource")
    return list(dict.fromkeys(protocols))

# ── Main entry point ──────────────────────────────────────────────────────


def run_security(args) -> int:
    """Dispatch to the selected security engine and output results."""
    # Set up logging
    level = (
        logging.DEBUG
        if getattr(args, "debug", False)
        else logging.INFO if getattr(args, "verbose", False) else logging.WARNING
    )
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")

    _apply_ifds_config(args)

    engine = args.engine
    targets = args.targets or ["."]
    recursive = getattr(args, "recursive", False)
    exclude = getattr(args, "exclude", "") or ""

    if engine == "ast-scanner":
        result = _run_ast_scanner(targets, args, exclude=exclude, recursive=recursive)
        _output_results(engine, result, args)
        issues = result.get_issue_list(b_constants.LOW, b_constants.LOW)
        return 1 if issues else 0

    elif engine == "cpa":
        result = _run_cpa(targets, args, exclude=exclude, recursive=recursive)
        _output_results(engine, result, args)
        issues = result.get_issue_list(b_constants.LOW, b_constants.LOW)
        return 1 if issues else 0

    elif engine == "ifds":
        if not args.function:
            print(
                "Error: --function is required for 'ifds' engine",
                file=sys.stderr,
            )
            return 2
        result = _run_ifds(targets, args)
        _output_results(engine, result, args)
        status = result.get("status", "complete")
        if status == "invalid":
            return 2
        if status in {"partial", "cancelled"}:
            return 3
        if status == "failed":
            return 4
        return 1 if result.get("findings") else 0

    elif engine == "cpg":
        result = _run_cpg(targets, args)
        _output_results(engine, result, args)
        return 1 if result else 0

    else:
        print(f"Unknown engine: {engine}", file=sys.stderr)
        return 1
