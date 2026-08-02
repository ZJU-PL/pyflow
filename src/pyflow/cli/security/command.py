"""
Unified security analysis CLI — ``pyflow security``.

Dispatches to one of four engine backends:

- ``ast-scanner`` — fast AST pattern matching (Bandit-style), no analysis pipeline
- ``ast-dataflow`` — interprocedural taint dataflow over the Python AST
- ``ifds`` — IFDS solver over CFG supergraphs (interprocedural, flow-sensitive)
- ``cpg`` — CPG-based context-sensitive security analysis with heap-aware alias tracking
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Sequence

from pyflow.analysis.entrypoints import EntryPointDefaults
from pyflow.checker.pattern.core.manager import SecurityManager
from pyflow.checker.pattern.core.config import SecurityConfig
from pyflow.checker.pattern.core import constants as b_constants
from pyflow.checker.ast_dataflow import ASTDataflowManager, BugFinderConfig
from pyflow.frontend.entry_discovery import resolve_entry_file
from .reporting import (
    _ifds_result_to_dict,
    _nullness_result_to_dict,
    _output_results,
    _typestate_result_to_dict,
)

if TYPE_CHECKING:
    from pyflow.analysis.ifds.modeling.calls import CallModelRegistry
    from pyflow.analysis.taint import TaintRule

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
    "ifds_trace_mode": "ifds_trace_mode",
    "ifds_context_depth": "ifds_context_depth",
    "unknown_call_policy": "ifds_unknown_call_policy",
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
        print(
            f"Error: invalid JSON in config file {config_path}: {exc}", file=sys.stderr
        )
        raise SystemExit(2)

    unknown = set(config_data) - {
        "solver_options",
        "frameworks",
        "sources",
        "sinks",
        "sanitizers",
        "analysis",
        "function",
        "ifds_trace_mode",
        "ifds_context_depth",
        "unknown_call_policy",
        "registry_path",
        "typestate_protocol",
    }
    if unknown:
        print(
            f"Warning: unknown config keys: {', '.join(sorted(unknown))}",
            file=sys.stderr,
        )

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


def _run_ast_dataflow(
    targets: List[str],
    args,
    *,
    exclude: str = "",
    recursive: bool = False,
) -> ASTDataflowManager:
    """Run the AST-based interprocedural taint detector."""
    config = BugFinderConfig(
        verbose=getattr(args, "verbose", False),
        recursive=recursive,
        exclude=_parse_exclude_tuple(exclude),
        sources=tuple(getattr(args, "sources", ()) or ()),
        sinks=tuple(getattr(args, "sinks", ()) or ()),
        sanitizers=tuple(getattr(args, "sanitizers", ()) or ()),
        frameworks=getattr(args, "framework", None),
        registry_paths=tuple(getattr(args, "registry_path", ()) or ()),
    )
    manager = ASTDataflowManager(
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

    solver_options = _ifds_solver_options(args)

    files = _discover_python_files(targets, getattr(args, "recursive", False))
    try:
        entry_file = _resolve_ifds_entry_file(targets, getattr(args, "entry", None))
    except ValueError as error:
        print(f"Error: {error}", file=sys.stderr)
        return {
            "entry": "<unknown>",
            "findings": [],
            "diagnostics": [str(error)],
            "status": "invalid",
            "termination_reason": str(error),
        }

    if entry_file not in files:
        files.append(entry_file)
    entry_label = _entry_label(entry_file, targets)

    if getattr(args, "analysis", "taint") == "typestate":
        try:
            _session, typestate_result = run_typestate_analysis(
                files,
                entry_file=entry_file,
                enabled_protocols=_parse_typestate_protocols(args),
                registry_frameworks=getattr(args, "framework", ()) or (),
                registry_paths=getattr(args, "registry_path", []) or (),
                collection_mutator_names=getattr(args, "collection_mutators", None),
                collection_accessor_names=getattr(args, "collection_accessors", None),
                dependency_strategy=getattr(args, "dependency_strategy", "auto"),
                verbose=getattr(args, "verbose", False),
                solver_options=solver_options,
            )
        except Exception as e:
            print(f"IFDS analysis failed: {e}", file=sys.stderr)
            return {
                "entry": entry_label,
                "analysis": "typestate",
                "findings": [],
                "diagnostics": [str(e)],
                "status": "failed",
                "termination_reason": str(e),
            }
        result = _typestate_result_to_dict(entry_label, typestate_result)
        return _apply_session_diagnostics(result, _session)

    if getattr(args, "analysis", "taint") == "nullness":
        try:
            _session, nullness_result = run_nullness_analysis(
                files,
                entry_file=entry_file,
                registry_frameworks=getattr(args, "framework", ()) or (),
                registry_paths=getattr(args, "registry_path", []) or (),
                dependency_strategy=getattr(args, "dependency_strategy", "auto"),
                verbose=getattr(args, "verbose", False),
                solver_options=solver_options,
            )
        except Exception as e:
            print(f"IFDS analysis failed: {e}", file=sys.stderr)
            return {
                "entry": entry_label,
                "analysis": "nullness",
                "findings": [],
                "diagnostics": [str(e)],
                "status": "failed",
                "termination_reason": str(e),
            }
        result = _nullness_result_to_dict(entry_label, nullness_result)
        return _apply_session_diagnostics(result, _session)

    try:
        call_models, taint_rules, entry_point_defaults = _build_taint_configuration(
            args, source_files=files
        )
    except (OSError, ValueError) as error:
        print(f"Invalid taint policy configuration: {error}", file=sys.stderr)
        return {
            "entry": entry_label,
            "findings": [],
            "diagnostics": [str(error)],
            "status": "invalid",
            "termination_reason": str(error),
        }

    if not call_models.as_mapping() or not taint_rules:
        print(
            "No typed taint models or rules specified. Use --sources/--sinks "
            "--framework,"
            " or --registry-path.",
            file=sys.stderr,
        )
        return {
            "entry": entry_label,
            "findings": [],
            "diagnostics": [],
            "status": "invalid",
            "termination_reason": "No typed taint models or rules configured",
        }

    try:
        _session, taint_result, _shadow_matches = run_taint_analysis(
            files,
            entry_file=entry_file,
            call_models=call_models,
            rules=taint_rules,
            entry_point_defaults=entry_point_defaults,
            collection_mutator_names=getattr(args, "collection_mutators", None),
            collection_accessor_names=getattr(args, "collection_accessors", None),
            unknown_call_policy=getattr(
                args, "ifds_unknown_call_policy", "preserve"
            ),
            conservative_unresolved_call_side_effects=getattr(
                args, "conservative_unresolved_calls", False
            ),
            dependency_strategy=getattr(args, "dependency_strategy", "auto"),
            verbose=getattr(args, "verbose", False),
            solver_options=solver_options,
        )
    except Exception as e:
        print(f"IFDS analysis failed: {e}", file=sys.stderr)
        return {
            "entry": entry_label,
            "findings": [],
            "diagnostics": [str(e)],
            "status": "failed",
            "termination_reason": str(e),
        }

    result = _ifds_result_to_dict(entry_label, taint_result)
    return _apply_session_diagnostics(result, _session)


def _diagnostics_to_dicts(diagnostics) -> list[Any]:
    from dataclasses import asdict, is_dataclass

    return [
        (asdict(diagnostic) if is_dataclass(diagnostic) else str(diagnostic))
        for diagnostic in diagnostics
    ]


def _apply_session_diagnostics(result: Dict[str, Any], session) -> Dict[str, Any]:
    diagnostics = (
        *tuple(result.get("diagnostics", ())),
        *tuple(getattr(session, "diagnostics", ())),
    )
    result["diagnostics"] = _diagnostics_to_dicts(diagnostics)
    if result.get("status") == "complete" and any(
        getattr(diagnostic, "affects_completeness", False) for diagnostic in diagnostics
    ):
        result["status"] = "partial"
        result["termination_reason"] = (
            "Analysis preparation recovered from one or more incomplete stages"
        )
    return result


def _run_cpg(targets: List[str], args) -> Dict[str, Any]:
    """Run the CPG-based context-sensitive security analysis."""
    from pyflow.ir.cpg.build import build_cpg, build_cpg_from_directory
    from pyflow.ir.cpg.taint import CPGTaintEngine
    from pyflow.ir.cpg.rules import load_rules, detect_frameworks

    findings: List[Dict[str, Any]] = []
    diagnostics: List[Dict[str, Any]] = []
    statistics: Dict[str, int] = {}
    status = "complete"
    analyzed_targets = 0

    for target in targets:
        path = Path(target)
        if not path.exists():
            print(f"Error: '{target}' not found", file=sys.stderr)
            diagnostics.append(
                {
                    "code": "cpg-target-not-found",
                    "message": f"Target not found: {target}",
                    "function": None,
                    "affects_completeness": True,
                }
            )
            status = "partial"
            continue

        if path.is_dir():
            cpg = build_cpg_from_directory(
                str(target), recursive=getattr(args, "recursive", False)
            )
        else:
            source = path.read_text(encoding="utf-8", errors="replace")
            cpg = build_cpg(source, filename=str(target))

        if len(cpg.functions) == 0:
            diagnostics.append(
                {
                    "code": "cpg-no-functions",
                    "message": f"No analyzable functions found in {target}",
                    "function": None,
                    "affects_completeness": True,
                }
            )
            status = "partial"
            continue

        cpg.build()
        analyzed_targets += 1
        engine = CPGTaintEngine(
            cpg,
            max_call_depth=getattr(args, "cpg_context_depth", 3),
            max_states=getattr(args, "cpg_max_states", None),
            max_seconds=getattr(args, "cpg_max_seconds", None),
        )

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

        result = engine.analyze()
        findings.extend(f.to_dict() for f in result.findings)
        diagnostics.extend(
            {
                "code": diagnostic.code,
                "message": diagnostic.message,
                "function": diagnostic.function,
                "affects_completeness": diagnostic.affects_completeness,
                "level": diagnostic.level,
                "filename": diagnostic.filename,
                "line": diagnostic.line,
                "operation": diagnostic.operation,
            }
            for diagnostic in result.diagnostics
        )
        for key, value in result.statistics.items():
            statistics[key] = statistics.get(key, 0) + value
        if result.status != "complete" and status == "complete":
            status = result.status

    if analyzed_targets == 0:
        status = "failed"

    return {
        "engine": "cpg",
        "status": status,
        "findings": findings,
        "diagnostics": diagnostics,
        "statistics": statistics,
    }


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


def _resolve_ifds_entry_file(
    targets: Sequence[str | Path], entry: str | Path | None
) -> Path:
    paths = [Path(target) for target in targets]
    if len(paths) != 1:
        raise ValueError(
            "IFDS analysis requires exactly one file or project directory."
        )

    target = paths[0]
    if target.is_file():
        if entry is not None:
            raise ValueError("--entry is only valid when the target is a directory.")
        if target.suffix != ".py":
            raise ValueError(f"Target '{target}' is not a Python file.")
        return target.resolve()

    if not target.is_dir():
        raise ValueError(f"Target '{target}' does not exist.")

    resolved = resolve_entry_file(target, entry)
    if resolved is None:
        raise ValueError(
            f"No entry point detected in '{target}'. Use --entry to specify one "
            "relative to the project root."
        )
    return resolved


def _entry_label(entry_file: Path, targets: Sequence[str | Path]) -> str:
    if len(targets) == 1:
        target = Path(targets[0])
        if target.is_file():
            return str(target)
        if target.is_dir():
            try:
                return str(entry_file.relative_to(target.resolve()))
            except ValueError:
                pass
    return str(entry_file)


def _build_taint_configuration(
    args,
    source_files: Sequence[Path] = (),
) -> tuple[CallModelRegistry, tuple[TaintRule, ...], EntryPointDefaults]:
    """Build typed CLI models and policies from names and v2 rule packs."""
    from pyflow.analysis.ifds.modeling.calls import CallModel, CallModelRegistry
    from pyflow.analysis.taint import TaintRule

    sources = list(getattr(args, "sources", []) or [])
    sinks = list(getattr(args, "sinks", []) or [])
    sanitizers = list(getattr(args, "sanitizers", []) or [])
    models = [
        *(
            CallModel(name=name, source_kinds=frozenset({"untrusted"}))
            for name in sources
        ),
        *(CallModel(name=name, sink_kinds=frozenset({"dangerous"})) for name in sinks),
        *(
            CallModel(name=name, sanitizer_kinds=frozenset({"*"}))
            for name in sanitizers
        ),
    ]
    rules: list[TaintRule] = []
    if sources and sinks:
        rules.append(
            TaintRule(
                rule_id="PYFLOW-CLI-DANGEROUS",
                title="Untrusted data reaches configured sink",
                source_kinds=frozenset({"untrusted"}),
                sink_kinds=frozenset({"dangerous"}),
                severity="high",
            )
        )

    custom_paths = getattr(args, "registry_path", []) or []
    raw_frameworks = getattr(args, "framework", None)
    auto_detect = raw_frameworks == []
    given_frameworks = tuple(raw_frameworks) if raw_frameworks else None

    # No framework or custom paths → user handles models manually.
    if given_frameworks is None and not auto_detect and not custom_paths and models:
        return CallModelRegistry(models), tuple(rules), EntryPointDefaults()

    try:
        from pyflow.analysis.ifds.modeling.registry import load_registry

        registry = load_registry()
        if given_frameworks is not None:
            registry.activate("stdlib", *given_frameworks, type="taint")
        elif auto_detect:
            registry.activate("stdlib", type="taint")
            if source_files:
                for path in source_files:
                    try:
                        registry.detect(path.read_text(encoding="utf-8").splitlines())
                    except OSError:
                        continue
        else:
            registry.activate("stdlib", type="taint")
        if custom_paths:
            registry.load_custom(*custom_paths)
        config = registry.as_config()
        entry_point_defaults = registry.as_taint_policy().entry_point_defaults
        models.extend(config.call_models.as_mapping().values())
        rules.extend(config.rules)
    except ImportError:
        entry_point_defaults = EntryPointDefaults()

    return CallModelRegistry(models), tuple(rules), entry_point_defaults


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
        return _security_exit_code(args, status="complete", has_findings=bool(issues))

    elif engine == "ast-dataflow":
        result = _run_ast_dataflow(targets, args, exclude=exclude, recursive=recursive)
        _output_results(engine, result, args)
        issues = result.get_issue_list(b_constants.LOW, b_constants.LOW)
        status = getattr(getattr(result, "analysis_result", None), "status", "complete")
        return _security_exit_code(args, status=status, has_findings=bool(issues))

    elif engine == "ifds":
        result = _run_ifds(targets, args)
        _output_results(engine, result, args)
        status = result.get("status", "complete")
        return _security_exit_code(
            args, status=status, has_findings=bool(result.get("findings"))
        )

    elif engine == "cpg":
        result = _run_cpg(targets, args)
        _output_results(engine, result, args)
        status = result.get("status", "complete")
        return _security_exit_code(
            args, status=status, has_findings=bool(result.get("findings"))
        )

    else:
        print(f"Unknown engine: {engine}", file=sys.stderr)
        return 1


def _security_exit_code(args, *, status: str, has_findings: bool) -> int:
    """Keep process health separate from analysis contents when requested."""
    if getattr(args, "exit_code_policy", "findings") == "report":
        return 0
    if status == "invalid":
        return 2
    if status in {"partial", "cancelled"}:
        return 3
    if status == "failed":
        return 4
    return 1 if has_findings else 0
