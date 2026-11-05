"""Standalone command-line access to PyFlow's type-information engine."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Iterable, Sequence

from pyflow.analysis.typeinfo import TypeInfoService
from pyflow.analysis.typeinfo.inference.models import ModuleInferenceResult
from pyflow.ir.mir.lowering import _default_root
from pyflow.language.modules.project_resolution import ProjectContext

_IGNORED_DIRECTORIES = {
    "__pycache__",
    ".git",
    ".hg",
    ".svn",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "venv",
    "node_modules",
    "site-packages",
    "dist-packages",
}


def add_typeinfo_parser(subparsers) -> argparse.ArgumentParser:
    """Register ``pyflow typeinfo``."""
    parser = subparsers.add_parser(
        "typeinfo",
        help="Query PyFlow's type-information engine without LSP/MCP",
        description=(
            "Analyze a Python file or project with TypeInfoService.  The default "
            "mode lists inferred and declared symbol types.  Use --symbol, "
            "--line/--column, or --diagnostics for focused queries."
        ),
    )
    parser.add_argument(
        "input_path",
        type=Path,
        help="Python file or project directory to analyze",
    )
    parser.add_argument(
        "--module",
        "-m",
        help="Import-qualified module name (inferred for a single file)",
    )
    query = parser.add_mutually_exclusive_group()
    query.add_argument(
        "--symbol",
        "-s",
        metavar="NAME",
        help="Type of a module-level symbol or Class.member",
    )
    query.add_argument(
        "--diagnostics",
        action="store_true",
        help="Print type-source, inference, and stub diagnostics",
    )
    query.add_argument(
        "--summary",
        action="store_true",
        help="Print only per-module analysis counts instead of symbol types",
    )
    parser.add_argument(
        "--line",
        type=int,
        help="1-based source line for an expression query",
    )
    parser.add_argument(
        "--column",
        type=int,
        help="0-based character column for an expression query",
    )
    parser.add_argument(
        "--max-modules",
        type=int,
        default=None,
        help="Limit directory-wide diagnostics/summary analysis",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )
    parser.set_defaults(func=run_typeinfo)
    return parser


def _iter_project_modules(context: ProjectContext, root: Path) -> list[tuple[str, Path]]:
    """Return import-qualified Python modules under *root* in stable order."""
    modules: list[tuple[str, Path]] = []
    for path in sorted(root.rglob("*.py")):
        relative = path.relative_to(root)
        if any(part in _IGNORED_DIRECTORIES or part.startswith(".") for part in relative.parts):
            continue
        module_name = context.module_name_from_path(path, allow_absolute_fallback=False)
        if module_name:
            modules.append((module_name, path))
    return modules


def _select_modules(
    args,
    context: ProjectContext,
    input_path: Path,
) -> list[tuple[str, Path | None]]:
    if input_path.is_file():
        module_name = args.module or context.module_name_from_path(input_path)
        if not module_name:
            raise ValueError(f"could not infer a module name for {input_path}")
        return [(module_name, input_path)]

    if args.module:
        resolution = context.find_module(args.module)
        if resolution is None:
            raise ValueError(f"module {args.module!r} was not found under {input_path}")
        return [(args.module, Path(resolution.path) if resolution.path else None)]

    modules = _iter_project_modules(context, input_path)
    if args.max_modules is not None:
        modules = modules[: max(0, args.max_modules)]
    if not modules:
        raise ValueError(f"no importable Python modules found under {input_path}")
    return modules


def _collect(service: TypeInfoService, module_name: str, path: Path | None) -> None:
    if path is not None and path.is_file():
        service.collect_module(
            module_name,
            source=path.read_text(encoding="utf-8"),
            path=str(path),
        )
    else:
        service.collect_module(module_name)


def _render_callable(info) -> str | None:
    """Render a ``FunctionTypeInfo`` as a user-facing callable type."""
    if info.is_property:
        return None if info.returns is None else str(info.returns)
    args: list[str] = []
    for index, (name, typ) in enumerate(info.params.items()):
        if index == 0 and info.method_kind in {"instance", "class"} and name in {"self", "cls"}:
            continue
        raw = info.raw_params.get(name)
        args.append(str(typ) if typ is not None else raw or "Any")
    returns = info.returns
    if returns is not None:
        rendered_return = str(returns)
    else:
        rendered_return = info.raw_returns or "Any"
    return f"Callable[[{', '.join(args)}], {rendered_return}]"


def _module_types(service: TypeInfoService, module_name: str) -> dict[str, dict[str, object]]:
    """Collect module symbols plus callable signatures without source positions."""
    types: dict[str, dict[str, object]] = {}
    for name, fact in sorted(service.members_of(module_name).items()):
        canonical = name if name.startswith(f"{module_name}.") else f"{module_name}.{name}"
        types[canonical] = {
            "type": None if fact.typ is None else str(fact.typ),
            "source": fact.source,
            "kind": fact.kind,
        }
    result = service.inference_result(module_name)
    if result is not None:
        for qualified in sorted(result.functions):
            relative = qualified.removeprefix(f"{module_name}.")
            info = service.signature_of(module_name, relative)
            if info is None or (qualified in types and types[qualified]["kind"] == "function"):
                continue
            rendered = _render_callable(info)
            if rendered is None:
                continue
            types[qualified] = {
                "type": rendered,
                "source": info.source,
                "kind": "method" if "." in relative else "function",
            }
    return types


def _module_report(service: TypeInfoService, module_name: str) -> dict[str, object]:
    result = service.inference_result(module_name)
    diagnostics = [item for item in service.diagnostics() if item.module_name == module_name]
    return {
        "module": module_name,
        "status": "unavailable" if result is None else result.status,
        "converged": False if result is None else result.converged,
        "iterations": 0 if result is None else result.iterations,
        "types": _module_types(service, module_name),
        "diagnostics": len(diagnostics),
    }


def _module_summary(service: TypeInfoService, module_name: str) -> dict[str, object]:
    result = service.inference_result(module_name)
    diagnostics = [item for item in service.diagnostics() if item.module_name == module_name]
    if result is None:
        return {
            "module": module_name,
            "status": "unavailable",
            "converged": False,
            "symbols": 0,
            "functions": 0,
            "expressions": 0,
            "diagnostics": len(diagnostics),
        }
    return {
        "module": module_name,
        "status": result.status,
        "converged": result.converged,
        "iterations": result.iterations,
        "symbols": len(result.symbols),
        "functions": len(result.functions),
        "expressions": len(result.expressions),
        "diagnostics": len(diagnostics),
    }


def _relative_symbol(module_name: str, symbol: str) -> str:
    prefix = f"{module_name}."
    return symbol.removeprefix(prefix)


def _symbol_result(
    service: TypeInfoService,
    module_name: str,
    symbol: str,
) -> dict[str, object]:
    relative = _relative_symbol(module_name, symbol)
    canonical = f"{module_name}.{relative}"
    fact = service.fact_of(module_name, relative)
    result = service.inference_result(module_name)
    status = result.status if result is not None else "unavailable"
    if fact is not None:
        return {
            "module": module_name,
            "symbol": canonical,
            "type": str(fact.typ),
            "source": fact.source,
            "kind": fact.kind,
            "raw_annotation": fact.raw_annotation,
            "status": status,
        }
    value = result.value_of(relative) if result is not None else None
    if value is None or not value.types:
        raise ValueError(f"symbol {canonical!r} was not found")
    typ = value.runtime_type()
    return {
        "module": module_name,
        "symbol": canonical,
        "type": None if typ is None else str(typ),
        "source": "inference",
        "kind": "symbol",
        "raw_annotation": None,
        "complete": value.is_complete,
        "status": status,
    }


def _expression_result(
    service: TypeInfoService,
    module_name: str,
    line: int,
    column: int,
) -> dict[str, object]:
    result = service.inference_result(module_name)
    if result is None:
        raise ValueError(f"type analysis for module {module_name!r} is unavailable")
    value = result.expression_value(line, column)
    typ = None if value is None else value.runtime_type()
    return {
        "module": module_name,
        "line": line,
        "column": column,
        "type": None if typ is None else str(typ),
        "complete": None if value is None else value.is_complete,
        "unknown": None if value is None else value.unknown,
        "status": result.status,
    }


def _diagnostic_result(
    service: TypeInfoService,
    modules: Sequence[str],
) -> list[dict[str, object]]:
    selected = set(modules)
    return [
        asdict(item)
        for item in service.diagnostics()
        if not selected or item.module_name in selected
    ]


def _print_human(payload: object, *, mode: str) -> None:
    if mode == "types":
        if isinstance(payload, list):
            for item in payload:
                print(
                    f"{item['module']}: {item['status']} "
                    f"(converged={item['converged']}, diagnostics={item['diagnostics']})"
                )
                types = item.get("types", {})
                if not types:
                    print("  <no type facts>")
                    continue
                for name, info in types.items():
                    print(f"  {name}: {info['type']}  [{info['source']}]")
        return
    if mode == "summary":
        if isinstance(payload, list):
            for item in payload:
                print(
                    f"{item['module']}: {item['status']} "
                    f"(converged={item['converged']}, symbols={item['symbols']}, "
                    f"functions={item['functions']}, expressions={item['expressions']}, "
                    f"diagnostics={item['diagnostics']})"
                )
        return
    if mode == "symbol":
        raw = f" raw={payload['raw_annotation']!r}" if payload.get("raw_annotation") else ""
        print(
            f"{payload['symbol']}: {payload['type']} ({payload['status']}, {payload['source']}{raw})"
        )
        return
    if mode == "expression":
        print(
            f"{payload['module']}:{payload['line']}:{payload['column']}: "
            f"{payload['type']} (complete={payload['complete']}, status={payload['status']})"
        )
        return
    if mode == "diagnostics":
        if not payload:
            print("No type diagnostics.")
            return
        for item in payload:
            location = item.get("path") or item.get("module_name") or "<unknown>"
            line = item.get("lineno")
            column = item.get("col_offset")
            if line is not None:
                location = f"{location}:{line}"
                if column is not None:
                    location = f"{location}:{column}"
            print(
                f"{location}: {item.get('severity', 'warning')} "
                f"[{item.get('code')}] {item.get('message')}"
            )


def run_typeinfo(args) -> int:
    """Execute ``pyflow typeinfo``."""
    input_path = Path(args.input_path)
    if not input_path.exists():
        print(f"Error: Path '{input_path}' not found", file=sys.stderr)
        return 1
    if (args.line is None) != (args.column is None):
        print("Error: --line and --column must be provided together", file=sys.stderr)
        return 2
    if args.line is not None and (args.symbol or args.diagnostics or args.summary):
        print(
            "Error: expression queries cannot be combined with "
            "--symbol, --diagnostics, or --summary",
            file=sys.stderr,
        )
        return 2
    if args.max_modules is not None and args.max_modules < 0:
        print("Error: --max-modules must be non-negative", file=sys.stderr)
        return 2

    root = _default_root(input_path)
    context = ProjectContext(root)
    try:
        modules = _select_modules(args, context, input_path)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if (args.symbol or args.line is not None) and len(modules) != 1:
        print(
            "Error: --symbol and expression queries require a single --module",
            file=sys.stderr,
        )
        return 2

    service = TypeInfoService(context)
    try:
        for module_name, path in modules:
            _collect(service, module_name, path)
        module_names = [name for name, _ in modules]
        if args.symbol:
            payload = _symbol_result(service, module_names[0], args.symbol)
            mode = "symbol"
        elif args.line is not None:
            payload = _expression_result(service, module_names[0], args.line, args.column)
            mode = "expression"
        elif args.diagnostics:
            payload = _diagnostic_result(service, module_names)
            mode = "diagnostics"
        elif args.summary:
            payload = [_module_summary(service, name) for name in module_names]
            mode = "summary"
        else:
            payload = [_module_report(service, name) for name in module_names]
            mode = "types"
    except (ValueError, OSError, SyntaxError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if args.json or args.pretty:
        print(json.dumps(payload, indent=2 if args.pretty else None, default=str))
    else:
        _print_human(payload, mode=mode)
    return 0
