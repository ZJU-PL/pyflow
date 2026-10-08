"""First-party import contracts for the framework's stable layer boundaries."""

import ast
from importlib.util import resolve_name
from pathlib import Path
import subprocess
import sys

SOURCE = Path(__file__).resolve().parents[2] / "src" / "pyflow"
CONTRACTS = {
    "model": {
        "application",
        "api",
        "cli",
        "lsp",
        "checker",
        "frontend",
        "analysis",
        "optimization",
        "ir",
    },
    "ir": {"application", "api", "cli", "lsp", "checker", "frontend"},
    "analysis": {"application", "api", "cli", "lsp", "checker"},
    "optimization": {"application", "api", "cli", "lsp", "checker"},
    "frontend": {"api", "cli", "lsp", "checker"},
    "application": {"api", "cli", "lsp", "checker"},
    "api": {"cli", "lsp"},
}


def _imports(path):
    parts = ("pyflow", *path.relative_to(SOURCE).with_suffix("").parts)
    package = ".".join(parts[:-1])
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield node.lineno, alias.name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if node.level:
                module = resolve_name("." * node.level + module, package)
            yield node.lineno, module
            for alias in node.names:
                yield node.lineno, f"{module}.{alias.name}"
        elif (
            isinstance(node, ast.Call)
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            function = node.func
            name = (
                function.attr
                if isinstance(function, ast.Attribute)
                else function.id if isinstance(function, ast.Name) else ""
            )
            if name in {"import_module", "__import__"}:
                yield node.lineno, node.args[0].value


def test_imports_respect_layer_boundaries():
    violations = set()
    for path in SOURCE.rglob("*.py"):
        relative = path.relative_to(SOURCE)
        # Vendored PythonStan is maintained upstream, outside these contracts.
        if "_pythonstan" in relative.parts:
            continue
        forbidden = CONTRACTS.get(relative.parts[0], set())
        for line, dependency in _imports(path):
            parts = dependency.split(".")
            if len(parts) > 1 and parts[0] == "pyflow":
                if parts[1] in forbidden:
                    violations.add(f"{relative}:{line} imports {dependency}")
    assert not violations, "\n".join(sorted(violations))


def test_lightweight_imports_do_not_load_analysis_engines():
    subprocess.run(
        [
            sys.executable,
            "-c",
            """
import sys
import pyflow
from pyflow.model.entrypoints import InterfaceDeclaration
from pyflow.application.program import Program
program = Program()
assert program.session._pass_manager is None
assert not any(name.startswith(('pyflow.analysis', 'pyflow.optimization',
                                'pyflow.api', 'pyflow.application.pipeline'))
               for name in sys.modules)
""",
        ],
        check=True,
        capture_output=True,
        text=True,
    )


def test_shared_checker_utilities_do_not_import_engines_or_transports():
    violations = set()
    for package in ("common", "formatters"):
        allowed = {"common"} if package == "common" else {"common", "formatters"}
        for path in (SOURCE / "checker" / package).rglob("*.py"):
            for line, dependency in _imports(path):
                parts = dependency.split(".")
                transport = dependency.startswith(("pyflow.cli", "pyflow.lsp"))
                engine = (
                    len(parts) > 2
                    and parts[:2] == ["pyflow", "checker"]
                    and parts[2] not in allowed
                )
                if transport or engine:
                    relative = path.relative_to(SOURCE)
                    violations.add(f"{relative}:{line} imports {dependency}")
    assert not violations, "\n".join(sorted(violations))


def test_shared_checker_imports_do_not_load_specific_engines():
    subprocess.run(
        [
            sys.executable,
            "-c",
            """
import sys
import pyflow.checker.common.taint.refinement
import pyflow.checker.formatters.security
import pyflow.checker.formatters.cpg
import pyflow.checker.formatters.capability
assert not any(name.startswith((
    'pyflow.checker.ast_rules', 'pyflow.checker.ast_dataflow',
    'pyflow.checker.ifds', 'pyflow.checker.cpg',
    'pyflow.checker.capability', 'pyflow.checker.supply_chain',
    'pyflow.cli', 'pyflow.lsp',
)) for name in sys.modules)
""",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
