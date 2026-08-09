"""Static discovery of concolic exploration targets."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef


@dataclass(frozen=True)
class ParameterTarget:
    """One positional parameter in a statically discovered function."""

    name: str
    annotation: str | None
    required: bool
    position: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "annotation": self.annotation,
            "required": self.required,
            "position": self.position,
        }


@dataclass(frozen=True)
class FunctionTarget:
    """A source-level callable considered for concolic exploration."""

    path: Path
    module: str
    qualname: str
    entry: str
    line: int
    is_async: bool
    descriptor_kind: str
    parameters: tuple[ParameterTarget, ...]
    return_annotation: str | None
    eligibility_reasons: tuple[str, ...] = ()
    hazards: tuple[str, ...] = ()

    @property
    def eligible(self) -> bool:
        return not self.eligibility_reasons

    @property
    def identifier(self) -> str:
        return f"{self.module}:{self.qualname}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.identifier,
            "path": str(self.path),
            "module": self.module,
            "qualname": self.qualname,
            "entry": self.entry,
            "line": self.line,
            "is_async": self.is_async,
            "descriptor_kind": self.descriptor_kind,
            "parameters": [parameter.to_dict() for parameter in self.parameters],
            "return_annotation": self.return_annotation,
            "eligible": self.eligible,
            "eligibility_reasons": list(self.eligibility_reasons),
            "hazards": list(self.hazards),
        }


def discover_targets(
    root: str | Path,
    *,
    include_private: bool = False,
) -> tuple[FunctionTarget, ...]:
    """Discover functions without importing or executing project modules."""
    project_root = Path(root).resolve()
    files = (project_root,) if project_root.is_file() else tuple(_python_files(project_root))
    targets: list[FunctionTarget] = []
    for path in files:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError, UnicodeError):
            continue
        module = _module_name(project_root, path)
        module_hazards = _module_side_effects(tree)
        for statement in tree.body:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if include_private or not statement.name.startswith("_"):
                    targets.append(
                        _function_target(
                            path,
                            module,
                            statement,
                            statement.name,
                            "function",
                            module_hazards,
                        )
                    )
            elif isinstance(statement, ast.ClassDef):
                for member in statement.body:
                    if not isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        continue
                    if not include_private and member.name.startswith("_"):
                        continue
                    kind = _descriptor_kind(member)
                    target = _function_target(
                        path,
                        module,
                        member,
                        f"{statement.name}.{member.name}",
                        kind,
                        module_hazards,
                    )
                    reasons = list(target.eligibility_reasons)
                    if kind == "property":
                        reasons.append("property_entry_not_supported")
                    elif kind == "method" and not _class_is_default_constructible(statement):
                        reasons.append("receiver_construction_requires_arguments")
                    targets.append(
                        FunctionTarget(
                            path=target.path,
                            module=target.module,
                            qualname=target.qualname,
                            entry=target.qualname,
                            line=target.line,
                            is_async=target.is_async,
                            descriptor_kind=target.descriptor_kind,
                            parameters=target.parameters,
                            return_annotation=target.return_annotation,
                            eligibility_reasons=tuple(reasons),
                            hazards=target.hazards,
                        )
                    )
    return tuple(sorted(targets, key=lambda target: (str(target.path), target.line)))


def _python_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*.py")):
        if any(part.startswith(".") for part in path.relative_to(root).parts):
            continue
        if any(part in {"__pycache__", ".venv", "venv", "build", "dist"} for part in path.parts):
            continue
        yield path


def _module_name(root: Path, path: Path) -> str:
    relative = Path(path.name) if root.is_file() else path.relative_to(root)
    parts = list(relative.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts) or path.stem


def _function_target(
    path: Path,
    module: str,
    node: FunctionNode,
    qualname: str,
    descriptor_kind: str,
    module_hazards: tuple[str, ...],
) -> FunctionTarget:
    positional = tuple(node.args.posonlyargs) + tuple(node.args.args)
    required_count = len(positional) - len(node.args.defaults)
    implicit_receiver = descriptor_kind in {"method", "classmethod", "property"}
    exposed_positional = positional[1:] if implicit_receiver and positional else positional
    exposed_required_count = max(0, required_count - (1 if implicit_receiver else 0))
    parameters = tuple(
        ParameterTarget(
            parameter.arg,
            ast.unparse(parameter.annotation) if parameter.annotation else None,
            index < exposed_required_count,
            index,
        )
        for index, parameter in enumerate(exposed_positional)
    )
    reasons: list[str] = []
    if node.args.vararg is not None:
        reasons.append("variadic_positional_not_supported")
    if node.args.kwarg is not None:
        reasons.append("variadic_keyword_not_supported")
    if any(default is None for default in node.args.kw_defaults):
        reasons.append("required_keyword_only_not_supported")
    return FunctionTarget(
        path=path,
        module=module,
        qualname=qualname,
        entry=node.name,
        line=node.lineno,
        is_async=isinstance(node, ast.AsyncFunctionDef),
        descriptor_kind=descriptor_kind,
        parameters=parameters,
        return_annotation=(ast.unparse(node.returns) if node.returns is not None else None),
        eligibility_reasons=tuple(reasons),
        hazards=tuple(sorted(set(module_hazards + _function_hazards(node)))),
    )


def _descriptor_kind(node: FunctionNode) -> str:
    names = {decorator.id for decorator in node.decorator_list if isinstance(decorator, ast.Name)}
    if "staticmethod" in names:
        return "staticmethod"
    if "classmethod" in names:
        return "classmethod"
    if "property" in names:
        return "property"
    return "method"


def _class_is_default_constructible(node: ast.ClassDef) -> bool:
    initializer = next(
        (
            member
            for member in node.body
            if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef))
            and member.name == "__init__"
        ),
        None,
    )
    if initializer is None:
        return True
    positional = tuple(initializer.args.posonlyargs) + tuple(initializer.args.args)
    receiver_count = 1 if positional else 0
    required = len(positional) - len(initializer.args.defaults)
    if required > receiver_count:
        return False
    return not any(default is None for default in initializer.args.kw_defaults)


_HAZARDOUS_CALLS = {
    "open": "filesystem",
    "os.remove": "filesystem",
    "os.unlink": "filesystem",
    "os.rename": "filesystem",
    "os.system": "process",
    "subprocess.run": "process",
    "subprocess.call": "process",
    "subprocess.Popen": "process",
    "socket.socket": "network",
    "requests.get": "network",
    "requests.post": "network",
    "urllib.request.urlopen": "network",
}


def _call_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return None


def _hazards(nodes: Iterable[ast.AST]) -> tuple[str, ...]:
    found: set[str] = set()
    for root in nodes:
        for node in ast.walk(root):
            if isinstance(node, ast.Call):
                name = _call_name(node.func)
                if name in _HAZARDOUS_CALLS:
                    found.add(_HAZARDOUS_CALLS[name])
    return tuple(sorted(found))


def _function_hazards(node: FunctionNode) -> tuple[str, ...]:
    return _hazards(node.body)


def _module_side_effects(tree: ast.Module) -> tuple[str, ...]:
    executable = [
        statement
        for statement in tree.body
        if not isinstance(
            statement,
            (
                ast.Import,
                ast.ImportFrom,
                ast.FunctionDef,
                ast.AsyncFunctionDef,
                ast.ClassDef,
            ),
        )
    ]
    return tuple(f"module_{hazard}" for hazard in _hazards(executable))
