"""Evaluate runtime type facts against a local TypeEvalPy checkout.

The default prediction universe is GT-conditioned. ``--all-facts`` additionally
exports source-derived definitions, bindings, parameters and literal elements;
its precision is relative to the (potentially incomplete) benchmark annotations.
No benchmark code is executed. Generated reports and result files are local
experiment artifacts and should be kept outside the documentation tree.
"""

from __future__ import annotations

import argparse
import ast
from collections import Counter, defaultdict
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

from pyflow.analysis.typeinfo import TypeInfoService
from pyflow.analysis.typeinfo.core.typesystem import (
    CallableType,
    Instance,
    TupleType,
    TypeType,
    UnionType,
)
from pyflow.analysis.typeinfo.inference.domain import AbstractTypeValue
from pyflow.analysis.typeinfo.inference.models import SourceSpan
from pyflow.language.modules.project_resolution import ProjectContext

IDENTITY = ("file", "line_number", "col_offset", "function", "parameter", "variable")


def fact_key(fact):
    return tuple(fact.get(key) for key in IDENTITY)


def kind(fact):
    return "variable" if "variable" in fact else "parameter" if "parameter" in fact else "function"


def load_comparator(root):
    """Load the requested checkout, never an ambient result_analyzer package.

    TypeEvalPy's exact comparison sorts the expected alternatives but leaves
    predictions in set iteration order. Sort both sides to remove PYTHONHASHSEED
    dependent scores. Keep the upstream spelling/erasure and partial semantics.
    """
    path = root / "src/result_analyzer/analysis_utils.py"
    spec = importlib.util.spec_from_file_location("typeevalpy_comparator", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    original = module.format_type
    module.format_type = lambda *args, **kwargs: [sorted(row) for row in original(*args, **kwargs)]
    return module, hashlib.sha256(path.read_bytes()).hexdigest()


def render_types(typ, module, *, normalize=True):
    if typ is None or str(typ) in {"Any", "Unknown", "Never"}:
        return []
    if isinstance(typ, UnionType):
        return sorted(
            {name for item in typ.items for name in render_types(item, module, normalize=normalize)}
        )
    name = str(typ)
    if normalize:
        if name.startswith(module + "."):
            name = name[len(module) + 1 :]
        if name in {"None", "NoneType"}:
            name = "nonetype"
        elif isinstance(typ, CallableType):
            name = "callable"
        elif isinstance(typ, TupleType):
            name = "tuple"
        elif isinstance(typ, TypeType):
            name = "type"
        elif isinstance(typ, Instance):
            name = typ.type.full_name
            if name.startswith(module + "."):
                name = name[len(module) + 1 :]
            if name.startswith("builtins."):
                name = name[len("builtins.") :]
            if name in {"collections.abc.Generator", "types.GeneratorType"}:
                name = "generator"
    return [name]


def span(node):
    return SourceSpan(node.lineno, node.col_offset, node.end_lineno, node.end_col_offset)


def project(value, selector):
    """Translate an element fact using stored values/types, without new inference."""
    if value is None:
        return None
    # Literal shapes, when available, retain callable identities and nesting.
    if isinstance(selector, ast.Constant):
        key = selector.value
        items = getattr(value, "sequence_items", None)
        if items is not None and isinstance(key, int) and -len(items) <= key < len(items):
            return items[key]
        entries = getattr(value, "mapping_items", None)
        if entries is not None:
            return dict(entries).get(key)
        if isinstance(key, str) and value.dict_shapes:
            types = [dict(shape).get(key) for shape in value.dict_shapes]
            if all(typ is not None for typ in types):
                return AbstractTypeValue(frozenset(types), unknown=value.unknown)
    types = []
    for typ in value.types:
        parts = typ.items if isinstance(typ, UnionType) else (typ,)
        for part in parts:
            if isinstance(part, TupleType):
                if (
                    isinstance(selector, ast.Constant)
                    and isinstance(selector.value, int)
                    and not part.unknown_size
                ):
                    if -len(part.args) <= selector.value < len(part.args):
                        types.append(part.args[selector.value])
                else:
                    types.extend(part.args)
            elif isinstance(part, Instance):
                if part.type.raw_type is dict and len(part.args) == 2:
                    types.append(part.args[1])
                elif part.type.raw_type in {list, tuple} and part.args:
                    types.append(part.args[0])
    return AbstractTypeValue(frozenset(types), unknown=value.unknown) if types else None


class Adapter:
    def __init__(self, source, filename="main.py"):
        self.source = source
        self.filename = filename
        self.tree = ast.parse(source)
        self.expressions = defaultdict(list)
        self.names = {}
        self.functions = {}
        self.parameters = {}
        self.candidates = []
        self._index(self.tree, [])

    def _index(self, node, parents, function_scope=None):
        if isinstance(node, ast.expr):
            self.expressions[(node.lineno, node.col_offset + 1)].append(node)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            name = "lambda" if isinstance(node, ast.Lambda) else ".".join([*parents, node.name])
            key = (
                ".".join([*parents, f"<lambda@{node.lineno}:{node.col_offset}>"])
                if isinstance(node, ast.Lambda)
                else name
            )
            if not isinstance(node, ast.Lambda):
                # Python AST columns are UTF-8 byte offsets; GT is one-based.
                prefix = self.source.splitlines()[node.lineno - 1].encode("utf-8")
                col = (
                    prefix.index(
                        node.name.encode("utf-8"),
                        node.col_offset + (10 if isinstance(node, ast.AsyncFunctionDef) else 4),
                    )
                    + 1
                )
                fact = dict(
                    file=self.filename, line_number=node.lineno, col_offset=col, function=name
                )
                self.candidates.append(fact)
                # GT sometimes omits enclosing function scopes from names.
                # Exact positions disambiguate nested definitions; accept
                # qualified suffixes, never a name from another source span.
                parts = name.split(".")
                for index in range(len(parts)):
                    self.functions[(node.lineno, col, ".".join(parts[index:]))] = key
            args = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
            args += [arg for arg in (node.args.vararg, node.args.kwarg) if arg]
            for arg in args:
                fact = dict(
                    file=self.filename,
                    line_number=arg.lineno,
                    col_offset=arg.col_offset + 1,
                    function=name,
                    parameter=arg.arg,
                )
                self.candidates.append(fact)
                self.parameters[(arg.lineno, arg.col_offset + 1, arg.arg)] = key
            function_scope = name
            parents = [*parents, "<lambda>" if isinstance(node, ast.Lambda) else node.name]
        elif isinstance(node, ast.ClassDef):
            parents = [*parents, node.name]
        if isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)) and isinstance(
            node.ctx, ast.Store
        ):
            fact = dict(
                file=self.filename,
                line_number=node.lineno,
                col_offset=node.col_offset + 1,
                variable=ast.unparse(node),
            )
            if function_scope is not None:
                fact["function"] = function_scope
            elif parents and isinstance(node, ast.Name):
                fact["variable"] = ".".join([*parents, node.id])
            self.candidates.append(fact)
            self.names[span(node)] = fact["variable"]
        for child in ast.iter_child_nodes(node):
            self._index(child, parents, function_scope)

    def variable_value(self, fact, result):
        text = fact["variable"]
        candidates = self.expressions[(fact["line_number"], fact["col_offset"])]
        # Exact AST span only: never fall back to an unrelated covering call.
        for node in candidates:
            if text in {ast.unparse(node), self.names.get(span(node))}:
                value = result.expressions.get(span(node))
                return value, "pyflow_missing" if value is not None else "adapter_missing"
        try:
            requested = ast.parse(text, mode="eval").body
        except SyntaxError:
            return None, "adapter_missing"
        selectors = []
        while isinstance(requested, ast.Subscript):
            selectors.append(requested.slice)
            requested = requested.value
        for node in candidates:
            if ast.unparse(requested) in {ast.unparse(node), self.names.get(span(node))}:
                value = result.expressions.get(span(node))
                if value is None:
                    return None, "adapter_missing"
                if not value.types:
                    return None, "pyflow_missing"
                for selector in reversed(selectors):
                    value = project(value, selector)
                    if value is None:
                        return None, "adapter_missing"
                return value, "pyflow_missing"
        return None, "adapter_missing"

    def predict(self, fact, result):
        generator = False
        if kind(fact) == "variable":
            value, reason = self.variable_value(fact, result)
        else:
            if kind(fact) == "parameter":
                key = self.parameters.get(
                    (fact["line_number"], fact["col_offset"], fact["parameter"])
                )
            else:
                key = self.functions.get(
                    (fact["line_number"], fact["col_offset"], fact["function"])
                )
            if key is None:
                return None, dict(
                    category="adapter_missing", detail="definition position/name not found"
                )
            summary = result.functions.get(f"{result.module_name}.{key}")
            if summary is None:
                return None, dict(category="pyflow_missing", detail="no function summary")
            value = (
                summary.parameters.get(fact["parameter"])
                if kind(fact) == "parameter"
                else summary.return_value
            )
            generator = kind(fact) == "function" and summary.is_generator
            reason = "pyflow_missing"
        typ = None if value is None else value.runtime_type()
        rendered = ["generator"] if generator else render_types(typ, result.module_name)
        evidence = dict(
            category=reason,
            raw_type=str(typ),
            raw_types=render_types(typ, result.module_name, normalize=False),
            unknown=value is None or value.unknown,
        )
        if not rendered:
            return None, evidence
        return {**fact, "type": rendered}, evidence


def metrics(counts):
    counts = {key: counts.get(key, 0) for key in ("exact", "partial", "missing", "wrong")}
    total = sum(counts.values())
    predicted = total - counts["missing"]
    return dict(
        **counts,
        total=total,
        predicted=predicted,
        exact_recall_pct=round(100 * counts["exact"] / total, 2) if total else 0,
        partial_recall_pct=(
            round(100 * (counts["exact"] + counts["partial"]) / total, 2) if total else 0
        ),
        exact_precision_pct=round(100 * counts["exact"] / predicted, 2) if predicted else 0,
        partial_precision_pct=(
            round(100 * (counts["exact"] + counts["partial"]) / predicted, 2) if predicted else 0
        ),
    )


def evaluate(args):
    root = args.benchmark_dir.expanduser().resolve()
    comparator, digest = load_comparator(args.typeevalpy_root.expanduser().resolve())
    if not root.is_dir():
        raise ValueError(f"Not a benchmark directory: {root}")
    gtfiles = sorted(root.rglob("*_gt.json"))
    if args.limit is not None:
        gtfiles = gtfiles[: args.limit]
    totals, statuses, reasons = Counter(), Counter(), Counter()
    by_kind, by_feature = defaultdict(Counter), defaultdict(Counter)
    errors, per_file = [], {}
    unrestricted = Counter()
    for gtfile in gtfiles:
        expected = json.loads(gtfile.read_text())
        rel = gtfile.relative_to(root)
        feature = rel.parts[1] if len(rel.parts) > 2 else "other"
        src = gtfile.with_name(gtfile.name.removesuffix("_gt.json") + ".py")
        diagnostics, predictions = [], []
        try:
            source = src.read_text(encoding="utf-8")
            context = ProjectContext(src.parent)
            module = context.module_name_from_path(src)
            service = TypeInfoService(context)
            service.collect_module(module, source=source, path=str(src))
            result = service.inference_result(module)
            adapter = Adapter(source, src.name)
            statuses[result.status] += 1
        except Exception as error:
            errors.append(dict(file=str(rel), error=f"{type(error).__name__}: {error}"))
            statuses["crash"] += 1
            result = None
        counts = Counter()
        seen = set()
        for fact in expected:
            if fact_key(fact) in seen:
                raise ValueError(f"Duplicate GT identity in {gtfile}: {fact}")
            seen.add(fact_key(fact))
            prediction, evidence = (
                adapter.predict(fact, result)
                if result is not None and fact["file"] == src.name
                else (
                    None,
                    dict(
                        category="adapter_missing" if result is not None else "pyflow_missing",
                        detail=(
                            "GT filename differs from source"
                            if result is not None
                            else "analysis crashed"
                        ),
                    ),
                )
            )
            outcome = "missing"
            if prediction is not None:
                predictions.append(prediction)
                if comparator.check_match(fact, prediction):
                    outcome = "exact"
                elif comparator.check_match(fact, prediction, partial_match=True):
                    outcome = "partial"
                else:
                    outcome = "wrong"
                raw = {**fact, "type": evidence["raw_types"]}
                evidence["category"] = (
                    "normalisation_mismatch"
                    if outcome == "exact" and not comparator.check_match(fact, raw)
                    else "type_mismatch" if outcome != "exact" else "matched"
                )
            counts[outcome] += 1
            by_kind[kind(fact)][outcome] += 1
            by_feature[feature][outcome] += 1
            reasons[evidence["category"]] += 1
            diagnostics.append(
                dict(expected=fact, prediction=prediction, outcome=outcome, **evidence)
            )
        if args.all_facts and result is not None:
            independent = {}
            for fact in adapter.candidates:
                prediction, _ = adapter.predict(fact, result)
                if prediction is not None:
                    independent[fact_key(fact)] = prediction
            for fact in adapter.candidates:
                if kind(fact) != "variable":
                    continue
                value, _ = adapter.variable_value(fact, result)
                queue = [(fact["variable"], value, 0)]
                while queue:
                    name, value, depth = queue.pop()
                    if depth >= 4 or value is None:
                        continue
                    items = getattr(value, "sequence_items", None)
                    if items is None:
                        typ = value.public_type()
                        if isinstance(typ, TupleType) and not typ.unknown_size:
                            items = tuple(AbstractTypeValue.from_type(t) for t in typ.args)
                    if items is not None:
                        children = [(f"{name}[{i}]", item) for i, item in enumerate(items[:64])]
                    elif value.dict_shapes:
                        keys = sorted({key for shape in value.dict_shapes for key, _ in shape})
                        children = [
                            (f"{name}[{key!r}]", project(value, ast.Constant(key)))
                            for key in keys[:64]
                        ]
                    else:
                        children = []
                    for child_name, child in children:
                        types = (
                            render_types(child.runtime_type(), result.module_name) if child else []
                        )
                        if types:
                            prediction = {**fact, "variable": child_name, "type": types}
                            independent[fact_key(prediction)] = prediction
                        queue.append((child_name, child, depth + 1))
            gtmap = {fact_key(fact): fact for fact in expected}
            unrestricted["predicted"] += len(independent)
            for key, prediction in independent.items():
                gt = gtmap.get(key)
                unrestricted[
                    (
                        "unannotated"
                        if gt is None
                        else (
                            "exact"
                            if comparator.check_match(gt, prediction)
                            else (
                                "partial"
                                if comparator.check_match(gt, prediction, partial_match=True)
                                else "wrong"
                            )
                        )
                    )
                ] += 1
        else:
            independent = None
        if args.results_dir:
            destination = args.results_dir / rel.parent
            destination.mkdir(parents=True, exist_ok=True)
            stem = src.stem
            (destination / f"{stem}_result.json").write_text(
                json.dumps(predictions, indent=2) + "\n"
            )
            (destination / f"{stem}_diagnostics.json").write_text(
                json.dumps(diagnostics, indent=2) + "\n"
            )
            if independent is not None:
                (destination / f"{stem}_all_result.json").write_text(
                    json.dumps(list(independent.values()), indent=2) + "\n"
                )
        totals.update(counts)
        per_file[str(rel)] = metrics(counts)
    summary = dict(
        benchmark=str(root),
        files=len(gtfiles),
        statuses=dict(statuses),
        facts=sum(totals.values()),
        **metrics(totals),
        by_kind={k: metrics(v) for k, v in sorted(by_kind.items())},
        by_feature={k: metrics(v) for k, v in sorted(by_feature.items())},
        categories=dict(reasons),
        errors=errors,
        per_file=per_file,
        methodology=dict(
            precision="GT-conditioned nominal runtime type accuracy",
            positions="one-based TypeEvalPy columns -> exact UTF-8 AST spans",
            comparator_sha256=digest,
            deterministic_exact_sort=True,
        ),
    )
    if args.all_facts:
        denominator = unrestricted["predicted"]
        summary["all_facts"] = dict(
            unrestricted,
            exact_precision_pct=(
                round(100 * unrestricted["exact"] / denominator, 2) if denominator else 0
            ),
            partial_precision_pct=(
                round(100 * (unrestricted["exact"] + unrestricted["partial"]) / denominator, 2)
                if denominator
                else 0
            ),
            caveat="Source-derived binding universe; unannotated predictions count against precision. Not official leaderboard precision.",
        )
    if args.summary_out:
        args.summary_out.parent.mkdir(parents=True, exist_ok=True)
        args.summary_out.write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({k: v for k, v in summary.items() if k != "per_file"}, indent=2))
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--typeevalpy-root", type=Path, required=True)
    parser.add_argument("--benchmark-dir", type=Path, required=True)
    parser.add_argument("--summary-out", type=Path)
    parser.add_argument("--results-dir", type=Path)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--all-facts", action="store_true")
    args = parser.parse_args()
    summary = evaluate(args)
    return bool(summary["errors"])


if __name__ == "__main__":
    sys.exit(main())
