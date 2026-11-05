# Typeinfo differential audit against mypy

This document records a differential audit of PyFlow's type-inference subsystem
against mypy, run over the real-world corpus at `~/Work/tools/data/py/top100`.

## Harness

`tools/typeinfo_mypy_diff.py` is the reproducible harness.  It

1. discovers importable top-level packages in a corpus project;
2. samples modules with the most annotated surface (`--max-modules`);
3. analyses the sample with `ProjectTypeInferenceEngine` (crash, status,
   diagnostics, elapsed time and expression types);
4. copies the project into a shadow tree (`cp -Rc`, APFS clone), wraps each
   selected expression in `reveal_type(...)` on its own line and runs the
   installed mypy from `.venv` with
   `--check-untyped-defs --show-error-codes --no-error-summary --no-pretty
   --show-column-numbers`;
5. normalises both type strings (module prefixes, `Optional`/`Union`, sorted
   unions, `Literal[...]?`, named-tuple `fallback=`, callable parameter names)
   and classifies every expression.

Only expressions where mypy reports a concrete, `Any`-free type are compared.
Each record is written as one JSONL object with the module, position, source
text, PyFlow type, mypy type, verdict and PyFlow completeness.

### Commands

```bash
# one project, JSONL detail + JSON summary
.venv/bin/python tools/typeinfo_mypy_diff.py \
    --project Textualize--rich --max-modules 8 \
    --out /tmp/rich.jsonl --summary-out /tmp/rich.json

# the sampled target list from the audit brief
.venv/bin/python tools/typeinfo_mypy_diff.py \
    --project Textualize--rich --project pallets--flask \
    --project django--django --project scikit-learn--scikit-learn \
    --project yt-dlp--yt-dlp --project fastapi--fastapi \
    --project scrapy--scrapy --project apache--superset \
    --project huggingface--transformers --project vllm-project--vllm \
    --project home-assistant--core --project ansible--ansible \
    --project keras-team--keras --project ultralytics--ultralytics \
    --max-modules 4 --budget 90 \
    --out /tmp/corpus.jsonl --summary-out /tmp/corpus.json
```

`--module-filter REGEX` narrows the sample and `--per-package N` caps modules
per package for libraries that ship many top-level packages.

## Findings and fixes

Gaps are ordered by the taxonomy in the audit brief.  Every fixed gap has a
regression test in `tests/analysis/typeinfo/test_typeinfo_mypy_diff_regressions.py`.

| ID | Category | Minimised repro | mypy | PyFlow (before) | Root cause | Fix | Test |
| --- | --- | --- | --- | --- | --- | --- | --- |
| G1 | C2 unsound | `import pathlib; c = pathlib.Path.cwd` | `def () -> Path` | `Callable[[Any], Path]` (kept `cls`) | Dotted names rooted at an imported module were resolved by `expressions.py` → `_external_type` and returned the raw stub function; the member-kind information was lost | `TypeInfoService` exposes `method_kind`; `typeshed_resolver.resolve_typeshed_method_kind`; binding applied in `MemberInference._external_member_type` / `_attribute_value` | `test_stdlib_classmethod_is_bound_on_class_and_instance` |
| G2 | C2 unsound | `dict.fromkeys` / `datetime.datetime.now` | bound classmethod | `cls` leaked as `Any`/`_T` | same as G1 plus `FunctionSummary.method_kind` was not propagated for project modules | `FunctionSummary.method_kind`, `StaticTypeInferenceEngine.external_method_kind` hook | `test_stdlib_classmethod_is_bound_on_class_and_instance` |
| G3 | C5 unknown | `xs: list[int] = []; a = xs.append` | `def (int) -> None` | `Callable[..., Any]` | `TypeInfoService.collect_module` skipped the `builtins` stub; `TypeSystem.get_members` only used runtime `inspect`, which cannot read builtin methods | Collect `builtins.pyi`; fill signatureless members from typeshed (`_typeshed_class_members`); derive class type parameters from generic bases (`class list(MutableSequence[_T])`) | `test_builtin_container_methods_keep_typeshed_signatures` |
| G4 | C2 unsound | `from typing import Dict; b: Dict[str,int] = {}; c = b["x"]` | `int` | `_VT` | `_subscript_value` returned `__getitem__`'s return type without substituting the receiver's type arguments | Substitute `typ.type.type_parameters` with `typ.args` before projecting the return type | `test_typing_alias_subscript_uses_value_type` |
| G5 | C2 unsound | `import math; a = math.ceil(1.5)` | `int` | `_T` | Overload selection accepted the `_SupportsCeil[_T]` overload but never solved `_T` from the protocol member `float.__ceil__() -> int`; unsolved variables leaked into results | Structural protocol type-variable solving (`constraints.py` analogue); unsolved variables erased to their value restriction/`Any`; stub protocols marked `is_protocol` and checked structurally | `test_protocol_overload_binds_type_variable_from_member` |

### Supporting changes

* `TypeSystem.get_members` now consults the vendored typeshed snapshot for
  stdlib classes.  Runtime introspection yields `Callable[..., Any]` for most
  C-level methods (`float.__ceil__`, `list.append`, `dict.get`); the stub
  declares the real signature.  Only signature-less members are replaced, so
  project-declared members always win.
* Class type parameters are now derived from generic base classes, not only
  from explicit `Generic[...]`/`Protocol[...]` parameters (mypy
  `semanal_classprop` behaviour).  This is what makes `list[int]` substitute
  `_T` in typeshed member signatures.

## Corpus metrics (after fixes)

`modules` = analysed/requested, `expr` = comparable expressions (mypy concrete),
`match` = identical after normalisation, `C5*` = PyFlow unknown/missing where
mypy is concrete.  No module crashed on the sample (56 modules analysed, 0 crashes).

| Project | modules | expr | match | mismatch | C5-unknown | C5-missing | PyFlow s |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Textualize--rich | 4/4 | 887 | 743 | 100 | 17 | 26 | 16.16 |
| ansible--ansible | 4/4 | 508 | 300 | 81 | 30 | 91 | 31.87 |
| apache--superset | 4/4 | 993 | 725 | 54 | 0 | 213 | 79.24 |
| django--django | 4/4 | 609 | 481 | 19 | 4 | 105 | 40.25 |
| fastapi--fastapi | 4/4 | 307 | 200 | 29 | 22 | 54 | 12.24 |
| home-assistant--core | 4/4 | 0 | 0 | 0 | 0 | 0 | 33.38 (mypy timeout) |
| huggingface--transformers | 4/4 | 1074 | 919 | 66 | 11 | 77 | 639.02 |
| keras-team--keras | 4/4 | 1453 | 1339 | 71 | 0 | 43 | 72.53 |
| pallets--flask | 4/4 | 245 | 163 | 36 | 14 | 32 | 4.3 |
| scikit-learn--scikit-learn | 4/4 | 259 | 222 | 7 | 0 | 30 | 67.04 |
| scrapy--scrapy | 4/4 | 282 | 219 | 53 | 3 | 7 | 10.08 |
| ultralytics--ultralytics | 4/4 | 166 | 155 | 10 | 0 | 1 | 46.4 |
| vllm-project--vllm | 4/4 | 2057 | 1423 | 211 | 2 | 421 | 206.23 |
| yt-dlp--yt-dlp | 4/4 | 192 | 167 | 20 | 4 | 1 | 4.03 |
| **total** | **56** | **9032** | **7056** | **757** | **107** | **1101** | |

`home-assistant--core` produced no comparable rows because mypy exceeded the
120 s per-module budget on its sampled modules; PyFlow itself analysed them.
`ansible--ansible` uses a `lib/` source layout, which `ProjectContext` does not
add to its import path by itself; the harness passes the same extra roots to
both tools.

The remaining mismatches are dominated by four benign classes:

* mypy prints `Callable[[X], Any]` for methods of generic builtins inside
  untyped function bodies while PyFlow reports the (correct) `-> None`;
* mypy's inferred literal widening (`Literal[0]?`) versus PyFlow's base type;
* named-tuple `tuple[..., fallback=X]` versus the named-tuple instance
  (normalised by the harness, still noisy in raw output);
* `classmethod`/`staticmethod` decorator return annotations (`decorator:
  Callable[..., Any]`) that PyFlow models as the decorated callable.

## Remaining known limitations

* `pyflow query --get-type` at the *first* column of a compound expression
  (`sys.platform == "win32"`) reports the left-most sub-expression
  (`sys.platform` → `str`).  This is the documented token-hover heuristic in
  `ModuleInferenceResult.expression_value`; the harness queries exact spans.
  Changing it would alter LSP hover semantics, so it was left as-is.
* An annotation naming an uninstalled third-party class
  (`MapAdapter | None` in Flask) still marks the module `partial`.  mypy
  silently uses `Any`; PyFlow deliberately keeps the diagnostic
  (`unresolved-annotation`, `affects_completeness=True`).  A future change
  should distinguish "missing dependency" from "analysis failed".
* `NewType` is collapsed to its base type (`TaskID` → `int`).
* Unbound access to a method of a class from *another project module*
  (`Builder.build`) reports the receiver-bound signature rather than the
  unbound one; calls still type-check, but the displayed callable is narrower.
* Union return kinds (`Generator` vs declared `Iterable`) prefer the inferred
  generator type; mypy reports the declared return type of the callee.
