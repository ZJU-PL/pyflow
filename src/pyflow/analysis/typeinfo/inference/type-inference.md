# Standalone static type inference

PyFlow's standalone type-inference engine is a deterministic abstract
interpreter for Python source. It is independent of CPA, IPA, the store graph,
and runtime execution. Its results can therefore be used by lightweight query
clients and as input to later whole-program analyses.

## Public API

```python
from pyflow.analysis.typeinfo import StaticTypeInferenceEngine

result = StaticTypeInferenceEngine().infer_source(
    "package.module",
    """
def identity(value):
    return value

answer = identity(1)
""",
)

assert str(result.type_of("answer")) == "int"
assert result.converged
```

`TypeInfoService` runs the engine by default and exposes its complete result:

```python
service.collect_module("package.module")
result = service.inference_result("package.module")
```

Static inference can be disabled with
`TypeInfoService(..., enable_static_inference=False)`.

For an import closure, including cyclic imports, use the project orchestrator:

```python
from pyflow.analysis.typeinfo import ProjectTypeInferenceEngine
from pyflow.language.modules.project_resolution import ProjectContext

project = ProjectTypeInferenceEngine(ProjectContext("/path/to/project"))
result = project.infer_project(["package.entrypoint"])
assert result.converged
```

## Argument-sensitive inference

Calls to an unannotated function are analyzed in normalized argument contexts.
This preserves relationships that a single merged function summary loses:

```python
def wrap(value):
    return [value]

integers = wrap(1)       # list[int]
strings = wrap("value") # list[str]
```

Each `FunctionSummary` retains a conservative aggregate result and exposes its
context-specific results through `specializations`. A specialization records
the normalized parameter values, return value, yield value, and whether the
context was widened.

Callable identities participate in context keys independently of their
evolving display signatures. Consequently, higher-order calls remain separate
without producing a new context on every solver iteration. Recursive and
mutually recursive contexts use provisional bottom results and converge through
the module fixed point.

Context growth is bounded by `max_specializations_per_function`. Calls beyond
the limit are joined into one widened overflow context rather than discarded or
silently converted to `Any`. The engine emits a
`specialization-budget-exceeded` diagnostic when widening occurs.

## Semantics and guarantees

The engine distinguishes three concepts that are often accidentally merged:

- lattice bottom: no evidence has reached a value yet;
- unknown: unmodelled alternatives may exist;
- `Any`: an explicit gradual-typing opt-out.

The analysis is monotone over call-site evidence, class attributes, control-flow
joins, recursive call summaries, and widened contexts. Loops and recursive call
graphs are solved to a fixed point. Finite unions are widened when the configured
union bound is exceeded, guaranteeing termination.

Inference currently models:

- annotations, forward references, unions, generic aliases, and `TypeVar`;
- literals and built-in container element/key/value types;
- assignments, unpacking, augmented assignments, and named expressions;
- branch joins, loops, assertions, optional narrowing, and `isinstance`;
- structural pattern matching;
- user-defined functions, recursion, closures, higher-order calls,
  keyword-only arguments, `*args`, and `**kwargs`;
- argument-sensitive function and method contexts;
- generic substitution at calls;
- classes, constructors, instance attributes, inheritance, and methods;
- common built-in functions and container/string methods;
- comprehensions, generators, coroutines, `await`, and `yield from`;
- expression-level, symbol-level, and function-summary queries;
- annotation consistency, convergence, and precision-budget diagnostics.

External modules may supply types through the `external_symbol_resolver`
callback. Argument-sensitive library behavior can be added without modifying
the solver:

```python
from pyflow.analysis.typeinfo import MappingCallModelProvider

models = MappingCallModelProvider()
models.register("package.echo", lambda args, kwargs: args[0])
engine = StaticTypeInferenceEngine(call_model_providers=(models,))
```

Model failures are isolated and reported as diagnostics rather than aborting
the fixed point.

## Precision controls

```python
from pyflow.analysis.typeinfo import InferenceOptions

options = InferenceOptions(
    max_iterations=24,
    max_loop_iterations=12,
    max_union_size=16,
    max_specializations_per_function=32,
    strict_annotations=False,
)
```

Reaching an iteration limit produces a diagnostic and marks the result as not
converged. It never silently presents a partial fixed point as complete.

## Bounded-soundness testing

Concrete traces provide a lower-bound oracle: every runtime type observed in a
test should be admitted by the inferred may-type.

```python
from pyflow.analysis.typeinfo import ObservedType, validate_observed_types

violations = validate_observed_types(
    result,
    [ObservedType(int, symbol="answer")],
)
assert not violations
```

An unknown result admits an observation and is therefore imprecise rather than
unsound. A closed inferred type that excludes an observation is reported as a
`SoundnessViolation`.

## Current limits and roadmap

No finite static engine precisely models unrestricted Python reflection,
monkey-patching, `eval`, dynamically generated classes, arbitrary descriptors,
or native extension behavior. Such operations retain `unknown` unless a trusted
model supplies a conservative result.

The next major precision layer is an inference-owned allocation-site heap. It
will make container and instance mutation alias-aware without consuming CPA
results. Later layers include Python data-model protocol dispatch, modern
overload and generic constraint solving, CFG-based flow refinement, and
incremental project-summary invalidation.
