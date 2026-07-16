# Migration Notes: PythonStAn -> PyFlow Pointer Analysis

This document records every **intentional divergence** between the vendored
PythonStAn code under `_pythonstan/` and the upstream source at
`~/Downloads/PythonStAn-main/pythonstan`. Pure import-path rewrites
(`pythonstan.X` -> `pyflow.analysis.alias.kcfa._pythonstan.X`) are **not** listed
here — they are mechanical and expected from vendoring. Only changes that affect
behavior, types, or structure are documented.

Each entry classifies the change as one of:

- **[BUGFIX]** — fixes a defect in the upstream code
- **[ENHANCEMENT]** — implements functionality the upstream left as a TODO or stub
- **[REFACTOR]** — moves code without changing behavior (may be neutral)
- **[BEHAVIOR]** — changes analysis results in a deliberate way
- **[COMPAT]** — hardens code for portability or dependency reduction
- **[NEW]** — adds code with no upstream counterpart

---

## 1. `analysis/alias/kcfa/kcfa/state.py`  [ENHANCEMENT] [BEHAVIOR]

### MRO-aware base-class field resolution (former TODO)

Upstream had a TODO where inherited attribute lookup should have been:

```python
# TODO here can use the class hierarchy manager to get the base class
# and the index of the base class.
```

The migration replaces this with full MRO-aware resolution:
- Resolves base-class `ClassObject`s from their points-to sets
- Registers them in `self.class_hierarchy` and computes the MRO
- Walks the MRO chain looking for the field on each base class's internal scope
- Adds a `PointerFlowEdge` with `PointerFlowKind.INHERIT` when found
- Falls back to the first base's field access if no non-empty match is found

A new helper `_base_class_variable` safely returns `None` for unresolvable bases
instead of crashing on `base.id` access.

### Generator/Coroutine object unwrapping

```python
if isinstance(func_obj, (GeneratorObject, CoroutineObject)):
    func_obj = func_obj.func_obj
```

When resolving a call target, generator and coroutine wrapper objects are
unwrapped to their underlying function object before scope lookup. Upstream did
not handle these object kinds.

### Module-scope global variable fallback

When a global variable is not found in the current scope, the migration adds a
fallback that searches the function object's module scope:

```python
module_scope = getattr(func_obj.container_scope, "module", None) or scope.module
if module_scope is not None:
    module_global = self._get_variable_direct(
        module_scope, module_scope.context, var.name, VariableKind.GLOBAL,
    )
    if module_global is not None:
        return module_global
```

This fixes cases where a function references a module-level global that was not
visible through the original lookup chain.

### `class_hierarchy` field

A new `self.class_hierarchy = None` attribute is initialized on `State`. The
solver sets it before analysis runs (see `solver.py` below).

**Covered by tests:** `test_inherited_method_return_flows_to_call_target`,
`test_multiple_inheritance_uses_mro_first_method`.

---

## 2. `analysis/alias/kcfa/kcfa/solver.py`  [BUGFIX] [REFACTOR] [BEHAVIOR]

### Class hierarchy plumbing

`Solver.__init__` now accepts and stores `class_hierarchy`, and propagates it to
`self.state.class_hierarchy`. This is the wiring that enables the MRO-aware
field resolution in `state.py`.

### Builtin initialization extracted from `analysis.py`  [REFACTOR]

The inline builtin-function initialization block (previously ~28 lines in
`analysis.py`) is moved to `Solver.initialize_builtins()`. The `BUILTIN_FUNCTIONS`
list is now a class attribute on `Solver`. `analysis.py` calls
`self.solver.initialize_builtins(module_scope, context)`.

### `FieldKind` enum comparison bug fix  [BUGFIX]

```python
# upstream (broken — compares enum member to a string):
if isinstance(base_obj, ModuleObject) and c.field and c.field.kind.name == 'ATTR':

# migration (correct — compares enum to enum):
if isinstance(base_obj, ModuleObject) and c.field and c.field.kind == FieldKind.ATTRIBUTE:
```

The upstream code compared `FieldKind.ATTRIBUTE.name` (the string `'ATTRIBUTE'`)
against the string `'ATTR'`, which would never match. The migration compares the
enum member directly.

### Module-scope variable kind: `LOCAL` -> `GLOBAL`  [BEHAVIOR]

```python
# upstream:
scope=module_scope.stmt, context=module_scope.context, kind=VariableKind.LOCAL

# migration:
kind=VariableKind.GLOBAL
```

When creating a variable for a module attribute access (`module.attr`), the
migration uses `GLOBAL` instead of `LOCAL`. This affects how the variable is
looked up and stored in the environment.

### Closure variable kind resolution  [BEHAVIOR]

```python
# upstream:
var = self.variable_factory.make_variable(var_name, VariableKind.CELL)
cell_vars[var_name] = self.state.get_variable(scope.parent, context, var)

# migration:
closure_scope = scope.parent or scope  # fallback if no parent
var_kind = self._resolve_outer_var_kind(closure_scope, var_name)
var = self.variable_factory.make_variable(var_name, var_kind)
cell_vars[var_name] = self.state.get_variable(closure_scope, context, var)
```

Instead of hardcoding `VariableKind.CELL` for all closure-captured variables,
the migration resolves the actual kind (LOCAL vs GLOBAL vs CELL) via
`_resolve_outer_var_kind`. It also guards against `scope.parent` being `None`.

### Per-class used variables  [BEHAVIOR]

```python
# upstream:
for inner_var in self.ir_translator.used_variables:

# migration:
for inner_var in self.ir_translator.get_class_used_variables(ir_cls):
```

The upstream code used a single shared `used_variables` set across all classes.
The migration tracks per-class used variables (see `ir_translator.py` below) so
that variables from one class body do not leak into another.

---

## 3. `analysis/alias/kcfa/kcfa/analysis.py`  [REFACTOR]

### Builtin initialization extraction

The ~28-line inline builtin initialization block is removed and replaced with:

```python
self.solver.initialize_builtins(module_scope, context)
logger.debug(f"Initialized {len(self.solver.BUILTIN_FUNCTIONS)} builtin functions")
```

No behavior change — the same builtins are initialized in the same way, just
from `Solver` instead of `AnalysisDriver`.

---

## 4. `analysis/alias/kcfa/kcfa/ir_translator.py`  [ENHANCEMENT] [BEHAVIOR]

### Per-class used variable tracking  [BEHAVIOR]

New instance state and methods:

```python
self._class_used_variables: Dict[IRClass, List['Variable']] = {}

def get_class_used_variables(self, cls_stmt: IRClass) -> List['Variable']:
    return self._class_used_variables.get(cls_stmt, [])
```

During class body translation, `used_variables` is saved and restored around
each class, and the class's variables are stored in `_class_used_variables`.
This prevents variable leakage between class bodies (consumed by `solver.py`).

### `World.setup()` guard  [COMPAT]

```python
from pyflow.analysis.alias.kcfa._pythonstan.world import World
if not hasattr(World, "scope_manager"):
    World.setup()
```

Guards against `World` not being initialized when the translator runs outside
the normal pipeline (e.g., in tests or direct invocation).

### `CopyConstraint` for `ast.Name` RHS in store targets  [ENHANCEMENT]

```python
elif isinstance(rval, ast.Name):
    source_var = self._make_variable(rval.id)
    constraints.append(CopyConstraint(source=source_var, target=target_var))
```

When the right-hand side of a store target is a simple `ast.Name`, the migration
generates a `CopyConstraint` to propagate points-to information. Upstream did not
handle this case, losing flow for name-to-name assignments in certain store
contexts.

### `kwargs` type: `dict` -> `tuple` of `(Optional[str], Variable)`  [BEHAVIOR]

```python
# upstream:
keyword_vars = {kw_name: self._make_variable(kw_val)
                for kw_name, kw_val in stmt.get_keywords()
                if kw_name is not None}      # drops **kwargs entries!
kwargs=frozenset(keyword_vars.items())

# migration:
keyword_vars = tuple(
    (kw_name, self._make_variable(kw_val))
    for kw_name, kw_val in stmt.get_keywords()
)                                           # preserves **kwargs with kw_name=None
kwargs=frozenset(keyword_vars)
```

The upstream code **dropped** keyword arguments where `kw_name is None` (i.e.,
`**kwargs` unpacking). The migration preserves them with `kw_name=None`, paired
with the `Optional[str]` type change in `constraints.py`.

### Class-scope local variable tracking

```python
if isinstance(self._current_scope, IRClass):
    self._local_vars.setdefault(self._current_scope, set()).add(stmt.name)
```

Local variables defined inside a class body are now tracked in `_local_vars`
under the `IRClass` scope. Applied at both function-def and class-def sites.

**Covered by tests:** `test_dict_constructor_keyword_value_flows_to_subscript_load`,
`test_dict_constructor_unpack_flows_to_subscript_load`.

---

## 5. `analysis/alias/kcfa/kcfa/constraints.py`  [BEHAVIOR]

### `kwargs` type signature

```python
# upstream:
kwargs: FrozenSet[Tuple[str, 'Variable']]

# migration:
kwargs: FrozenSet[Tuple[Optional[str], 'Variable']]
```

Paired with the `ir_translator.py` change to support `**kwargs` unpacking.

---

## 6. `analysis/alias/kcfa/kcfa/builtin_api_handler.py`  [ENHANCEMENT]

### `object()` builtin handler  [NEW]

`"object"` is added to `TYPE_BUILTINS` and a new `_handle_object` method is
registered:

```python
def _handle_object(self, scope, context, call):
    constraints = []
    if call.target:
        alloc_site = AllocSite(stmt=call.stmt, kind=AllocKind.OBJECT)
        constraints.append(AllocConstraint(target=call.target, alloc_site=alloc_site))
    return constraints
```

Upstream had no handler for `object()`, so `x = object()` would not produce an
allocation site.

### `dict(**kwargs)` and `dict(iterable)` handling (former TODO)  [ENHANCEMENT]

Upstream had:

```python
# TODO: Handle dict(**kwargs) and dict(iterable) properly
```

The migration implements both:
- **Iterable argument**: loads `elem` field from the iterable and stores it into
  the new dict's `elem` field.
- **`**kwargs` unpacking** (`kw_name is None`): loads `elem` from the kwargs dict
  and stores into the new dict's `elem` field.
- **Named keywords**: stores each value under both `key(kw_name)` and `elem()`.

**Covered by tests:** `test_dict_constructor_keyword_value_flows_to_subscript_load`,
`test_dict_constructor_unpack_flows_to_subscript_load`.

---

## 7. `analysis/alias/kcfa/kcfa/class_hierarchy.py`  [BUGFIX]

### `update_bases` method rewritten

```python
# upstream:
# Add with new bases
self.add_class(class_obj, base_objects)

# migration:
# add_class() intentionally preserves existing entries, so update the base
# map directly here.
self._bases[class_obj] = base_objects
for base_obj in base_objects:
    if base_obj not in self._subclasses:
        self._subclasses[base_obj] = []
    if class_obj not in self._subclasses[base_obj]:
        self._subclasses[base_obj].append(class_obj)
self._invalidate_mro_cache(class_obj)
```

Upstream called `add_class()` to update bases, but `add_class()` is a no-op if
the class already exists (it preserves existing entries). This meant calling
`update_bases` on an already-registered class would **not** update its bases.
The migration directly updates `_bases` and `_subclasses` and invalidates the
MRO cache.

---

## 8. `analysis/alias/kcfa/kcfa/heap_model.py`  [COMPAT] [BEHAVIOR]

### Dead import removed  [COMPAT]

```python
# upstream:
from yaml import NodeEvent    # unused, and creates a hard yaml dependency

# migration: removed entirely
```

### Heap allocation context: `scope.module` -> `scope`  [BEHAVIOR]

```python
# upstream:
return (context, scope.module)

# migration:
return (context, scope)
```

The allocation-site context key uses the scope directly instead of its module.
This changes the granularity of heap context — allocation sites are now
distinguished by their immediate scope rather than collapsing to module level.

---

## 9. `analysis/alias/kcfa/kcfa/object.py`  [ENHANCEMENT]

### `name` property on function objects

```python
@property
def name(self) -> Optional[str]:
    return getattr(self.stmt, "name", None)
```

Added to support the bridge layer's `points_to(var_name)` query, which matches
variables by `name`. Without this, the bridge could not resolve function-object
names.

---

## 10. `analysis/alias/kcfa/kcfa/module_analysis.py`  [REFACTOR]

### `Scope` import relocated

```python
# upstream:
from .variable import Variable, Scope, VariableKind

# migration:
from .variable import Variable, VariableKind
from .context import Scope
```

`Scope` was moved from `variable.py` to `context.py` in the upstream kcfa
refactor. The migration picks up the new location. The stale TODO comment
("kcfa has been refactored, this module need to be rewritten") is also removed.

---

## 11. `analysis/alias/kcfa/kcfa/module_summary.py`  [COMPAT]

Stale TODO comment ("kcfa has been refactored, this module need to be
rewritten") and trailing blank line removed. No code changes.

---

## 12. `analysis/alias/kcfa/kcfa/processor/processor.py`  [COMPAT]

### Abstract method bodies: `...` -> `return False`

```python
# upstream (invalid for runtime abstract methods):
def can_process(self, stmt) -> ...: ...

# migration:
def can_process(self, stmt) -> bool: return False
```

All six abstract methods on `Processor` are changed from `...` (Ellipsis) bodies
to `return False`. This makes the abstract base safe to instantiate if a
subclass forgets to override a method — it returns `False` instead of raising
`TypeError` on the `...` return.

---

## 13. `world/pipeline.py`  [BEHAVIOR]

### Closure analysis reordering

```python
# upstream: closure analysis runs once, after the per-module loop:
self.analysis_manager.analysis("closure", mod)

# migration: closure analysis runs inside the per-module loop,
#            alongside cfg, for each module:
self.analysis_manager.analysis("closure", mod)    # added inside loop
```

Closure analysis is moved from after the loop to inside the loop, running on
each module as it is processed. This ensures closure information is available
before the pointer analysis runs on each module, rather than only after all
modules are loaded.

### `print` statement removed  [COMPAT]

```python
# upstream:
print("Time count: ", self.config.time_count)

# migration: removed
```

---

## 14. `world/analysis_manager.py`  [COMPAT]

### `AIAnalysisDriver` dropped

```python
# upstream:
from pythonstan.analysis.pointer.ai.analysis import AIAnalysisDriver
...
analyzer = AIAnalysisDriver(config)

# migration:
# import removed
...
raise NotImplementedError("PythonStAn does not provide an AIAnalysisDriver")
```

The upstream `AIAnalysisDriver` import path (`analysis.pointer.ai.analysis`)
does not exist in the source tree (there is an `analysis/ai/` directory, but no
`analysis/alias/kcfa/ai/`). The migration replaces the broken import with an
explicit `NotImplementedError`.

---

## 15. `world/config.py`  [COMPAT]

### Optional `yaml` dependency

```python
# upstream:
import yaml
...
info = yaml.safe_load(f)

# migration:
import json as _json
try:
    import yaml as _yaml
except ImportError:
    _yaml = None
...
if filename.endswith('.json'):
    info = _json.load(f)
elif _yaml is not None:
    info = _yaml.safe_load(f)
else:
    info = _json.load(f)
```

The hard `yaml` dependency is made optional. JSON config files are now
supported. If `yaml` is not installed, non-`.json` files fall back to JSON
parsing.

---

## 16. `world/namespace.py`  [COMPAT]

### Stub path fix for vendored layout

```python
# upstream:
Path(__file__).resolve().parents[2]

# migration:
Path(__file__).resolve().parents[1]
```

The stubs directory is at a different depth in the vendored tree. This adjusts
the path resolution so `NamespaceManager` finds `stubs/stdlib/` correctly.

---

## 17. `analysis/alias/kcfa/kcfa/debug_monitor.py`  [NEW]

No upstream counterpart. The upstream `debug_monitor.py` was never committed to
the PythonStAn repository. This is a **no-op stub** with a `DebugMonitor` class
whose methods all do nothing. It exists solely so that imports of
`debug_monitor.DebugMonitor` in the solver do not fail.

---

## 18. `stubs/stdlib/`  [NEW]

No upstream counterpart. PythonStAn had no stubs directory. The migration adds
~40 hand-written mock stdlib modules (e.g., `os`, `re`, `json`, `functools`,
`datetime`, `pathlib`, `collections`, `itertools`) with a `README.md` and
`LICENSE.pythonstan`.

Design principles (from the stubs README):
1. Preserve dataflow — functions return values derived from inputs
2. Preserve call graphs — decorators maintain `__wrapped__` and call through
3. Preserve aliasing semantics — views return inputs, copies allocate
4. Model key types — `Pattern`, `Match`, `Logger`, `Path`, etc.
5. No defensive programming — fail fast, no silent defaults

The bridge layer uses `mock_libs=True` and `prefer_mock_libs=True` by default,
so these stubs take precedence over real stdlib modules during analysis.

**Covered by tests:** `test_pointer_stdlib_stubs_are_resolved_from_vendor_tree`,
`test_imported_module_attribute_flows_to_local`.

---

## 19. `analysis/alias/kcfa/kcfa/libs/__init__.py`  [NEW]

Empty package init. Upstream had `libs/math.py` but no `__init__.py`, which
would fail to import as a package in some configurations.

---

## 20. SPDX license headers  [COMPAT]

All `__init__.py` files in the vendored tree gain SPDX copyright/license
headers:

```
# SPDX-FileCopyrightText: 2026 PyFlow Contributors
# SPDX-License-Identifier: MIT
```

---

## Summary Table

| File | Classification | Impact |
|---|---|---|
| `state.py` | ENHANCEMENT, BEHAVIOR | MRO field resolution, generator/coroutine, module global fallback |
| `solver.py` | BUGFIX, REFACTOR, BEHAVIOR | FieldKind enum fix, GLOBAL var kind, closure kind resolution, per-class vars |
| `analysis.py` | REFACTOR | Builtin init extracted to solver |
| `ir_translator.py` | ENHANCEMENT, BEHAVIOR | Per-class vars, CopyConstraint for Name, Optional kwargs, class-scope locals |
| `constraints.py` | BEHAVIOR | Optional[str] kwargs type |
| `builtin_api_handler.py` | ENHANCEMENT | object() handler, dict(**kwargs)/dict(iterable) |
| `class_hierarchy.py` | BUGFIX | update_bases now actually updates |
| `heap_model.py` | COMPAT, BEHAVIOR | Dead import removed, scope.module -> scope |
| `object.py` | ENHANCEMENT | name property for bridge queries |
| `module_analysis.py` | REFACTOR | Scope import relocated, TODO removed |
| `module_summary.py` | COMPAT | TODO removed |
| `processor.py` | COMPAT | Abstract method bodies ... -> return False |
| `pipeline.py` | BEHAVIOR | Closure analysis moved inside module loop |
| `analysis_manager.py` | COMPAT | AIAnalysisDriver -> NotImplementedError |
| `config.py` | COMPAT | Optional yaml, JSON config support |
| `namespace.py` | COMPAT | Stub path fix for vendored layout |
| `debug_monitor.py` | NEW | No-op stub (upstream never committed it) |
| `stubs/stdlib/` | NEW | ~40 mock stdlib modules |
| `libs/__init__.py` | NEW | Empty package init |
| `__init__.py` files | COMPAT | SPDX license headers |
