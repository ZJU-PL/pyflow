# Concolic Execution

An AST-level migration of Py-Conbyte's path-flipping
workflow. Install its solver with `pip install -e ".[concolic]"` (it is also
included in the `dev` and `test` extras).

It supports integer/float/string/list
inputs, byte-string literals, arithmetic, comparisons, `if`/`while`/`for`,
local functions and
classes (including defaults, keyword calls, and `*args`/`**kwargs`),
inheritance, class variables, `super()`, function and supported class decorators (including transparent
`functools.cache`/`lru_cache`/`wraps`), method decorators, properties (including `cached_property`), and basic dataclasses
(including `asdict`, `astuple`, and `replace`);
lists/dictionaries (including union), sets (including common mutating methods), unpacking, f-strings, percent
formatting, assignment expressions, and structural pattern matching (including
dataclass and literal-`__match_args__` class patterns),
synchronous and asynchronous comprehensions; lazy generator expressions;
suspended generator frames with `send`, `throw`, `close`, and `yield from`;
and incremental sequence, `map`, `filter`, `zip`, `enumerate`, and common
`itertools` iterators; local and
package-relative imports, safe computed module constants, and the common `re.compile(...).match(...).group()`
workflow, plus structured `base64`, `bisect`, `collections.Counter`/`namedtuple`, `copy`,
`dataclasses`, deterministic `datetime`, `functools.partial`, `hashlib`,
`heapq`, `itertools`, `json`, `math`, `operator`, `os.path`, lexical
`pathlib.Path`, basic `enum.Enum`/`IntEnum`/`StrEnum`, `statistics`, `struct`,
`binascii`, `codecs`, `html`, `unicodedata`, `zlib`, and `urllib.parse`
summaries, plus `contextlib.suppress`, `nullcontext`, and supported
`contextmanager`/`asynccontextmanager` decorators. It also models context
managers and `try`/`except`/`finally`, simple `except*`, exception chaining,
lazy coroutine calls, local `await`, async generators and iterators, and
incremental `async with` hooks. Async generators support `__anext__`, `asend`,
`athrow`, and suspending `aclose`; local objects may provide `__await__`.
A small `asyncio` model supports `sleep`,
`create_task`, and `gather`; select `--scheduler nondeterministic` to explore
task-order choices separately from SMT branch choices. Task state includes
deferred cancellation plus `done`, `cancelled`, `result`, and `exception`
behavior for the supported scheduler model, including cancellation propagation
through directly awaited tasks.

Resource controls include:

- `--total-timeout`, `--per-run-timeout`, and `--solver-timeout` for
  wall-clock budgets in seconds;
- `--solver-rlimit` for deterministic per-query Z3 work limits;
- `--max-solver-calls` and `--max-pending-states` for global search bounds;
- `--max-loop-iterations`, `--max-resume-steps`, and `--max-task-switches` for
  one concrete execution; and
- `--max-schedule-states` for nondeterministic scheduling prefixes per input.
- `--max-symbolic-container-size` for bounded input-list shape exploration.
- `--max-opaque-refinements` for the number of distinct CPython observations
  retained by observation-refined library models.

The `explore_file` keyword arguments use the corresponding underscore names.
Budget termination is explicit in `ExplorationStatistics.stop_reason`. A
per-run timeout is recorded as a structured resource outcome. Inconclusive
solver queries are counted and diagnosed without aborting unrelated pending
states; only an exhausted total budget stops the complete exploration.

## Coverage and Search

Every execution records the AST source spans it evaluated and the concrete
outcomes of symbolic branch edges. The aggregate `ExplorationResult.coverage`
contains their union; each `RunRecord.coverage` retains the contribution from
one input and schedule. Run outcomes distinguish normal returns, unhandled
target exceptions, unsupported syntax, resource limits, and engine errors.

Exploration retains a persistent path trie containing observed, reserved, and
exhausted branch alternatives. Coverage-guided search is the default. Select
shallow-first exploration with `--search-strategy breadth_first`, or FIFO with
`--search-strategy fifo`. Use `--max-uninteresting-iterations N` to stop after
N executions without new node or branch coverage.

Input lists and sets have bounded symbolic shape, so an empty seed can discover
nonempty paths. Input dictionaries track symbolic presence for keys observed
by membership tests. Aliased mutable parameters retain shared heap
identity through execution, model generation, and replay.

## Observation-Refined Library Calls

Pass `--refine-opaque-calls` (or `refine_opaque_calls=True`) to continue through
otherwise unsupported calls in a conservative allowlist of deterministic
standard-library modules. The engine invokes the real CPython operation on
deep-copied concrete arguments, records its return value, exception, and
argument effects, and adds the observation to a refinement store shared by all
executions in the current search.

Primitive results are represented by typed uninterpreted functions constrained
at every observed point. For Boolean, integer, and string results, the engine
also proposes small branch-relevant relations, validates them against prior
observations and fresh probes, and uses a valid relation as solver guidance.
Guidance is speculative: an unsatisfiable guided query is retried without it.
This lets path solving invert common operations such as predicates, integer
sign changes, and string prefix/suffix transformations without treating an
inferred relation as a sound global summary.

List, dictionary, and set mutations are reflected in the concolic runtime;
container-valued results can continue through concrete container operations.
Each refined operation is attached to its `RunRecord`, included in JSON output,
and replayed independently so a CPython mismatch identifies the responsible
library call rather than only the final program result. Refinement is opt-in,
allowlisted, and bounded because it executes host-library code.

Exploration statistics report execution outcomes, solver SAT/UNSAT/timeout
counts, solver and execution time, queue size, dropped and enqueued states,
coverage discoveries, plateau length, and the final stop reason. `--json`
serializes coverage, outcomes, timings, and statistics along with generated
inputs and contract counterexamples.

## Corpus Reduction and Pytest Generation

`minimize_runs` greedily selects a deterministic small corpus that preserves
the observed branch and AST-node coverage. Distinct non-returning outcomes and
contract-counterexample inputs are retained, while ties prefer smaller inputs,
shorter schedules, and shorter paths.

Before a run can become a generated test, `replay_runs` executes it against a
fresh CPython module. A shared behavioral observation layer compares return
values, exception type/message, nested values, NaNs, iterators, and arguments
after execution. The standard-library model suite uses the same oracle.

Use `--emit-pytest PATH` to write the minimized, replay-validated corpus as a
pytest module. Generated tests support synchronous and asynchronous entrypoints,
expected target exceptions, and mutated scalar/list/dictionary inputs. When
combined with `--json`, the result includes replay statuses, skipped cases, and
the generated-test count.

## Project Support Scanning

Use `--scan-project` with a source tree to discover functions statically,
synthesize deterministic annotation-guided inputs, explore them in isolated
workers, and validate supported runs against CPython:

```bash
pyflow concolic ./src --scan-project --json --json-output concolic-report.json
```

The shared function catalog records source identity, signatures, eligibility,
and side-effect hazards without importing the project. Input tiers cover
primitive values, bytes, `Literal`, optional and union values, `Annotated`,
tuples, and annotated lists, dictionaries, sets, and frozen sets. The worker
audit wall blocks indirect filesystem/process/network mutation at runtime, in
addition to the static hazard scan.
Reports classify unsupported operations, replay mismatches, exhausted budgets,
timeouts, input-generation failures, and side-effect hazards. Functions flagged
for filesystem, process, or network activity are skipped unless
`--allow-side-effects` is supplied.

`discover_operations(path)` builds a frequency-ranked call corpus from `.py`
and `.pyi` trees without importing them. Import aliases are resolved and each
operation is classified as built-in, locally defined, modelled, or unknown, so
typeshed and application stubs can directly prioritize the next model work.

## Architecture

The package root only defines the public API. Implementation modules are grouped
by responsibility:

- `core/` contains the shared runtime model, local-module loader, and low-level
  value/input helpers.
- `exploration/` owns the public exploration workflow, resource budgets,
  contracts, path solving, and pending-state search policies.
- `interpreter/` contains ordinary AST semantics. Its executor composes focused
  mixins for statements, values, calls, objects, collections, language
  semantics, coverage, and registry-backed standard-library models.
- `resumable/` is the interpreter's suspension subsystem: CFG discovery,
  resumable frames, generator/coroutine execution, async protocols, and task
  scheduling.
- `project/` contains static target discovery, annotation-guided input
  synthesis, isolated workers, and project support measurement.
- `artifacts/` turns exploration results into minimized corpora, CPython replay
  results, and generated pytest modules.

Dependencies point toward `core/`. `exploration/` composes `interpreter/`, and
`interpreter/` composes `resumable/`; neither project scanning nor artifact
generation is part of execution semantics. New ordinary Python behavior belongs
in the corresponding `interpreter` module, while behavior that crosses a
suspension point belongs in `resumable`.

## Contracts

Pass `--check-contracts` (or `check_contracts=True` through `explore_file`) to
check composite PEP 316 and decorator contracts. `pre:` clauses constrain entry, `raises:`
declares expected exception types, and `post:` clauses may reference parameters
and `__return__`. A clause such as `post[values]: len(values) ==
len(__old__.values) + 1` compares the post-state with a deep pre-state snapshot.
Passing postconditions are negated in the solver to search for structured
counterexamples. Multiline sections, inherited class invariants, common
`require`/`ensure` decorators, and programmatic `register_contract` overlays
are supported.
