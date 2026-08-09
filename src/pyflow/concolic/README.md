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
`pathlib.Path`, basic `enum.Enum`/`IntEnum`/`StrEnum`, `statistics`, and `urllib.parse`
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
- `--max-solver-calls` and `--max-pending-states` for global search bounds;
- `--max-loop-iterations`, `--max-resume-steps`, and `--max-task-switches` for
  one concrete execution; and
- `--max-schedule-states` for nondeterministic scheduling prefixes per input.

The `explore_file` keyword arguments use the corresponding underscore names.
Budget termination is explicit in `ExplorationStatistics.stop_reason`, with
values such as `total_timeout`, `solver_timeout`, `max_solver_calls`, and
`max_pending_states`. A per-run timeout is recorded as a structured resource
outcome and exploration continues with other pending states.

## Coverage and Search

Every execution records the AST source spans it evaluated and the concrete
outcomes of symbolic branch edges. The aggregate `ExplorationResult.coverage`
contains their union; each `RunRecord.coverage` retains the contribution from
one input and schedule. Run outcomes distinguish normal returns, unhandled
target exceptions, unsupported syntax, resource limits, and engine errors.

Coverage-guided search is the default. It dynamically prioritizes pending
inputs that target branch edges not covered by previous executions. Select
FIFO behavior with `--search-strategy fifo` or
`search_strategy="fifo"`. Use `--max-uninteresting-iterations N` to stop after
N executions without new node or branch coverage.

Exploration statistics report execution outcomes, solver SAT/UNSAT/timeout
counts, solver and execution time, queue size, dropped and enqueued states,
coverage discoveries, plateau length, and the final stop reason. `--json`
serializes coverage, outcomes, timings, and statistics along with generated
inputs and contract counterexamples.

## Architecture

The implementation is organized around three dependency layers:

- The package root exposes the API in `__init__.py`; `engine.py` owns path and
  schedule exploration, while the other root modules provide shared runtime
  values, module loading, contracts, and small utilities.
- `interpreter/` contains the ordinary AST semantics. Its executor composes focused
  mixins for statements, values, calls, objects, collections, language
  semantics, and standard-library summaries.
- `resumable/` contains suspension-aware execution: CFG discovery, resumable
  frames, the generator/coroutine machine, async protocols, and task
  scheduling.

Dependencies point inward toward the shared package-root model. The
`interpreter` layer composes `resumable`; `resumable` is its suspension
subsystem and does not import the ordinary interpreter mixins. New syntax
behavior should generally live in the corresponding `interpreter` module;
behavior that crosses a suspension point belongs in `resumable`.

## Contracts

Pass `--check-contracts` (or `check_contracts=True` through `explore_file`) to
check single-line PEP 316 postconditions in an entry function's docstring. A
supported clause has the form `post: expression`; it may reference parameters
and `__return__`. PyFlow adds the negation of each passing clause to the path
solver and reports any discovered violation as a structured counterexample.
Snapshot values such as `__old__` are not supported yet.
