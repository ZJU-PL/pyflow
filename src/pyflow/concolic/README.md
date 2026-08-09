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

Resource controls include `--max-loop-iterations`, `--max-resume-steps`, and
`--max-task-switches`. Nondeterministic exploration is separately bounded by
`--max-schedule-states`. The corresponding `explore_file` keyword arguments
are `max_loop_iterations`, `max_resume_steps`, `max_task_switches`, and
`max_schedule_states`.

## Contracts

Pass `--check-contracts` (or `check_contracts=True` through `explore_file`) to
check single-line PEP 316 postconditions in an entry function's docstring. A
supported clause has the form `post: expression`; it may reference parameters
and `__return__`. PyFlow adds the negation of each passing clause to the path
solver and reports any discovered violation as a structured counterexample.
Snapshot values such as `__old__` are not supported yet.
