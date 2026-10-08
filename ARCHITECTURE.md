# PyFlow architecture

PyFlow uses one pass-based execution model. The boundaries below are enforced
by `tests/tooling/test_architecture.py`, which runs in the existing CI tooling
job and the normal test suite. The check resolves absolute and relative imports,
including imports inside functions and literal dynamic imports. It applies to
first-party source; vendored PythonStan is excluded.

## Responsibilities and dependencies

| Package | Responsibility | Forbidden dependencies |
| --- | --- | --- |
| `model` | Entry declarations, argument models, shared errors | IR, algorithms, frontend, application, public API, checker, transports |
| `ir` | Graphs, stable identities, source metadata, versioned facts | Frontend, application, public API, checker, transports |
| `analysis`, `optimization` | Solvers and transformations | Application, public API, checker, transports |
| `frontend` | Source loading and extraction | Public API, checker, transports |
| `application` | Program, sessions, pipeline definitions, scheduling, CPG source orchestration | Public API, checker, transports |
| `api` | Query composition, snapshots, IFDS run entry points | CLI, LSP/MCP |
| `cli`, `lsp`, `checker` | User-facing workflows and diagnostics | Must respect the contracts of the lower packages they use |

Algorithms receive a program/context as arguments. They do not import public API
facades or parse transport options. Entry declarations live exclusively in
`pyflow.model.entrypoints`. CPG source/directory loading lives in
`pyflow.application.cpg`; CPG graph structures remain in `ir.cpg`.

These contracts enforce selected package boundaries, not a complete dependency
DAG. Some IR graph builders still consume shared analysis helpers, and frontend
extraction constructs an application Program. Further separating framework
infrastructure from specific algorithms can happen within these boundaries.

## State ownership

- **Program** owns declarations, extracted code, store graph, frontend metadata,
  and its `IRCatalog`. The catalog belongs to the model because it defines the
  identities of its IR objects.
- **AnalysisSession** belongs to one Program. It owns immutable `AnalysisOptions`,
  revision-pinned solver results, the pass manager, its cache and execution log.
  It coordinates invalidation of results and published catalog facts.
- **CompilerContext** supplies extraction, console, slot naming, and statistics
  services to passes. It is not an analysis-result registry.
- **API snapshots and query components** belong to the client. Query graph caches
  track catalog identity, IR revision, and published-fact revision.

Create a configured model and run it with explicit services:

```python
from pyflow.application.context import CompilerContext
from pyflow.application.pipeline import Pipeline
from pyflow.application.program import Program
from pyflow.application.session import AnalysisOptions
from pyflow.frontend.extractor import Extractor, extract_program

program = Program(options=AnalysisOptions(cpa_path_length=3))
program.interface.func.append((my_function, ()))
compiler = CompilerContext()
compiler.extractor = Extractor(compiler)
extract_program(compiler, program)
results = Pipeline().run(program, compiler=compiler)
ipa = program.session.get_result("ipa")
```

A terminal transformation may invalidate `ipa`, so clients needing final analysis
facts should request the analyses they require through `run_custom_pipeline`.
`dump_reports=True` adds analysis refresh stages before generating reports.
Statistics run while the initial CPA facts are current and do not mutate IR.

Use `program.session.configure(AnalysisOptions(...))` to change configuration.
It retires solver results, published facts, and the previous scheduler. Separate
Programs have separate sessions and options. Concurrent execution of passes on
the same mutable Program is not supported.

## Mutation, caching, and failure

An analysis publishes facts in the catalog and records its internal solver
object in the session. These are different representations with one coordinated
lifecycle. Clients consume published facts; algorithms may retain solver state.

A pass returning `changed=True` commits an IR revision at the pass boundary.
Only explicitly preserved analysis producers/results survive; the remaining
facts, solver objects, and caches are retired. Lower-level transformations may
also commit their own revisions. Results and caches check catalog identity as
well as revision, so replacing a catalog cannot make an old result valid again.
Preservation cannot revive a result that was already stale before the pass.

Result cache keys also track fact publication, result invalidation, and run options.
This is deliberately conservative: publishing new facts can cause an unrelated
cached pass to run again. Finer capability-specific keys can improve efficiency
without weakening the current correctness contract.

A failed pass may have made partial changes. The manager retires the program's
analysis state and caches before stopping. The Pipeline surfaces the failure;
it does not silently continue with partially valid results.

Raw external IR edits must call `program.session.mark_changed()` or commit an
IRCatalog revision. Edits without a version update cannot be detected by the
cache. Calling `invalidate_results` also removes the corresponding producers'
published facts without removing other producers of a shared capability.


## Runtime prerequisite scheduling and execution records

Pipeline construction expands prerequisites to establish an initial stage order.
Its `available` set denotes inclusion in that plan; it is not evidence that an
analysis is still valid during execution. Immediately before each invocation,
PassManager checks the availability of its analysis prerequisites and refreshes
any that are missing or stale. This check runs before result-cache lookup.

`requirements` must name registered analysis passes. Dependencies on analysis
passes also require current analysis results. Dependencies on transformations
and utility stages establish execution order; refreshing an analysis does not
replay those already completed stages. Explicit repeated stage requests remain
separate invocations, including consecutive repetitions.

Analysis availability is independent of result caching. Its markers track catalog
identity, IR revision, options, solver-result invalidation, and explicit fact
invalidation. Ordinary fact publication does not retire unrelated analysis
markers. A newly executed analysis retires its declared dependent analyses and
cached consumers, even if the IR revision is unchanged. This includes analysis
stage instances sharing a Session solver identity. Preservation metadata rebases
only previously valid markers; stale results cannot become valid by preservation.

The scheduler checks the whole required analysis set after each refresh because
one analysis can invalidate another. A refresh failure stops the consumer and
remaining pipeline. Requirements that cannot stabilize fail explicitly after
`max_analysis_refreshes` attempts per missing prerequisite (32 by default),
rather than executing a consumer with stale inputs or refreshing forever.

This implementation still identifies requirements by registered analysis pass
names; a separate PassDefinition/PassInvocation and arbitrary capability-provider
model remain future work. Changing analyses or adding prerequisites must be
reflected in their metadata; the scheduler cannot infer undeclared data inputs.

A run returns `PipelineResult`. Its ordered `records` retain every invocation,
including automatic prerequisite refreshes, repeated passes, and cache hits.
Each immutable `ExecutionRecord` includes the run ID, sequence, stage/pass name,
success, mutation flag, body duration, cache hit, IR revisions before/after,
and the pass result. Automatic records name the consumer that requested them.
`result["ipa"]` still selects that pass's latest result; `len(result)` counts
unique pass names, while `len(result.records)` counts invocations.

```python
results = Pipeline().run_custom_pipeline(
    compiler, program, ["type_analysis", "rewrite", "consumer"]
)
for record in results.records:
    print(record.sequence, record.stage_name, record.cached,
          record.revision_before, record.revision_after)
latest_types = results["type_analysis"]
```

Pipeline summaries use invocation records and their actual body time. Cache hits
have zero body time instead of reusing the original analysis's historical duration.
Execution-log dictionaries include the same scheduling metadata and keep solver
objects out of the serialized log.

## Pass implementation

- `application/passes/base.py`: interfaces, metadata, execution results.
- `application/passes/cache.py`: version-aware per-program caching.
- `application/passes/manager.py`: prerequisites, execution, invalidation, logs.
- `application/passes/builtin.py`: algorithm/transform adapters.
- `application/passes/registry.py`: explicit builtin registration and dependencies.
- `application/pipeline.py`: default execution stages and optional reporting.

Pipeline instances hold no mutable run state. The session lazily creates its
manager and builtin registry, so importing Program or the domain models does
not load analysis engines. New passes can be registered directly with
`program.session.pass_manager`.

Stage names such as `ipa_refresh` still select instances of the same analysis
implementation. The session maps them to one solver identity. A future stage
representation can remove these registration names without changing ownership
or invalidation rules.

## Import/API changes

The refactor uses explicit canonical imports; there are no compatibility modules
or legacy execution wrappers.

| Removed location or interface | Canonical interface |
| --- | --- |
| `api.entrypoints` | `model.entrypoints` |
| `application.errors` | `model.errors` |
| `application.passmanager` | `application.passes.base`, `.cache`, `.manager` |
| `application.passes` flat module | `.builtin` and `.registry` |
| `analysis.ifds.api` | `api.ifds` (`PreparedIFDSProgram` for prepared CFG input) |
| `application.analysis_snapshot` | `api.snapshot` |
| `ir.cpg.build` | `application.cpg` |
| Top-level Program/Pipeline/Context exports | Explicit defining-module imports; `CompilerContext` |
| `evaluate`, `depythonPass`, conditioning helpers, `use_pass_manager` | `Pipeline.run` or `Pipeline.run_custom_pipeline` |
| Program result registry and accessors | `program.session.results`, `record_result`, `get_result`, `invalidate_results` |
| Process-global pipeline switches | `AnalysisOptions` |

`config.py` retains ancillary output-directory and shape defaults. It no longer
controls pipeline scheduling or reporting switches.

## Shared checker infrastructure

Checker engines consume shared infrastructure through `checker.common` and
`checker.formatters`. Neither shared package may import a specific checker engine
or a transport. The architecture regression tests enforce this boundary and
verify that importing shared utilities does not load an engine.

- `common.taint` owns the immutable taint domain, locations, provenance, abstract
  strings, and uncertainty records used by AST dataflow and formal CPG analysis.
  `common.taint.refinement` owns their common update/refinement policies.
- `common.diagnostics.CheckerDiagnostic` is the diagnostic record used by AST
  dataflow and CPG. Its serializer also accepts native IFDS diagnostics and
  already serialized mappings, preserving source and completeness information.
- `common.reporting` serializes status, statistics, and procedure names.
  `common.metrics.Metrics` counts native Issue records and visitor scores;
  AST dataflow creates fresh metrics for each run.
- `formatters.utils` assembles Issue reports and baseline candidates for JSON
  and YAML and supplies their deterministic ordering.
- `formatters.sarif` owns severity conversion, source-coordinate conversion, and
  SARIF document assembly. Pattern scanning, AST dataflow, IFDS, CPG,
  capability, and supply-chain exports use these utilities.
- `formatters.security` renders AST/IFDS/CPG security reports from finding data;
  `formatters.cpg` renders native CPG findings, including full code flows;
  `formatters.capability` renders capability findings. These adapters import
  no solver implementations and accept no CLI argument objects.

Engines keep their native finding types and evidence. Engine-specific
normalization, such as binding IFDS nodes to source locations and witness paths,
remains in `checker.ifds.reporting`. The CLI selects engines, options, and output
streams; report rendering lives in the formatter package.

Canonical imports replace the former engine-local utility locations:

| Former interface | Shared interface |
| --- | --- |
| `checker.ast_dataflow.domain` | `checker.common.taint` |
| AST semantics refinement exports | `checker.common.taint.refinement` |
| `ASTDataflowTaintDiagnostic`, `CPGTaintDiagnostic` | `checker.common.diagnostics.CheckerDiagnostic` |
| `CPGTaintEngine.to_sarif` | `checker.formatters.cpg.findings_to_sarif` |
| `TaintFinding.to_sarif` | `checker.formatters.cpg.finding_to_sarif` |
| `RuleMetadata.to_sarif_rule` | `checker.formatters.cpg.rule_to_sarif` |
| `CPGTaintEngine.to_json` | `checker.formatters.json.findings_json` |
| Checker root engine exports | Explicit imports from the engine or common package |

JSON/YAML Issue schemas and engine-specific report fields remain intact.
SARIF severity labels now use one mapping across exporters: low/note is `note`,
medium/warning is `warning`, and high/critical/error is `error`. In particular,
CPG CLI low-severity results now use `note` rather than `warning`. Unknown source
lines in native CPG SARIF exports use line 1 instead of an invalid line 0.
