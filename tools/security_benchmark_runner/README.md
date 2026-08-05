# Static-analysis benchmark runner

An independent benchmark scaffold for running PyFlow, CodeQL, PySA, Bandit,
and future analyzers over repository snapshots. It is not part of the
`pyflow` package and its manifest has no vulnerable/fixed pairing semantics.

Run it from the repository root:

```bash
python -m tools.security_benchmark_runner --help
```

## Manifest

The version 1 manifest contains independent local or Git-backed samples.
`labels` and `metadata` are opaque JSON copied into results, so other datasets
can define their own labels.

```json
{
  "schema_version": 1,
  "name": "example-corpus",
  "samples": [
    {
      "id": "local-example",
      "source": {"kind": "local", "path": "corpus/example"},
      "target": ".",
      "labels": {"cwe": "CWE-22", "partition": "test"}
    },
    {
      "id": "git-example",
      "source": {
        "kind": "git",
        "url": "https://github.com/example/project.git",
        "revision": "0123456789abcdef"
      },
      "engine_args": {
        "pyflow-ifds": ["--entry", "src/app.py"]
      }
    }
  ]
}
```

## Run analyzers

The default engines are PyFlow's AST scanner, AST dataflow, IFDS, and CPG
engines. Repeat `--engine` to select engines; `--engine all` also enables
CodeQL, PySA, and Bandit. Per-engine settings come from `--config engines.json`.

```bash
python -m tools.security_benchmark_runner run manifest.json \
  -o results --jobs 4 --timeout 1800
```

Completed results resume by default. `--force` replaces them. Every
sample/engine gets an isolated directory containing `result.json`, raw output,
and stdout/stderr logs. The runner records exact commands, tool versions,
resolved Git revisions, timeouts, exit status, and configuration fingerprints.
PyFlow adapters use its `--exit-code-policy report` contract: process exit zero
means a report was emitted, while `complete`, `partial`, `invalid`, or `failed`
comes from the report itself.

## Engine configuration

Tool installation paths and analyzer settings are separate from the dataset:

```json
{
  "schema_version": 1,
  "engines": {
    "codeql": {
      "command": ["/opt/codeql/codeql"],
      "queries": [
        "codeql/python-queries@0.9.3:codeql-suites/python-security-extended.qls"
      ],
      "query_timeout_seconds": 1800
    },
    "pysa": {
      "command": ["/opt/pysa/bin/pyre"],
      "taint_models_path": "/opt/pysa/taint"
    },
    "bandit": {"command": ["/opt/bandit/bin/bandit"]},
    "pyflow-ifds": {"args": ["--framework", "stdlib"]}
  }
}
```

Commands are argv arrays and never pass through a shell. PySA gets a separate
`.pyre_configuration` per run. Bandit emits JSON and CodeQL emits SARIF 2.1.0.

### Running PySA

Install PySA's `pyre` client and binary in the same environment used to launch
the runner:

```bash
python -m pip install pyre-check
pyre --version
pyre analyze --help
```

Installing `pyre-check` is necessary but not sufficient for a useful security
scan: PySA is a configurable taint analyzer and needs a model directory that
contains at least one `taint.config` plus the relevant `.pysa` source, sink,
and propagation models. Keep those models versioned with the experiment and
point the engine configuration at them:

```json
{
  "schema_version": 1,
  "engines": {
    "pysa": {
      "command": ["/absolute/path/to/.venv/bin/pyre"],
      "taint_models_path": "/absolute/path/to/pysa-models",
      "configuration": {"workers": 4}
    }
  }
}
```

The adapter writes an isolated `.pyre_configuration`, invokes `pyre analyze`,
and reads `pysa-results/taint-output.json`. Model verification is enabled by
default so an invalid or unmatched model fails visibly instead of silently
producing zero findings. Set `"no_verify": true` only when intentionally using
PySA's `--no-verify` behavior.

A minimal self-contained model set looks like this:

```json
{
  "sources": [{"name": "Test"}],
  "sinks": [{"name": "Test"}],
  "rules": [{
    "name": "Test flow",
    "code": 9001,
    "sources": ["Test"],
    "sinks": ["Test"],
    "message_format": "Test data reaches test sink"
  }]
}
```

```python
def app.source() -> TaintSource[Test]: ...
def app.sink(value: TaintSink[Test]): ...
```

The function signatures in `.pysa` files must match the analyzed program; a
model that does not match a callable will not create the expected source or
sink. For benchmark runs, map PySA's numeric rule code to a CWE in the separate
evaluation mapping rather than embedding dataset-specific semantics in the
runner:

```json
{"schema_version": 1, "engines": {"pysa": {"rules": {"9001": ["CWE-78"]}}}}
```

The first PySA run can be relatively slow because it builds the environment,
call graph, and inferred models. Inspect `analyze.stderr.log` for messages such
as `Found N issues`, model verification failures, or a missing `taint.config`.

### Declarative analyzers

An analyzer that can be invoked as a command does not need a Python adapter.
Give it any engine name, select that name with `--engine`, and configure an
`adapter: command` entry. Steps run sequentially and stop on timeout or an
unaccepted exit code.

```json
{
  "schema_version": 1,
  "engines": {
    "semgrep": {
      "adapter": "command",
      "version_argv": ["semgrep", "--version"],
      "version_env": {"SEMGREP_SEND_METRICS": "off"},
      "steps": [
        {
          "name": "scan",
          "argv": [
            "semgrep", "scan", "--json", "--output", "{report}",
            "{target}", "{sample_args}"
          ],
          "accepted_returncodes": [0, 1],
          "timeout_seconds": 900,
          "cwd": "run_dir",
          "env": {"SEMGREP_SEND_METRICS": "off"}
        }
      ],
      "report": {
        "path": "report.json",
        "format": "json",
        "findings_pointer": "/results",
        "analysis_status_pointer": "/status"
      }
    }
  }
}
```

Scalar placeholders: `{target}`, `{run_dir}`, `{report}`, `{engine}`,
`{sample_id}`; a standalone `{sample_args}` expands the sample's complete argv.
Report formats: `json`, `jsonl`, `sarif`, `none` (JSON fields use RFC 6901
pointers). Step `cwd` is limited to `run_dir` or `target`, report paths stay
inside the isolated run directory, and commands never use a shell.

Dataset-specific converters are intentionally not part of this scaffold.
Datasets should produce the generic versioned manifest described above in
their own preparation workflow. Result normalization, CWE mapping, and metrics
are likewise independent.
