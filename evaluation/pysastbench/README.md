# PySASTBench synthetic microbenchmark

This directory contains the 240-file synthetic subset of PySASTBench used for
the PyFlow security-engine comparison: six CWE families, with paired
`*_vul.py` and `*_fix.py` files, plus `SyntheticDataset.csv` describing the
expected CWE and vulnerable function for each pair.

## Source and provenance

The benchmark is copied from the `SyntheticDataset` directory and metadata in
the PySASTBench repository:

<https://github.com/Victor725/PySASTBench>

That project is the benchmark accompanying “An Empirical Study on Static
Application Security Testing (SAST) Tools for Python” by Liu Zhuohang, Zhi
Wang, Haotong Liu, and Wanpeng Li (ICSE 2026 work). The repository is also
listed in [`evaluation/Tools.md`](../Tools.md) under “Benchmarks for Python
Code Analysis / Security Bug Finding”. The copy here is kept as evaluation
input; the benchmark’s synthetic code is not production-quality application
code and should not be treated as a standalone security oracle.

## Running the harness

From the repository root:

```bash
./.venv/bin/python evaluation/pysastbench/bench_micro.py
```

Useful options:

```bash
./.venv/bin/python evaluation/pysastbench/bench_micro.py \
  --output /tmp/pyflow-pysastbench-results \
  --workers 8 --timeout 45
```

The harness runs `ast-scanner`, `ast-dataflow`, `cpg`, and `ifds` through the
`pyflow security` CLI. It writes `summary.json`, per-file `records.json`, and
the raw JSONL stream to the selected output directory. A positive is counted
only when the engine reports the expected CWE at the benchmark’s target
function; a fixed pair is a negative. By default the evaluator treats CWE-77
and CWE-78, and CWE-94 and CWE-95, as equivalent semantic labels. Add
`--strict-cwe` to require exact labels.

The harness uses subprocess isolation and a per-file timeout because an
analysis failure or timeout should be recorded as an evaluation result rather
than aborting the remaining engines.

## Running the real-world projects

RealworldDataset is distributed as project archives. Extract it once before
running repeated engine comparisons:

```bash
./.venv/bin/python evaluation/pysastbench/extract_realworld.py \
  /path/to/PySASTBench-main
```

Then analyze the extracted `<CVE>/<project>-vul` and `<CVE>/<project>-fix`
directories:

```bash
./.venv/bin/python evaluation/pysastbench/bench_realworld.py \
  /path/to/PySASTBench-main \
  --workers 4 --timeout 60
```

The real-world runner does not extract archives itself. Each project is
analyzed as a unit, and the timeout is applied independently to each engine.
Both scripts derive the dataset, extracted-project, and metadata paths from
the supplied PySASTBench root. Use `--results` only when a non-default result
directory is needed.

After the run, the summary includes TP/FP/FN/TN, precision, recall, and F1.
Real-world detections require a finding with a listed CWE at the metadata
target function; timeouts and failed analyses count as no detection.
