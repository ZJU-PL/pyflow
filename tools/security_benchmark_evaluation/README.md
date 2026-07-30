# Security benchmark result evaluation

This package is deliberately separate from the benchmark runner. The runner
captures reproducible analyzer executions and raw reports; this package
normalizes those reports, applies rule-to-CWE mappings, and computes metrics.

```bash
python -m tools.security_benchmark_evaluation results \
  -o evaluated --mapping cwe-mapping.json
```

The command writes `normalized.jsonl` and `metrics.json`. Built-in
normalization understands PyFlow/Bandit-style JSON, PySA JSONL, and SARIF
(including CodeQL). Analyzer-native CWE metadata is combined with an optional
mapping file:

```json
{
  "schema_version": 1,
  "engines": {
    "bandit": {
      "rules": {"B101": ["CWE-703"]}
    },
    "my-analyzer": {
      "regex_rules": [
        {"pattern": "^SQL", "cwes": ["CWE-89"]}
      ]
    }
  }
}
```

The default expected label is `labels.cwe`; change it with `--label-pointer`.
Metrics include completion, warnings, mapped warnings, and detection recall.
Precision is intentionally not reported because many vulnerability corpora do
not provide sufficient negative examples or finding-level ground truth.
