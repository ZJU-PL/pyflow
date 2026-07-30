"""Filesystem orchestration for normalization and metric computation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .mapping import CweMappings
from .metrics import compute_metrics
from .normalizers import normalize_run


def evaluate_results(
    results_dir: str | Path,
    output_dir: str | Path,
    *,
    mapping_path: str | Path | None = None,
    label_pointer: str = "/cwe",
) -> dict[str, Any]:
    source = Path(results_dir).resolve()
    destination = Path(output_dir).resolve()
    mappings = CweMappings.load(mapping_path)
    result_paths = sorted((source / "runs").glob("*/*/result.json"))
    if not result_paths:
        raise ValueError(f"no runner result files found under {source / 'runs'}")
    normalized = []
    for result_path in result_paths:
        try:
            payload = json.loads(result_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"cannot read runner result {result_path}: {exc}") from exc
        if not isinstance(payload, dict):
            raise ValueError(f"runner result must be an object: {result_path}")
        normalized.append(normalize_run(payload, result_path, mappings))
    destination.mkdir(parents=True, exist_ok=True)
    normalized_path = destination / "normalized.jsonl"
    normalized_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in normalized),
        encoding="utf-8",
    )
    metrics = compute_metrics(normalized, label_pointer=label_pointer)
    metrics["source_results"] = str(source)
    metrics["normalized_results"] = normalized_path.name
    (destination / "metrics.json").write_text(
        json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return metrics
