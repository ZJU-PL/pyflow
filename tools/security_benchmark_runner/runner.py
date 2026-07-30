"""Dataset-independent orchestration for reproducible analyzer executions."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from .adapters import AdapterContext, adapter_for
from .manifest import BenchmarkManifest, Sample
from .process import ProcessOutcome, run_process


RUN_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class RunnerOptions:
    output_dir: Path
    engines: tuple[str, ...]
    jobs: int = 1
    timeout_seconds: float = 1800.0
    force: bool = False
    sample_ids: frozenset[str] = frozenset()
    engine_config: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.jobs < 1:
            raise ValueError("jobs must be at least 1")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if not self.engines:
            raise ValueError("at least one engine is required")


@dataclass(frozen=True)
class SourceSnapshot:
    root: Path
    identity: Mapping[str, Any]
    commands: tuple[ProcessOutcome, ...] = ()


class SourcePreparationError(RuntimeError):
    def __init__(self, message: str, commands: tuple[ProcessOutcome, ...] = ()):
        super().__init__(message)
        self.commands = commands


class BenchmarkRunner:
    """Prepare each sample once and run selected engines in isolated directories."""

    def __init__(self, manifest: BenchmarkManifest, options: RunnerOptions) -> None:
        self.manifest = manifest
        self.options = options
        self.output_dir = options.output_dir.resolve()

    def run(self) -> dict[str, Any]:
        self._initialize_output()
        samples = self._selected_samples()
        records: list[dict[str, Any]] = []
        resumed = 0
        with ThreadPoolExecutor(max_workers=self.options.jobs) as executor:
            futures = {
                executor.submit(self._run_sample, sample): sample for sample in samples
            }
            for future in as_completed(futures):
                sample_records = future.result()
                records.extend(sample_records)
                resumed += sum(
                    bool(record.pop("_resumed", False)) for record in sample_records
                )
        records.sort(
            key=lambda record: (str(record["sample_id"]), str(record["engine"]))
        )
        counts = Counter(str(record["status"]) for record in records)
        summary = {
            "schema_version": RUN_SCHEMA_VERSION,
            "benchmark": self.manifest.name,
            "generated_at": _utc_now(),
            "sample_count": len(samples),
            "run_count": len(records),
            "resumed_count": resumed,
            "status_counts": dict(sorted(counts.items())),
            "runs": [
                {
                    "sample_id": record["sample_id"],
                    "engine": record["engine"],
                    "status": record["status"],
                    "finding_count": record.get("finding_count"),
                    "result": record["result_path"],
                }
                for record in records
            ],
        }
        _atomic_json(self.output_dir / "summary.json", summary)
        return summary

    def _initialize_output(self) -> None:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        normalized_manifest = self.manifest.as_dict()
        _atomic_json(self.output_dir / "manifest.json", normalized_manifest)
        configuration = {
            "schema_version": RUN_SCHEMA_VERSION,
            "engines": list(self.options.engines),
            "jobs": self.options.jobs,
            "timeout_seconds": self.options.timeout_seconds,
            "engine_config": {
                key: dict(value) for key, value in self.options.engine_config.items()
            },
            "manifest_sha256": _json_digest(normalized_manifest),
        }
        _atomic_json(self.output_dir / "run-configuration.json", configuration)

    def _selected_samples(self) -> tuple[Sample, ...]:
        if not self.options.sample_ids:
            return self.manifest.samples
        available = {sample.id: sample for sample in self.manifest.samples}
        missing = sorted(self.options.sample_ids - available.keys())
        if missing:
            raise ValueError(f"unknown sample ids: {', '.join(missing)}")
        return tuple(
            available[sample_id] for sample_id in sorted(self.options.sample_ids)
        )

    def _run_sample(self, sample: Sample) -> list[dict[str, Any]]:
        try:
            snapshot = self._prepare_source(sample)
            source_error = None
        except SourcePreparationError as exc:
            snapshot = None
            source_error = exc
            self._write_source_failure(sample, exc)
        records = []
        for engine in self.options.engines:
            if snapshot is None:
                records.append(
                    self._source_failure_record(sample, engine, source_error)
                )
            else:
                records.append(self._run_engine(sample, snapshot, engine))
        return records

    def _prepare_source(self, sample: Sample) -> SourceSnapshot:
        acquisition_dir = self.output_dir / "acquisition" / sample.id
        acquisition_dir.mkdir(parents=True, exist_ok=True)
        if sample.source.kind == "local":
            assert sample.source.path is not None
            root = Path(sample.source.path)
            if not root.is_absolute():
                root = self.manifest.base_dir / root
            root = root.resolve()
            if not root.is_dir():
                raise SourcePreparationError(f"local source is not a directory: {root}")
            identity: dict[str, Any] = {
                "kind": "local",
                "path": str(root),
                "tree_sha256": _tree_digest(root, excluded_root=self.output_dir),
            }
            git_revision = _git_revision(root)
            if git_revision:
                identity["git_revision"] = git_revision
            snapshot = SourceSnapshot(root=root, identity=identity)
            _atomic_json(acquisition_dir / "source.json", dict(identity))
            return snapshot
        return self._prepare_git_source(sample, acquisition_dir)

    def _prepare_git_source(
        self, sample: Sample, acquisition_dir: Path
    ) -> SourceSnapshot:
        assert sample.source.url is not None and sample.source.revision is not None
        checkout = self.output_dir / "checkouts" / sample.id
        commands: list[ProcessOutcome] = []
        if checkout.exists() and not (checkout / ".git").exists():
            shutil.rmtree(checkout)
        if not checkout.exists():
            checkout.parent.mkdir(parents=True, exist_ok=True)
            clone = run_process(
                [
                    "git",
                    "clone",
                    "--filter=blob:none",
                    "--no-checkout",
                    sample.source.url,
                    str(checkout),
                ],
                cwd=self.output_dir,
                timeout_seconds=max(self.options.timeout_seconds, 600),
                stdout_path=acquisition_dir / "clone.stdout.log",
                stderr_path=acquisition_dir / "clone.stderr.log",
            )
            commands.append(clone)
            if clone.timed_out or clone.error or clone.returncode != 0:
                raise SourcePreparationError("git clone failed", tuple(commands))
        verify = _quiet_git(
            checkout, "rev-parse", "--verify", f"{sample.source.revision}^{{commit}}"
        )
        if verify is None:
            fetch = run_process(
                ["git", "-C", str(checkout), "fetch", "--prune", "origin"],
                cwd=self.output_dir,
                timeout_seconds=max(self.options.timeout_seconds, 600),
                stdout_path=acquisition_dir / "fetch.stdout.log",
                stderr_path=acquisition_dir / "fetch.stderr.log",
            )
            commands.append(fetch)
            if fetch.timed_out or fetch.error or fetch.returncode != 0:
                raise SourcePreparationError("git fetch failed", tuple(commands))
        checkout_result = run_process(
            [
                "git",
                "-C",
                str(checkout),
                "checkout",
                "--detach",
                sample.source.revision,
            ],
            cwd=self.output_dir,
            timeout_seconds=self.options.timeout_seconds,
            stdout_path=acquisition_dir / "checkout.stdout.log",
            stderr_path=acquisition_dir / "checkout.stderr.log",
        )
        commands.append(checkout_result)
        if (
            checkout_result.timed_out
            or checkout_result.error
            or checkout_result.returncode != 0
        ):
            raise SourcePreparationError("git checkout failed", tuple(commands))
        resolved = _quiet_git(checkout, "rev-parse", "HEAD")
        if resolved is None:
            raise SourcePreparationError(
                "cannot resolve checked-out revision", tuple(commands)
            )
        identity: dict[str, Any] = {
            "kind": "git",
            "url": sample.source.url,
            "requested_revision": sample.source.revision,
            "resolved_revision": resolved,
        }
        source_record: dict[str, Any] = dict(identity)
        source_record["commands"] = [command.as_dict() for command in commands]
        _atomic_json(acquisition_dir / "source.json", source_record)
        return SourceSnapshot(
            root=checkout, identity=identity, commands=tuple(commands)
        )

    def _run_engine(
        self, sample: Sample, snapshot: SourceSnapshot, engine: str
    ) -> dict[str, Any]:
        run_dir = self.output_dir / "runs" / sample.id / engine
        result_path = run_dir / "result.json"
        execution_fingerprint = self._execution_fingerprint(sample, snapshot, engine)
        if result_path.exists() and not self.options.force:
            loaded = json.loads(result_path.read_text(encoding="utf-8"))
            if not isinstance(loaded, dict):
                raise ValueError(f"invalid existing result: {result_path}")
            record: dict[str, Any] = loaded
            if record.get("status") == "source_failed":
                shutil.rmtree(run_dir)
            elif record.get("execution_fingerprint") != execution_fingerprint:
                raise ValueError(
                    f"existing result configuration differs for {sample.id}/{engine}; "
                    "use --force to replace it"
                )
            else:
                record["_resumed"] = True
                return record
        elif run_dir.exists() and (self.options.force or not result_path.exists()):
            shutil.rmtree(run_dir)
        run_dir.mkdir(parents=True, exist_ok=True)
        target = (snapshot.root / sample.target).resolve()
        try:
            target.relative_to(snapshot.root.resolve())
        except ValueError:
            return self._write_invalid_target(sample, engine, run_dir, target)
        if not target.exists():
            return self._write_invalid_target(sample, engine, run_dir, target)
        started_at = _utc_now()
        started = time.monotonic()
        try:
            engine_config = self.options.engine_config.get(engine, {})
            adapter = adapter_for(engine, engine_config)
            result = adapter.run(
                AdapterContext(
                    engine=engine,
                    sample_id=sample.id,
                    target=target,
                    run_dir=run_dir,
                    timeout_seconds=self.options.timeout_seconds,
                    sample_args=sample.engine_args.get(engine, ()),
                    config=engine_config,
                )
            )
            status = result.status
            error = result.error
            commands = [command.as_dict() for command in result.commands]
            tool_version = result.tool_version
            raw_output = result.raw_output
            finding_count = result.finding_count
            analysis_status = result.analysis_status
            details = dict(result.details)
        except (
            Exception
        ) as exc:  # benchmark isolation: one adapter must not abort others
            status = "failed"
            error = f"{type(exc).__name__}: {exc}"
            commands = []
            tool_version = None
            raw_output = None
            finding_count = None
            analysis_status = None
            details = {}
        record = {
            "schema_version": RUN_SCHEMA_VERSION,
            "benchmark": self.manifest.name,
            "sample_id": sample.id,
            "engine": engine,
            "execution_fingerprint": execution_fingerprint,
            "status": status,
            "analysis_status": analysis_status,
            "started_at": started_at,
            "finished_at": _utc_now(),
            "duration_seconds": round(time.monotonic() - started, 6),
            "source": dict(snapshot.identity),
            "target": sample.target,
            "labels": dict(sample.labels),
            "metadata": dict(sample.metadata),
            "tool_version": tool_version,
            "engine_config": dict(self.options.engine_config.get(engine, {})),
            "engine_args": list(sample.engine_args.get(engine, ())),
            "finding_count": finding_count,
            "raw_output": raw_output,
            "commands": commands,
            "details": details,
            "error": error,
            "result_path": str(result_path.relative_to(self.output_dir)),
        }
        _atomic_json(result_path, record)
        return record

    def _execution_fingerprint(
        self, sample: Sample, snapshot: SourceSnapshot, engine: str
    ) -> str:
        return _json_digest(
            {
                "schema_version": RUN_SCHEMA_VERSION,
                "manifest": self.manifest.as_dict(),
                "sample": sample.as_dict(),
                "source": dict(snapshot.identity),
                "engine": engine,
                "engine_config": dict(self.options.engine_config.get(engine, {})),
                "engine_args": list(sample.engine_args.get(engine, ())),
                "timeout_seconds": self.options.timeout_seconds,
            }
        )

    def _write_invalid_target(
        self, sample: Sample, engine: str, run_dir: Path, target: Path
    ) -> dict[str, Any]:
        result_path = run_dir / "result.json"
        record = {
            "schema_version": RUN_SCHEMA_VERSION,
            "benchmark": self.manifest.name,
            "sample_id": sample.id,
            "engine": engine,
            "status": "invalid",
            "analysis_status": None,
            "started_at": _utc_now(),
            "finished_at": _utc_now(),
            "duration_seconds": 0.0,
            "source": sample.source.as_dict(),
            "target": sample.target,
            "labels": dict(sample.labels),
            "metadata": dict(sample.metadata),
            "tool_version": None,
            "finding_count": None,
            "raw_output": None,
            "commands": [],
            "details": {},
            "error": f"target does not exist inside snapshot: {target}",
            "result_path": str(result_path.relative_to(self.output_dir)),
        }
        _atomic_json(result_path, record)
        return record

    def _write_source_failure(
        self, sample: Sample, exc: SourcePreparationError
    ) -> None:
        path = self.output_dir / "acquisition" / sample.id / "source.json"
        _atomic_json(
            path,
            {
                "kind": sample.source.kind,
                "status": "failed",
                "error": str(exc),
                "commands": [command.as_dict() for command in exc.commands],
            },
        )

    def _source_failure_record(
        self,
        sample: Sample,
        engine: str,
        exc: SourcePreparationError | None,
    ) -> dict[str, Any]:
        run_dir = self.output_dir / "runs" / sample.id / engine
        run_dir.mkdir(parents=True, exist_ok=True)
        result_path = run_dir / "result.json"
        record = {
            "schema_version": RUN_SCHEMA_VERSION,
            "benchmark": self.manifest.name,
            "sample_id": sample.id,
            "engine": engine,
            "status": "source_failed",
            "analysis_status": None,
            "started_at": _utc_now(),
            "finished_at": _utc_now(),
            "duration_seconds": 0.0,
            "source": sample.source.as_dict(),
            "target": sample.target,
            "labels": dict(sample.labels),
            "metadata": dict(sample.metadata),
            "tool_version": None,
            "finding_count": None,
            "raw_output": None,
            "commands": [
                command.as_dict() for command in (exc.commands if exc else ())
            ],
            "details": {},
            "error": str(exc or "source preparation failed"),
            "result_path": str(result_path.relative_to(self.output_dir)),
        }
        _atomic_json(result_path, record)
        return record


def load_engine_config(path: str | Path | None) -> dict[str, dict[str, Any]]:
    if path is None:
        return {}
    config_path = Path(path)
    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot load engine config {config_path}: {exc}") from exc
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError("engine config must be an object with schema_version 1")
    engines = data.get("engines", {})
    if not isinstance(engines, dict):
        raise ValueError("engine config 'engines' must be an object")
    result: dict[str, dict[str, Any]] = {}
    for name, value in engines.items():
        if not isinstance(name, str) or not isinstance(value, dict):
            raise ValueError("each engine configuration must be an object")
        result[name] = value
    return result


def _atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".tmp-{os.getpid()}")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(path)


def _json_digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _tree_digest(root: Path, *, excluded_root: Path | None = None) -> str:
    digest = hashlib.sha256()
    excluded = excluded_root.resolve() if excluded_root is not None else None
    if excluded is not None and not excluded.is_relative_to(root.resolve()):
        excluded = None
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if excluded is not None and (path == excluded or excluded in path.parents):
            continue
        relative = path.relative_to(root)
        if ".git" in relative.parts:
            continue
        try:
            file_stat = path.lstat()
        except OSError:
            continue
        digest.update(relative.as_posix().encode("utf-8", errors="surrogateescape"))
        digest.update(b"\0")
        digest.update(str(stat.S_IMODE(file_stat.st_mode)).encode())
        digest.update(b"\0")
        if path.is_symlink():
            digest.update(b"link\0")
            digest.update(os.readlink(path).encode("utf-8", errors="surrogateescape"))
        elif path.is_file():
            digest.update(b"file\0")
            try:
                with path.open("rb") as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        digest.update(chunk)
            except OSError:
                digest.update(b"unreadable")
        elif path.is_dir():
            digest.update(b"dir")
        digest.update(b"\0")
    return digest.hexdigest()


def _git_revision(root: Path) -> str | None:
    return _quiet_git(root, "rev-parse", "HEAD")


def _quiet_git(root: Path, *args: str) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), *args],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    value = completed.stdout.strip()
    return value or None


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
