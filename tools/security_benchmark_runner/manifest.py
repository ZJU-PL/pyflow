"""Versioned input manifest for repository-level analyzer benchmarks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Mapping


SCHEMA_VERSION = 1
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,191}$")


class ManifestError(ValueError):
    """Raised when a benchmark manifest violates the versioned contract."""


@dataclass(frozen=True)
class SourceSpec:
    """Location of one immutable or locally managed source snapshot."""

    kind: str
    path: str | None = None
    url: str | None = None
    revision: str | None = None

    @classmethod
    def from_dict(cls, value: object, *, sample_id: str) -> "SourceSpec":
        data = _object(value, f"sample {sample_id!r} source")
        kind = _string(data.get("kind"), f"sample {sample_id!r} source.kind")
        if kind == "local":
            path = _string(data.get("path"), f"sample {sample_id!r} source.path")
            return cls(kind=kind, path=path)
        if kind == "git":
            url = _string(data.get("url"), f"sample {sample_id!r} source.url")
            revision = _string(
                data.get("revision"), f"sample {sample_id!r} source.revision"
            )
            return cls(kind=kind, url=url, revision=revision)
        raise ManifestError(
            f"sample {sample_id!r} source.kind must be 'local' or 'git'"
        )

    def as_dict(self) -> dict[str, Any]:
        if self.kind == "local":
            return {"kind": "local", "path": self.path}
        return {"kind": "git", "url": self.url, "revision": self.revision}


@dataclass(frozen=True)
class Sample:
    """One independent analyzer input.

    ``labels`` and ``metadata`` deliberately have no prescribed vulnerability
    semantics, so the same runner can consume security and non-security corpora.
    """

    id: str
    source: SourceSpec
    target: str = "."
    labels: Mapping[str, Any] = field(default_factory=dict)
    metadata: Mapping[str, Any] = field(default_factory=dict)
    engine_args: Mapping[str, tuple[str, ...]] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, value: object, *, index: int) -> "Sample":
        data = _object(value, f"samples[{index}]")
        sample_id = _string(data.get("id"), f"samples[{index}].id")
        if not _SAFE_ID.fullmatch(sample_id):
            raise ManifestError(
                f"sample id {sample_id!r} must match {_SAFE_ID.pattern}"
            )
        target = data.get("target", ".")
        target = _string(target, f"sample {sample_id!r} target")
        _validate_relative_target(target, sample_id)
        labels = _json_object(data.get("labels", {}), f"sample {sample_id!r} labels")
        metadata = _json_object(
            data.get("metadata", {}), f"sample {sample_id!r} metadata"
        )
        engine_args_raw = _object(
            data.get("engine_args", {}), f"sample {sample_id!r} engine_args"
        )
        engine_args: dict[str, tuple[str, ...]] = {}
        for engine, args in engine_args_raw.items():
            if not isinstance(engine, str) or not engine:
                raise ManifestError(
                    f"sample {sample_id!r} engine_args keys must be strings"
                )
            if not isinstance(args, list) or not all(
                isinstance(arg, str) for arg in args
            ):
                raise ManifestError(
                    f"sample {sample_id!r} engine_args[{engine!r}] "
                    "must be a list of strings"
                )
            engine_args[engine] = tuple(args)
        return cls(
            id=sample_id,
            source=SourceSpec.from_dict(data.get("source"), sample_id=sample_id),
            target=target,
            labels=labels,
            metadata=metadata,
            engine_args=engine_args,
        )

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "id": self.id,
            "source": self.source.as_dict(),
            "target": self.target,
        }
        if self.labels:
            result["labels"] = dict(self.labels)
        if self.metadata:
            result["metadata"] = dict(self.metadata)
        if self.engine_args:
            result["engine_args"] = {
                engine: list(args) for engine, args in self.engine_args.items()
            }
        return result


@dataclass(frozen=True)
class BenchmarkManifest:
    """Validated collection of independent benchmark samples."""

    name: str
    samples: tuple[Sample, ...]
    metadata: Mapping[str, Any] = field(default_factory=dict)
    schema_version: int = SCHEMA_VERSION
    base_dir: Path = field(default_factory=Path.cwd, compare=False, repr=False)

    @classmethod
    def load(cls, path: str | Path) -> "BenchmarkManifest":
        manifest_path = Path(path).resolve()
        try:
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise ManifestError(f"cannot read manifest {manifest_path}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise ManifestError(f"invalid JSON in {manifest_path}: {exc}") from exc
        return cls.from_dict(data, base_dir=manifest_path.parent)

    @classmethod
    def from_dict(
        cls, value: object, *, base_dir: str | Path | None = None
    ) -> "BenchmarkManifest":
        data = _object(value, "manifest")
        version = data.get("schema_version")
        if version != SCHEMA_VERSION:
            raise ManifestError(
                f"unsupported schema_version {version!r}; expected {SCHEMA_VERSION}"
            )
        name = _string(data.get("name"), "manifest.name")
        raw_samples = data.get("samples")
        if not isinstance(raw_samples, list):
            raise ManifestError("manifest.samples must be a list")
        samples = tuple(
            Sample.from_dict(sample, index=index)
            for index, sample in enumerate(raw_samples)
        )
        ids = [sample.id for sample in samples]
        duplicates = sorted(
            {sample_id for sample_id in ids if ids.count(sample_id) > 1}
        )
        if duplicates:
            raise ManifestError(f"duplicate sample ids: {', '.join(duplicates)}")
        metadata = _json_object(data.get("metadata", {}), "manifest.metadata")
        return cls(
            name=name,
            samples=samples,
            metadata=metadata,
            base_dir=Path(base_dir or Path.cwd()).resolve(),
        )

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "schema_version": self.schema_version,
            "name": self.name,
            "samples": [sample.as_dict() for sample in self.samples],
        }
        if self.metadata:
            result["metadata"] = dict(self.metadata)
        return result

    def write(self, path: str | Path) -> None:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            json.dumps(self.as_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


def _validate_relative_target(target: str, sample_id: str) -> None:
    path = PurePosixPath(target.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts:
        raise ManifestError(
            f"sample {sample_id!r} target must stay within its source snapshot"
        )


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ManifestError(f"{label} must be a JSON object")
    return value


def _json_object(value: object, label: str) -> dict[str, Any]:
    data = _object(value, label)
    try:
        json.dumps(data)
    except (TypeError, ValueError) as exc:
        raise ManifestError(f"{label} must contain JSON-compatible values") from exc
    return data


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ManifestError(f"{label} must be a non-empty string")
    return value
