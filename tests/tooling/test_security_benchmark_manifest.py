from __future__ import annotations

import pytest

from tools.security_benchmark_runner.manifest import BenchmarkManifest, ManifestError


def test_manifest_accepts_local_and_git_samples(tmp_path):
    manifest = BenchmarkManifest.from_dict(
        {
            "schema_version": 1,
            "name": "mixed",
            "samples": [
                {
                    "id": "local-one",
                    "source": {"kind": "local", "path": "corpus/one"},
                    "labels": {"group": "a"},
                },
                {
                    "id": "git-one",
                    "source": {
                        "kind": "git",
                        "url": "https://example.invalid/repo.git",
                        "revision": "0123456789abcdef",
                    },
                    "target": "src",
                    "engine_args": {"pyflow-ifds": ["--entry", "app.py"]},
                },
            ],
        },
        base_dir=tmp_path,
    )

    assert manifest.name == "mixed"
    assert manifest.samples[0].source.kind == "local"
    assert manifest.samples[1].engine_args["pyflow-ifds"] == (
        "--entry",
        "app.py",
    )


@pytest.mark.parametrize("target", ["../outside", "/absolute", "src/../../outside"])
def test_manifest_rejects_targets_outside_snapshot(target):
    with pytest.raises(ManifestError, match="within its source snapshot"):
        BenchmarkManifest.from_dict(
            {
                "schema_version": 1,
                "name": "bad",
                "samples": [
                    {
                        "id": "bad-target",
                        "source": {"kind": "local", "path": "."},
                        "target": target,
                    }
                ],
            }
        )


def test_manifest_rejects_duplicate_ids():
    sample = {"id": "duplicate", "source": {"kind": "local", "path": "."}}
    with pytest.raises(ManifestError, match="duplicate sample ids"):
        BenchmarkManifest.from_dict(
            {
                "schema_version": 1,
                "name": "bad",
                "samples": [sample, sample],
            }
        )
