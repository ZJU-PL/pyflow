from __future__ import annotations

import random

from pyflow.checker.supply_chain import scan_targets


def test_malformed_manifest_corpus_fails_closed_without_crashing(tmp_path):
    """Exercise every manifest dispatcher with deterministic hostile bytes."""

    generator = random.Random(20260723)
    names = (
        "requirements.txt",
        "pyproject.toml",
        "poetry.lock",
        "pdm.lock",
        "uv.lock",
        "Pipfile.lock",
        "pylock.toml",
        "setup.cfg",
        "setup.py",
    )
    expected_failure_kinds = {
        "invalid-requirement",
        "invalid-lockfile",
        "invalid-pyproject",
        "invalid-pylock",
        "invalid-setup-config",
        "invalid-setup-script",
    }
    observed: set[str] = set()
    for index, name in enumerate(names):
        path = tmp_path / f"case-{index}" / name
        path.parent.mkdir()
        path.write_bytes(generator.randbytes(257 + index * 31))

        scan = scan_targets([path])

        observed.update(finding.kind for finding in scan.findings)
        assert not scan.metadata["inventoryComplete"]

    assert observed & expected_failure_kinds
