"""Command-line validation for shipped IFDS rule packs."""

from __future__ import annotations

import json
import sys

from .loader import validate_registry


def main(argv: list[str] | None = None) -> int:
    argv = argv or []
    issues = validate_registry()
    if "--json" in argv:
        print(
            json.dumps(
                [
                    {
                        "path": issue.path,
                        "message": issue.message,
                        "severity": issue.severity,
                    }
                    for issue in issues
                ],
                indent=2,
            )
        )
    else:
        for issue in issues:
            print(f"{issue.severity}: {issue.path}: {issue.message}")
        if not issues:
            print("All IFDS rule packs are valid.")
    return 1 if issues else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
