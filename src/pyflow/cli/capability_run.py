"""Execute a Python entrypoint under the CPython capability audit guard."""

from __future__ import annotations

import json
from pathlib import Path
import sys

from pyflow.analysis.capability import (
    CapabilityViolation,
    RuntimeCapabilityPolicy,
    install_runtime_guard,
)


def add_capability_run_parser(subparsers) -> None:
    parser = subparsers.add_parser(
        "capability-run",
        help="Run Python code with a fail-closed capability allow list",
    )
    parser.add_argument("script", help="Python script to execute")
    parser.add_argument(
        "--allow",
        action="append",
        default=[],
        metavar="CAPABILITY",
        help="Allowed capability or glob (repeatable, for example file.read)",
    )
    parser.add_argument("--audit-log", type=Path, help="Write observed audit events as JSON")
    parser.add_argument("args", nargs="*", help="Arguments passed to the protected script")


def run_capability_guard(args) -> int:
    script = Path(args.script).resolve()
    try:
        source = script.read_text(encoding="utf-8")
        code = compile(source, str(script), "exec")
    except (OSError, SyntaxError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    policy = RuntimeCapabilityPolicy.allowing(args.allow)
    install_runtime_guard(policy)
    old_argv = sys.argv
    old_path = list(sys.path)
    sys.argv = [str(script), *args.args]
    sys.path.insert(0, str(script.parent))
    namespace = {
        "__name__": "__main__",
        "__file__": str(script),
        "__package__": None,
        "__cached__": None,
    }
    exit_code = 0
    try:
        exec(code, namespace, namespace)
    except CapabilityViolation as exc:
        print(f"Capability violation: {exc}", file=sys.stderr)
        exit_code = 126
    finally:
        sys.argv = old_argv
        sys.path[:] = old_path
        if args.audit_log:
            original_allowed = policy.allowed
            policy.allowed = frozenset((*original_allowed, "file.write"))
            payload = [
                {
                    "capability": event.capability,
                    "audit_event": event.audit_event,
                    "arguments": list(event.arguments),
                }
                for event in policy.events
            ]
            try:
                args.audit_log.write_text(
                    json.dumps(payload, indent=2) + "\n",
                    encoding="utf-8",
                )
            finally:
                policy.allowed = original_allowed
    return exit_code


__all__ = ["add_capability_run_parser", "run_capability_guard"]
