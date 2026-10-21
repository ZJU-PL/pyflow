"""Isolated CLI backends; the parent owns the hard wall-clock deadline."""

from __future__ import annotations

import gc
import json
import os
import signal
import subprocess
import sys
from contextlib import redirect_stdout


class CallgraphWorkerError(RuntimeError):
    pass


def run_isolated_callgraph(request: dict, *, timeout: float) -> str:
    """Run preparation, import resolution, analysis and rendering under one limit.

    Killing the process group also terminates children started by a backend.
    Nothing is written to the requested output file until a successful result
    has been received, so timeout cannot publish a truncated JSON document.
    """
    payload = json.dumps(request)
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "from pyflow.cli.callgraph_worker import main; raise SystemExit(main())",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=os.name == "posix",
    )
    try:
        stdout, stderr = process.communicate(payload, timeout=timeout)
    except (subprocess.TimeoutExpired, KeyboardInterrupt) as error:
        if os.name == "posix":
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:
            process.kill()
        process.communicate()
        if isinstance(error, KeyboardInterrupt):
            raise
        raise CallgraphWorkerError(
            f"Call graph analysis exceeded {timeout:g} seconds during preparation or analysis; "
            "the worker was terminated. Increase --max-seconds or narrow the input/import depth."
        ) from None
    if process.returncode:
        raise CallgraphWorkerError(
            stderr.strip() or f"Call graph worker exited with code {process.returncode}"
        )
    if stderr:
        sys.stderr.write(stderr)
    from pyflow.analysis.callgraph.formats import CallGraphOutput

    document = json.loads(stdout)
    return CallGraphOutput(document["output"], document["status"])


def main() -> int:
    try:
        request = json.load(sys.stdin)
        kwargs = {
            "verbose": request.get("verbose", False),
            "format": request.get("format", "text"),
            "project_root": request.get("project_root"),
            "max_import_depth": request.get("max_import_depth", 3),
        }
        with redirect_stdout(sys.stderr):
            if request["algorithm"] == "pycg":
                from pyflow.analysis.callgraph.pycg_based import analyze_file_pycg

                output = analyze_file_pycg(
                    request["filepath"],
                    **kwargs,
                )
            elif request["algorithm"] == "pycg-mir":
                from pyflow.analysis.callgraph.pycg_mir import analyze_file_pycg_mir

                output = analyze_file_pycg_mir(
                    request["filepath"],
                    import_policy=request.get("import_policy") or "opaque",
                    max_seconds=request["analysis_seconds"],
                    json_schema=request.get("json_schema", "legacy"),
                    **kwargs,
                )
            else:
                raise ValueError("Unsupported isolated callgraph backend")
        if output.startswith("Error analyzing "):
            print(output, file=sys.stderr)
            return 1
        json.dump(
            {"output": str(output), "status": getattr(output, "status", "complete")}, sys.stdout
        )
        sys.stdout.write("\n")
        return 0
    except Exception as error:
        print(str(error), file=sys.stderr)
        return 1
    finally:
        # Do not spend the remaining deadline collecting a discarded IR heap.
        gc.freeze()


if __name__ == "__main__":
    raise SystemExit(main())
