# SPDX-FileCopyrightText: 2026 PyFlow Contributors
# SPDX-License-Identifier: MIT
"""Stub debug monitor for pointer analysis.

The original PythonStAn debug_monitor.py was not committed to the repository.
This stub provides a no-op implementation so the solver imports cleanly.
"""


class DebugMonitor:
    """No-op debug monitor for pointer analysis instrumentation."""

    def __init__(self, **kwargs) -> None:
        self.enabled = False
        self.track_object_flow = False
        self.track_pfg_activation = False

    def set_iteration(self, n: int) -> None:
        pass

    def record_iteration_snapshot(self, **kwargs) -> None:
        pass

    def record_object_allocated(self, **kwargs) -> None:
        pass

    def record_call_constraint_processed(self, **kwargs) -> None:
        pass

    def record_call_failed(self, **kwargs) -> None:
        pass

    def finalize(self) -> None:
        pass
