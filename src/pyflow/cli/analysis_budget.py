"""Wall-clock limits for synchronous CLI analysis on Unix."""

from contextlib import contextmanager
import math
import signal
import threading
from time import monotonic


class AnalysisBudgetExceeded(BaseException):
    """An analysis ran out of its explicitly configured CLI time budget."""


def positive_seconds(value):
    import argparse

    parsed = float(value)
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("must be finite and greater than zero")
    return parsed


def positive_iterations(value):
    import argparse

    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


@contextmanager
def analysis_time_budget(seconds):
    """Interrupt CLI work, restoring any caller's existing alarm afterward.

    Unix main-thread callers get a timer that also covers frontend work.
    Other callers get an elapsed-time check on completion; their engines
    still need cooperative state/iteration limits for early termination.
    """
    started = monotonic()
    use_alarm = (
        hasattr(signal, "setitimer") and threading.current_thread() is threading.main_thread()
    )
    if not use_alarm:
        yield
        if monotonic() - started >= seconds:
            raise AnalysisBudgetExceeded(f"Analysis exceeded {seconds:g} seconds")
        return
    previous_handler = signal.getsignal(signal.SIGALRM)
    previous_delay, previous_interval = signal.getitimer(signal.ITIMER_REAL)
    # Respect an earlier caller-owned alarm rather than replacing its deadline.
    caller_first = previous_delay > 0 and previous_delay <= seconds
    caller_fired = False

    def expire(signum, frame):
        nonlocal caller_fired
        if caller_first and not caller_fired:
            caller_fired = True
            if callable(previous_handler):
                previous_handler(signum, frame)
                signal.setitimer(signal.ITIMER_REAL, max(1e-6, seconds - (monotonic() - started)))
                return
            if previous_handler == signal.SIG_IGN:
                signal.setitimer(signal.ITIMER_REAL, max(1e-6, seconds - (monotonic() - started)))
                return
        raise AnalysisBudgetExceeded(f"Analysis exceeded {seconds:g} seconds")

    signal.signal(signal.SIGALRM, expire)
    signal.setitimer(signal.ITIMER_REAL, min(seconds, previous_delay) if caller_first else seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        if previous_delay and (not caller_fired or previous_interval):
            remaining = previous_delay - (monotonic() - started)
            if previous_interval and remaining <= 0:
                remaining %= previous_interval
            signal.setitimer(signal.ITIMER_REAL, max(1e-6, remaining), previous_interval)
