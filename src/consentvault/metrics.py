"""The application metrics, written as CloudWatch embedded metric format (EMF) log lines on standard error.

Standard output stays each command's one-line JSON result. In the cloud every task's standard error goes to its
CloudWatch log group (the awslogs driver ships both streams), which extracts each EMF line into a metric
in the ConsentVault namespace (the alarms in the ops repository read those). Writing a log line needs no metric write
permission, so the internet-facing API role holds none.

Only the names in ``METRICS`` can be written, and only a finite number: a line carries the metric's value and its
timestamp and nothing else (no organisation, no contact, no request detail), by construction.
"""

from __future__ import annotations

import json
import math
import os
import random
import sys
import threading
import time
from typing import TextIO

from .errors import ConsentVaultError

NAMESPACE = "ConsentVault"

# name -> CloudWatch unit. Each is emitted from the code path that knows the value.
METRICS = {
    "CaptureErrors": "Count",            # api: captures answered 5xx this minute (the alarm divides the sums)
    "Captures": "Count",                 # api: captures answered this minute
    "GateLatencyMs": "Milliseconds",     # api: one per gate request (the alarm reads p99)
    "Gate503Count": "Count",             # api: 1 for a gate request answered 503, else 0
    "UnsealedOldestAgeSeconds": "Seconds",  # seal job: the oldest event still waiting for its seal
    "VerifyChainFailures": "Count",      # verify-chain job: organisations (or the one ledger) with a break
    "VerifySealsFailures": "Count",      # verify-seals job: organisations (or the one ledger) with a failed seal
    "KeysPastRotationAge": "Count",      # key-lifecycle job: active organisation keys still past their rotation age
    "KeysOnOldVersion": "Count",         # key-lifecycle job: retired key versions with anything still wrapped under them
    "IsolationLeaks": "Count",           # isolation-self-test job: findings (a row read across organisations, a table unprobed)
    "TwentyReconcileFailures": "Count",  # twenty-reconcile job: Twenty systems whose reconcile did not complete this pass
    "TwentyHiddenStops": "Count",        # twenty-reconcile job: corrections that uncovered a stop (each also an alarm row)
}

CAPTURE_PATHS = ("/v1/events",)
GATE_PATHS = ("/v1/permission", "/v1/permission:batch")


class MetricError(ConsentVaultError):
    """A metric name that is not one of METRICS, or a value that is not a finite number."""


def line(name: str, value: float, *, now_ms: int | None = None) -> str:
    unit = METRICS.get(name)
    if unit is None:
        raise MetricError(f"not an application metric: {name!r}")
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise MetricError(f"metric {name} needs a finite number")
    return json.dumps({"_aws": {"Timestamp": now_ms if now_ms is not None else int(time.time() * 1000),
                                "CloudWatchMetrics": [{"Namespace": NAMESPACE, "Dimensions": [[]],
                                                       "Metrics": [{"Name": name, "Unit": unit}]}]},
                       name: value}, separators=(",", ":"), sort_keys=True)


def emit(name: str, value: float, *, stream: TextIO | None = None) -> None:
    out = stream if stream is not None else sys.stderr
    out.write(line(name, value) + "\n")
    out.flush()


MAX_VALUES_PER_LINE = 100  # an embedded-metric line carries at most 100 values for one metric
MAX_LATENCIES_PER_WINDOW = 3000  # per task per minute; beyond it a uniform sample of the minute is kept (reservoir)
TICK_SECONDS = 60


def emit_values(name: str, values: list, *, stream: TextIO | None = None) -> None:
    """One metric with many values (CloudWatch computes percentiles over them), at most 100 per line."""
    if not values:
        raise MetricError(f"metric {name} needs at least one value")
    for i in range(0, len(values), MAX_VALUES_PER_LINE):
        chunk = values[i:i + MAX_VALUES_PER_LINE]
        for v in chunk:
            line(name, v)  # validates each value
        doc = json.loads(line(name, chunk[0]))
        doc[name] = chunk
        out = stream if stream is not None else sys.stderr
        out.write(json.dumps(doc, separators=(",", ":"), sort_keys=True) + "\n")
        out.flush()


class RequestWindow:
    """The API's request outcomes for the current minute. ``flush`` writes the summary and starts over; an idle minute
    is written as zeros, so a metric that stops arriving means the pipeline broke (the alarms treat missing as red)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._rng = random.Random()
        self._reset()

    def _reset(self) -> None:
        self._captures = self._capture_errors = self._gate_503 = self._gates = 0
        self._latencies: list[float] = []

    def observe(self, path: str, status: int | None, elapsed_ms: float) -> None:
        failed = status is None or status >= 500  # no answer at all counts as a server error
        with self._lock:
            if path in CAPTURE_PATHS:
                self._captures += 1
                self._capture_errors += 1 if failed else 0
            elif path in GATE_PATHS:
                self._gates += 1
                ms = round(elapsed_ms, 3)
                if len(self._latencies) < MAX_LATENCIES_PER_WINDOW:
                    self._latencies.append(ms)
                else:  # bounded memory: a uniform sample of every request this minute (reservoir sampling)
                    slot = self._rng.randrange(self._gates)
                    if slot < MAX_LATENCIES_PER_WINDOW:
                        self._latencies[slot] = ms
                self._gate_503 += 1 if (status is None or status == 503) else 0

    def flush(self, *, stream: TextIO | None = None) -> None:
        with self._lock:
            captures, errors, g503, lat = self._captures, self._capture_errors, self._gate_503, self._latencies
            self._reset()
        # Counts, not a rate: CloudWatch sums each across every task's lines, and the alarm divides the sums, so an idle
        # task's zeros never dilute a busy one's errors.
        emit("CaptureErrors", errors, stream=stream)
        emit("Captures", captures, stream=stream)
        emit("Gate503Count", g503, stream=stream)
        emit_values("GateLatencyMs", lat or [0], stream=stream)


WINDOW = RequestWindow()


def observe_request(path: str, status: int | None, elapsed_ms: float) -> None:
    """The API's hook after every POST: recorded in the current minute's window (written by the ticker)."""
    WINDOW.observe(path, status, elapsed_ms)


EXIT_TICKER_DIED = 70


def _exit_process(code: int) -> None:
    os._exit(code)


def start_ticker(window: RequestWindow | None = None, *, interval_s: float = TICK_SECONDS,
                 stream: TextIO | None = None, die=_exit_process):
    """Flush ``window`` every ``interval_s`` seconds on a daemon thread; returns a stop function that writes the last
    window and joins the thread. A flush that fails is printed and the whole process exits (``die``, default
    ``os._exit(70)``): ECS replaces the task, and the gap in the metrics (missing data is breaching) shows red."""
    w = window if window is not None else WINDOW
    stopping = threading.Event()

    def run() -> None:
        while not stopping.wait(interval_s):
            try:
                w.flush(stream=stream)
            except Exception as exc:  # loud-failure-exempt: printed, then the process exits so ECS replaces the task
                print(f"consentvault: the metrics ticker failed ({type(exc).__name__}); exiting so the task is "
                      "replaced", file=sys.stderr, flush=True)
                die(EXIT_TICKER_DIED)
                return

    thread = threading.Thread(target=run, name="consentvault-metrics", daemon=True)
    thread.start()

    def stop() -> None:
        stopping.set()
        thread.join(timeout=interval_s + 5)
        w.flush(stream=stream)
    return stop
