"""The application metrics leave the product as CloudWatch embedded metric format (EMF) log lines on standard error (standard output stays each command's result): one JSON
object per value, namespace ConsentVault, no dimensions, and nothing but the metric value and its timestamp. The log group
extracts them into the metrics the alarms read; no metric write permission is needed.

Each emitter sits in the code path that knows the value: the API's capture and gate routes, the seal job, the two
verify jobs, the key-lifecycle job and the isolation self-test."""

import io
import json
import re

import pytest

from consentvault import metrics

PHONE = "+15555550142"


def _parse(line):
    doc = json.loads(line)
    meta = doc["_aws"]
    assert isinstance(meta["Timestamp"], int) and meta["Timestamp"] > 1_600_000_000_000
    [directive] = meta["CloudWatchMetrics"]
    assert directive["Namespace"] == "ConsentVault" and directive["Dimensions"] == [[]]
    [m] = directive["Metrics"]
    assert set(m) == {"Name", "Unit"} and m["Unit"] in ("Count", "Milliseconds", "Seconds", "None")
    assert set(doc) == {"_aws", m["Name"]}, "an EMF line carries the metric and nothing else"
    v = doc[m["Name"]]
    vals = v if isinstance(v, list) else [v]
    assert vals and len(vals) <= 100 and all(isinstance(x, (int, float)) and not isinstance(x, bool) for x in vals)
    return m["Name"], doc[m["Name"]], m["Unit"]


@pytest.mark.parametrize("name,value,unit", [("CaptureErrors", 1, "Count"), ("Captures", 3, "Count"),
                                             ("GateLatencyMs", 12.5, "Milliseconds"),
                                             ("Gate503Count", 1, "Count"), ("UnsealedOldestAgeSeconds", 7200, "Seconds"),
                                             ("VerifyChainFailures", 2, "Count"), ("VerifySealsFailures", 0, "Count")])
def test_each_metric_is_one_valid_emf_line(name, value, unit):
    out = io.StringIO()
    metrics.emit(name, value, stream=out)
    [line] = out.getvalue().splitlines()
    assert _parse(line) == (name, value, unit)


def test_only_the_named_metrics_and_only_numbers_can_be_emitted():
    for bad_name in ("Contact", "org_id", PHONE):
        with pytest.raises(metrics.MetricError):
            metrics.emit(bad_name, 1, stream=io.StringIO())
    for bad_value in (PHONE, "1", None, True, float("nan"), float("inf")):
        with pytest.raises(metrics.MetricError):
            metrics.emit("Gate503Count", bad_value, stream=io.StringIO())


def _lines(out):
    return [json.loads(x) for x in out.getvalue().splitlines()]


def _values(out):
    found = {}
    for line in out.getvalue().splitlines():
        name, value, _ = _parse(line)
        found.setdefault(name, []).append(value)
    return found


def test_the_minute_window_summarises_capture_and_gate_requests_and_ignores_other_routes():
    w = metrics.RequestWindow()
    w.observe("/v1/events", 201, 30.0)
    w.observe("/v1/events", 503, 30.0)
    w.observe("/v1/events", 400, 30.0)  # a client's mistake is not a capture error
    w.observe("/v1/events", 200, 30.0)
    w.observe("/v1/permission", 200, 41.0)
    w.observe("/v1/permission:batch", 503, 900.0)
    w.observe("/v1/proof", 500, 5.0)
    out = io.StringIO()
    w.flush(stream=out)
    got = _values(out)
    assert got == {"CaptureErrors": [1], "Captures": [4], "Gate503Count": [1], "GateLatencyMs": [[41.0, 900.0]]}
    assert PHONE not in out.getvalue() and not re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-", out.getvalue())
    again = io.StringIO()
    w.flush(stream=again)  # the window starts over after each flush
    assert _values(again) == {"CaptureErrors": [0], "Captures": [0], "Gate503Count": [0], "GateLatencyMs": [[0]]}


def test_an_idle_minute_still_emits_all_three_as_zeros():
    out = io.StringIO()
    metrics.RequestWindow().flush(stream=out)
    assert _values(out) == {"CaptureErrors": [0], "Captures": [0], "Gate503Count": [0], "GateLatencyMs": [[0]]}


def test_a_busy_minute_keeps_every_latency_in_lines_of_at_most_one_hundred_values():
    w = metrics.RequestWindow()
    for i in range(250):
        w.observe("/v1/permission", 200, float(i))
    out = io.StringIO()
    w.flush(stream=out)
    lat = _values(out)["GateLatencyMs"]
    assert [len(x) for x in lat] == [100, 100, 50] and sorted(sum(lat, [])) == [float(i) for i in range(250)]


def test_the_ticker_flushes_every_interval_including_zeros_and_stops():
    import time

    out = io.StringIO()
    stop = metrics.start_ticker(metrics.RequestWindow(), interval_s=0.05, stream=out)
    time.sleep(0.4)
    stop()
    got = _values(out)
    assert len(got["Gate503Count"]) >= 3 and set(got["Gate503Count"]) == {0}
    assert len(got["CaptureErrors"]) == len(got["Captures"]) == len(got["Gate503Count"]) == len(got["GateLatencyMs"])
    n = len(out.getvalue().splitlines())
    time.sleep(0.2)
    assert len(out.getvalue().splitlines()) == n, "the ticker kept running after stop"


def test_serve_cloud_starts_the_ticker_before_serving_and_stops_it_after():
    from pathlib import Path

    from consentvault import cmd_cloud

    src = Path(cmd_cloud.__file__).read_text()
    assert src.index("metrics.start_ticker(") < src.index("server.serve_forever()") < src.index("stop_ticker()")


EXPECTED_SCHEMA = {  # name -> unit; the ops alarms read these exact names in namespace ConsentVault, no dimensions
    "CaptureErrors": "Count", "Captures": "Count", "GateLatencyMs": "Milliseconds", "Gate503Count": "Count",
    "UnsealedOldestAgeSeconds": "Seconds", "VerifyChainFailures": "Count", "VerifySealsFailures": "Count",
    "KeysPastRotationAge": "Count", "KeysOnOldVersion": "Count", "IsolationLeaks": "Count",
    "TwentyReconcileFailures": "Count", "TwentyHiddenStops": "Count"}


def test_the_metric_schema_is_exactly_what_the_alarms_read():
    assert metrics.NAMESPACE == "ConsentVault" and metrics.METRICS == EXPECTED_SCHEMA


def test_the_cloud_api_handler_reports_every_post_through_the_hook(monkeypatch):
    from consentvault import api

    seen = []
    monkeypatch.setattr(metrics.WINDOW, "observe", lambda path, status, ms: seen.append((path, status)))
    h = api._CloudHandler.__new__(api._CloudHandler)
    h.path = "/v1/permission"

    def fake(self):
        self._sent_status = 503
    monkeypatch.setattr(api._CloudHandler, "_do_post", fake)
    api._CloudHandler.do_POST(h)
    assert seen == [("/v1/permission", 503)]


def test_two_tasks_one_with_8_errors_in_100_and_one_idle_breach_the_capture_alarm():
    """CloudWatch sums each metric across the tasks' lines in the period; the alarm divides the sums (metric math,
    ops tofu/compute/alarms.tf). An idle task's zeros add nothing to either sum, so 8 in 100 reads 8 percent."""
    busy, idle = metrics.RequestWindow(), metrics.RequestWindow()
    for i in range(100):
        busy.observe("/v1/events", 503 if i < 8 else 201, 10.0)
    out = io.StringIO()
    busy.flush(stream=out)
    idle.flush(stream=out)
    for _ in range(3):  # the rest of the alarm's five-minute period: both tasks idle
        metrics.RequestWindow().flush(stream=out)
        metrics.RequestWindow().flush(stream=out)
    v = _values(out)
    errors, total = sum(v["CaptureErrors"]), sum(v["Captures"])
    rate = errors / total if total else 0
    assert (errors, total) == (8, 100) and rate == 0.08 and rate > 0.02  # breaches the 2 percent threshold
    per_line_average = sum(e / c if c else 0 for e, c in zip(v["CaptureErrors"], v["Captures"])) / len(v["Captures"])
    assert per_line_average < 0.02, "the old per-task average would have hidden it"


def test_a_ticker_whose_flush_fails_ends_the_process_so_the_task_is_replaced():
    import time

    died = []

    class Broken(metrics.RequestWindow):
        def flush(self, *, stream=None):
            raise OSError("stderr closed")
    stop = metrics.start_ticker(Broken(), interval_s=0.05, stream=io.StringIO(), die=died.append)
    time.sleep(0.3)
    assert died and died[0] != 0
    stop_ok = True
    try:
        stop()
    except OSError:
        stop_ok = False
    assert stop_ok is False  # the final flush fails loudly too


def test_the_default_on_ticker_death_is_to_exit_the_process():
    import inspect

    src = inspect.getsource(metrics.start_ticker)
    assert "os._exit" in src


def test_the_latency_buffer_is_capped_and_keeps_a_fair_sample():
    w = metrics.RequestWindow()
    n = metrics.MAX_LATENCIES_PER_WINDOW * 3
    for i in range(n):
        w.observe("/v1/permission", 200, float(i))
    out = io.StringIO()
    w.flush(stream=out)
    lat = sum(_values(out)["GateLatencyMs"], [])
    assert len(lat) == metrics.MAX_LATENCIES_PER_WINDOW
    assert max(lat) > n * 0.6 and min(lat) < n * 0.4, "a fair sample spans the whole minute, not just its start"
    assert _values(out)["Gate503Count"] == [0]
