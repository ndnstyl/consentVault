"""The test database setup explains its failures: a taken port is retried on a new one, a slow or failed start prints the
server log and names the port, the elapsed time and the deadline."""

import shutil
import socket
import subprocess
import tempfile
from pathlib import Path

import pytest

import conftest as c


@pytest.fixture
def cluster():
    bindir = c._pg_bin()
    root = Path(tempfile.mkdtemp(prefix="consentvault-pgsetup-"))
    c.claim_cluster(root)
    data = root / "data"
    subprocess.run([str(bindir / "initdb"), "-D", str(data), "-U", "postgres", "-A", "trust", "-E", "UTF8", "--locale=C"],
                   check=True, capture_output=True)
    yield bindir, root, data
    subprocess.run([str(bindir / "pg_ctl"), "stop", "-m", "immediate", "-D", str(data)], capture_output=True)  # loud-failure-exempt: teardown of a server that may never have started
    shutil.rmtree(root, ignore_errors=True)


def test_a_forced_port_clash_is_retried_on_a_new_port(cluster, capsys):
    bindir, root, data = cluster
    with socket.socket() as taken:
        taken.bind(("127.0.0.1", 0))
        taken.listen(1)
        clash = taken.getsockname()[1]
        ports = iter([clash, c._free_port()])
        port = c.start_cluster(bindir, root, data, pick_port=lambda: next(ports))
    assert port != clash
    err = capsys.readouterr().err
    assert "postgres start failed" in err and "Address already in use" in err  # the first attempt's log was shown
    with socket.create_connection(("127.0.0.1", port), timeout=5):
        pass


def test_a_clash_on_every_attempt_fails_with_the_port_the_time_and_the_log(cluster, capsys):
    bindir, root, data = cluster
    with socket.socket() as taken:
        taken.bind(("127.0.0.1", 0))
        taken.listen(1)
        clash = taken.getsockname()[1]
        with pytest.raises(RuntimeError) as e:
            c.start_cluster(bindir, root, data, pick_port=lambda: clash)
    msg = str(e.value)
    assert f"port {clash}" in msg and "after " in msg and "attempt 2/2" in msg and "startup deadline 60s" in msg
    assert "Address already in use" in capsys.readouterr().err


def test_a_forced_slow_start_names_the_deadline_prints_the_log_and_is_not_retried(tmp_path, capsys):
    root = tmp_path
    (root / "pg.log").write_text("LOG:  still recovering, 61 seconds in\n")
    calls = []

    def slow(cmd, **kw):
        calls.append(cmd)
        raise subprocess.CalledProcessError(1, cmd, output="", stderr="pg_ctl: server did not start in time\n")

    with pytest.raises(RuntimeError) as e:
        c.start_cluster(Path("/nonexistent"), root, root / "data", deadline=60, pick_port=lambda: 54999, run=slow)
    msg = str(e.value)
    assert "port 54999" in msg and "after " in msg and "startup deadline 60s" in msg
    assert "still not accepting connections at the 60s startup deadline" in msg
    assert len(calls) == 1  # a slow start is not a port clash: no second try
    err = capsys.readouterr().err
    assert "still recovering, 61 seconds in" in err and "server did not start in time" in err


def test_a_pg_ctl_that_never_answers_fails_at_its_own_deadline(tmp_path, capsys):
    def hang(cmd, **kw):
        assert kw["timeout"] == 3 + 30
        raise subprocess.TimeoutExpired(cmd, kw["timeout"])

    with pytest.raises(RuntimeError) as e:
        c.start_cluster(Path("/nonexistent"), tmp_path, tmp_path / "data", deadline=3, pick_port=lambda: 54998, run=hang)
    assert "port 54998" in str(e.value) and "3s startup deadline" in str(e.value)
    assert "postgres start failed" in capsys.readouterr().err


def test_a_server_whose_test_run_is_gone_is_stopped_and_removed_by_the_next_sweep(cluster):
    """pg_ctl daemonizes the server, so a test run killed before its teardown leaves it running; the next run's sweep stops it."""
    bindir, root, data = cluster
    port = c.start_cluster(bindir, root, data)
    gone = subprocess.Popen(["true"])
    gone.wait()
    (root / c.OWNER_FILE).write_text(str(gone.pid))
    assert str(root) in c.sweep_stale_clusters(bindir, root.parent)
    assert not root.exists()
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", port), timeout=2).close()


def test_a_server_whose_test_run_is_alive_is_left_running(cluster):
    bindir, root, data = cluster
    port = c.start_cluster(bindir, root, data)
    assert str(root) not in c.sweep_stale_clusters(bindir, root.parent)
    with socket.create_connection(("127.0.0.1", port), timeout=5):
        pass
