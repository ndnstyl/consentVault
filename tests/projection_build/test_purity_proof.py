"""Build-order step 7: the proof of purity on two fresh databases, run with ``recorded_at`` (the database clock stamp the history table puts on
every row as it is written) left out of the fingerprint, the way the chain columns and the ciphertexts already are. A row written in two
different runs can never carry the same stamp, so a fingerprint that includes it cannot match by construction.

The test author's own fingerprint helper (tests/projection/support.py, CHAIN_COLUMNS) does not exclude it; the same assertion as the gate
test is made here with that one column added."""

import pytest
from projection import support
from projection.conftest import cloud  # noqa: F401
from projection.support import ALLOWED_KEY_CALLS, need_cutover, purity_run


@pytest.fixture(autouse=True)
def _exclude_the_clock_stamp(monkeypatch):
    monkeypatch.setattr(support, "CHAIN_COLUMNS", support.CHAIN_COLUMNS | {"recorded_at"})


def test_a_year_of_clock_and_different_lookups_change_no_history_row(cloud):
    for co in (cloud.a, cloud.b):
        assert cloud.grant(co, support.PHONE)[0] == 201
    cloud.call("/v1/events", {"contact": support.PHONE2, "event_type": "grant"}, token="not-a-token")
    store, first, second = purity_run(cloud)
    assert first.fingerprints and second.fingerprints == first.fingerprints == store.fingerprints
    assert set(first.key_calls) <= ALLOWED_KEY_CALLS
    assert first.evidence_calls == [] or all(c[0] in ("get", "read") for c in first.evidence_calls)
    assert first.sender_calls == [] and second.sender_calls == []
