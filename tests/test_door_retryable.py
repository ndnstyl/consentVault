import psycopg
import pytest

from consentvault import door
from consentvault.errors import LedgerError
from consentvault.providers.errors import EvidenceStoreError
from consentvault.tenancy.pipeline import EvidenceStoreUnavailable


def _chain(outer, cause):
    try:
        try:
            raise cause
        except Exception as exc:
            raise outer from exc
    except Exception as exc:
        return exc


def test_an_evidence_store_outage_is_a_passing_fault():
    exc = _chain(EvidenceStoreUnavailable("the evidence store did not take object x: EvidenceStoreError"), EvidenceStoreError("HTTP 503"))
    assert door.retryable(exc) is True


@pytest.mark.parametrize("cause", [psycopg.errors.SerializationFailure("x"), psycopg.errors.DeadlockDetected("x"),
                                   psycopg.errors.AdminShutdown("x"), psycopg.errors.ConnectionFailure("x"),
                                   psycopg.OperationalError("server closed the connection")])
def test_database_connection_and_rollback_faults_pass(cause):
    assert door.retryable(_chain(LedgerError("refused"), cause)) is True


@pytest.mark.parametrize("cause", [psycopg.errors.ProgramLimitExceeded("index row too large"), psycopg.errors.QueryCanceled("timeout"),
                                   FileNotFoundError("gone"), TimeoutError("slow"), TypeError("bad"), ValueError("bad")])
def test_a_size_limit_a_timeout_a_missing_file_or_a_bad_type_is_final_for_that_post(cause):
    assert door.retryable(_chain(LedgerError("refused"), cause)) is False
