"""No decision the projection makes reads live configuration (one-door review rounds 5, 6 and 7: each found one critical of the
same class, a decision during projection that read live configuration or state instead of facts stored at arrival).

This test enumerates every read of a table in the modules the projection runs through, function by function, and fails when

* a read is not in ``READS`` (a new read must be classified here, in review, before it ships), or
* a read is classed ``live_decision`` (a decision from live configuration; there must be none), or
* an entry in ``READS`` no longer exists (the list is kept honest), or
* a function that reads the organisation's live configuration (``ARRIVAL_ONLY``) is called from anywhere but the arrival snapshot.

Classes:
  post_and_facts      the post, the facts stored beside it, its attempts and its link to an event
  derived_record      the event chain and the records derived from it (the write target, or a lookup of what was already written)
  immutable_wording   a disclosure looked up by the hash of its text: wording is immutable, so the answer never changes
  arrival_snapshot    live configuration read ONLY at arrival, to be stored beside the post (never during projection)
  downstream_effect   what is queued for connected systems after the event is decided; it decides nothing about the event
  operational_state   whether the organisation is closed, the retention date of the evidence: retried, never a final reason, and
                      neither decides whether an event exists
  contact_key         the keys the event's personal data is sealed under (derived, created on first use)
"""

import ast
import re
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "consentvault"
MODULES = ("door.py", "tenancy/pipeline.py", "ledger.py", "records.py", "sync/outbox.py", "disclosure.py")
READ = re.compile(r"\b(?:FROM|JOIN|UPDATE|INTO)\s+(?:ONLY\s+)?(?:consentvault\.)?([a-z_][a-z_0-9]*)\b(\()?", re.I)

READS = {
    # the projection itself (door.py)
    ("door.py", "_already", "event_source_post"): "post_and_facts",
    ("door.py", "_attempt", "projection_attempt"): "post_and_facts",
    ("door.py", "_first_attempt_age", "projection_attempt"): "post_and_facts",
    ("door.py", "backfill_request_keys", "raw_post_fact"): "post_and_facts",
    ("door.py", "backfill_request_keys", "raw_post_request"): "post_and_facts",
    ("door.py", "event_by_id", "event"): "derived_record",
    ("door.py", "link", "event_source_post"): "post_and_facts",
    ("door.py", "project_pending", "event_source_post"): "post_and_facts",
    ("door.py", "project_pending", "projection_attempt"): "post_and_facts",
    ("door.py", "project_pending", "raw_post"): "post_and_facts",
    ("door.py", "project_pending", "raw_post_fact"): "post_and_facts",
    ("door.py", "project_text_reply", "event_source_post"): "post_and_facts",
    # the capture pipeline (tenancy/pipeline.py)
    ("tenancy/pipeline.py", "_check_disclosure", "disclosure"): "immutable_wording",
    ("tenancy/pipeline.py", "capture", "evidence_object"): "derived_record",
    ("tenancy/pipeline.py", "capture", "receipt_of()"): "derived_record",
    ("tenancy/pipeline.py", "contact_key", "contact_key"): "contact_key",
    ("tenancy/pipeline.py", "contact_key", "contact_key_of()"): "contact_key",
    ("tenancy/pipeline.py", "org_channels", "channel"): "arrival_snapshot",
    ("tenancy/pipeline.py", "org_purposes", "purpose"): "arrival_snapshot",
    ("tenancy/pipeline.py", "org_region", "organization"): "arrival_snapshot",
    ("tenancy/pipeline.py", "org_status", "organization"): "operational_state",
    ("tenancy/pipeline.py", "projection_settings", "brand"): "arrival_snapshot",
    ("tenancy/pipeline.py", "projection_settings", "capture_source"): "arrival_snapshot",
    ("tenancy/pipeline.py", "projection_settings", "credential"): "arrival_snapshot",
    ("tenancy/pipeline.py", "reconcile_uncommitted", "evidence_object"): "derived_record",
    ("tenancy/pipeline.py", "retention_until", "retention_policy"): "operational_state",
    # the ledger append (ledger.py)
    ("ledger.py", "<module>", "event"): "derived_record",
    ("ledger.py", "_insert_event_sql", "event"): "derived_record",
    ("ledger.py", "_plaintext_breaks", "contact_key"): "contact_key",
    ("ledger.py", "_plaintext_breaks", "erasure_coverage"): "derived_record",
    ("ledger.py", "_plaintext_breaks", "erasure_request"): "derived_record",
    ("ledger.py", "record_tenant_event", "contact_key"): "contact_key",
    ("ledger.py", "record_tenant_event", "contact_key_of()"): "contact_key",
    ("ledger.py", "record_tenant_event", "ledger_head()"): "derived_record",
    ("ledger.py", "verify_chain", "chain_head"): "derived_record",
    ("ledger.py", "verify_chain", "event"): "derived_record",
    # the wording lookup by hash (disclosure.py)
    ("disclosure.py", "get", "disclosure"): "immutable_wording",
    ("disclosure.py", "register", "disclosure"): "immutable_wording",
    # what is queued for connected systems once the event is decided (sync/outbox.py)
    ("sync/outbox.py", "_echo_targets", "sync_echo_targets()"): "downstream_effect",
    ("sync/outbox.py", "enqueue_event_pushes", "sync_advance_state()"): "downstream_effect",
    ("sync/outbox.py", "enqueue_event_pushes", "sync_targets()"): "downstream_effect",
}
NOT_TABLES = {"a", "the", "p"}   # words inside prose comments or aliases of the queries above

# Readers of the organisation's live configuration: only the arrival snapshot may call them.
ARRIVAL_ONLY = {"org_region", "org_channels", "org_purposes"}
ARRIVAL_CALLERS = {"projection_settings", "org_region", "org_channels", "org_purposes"}


def _found() -> set[tuple[str, str, str]]:
    out = set()
    for m in MODULES:
        tree = ast.parse((SRC / m).read_text())

        def walk(node, fn):
            for ch in ast.iter_child_nodes(node):
                if isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    walk(ch, ch.name)
                    continue
                if isinstance(ch, ast.Constant) and isinstance(ch.value, str) and re.search(r"\b(SELECT|INSERT|UPDATE)\b", ch.value):
                    for table, call in READ.findall(ch.value):
                        if table not in NOT_TABLES:
                            out.add((m, fn, table + ("()" if call else "")))
                walk(ch, fn)

        walk(tree, "<module>")
    return out


def test_every_read_of_a_table_during_projection_is_classified():
    found = _found()
    unclassified = sorted(found - set(READS))
    assert not unclassified, f"a read of a table the projection runs through is not classified in READS: {unclassified}"
    stale = sorted(set(READS) - found)
    assert not stale, f"READS lists reads that no longer exist: {stale}"


def test_no_decision_reads_live_configuration():
    live = sorted(k for k, v in READS.items() if v == "live_decision")
    assert not live, f"decisions from live configuration: {live}"


def test_the_live_configuration_readers_are_called_only_from_the_arrival_snapshot():
    callers = []
    for m in MODULES + ("api.py",):
        tree = ast.parse((SRC / m).read_text())
        for fn in ast.walk(tree):
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for node in ast.walk(fn):
                    if isinstance(node, ast.Call):
                        name = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
                        if name in ARRIVAL_ONLY and fn.name not in ARRIVAL_CALLERS:
                            callers.append((m, fn.name, name))
    assert not callers, f"a projection step reads live configuration: {callers}"


def test_the_pipeline_has_no_live_fallback_for_the_arrival_settings():
    """The checks take the settings stored at arrival or refuse by name; none falls back to the live tables, and the old
    fallback is gone."""
    src = (SRC / "tenancy" / "pipeline.py").read_text()
    tree = ast.parse(src)
    functions = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    assert "_check_source_and_brands" not in functions
    for name in ("check_channel_purpose", "check_source_from_settings", "settings_complete"):
        body = ast.get_source_segment(src, functions[name])
        assert "conn.execute" not in body and "org_channels(" not in body and "org_purposes(" not in body \
            and "org_region(" not in body, f"{name} still reads live configuration"
