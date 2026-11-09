"""No decision the projection makes reads live configuration (one-door review rounds 5, 6, 7 and 8: each found one critical of the
same class, a decision during projection that read live configuration or state instead of facts stored at arrival).

The guard scans EVERY module `project_view` can reach (door.py and everything it imports, transitively, plus api.py's intake), and
in each function every string that names a `consentvault.` table, view or SQL function, however the query is built (fragments of a
concatenated or formatted query are separate strings and are each scanned). It fails when

* a name is not in ``READS`` with a class (a new read must be classified here, in review, before it ships);
* a read is classed ``live_decision`` (there must be none);
* an entry in ``READS`` no longer exists (the list is kept honest);
* a reader of live configuration (``ARRIVAL_ONLY``) is called from anywhere but its named intake caller;
* the database's triggers on the event, evidence and link tables are not exactly the listed ones (a trigger reads whatever it
  likes, so a new one must be listed here, in review).

``test_the_guard_catches_the_round_five_to_seven_bug_reintroduced`` re-adds the reads that earlier rounds shipped, into a copy of the
source, and requires the guard to fail on each, so the guard cannot go quiet unnoticed.

Classes:
  post_and_facts      the post, the facts stored beside it, its attempts and its link to an event
  derived_record      the event chain and what is derived from it (the write target, or a lookup of what was already written)
  immutable_wording   a disclosure looked up by the hash of its text: wording is immutable, so the answer never changes
  arrival_snapshot    live configuration read ONLY at arrival, to be stored beside the post (never during projection)
  arrival_identity    which credential and organisation a site key belongs to, with the times it was revoked or its source retired
  downstream_effect   what is queued for connected systems after the event is decided; it decides nothing about the event
  operational_state   whether the organisation is closed, the retention date of the evidence: retried, never a final reason
  contact_key         the keys the event's personal data is sealed under (derived, created on first use)
  plumbing            the entered organisation, locks and the database's own identity helpers
  outside_projection  reached by import only (audit, replay guard, token issue): not called by the projection
"""

import ast
import re
import shutil
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src" / "consentvault"
NAME = re.compile(r"(?<![\w.])consentvault\.([a-z_][a-z_0-9]*)\b(\()?")
IGNORED_NAMES = {"safelog"}

# door.py and its transitive imports (test_the_module_list_is_current checks the list is current)
MODULES = ("confirmations.py", "dbclock.py", "disclosure.py", "door.py", "edge_envelope.py", "errors.py", "ledger.py", "lengths.py",
           "normalize.py", "rawpost.py", "records.py", "safelog.py", "stopwords.py", "sync/outbox.py", "tenancy/__init__.py",
           "tenancy/admin_base.py", "tenancy/audit.py", "tenancy/crypto.py", "tenancy/keys_protocol.py", "tenancy/logscrub.py",
           "tenancy/oauth.py", "tenancy/pipeline.py", "tenancy/replay.py", "tenancy/site_keys.py", "urlguard.py", "__init__.py",
           "providers/_names.py", "providers/errors.py", "providers/evidence.py", "sync/errors.py", "tenancy/errors.py")
CALL_MODULES = MODULES + ("api.py",)   # api.py's intake is the one caller of the arrival readers, so its calls are checked too

READS = {
    ('confirmations.py', 'enqueue_confirmation_intents', 'confirmation_enqueue()'): "downstream_effect",
    ('disclosure.py', 'get', 'disclosure'): "immutable_wording",
    ('disclosure.py', 'register', 'disclosure'): "immutable_wording",
    ('door.py', '_wording_as_of', 'wording_as_of()'): "immutable_wording",   # as of the post's stored arrival, for a post stored without the fact
    ('door.py', '_already', 'event_source_post'): "post_and_facts",
    ('door.py', '_attempt', 'projection_attempt'): "post_and_facts",
    ('door.py', '_first_attempt_age', 'projection_attempt'): "post_and_facts",
    ('door.py', 'backfill_request_keys', 'current_org()'): "plumbing",
    ('door.py', 'backfill_request_keys', 'raw_post_fact'): "post_and_facts",
    ('door.py', 'backfill_request_keys', 'raw_post_request'): "post_and_facts",
    ('door.py', 'event_by_id', 'event'): "derived_record",
    ('door.py', 'link', 'event_source_post'): "post_and_facts",
    ('door.py', 'project_pending', 'current_org()'): "plumbing",
    ('door.py', 'project_pending', 'event_source_post'): "post_and_facts",
    ('door.py', 'project_pending', 'projection_attempt'): "post_and_facts",
    ('door.py', 'project_pending', 'raw_post'): "post_and_facts",
    ('door.py', 'project_pending', 'raw_post_fact'): "post_and_facts",
    ('door.py', 'project_text_reply', 'event_source_post'): "post_and_facts",
    ('door.py', 'seen', 'request_counted()'): "post_and_facts",
    ('ledger.py', '<module>', 'current_org()'): "plumbing",
    ('ledger.py', '<module>', 'event'): "derived_record",
    ('ledger.py', '<module>', 'ledger_lock_key()'): "plumbing",
    ('ledger.py', '_insert_event_sql', 'event'): "derived_record",
    ('ledger.py', '_plaintext_breaks', 'contact_key'): "contact_key",
    ('ledger.py', '_plaintext_breaks', 'erasure_coverage'): "derived_record",
    ('ledger.py', '_plaintext_breaks', 'erasure_request'): "derived_record",
    ('ledger.py', 'record_event', 'mint_contact_salt()'): "derived_record",
    ('ledger.py', 'record_tenant_event', 'contact_key'): "contact_key",
    ('ledger.py', 'record_tenant_event', 'contact_key_of()'): "contact_key",
    ('ledger.py', 'record_tenant_event', 'current_org()'): "plumbing",
    ('ledger.py', 'record_tenant_event', 'ledger_head()'): "derived_record",
    ('ledger.py', 'verify_chain', 'chain_head'): "derived_record",
    ('ledger.py', 'verify_chain', 'event'): "derived_record",
    ('ledger.py', 'verify_chain', 'home_org()'): "plumbing",
    ('rawpost.py', '<module>', 'current_org()'): "plumbing",
    ('rawpost.py', '<module>', 'raw_post_lock_key()'): "plumbing",
    ('rawpost.py', '_insert_fact', 'raw_post_fact'): "post_and_facts",
    ('rawpost.py', '_write_request_key', 'raw_post_request'): "post_and_facts",
    ('rawpost.py', 'link_event', 'event_source_post'): "post_and_facts",
    ('rawpost.py', 'open_key', 'raw_post_key'): "post_and_facts",
    ('rawpost.py', 'read_body', 'raw_post'): "post_and_facts",
    ('rawpost.py', 'read_facts', 'raw_post_fact'): "post_and_facts",
    ('rawpost.py', 'verify_raw_anchors', 'current_org()'): "plumbing",
    ('rawpost.py', 'verify_raw_anchors', 'raw_post'): "post_and_facts",
    ('rawpost.py', 'verify_raw_anchors', 'raw_post_chain_head'): "post_and_facts",
    ('rawpost.py', 'verify_raw_bodies', 'current_org()'): "plumbing",
    ('rawpost.py', 'verify_raw_bodies', 'raw_post'): "post_and_facts",
    ('rawpost.py', 'verify_raw_bodies', 'raw_post_key'): "post_and_facts",
    ('rawpost.py', 'verify_raw_chain', 'current_org()'): "plumbing",
    ('rawpost.py', 'verify_raw_chain', 'raw_post'): "post_and_facts",
    ('rawpost.py', 'verify_raw_chain', 'raw_post_fact'): "post_and_facts",
    ('rawpost.py', 'write', 'current_org()'): "plumbing",
    ('rawpost.py', 'write', 'home_org()'): "plumbing",
    ('rawpost.py', 'write', 'raw_post'): "post_and_facts",
    ('rawpost.py', 'write', 'raw_post_fact'): "post_and_facts",
    ('rawpost.py', 'write', 'raw_post_head()'): "post_and_facts",
    ('rawpost.py', 'write', 'raw_post_key'): "post_and_facts",
    ('rawpost.py', 'write', 'raw_post_original_arrival'): "post_and_facts",
    ('records.py', 'write_event_records', 'record_display_write()'): "derived_record",
    ('records.py', 'write_event_records', 'record_index_refresh()'): "derived_record",
    ('records.py', 'write_event_records', 'record_upsert()'): "derived_record",
    ('sync/outbox.py', '_echo_targets', 'sync_echo_targets()'): "downstream_effect",
    ('sync/outbox.py', 'enqueue_event_pushes', 'current_org()'): "plumbing",
    ('sync/outbox.py', 'enqueue_event_pushes', 'sync_advance_state()'): "downstream_effect",
    ('sync/outbox.py', 'enqueue_event_pushes', 'sync_enqueue()'): "downstream_effect",
    ('sync/outbox.py', 'enqueue_event_pushes', 'sync_enqueue_refresh()'): "downstream_effect",
    ('sync/outbox.py', 'enqueue_event_pushes', 'sync_targets()'): "downstream_effect",
    ('tenancy/admin_base.py', 'org_id', 'current_org()'): "plumbing",
    ('tenancy/admin_base.py', 'org_status', 'current_org()'): "plumbing",
    ('tenancy/admin_base.py', 'org_status', 'organization'): "operational_state",
    ('tenancy/audit.py', 'append', 'append_audit()'): "outside_projection",
    ('tenancy/audit.py', 'append', 'append_audit_detailed()'): "outside_projection",
    ('tenancy/audit.py', 'append_platform', 'append_platform_audit()'): "outside_projection",
    ('tenancy/audit.py', 'chain_breaks', 'audit_chain_breaks'): "outside_projection",
    ('tenancy/audit.py', 'chain_breaks', 'current_org()'): "plumbing",
    ('tenancy/audit.py', 'head', 'audit_head()'): "outside_projection",
    ('tenancy/audit.py', 'platform_head', 'platform_audit_head()'): "outside_projection",
    ('tenancy/oauth.py', 'issue_token', 'resolve_credential()'): "outside_projection",
    ('tenancy/pipeline.py', '<module>', 'current_org()'): "plumbing",
    ('tenancy/pipeline.py', '<module>', 'ledger_lock_key()'): "plumbing",
    ('tenancy/pipeline.py', 'wording_at_arrival', 'current_org()'): "plumbing",
    ('tenancy/pipeline.py', 'wording_at_arrival', 'disclosure'): "arrival_snapshot",
    ('tenancy/pipeline.py', 'capture', 'current_org()'): "plumbing",
    ('tenancy/pipeline.py', 'capture', 'evidence_object'): "derived_record",
    ('tenancy/pipeline.py', 'capture', 'receipt_of()'): "derived_record",
    ('tenancy/pipeline.py', 'contact_key', 'contact_key'): "contact_key",
    ('tenancy/pipeline.py', 'contact_key', 'contact_key_of()'): "contact_key",
    ('tenancy/pipeline.py', 'org_channels', 'channel'): "arrival_snapshot",
    ('tenancy/pipeline.py', 'org_channels', 'current_org()'): "plumbing",
    ('tenancy/pipeline.py', 'org_purposes', 'current_org()'): "plumbing",
    ('tenancy/pipeline.py', 'org_purposes', 'purpose'): "arrival_snapshot",
    ('tenancy/pipeline.py', 'org_region', 'current_org()'): "plumbing",
    ('tenancy/pipeline.py', 'org_region', 'organization'): "arrival_snapshot",
    ('tenancy/pipeline.py', 'org_status', 'current_org()'): "plumbing",
    ('tenancy/pipeline.py', 'org_status', 'organization'): "operational_state",
    ('tenancy/pipeline.py', 'projection_settings', 'brand'): "arrival_snapshot",
    ('tenancy/pipeline.py', 'projection_settings', 'capture_source'): "arrival_snapshot",
    ('tenancy/pipeline.py', 'projection_settings', 'credential'): "arrival_snapshot",
    ('tenancy/pipeline.py', 'projection_settings', 'current_org()'): "plumbing",
    ('tenancy/pipeline.py', 'reconcile_uncommitted', 'current_org()'): "plumbing",
    ('tenancy/pipeline.py', 'reconcile_uncommitted', 'evidence_object'): "derived_record",
    ('tenancy/pipeline.py', 'retention_until', 'current_org()'): "plumbing",
    ('tenancy/pipeline.py', 'retention_until', 'retention_policy'): "operational_state",
    ('tenancy/replay.py', 'claim_nonce', 'claim_replay_nonce()'): "outside_projection",
    ('tenancy/replay.py', 'sweep', 'sweep_replay_guard()'): "outside_projection",
    ('tenancy/site_keys.py', 'resolve_site_key', 'resolve_site_key()'): "arrival_identity",
    ('tenancy/site_keys.py', 'resolve_site_key_times', 'resolve_site_key_times()'): "arrival_identity",
}

# A reader of live configuration may be called only from its named caller(s): (file, function).
ARRIVAL_ONLY = {
    "projection_settings": {("api.py", "_capture"), ("api.py", "settings_reader"),   # the intake, and its reader run in the store
                           ("api.py", "_projection_settings_selfcheck")},   # intake, and the start-up self-check of it
    "org_region": {("tenancy/pipeline.py", "projection_settings")},
    "org_channels": {("tenancy/pipeline.py", "projection_settings")},
    "org_purposes": {("tenancy/pipeline.py", "projection_settings")},
    "resolve_site_key": {("api.py", "_edge_envelope"), ("door.py", "_resolve_site_key")},
    "resolve_site_key_times": {("door.py", "_resolve_site_key")},
    "wording_at_arrival": {("api.py", "_capture"), ("api.py", "settings_reader")},
}

EXPECTED_TRIGGERS = {
    ("event", "event_append_only", "refuse_change"), ("event", "event_chain_head", "check_chain_head"),
    ("event", "event_clear_contact_home_only", "check_clear_contact_home_only"),
    ("event", "event_contact_salt_check", "check_contact_salt"), ("event", "event_no_truncate", "refuse_change"),
    ("event", "event_received_check", "check_received_at"), ("event", "event_release_check", "check_release_ref"),
    ("event", "event_scope_check", "check_grant_scope"), ("event", "event_verified_claim", "check_verified_claim"),
    ("event_source_post", "event_source_post_append_only", "refuse_change_except_key_digest"),
    ("event_source_post", "event_source_post_no_truncate", "refuse_change"),
    ("evidence_object", "evidence_object_guard", "evidence_object_guard"),
    ("evidence_object", "evidence_object_no_truncate", "refuse_change"),
}


def _walk_functions(tree):
    """(function name, node) for every statement-level node, the function being the innermost def that holds it."""
    def walk(node, fn):
        for ch in ast.iter_child_nodes(node):
            if isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef)):
                yield from walk(ch, ch.name)
            else:
                yield fn, ch
                yield from walk(ch, fn)
    yield from walk(tree, "<module>")


def found_reads(root: Path) -> set[tuple[str, str, str]]:
    out = set()
    for m in MODULES:
        tree = ast.parse((root / m).read_text())
        docstrings = {id(n.body[0].value) for n in ast.walk(tree)
                      if isinstance(n, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n.body
                      and isinstance(n.body[0], ast.Expr) and isinstance(getattr(n.body[0], "value", None), ast.Constant)}
        for fn, node in _walk_functions(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docstrings \
                    and not re.fullmatch(r"consentvault(\.\w+)*", node.value):
                for name, call in NAME.findall(node.value):
                    if name not in IGNORED_NAMES:
                        out.add((m, fn, name + ("()" if call else "")))
    return out


def calls_of_arrival_only(root: Path) -> set[tuple[str, str, str]]:
    out = set()
    for m in CALL_MODULES:
        for fn, node in _walk_functions(ast.parse((root / m).read_text())):
            if isinstance(node, ast.Call):
                name = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
                if name in ARRIVAL_ONLY:
                    out.add((m, fn, name))
    return out


def violations(root: Path) -> list[str]:
    found = found_reads(root)
    problems = [f"unclassified read {k}" for k in sorted(found - set(READS))]
    problems += [f"stale entry {k}" for k in sorted(set(READS) - found)]
    problems += [f"live decision {k}" for k, v in READS.items() if v == "live_decision"]
    problems += [f"live-configuration reader {name} called from {m}:{fn}" for m, fn, name in sorted(calls_of_arrival_only(root))
                 if (m, fn) not in ARRIVAL_ONLY[name]]
    return problems


def test_no_projection_step_reads_live_configuration():
    assert violations(SRC) == []


def test_the_module_list_is_current():
    """Everything door.py imports (transitively) is scanned."""
    seen, todo = set(), [SRC / "door.py"]
    while todo:
        p = todo.pop()
        if p in seen:
            continue
        seen.add(p)
        for n in ast.walk(ast.parse(p.read_text())):
            if isinstance(n, ast.ImportFrom) and n.level >= 1:
                base = p.parent
                for _ in range(n.level - 1):
                    base = base.parent
                target = base.joinpath(*(n.module or "").split(".")) if n.module else base
                for cand in [target.with_suffix(".py"), target / "__init__.py", *[(target / a.name).with_suffix(".py") for a in n.names]]:
                    if cand.exists() and cand not in seen:
                        todo.append(cand)
    reached = {str(p.relative_to(SRC)) for p in seen}
    assert reached <= set(MODULES), f"modules the projection can reach that the guard does not scan: {sorted(reached - set(MODULES))}"


def test_the_pipeline_has_no_live_fallback_for_the_arrival_settings():
    src = (SRC / "tenancy" / "pipeline.py").read_text()
    functions = {n.name: n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef)}
    assert "_check_source_and_brands" not in functions
    for name in ("check_channel_purpose", "check_source_from_settings", "settings_complete"):
        body = ast.get_source_segment(src, functions[name])
        assert "conn.execute" not in body and "org_channels(" not in body and "org_purposes(" not in body \
            and "org_region(" not in body, f"{name} still reads live configuration"


MUTATIONS = {
    "M1 the settings read again in the pure phase": (
        'req = parse_capture(dict(payload), body, tuple(cred.get("scopes") or ()))\n',
        '            self.settings = self.pipeline.projection_settings(conn, uuid.UUID(str(cred.get("credential_id"))))\n'),
    "M2 a SQL function the scan has not seen": (
        'req = parse_capture(dict(payload), body, tuple(cred.get("scopes") or ()))\n',
        '            conn.execute("SELECT consentvault.source_status_now(%s) AS s", (cred.get("credential_id"),))\n'),
    "M3 a table named in the fragment of a built query": (
        'req = parse_capture(dict(payload), body, tuple(cred.get("scopes") or ()))\n',
        '            cols = "status"\n'
        '            conn.execute(f"SELECT {cols}" + " FROM consentvault.capture_source WHERE source_id = %s", (1,))\n'),
}


@pytest.mark.parametrize("name", list(MUTATIONS))
def test_the_guard_catches_the_round_five_to_seven_bug_reintroduced(name, tmp_path):
    root = tmp_path / "consentvault"
    shutil.copytree(SRC, root, ignore=shutil.ignore_patterns("__pycache__"))
    base = violations(root)   # whatever the unmutated source already reports; the mutation must add to it
    anchor, added = MUTATIONS[name]
    path = root / "door.py"
    text = path.read_text()
    assert text.count(anchor) == 1
    path.write_text(text.replace(anchor, anchor + added))
    assert set(violations(root)) - set(base), f"the guard did not fail on: {name}"


def test_the_database_triggers_on_the_event_tables_are_the_listed_ones(conn):
    rows = conn.execute(
        "SELECT c.relname AS t, g.tgname AS n, p.proname AS f FROM pg_trigger g JOIN pg_class c ON c.oid = g.tgrelid"
        " JOIN pg_proc p ON p.oid = g.tgfoid JOIN pg_namespace ns ON ns.oid = c.relnamespace"
        " WHERE ns.nspname = 'consentvault' AND NOT g.tgisinternal"
        " AND c.relname IN ('event', 'evidence_object', 'event_source_post')").fetchall()
    assert {(r["t"], r["n"], r["f"]) for r in rows} == EXPECTED_TRIGGERS


def test_the_repeated_site_key_lookup_takes_no_configuration_from_the_live_key():
    """The identity lookup may say which credential a key belongs to and when it was revoked or its source retired; it never takes
    the source's brands or source id (live configuration) into a stored fact."""
    src = (SRC / "door.py").read_text()
    fn = next(n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef) and n.name == "_resolve_site_key")
    used = {n.attr for n in ast.walk(fn) if isinstance(n, ast.Attribute)}
    assert not used & {"brand_ids", "source_id", "allowed_origins"}, sorted(used & {"brand_ids", "source_id", "allowed_origins"})


# Module-level containers that are constant tables built from literals, or the safe logger's own registries: none holds configuration
# and none is filled after import. Anything else mutable at module level is state that could carry live configuration from the intake
# to the projection without a query to catch it.
CONSTANT_TABLES = {
    ("ledger.py", "HASH_VERSIONS"), ("ledger.py", "_CIPHER_COLUMNS_V2"), ("normalize.py", "TRUNK_REGIONS"), ("rawpost.py", "RECEIPT_FIELDS"),
    ("safelog.py", "FIELDS"), ("safelog.py", "_CLASSES"), ("safelog.py", "_DB_REFUSALS"), ("safelog.py", "_SETUP"), ("safelog.py", "__all__"),
    ("tenancy/admin_base.py", "STATUS"), ("tenancy/admin_base.py", "ROLE_SCOPES"), ("tenancy/audit.py", "ACTIONS"),
    ("tenancy/logscrub.py", "_JSON_SIMPLE"), ("stopwords.py", "cache on _load"),
}
MUTABLE = (ast.Dict, ast.List, ast.Set, ast.DictComp, ast.ListComp, ast.SetComp)
MUTABLE_CONSTRUCTORS = {"dict", "list", "set", "defaultdict", "OrderedDict", "deque", "Counter", "bytearray"}


def state_violations(root: Path) -> list:
    found = []
    for m in MODULES:
        tree = ast.parse((root / m).read_text())
        for n in tree.body:
            if isinstance(n, (ast.Assign, ast.AnnAssign)) and n.value is not None:
                v = n.value
                tgt = n.targets[0] if isinstance(n, ast.Assign) else n.target
                if isinstance(v, MUTABLE) or (isinstance(v, ast.Call) and getattr(v.func, "id", getattr(v.func, "attr", "")) in MUTABLE_CONSTRUCTORS):
                    found.append((m, getattr(tgt, "id", "?")))
        for n in ast.walk(tree):
            if isinstance(n, ast.Global):
                found.append((m, "global " + ",".join(n.names)))
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for d in n.decorator_list:
                    if getattr(d, "id", getattr(getattr(d, "func", d), "attr", getattr(getattr(d, "func", d), "id", ""))) in ("lru_cache", "cache", "cached_property"):
                        found.append((m, "cache on " + n.name))
    return sorted(f for f in found if f not in CONSTANT_TABLES)


def test_no_module_keeps_state_between_intake_and_projection():
    assert state_violations(SRC) == []


@pytest.mark.parametrize("line", ["_R9_CACHE: dict = {}", "_R9_CACHE = {k: v for k, v in ()}", "_R9_CACHE = dict()",
                                  "_R9_CACHE = [x for x in ()]", "_R9_CACHE = {1: 2}"])
def test_a_planted_module_level_cache_is_flagged(line, tmp_path):
    root = tmp_path / "consentvault"
    shutil.copytree(SRC, root, ignore=shutil.ignore_patterns("__pycache__"))
    path = root / "door.py"
    path.write_text(path.read_text() + "\n" + line + "\n")
    assert ("door.py", "_R9_CACHE") in state_violations(root)
