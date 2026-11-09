"""Shadow start (pure projection, migration step 6): a post stored before migration 0082 has facts with no status; the backfill gives
it a status-bearing fact set and the pure fold then projects it from its own arrival facts, never waiting on a fact that will not come."""

import pytest

from admin.conftest import vault  # noqa: F401  (the multi-mode vault the world is built on)
from consentvault import history_backfill
from consentvault.rawpost import RawPostWriter
from consentvault.tenancy.tokens import org_transaction
from contract_world.world import World
from projection.support import PHONE, door_post, grant_fields, sql
from projection.conftest import _loader_role  # noqa: F401


@pytest.fixture
def world(request, tmp_path):
    _loader_role(request)
    return World(request.getfixturevalue("vault"), tmp_path)


def _as_stored_before_0082(world, org, post):
    """Put one post's facts back to what a store written before migration 0082 holds: no status, no label, no chain; and no history."""
    with world.vault.superuser() as su, su.transaction():
        su.execute("SET LOCAL session_replication_role = replica")
        su.execute("UPDATE consentvault.raw_post_fact SET status = NULL, label = NULL, fact_seq = NULL, observed_at = NULL,"
                   " fact_sha256 = NULL, prev_fact_sha256 = NULL WHERE org_id = %s AND post_id = %s", (org.org_id, post))
        su.execute("DELETE FROM consentvault.post_history WHERE org_id = %s AND post_id = %s", (org.org_id, post))


def test_a_pre_0082_post_is_backfilled_then_projects_from_its_own_arrival_credential(world):
    o = world.a
    post = door_post(world, o, grant_fields(o, PHONE))
    _as_stored_before_0082(world, o, post)
    assert not sql(world, "SELECT 1 FROM consentvault.post_history WHERE org_id = %s AND post_id = %s", (o.org_id, post))
    writer = RawPostWriter(crypto=world.crypto)
    with world.vault.appconn() as c, org_transaction(c, world.admin_token(o.org_id)):
        done = history_backfill.shadow_start(writer, c, lambda conn: __import__("contextlib").nullcontext())
    assert done["posts"] == 1 and done["facts"] > 0 and done["history_rows"] == 1
    kinds = {(r["name"], r["status"], r["label"]) for r in sql(world, "SELECT name, status, label FROM consentvault.raw_post_fact"
                                                                      " WHERE org_id = %s AND post_id = %s AND label = 'backfill'", (o.org_id, post))}
    assert ("request_signature", "value", "backfill") in kinds, "the arrival fact is copied with its value"
    assert ("tenant", "not_found", "backfill") in kinds or ("site_key_lookup", "not_found", "backfill") in kinds, "a name the post never had is not_found"
    (row,) = sql(world, "SELECT * FROM consentvault.post_history WHERE org_id = %s AND post_id = %s", (o.org_id, post))
    assert row["standing"] == "counts" and row["event_type_sent"] == "grant"
    with world.vault.appconn() as c, org_transaction(c, world.admin_token(o.org_id)):   # run twice: nothing more is written
        again = history_backfill.shadow_start(writer, c, lambda conn: __import__("contextlib").nullcontext())
    assert again == {"posts": 0, "facts": 0, "history_rows": 0}
