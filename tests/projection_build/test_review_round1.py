import uuid, contextlib
import psycopg
import pytest
from admin.conftest import vault  # noqa: F401
from consentvault import history_backfill, door
from consentvault.rawpost import RawPostWriter
from consentvault.tenancy.tokens import org_transaction
from contract_world.world import World
from projection.support import PHONE, door_post, grant_fields, stop_fields, sql, write_fact
from projection.conftest import _loader_role  # noqa: F401


@pytest.fixture
def world(request, tmp_path):
    _loader_role(request)
    return World(request.getfixturevalue("vault"), tmp_path)


def _pre0082(world, org, post):
    with world.vault.superuser() as su, su.transaction():
        su.execute("SET LOCAL session_replication_role = replica")
        su.execute("UPDATE consentvault.raw_post_fact SET status = NULL, label = NULL, fact_seq = NULL, observed_at = NULL,"
                   " fact_sha256 = NULL, prev_fact_sha256 = NULL WHERE org_id = %s AND post_id = %s", (org.org_id, post))
        su.execute("DELETE FROM consentvault.post_history WHERE org_id = %s AND post_id = %s", (org.org_id, post))


def test_r1_rebuild_before_shadow_start_freezes_wrong_history(world):
    o = world.a
    post = door_post(world, o, stop_fields(o, PHONE))
    _pre0082(world, o, post)
    writer = RawPostWriter(crypto=world.crypto)
    with world.vault.appconn() as c, org_transaction(c, world.admin_token(o.org_id)):
        n = door.history_catch_up(writer, c, lambda conn: contextlib.nullcontext())
    assert sql(world, "SELECT 1 FROM consentvault.post_history WHERE org_id=%s AND post_id=%s", (o.org_id, post)) == [] and n == 0
    with world.vault.appconn() as c, org_transaction(c, world.admin_token(o.org_id)):
        done = history_backfill.shadow_start(writer, c, lambda conn: contextlib.nullcontext())
    (row2,) = sql(world, "SELECT standing FROM consentvault.post_history WHERE org_id=%s AND post_id=%s", (o.org_id, post))
    assert row2["standing"] == "counts"


def test_r2_app_cannot_insert_a_backfill_labelled_history_row(world):
    o = world.a
    post = door_post(world, o, grant_fields(o, PHONE))
    with world.vault.superuser() as su, su.transaction():
        su.execute("SET LOCAL session_replication_role = replica")
        su.execute("DELETE FROM consentvault.post_history WHERE org_id = %s AND post_id = %s", (o.org_id, post))
        seq = su.execute("SELECT seq FROM consentvault.raw_post WHERE post_id=%s", (post,)).fetchone()["seq"]
    with pytest.raises(psycopg.Error):
        with world.vault.appconn() as c, org_transaction(c, world.capture_token(o.org_id)):
            c.execute("INSERT INTO consentvault.post_history (org_id, post_id, post_seq, placed_at, received_at, event_id, label,"
                      " event_type_sent, channels_sent, standing, earliest_copy, rule_set_version, fold_code_version, hash_version)"
                      " VALUES (%s,%s,%s,'2001-01-01','2001-01-01',%s,'backfill','revoke','{sms}','counts',true,'x','x',3)",
                      (o.org_id, post, seq, uuid.uuid4()))
    writer = RawPostWriter(crypto=world.crypto)
    with world.vault.appconn() as c, org_transaction(c, world.admin_token(o.org_id)):
        n = door.history_catch_up(writer, c, lambda conn: contextlib.nullcontext(), every_post=True)
    assert n == 1


def test_r3_backfilled_not_found_makes_later_signature_lost_race(world):
    o = world.a
    post = door_post(world, o, stop_fields(o, PHONE), facts=[])
    _pre0082(world, o, post)
    writer = RawPostWriter(crypto=world.crypto)
    with world.vault.appconn() as c, org_transaction(c, world.admin_token(o.org_id)):
        history_backfill.shadow_start(writer, c, lambda conn: contextlib.nullcontext())
    row = write_fact(world, o, post, "request_signature", "valid")
    assert row["status"] == "value"


def test_r4_app_cannot_write_a_reroute_row_pointing_at_another_organisations_post(world):
    a, b = world.a, world.b
    pa = door_post(world, a, grant_fields(a, PHONE))
    pb = door_post(world, b, grant_fields(b, PHONE))
    with pytest.raises(psycopg.Error):
        with world.vault.appconn() as c, org_transaction(c, world.capture_token(a.org_id)):
            c.execute("INSERT INTO consentvault.raw_post_reroute (from_org, from_post, to_org, to_post) VALUES (%s,%s,%s,%s)",
                      (a.org_id, pa, b.org_id, pb))
    with pytest.raises(psycopg.Error) as exc:
        with world.vault.appconn() as c, org_transaction(c, world.capture_token(a.org_id)):
            c.execute("SELECT consentvault.record_reroute(%s, %s, %s)", (pa, b.org_id, pb))
    assert sql(world, "SELECT 1 FROM consentvault.raw_post_reroute WHERE from_post = %s", (pa,)) == []
    assert "foreign key" not in str(exc.value).lower(), "the refusal does not say whether the other organisation's post exists"


def test_r5_a_session_setting_does_not_switch_on_loader_mode(world):
    o = world.a
    post = door_post(world, o, grant_fields(o, PHONE))
    with world.vault.superuser() as su, su.transaction():
        su.execute("SET LOCAL session_replication_role = replica")
        su.execute("INSERT INTO consentvault.replay_target DEFAULT VALUES")
    with world.vault.appconn() as c, org_transaction(c, world.capture_token(o.org_id)):
        c.execute("SELECT set_config('consentvault.loading_post', %s, true)", (post,))
        c.execute("INSERT INTO consentvault.raw_post_fact (org_id, post_id, fact_id, source, name, value_ct, status, label)"
                  " VALUES (%s,%s,%s,'vault','forged',%s,'value','retry')", (o.org_id, post, uuid.uuid4(), b"x"))
    (row,) = sql(world, "SELECT fact_sha256, fact_seq FROM consentvault.raw_post_fact WHERE post_id=%s AND name='forged'", (post,))
    assert row["fact_sha256"] is not None and row["fact_seq"] is not None, "the chain trigger still computed the row"


def test_r7_a_start_that_arrived_before_the_stop_and_was_stored_after_it_cannot_lift_it(world):
    o = world.a
    stop = door_post(world, o, stop_fields(o, PHONE))
    lift = door_post(world, o, grant_fields(o, PHONE))
    (h,) = sql(world, "SELECT event_id, contact_fp, placed_at FROM consentvault.post_history WHERE org_id=%s AND post_id=%s", (o.org_id, stop))
    assert h["contact_fp"], "the stop's history row carries its contact fingerprint"
    with world.vault.superuser() as su, su.transaction():
        su.execute("INSERT INTO consentvault.raw_post_match (org_id, post_id, match_id, map_version, status, contact_fp)"
                   " VALUES (%s,%s,gen_random_uuid(),0,'matched',%s)", (o.org_id, lift, h["contact_fp"]))
        su.execute("INSERT INTO consentvault.raw_post_original_arrival (org_id, post_id, arrived_at) VALUES (%s,%s,%s)",
                   (o.org_id, lift, h["placed_at"] - __import__("datetime").timedelta(hours=1)))
    with pytest.raises(psycopg.Error) as exc:
        with org_enter(world, o) as c:
            c.execute("INSERT INTO consentvault.history_stop_lift (org_id, stop_event_id, lifting_post_id, contact_fp) VALUES (%s,%s,%s,%s)",
                      (o.org_id, h["event_id"], lift, h["contact_fp"]))
    assert "did not arrive after" in str(exc.value)


def test_r8_the_history_stop_reader_refuses_a_session_with_no_organisation(world):
    o = world.a
    cut = door_post(world, o, stop_fields(o, PHONE))
    (h,) = sql(world, "SELECT contact_fp FROM consentvault.post_history WHERE org_id=%s AND post_id=%s", (o.org_id, cut))
    with org_enter(world, o) as c:
        assert c.execute("SELECT consentvault.history_stop_on_record(%s,%s,'sms') AS s", (o.org_id, h["contact_fp"])).fetchone()["s"]
    with pytest.raises(psycopg.Error):
        with world.vault.appconn() as c:
            c.execute("SELECT * FROM consentvault.history_stop_on_record(%s,%s,'sms')", (o.org_id, h["contact_fp"])).fetchall()


@contextlib.contextmanager
def org_enter(world, o):
    with world.vault.appconn() as c, org_transaction(c, world.capture_token(o.org_id)):
        yield c


def test_r9_a_populated_outcome_table_is_kept_by_the_down_file():
    from pathlib import Path
    text = (Path(__file__).resolve().parents[2] / "migrations" / "down" / "0085_projection_outcome.sql").read_text()
    kept = text.split("IF EXISTS (SELECT 1 FROM consentvault.projection_outcome) THEN")[1].split("ELSE")[0]
    assert "RENAME TO" in kept and "DROP TABLE" not in kept, "rows are renamed away, never dropped"


def test_gap_history_rows_carry_the_contact_fingerprint(world):
    o = world.a
    post = door_post(world, o, stop_fields(o, PHONE))
    (h,) = sql(world, "SELECT contact_fp, contact_key_ref FROM consentvault.post_history WHERE org_id=%s AND post_id=%s", (o.org_id, post))
    assert h["contact_fp"] == world.crypto.contact_fingerprint(o.org_id, "phone", PHONE)


def test_gap_shadow_start_gives_a_legacy_event_with_no_post_a_legacy_event_post_and_every_legacy_event_a_backfill_row(world):
    a = world.a
    kept = door_post(world, a, grant_fields(a, PHONE))
    orphan = door_post(world, a, grant_fields(a, "+13055550177"))
    ev = {p: sql(world, "SELECT event_id FROM consentvault.event_source_post WHERE org_id=%s AND post_id=%s", (a.org_id, p))[0]["event_id"]
          for p in (kept, orphan)}
    for p in (kept, orphan):
        _pre0082(world, a, p)
    with world.vault.superuser() as su, su.transaction():
        su.execute("SET LOCAL session_replication_role = replica")
        su.execute("DELETE FROM consentvault.event_source_post WHERE org_id = %s AND event_id = %s", (a.org_id, ev[orphan]))
    writer = RawPostWriter(crypto=world.crypto)
    with world.vault.appconn() as c, org_transaction(c, world.admin_token(a.org_id)):
        out = history_backfill.shadow_start(writer, c, lambda conn: contextlib.nullcontext())
    assert out["legacy_event_posts"] == 1
    rows = {str(r["backfill_of_event_id"]): r for r in sql(world, "SELECT * FROM consentvault.post_history WHERE org_id = %s AND label = 'backfill'", (a.org_id,))}
    assert set(rows) == {str(ev[kept]), str(ev[orphan])}
    assert all(r["fold_code_version"] == "backfill-1" and r["standing"] == "counts" and r["contact_fp"] for r in rows.values())
    (post,) = sql(world, "SELECT intake FROM consentvault.raw_post WHERE org_id = %s AND post_id = %s", (a.org_id, rows[str(ev[orphan])]["post_id"]))
    assert post["intake"] == "legacy_event"
    assert str(rows[str(ev[kept])]["post_id"]) == kept
    with world.vault.appconn() as c, org_transaction(c, world.admin_token(a.org_id)):
        again = history_backfill.shadow_start(writer, c, lambda conn: contextlib.nullcontext())
    assert again["legacy_event_posts"] == 0 and again["history_rows"] == 0, "running it again adds nothing"


def test_item10_a_broken_history_link_fails_ledger_verify_chain(world):
    from consentvault import ledger
    o = world.a
    door_post(world, o, grant_fields(o, PHONE))
    door_post(world, o, grant_fields(o, "+13055550143"))
    with world.vault.superuser() as su:
        assert ledger.verify_chain(su) == []
    with world.vault.superuser() as su, su.transaction():
        su.execute("SET LOCAL session_replication_role = replica")
        su.execute("UPDATE consentvault.post_history SET prev_hash = repeat('0', 64) WHERE org_id = %s AND history_seq ="
                   " (SELECT max(history_seq) FROM consentvault.post_history WHERE org_id = %s)", (o.org_id, o.org_id))
    with world.vault.superuser() as su:
        assert any(b.reason.startswith("history:") for b in ledger.verify_chain(su))
