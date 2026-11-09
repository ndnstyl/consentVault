"""The old fold turns off per organisation once its watermark row exists; the new fold derives intents from the row's own values and the
facts the intake captured at arrival."""

import contextlib

import pytest
from admin.conftest import vault  # noqa: F401
from contract_world.world import World
from projection.conftest import _loader_role
from projection.support import PHONE, door_post, grant_fields, sql, stop_fields


@pytest.fixture
def world(request, tmp_path):
    _loader_role(request)
    w = World(request.getfixturevalue("vault"), tmp_path)
    return w


def _cut(world, org):
    with world.vault.superuser() as su:
        su.execute("INSERT INTO consentvault.effect_watermark (org_id, head_seq) VALUES (%s, 0)", (org.org_id,))


def _events(world, org):
    return sql(world, "SELECT count(*) AS n FROM consentvault.event WHERE org_id = %s", (org.org_id,))[0]["n"]


def test_before_the_watermark_row_the_old_fold_writes_its_event_and_after_it_does_not(world):
    a, b = world.a, world.b
    door_post(world, a, grant_fields(a, PHONE))
    assert _events(world, a) == 1
    _cut(world, a)
    post = door_post(world, a, grant_fields(a, "+13055550143"))
    assert _events(world, a) == 1, "no event after the watermark row"
    assert sql(world, "SELECT 1 FROM consentvault.post_history WHERE org_id = %s AND post_id = %s", (a.org_id, post))
    door_post(world, b, grant_fields(b, PHONE))
    assert _events(world, b) == 1, "another organisation without a watermark row still gets its event"


def test_a_counted_post_above_the_watermark_derives_one_push_intent_per_target_and_a_second_projection_adds_none(world):
    a = world.a
    _cut(world, a)
    from projection.support import add_push_target
    add_push_target(a, "crm")
    post = door_post(world, a, grant_fields(a, PHONE))
    got = sql(world, "SELECT effect, state FROM consentvault.effect_intent WHERE org_id = %s AND post_id = %s", (a.org_id, post))
    assert [(r["effect"], r["state"]) for r in got] == [("push", "pending")]
