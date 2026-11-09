"""A multi-tenant replay of every stored post's decision, after the source's brands are edited, gives the decisions it gave before
the edit (one-door review round 7): the decisions read only the post and the facts stored beside it."""

import uuid

from consentvault import api, door
from consentvault.tenancy.tokens import mint_org_token, org_transaction
from .test_door_site_key_state import _orgs, hw  # noqa: F401


def _decisions(hw, org_id):
    """For every post of the organisation, replay the pure phase (reader, rule set, the typed fields and the source, brand, channel,
    purpose and settings checks) from the stored bytes and facts alone: None when it produces an event, else its plain reason."""
    from consentvault.api import _cloud_parts

    settings = hw.cloud.settings
    pipeline, writer = _cloud_parts(settings)
    token = mint_org_token(settings.token_key, org_id, ("gate_read",), credential_id=None, ttl_seconds=300)
    out = {}
    with api.connect(settings.dsn) as conn:
        enter = lambda c: org_transaction(c, token)
        backend = api.cloud_backends(settings, pipeline)
        with enter(conn):
            rows = conn.execute("SELECT post_id::text AS p, seq, intake, method, path, EXTRACT(EPOCH FROM received_at)::float8 AS arrived"
                                " FROM consentvault.raw_post WHERE kind = 'post' ORDER BY seq").fetchall()
        for r in rows:
            with enter(conn):
                view = door.read_view(writer, conn, str(org_id), r["p"], r["seq"], r["intake"], r["method"], r["path"], r["arrived"])
            b = backend.get(view.intake)
            if b is None:
                continue
            b = b.for_post(view.facts) if hasattr(b, "for_post") else b
            reading = door.read_post(view.body, None, door.CODE_VERSION, intake=view.intake, context=door._view_context(view))
            auth = __import__('dataclasses').replace(door.auth_from_facts(view.facts), org_id=str(org_id))
            reason = door.decide(reading, auth, set())
            if reason is None:
                try:
                    fields = b.prepare(conn, reading.payload, view.body, auth)
                except Exception as exc:
                    fields = door.reason_of(exc)
                reason = fields if isinstance(fields, str) else None
                if isinstance(fields, dict) and view.arrived_epoch is not None:   # as project_view does
                    from datetime import datetime, timezone
                    fields["arrived_at"] = datetime.fromtimestamp(view.arrived_epoch, tz=timezone.utc)
                if reason is None and hasattr(b, "check_wording"):   # the wording checks are part of the replayed decision
                    try:
                        with api.connect(settings.dsn) as fresh:   # a connection that is idle, as the token entry needs
                            b.check_wording(fresh, fields)
                    except Exception as exc:
                        reason = door.reason_of(exc)
            out[r["p"]] = reason
    return out


def test_the_decisions_of_every_stored_post_are_the_same_after_a_brand_edit(hw):
    a = hw.cloud.a
    for contact in ("+12125550441", "+12125550442"):
        hw.cloud.call("/v1/events", {"contact": contact, "event_type": "revoke", "channels": ["sms"], "purposes": ["marketing"],
                                     "brand_ids": [str(a.org.brand_id)], "method": "keyword", "origin": "consumer",
                                     "client_nonce": str(uuid.uuid4())}, token=hw.cloud.token(a, "capture"))
    hw.cloud.grant(a, "+12125550443")
    hw.cloud.grant(a, "+12125550444", brand_ids=[str(uuid.uuid4())])   # a brand the source never held: refused both times
    api.rebuild_cloud(hw.cloud.settings, _orgs(hw))
    before = _decisions(hw, a.org.org_id)
    with hw.t.superuser() as su:
        su.execute("UPDATE consentvault.capture_source SET brand_ids = ARRAY[gen_random_uuid()] WHERE org_id = %s AND source_id = %s",
                   (a.org.org_id, a.org.source_id))
        su.execute("UPDATE consentvault.capture_source SET status = 'retired' WHERE org_id = %s AND source_id = %s",
                   (a.org.org_id, a.org.source_id))
    after = _decisions(hw, a.org.org_id)
    assert before == after and len(before) >= 4
    assert any(v is None for v in before.values()) and any(v == "brand_not_allowed" for v in before.values())
    with hw.t.superuser() as su:   # and what was decided then is what the register holds
        derived = {r["post_id"] for r in su.execute("SELECT post_id::text AS post_id FROM consentvault.event_source_post"
                                                    " WHERE org_id = %s AND role = 'trigger'", (a.org.org_id,)).fetchall()}
    assert {p for p, v in before.items() if v is None} == derived
