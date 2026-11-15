"""Fixtures for the record link tests: the export tests' two sealed organisations, plus one widget post for the first
organisation's grant (the consent box, the wording, a certificate, a page URL and the contact, each planted as a canary),
a login for the public read path, and helpers that mint a link and read it the way a stranger does."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest

from consentvault import db

from export.conftest import pinned_dsn, throwaway_tsa, world  # noqa: F401  (fixtures reused as they are)
from export.support import PHONE
from isolation.harness import make_login_role
from match_support import make_writer, post

CERT_URL = "https://cert.trustedform.com/454a35b802f3e7b63ffabb4efedb7c6ebe67886c"
PAGE_URL = "https://alpha.example.com/signup?gclid=CANARYCLICKID"
WORDING = "I agree to texts from Alpha about my account. Reply STOP to end."
DECIDED = "2026-11-15T10:00:00.000-05:00"


def link_post(t, org, event_id, post_id):
    with t.superuser() as su:
        su.execute("INSERT INTO consentvault.event_source_post (org_id, event_id, post_id, role) VALUES (%s, %s, %s, 'trigger')",
                   (org.org_id, event_id, uuid.UUID(str(post_id))))


@pytest.fixture
def record(world, tmp_path):  # noqa: F811
    """The first organisation's grant, with a stored widget post that carries every field the page may show."""
    t = world
    body = {"contact": PHONE, "checked": True, "decided_at": DECIDED, "disclosure_text": WORDING,
            "disclosure_sha256": "0" * 64, "page_url": PAGE_URL, "session": "s-canary",
            "third_party": [{"name": "xxTrustedFormCertUrl", "value": CERT_URL}]}
    stored, _ = post(t, make_writer(t, tmp_path), body, org=t.a, source_id=t.a.source_id)
    event_id = t.a.event_ids[0]
    link_post(t, t.a, event_id, stored.post_id)
    t.record_post_id = str(stored.post_id)
    return t


@pytest.fixture
def public_dsn(record, pg_server):
    return make_login_role(pg_server["port"], record.app_dsn.rsplit("/", 1)[1], "consentvault_public_verify")


@pytest.fixture
def public_conn(public_dsn):
    c = db.connect(public_dsn)
    yield c
    c.close()


# ---- helpers the share tests use ---------------------------------------------------------------------------------------------

from contextlib import contextmanager  # noqa: E402

from consentvault.tenancy.tokens import org_transaction  # noqa: E402

PUBLIC = "/v1/public/record-link"
BANNED = [r"\bcompliant\b", r"non-compliant", r"in compliance", r"compliance status", r"valid consent", r"consent is valid",
          r"\bprov(e|es|en)\b", r"\bproof\b", r"\blawful\b", r"legally sufficient", r"permitted to", r"safe to", r"cleared to",
          r"guarantee", r"court-ready", r"qualifies", r"satisfied", r"meets (the )?TCPA", "—", "–", r"\bvalid\b",
          r"\bcovers\b", r"\bconsented\b", r"\bauthori[sz]ed\b", r"\bverdict\b", r"\bopted in\b", r"\b(has|with|without) consent\b"]


@contextmanager
def admin(t, org=None):
    org = org or t.a
    with t.app() as app, org_transaction(app, t.token(org, ("admin",))):
        yield app


def mint_link(t, *, org=None, event_id=None, flags=None, ack=None, note="", actor="member:test"):
    from consentvault import share

    org = org or t.a
    with admin(t, org) as app:
        return share.mint(app, event_id=event_id or org.event_ids[0], actor=actor, flags=flags or {}, contact_ack=ack, note=note)


def attach_post(t, tmp_path, event_id, **overrides):
    """Store a widget post for the first organisation and make it the trigger of ``event_id``."""
    body = {"contact": PHONE, "checked": True, "decided_at": DECIDED, "disclosure_text": WORDING, "disclosure_sha256": "0" * 64,
            "page_url": PAGE_URL, "session": "s-canary"}
    body.update(overrides)
    stored, _ = post(t, make_writer(t, tmp_path), body, org=t.a, source_id=t.a.source_id)
    link_post(t, t.a, event_id, stored.post_id)
    return str(stored.post_id)


@pytest.fixture
def routes(record, public_dsn):
    from consentvault import share_routes

    return share_routes.PublicRecordLinks(connect=lambda: db.connect(public_dsn), crypto=record.crypto)


def get(routes, link_id, suffix="", method="GET", body=b"", headers=None):
    return routes.handle(method, f"{PUBLIC}/{link_id}{suffix}", body=body, headers=headers or {})


def text_of(reply) -> str:
    if reply.raw is not None:
        return reply.raw.decode("utf-8", "replace")
    import json as _json

    return _json.dumps(reply.payload, sort_keys=True)
