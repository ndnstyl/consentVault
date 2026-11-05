"""Shared helpers for the matching tests: store a post the way an intake does, read it, link it, and read the history back."""

import json
import uuid
from datetime import datetime, timedelta, timezone

from consentvault import intake, match, rawpost
from consentvault.tenancy.pipeline import ReceiptSigner
from consentvault.tenancy.tokens import org_transaction
from consentvault.providers.evidence import LocalAppendOnlyEvidenceStore

T0 = datetime(2026, 10, 20, 13, 0, 0, tzinfo=timezone.utc)
JSON = (("content-type", "application/json"),)


def make_writer(tenancy, tmp_path):
    return rawpost.RawPostWriter(crypto=tenancy.crypto, store=LocalAppendOnlyEvidenceStore(str(tmp_path / "ev")),
                                 receipts=ReceiptSigner.generate(key_id="k"))


def post(tenancy, writer, body, *, org=None, source_id=None, intake_name="edge_site_key", headers=JSON, edge_at=None,
         scopes=("capture",), home=False):
    """Store and read one post on a capture-only token, the way a sender's own token runs the path."""
    org = org or tenancy.a
    token = tenancy.token_for_home(scopes) if home else tenancy.token(org, scopes)
    enter = lambda c: org_transaction(c, token)  # noqa: E731
    if isinstance(body, dict):
        body = json.dumps(body).encode()
    req = rawpost.RawRequest(intake=intake_name, method="POST", path="/capture", query="", headers=tuple(headers), body=body,
                             edge_received_at=edge_at)
    with tenancy.app() as app:
        stored = writer.write(app, enter, req)
        after = intake.read_after_commit(writer, app, enter, stored, req, source_id=source_id)
    return stored, after


def fp_of(tenancy, kind, norm, org=None):
    return tenancy.crypto.contact_fingerprint((org or tenancy.a).org_id, kind, norm)


def history(tenancy, writer, fp, org=None):
    org = org or tenancy.a
    with tenancy.app() as app, org_transaction(app, tenancy.admin_token(org.org_id)):
        return match.history_for_fp(writer, app, org.org_id, fp)


def match_rows(tenancy, post_id=None, org=None):
    org = org or tenancy.a
    with tenancy.superuser() as su:
        if post_id:
            return su.execute("SELECT * FROM consentvault.raw_post_match WHERE org_id = %s AND post_id = %s ORDER BY matched_at, match_id",
                              (org.org_id, uuid.UUID(post_id))).fetchall()
        return su.execute("SELECT * FROM consentvault.raw_post_match WHERE org_id = %s ORDER BY matched_at, match_id",
                          (org.org_id,)).fetchall()


def at(seconds):
    return T0 + timedelta(seconds=seconds)
