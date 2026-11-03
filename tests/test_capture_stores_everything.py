"""Every place the old intake refused, held, trimmed or rewrote what was sent is now one stored post: the decrypted bytes equal
the sent bytes, the fingerprint is their SHA-256, and the sender gets a 201 receipt (tasks T030 and T031).

The cases are tests/fixtures/audit_cases.json, one request for each point of the audit."""

import base64
import hashlib
import http.client
import json
from pathlib import Path

import pytest

from consentvault import rawpost

from isolation.cloud_harness import Cloud
from test_api import SECRET, TOKEN, VERIFIED_SECRET, PURPOSES, _serve  # noqa: F401  (the single-company server fixture helpers)

CASES = json.loads((Path(__file__).parent / "fixtures" / "audit_cases.json").read_text())["cases"]


def send(base: str, case: dict, extra_headers: dict | None = None):
    host, port = base.replace("http://", "").split(":")
    conn = http.client.HTTPConnection(host, int(port), timeout=60)
    body = base64.b64decode(case["body_b64"])
    headers = {**case["headers"], **(extra_headers or {})}
    conn.request(case["method"], case["path"], body=body if case["method"] not in ("GET",) else None, headers=headers)
    res = conn.getresponse()
    raw = res.read()
    conn.close()
    return res.status, (json.loads(raw) if raw else {}), body


def check_answer(case, status, answer, body):
    where = f"{case['row']}: {case['name']} (was: {case['was']})"
    assert status == 201, (where, status, answer)
    assert answer["stored"] is True, where
    assert answer["body_sha256"] == hashlib.sha256(body).hexdigest(), where
    assert answer["body_bytes"] == len(body), where
    assert answer["receipt"]["body_sha256"] == answer["body_sha256"] and answer["receipt"]["post_id"] == answer["post_id"], where


def test_the_corpus_has_a_case_for_every_group_of_the_audit():
    rows = {c["row"] for c in CASES}
    assert len(CASES) >= 50
    for needed in ("D1", "D3", "D4", "D5", "D6", "D7", "D13", "D14", "D25", "D34", "D43", "E2", "F4", "F9", "A2", "A9", "A12", "B12"):
        assert needed in rows, needed


def test_every_audited_request_is_stored_whole_by_the_single_company_server(dsn, app_dsn, conn, disclosure):
    from consentvault import api

    settings = api.ApiSettings(dsn=app_dsn, secret=SECRET, token=TOKEN, purposes=PURPOSES, verified_secret=VERIFIED_SECRET,
                               default_region="US")  # gitleaks:allow (test constant)
    for base in _serve(settings):
        sent = []
        for case in CASES:
            status, answer, body = send(base, case)
            base.settle()
            check_answer(case, status, answer, body)
            sent.append((case, answer, body))
        rows = {str(r["post_id"]): r for r in conn.execute("SELECT * FROM consentvault.raw_post ORDER BY seq").fetchall()}
        assert len(rows) == len(CASES)
        writer = rawpost.RawPostWriter()
        home = conn.execute("SELECT consentvault.home_org() AS h").fetchone()["h"]
        for case, answer, body in sent:
            row = rows[answer["post_id"]]
            assert writer.read_body(conn, home, answer["post_id"]) == body, case["name"]
            assert (row["method"], row["body_bytes"], row["body_sha256"]) == (case["method"], len(body), answer["body_sha256"])
        assert rawpost.verify_raw_chain(conn) == []


@pytest.fixture
def cloud(tenancy, tmp_path):
    c = Cloud(tenancy, str(tmp_path / "evidence"))
    yield c
    c.close()


def test_every_audited_request_is_stored_whole_by_the_cloud_server_with_and_without_a_credential(cloud):
    from consentvault.tenancy.tokens import org_transaction

    writer = rawpost.RawPostWriter(crypto=cloud.t.crypto, store=cloud.store)
    bearer = {"Authorization": "Bearer " + cloud.token(cloud.a, "capture")}
    sent = []
    for case in CASES:
        for label, extra in (("with a credential", bearer), ("with none", {})):
            status, answer, body = send(cloud.base, case, extra)
            check_answer({**case, "name": f"{case['name']} {label}"}, status, answer, body)
            sent.append((case, label, answer, body))
    cloud.server.drain(120)
    for case, label, answer, body in sent:
        org = cloud.a.org.org_id if label == "with a credential" else cloud.t.home
        assert answer["receipt"]["org_id"] == str(org), (case["name"], label)
        with cloud.t.app() as app, org_transaction(app, cloud.t.admin_token(org)):
            assert writer.read_body(app, org, answer["post_id"]) == body, (case["name"], label)
    for org in (cloud.a.org.org_id, cloud.t.home):
        with cloud.t.app() as app, org_transaction(app, cloud.t.admin_token(org)):
            assert rawpost.verify_raw_chain(app) == []


@pytest.fixture
def tenancy(dsn, pg_server):
    from isolation.harness import build_tenancy
    return build_tenancy(dsn, pg_server["port"])
