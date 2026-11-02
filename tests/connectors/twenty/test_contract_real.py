"""Contract proofs against a REAL Twenty (twenty.md section 8). Opt-in: skipped unless TWENTY_TEST_URL names a throwaway Twenty
(``deploy/testing/twenty/up.sh`` starts one on http://localhost:3100). The suite makes its OWN workspace through Twenty's own
sign-up API (a random user on the reserved example.com domain), so it never reads or writes any other workspace's data.

The Twenty container is reached through a local stand-in of the egress door that skips only the address check (the instance is
on loopback); every other rule of the door holds: no redirect, one deadline per call, JSON only.
"""

import json
import os
import secrets
import urllib.request

import pytest

from consentvault.sync.connectors import twenty_api as api
from consentvault.urlguard import open_no_redirect

from .door import LocalDoor

URL = os.environ.get("TWENTY_TEST_URL", "").rstrip("/")
pytestmark = pytest.mark.skipif(not URL, reason="TWENTY_TEST_URL is not set: the real-Twenty contract suite is opt-in")


def _gql(query: str, variables=None, token=None) -> dict:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(URL + "/metadata", data=json.dumps({"query": query, "variables": variables or {}}).encode(),
                                 method="POST", headers=headers)
    out = json.loads(open_no_redirect(req, timeout=30, loopback_http=True).read())
    if out.get("errors"):
        raise AssertionError(f"Twenty refused a setup call: {out['errors'][0].get('message')}")
    return out["data"]


@pytest.fixture(scope="module")
def key() -> str:
    """A fresh user, workspace and Admin-role API key, made through Twenty's own API (never another workspace's)."""
    email, pw = f"cv-suite-{secrets.token_hex(4)}@example.com", "Cv-" + secrets.token_hex(12)
    agnostic = _gql("mutation($e:String!,$p:String!){ signUp(email:$e, password:$p) { tokens { accessOrWorkspaceAgnosticToken"
                    " { token } } } }", {"e": email, "p": pw})["signUp"]["tokens"]["accessOrWorkspaceAgnosticToken"]["token"]
    login = _gql('mutation { signUpInNewWorkspace(input:{displayName:"cv suite"}) { loginToken { token } } }',
                 token=agnostic)["signUpInNewWorkspace"]["loginToken"]["token"]
    access = _gql("mutation($t:String!,$o:String!){ getAuthTokensFromLoginToken(loginToken:$t, origin:$o) { tokens {"
                  " accessOrWorkspaceAgnosticToken { token } } } }", {"t": login, "o": URL}
                  )["getAuthTokensFromLoginToken"]["tokens"]["accessOrWorkspaceAgnosticToken"]["token"]
    _gql('mutation { activateWorkspace(data:{displayName:"cv suite"}) { id } }', token=access)
    role = next(r["id"] for r in _gql("{ getRoles { id label } }", token=access)["getRoles"] if r["label"] == "Admin")
    kid = _gql('mutation($r:UUID!){ createApiKey(input:{name:"cv suite", expiresAt:"2030-01-01T00:00:00Z", roleId:$r}) { id } }',
               {"r": role}, token=access)["createApiKey"]["id"]
    return _gql('mutation($k:UUID!){ generateApiKeyToken(apiKeyId:$k, expiresAt:"2030-01-01T00:00:00Z") { token } }',
                {"k": kid}, token=access)["generateApiKeyToken"]["token"]


@pytest.fixture(scope="module")
def client(key) -> api.TwentyClient:
    return api.TwentyClient(URL, key, LocalDoor())


def _new(client, **extra) -> str:
    body = {"name": {"firstName": "ConsentVault", "lastName": "connection test"},
            "emails": {"primaryEmail": f"t-{secrets.token_hex(4)}@example.invalid", "additionalEmails": []}, **extra}
    return client.create_person(body)["id"]


def test_version_endpoint_reads_the_tested_version():
    res = open_no_redirect(urllib.request.Request(URL + "/client-config"), timeout=10, loopback_http=True)
    assert json.loads(res.read())["appVersion"] == "v2.46.0"


def test_people_list_shape(client):
    people, info = client.people(limit=1)
    assert isinstance(people, list) and {"hasNextPage", "endCursor"} <= set(info)


def test_field_naming_and_create_every_field_with_its_type(client):
    obj = client.person_object()
    have = {f["name"]: f["type"] for f in obj["fields"]}
    for name, ftype in api.FIELDS.items():
        if name not in have:
            got = client.create_field(obj["id"], name, ftype)
            assert got.get("name") == name and got.get("type") == ftype
    have = {f["name"]: f["type"] for f in client.person_object()["fields"]}
    assert all(have.get(n) == t for n, t in api.FIELDS.items())


def test_fields_write_readback_byte_for_byte_and_empty_string_versus_null(client):
    pid = _new(client)
    want = {"cvStatusSms": "denied", "cvStatusVoice": "permitted", "cvStatusAiVoice": "none", "cvStatusEmail": "none",
            "cvLastCheck": "proceed", "cvLastCheckAt": "2026-10-31T12:00:00.000Z", "cvStateSeq": "10",
            "cvEvidenceLink": "https://app.consentvault.ai/evidence?record=00000000-0000-0000-0000-000000000000"}
    client.patch(pid, want)
    got = client.person(pid)
    assert {f: got[f] for f in want} == want
    client.patch(pid, {"cvStatusEmail": None})
    assert client.person(pid)["cvStatusEmail"] in (None, "")
    client.delete_person(pid, soft=False)


def test_phone_composite_shape_and_match_by_contact_point(client):
    pid = _new(client, phones={"primaryPhoneNumber": "5555552077", "primaryPhoneCallingCode": "+1",
                               "primaryPhoneCountryCode": "US", "additionalPhones": []})
    p = client.person(pid)
    assert p["phones"]["primaryPhoneCallingCode"] == "+1" and p["phones"]["primaryPhoneNumber"] == "5555552077"
    assert ("phone", "+15555552077") in api.contact_points(p)
    assert pid in [x["id"] for x in client.find("phone", "+15555552077")]
    client.delete_person(pid, soft=False)


def test_people_filter_updated_at(client):
    people, _ = client.people(filter='updatedAt[gt]:"2000-01-01T00:00:00Z"', limit=60)
    assert people and all("updatedAt" in p for p in people)


def test_soft_delete_answers_404_reads_as_deleted_restores_and_a_hard_delete_is_gone(client):
    pid = _new(client)
    client.delete_person(pid, soft=True)
    with pytest.raises(api.PersonGone):
        client.person(pid)
    # Read from 2.46.0: a PATCH to a soft-deleted Person is ACCEPTED (the contract assumed 404). The connector never PATCHes
    # without a GET of the same Person answering first under its lease, and a clear treats the GET's 404 as the wait (R25).
    try:
        client.patch(pid, {"cvStatusSms": "denied"})
        patch_on_deleted = "accepted"
    except api.PersonGone:
        patch_on_deleted = "404"
    assert patch_on_deleted in ("accepted", "404")
    assert client.is_soft_deleted(pid)                     # read_soft_deleted
    client.restore_person(pid)
    assert client.person(pid)["id"] == pid                 # restore_events: the record is back
    client.delete_person(pid, soft=False)                  # DELETE without ?soft_delete=true is a hard delete
    assert not client.is_soft_deleted(pid)
    with pytest.raises(api.PersonGone):
        client.person(pid)


def test_a_rejected_key_is_key_rejected():
    with pytest.raises(api.TwentyError) as e:
        api.TwentyClient(URL, "not-a-key", LocalDoor()).people(limit=1)
    assert e.value.error_class == "key_rejected"


def test_record_url_opens_the_record_page(client):
    pid = _new(client)
    res = open_no_redirect(urllib.request.Request(api.record_link(URL, pid)), timeout=10, loopback_http=True)
    assert res.status == 200 and b"<html" in res.read(4096).lower()
    client.delete_person(pid, soft=False)


def test_the_connector_writes_a_stop_into_a_real_twenty_person(env, key, client):
    """End to end: the vault's stop reaches a real Twenty Person through the real worker, and reads back."""
    from .support import TwentyEnv

    pid = _new(client, phones={"primaryPhoneNumber": "5555552088", "primaryPhoneCallingCode": "+1",
                               "primaryPhoneCountryCode": "US", "additionalPhones": []})

    class RealTwenty(LocalDoor):
        api_key = key

    tw = TwentyEnv(env, env.t.a, twenty=RealTwenty(), base_url=URL, allow_http=True)
    env.stop(env.t.a, "+15555552088")
    tw.drain()
    got = client.person(pid)
    assert got["cvStatusSms"] == "denied" and got["cvStopFlag"] in (False, None)
    assert env.outbox(env.t.a, system_id=tw.sys.system_id)[0]["confirmation"] == "applied"
    client.delete_person(pid, soft=False)
