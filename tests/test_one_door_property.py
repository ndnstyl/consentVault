"""The one-door property test (specs/capture-everything/one-door.md, "Proof: invariants before code").

Random sequences of grant, stop, START text, form consent, resend, duplicate and crash are driven through every entry point
(the single-company HTTP server, the library, the command line) and the result is compared with a reference fold of about 30
lines. Each entry point is an adapter: it hands the request to the one door and nothing more. The invariants:

  1. every request is stored whole (one raw post per request, whatever the request was);
  2. a text never creates consent;
  3. a stop always counts;
  4. only that person's later form consent lifts a stop;
  5. a duplicate (the same signed request again) changes nothing;
  6. a crash at any point, then a re-run of the projection, gives the same history;
  7. every adapter gives the same answer for the same sequence (each is compared with the one reference, so with each other).

The test talks only to the entry points and to the stored result (raw_post, event), so it survives the redesign. The re-run is
``consentvault.door.rebuild(conn)``, the projection that appends the events of every stored post that has none, and a crash
is ``consentvault.door.project_post`` failing once, after the answer is given.
"""

import json
import random
import time

import pytest

from consentvault import api, rawpost
from consentvault.errors import ConsentVaultError
from test_api import SECRET, TOKEN, VERIFIED_SECRET, PURPOSES, _call, _serve

CONTACTS = ("+12125550101", "+12125550102")
KINDS = ("grant", "stop", "start", "form", "resend", "dup", "crash_grant", "crash_stop")
BASE = {"form": "grant", "crash_grant": "grant", "crash_stop": "stop"}
SEEDS = list(range(12))
LENGTH = 9


def make_sequence(seed: int, http: bool) -> list[tuple]:
    """Ops are (kind, person, ref). A resend or duplicate (HTTP only: they need a signed request) points at an earlier op."""
    rng = random.Random(seed)
    ops: list[tuple] = []
    for _ in range(LENGTH):
        kind = rng.choice(KINDS)
        if kind in ("dup", "resend") and not (http and ops):
            kind = "grant"
        ops.append((kind, rng.randrange(len(CONTACTS)), rng.randrange(len(ops)) if kind in ("dup", "resend") else None))
    return ops


def base_kinds(ops) -> list[str]:
    out: list[str] = []
    for kind, _, ref in ops:
        out.append(out[ref] if kind in ("dup", "resend") else BASE.get(kind, kind))
    return out


def reference_fold(ops) -> dict[int, list[str]]:
    """Per person, the events their posts produce, in order. A START text produces none, a duplicate (the same signed request
    again) produces none, a resend (a new signed request with the same content) counts again."""
    history: dict[int, list[str]] = {i: [] for i in range(len(CONTACTS))}
    for (kind, person, _), base in zip(ops, base_kinds(ops)):
        if kind != "dup" and base != "start":
            history[person].append("grant" if base == "grant" else "revoke")
    return history


def stops_lifted(types: list[str]) -> list[bool]:
    """For each stop in a person's history, whether that person's own later consent follows it."""
    return [any(t == "grant" for t in types[i + 1:]) for i, t in enumerate(types) if t == "revoke"]


class Http:
    def __init__(self, app_dsn, disclosure):
        self.disclosure, self.count, self.sent = disclosure, 0, []
        settings = api.ApiSettings(dsn=app_dsn, secret=SECRET, token=TOKEN, purposes=PURPOSES, verified_secret=VERIFIED_SECRET,
                                   default_region="US")  # gitleaks:allow (test constant)
        self._gen = _serve(settings)
        self.base = next(self._gen)

    def close(self):
        self._gen.close()

    def send(self, kind, person, ref):
        if kind == "dup":
            body, headers = self.sent[ref]
        else:
            payload = {"contact": CONTACTS[person], "channels": ["sms"], "purposes": ["marketing"], "method": "checkbox",
                       "origin": "consumer", "session_ref": "s-%d" % self.count}
            if kind == "stop":
                payload.update(event_type="revoke", method="keyword")
            else:
                payload.update(event_type="grant", checked=True, disclosure_sha256=self.disclosure)
                if kind == "start":
                    payload["inbound_message"] = "START"
            body = json.dumps(payload).encode()
            ts = str(int(time.time()))
            headers = {"Content-Type": "application/json", api.TIMESTAMP_HEADER: ts, api.SIGNATURE_HEADER: api.sign(SECRET, ts, body)}
        self.count += 1
        self.sent.append((body, headers))
        status, answer, _ = _call(self.base + "/v1/events", "POST", body, headers)
        self.base.settle()
        assert status == 201 and answer["stored"] is True, (status, answer)


class Library:
    def __init__(self, conn, disclosure):
        self.conn, self.disclosure, self.count = conn, disclosure, 0

    def close(self):
        pass

    def send(self, kind, person, ref):
        from consentvault.capture import capture, capture_verified
        from consentvault.ledger import record_event

        common = dict(contact=CONTACTS[person], channels=["sms"], purposes=["marketing"], region="US", allowed_purposes=PURPOSES,
                      session_ref="lib-%d" % self.count)
        self.count += 1
        if kind == "stop":
            record_event(self.conn, event_type="revoke", method="keyword", origin="consumer", **common)
        elif kind == "start":
            with pytest.raises(ConsentVaultError):  # a text is stored as a post and creates no consent
                capture_verified(self.conn, verification="inbound_keyword", inbound_message="START", checked=True,
                                 disclosure_sha256=self.disclosure, **common)
        else:
            capture(self.conn, checked=True, disclosure_sha256=self.disclosure, **common)


class Cli:
    def __init__(self, dsn, disclosure, monkeypatch):
        self.disclosure, self.count = disclosure, 0
        monkeypatch.setenv("CONSENTVAULT_DSN", dsn)
        monkeypatch.setenv("CONSENTVAULT_DEFAULT_REGION", "US")
        monkeypatch.setenv("CONSENTVAULT_PURPOSES", "marketing")

    def close(self):
        pass

    def send(self, kind, person, ref):
        from consentvault import cli

        self.count += 1
        args = ["--contact", CONTACTS[person], "--channel", "sms", "--purpose", "marketing", "--session-ref", "cli-%d" % self.count]
        if kind == "stop":
            argv = ["revoke", *args]
        elif kind == "start":
            argv = ["capture", *args, "--checked", "--disclosure", self.disclosure, "--inbound-message", "START"]
        else:
            argv = ["capture", *args, "--checked", "--disclosure", self.disclosure]
        with pytest.raises(SystemExit) if kind == "start" else pytest.MonkeyPatch().context():
            code = cli.main(argv)
        if kind != "start":
            assert code == 0, (argv, code)


def history(conn) -> dict[int, list[str]]:
    out: dict[int, list[str]] = {i: [] for i in range(len(CONTACTS))}
    for r in conn.execute("SELECT contact_norm, event_type FROM consentvault.event"
                          " WHERE event_type IN ('grant', 'revoke', 'suppress') ORDER BY seq").fetchall():
        out[CONTACTS.index(r["contact_norm"])].append("revoke" if r["event_type"] in ("revoke", "suppress") else "grant")
    return out


@pytest.mark.parametrize("adapter_name", ["http", "library", "cli"])
@pytest.mark.parametrize("seed", SEEDS)
def test_every_adapter_gives_the_reference_history_for_a_random_sequence(adapter_name, seed, dsn, app_dsn, conn, disclosure, monkeypatch):
    ops = make_sequence(seed, adapter_name == "http")
    adapter = {"http": lambda: Http(app_dsn, disclosure), "library": lambda: Library(conn, disclosure),
               "cli": lambda: Cli(dsn, disclosure, monkeypatch)}[adapter_name]()
    try:
        for (kind, person, ref), base in zip(ops, base_kinds(ops)):
            if kind.startswith("crash"):
                from consentvault import door  # the one door; absent before the redesign, which fails this test by name

                def crash(*a, **k):
                    raise RuntimeError("crash between the answer and the projection")
                with pytest.MonkeyPatch.context() as m:
                    m.setattr(door, "project_post", crash)
                    adapter.send(base, person, ref)
            else:
                adapter.send("dup" if kind == "dup" else base, person, ref)
    finally:
        adapter.close()
    want = reference_fold(ops)

    # 1. every request is stored whole
    posts = conn.execute("SELECT count(*) AS n FROM consentvault.raw_post").fetchone()["n"]
    assert posts == len(ops), f"{adapter_name}: {len(ops)} requests sent but {posts} stored"
    assert rawpost.verify_raw_chain(conn) == []

    # 2, 3, 5: a text creates nothing, a stop counts, a duplicate changes nothing: the history is the reference history
    from consentvault import door
    door.rebuild(conn)  # 6. a crash, then a re-run of the projection: the same history; and a second re-run changes nothing
    assert history(conn) == want, f"{adapter_name}: history differs from the reference fold"
    door.rebuild(conn)
    assert history(conn) == want

    # 4. only that person's later form consent lifts a stop
    from consentvault.gate import contact_facts
    for i, contact in enumerate(CONTACTS):
        assert [bool(s["lifted_by_post_ids"]) for s in contact_facts(conn, contact).stops] == stops_lifted(want[i]), (adapter_name, contact)
