"""The one-door property test (specs/capture-everything/one-door.md, "Proof: invariants before code").

Random sequences of grant, stop, START text, form consent, resend, duplicate and crash are driven through every entry point
(the single-company HTTP server, the library, the command line) and the result is compared with a reference fold of about 30
lines. Each entry point is an adapter: it hands the request to the one door and nothing more. The invariants:

  1. every request is stored whole (one raw post per request, whatever the request was);
  2. a text never creates consent;
  3. a stop always counts;
  4. only that person's later form consent lifts a stop;
  5. a duplicate (the same signed request again) changes nothing;
  6. a crash at any point, then a re-run of the projection, gives the same history, and a replay of every post from an empty
     projection gives the same history fingerprint (the record contract's third gate);
  7. every adapter gives the same answer for the same sequence (each is compared with the one reference, so with each other).

The test talks only to the entry points and to the stored result (raw_post, event), so it survives the redesign. The re-run is
``consentvault.door.rebuild(conn)``, the projection that appends the events of every stored post that has none, and a crash
is ``consentvault.door.project_post`` failing once, after the answer is given. Three more operations (the first review round):
``fail_store`` (the store fails, the sender resends the same signed request and the resend counts), ``fault_*`` (a passing
database fault while the ledger appends the event; the rebuild repairs it) and ``door_stop`` (a stop through another door, the
library's system intake, which brings every earlier post up to date before it is projected). The second round adds ``poison``
(a post no event can come from: a grant whose channels are a number, or a stop whose subject key is far past the index limit): it
is stored, its own error is its own stored reason, and it never stops a later post from counting.
"""

import hashlib
import json
import random
import secrets
import time
import uuid

import psycopg
import pytest

from consentvault import api, door, rawpost
from consentvault.errors import ConsentVaultError
from test_api import SECRET, TOKEN, VERIFIED_SECRET, PURPOSES, _call, _serve

CONTACTS = ("+12125550101", "+12125550102")
KINDS = ("grant", "stop", "start", "form", "resend", "dup", "crash_grant", "crash_stop", "fail_store", "fault_grant", "fault_stop",
         "door_stop", "poison")
BASE = {"form": "grant", "crash_grant": "grant", "crash_stop": "stop", "fail_store": "grant", "fault_grant": "grant",
        "fault_stop": "stop", "door_stop": "stop", "poison": "poison"}
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
        if kind != "dup" and base not in ("start", "poison"):
            history[person].append("grant" if base == "grant" else "revoke")
    return history


class Http:
    def __init__(self, app_dsn, disclosure):
        self.disclosure, self.count, self.sent = disclosure, 0, []
        settings = api.ApiSettings(dsn=app_dsn, secret=SECRET, token=TOKEN, purposes=PURPOSES, verified_secret=VERIFIED_SECRET,
                                   default_region="US")  # gitleaks:allow (test constant)
        self._gen = _serve(settings)
        self.base = next(self._gen)

    def close(self):
        self._gen.close()

    def send_poison(self, payload):
        body = json.dumps(payload).encode()
        ts = str(int(time.time()))
        headers = {"Content-Type": "application/json", api.TIMESTAMP_HEADER: ts, api.SIGNATURE_HEADER: api.sign(SECRET, ts, body)}
        self.count += 1
        status, answer, _ = _call(self.base + "/v1/events", "POST", body, headers)
        self.base.settle()
        assert status == 201 and answer["stored"] is True, (status, answer)

    def send(self, kind, person, ref, fail=False):
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
        if kind == "fail_store":
            real, calls = rawpost.RawPostWriter.write, {"n": 0}

            def flaky(writer, *a, **k):
                calls["n"] += 1
                if calls["n"] == 1:
                    raise rawpost.StoreUnavailable("the store failed once")
                return real(writer, *a, **k)
            with pytest.MonkeyPatch.context() as m:
                m.setattr(rawpost.RawPostWriter, "write", flaky)
                status, _, _ = _call(self.base + "/v1/events", "POST", body, headers)
                self.base.settle()
            assert status == 503, status
        status, answer, _ = _call(self.base + "/v1/events", "POST", body, headers)
        self.base.settle()
        assert status == 201 and answer["stored"] is True, (status, answer)


class Library:
    def __init__(self, conn, disclosure):
        self.conn, self.disclosure, self.count = conn, disclosure, 0

    def close(self):
        pass

    def send(self, kind, person, ref, fail=False):
        from consentvault.capture import capture, capture_verified, revoke

        common = dict(contact=CONTACTS[person], channels=["sms"], purposes=["marketing"], region="US", allowed_purposes=PURPOSES,
                      session_ref="lib-%d" % self.count)
        self.count += 1
        if fail:  # a failure is raised to the caller in this process (or answered stored-and-waiting behind an unfinished earlier post)
            try:
                answer = self.send(kind, person, ref)
            except ConsentVaultError:
                return
            assert isinstance(answer, door.StoredWaiting), answer
            return
        if kind == "stop":
            return revoke(self.conn, method="keyword", origin="consumer", **common)
        elif kind == "start":
            try:  # a text is stored as a post and creates no consent
                answer = capture_verified(self.conn, verification="inbound_keyword", inbound_message="START", checked=True,
                                          disclosure_sha256=self.disclosure, **common)
            except ConsentVaultError:
                return
            assert isinstance(answer, door.StoredWaiting), answer
        else:
            return capture(self.conn, checked=True, disclosure_sha256=self.disclosure, **common)


class Cli:
    def __init__(self, dsn, disclosure, monkeypatch, capsys):
        self.disclosure, self.count, self.capsys = disclosure, 0, capsys
        monkeypatch.setenv("CONSENTVAULT_DSN", dsn)
        monkeypatch.setenv("CONSENTVAULT_DEFAULT_REGION", "US")
        monkeypatch.setenv("CONSENTVAULT_PURPOSES", "marketing")

    def close(self):
        pass

    def send(self, kind, person, ref, fail=False):
        from consentvault import cli

        self.count += 1
        args = ["--contact", CONTACTS[person], "--channel", "sms", "--purpose", "marketing", "--session-ref", "cli-%d" % self.count]
        if kind == "stop":
            argv = ["revoke", *args]
        elif kind == "start":
            argv = ["capture", *args, "--checked", "--disclosure", self.disclosure, "--inbound-message", "START"]
        else:
            argv = ["capture", *args, "--checked", "--disclosure", self.disclosure]
        try:
            code = cli.main(argv)
        except SystemExit as exc:  # loud-failure-exempt: the exit code is the answer under test
            code = exc.code
        if kind == "start" or fail:   # an error exit, or stored-and-waiting behind an unfinished earlier post (exit 0, answered by name)
            assert code in (0, None) and '"waiting": true' in self.capsys.readouterr().out or code not in (0, None), (argv, code)
        else:
            assert code == 0, (argv, code)


def history(conn) -> dict[int, list[str]]:
    out: dict[int, list[str]] = {i: [] for i in range(len(CONTACTS))}
    for r in conn.execute("SELECT contact_norm, event_type FROM consentvault.event"
                          " WHERE event_type IN ('grant', 'revoke', 'suppress') ORDER BY seq").fetchall():
        out[CONTACTS.index(r["contact_norm"])].append("revoke" if r["event_type"] in ("revoke", "suppress") else "grant")
    return out


def fingerprint(conn) -> str:
    """The history as the vault tells it, as one hash: every event in the order of the post that placed it (the earliest post
    carrying its request key), with what the event says. Independent of the order the projection wrote the events in, of which
    copy of a request produced one, and of the event's own sequence number."""
    rows = conn.execute(
        "SELECT consentvault.arrival_post_seq(e.org_id, e.event_id) AS place, e.contact_norm, e.event_type, e.channels,"
        " e.purposes, e.method, e.origin, e.session_ref FROM consentvault.event e"
        " WHERE e.event_type IN ('grant', 'revoke', 'suppress') ORDER BY place, e.contact_norm, e.event_type, e.session_ref").fetchall()
    return hashlib.sha256(json.dumps([[r["place"], r["contact_norm"], r["event_type"], list(r["channels"]), list(r["purposes"]),
                                       r["method"], r["origin"], r["session_ref"]] for r in rows]).encode()).hexdigest()


def replay_from_empty(conn, pg_server) -> str:
    """Every stored post is written again, in arrival order and with the facts known at arrival, into a database with nothing in
    it, and projected there by the same rebuild. Returns that database's history fingerprint."""
    import conftest
    from consentvault import db, door
    from consentvault.rawpost import Fact, RawPostWriter, RawRequest

    port, name = pg_server["port"], "t_" + uuid.uuid4().hex[:12]
    conftest.ensure_roles(port)
    conftest.create_vault_database(port, name)
    empty_dsn = conftest._dsn(port, name, conftest.MIGRATOR_ROLE)
    try:
        with db.connect(empty_dsn) as c:
            db.migrate(c)
        conftest.pin_as_superuser(empty_dsn)
        with db.connect(empty_dsn) as empty:
            from consentvault import disclosure as wording   # the registered wording the posts point to is reference data, not projection
            wording.register(empty, "I agree to be contacted by text.", "test-form", "en", ["sms"], ["marketing"])
            writer = RawPostWriter()
            for p in conn.execute("SELECT * FROM consentvault.raw_post WHERE kind = 'post' ORDER BY seq").fetchall():
                facts = tuple(Fact(f["source"], f["name"], json.loads(bytes(f["value_ct"]))) for f in conn.execute(
                    "SELECT source, name, value_ct FROM consentvault.raw_post_fact WHERE post_id = %s AND arrival_ordinal IS NOT NULL"
                    " ORDER BY arrival_ordinal", (p["post_id"],)).fetchall())
                writer.write(empty, None, RawRequest(
                    intake=p["intake"], method=p["method"], path=p["path"], query=bytes(p["query_ct"]),
                    headers=tuple((n, v) for n, v in json.loads(bytes(p["headers_ct"]))), body=bytes(p["body_ct"]), facts=facts,
                    headers_presented_by=p["headers_presented_by"]))
            door.rebuild(empty)
            door.rebuild(empty)
            return fingerprint(empty)
    finally:
        with psycopg.connect(conftest._dsn(port, "postgres"), autocommit=True) as admin:
            admin.execute(f'DROP DATABASE "{name}" WITH (FORCE)')


@pytest.mark.parametrize("adapter_name", ["http", "library", "cli"])
@pytest.mark.parametrize("seed", SEEDS)
def test_every_adapter_gives_the_reference_history_for_a_random_sequence(adapter_name, seed, dsn, app_dsn, conn, disclosure, monkeypatch, pg_server, capsys):
    ops = make_sequence(seed, adapter_name == "http")
    posts_seen: list = []
    adapter = {"http": lambda: Http(app_dsn, disclosure), "library": lambda: Library(conn, disclosure),
               "cli": lambda: Cli(dsn, disclosure, monkeypatch, capsys)}[adapter_name]()
    try:
        for (kind, person, ref), base in zip(ops, base_kinds(ops)):
            if kind.startswith("crash"):

                def crash(*a, **k):
                    raise RuntimeError("crash between the answer and the projection")
                with pytest.MonkeyPatch.context() as m:
                    m.setattr(door, "project_post", crash)
                    if adapter_name == "http":
                        adapter.send(base, person, ref)  # the server logs the failed projection loudly and has already answered
                    else:
                        with pytest.raises(RuntimeError):  # the caller in this process is told; the post is stored all the same
                            adapter.send(base, person, ref)
            elif kind.startswith("fault_"):
                import psycopg
                from consentvault.errors import LedgerError
                real, calls = door.record_event, {"n": 0}

                def flaky(*a, **k):  # one passing database fault while the ledger appends the event
                    calls["n"] += 1
                    if calls["n"] > 1:
                        return real(*a, **k)
                    try:
                        raise psycopg.errors.SerializationFailure("could not serialize")
                    except psycopg.Error as exc:
                        raise LedgerError("event refused by the database") from exc
                with pytest.MonkeyPatch.context() as m:
                    m.setattr(door, "record_event", flaky)
                    adapter.send(base, person, ref, fail=adapter_name != "http")  # the server answers all the same
            elif kind == "fail_store":
                if adapter_name == "http":
                    adapter.send("fail_store", person, ref)  # the store fails once (a 503), the sender resends the same request
                else:
                    real, calls = rawpost.RawPostWriter.write, {"n": 0}

                    def flaky_store(writer, *a, **k):
                        calls["n"] += 1
                        if calls["n"] == 1:
                            raise rawpost.StoreUnavailable("the store failed once")
                        return real(writer, *a, **k)
                    with pytest.MonkeyPatch.context() as m:
                        m.setattr(rawpost.RawPostWriter, "write", flaky_store)
                        adapter.send(base, person, ref, fail=True)
                    adapter.send(base, person, ref)
            elif kind == "poison":
                poison = ({"contact": CONTACTS[person], "event_type": "grant", "channels": 5, "purposes": ["marketing"],
                           "method": "checkbox", "origin": "consumer", "checked": True, "disclosure_sha256": disclosure}
                          if person == 0 else
                          {"contact": CONTACTS[person], "event_type": "revoke", "channels": ["sms"], "purposes": ["marketing"],
                           "method": "keyword", "origin": "consumer", "subject_key": secrets.token_hex(6000)})
                if adapter_name == "http":
                    adapter.send_poison(poison)
                else:
                    try:  # the caller in this process is told (or answered stored-and-waiting behind an unfinished post); the post is stored all the same
                        answer = door.submit(conn, intake="library", region="US", allowed_purposes=PURPOSES, payload=poison)
                    except Exception:
                        pass
                    else:
                        assert isinstance(answer, door.StoredWaiting), answer
            elif kind == "door_stop":
                # a stop through another door: the library's system intake
                door.submit(conn, intake="system_stop", region="US", allowed_purposes=PURPOSES, payload={
                    "contact": CONTACTS[person], "event_type": "revoke", "channels": ["sms"], "purposes": ["marketing"],
                    "method": "keyword", "origin": "consumer", "session_ref": "door-%d" % len(posts_seen)})
                posts_seen.append(1)
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
    monkeypatch.setattr(door, "HALT_CAP_SECONDS", 0)   # the history is compared once nothing waits behind an unfinished post (the halt is tested apart)
    door.rebuild(conn)  # 6. a crash, then a re-run of the projection: the same history; and a second re-run changes nothing
    assert history(conn) == want, f"{adapter_name}: history differs from the reference fold"
    door.rebuild(conn)
    assert history(conn) == want

    # 3 (the record contract). The same history from empty: every post replayed into a database with nothing in it, in arrival
    #    order, gives the identical history fingerprint, whichever copy of a request projected first here and whatever crashed.
    assert replay_from_empty(conn, pg_server) == fingerprint(conn), f"{adapter_name}: a replay from empty gives another history"

    # 4. only that person's later form consent lifts a stop: the last event of each person is a grant only when their own consent
    #    post came after their last stop, and every event cites the one post it came from (events are a projection, never a source)
    for i in range(len(CONTACTS)):
        assert (want[i][-1:] == ["grant"]) == (history(conn)[i][-1:] == ["grant"]), (adapter_name, CONTACTS[i])
    orphans = conn.execute("SELECT count(*) AS n FROM consentvault.event e WHERE e.event_type IN ('grant', 'revoke', 'suppress')"
                           " AND NOT EXISTS (SELECT 1 FROM consentvault.event_source_post s WHERE s.event_id = e.event_id"
                           " AND s.role = 'trigger')").fetchone()["n"]
    assert orphans == 0, f"{adapter_name}: {orphans} events cite no post"
