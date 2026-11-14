"""A fake Twenty (the REST behaviour the connector relies on, as read from a running v2.46.0) and helpers that connect a Twenty
system the way the admin lane does. No test here makes a network call."""

from __future__ import annotations

import copy
import json
import re
import urllib.parse
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from consentvault.sync.connectors import twenty as tw
from consentvault.sync.connectors import twenty_api as api
from consentvault.sync.connectors.twenty_receiver import TwentyReceiver
from consentvault.sync.connectors.twenty_reconcile import TwentyReconcile
from consentvault.sync.worker import SyncWorker
from consentvault.tenancy.tokens import org_transaction

BASE = "https://crm.example.test"
API_KEY = "tw-test-key-" + "x" * 24
WEBHOOK_SECRET = "whsec-" + "s" * 30


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class FakeTwenty:
    """In-memory People with soft delete, restore, hard delete, filters, read-back and the call log. ``hook`` runs before
    every call (a test stalls the clock there); ``fail`` scripts the next answers of a method."""

    def __init__(self, api_key: str = API_KEY) -> None:
        self.api_key = api_key
        self.people: dict[str, dict] = {}
        self.deleted: set[str] = set()
        self.calls: list[tuple[str, str]] = []
        self.fail: dict[str, list] = {}
        self.hook = None
        self.overwrite_on_patch: dict | None = None   # a "second writer": applied after every PATCH
        self.fields_created: list[str] = []
        self._tick = 0

    # helpers for tests ------------------------------------------------------------------------------------------------
    def add(self, *, email: str | None = None, phone: str | None = None, emails=(), phones=(), flag=False, **fields) -> str:
        pid = str(uuid.uuid4())
        self.people[pid] = {"id": pid, "name": {"firstName": "Test", "lastName": "Person"},
                            "emails": {"primaryEmail": email or "", "additionalEmails": list(emails)},
                            "phones": {"primaryPhoneNumber": (phone or "")[-10:] if phone else "",
                                       "primaryPhoneCallingCode": "+1" if phone else "", "primaryPhoneCountryCode": "US" if phone else "",
                                       "additionalPhones": [{"number": p[-10:], "callingCode": "+1", "countryCode": "US"}
                                                            for p in phones]},
                            "cvStopFlag": flag, "createdAt": _now_iso(), "updatedAt": self._stamp(), "deletedAt": None,
                            **{f: None for f in api.OWNED}, **fields}
        return pid

    def _stamp(self) -> str:
        self._tick += 1
        return (datetime.now(timezone.utc) + timedelta(milliseconds=self._tick)).isoformat(timespec="milliseconds").replace("+00:00", "Z")

    def touch(self, pid: str, **fields) -> dict:
        p = self.people[pid]
        p.update(fields)
        p["updatedAt"] = self._stamp()
        return copy.deepcopy(p)

    def add_point(self, pid: str, *, email: str | None = None, phone: str | None = None) -> dict:
        p = self.people[pid]
        if email:
            p["emails"]["additionalEmails"].append(email)
        if phone:
            p["phones"]["additionalPhones"].append({"number": phone[-10:], "callingCode": "+1", "countryCode": "US"})
        p["updatedAt"] = self._stamp()
        return copy.deepcopy(p)

    def soft_delete(self, pid: str) -> None:
        self.deleted.add(pid)
        self.people[pid]["deletedAt"] = _now_iso()

    def restore(self, pid: str) -> dict:
        self.deleted.discard(pid)
        self.people[pid]["deletedAt"] = None
        return self.touch(pid)

    def destroy(self, pid: str) -> dict:
        self.deleted.discard(pid)
        return self.people.pop(pid)

    def status_of(self, pid: str) -> dict:
        return {f: self.people[pid].get(f) for f in api.OWNED}

    def script(self, method: str, *answers) -> None:
        self.fail.setdefault(method, []).extend(answers)

    def count(self, method: str) -> int:
        return sum(1 for m, _ in self.calls if m == method)

    # the transport ------------------------------------------------------------------------------------------------------
    def call(self, method: str, url: str, headers: dict, payload) -> api.CallResult:
        parts = urllib.parse.urlparse(url)
        self.calls.append((method, parts.path))
        if self.hook is not None:
            self.hook(method, parts.path)
        if self.fail.get(method):
            got = self.fail[method].pop(0)
            if isinstance(got, api.CallResult):
                return got
            return api.CallResult("response", got, {}, {"error": "scripted"})
        if headers.get("Authorization") != f"Bearer {self.api_key}":
            return api.CallResult("response", 401, {}, {"error": "unauthorized"})
        q = dict(urllib.parse.parse_qsl(parts.query))
        path = parts.path
        if path == "/rest/metadata/objects":
            return self._ok({"data": [{"id": "person-object", "nameSingular": "person",
                                       "fields": [{"name": f, "type": t} for f, t in api.FIELDS.items() if f in self.fields_created]
                                       + [{"name": "emails", "type": "EMAILS"}, {"name": "phones", "type": "PHONES"}]}]})
        if path == "/rest/metadata/fields" and method == "POST":
            self.fields_created.append(payload["name"])
            return api.CallResult("response", 201, {}, {"id": str(uuid.uuid4()), **payload})
        m = re.fullmatch(r"/rest/people(?:/([^/]+))?(/restore)?", path)
        if not m:
            return api.CallResult("response", 404, {}, {"error": "no route"})
        pid, restore = m.group(1), m.group(2)
        if pid is None and method == "GET":
            return self._list(q)
        if pid is None and method == "POST":
            new = self.add(email=payload.get("emails", {}).get("primaryEmail"))
            return api.CallResult("response", 201, {}, {"data": {"createPerson": copy.deepcopy(self.people[new])}})
        if restore:
            if pid not in self.deleted:
                return api.CallResult("response", 404, {}, {})
            return self._ok({"data": {"restorePerson": self.restore(pid)}})
        if pid not in self.people or (pid in self.deleted and method != "DELETE"):
            return api.CallResult("response", 404, {}, {"statusCode": 404})
        if method == "GET":
            return self._ok({"data": {"person": copy.deepcopy(self.people[pid])}})
        if method == "PATCH":
            self.touch(pid, **payload)
            if self.overwrite_on_patch:
                self.touch(pid, **self.overwrite_on_patch)
            return self._ok({"data": {"updatePerson": copy.deepcopy(self.people[pid])}})
        if method == "DELETE":
            if q.get("soft_delete") == "true":
                self.soft_delete(pid)
            else:
                self.destroy(pid)
            return self._ok({"data": {"deletePerson": {"id": pid}}})
        return api.CallResult("response", 405, {}, {})

    @staticmethod
    def _ok(body) -> api.CallResult:
        return api.CallResult("response", 200, {}, json.loads(json.dumps(body)))

    def _list(self, q: dict) -> api.CallResult:
        flt = q.get("filter", "")
        live = [p for pid, p in self.people.items() if pid not in self.deleted]
        if flt.startswith("and(id[eq]:"):
            pid = re.search(r'id\[eq\]:"([^"]+)"', flt).group(1)
            out = [self.people[pid]] if pid in self.deleted else []
        elif flt.startswith("emails.primaryEmail[ilike]:"):
            want = json.loads(flt.split(":", 1)[1]).lower()
            out = [p for p in live if (p["emails"]["primaryEmail"] or "").lower() == want]
        elif flt.startswith("phones.primaryPhoneNumber[like]:"):
            tail = json.loads(flt.split(":", 1)[1]).lstrip("%")
            out = [p for p in live if (p["phones"]["primaryPhoneNumber"] or "").endswith(tail)]
        elif flt.startswith("updatedAt[gt]:"):
            since = json.loads(flt.split(":", 1)[1])
            out = [p for p in live if p["updatedAt"] > since]
        elif flt == "":
            out = live
        else:
            return api.CallResult("response", 400, {}, {"error": f"unknown filter {flt}"})
        out = sorted(out, key=lambda p: p["updatedAt"])
        return self._ok({"data": {"people": copy.deepcopy(out)}, "totalCount": len(out),
                         "pageInfo": {"hasNextPage": False, "endCursor": None}})

    # webhooks Twenty would send -----------------------------------------------------------------------------------------
    def event(self, name: str, pid: str, record: dict | None = None) -> bytes:
        rec = record if record is not None else copy.deepcopy(self.people.get(pid) or {"id": pid})
        body = {"targetUrl": "https://api.consentvault.ai/v1/connectors/twenty/x/webhook", "eventName": name,
                "objectMetadata": {"id": "person-object", "nameSingular": "person"}, "workspaceId": "w", "webhookId": "h",
                "eventDate": _now_iso(), "userId": None, "workspaceMemberId": "member-1", "record": rec}
        return json.dumps(body, separators=(",", ":")).encode()


def signed(raw: bytes, *, secret: str = WEBHOOK_SECRET, at: datetime | None = None) -> dict:
    ts = str(int((at or datetime.now(timezone.utc)).timestamp() * 1000))
    return {"X-Twenty-Webhook-Timestamp": ts, "X-Twenty-Webhook-Signature": api.sign(secret.encode(), ts, raw)}


class FakeMonotonic:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


@dataclass
class TwentySys:
    system_id: uuid.UUID
    receiver_id: str


class TwentyEnv:
    """One organisation with a Twenty system: the fake Twenty, the worker with the connector, the receiver, the reconcile."""

    def __init__(self, env, org, *, twenty: FakeTwenty | None = None, base_url: str = BASE, allow_http: bool = False) -> None:
        self.env, self.org, self.t = env, org, env.t
        self.twenty = twenty or FakeTwenty()
        for ch in ("sms", "voice", "artificial_voice", "email"):   # the organisation's channels (an erasure stops each one)
            env.q("INSERT INTO consentvault.channel (org_id, channel, label) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING",
                  [org.org_id, ch, ch])
        self.mono = FakeMonotonic()
        self.delivery = tw.TwentyDelivery(self.t.crypto, env.custody, self.twenty, clock=env.clock, monotonic=self.mono)
        with self.t.app() as app, org_transaction(app, self.t.admin_token(org.org_id)):
            made = tw.create_twenty_system(app, env.custody, org.org_id, name=f"twenty-{uuid.uuid4().hex[:6]}",
                                           base_url=base_url, api_key=self.twenty.api_key, allow_http_loopback=allow_http)
            tw.set_webhook_secret(app, env.custody, org.org_id, made["system_id"], WEBHOOK_SECRET)
            tw.activate(app, made["system_id"])
        self.sys = TwentySys(made["system_id"], made["receiver_id"])
        self.receiver = TwentyReceiver(self.t.app, self.t.crypto, env.custody, self.t.key, clock=env.clock)
        self.reconciler = TwentyReconcile(self.t.crypto, env.custody, self.twenty, clock=env.clock, monotonic=self.mono)

    def worker(self, **config) -> SyncWorker:
        w = self.env.make_worker(**config)
        w.twenty = self.delivery
        return w

    def drain(self, rounds: int = 6):
        """Run the worker until a pass claims nothing (bounded), making waiting rows due between passes."""
        reports = []
        for _ in range(rounds):
            self.env.ageing(self.org)
            with self.env.worker_conn() as w:
                rep = self.worker().run_once(w, raise_on_error=False)
            reports.append(rep)
            mine = next(o for o in rep.orgs if o.org_id == self.org.org_id)
            if mine.claimed == 0:
                break
        return reports

    def webhook(self, name: str, pid: str, record: dict | None = None, **kw):
        raw = self.twenty.event(name, pid, record)
        kw.setdefault("at", self.env.clock())
        return self.receiver.handle(self.sys.receiver_id, signed(raw, **kw), raw)

    def reconcile(self, *, full: bool = False):
        with self.t.app() as app, self.env.worker_conn() as w:
            wt = self.env.dispatch(w, self.org)
            ct = self.t.token(self.org, scopes=("capture",))
            return self.reconciler.run(app, ct, w, wt, self.org.org_id, self.sys.system_id, full=full)

    def links(self) -> list[dict]:
        return self.env.q("SELECT * FROM consentvault.connector_link WHERE org_id = %s AND system_id = %s",
                          [self.org.org_id, self.sys.system_id])

    def alarms(self, name: str) -> list[dict]:
        return self.env.q("SELECT * FROM consentvault.operator_alarm WHERE org_id = %s AND name = %s", [self.org.org_id, name])

    def activity(self, name: str) -> int:
        rows = self.env.q("SELECT sum(n) AS n FROM consentvault.connector_activity WHERE org_id = %s AND system_id = %s"
                          " AND name = %s", [self.org.org_id, self.sys.system_id, name])
        return int(rows[0]["n"] or 0)

    def clears(self) -> list[dict]:
        return self.env.outbox(self.org, push_kind="clear")

    def gate(self, contact: str, channel: str = "sms") -> str:
        """The ledger's state of a contact on a channel, as the connector combines it: denied when any purpose is stopped."""
        rows = self.env.q("SELECT allowed, reason FROM consentvault.current_permission WHERE org_id = %s AND contact_fp = %s"
                          " AND channel = %s", [self.org.org_id, self.env.fp(self.org, contact), channel])
        if any(not r["allowed"] and r["reason"].startswith("stopped:") for r in rows):
            return "denied"
        return "permitted" if any(r["allowed"] for r in rows) else "none"
