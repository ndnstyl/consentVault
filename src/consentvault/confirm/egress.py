"""The confirmation service's two outside reads in the cloud, made through the egress Worker's ``/call`` door (the one host the
private network may call; sync/connectors/webhook.py ``EgressTransport``), never directly:

* ``lookup(host, kind)``  the CNAME and TXT records of an organisation's wording link host, from the public resolver over
  https (``cloudflare-dns.com``, DNS JSON);
* ``page_answers(host)``  the page probe: ``GET https://<host>/c/ping`` must come back from the vault itself, naming that same
  host (``confirm.wiring.ConfirmationDoor``). DNS that points the right way is not enough: the host must also be served (a
  Cloudflare custom hostname for it), or every link in a message would be dead.

A door or resolver that does not answer raises ``TimeoutError`` (the hourly recheck then changes nothing, as for a resolver
that does not answer); it is never read as "the record is missing" or "the page is not there".
"""

from __future__ import annotations

import urllib.parse

RESOLVER = "https://cloudflare-dns.com/dns-query"
PROBE_PATH = "/c/ping"
PROBE_SERVICE = "consentvault-link-host"
_TYPES = {"CNAME": 5, "TXT": 16}


class EgressDns:
    def __init__(self, transport):
        self._t = transport

    def _get(self, url: str, accept: str):
        res = self._t.call("GET", url, {"accept": accept}, None)
        if res.kind in ("timeout", "unreachable"):
            raise TimeoutError(f"the egress door could not complete the read ({res.kind})")
        return res

    def lookup(self, host: str, kind: str):
        if kind not in _TYPES:
            raise ValueError("kind is CNAME or TXT")
        res = self._get(f"{RESOLVER}?{urllib.parse.urlencode({'name': host, 'type': kind})}", "application/dns-json")
        if res.kind != "response" or res.status != 200 or not isinstance(res.body, dict):
            raise TimeoutError("the resolver did not answer")
        for answer in res.body.get("Answer") or []:
            if isinstance(answer, dict) and answer.get("type") == _TYPES[kind]:
                value = str(answer.get("data", "")).strip()
                return value.strip('"') if kind == "TXT" else value.rstrip(".")
        return None

    def page_answers(self, host: str) -> bool:
        res = self._get(f"https://{host}{PROBE_PATH}", "application/json")
        return (res.kind == "response" and res.status == 200 and isinstance(res.body, dict)
                and res.body.get("service") == PROBE_SERVICE and res.body.get("host") == host)
