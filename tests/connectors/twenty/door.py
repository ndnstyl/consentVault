"""The egress door's /call for a loopback Twenty (the contract suite only): same deadline, no redirects, JSON answers; only the
address check is skipped. Every outcome is a named CallResult the connector classifies; nothing is swallowed."""

import json
import urllib.error
import urllib.request

from consentvault.sync.connectors import twenty_api as api
from consentvault.urlguard import open_no_redirect


def _json(raw: bytes):
    try:
        return json.loads(raw) if raw else None
    except ValueError:  # loud-failure-exempt: a non-JSON answer is carried as no body; its status is what the connector classifies
        return None


class LocalDoor:
    def __init__(self, timeout: float = 10.0) -> None:
        self.timeout = timeout

    def call(self, method, url, headers, payload):
        data = None if payload is None else json.dumps(payload).encode()
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            res = open_no_redirect(req, timeout=self.timeout, loopback_http=True)
        except urllib.error.HTTPError as exc:  # loud-failure-exempt: the receiver's status is the answer, returned by name
            return api.CallResult("response", exc.code, {}, _json(exc.read()))
        except TimeoutError as exc:  # loud-failure-exempt: returned as a timeout, which the connector retries and counts
            return api.CallResult("timeout", detail=str(exc))
        except (urllib.error.URLError, OSError) as exc:  # loud-failure-exempt: returned as unreachable, retried and counted
            return api.CallResult("unreachable", detail=type(exc).__name__)
        return api.CallResult("response", res.status, dict(res.headers), _json(res.read()))
