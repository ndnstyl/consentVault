"""Live tests for the self-host stack. They need the stack up (deploy/selfhost/README.md) and fail loudly when it is not.

Settings come from deploy/selfhost/selfhost.settings; the OpenBao token comes from $SELFHOST_SECRETS_DIR
(default deploy/selfhost/secrets). Nothing here holds a credential.
"""

import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SELFHOST = ROOT / "deploy" / "selfhost"


def load_settings() -> dict:
    path = SELFHOST / "selfhost.settings"
    if not path.is_file():
        pytest.fail(f"{path} is missing: run deploy/selfhost/bin/make-settings.sh and bring the stack up")
    out = {}
    for line in path.read_text().splitlines():
        if line.strip() and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


@pytest.fixture(scope="session")
def settings() -> dict:
    return load_settings()


def _parse(raw: bytes):
    if not raw:
        return {}
    if raw.lstrip()[:1] in (b"{", b"["):
        return json.loads(raw)
    return {"raw": raw[:300].decode("utf-8", "replace")}


def http_json(method: str, url: str, *, headers=None, data=None, form=None):
    """Returns (status, parsed body, headers). An HTTP error status is an answer the tests assert on; no answer raises."""
    body = None
    h = dict(headers or {})
    if form is not None:
        body = urllib.parse.urlencode(form).encode()
        h["Content-Type"] = "application/x-www-form-urlencoded"
    elif data is not None:
        body = json.dumps(data).encode()
        h["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, _parse(r.read()), dict(r.headers)
    except urllib.error.HTTPError as e:  # loud-failure-exempt: the status is the answer under test, returned to the assertion
        return e.code, _parse(e.read()), dict(e.headers)
    except OSError as e:
        raise AssertionError(f"{method} {url} is unreachable: {e}; is the self-host stack up?") from e
