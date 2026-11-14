"""Helpers for the records list export tests: wait for a build, fetch a one-use link, open the zip."""

from __future__ import annotations

import csv
import io
import json
import time
import urllib.parse
import zipfile

from consentvault.tenancy.admin_routes import Request


def start(person, **body):
    body.setdefault("contact_form", "masked")
    return person.ok("POST", "/v1/records/exports", body=body)


def run_builds(person):
    """One pass of the build worker (records.md section 7) at the app clock's now; production runs it on a schedule."""
    from .world import need
    return need("consentvault.records_exports", "run_export_builds")(now=person.vault.app._clock())


def wait_ready(person, export_id, *, want="ready", timeout=20.0):
    end = time.time() + timeout
    while time.time() < end:
        run_builds(person)
        got = person.ok("GET", f"/v1/records/exports/{export_id}")
        if got["status"] == want:
            return got
        if got["status"] == "failed" and want != "failed":
            raise AssertionError(f"export failed: {got}")
        time.sleep(0.1)
    raise AssertionError(f"export {export_id} never reached {want}: {got}")


def download(world, person, url):
    """Fetch a one-use link the way a browser would: the credential is in the query string, no session token."""
    parts = urllib.parse.urlsplit(url)
    query = {k: v[0] for k, v in urllib.parse.parse_qs(parts.query).items()}
    r = world.vault.app.handle(Request("GET", parts.path, query, None, request_id="req-dl"))
    return r


def open_zip(data: bytes):
    z = zipfile.ZipFile(io.BytesIO(data))
    rows = list(csv.DictReader(io.StringIO(z.read("records.csv").decode("utf-8"))))
    return z, rows, json.loads(z.read("manifest.json"))
