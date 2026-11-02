"""The hourly signed chain head, pushed to each organization's own sink."""

import base64
import json
import subprocess
import sys

import pytest

from consentvault import db
from consentvault.cmd_anchor import TenantAnchorRunError, anchor_payload, anchor_tenants
from consentvault.evidence import LocalEcdsaSigner, export_tenant
from consentvault.providers.anchors import AnchorReceipt, AnchorSink, FileAnchorSink
from consentvault.providers.errors import AnchorSinkError
from consentvault.tenancy.tokens import org_transaction

from .support import PHONE, token, worker_dsn


class RefusingSink(AnchorSink):
    label = "refusing"

    def publish(self, org_id, record):
        raise AnchorSinkError("the tenant's webhook answered HTTP 503", code="http_503")  # as the real webhook sink raises it


@pytest.fixture
def anchors(world, pg_server, tmp_path):
    t = world
    sinks = {t.a.org_id: FileAnchorSink(tmp_path / "alpha.jsonl"), t.b.org_id: FileAnchorSink(tmp_path / "bravo.jsonl")}
    signer = LocalEcdsaSigner.generate("evidence-test", 2)
    return {"t": t, "sinks": sinks, "signer": signer, "wdsn": worker_dsn(t, pg_server["port"]), "tmp": tmp_path}


def run(a, sinks=None, now=None):
    with db.connect(a["wdsn"]) as worker, a["t"].app() as app:
        return anchor_tenants(worker, app, a["signer"], lambda org: (sinks or a["sinks"]).get(org), now=now)


def lines(path):
    return [json.loads(x) for x in path.read_text().splitlines()]


def chain_heads(t, org):
    with t.superuser() as su:
        return su.execute("SELECT seq, row_hash, sink FROM consentvault.chain_head WHERE org_id = %s ORDER BY anchored_at",
                          (org.org_id,)).fetchall()


def test_each_organization_gets_only_its_own_signed_head(anchors):
    t = anchors["t"]
    results = run(anchors)
    published = [r for r in results if r["status"] == "published"]
    assert {r["org_id"] for r in published} == {str(t.a.org_id), str(t.b.org_id)}
    assert [r["org_id"] for r in results if r["status"] == "empty"] == [str(t.home)]  # the home organization holds nothing
    for org, name in ((t.a, "alpha"), (t.b, "bravo")):
        recs = lines(anchors["tmp"] / f"{name}.jsonl")
        assert len(recs) == 1 and recs[0]["org_id"] == str(org.org_id)
        with t.superuser() as su:
            head = su.execute("SELECT seq, row_hash FROM consentvault.event WHERE org_id = %s ORDER BY seq DESC LIMIT 1",
                              (org.org_id,)).fetchone()
        assert (recs[0]["seq"], recs[0]["row_hash"]) == (head["seq"], head["row_hash"])
        assert recs[0]["key_id"] == "evidence-test" and recs[0]["key_version"] == 2
        assert [(h["seq"], h["row_hash"]) for h in chain_heads(t, org)] == [(head["seq"], head["row_hash"])]


def test_the_signature_verifies_under_the_evidence_key_and_names_the_organization(anchors, tmp_path):
    t = anchors["t"]
    run(anchors)
    rec = lines(anchors["tmp"] / "alpha.jsonl")[0]
    pub = tmp_path / "pub.pem"
    pub.write_bytes(anchors["signer"].public_key_pem())
    msg = tmp_path / "msg"
    sig = tmp_path / "sig"
    msg.write_bytes(anchor_payload(t.a.org_id, rec["seq"], rec["row_hash"], rec["anchored_at"]))
    sig.write_bytes(base64.b64decode(rec["signature"]))
    ok = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(pub), "-signature", str(sig), str(msg)],
                        capture_output=True, text=True)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    msg.write_bytes(anchor_payload(t.b.org_id, rec["seq"], rec["row_hash"], rec["anchored_at"]))
    assert subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(pub), "-signature", str(sig), str(msg)],
                          capture_output=True, text=True).returncode != 0


def test_an_unchanged_head_is_published_again_but_recorded_once(anchors):
    t = anchors["t"]
    run(anchors)
    run(anchors)
    assert len(lines(anchors["tmp"] / "alpha.jsonl")) == 2
    assert len(chain_heads(t, t.a)) == 1
    with t.app() as app, org_transaction(app, token(t, t.a, ("capture",))):
        from consentvault.ledger import record_tenant_event

        record_tenant_event(app, t.crypto, contact=PHONE, event_type="grant", channels=["sms"], purposes=["marketing"],
                            method="checkbox", origin="consumer", disclosure_sha256=t.a.disclosure)
    run(anchors)
    assert len(chain_heads(t, t.a)) == 2 and len(chain_heads(t, t.b)) == 1


def test_one_organizations_failing_sink_is_named_and_does_not_stop_the_others(anchors):
    t = anchors["t"]
    sinks = {**anchors["sinks"], t.b.org_id: RefusingSink()}
    with pytest.raises(TenantAnchorRunError) as err:
        run(anchors, sinks)
    assert [org for org, _ in err.value.failures] == [str(t.b.org_id)]
    assert err.value.failures[0][1] == "AnchorSinkError (code http_503)" and str(t.b.org_id) in str(err.value)
    assert [r["org_id"] for r in err.value.results if r["status"] == "published"] == [str(t.a.org_id)]
    assert len(lines(anchors["tmp"] / "alpha.jsonl")) == 1 and not (anchors["tmp"] / "bravo.jsonl").exists()
    assert chain_heads(t, t.b) == []


def test_an_organization_with_no_sink_is_a_named_failure_and_an_empty_ledger_is_not(anchors, pg_server):
    t = anchors["t"]
    with pytest.raises(TenantAnchorRunError) as err:
        run(anchors, {t.a.org_id: anchors["sinks"][t.a.org_id]})
    assert err.value.failures[0][0] == str(t.b.org_id) and err.value.failures[0][1] == "AnchorError (code no_anchor_sink)"
    from isolation.harness import create_org

    with db.connect(t.operator_dsn) as owner:
        c = create_org(owner, t.key, t.provider, "charlie")
    sinks = {**anchors["sinks"], c.org_id: FileAnchorSink(anchors["tmp"] / "charlie.jsonl")}
    results = run(anchors, sinks)
    assert {r["org_id"]: r["status"] for r in results}[str(c.org_id)] == "empty"
    assert not (anchors["tmp"] / "charlie.jsonl").exists()


def test_a_signing_key_that_fails_is_a_named_failure_for_every_organization(anchors):
    class Broken:
        key_id, key_version = "broken", 1

        def sign(self, message):
            raise RuntimeError("kms is down")

    anchors["signer"] = Broken()
    with pytest.raises(TenantAnchorRunError) as err:
        run(anchors)
    assert len(err.value.failures) == 2 and all("signing_unavailable" in r.lower() or "SigningUnavailableError" in r
                                                for _, r in err.value.failures)
    assert not (anchors["tmp"] / "alpha.jsonl").exists()


def test_the_verifier_checks_signed_anchors_from_the_sink_file(anchors, throwaway_tsa, tmp_path):
    t = anchors["t"]
    run(anchors)
    out = tmp_path / "bundle"
    with t.app() as app, org_transaction(app, token(t, t.a)):
        export_tenant(app, t.crypto, PHONE, out, signer=anchors["signer"])
    pub = tmp_path / "pub.pem"
    pub.write_bytes(anchors["signer"].public_key_pem())

    def verify(anchor_file):
        return subprocess.run([sys.executable, str(out / "verify.py"), "--cafile", str(throwaway_tsa.ca), "--anchors",
                               str(anchor_file), "--evidence-key", str(pub)], capture_output=True, text=True, cwd=str(out))

    good = verify(anchors["tmp"] / "alpha.jsonl")
    assert good.returncode == 0, good.stdout
    assert "signature verifies under the evidence key" in good.stdout and "belongs to this bundle's organization" in good.stdout
    other = verify(anchors["tmp"] / "bravo.jsonl")
    assert other.returncode != 0
    assert any("belongs to this bundle's organization" in ln for ln in other.stdout.splitlines() if ln.startswith("FAIL"))
    forged = anchors["tmp"] / "forged.jsonl"
    rec = lines(anchors["tmp"] / "alpha.jsonl")[0]
    rec["anchored_at"] = "2020-01-01T00:00:00.000000Z"
    forged.write_text(json.dumps(rec) + "\n")
    bad = verify(forged)
    assert bad.returncode != 0
    assert any("signature verifies under the evidence key" in ln for ln in bad.stdout.splitlines() if ln.startswith("FAIL"))
