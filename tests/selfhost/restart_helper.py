"""Two halves of the OpenBao restart proof, driven by restart_proof.sh: ``wrap`` makes an org key and wraps a data key
with it (state kept in a scratch folder), ``check`` unwraps after the restart and expects the same data key back."""

import base64
import json
import os
import sys
import uuid
from pathlib import Path

from consentvault.providers.keys import OpenBaoKeyProvider, UrllibBaoTransport

from tests.selfhost.conftest import SELFHOST, load_settings


def provider(state: Path) -> OpenBaoKeyProvider:
    s = load_settings()
    token = (Path(os.environ["SELFHOST_SECRETS_DIR"]) / "openbao-vault-token").read_text().strip()
    return OpenBaoKeyProvider(UrllibBaoTransport(f"http://127.0.0.1:{s['OPENBAO_PORT']}", token), state / "destruction.json")


def main(mode: str, state_dir: str) -> int:
    state = Path(state_dir)
    state.mkdir(parents=True, exist_ok=True)
    kp = provider(state)
    f = state / "proof.json"
    if mode == "wrap":
        org, dek = "org-" + uuid.uuid4().hex[:10], os.urandom(32)
        kp.create_org_key(org)
        f.write_text(json.dumps({"org": org, "dek": base64.b64encode(dek).decode(),
                                 "wrapped": base64.b64encode(kp.wrap(org, dek)).decode()}))
        print(f"wrapped a data key under {org}")
        return 0
    if mode == "check":
        d = json.loads(f.read_text())
        got = kp.unwrap(d["org"], base64.b64decode(d["wrapped"]))
        if got != base64.b64decode(d["dek"]):
            print("FAIL: the unwrapped key differs", file=sys.stderr)
            return 1
        print(f"unwrapped the data key wrapped before the restart ({d['org']})")
        return 0
    print("usage: restart_helper.py wrap|check STATE_DIR", file=sys.stderr)
    return 2


if __name__ == "__main__":
    _ = SELFHOST
    sys.exit(main(sys.argv[1], sys.argv[2]))
