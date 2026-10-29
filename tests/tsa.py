"""A throwaway RFC 3161 authority built with the openssl CLI, for seal tests."""

import shutil
import subprocess
from pathlib import Path

TS_CONF = """oid_section = OIDs
[OIDs]
tsa_policy1 = 1.2.3.4.1
[tsa]
default_tsa = tsa_config1
[tsa_config1]
dir = .
serial = ./tsa.serial
crypto_device = builtin
signer_cert = ./tsa.pem
certs = ./tsa.pem
signer_key = ./tsa.key
signer_digest = sha256
default_policy = tsa_policy1
other_policies = tsa_policy1
digests = sha256
accuracy = secs:1
ordering = yes
tsa_name = yes
ess_cert_id_chain = no
"""


def _run(cmd, cwd):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)


class ThrowawayTsa:
    def __init__(self, root: Path):
        self.root = root
        self.ca = root / "ca.pem"

    def stamp(self, digest_hex: str) -> bytes:
        q = self.root / "q.tsq"
        r = self.root / "r.tsr"
        a = _run(["openssl", "ts", "-query", "-digest", digest_hex, "-sha256", "-cert", "-out", str(q)], self.root)
        b = _run(["openssl", "ts", "-reply", "-queryfile", str(q), "-config", "ts.cnf",
                  "-section", "tsa_config1", "-out", str(r)], self.root)
        if a.returncode or b.returncode:
            raise RuntimeError(a.stderr + b.stderr)
        return r.read_bytes()


def build(root: Path) -> ThrowawayTsa | None:
    """Return a working throwaway TSA, or None when this openssl cannot do RFC 3161."""
    if not shutil.which("openssl"):
        return None
    (root / "ts.cnf").write_text(TS_CONF)
    (root / "tsa.serial").write_text("01\n")
    (root / "ext.cnf").write_text("basicConstraints=CA:FALSE\nextendedKeyUsage=critical,timeStamping\n")
    steps = [
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem",
         "-subj", "/CN=Test CA", "-days", "2"],
        ["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", "tsa.key", "-out", "tsa.csr",
         "-subj", "/CN=Test TSA"],
        ["openssl", "x509", "-req", "-in", "tsa.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
         "-out", "tsa.pem", "-days", "2", "-extfile", "ext.cnf"],
    ]
    for s in steps:
        if _run(s, root).returncode:
            return None
    tsa = ThrowawayTsa(root)
    try:
        token = tsa.stamp("00" * 32)
        ok = _run(["openssl", "ts", "-verify", "-in", "r.tsr", "-digest", "00" * 32, "-CAfile", "ca.pem"], root)
    except RuntimeError:
        return None
    return tsa if token and ok.returncode == 0 else None
