"""The managed image's default command is the multi-tenant cloud entry (serve-cloud): the dashboard's routes, the edge
sign-in and the one-minute metrics ticker live there. The single-company ``serve`` has none of them."""

import re
import shlex
from pathlib import Path

DOCKERFILE = Path(__file__).resolve().parents[1] / "docker" / "cloud.Dockerfile"


def _instruction(name):
    found = [m.group(1) for m in re.finditer(rf"(?m)^{name}\s+(.+)$", DOCKERFILE.read_text())]
    assert len(found) == 1, f"exactly one {name} in {DOCKERFILE}"
    return found[0]


def test_the_cloud_image_runs_serve_cloud_by_default():
    import json

    cmd = json.loads(_instruction("CMD"))
    assert cmd[:2] == ["consentvault", "serve-cloud"], cmd
    assert "serve" not in cmd[2:] and cmd[cmd.index("--host") + 1] == "0.0.0.0" and cmd[cmd.index("--port") + 1] == "8080"


def test_the_entrypoint_still_writes_the_secret_files_first():
    import json

    assert json.loads(_instruction("ENTRYPOINT")) == ["/usr/local/bin/cv-entrypoint"]


def test_serve_cloud_is_a_registered_command():
    from consentvault import cli

    cli.build_parser()
    assert "serve-cloud" in cli.REGISTRY


def test_the_image_declares_a_tmp_volume_with_the_runtime_users_secret_folder():
    """The task's root filesystem is read-only and /tmp is a Fargate ephemeral volume. Fargate fills that volume from the
    image only when the image declares the path with a VOLUME directive (ECS developer guide, "Bind mounts", the
    Dockerfile VOLUME example), keeping the directory's owner and mode. So the image makes /tmp sticky and world-writable
    (1777) and /tmp/cv owned by the runtime user, mode 700, before declaring VOLUME ["/tmp"]; the entrypoint (running as
    that user) then writes the injected secrets into /tmp/cv."""
    import json

    text = DOCKERFILE.read_text()
    lines = [l.strip() for l in text.splitlines()]
    run = next(i for i, l in enumerate(lines) if "/tmp/cv" in l and l.startswith("RUN"))
    body = " ".join(lines[run:run + 4])
    assert "mkdir -p /tmp/cv" in body and "chown consentvault:consentvault /tmp/cv" in body
    assert "chmod 0700 /tmp/cv" in body and "chmod 1777 /tmp" in body
    vol = next(i for i, l in enumerate(lines) if l.startswith("VOLUME"))
    assert json.loads(lines[vol].split(None, 1)[1]) == ["/tmp"]
    user = max(i for i, l in enumerate(lines) if l.startswith("USER"))
    assert run < vol and run < user and lines[user] == "USER consentvault"
    assert vol < next(i for i, l in enumerate(lines) if l.startswith("ENTRYPOINT"))
