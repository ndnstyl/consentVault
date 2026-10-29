"""Configuration from consentvault.toml and environment variables.

Environment wins over the file. Nothing here names anyone: an unset value
stays unset and the caller that needs it raises ConfigError.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from .errors import ConfigError

ENV_DSN = "CONSENTVAULT_DSN"
ENV_REGION = "CONSENTVAULT_DEFAULT_REGION"
ENV_TSA = "CONSENTVAULT_TSA_URL"
ENV_CONFIG = "CONSENTVAULT_CONFIG"
ENV_MIGRATIONS = "CONSENTVAULT_MIGRATIONS"
ENV_OWNER_DSN = "CONSENTVAULT_OWNER_DSN"
ENV_PURPOSES = "CONSENTVAULT_PURPOSES"
ENV_ANCHOR_SINK = "CONSENTVAULT_ANCHOR_SINK"
ENV_SEAL_MAX_DELAY = "CONSENTVAULT_SEAL_MAX_DELAY_SECONDS"
ENV_UNSEALED_GRACE = "CONSENTVAULT_UNSEALED_GRACE_SECONDS"

DEFAULT_SEAL_MAX_DELAY_SECONDS = 24 * 3600
DEFAULT_UNSEALED_GRACE_SECONDS = 3600


@dataclass(frozen=True)
class Config:
    dsn: str | None = None
    default_region: str | None = None
    tsa_url: str | None = None
    migrations_dir: str | None = None
    owner_dsn: str | None = None
    purposes: tuple[str, ...] = ()
    anchor_sink: str | None = None
    seal_max_delay_seconds: int = DEFAULT_SEAL_MAX_DELAY_SECONDS
    unsealed_grace_seconds: int = DEFAULT_UNSEALED_GRACE_SECONDS

    def require_owner_dsn(self) -> str:
        if not self.owner_dsn:
            raise ConfigError(
                f"no owner DSN: set {ENV_OWNER_DSN} or 'owner_dsn' in consentvault.toml. Migrations run as the role "
                "that owns the schema; every other command uses the restricted 'dsn'"
            )
        return self.owner_dsn

    def require_purposes(self) -> tuple[str, ...]:
        if not self.purposes:
            raise ConfigError(
                f"no purpose list: set {ENV_PURPOSES} (comma separated) or 'purposes' in consentvault.toml "
                "(for example [\"marketing\", \"service\"])"
            )
        return self.purposes

    def require_anchor_sink(self) -> str:
        if not self.anchor_sink:
            raise ConfigError(
                f"no anchor sink: set {ENV_ANCHOR_SINK} or 'anchor_sink' in consentvault.toml "
                "(a file path, or an http(s) webhook URL)"
            )
        return self.anchor_sink

    def require_dsn(self) -> str:
        if not self.dsn:
            raise ConfigError(
                f"no database DSN: set {ENV_DSN} or 'dsn' in consentvault.toml "
                "(for example postgresql://user@host:5432/dbname)"
            )
        return self.dsn

    def require_tsa_url(self) -> str:
        if not self.tsa_url:
            raise ConfigError(f"no timestamp authority: set {ENV_TSA} or 'tsa_url' in consentvault.toml")
        return self.tsa_url


def load_config(path: str | os.PathLike | None = None, env: Mapping[str, str] | None = None) -> Config:
    env = os.environ if env is None else env
    file_path = path or env.get(ENV_CONFIG)
    data: dict = {}
    if file_path:
        p = Path(file_path)
        if not p.is_file():
            raise ConfigError(f"config file not found: {p}")
        try:
            data = tomllib.loads(p.read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"config file {p} is not valid TOML: {exc}") from exc
    elif Path("consentvault.toml").is_file():
        try:
            data = tomllib.loads(Path("consentvault.toml").read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"consentvault.toml is not valid TOML: {exc}") from exc

    def pick(env_key: str, key: str) -> str | None:
        value = env.get(env_key) or data.get(key)
        if value is not None and not isinstance(value, str):
            raise ConfigError(f"setting '{key}' must be a string")
        return value or None

    region = pick(ENV_REGION, "default_region")
    raw_purposes = env.get(ENV_PURPOSES)
    if raw_purposes is not None:
        purposes_in = [x for x in raw_purposes.split(",")]
    else:
        purposes_in = data.get("purposes", [])
    if not isinstance(purposes_in, list) or not all(isinstance(x, str) for x in purposes_in):
        raise ConfigError("setting 'purposes' must be a list of strings")
    purposes = tuple(sorted({x.strip().lower() for x in purposes_in if x.strip()}))
    if "*" in purposes:
        raise ConfigError("'*' is reserved for stop-all and cannot be a configured purpose")
    raw_delay = env.get(ENV_SEAL_MAX_DELAY) or data.get("seal_max_delay_seconds", DEFAULT_SEAL_MAX_DELAY_SECONDS)
    try:
        delay = int(raw_delay)
    except (TypeError, ValueError):
        raise ConfigError("setting 'seal_max_delay_seconds' must be a whole number of seconds") from None
    if delay < 1:
        raise ConfigError("setting 'seal_max_delay_seconds' must be at least 1")
    raw_grace = env.get(ENV_UNSEALED_GRACE) or data.get("unsealed_grace_seconds", DEFAULT_UNSEALED_GRACE_SECONDS)
    try:
        grace = int(raw_grace)
    except (TypeError, ValueError):
        raise ConfigError("setting 'unsealed_grace_seconds' must be a whole number of seconds") from None
    if grace < 1:
        raise ConfigError("setting 'unsealed_grace_seconds' must be at least 1")
    return Config(
        dsn=pick(ENV_DSN, "dsn"),
        default_region=region.upper() if region else None,
        tsa_url=pick(ENV_TSA, "tsa_url"),
        migrations_dir=pick(ENV_MIGRATIONS, "migrations_dir"),
        owner_dsn=pick(ENV_OWNER_DSN, "owner_dsn"),
        purposes=purposes,
        anchor_sink=pick(ENV_ANCHOR_SINK, "anchor_sink"),
        seal_max_delay_seconds=delay,
        unsealed_grace_seconds=grace,
    )
