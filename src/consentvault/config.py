"""Configuration from consentvault.toml and environment variables.

Environment wins over the file. Nothing here names anyone: an unset value
stays unset and the caller that needs it raises ConfigError.
"""

from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

from .safelog import describe
from .errors import ConfigError

ENV_DSN = "CONSENTVAULT_DSN"
ENV_REGION = "CONSENTVAULT_DEFAULT_REGION"
ENV_TSA = "CONSENTVAULT_TSA_URL"
ENV_CONFIG = "CONSENTVAULT_CONFIG"
ENV_MIGRATIONS = "CONSENTVAULT_MIGRATIONS"
ENV_OWNER_DSN = "CONSENTVAULT_OWNER_DSN"
ENV_OPERATOR_DSN = "CONSENTVAULT_OPERATOR_DSN"
ENV_PURPOSES = "CONSENTVAULT_PURPOSES"
ENV_EDGE_KEYS = "CONSENTVAULT_EDGE_ASSERTION_KEYS"
ENV_ANCHOR_SINK = "CONSENTVAULT_ANCHOR_SINK"
ENV_SEAL_MAX_DELAY = "CONSENTVAULT_SEAL_MAX_DELAY_SECONDS"
ENV_UNSEALED_GRACE = "CONSENTVAULT_UNSEALED_GRACE_SECONDS"
ENV_BACKUP_RETENTION = "CONSENTVAULT_BACKUP_RETENTION_DAYS"
ENV_DB_AUTH = "CONSENTVAULT_DB_AUTH"
ENV_KEY_PROVIDER = "CONSENTVAULT_KEY_PROVIDER"
# IAM database login (db_auth = "iam"): (key, setting, the name the cloud task definitions set, file key, alias wins
# over the file). The cloud task's own names are deliberate per task and win over the file; AWS_REGION is ambient (any
# AWS container carries it), so a db_region written in the file wins over it.
IAM_SETTINGS = (
    ("host", "CONSENTVAULT_DB_HOST", "CV_DB_HOST", "db_host", True),
    ("dbname", "CONSENTVAULT_DB_NAME", "CV_DB_NAME", "db_name", True),
    ("user", "CONSENTVAULT_DB_USER", "CV_DB_USER", "db_user", True),
    ("region", "CONSENTVAULT_DB_REGION", "AWS_REGION", "db_region", False),
    ("ca_bundle", "CONSENTVAULT_DB_CA_BUNDLE", None, "db_ca_bundle", False),
)
# Where the product image puts AWS's RDS global CA bundle (pinned by sha256 and verified when the image is built).
DEFAULT_RDS_CA_BUNDLE = "/etc/consentvault/rds-global-bundle.pem"
_DIGITS = re.compile(r"[0-9]+")
_RDS_HOST_REGION = re.compile(r"\.([a-z]{2}(?:-[a-z]+)+-[0-9]+)\.rds\.amazonaws\.com(?:\.cn)?$")
ENV_DB_PORT = "CONSENTVAULT_DB_PORT"
DB_AUTH_MODES = ("password", "iam")

DEFAULT_SEAL_MAX_DELAY_SECONDS = 24 * 3600
DEFAULT_UNSEALED_GRACE_SECONDS = 3600
# How long the oldest database backup is kept (the managed database's automated backup window): a retired organisation
# key version is kept this long after the last key moved off it, so a restore of any backup still opens.
DEFAULT_BACKUP_RETENTION_DAYS = 35


@dataclass(frozen=True)
class Config:
    dsn: str | None = None
    default_region: str | None = None
    tsa_url: str | None = None
    migrations_dir: str | None = None
    owner_dsn: str | None = None
    operator_dsn: str | None = None
    purposes: tuple[str, ...] = ()
    anchor_sink: str | None = None
    seal_max_delay_seconds: int = DEFAULT_SEAL_MAX_DELAY_SECONDS
    unsealed_grace_seconds: int = DEFAULT_UNSEALED_GRACE_SECONDS
    backup_retention_days: int = DEFAULT_BACKUP_RETENTION_DAYS
    db_auth: str = "password"
    key_provider: str | None = None
    # {key id: ES256 public key PEM} of the portal edge Worker(s) allowed to sign sign-in assertions. Rotation order: add the
    # new key here, deploy the edge signing with it, then remove the old key.
    edge_assertion_keys: Mapping[str, str] = field(default_factory=dict)

    def require_owner_dsn(self) -> str:
        """The migration login (consentvault_migrator): a member of the NOLOGIN schema owner, used only by migrate."""
        if not self.owner_dsn:
            raise ConfigError(
                f"no migration DSN: set {ENV_OWNER_DSN} or 'owner_dsn' in consentvault.toml to the migrator login (a "
                "member of the schema owner). Migrations run as the schema owner; every other command uses the "
                "restricted 'dsn'"
            )
        return self.owner_dsn

    def require_operator_dsn(self) -> str:
        """The operator console's login (consentvault_operator_login): the operator jobs, never the schema owner."""
        if not self.operator_dsn:
            raise ConfigError(
                f"no operator DSN: set {ENV_OPERATOR_DSN} or 'operator_dsn' in consentvault.toml to the operator console "
                "login (a member of consentvault_console). The operator jobs never run as the schema owner"
            )
        return self.operator_dsn

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
                "(a file path, an http(s) webhook URL, or s3://<bucket> in the cloud)"
            )
        if self.anchor_sink.strip().split(":", 1)[0] == "UNSET":
            raise ConfigError(f"{ENV_ANCHOR_SINK} is still a placeholder (UNSET:...); set the real sink. Nothing was anchored")
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
            raise ConfigError(f"config file {p} is not valid TOML: {describe(exc)}") from exc
    elif Path("consentvault.toml").is_file():
        try:
            data = tomllib.loads(Path("consentvault.toml").read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"consentvault.toml is not valid TOML: {describe(exc)}") from exc

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
    raw_backup = env.get(ENV_BACKUP_RETENTION) or data.get("backup_retention_days", DEFAULT_BACKUP_RETENTION_DAYS)
    if isinstance(raw_backup, bool) or not _DIGITS.fullmatch(str(raw_backup).strip()):
        raise ConfigError("setting 'backup_retention_days' must be a whole number of days, 0 or more (the oldest "
                          f"database backup's age; default {DEFAULT_BACKUP_RETENTION_DAYS})")
    backup_days = int(raw_backup)
    dsn, operator_dsn = pick(ENV_DSN, "dsn"), pick(ENV_OPERATOR_DSN, "operator_dsn")
    auth = (env.get(ENV_DB_AUTH) or env.get("CV_DB_AUTH") or data.get("db_auth") or "password")
    if not isinstance(auth, str) or auth.strip().lower() not in DB_AUTH_MODES:
        raise ConfigError(f"setting 'db_auth' ({ENV_DB_AUTH}) must be one of {', '.join(DB_AUTH_MODES)}, not {auth!r}")
    auth = auth.strip().lower()
    if auth == "iam":
        dsn = operator_dsn = _iam_dsn(env, data, dsn, operator_dsn)
    edge_keys = _edge_keys(env.get(ENV_EDGE_KEYS), data.get("edge_assertion_keys"))
    return Config(
        dsn=dsn,
        default_region=region.upper() if region else None,
        tsa_url=pick(ENV_TSA, "tsa_url"),
        migrations_dir=pick(ENV_MIGRATIONS, "migrations_dir"),
        owner_dsn=pick(ENV_OWNER_DSN, "owner_dsn"),
        operator_dsn=operator_dsn,
        purposes=purposes,
        anchor_sink=pick(ENV_ANCHOR_SINK, "anchor_sink"),
        seal_max_delay_seconds=delay,
        unsealed_grace_seconds=grace,
        backup_retention_days=backup_days,
        db_auth=auth,
        key_provider=pick(ENV_KEY_PROVIDER, "key_provider"),
        edge_assertion_keys=edge_keys,
    )


def _edge_keys(raw_env: str | None, from_file) -> dict:
    import json

    value = from_file if from_file is not None else {}
    if raw_env:
        try:
            value = json.loads(raw_env)
        except ValueError:
            raise ConfigError(f"{ENV_EDGE_KEYS} must be JSON mapping key ids to public key PEM text") from None
    if not isinstance(value, dict) or not all(isinstance(k, str) and k and isinstance(v, str) and v.strip()
                                              for k, v in value.items()):
        raise ConfigError("edge assertion keys must map non-empty key ids to public key PEM text "
                          f"({ENV_EDGE_KEYS} or [edge_assertion_keys])")
    return dict(value)


def _iam_dsn(env: Mapping[str, str], data: dict, dsn: str | None, operator_dsn: str | None) -> str:
    """IAM login: the task's one login (its role's database user) serves both the service and the operator jobs.

    The migration login stays on its own password DSN (owner_dsn): only the one-off migration task holds that secret.
    """
    from .providers.rds_iam import build_dsn

    for name, value in ((ENV_DSN, dsn), (ENV_OPERATOR_DSN, operator_dsn)):
        if value:
            raise ConfigError(f"db_auth is 'iam' but {name} is also set: the IAM login builds the DSN from "
                              "CONSENTVAULT_DB_HOST/NAME/USER/REGION/CA_BUNDLE; set one or the other, never both")
    got: dict[str, str] = {}
    for key, primary, alias, file_key, alias_first in IAM_SETTINGS:
        from_alias = env.get(alias) if alias else None
        value = (env.get(primary) or from_alias or data.get(file_key)) if alias_first else (
            env.get(primary) or data.get(file_key) or from_alias)
        if not value and key == "ca_bundle":
            value = DEFAULT_RDS_CA_BUNDLE
        if not value or not isinstance(value, str):
            also = f" (or {alias})" if alias else ""
            raise ConfigError(f"db_auth is 'iam' but {primary}{also} or '{file_key}' in consentvault.toml is not set")
        got[key] = value
    named = _RDS_HOST_REGION.search(got["host"].lower())  # DNS names are case-insensitive
    if named and named.group(1) != got["region"]:
        raise ConfigError(f"the database host {got['host']} is in {named.group(1)} but the IAM sign-in region is "
                          f"{got['region']}: a token signed for one region is refused in another; set "
                          "CONSENTVAULT_DB_REGION or 'db_region' to the host's region")
    raw_port = env.get(ENV_DB_PORT) or data.get("db_port", 5432)
    if isinstance(raw_port, bool) or not _DIGITS.fullmatch(str(raw_port)) or not 0 < int(raw_port) < 65536:
        raise ConfigError(f"setting 'db_port' ({ENV_DB_PORT}) must be a TCP port number, ASCII digits 1 to 65535")
    return build_dsn(user=got["user"], host=got["host"], port=int(raw_port), dbname=got["dbname"],
                     region=got["region"], ca_bundle=got["ca_bundle"])
