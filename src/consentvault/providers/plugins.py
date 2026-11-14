"""The key-provider plugin hook: configuration names which ``KeyProvider`` holds the organisation keys.

``CONSENTVAULT_KEY_PROVIDER`` (or ``key_provider`` in consentvault.toml) is one of:

* ``openbao``: the built-in OpenBao transit provider, from ``CONSENTVAULT_OPENBAO_ADDR``, ``CONSENTVAULT_OPENBAO_TOKEN_FILE``
  (the token, read from a file), ``CONSENTVAULT_OPENBAO_LEDGER`` (the destruction schedule file, in the backup set),
  optional ``CONSENTVAULT_OPENBAO_MOUNT`` (default ``transit``), ``CONSENTVAULT_OPENBAO_NAMESPACE`` and
  ``CONSENTVAULT_OPENBAO_PROVABLE_DESTRUCTION=true`` (only for an HSM-backed or managed seal);
* ``module:Class``: a class importable on this interpreter;
* ``entrypoint:<name>``: a class published under the ``consentvault.key_providers`` entry-point group.

An external class must be a ``consentvault.providers.keys.KeyProvider`` subclass with a ``from_environment(env)``
classmethod that returns an instance; anything else is refused with ``ConfigError`` naming what was wrong. The managed
service's KMS adapter lives in a private repository and plugs in here; this repository carries no cloud key code.
"""

from __future__ import annotations

import importlib
import importlib.metadata
from pathlib import Path
from typing import Any, Mapping

from ..safelog import describe
from ..errors import ConfigError
from .keys import KeyProvider, OpenBaoKeyProvider, UrllibBaoTransport

ENV_KEY_PROVIDER = "CONSENTVAULT_KEY_PROVIDER"
ENTRY_POINT_GROUP = "consentvault.key_providers"
ENTRY_POINT_PREFIX = "entrypoint:"


def _entry_points():
    return importlib.metadata.entry_points(group=ENTRY_POINT_GROUP)


def resolve_object(spec: str) -> Any:
    """Import ``module:attribute`` and return the attribute; a named ``ConfigError`` on any failure."""
    module_name, sep, attr = (spec or "").partition(":")
    if not sep or not module_name or not attr:
        raise ConfigError(f"{spec!r} is not an import path of the form module:Class")
    try:
        module = importlib.import_module(module_name)
    except ImportError as exc:
        raise ConfigError(f"the module {module_name!r} named by {spec!r} cannot be imported: {describe(exc)}") from exc
    try:
        obj = module
        for part in attr.split("."):
            obj = getattr(obj, part)
    except AttributeError as exc:
        raise ConfigError(f"the module {module_name!r} has no attribute {attr!r}") from exc
    return obj


def _entry_point_class(name: str) -> Any:
    found = [ep for ep in _entry_points() if ep.name == name]
    if not found:
        raise ConfigError(f"there is no installed entry point {name!r} in the group {ENTRY_POINT_GROUP}")
    if len(found) > 1:
        raise ConfigError(f"more than one installed entry point is named {name!r} in {ENTRY_POINT_GROUP}")
    try:
        return found[0].load()
    except Exception as exc:  # an entry point's own import failure, of any kind, is reported by name
        raise ConfigError(f"the entry point {name!r} could not be loaded: {describe(exc)}") from exc


def _need(env: Mapping[str, str], name: str) -> str:
    value = env.get(name)
    if not value:
        raise ConfigError(f"the openbao key provider needs {name}")
    return value


def _bao_transport(address: str, token: str, namespace: str | None):
    return UrllibBaoTransport(address, token, namespace=namespace)


def _openbao(env: Mapping[str, str]) -> OpenBaoKeyProvider:
    address = _need(env, "CONSENTVAULT_OPENBAO_ADDR")
    token_file = _need(env, "CONSENTVAULT_OPENBAO_TOKEN_FILE")
    ledger = _need(env, "CONSENTVAULT_OPENBAO_LEDGER")
    try:
        token = Path(token_file).read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ConfigError(f"CONSENTVAULT_OPENBAO_TOKEN_FILE cannot be read: {describe(exc)}") from exc
    if not token:
        raise ConfigError("CONSENTVAULT_OPENBAO_TOKEN_FILE is empty")
    provable = env.get("CONSENTVAULT_OPENBAO_PROVABLE_DESTRUCTION", "false").strip().lower()
    if provable not in ("true", "false"):
        raise ConfigError("CONSENTVAULT_OPENBAO_PROVABLE_DESTRUCTION must be true or false")
    return OpenBaoKeyProvider(_bao_transport(address, token, env.get("CONSENTVAULT_OPENBAO_NAMESPACE") or None), ledger,
                              mount=env.get("CONSENTVAULT_OPENBAO_MOUNT") or "transit",
                              provable_destruction=provable == "true")


def load_key_provider(spec: str | None, *, env: Mapping[str, str]) -> KeyProvider:
    """Build the configured key provider. Raises ``ConfigError`` naming the reason for anything else."""
    if not spec:
        raise ConfigError(f"no key provider: set {ENV_KEY_PROVIDER} or 'key_provider' in consentvault.toml "
                          "(openbao, module:Class, or entrypoint:<name>)")
    if spec == "openbao":
        return _openbao(env)
    cls = _entry_point_class(spec[len(ENTRY_POINT_PREFIX):]) if spec.startswith(ENTRY_POINT_PREFIX) else resolve_object(spec)
    if not isinstance(cls, type) or not issubclass(cls, KeyProvider):
        raise ConfigError(f"{spec!r} is not a KeyProvider subclass (consentvault.providers.keys.KeyProvider)")
    factory = getattr(cls, "from_environment", None)
    if not callable(factory):
        raise ConfigError(f"{spec!r} has no from_environment(env) classmethod to build it from configuration")
    provider = factory(env)
    if not isinstance(provider, KeyProvider):
        raise ConfigError(f"{spec!r}.from_environment did not return a KeyProvider")
    return provider
