import json

import pytest
from consentvault.tenancy.tokens import TokenKey

from consentvault.config import load_config
from consentvault.errors import ConfigError
from consentvault.tenancy.session import session_minter_from_config

from providers.test_edge_assertion import PEM


def _NOW():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc)


class _Idp:
    def verify(self, token, *, require_mfa=False):
        raise AssertionError("not reached")


def test_the_edge_keys_are_a_startup_setting_mapping_key_ids_to_public_keys(tmp_path):
    cfg = load_config(env={"CONSENTVAULT_EDGE_ASSERTION_KEYS": json.dumps({"edge1": PEM.decode()})})
    assert set(cfg.edge_assertion_keys) == {"edge1"}
    f = tmp_path / "c.toml"
    f.write_text('[edge_assertion_keys]\nedge2 = """' + PEM.decode() + '"""\n')
    assert set(load_config(path=f, env={}).edge_assertion_keys) == {"edge2"}
    assert load_config(env={}).edge_assertion_keys == {}


@pytest.mark.parametrize("raw", ["not json", "[]", '{"k": 5}', '{"": "x"}'])
def test_a_malformed_key_setting_refuses_to_start(raw):
    with pytest.raises(ConfigError):
        load_config(env={"CONSENTVAULT_EDGE_ASSERTION_KEYS": raw})


def test_portal_sessions_are_refused_without_the_keys_and_work_with_several_for_rotation():
    with pytest.raises(ConfigError, match="CONSENTVAULT_EDGE_ASSERTION_KEYS"):
        session_minter_from_config(load_config(env={}), _Idp(), TokenKey("k1", b"x" * 32), clock=_NOW)
    two = load_config(env={"CONSENTVAULT_EDGE_ASSERTION_KEYS": json.dumps({"old": PEM.decode(), "new": PEM.decode()})})
    assert session_minter_from_config(two, _Idp(), TokenKey("k1", b"x" * 32), clock=_NOW) is not None
