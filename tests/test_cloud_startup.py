import json

import pytest

from consentvault.cloud_startup import build_admin_app
from consentvault.config import load_config
from consentvault.errors import ConfigError
from consentvault.tenancy.tokens import TokenKey

from providers.test_edge_assertion import PEM


class _Idp:
    def verify(self, token, *, require_mfa=False):
        raise AssertionError("not reached")


def _build(cfg):
    return build_admin_app(cfg, identity=_Idp(), token_key=TokenKey("k1", b"x" * 32), connect=lambda: None,
                           owner_connect=lambda: None, custody=object(), mailer=object())


def test_real_startup_refuses_to_build_the_portal_without_edge_keys():
    with pytest.raises(ConfigError, match="CONSENTVAULT_EDGE_ASSERTION_KEYS"):
        _build(load_config(env={}))


def test_real_startup_builds_the_portal_with_edge_keys():
    app = _build(load_config(env={"CONSENTVAULT_EDGE_ASSERTION_KEYS": json.dumps({"edge1": PEM.decode()})}))
    assert app._sessions is not None
