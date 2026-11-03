"""The raw post store's two byte levels: they move a body to the object store or raise an alarm, and never cut or refuse a post
(task T028)."""

import pytest

from consentvault import config as config_mod, rawpost
from consentvault.errors import ConfigError


def test_defaults_and_settings_are_read_from_the_environment_and_the_file(tmp_path):
    cfg = config_mod.load_config(env={})
    assert (cfg.raw_post_inline_limit_bytes, cfg.raw_post_unusual_size_bytes) == (65536, 1048576)
    cfg = config_mod.load_config(env={"CONSENTVAULT_RAW_POST_INLINE_LIMIT_BYTES": "1000",
                                      "CONSENTVAULT_RAW_POST_UNUSUAL_SIZE_BYTES": "2000"})
    assert (cfg.raw_post_inline_limit_bytes, cfg.raw_post_unusual_size_bytes) == (1000, 2000)
    path = tmp_path / "c.toml"
    path.write_text("raw_post_inline_limit_bytes = 10\nraw_post_unusual_size_bytes = 20\n")
    cfg = config_mod.load_config(path, env={})
    assert (cfg.raw_post_inline_limit_bytes, cfg.raw_post_unusual_size_bytes) == (10, 20)


@pytest.mark.parametrize("env", [{"CONSENTVAULT_RAW_POST_INLINE_LIMIT_BYTES": "lots"},
                                 {"CONSENTVAULT_RAW_POST_INLINE_LIMIT_BYTES": "-1"},
                                 {"CONSENTVAULT_RAW_POST_UNUSUAL_SIZE_BYTES": "0"}])
def test_a_level_that_is_not_a_whole_number_of_bytes_is_a_named_error(env):
    with pytest.raises(ConfigError, match="never a limit on what is stored"):
        config_mod.load_config(env=env)


def test_the_writer_takes_the_levels_and_a_zero_inline_limit_still_stores_everything(conn, app_conn, tmp_path):
    from consentvault.providers.evidence import LocalAppendOnlyEvidenceStore

    writer = rawpost.RawPostWriter(inline_limit=0, unusual_size=10, store=LocalAppendOnlyEvidenceStore(str(tmp_path / "ev")))
    req = rawpost.RawRequest(intake="api_single", method="POST", path="/v1/events", query="", headers=(), body=b"x" * 50)
    stored = writer.write(app_conn, None, req)
    assert stored.unusual_size is True and stored.body_bytes == 50
    row = conn.execute("SELECT body_ct, body_object_id FROM consentvault.raw_post").fetchone()
    assert row["body_ct"] is None and row["body_object_id"] is not None
    import uuid
    assert writer.read_body(conn, uuid.UUID(stored.org_id), stored.post_id) == b"x" * 50
