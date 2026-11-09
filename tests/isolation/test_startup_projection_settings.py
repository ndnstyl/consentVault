"""Start-up runs the settings read every tenant post is stored with, so schema or grant drift in it fails the deploy instead of
refusing every post at intake (one-door review round 8)."""

import dataclasses

import psycopg
import pytest

from consentvault import api
from consentvault.api import StartupRefusedError
from consentvault.tenancy import pipeline as pl
from .test_door_site_key_state import hw  # noqa: F401


def test_a_projection_settings_read_that_fails_refuses_the_start(hw, monkeypatch):
    def boom(self, conn, credential_id):
        raise psycopg.errors.UndefinedColumn("column s.brand_ids does not exist")

    monkeypatch.setattr(pl.CapturePipeline, "projection_settings", boom)
    with pytest.raises(StartupRefusedError) as refused:
        api.make_cloud_server(hw.cloud.settings, "127.0.0.1", 0)
    assert refused.value.code == "startup_projection_settings_refused"


def test_a_healthy_database_starts(hw):
    server = api.make_cloud_server(hw.cloud.settings, "127.0.0.1", 0)
    server.server_close()
