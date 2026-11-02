"""Ninth review: the down files refuse in the wrong order, and each guard line is held in place by a test."""

import psycopg
import pytest

from consentvault import db

from .helpers import set_status

TWELVE = ("consentvault.billing_link_account(uuid,text,text,text,text,text,text,bigint,bigint,timestamptz,"
          "timestamptz,text)")
ELEVEN = ("consentvault.billing_link_account(uuid,text,text,text,text,text,text,bigint,bigint,timestamptz,"
          "timestamptz)")


def down(name):
    return (db.default_migrations_dir() / "down" / name).read_text()


def regproc(su, signature):
    return su.execute("SELECT to_regprocedure(%s) AS f", (signature,)).fetchone()["f"]


def test_down_0040_refuses_while_the_twelve_argument_function_is_still_applied(tenancy):
    with tenancy.superuser() as su:
        assert regproc(su, TWELVE)
        with pytest.raises(psycopg.Error, match="down/0041"):
            su.execute(down("0040_price_change_mark.sql"))
        su.rollback()
        assert regproc(su, TWELVE)  # nothing was changed


def test_down_0041_then_0040_run_in_order_and_restore_the_older_function(tenancy):
    with tenancy.superuser() as su:
        su.execute(down("0041_price_set_mark.sql"))
        assert regproc(su, TWELVE) is None and regproc(su, ELEVEN)
        su.execute(down("0040_price_change_mark.sql"))
        assert regproc(su, ELEVEN)


def test_down_0041_refuses_a_role_that_is_not_the_schema_owner(tenancy):
    with tenancy.app() as app, pytest.raises(psycopg.Error, match="schema owner"):
        app.execute(down("0041_price_set_mark.sql"))
    with tenancy.superuser() as su:
        assert regproc(su, TWELVE)


def test_down_0041_refuses_when_it_is_not_applied(tenancy):
    with tenancy.superuser() as su:
        su.execute(down("0041_price_set_mark.sql"))
        with pytest.raises(psycopg.Error, match="0041 is not applied"):
            su.execute(down("0041_price_set_mark.sql"))


def test_down_0007_drops_the_twelve_argument_function_as_well(tenancy):
    with tenancy.superuser() as su:
        assert regproc(su, TWELVE)
        set_status(tenancy, tenancy.a, "suspended")
        set_status(tenancy, tenancy.b, "suspended")
        su.execute(down("0007_billing.sql"))
        assert regproc(su, TWELVE) is None and regproc(su, ELEVEN) is None
