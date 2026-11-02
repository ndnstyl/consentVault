"""The one check every scheduled self-check runs on its own login before it reads anything: the login must not be a
superuser or hold BYPASSRLS. Either answers every group-membership test with yes and reads past row security, so a job run
that way would prove nothing (the isolation self-test) or act with powers its role was never given (key rotation, the
restore drill's record)."""

from __future__ import annotations


def privileged(conn) -> str | None:
    """None for a bound login; otherwise its name and why it is refused."""
    row = conn.execute("SELECT rolname, rolsuper, rolbypassrls FROM pg_catalog.pg_roles WHERE rolname = current_user"
                       ).fetchone()
    if row is None:
        return "the login has no role row"
    if row["rolsuper"] or row["rolbypassrls"]:
        return f"login {row['rolname']} is a superuser or bypasses row security"
    return None
