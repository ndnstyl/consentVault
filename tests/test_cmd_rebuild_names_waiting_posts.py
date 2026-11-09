"""A post that waits for its intake to authenticate it (a delivery report, a reply not yet checked) is named in the rebuild's
unfinished list, not only counted (one-door review round 4, gate 2)."""

from consentvault import cmd_rebuild, door
from consentvault.rawpost import RawPostWriter, RawRequest


def test_a_post_awaiting_authentication_is_listed_by_name(conn):
    body = b"From=%2B12125550111&Body=Delivered&MessageStatus=delivered&MessageSid=SM1"
    stored = door.store_raw(RawPostWriter(), conn, None, RawRequest(
        intake="sms_reply", method="POST", path="/v1/provider/sms", query="", headers=(("content-type", "application/x-www-form-urlencoded"),),
        body=body, headers_presented_by="provider"))
    outcomes = door.rebuild(conn)
    failed = [o for o in outcomes if o.retry]
    summary = cmd_rebuild._summary("single", outcomes, failed)
    assert summary["awaiting"] == 1
    assert {"post": stored.post_id, "error": "awaiting_authentication"} in summary["unfinished_posts"]
    assert summary["unfinished"] == 1
