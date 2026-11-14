"""confirmations.md section 1 (Account id): a Twilio connection states account_sid, AC plus 32 hex, kept in the clear in its own
column and handed to the provider with the API key; any other shape is refused naming the field."""

import pytest

from contract_world.confirm import OUR_NUMBER

SID = "AC" + "0123456789abcdef" * 2


def body(stack, **creds):
    return {"channel": "sms", "provider": "twilio", "sender": {"number": OUR_NUMBER}, "provider_replies_itself": False,
            "credentials": {"api_key_sid": "SKtest", "api_key_secret": stack.twilio.api_key_secret,
                            "auth_token": stack.twilio.auth_token, **creds}}


@pytest.mark.parametrize("bad", ["AC123", "ac" + "0" * 32, "AC" + "G" * 32, "AC" + "0" * 33, 5])
def test_an_account_sid_of_any_other_shape_is_refused_naming_the_field(world, stack, bad):
    err = world.a.boss.err("POST", "/v1/confirmations/sending-accounts", body=body(stack, account_sid=bad), name="validation_failed")
    assert "credentials" in err["fields"] and "account_sid" in err["fields"]["credentials"]
    assert world.a.boss.ok("GET", "/v1/confirmations/settings")["sending_accounts"] == []


def test_a_twilio_connection_without_an_account_sid_is_refused(world, stack):
    err = world.a.boss.err("POST", "/v1/confirmations/sending-accounts", body=body(stack), name="validation_failed")
    assert "account_sid" in err["fields"]["credentials"]


def test_credential_keys_are_strict_per_provider_and_an_ses_region_must_be_on_the_allowlist(world, stack):
    a = world.a.boss
    err = a.err("POST", "/v1/confirmations/sending-accounts", body=body(stack, colour="red"), name="validation_failed")
    assert "colour" in err["fields"]["credentials"]
    mail = {"channel": "email", "provider": "ses", "from": {"email_address": "hello@example.com", "display_name": "Acme"}}
    a.err("POST", "/v1/confirmations/sending-accounts", body={**mail, "credentials": {"access_key": "k", "secret": "s", "region": "evil-1"}},
          name="validation_failed")
    a.err("POST", "/v1/confirmations/sending-accounts", body={**mail, "credentials": {"access_key": "k", "secret": "s", "extra": "x"}},
          name="validation_failed")
    pm = {"channel": "email", "provider": "postmark", "from": {"email_address": "hello@example.com", "display_name": "Acme"}}
    a.err("POST", "/v1/confirmations/sending-accounts", body={**pm, "credentials": {"server_token": "t", "region": "us-east-1"}},
          name="validation_failed")
    a.ok("POST", "/v1/confirmations/sending-accounts", body={**mail, "credentials": {"access_key": "k", "secret": "s", "region": "us-west-2"}})


def test_a_valid_account_sid_is_stored_in_the_clear_and_reaches_the_provider_with_the_api_key(world, stack):
    o = world.a
    seen = []
    real = stack.twilio.read_sender
    stack.twilio.read_sender = lambda creds: (seen.append(dict(creds)), real(creds))[1]
    acct = o.boss.ok("POST", "/v1/confirmations/sending-accounts", body=body(stack, account_sid=SID))
    (row,) = world.sql(o, "SELECT account_sid, credential_ids_ct FROM consentvault.sending_account WHERE org_id = %s", (o.org_id,))
    assert row["account_sid"] == SID and SID.encode() not in bytes(row["credential_ids_ct"])
    assert seen[0]["account_sid"] == SID and "auth_token" not in seen[0]
    o.boss.ok("POST", f"/v1/confirmations/sending-accounts/{acct['account_id']}:check", body={})
    assert seen[-1]["account_sid"] == SID
