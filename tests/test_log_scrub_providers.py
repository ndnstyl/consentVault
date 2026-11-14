"""Provider credentials never reach a log line: Twilio account and key ids and the auth token, AWS access keys and secrets, Postmark
tokens (confirmations.md section 1). Ordinary identifiers (a UUID, a request id) keep their value."""

import pytest

from consentvault.tenancy.logscrub import REDACTED, scrub

CASES = [
    "AC" + "0123456789abcdef" * 2,
    "SK" + "fedcba9876543210" * 2,
    "0123456789abcdef0123456789abcdef",                     # a Twilio auth token
    "AKIAIOSFODNN7EXAMPLE",
    "ASIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",             # an AWS secret access key
    "X-Postmark-Server-Token: 9d3a1c1e-7b1a-4c3e-9f6e-2a1b3c4d5e6f",
    "account_token=9d3a1c1e-7b1a-4c3e-9f6e-2a1b3c4d5e6f",
]


@pytest.mark.parametrize("secret", CASES)
def test_a_provider_credential_is_redacted_wherever_it_appears(secret):
    line = scrub(f"calling the provider with {secret} now")
    key = secret.split(": ")[-1].split("=")[-1]
    assert key not in line and REDACTED in line


def test_ordinary_identifiers_keep_their_value():
    text = "request req-1a2b3c org 9d3a1c1e-7b1a-4c3e-9f6e-2a1b3c4d5e6f status connected"
    assert scrub(text) == text


@pytest.mark.parametrize("line,hidden", [
    ("config api_key_secret=abcDEF123456", "abcDEF123456"),
    ("config aws_secret_access_key=wJalrXUtnFEMIEXAMPLE1", "wJalrXUtnFEMIEXAMPLE1"),
    ("callback?to=%2B18135550142&x=1", "8135550142"),
    ("mail%40example.com failed", "example.com"),
])
def test_a_key_name_with_a_prefix_and_a_url_encoded_contact_are_redacted(line, hidden):
    assert hidden not in scrub(line)


def test_a_contact_encoded_twice_is_redacted():
    assert "8135550142" not in scrub("callback?to=%252B18135550142")
    assert "8135550142" not in scrub("callback?to=%25252B18135550142")


def test_a_phone_number_after_an_underscore_is_redacted():
    assert "8135550142" not in scrub("lead_8135550142 failed") and "8135550142" not in scrub("phone_+18135550142")
