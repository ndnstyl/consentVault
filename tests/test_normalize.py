import pytest

from consentvault.errors import NormalizationError
from consentvault.normalize import normalize_contact, normalize_email, normalize_phone, subject_key


@pytest.mark.parametrize("raw", ["(212) 555-0100", "212-555-0100", "1 212 555 0100", "+1 (212) 555-0100", "212.555.0100"])
def test_nanp_phone_forms(raw):
    assert normalize_phone(raw, "US") == "+12125550100"


def test_plus_passthrough_international():
    assert normalize_phone("+44 20 7946 0000") == "+442079460000"


def test_no_region_no_plus_refused():
    with pytest.raises(NormalizationError):
        normalize_phone("2125550100")


def test_bad_numbers_refused():
    for bad in ["", "123", "+0123456789", "(012) 555-0100"]:
        with pytest.raises(NormalizationError):
            normalize_phone(bad, "US")


def test_email_lowercased():
    assert normalize_email("  Person@Example.COM ") == "person@example.com"
    with pytest.raises(NormalizationError):
        normalize_email("not-an-email")


def test_contact_kind_detection_and_subject_key():
    assert normalize_contact("A@Example.com") == ("email", "a@example.com")
    assert normalize_contact("212-555-0100", region="US") == ("phone", "+12125550100")
    assert len(subject_key("+12125550100")) == 64
    assert subject_key("+12125550100") == subject_key("+12125550100")
    assert subject_key("+12125550100", "caller-key") == "caller-key"
