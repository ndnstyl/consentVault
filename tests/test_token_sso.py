from consentvault.tenancy.tokens import TokenKey, mint_org_token, token_sso

KEY = TokenKey("k1", b"x" * 32)
ORG = "11111111-1111-4111-8111-111111111111"
CONN = "conn_01E4ZCR3C56J083X43JQXF3JK5"


def test_the_connection_a_session_came_through_rides_in_the_tenant_token_and_nowhere_else():
    assert token_sso(mint_org_token(KEY, ORG, ["admin"], credential_id="member:1", sso_connection=CONN)) == CONN
    assert token_sso(mint_org_token(KEY, ORG, ["admin"], credential_id="member:1")) is None


def test_an_unreadable_token_has_no_connection():
    for bad in (None, "", "v1.k1", "v1.k1.zz.sig", "v1.k1." + b"[]".hex() + ".sig", "v1.k1." + b'{"sso":5}'.hex() + ".sig"):
        assert token_sso(bad) is None, bad
