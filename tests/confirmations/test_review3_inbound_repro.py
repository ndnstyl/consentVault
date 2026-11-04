from contract_world.confirm import text_in

P = "+13055550142"


def _raw(world, o):
    return len(world.sql(o, "SELECT 1 FROM consentvault.raw_post WHERE org_id = %s", (o.org_id,)))


def test_r5_a_stop_text_that_fails_later_in_the_transaction_leaves_no_raw_post(world, stack, armed):
    o = world.a
    world.capture(o, P)
    before = _raw(world, o)
    with world.vault.superuser() as su:
        su.execute("CREATE FUNCTION public.cvt_g() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'down'; END $$")
        su.execute("CREATE TRIGGER cvt_g BEFORE INSERT ON consentvault.confirmation_reply FOR EACH ROW EXECUTE FUNCTION public.cvt_g()")
    try:
        assert text_in(armed, "STOP", sender=P, sid="SMr5").status == 503
    finally:
        with world.vault.superuser() as su:
            su.execute("DROP TRIGGER cvt_g ON consentvault.confirmation_reply")
            su.execute("DROP FUNCTION public.cvt_g()")
    print("R5 raw posts before", before, "after", _raw(world, o))
    assert _raw(world, o) == before + 1
