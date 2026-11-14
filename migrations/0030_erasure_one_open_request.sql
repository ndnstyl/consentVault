-- One open erasure request per contact. A second request for a contact whose first is still open (waiting for an
-- operator, held behind a legal hold, or waiting for deliveries) is a duplicate: it would be confirmed twice and write a
-- second stop and a second ledger intent for one person. A completed or declined request no longer blocks a new one.
--
-- The index is refused loudly when the table already holds two open requests for one contact: the migration names them
-- instead of choosing one to drop.
DO $$
DECLARE
    dup record;
BEGIN
    SELECT org_id, contact_fp, count(*) AS n INTO dup
      FROM consentvault.erasure_request WHERE status = 'pending_operator_confirmation'
     GROUP BY org_id, contact_fp HAVING count(*) > 1 LIMIT 1;
    IF FOUND THEN
        RAISE EXCEPTION 'consentvault migration 0030 refused: organisation % has % open erasure requests for contact %; '
            'decline all but one, then run it again', dup.org_id, dup.n, left(dup.contact_fp, 8)
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
END
$$;

CREATE UNIQUE INDEX erasure_request_one_open_idx ON consentvault.erasure_request (org_id, contact_fp)
    WHERE status = 'pending_operator_confirmation';
