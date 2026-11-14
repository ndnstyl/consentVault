-- Undo 0062: the push-start stamp goes; the claim's stamp is again a batch's attempt time.
DROP FUNCTION consentvault.sync_attempt_started(uuid[], integer[]);
