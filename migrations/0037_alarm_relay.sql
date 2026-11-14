-- Alarm relay: every operator alarm is published to the platform alerts channel by a scheduled job, and marked relayed only
-- after the publish succeeded. The mark is the one new change an alarm row accepts besides its acknowledgement, set once.
-- The job's login (the worker group) reads and marks alarms only through two owner-rights functions that return and touch
-- names, kinds, organisation ids and times: no reference id, no request id, no personal field.

ALTER TABLE consentvault.operator_alarm ADD COLUMN relayed_at timestamptz;

CREATE OR REPLACE FUNCTION consentvault.operator_alarm_guard() RETURNS trigger
    LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF (NEW.org_id, NEW.alarm_id, NEW.name, NEW.ref_kind, NEW.ref_id, NEW.error_class, NEW.request_id, NEW.raised_at)
       IS DISTINCT FROM
       (OLD.org_id, OLD.alarm_id, OLD.name, OLD.ref_kind, OLD.ref_id, OLD.error_class, OLD.request_id, OLD.raised_at)
       OR (OLD.acknowledged_at IS NOT NULL AND (NEW.acknowledged_at, NEW.acknowledged_by) IS DISTINCT FROM
           (OLD.acknowledged_at, OLD.acknowledged_by))
       OR (OLD.relayed_at IS NOT NULL AND NEW.relayed_at IS DISTINCT FROM OLD.relayed_at)
       OR ((NEW.acknowledged_at, NEW.relayed_at) IS NOT DISTINCT FROM (OLD.acknowledged_at, OLD.relayed_at))
    THEN
        RAISE EXCEPTION 'consentvault: an operator alarm is only ever acknowledged once and relayed once'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

GRANT UPDATE (relayed_at) ON consentvault.operator_alarm TO consentvault_operator;
GRANT CREATE ON SCHEMA consentvault TO consentvault_operator;

-- Alarms not yet relayed, oldest first, across organisations.
CREATE FUNCTION consentvault.alarm_relay_pending(p_limit integer)
    RETURNS TABLE (org_id uuid, alarm_id uuid, name text, error_class text, ref_kind text, raised_at timestamptz,
                   unrelayed_in_org bigint)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT a.org_id, a.alarm_id, a.name, a.error_class, a.ref_kind, a.raised_at,
           (SELECT count(*) FROM consentvault.operator_alarm b WHERE b.org_id = a.org_id AND b.relayed_at IS NULL)
      FROM consentvault.operator_alarm a
     WHERE a.relayed_at IS NULL
     ORDER BY a.raised_at, a.alarm_id
     LIMIT greatest(1, least(coalesce(p_limit, 100), 1000));
$$;
ALTER FUNCTION consentvault.alarm_relay_pending(integer) OWNER TO consentvault_operator;
REVOKE ALL ON FUNCTION consentvault.alarm_relay_pending(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.alarm_relay_pending(integer) TO consentvault_worker;

-- Mark one alarm relayed; true when it was unrelayed and is now marked.
CREATE FUNCTION consentvault.alarm_relay_mark(p_org uuid, p_alarm uuid) RETURNS boolean
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    n integer;
BEGIN
    UPDATE consentvault.operator_alarm SET relayed_at = pg_catalog.clock_timestamp()
     WHERE org_id = p_org AND alarm_id = p_alarm AND relayed_at IS NULL;
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n = 1;
END;
$$;
ALTER FUNCTION consentvault.alarm_relay_mark(uuid, uuid) OWNER TO consentvault_operator;
REVOKE ALL ON FUNCTION consentvault.alarm_relay_mark(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.alarm_relay_mark(uuid, uuid) TO consentvault_worker;

REVOKE CREATE ON SCHEMA consentvault FROM consentvault_operator;
