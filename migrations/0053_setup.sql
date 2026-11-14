-- Setup progress (setup.md): the only thing stored is a skip of an optional step. Whether a step is done is read from the facts
-- on every request and never stored; no column here holds a done flag, a status or a completion time.
CREATE TABLE consentvault.setup_step_skip (
    org_id     uuid NOT NULL REFERENCES consentvault.organization (org_id),
    step       text NOT NULL CHECK (step IN ('system', 'confirmations')),
    skipped_by uuid,
    skipped_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    reason     text CHECK (reason IS NULL OR length(reason) <= 200),
    PRIMARY KEY (org_id, step)
);

ALTER TABLE consentvault.setup_step_skip ENABLE ROW LEVEL SECURITY;
ALTER TABLE consentvault.setup_step_skip FORCE ROW LEVEL SECURITY;
CREATE POLICY setup_step_skip_tenant ON consentvault.setup_step_skip USING (org_id = (SELECT consentvault.current_org()))
    WITH CHECK (org_id = (SELECT consentvault.current_org()));
REVOKE ALL ON consentvault.setup_step_skip FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON consentvault.setup_step_skip TO consentvault_app;
