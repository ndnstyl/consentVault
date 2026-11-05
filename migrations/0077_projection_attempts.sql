-- No error is ever a final reason (specs/capture-everything/one-door.md, addendum). When a stored post cannot be projected for
-- any reason other than the reader's own refusal, the projection records the attempt on the post and moves on: the code version
-- that ran, the class of the error, and the time (the database's clock, stamped here and never supplied by the caller). The post
-- is projected again on every run until it projects. The first attempt's time is what bounds the halt behind a faulted post.
--
-- A table beside the post, not a fact: an attempt that fails because the post's key cannot be opened must still be recordable,
-- and an attempt holds no personal data (a class name, never the text of the error). Append-only; nothing in it is ever edited.
CREATE TABLE consentvault.projection_attempt (
    org_id       uuid NOT NULL DEFAULT consentvault.current_org() REFERENCES consentvault.organization (org_id),
    post_id      uuid NOT NULL,
    attempt_id   uuid NOT NULL DEFAULT gen_random_uuid(),
    code_version text NOT NULL,
    error_class  text NOT NULL,
    attempted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, post_id, attempt_id),
    FOREIGN KEY (org_id, post_id) REFERENCES consentvault.raw_post (org_id, post_id)
);
CREATE INDEX projection_attempt_post_idx ON consentvault.projection_attempt (org_id, post_id, attempted_at);
CREATE TRIGGER projection_attempt_append_only BEFORE UPDATE OR DELETE ON consentvault.projection_attempt
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();
CREATE TRIGGER projection_attempt_no_truncate BEFORE TRUNCATE ON consentvault.projection_attempt
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();

ALTER TABLE consentvault.projection_attempt ENABLE ROW LEVEL SECURITY;
ALTER TABLE consentvault.projection_attempt FORCE ROW LEVEL SECURITY;
CREATE POLICY projection_attempt_tenant ON consentvault.projection_attempt USING (org_id = (SELECT consentvault.current_org()))
    WITH CHECK (org_id = (SELECT consentvault.current_org()));
CREATE POLICY projection_attempt_read_scope ON consentvault.projection_attempt AS RESTRICTIVE FOR SELECT
    USING ((SELECT consentvault.may_read_evidence()));

GRANT SELECT ON consentvault.projection_attempt TO consentvault_app, consentvault_console;
GRANT INSERT (org_id, post_id, code_version, error_class) ON consentvault.projection_attempt TO consentvault_app;
