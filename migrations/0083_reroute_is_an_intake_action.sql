-- Pure projection, migration step 2 (specs/capture-everything/pure-projection.md, "Migration 0081": renumbered 0083). A post stored
-- again in the organisation its site key belongs to is an intake action, written by the site-key retry lane beside the facts that
-- say so; the fold reads only facts. One append-only row per original: the primary key makes a second reroute of one original fail,
-- and the lane reads an existing row as done. The row lives in the ORIGINAL's organisation (from_org); the copy lives in to_org.
CREATE TABLE consentvault.raw_post_reroute (
    from_org    uuid NOT NULL REFERENCES consentvault.organization (org_id),
    from_post   uuid NOT NULL,
    to_org      uuid NOT NULL REFERENCES consentvault.organization (org_id),
    to_post     uuid NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (from_post),
    UNIQUE (to_post),
    FOREIGN KEY (from_org, from_post) REFERENCES consentvault.raw_post (org_id, post_id),
    FOREIGN KEY (to_org, to_post) REFERENCES consentvault.raw_post (org_id, post_id)
);
CREATE TRIGGER raw_post_reroute_append_only BEFORE UPDATE OR DELETE ON consentvault.raw_post_reroute
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();
CREATE TRIGGER raw_post_reroute_no_truncate BEFORE TRUNCATE ON consentvault.raw_post_reroute
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();

ALTER TABLE consentvault.raw_post_reroute ENABLE ROW LEVEL SECURITY;
ALTER TABLE consentvault.raw_post_reroute FORCE ROW LEVEL SECURITY;
CREATE POLICY raw_post_reroute_tenant ON consentvault.raw_post_reroute USING (from_org = (SELECT consentvault.current_org()))
    WITH CHECK (from_org = (SELECT consentvault.current_org()));

GRANT SELECT ON consentvault.raw_post_reroute TO consentvault_app, consentvault_console, consentvault_integrity;
GRANT INSERT (from_org, from_post, to_org, to_post) ON consentvault.raw_post_reroute TO consentvault_app;
