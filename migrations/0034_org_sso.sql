-- Company single sign-on. The operator binds a sign-in-service organization (and its connections) to a ConsentVault organization;
-- an admin never types a connection id. The bound connections are the only ones that can ever admit anyone, and the binding is
-- proved when one of the organization's own admins signs in through a bound connection (that sign-in names the sign-in-service
-- organization too, and both must match). Only a proved binding may be required. Append-only versions, like retention: the
-- newest row is the setting in force and every change stays on record.
CREATE TABLE consentvault.org_sso (
    org_id            uuid NOT NULL REFERENCES consentvault.organization (org_id),
    version           integer NOT NULL CHECK (version >= 1),
    workos_org_id     text CHECK (workos_org_id IS NULL OR workos_org_id ~ '^org_[A-Za-z0-9]{10,64}$'),
    bound_connections text[] NOT NULL DEFAULT '{}'
        CHECK (array_to_string(bound_connections, ',') ~ '^(conn_[A-Za-z0-9]{10,64}(,conn_[A-Za-z0-9]{10,64})*)?$'),
    connection_id     text CHECK (connection_id IS NULL OR connection_id ~ '^conn_[A-Za-z0-9]{10,64}$'),
    require_sso       boolean NOT NULL DEFAULT false,
    verified          boolean NOT NULL DEFAULT false,
    set_by            uuid,
    set_by_operator   text CHECK (set_by_operator IS NULL OR length(set_by_operator) BETWEEN 1 AND 200),
    applies_from      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, version),
    CONSTRAINT org_sso_binding_pair CHECK ((workos_org_id IS NULL) = (cardinality(bound_connections) = 0)),
    -- proved means an admin signed in through one of the bound connections: the one that proved it is recorded
    CONSTRAINT org_sso_proved_in_binding CHECK (verified = (connection_id IS NOT NULL)
                                                AND (connection_id IS NULL OR connection_id = ANY (bound_connections))),
    -- only a proved binding may be required
    CONSTRAINT org_sso_required_needs_proved CHECK (NOT require_sso OR verified)
);
CREATE TRIGGER org_sso_append_only BEFORE UPDATE OR DELETE ON consentvault.org_sso
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();
ALTER TABLE consentvault.org_sso ENABLE ROW LEVEL SECURITY;
ALTER TABLE consentvault.org_sso FORCE ROW LEVEL SECURITY;
CREATE POLICY org_sso_tenant ON consentvault.org_sso USING (org_id = (SELECT consentvault.current_org()))
    WITH CHECK (org_id = (SELECT consentvault.current_org()));
GRANT SELECT, INSERT ON consentvault.org_sso TO consentvault_app;
GRANT SELECT, INSERT ON consentvault.org_sso TO consentvault_console;
