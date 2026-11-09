"""The registry of refusal codes: every start-up, role, migration and notification refusal the product raises in Python, each with its
own stable code and a one-line meaning. A log, a terminal or an alarm shows the error's class and this code (safelog.describe), never
the error's text, so an operator can tell which check fired.

Database refusals (a ``RAISE EXCEPTION`` in a migration) have their own generated registry, ``data/refusal_codes.json``, built by
``scripts/build_refusal_codes.py``. ``tests/test_refusal_codes.py`` checks that every refusal site in src/ passes a code registered
here, that no two sites share a code, and that no Python code collides with a database code.
"""

# The owner-rights and guard-pinning checks report one fixed sentence per kind of problem; each refuses with the code made from its
# sentence (api.startup_check_code), so every check has its own code: startup_the_schema_owner_can_log_in, and so on.
CHECK_CODE_FAMILY = "startup_<the check's sentence>"

PYTHON_REFUSALS: dict[str, str] = {
    # the multi-tenant API's start check
    "startup_session_refused": "the login itself must not serve tenants: a superuser, the schema owner or a BYPASSRLS member",
    "startup_database_refused": "a database start check refused; the database code beside it names which one",
    "startup_database_unreachable": "the start check could not reach the database",
    "startup_single_mode": "the vault is in single mode; a multi-tenant service must not serve it",
    "startup_tenancy_check_refused": "the tenancy check refused for a reason with no violation row; the database code beside it names it",
    "startup_guard_predates_pinning": "the trigger guard predates guard pinning; rerun the guard install as a superuser",
    "startup_migration_login_can_log_in": "a migration login can still log in outside a migration run",
    "startup_projection_login_missing": "no projection login is configured for the multi-tenant API",
    "startup_projection_login_refused": "the projection login is not a member of the projection role alone",
    "startup_projection_login_unusable": "the projection login cannot connect",
    "startup_projection_settings_refused": "the settings read that every tenant post is stored with fails against this database",
    "startup_manifest_drift": "the database's security surface differs from the manifest shipped with this build",
    "startup_test_clock_role": "the role consentvault_test_clock (a test cluster's) exists on the database's server",
    # migrations
    "migrations_dir_unset": "no migrations directory was configured",
    "migrations_dir_missing": "the configured migrations directory does not exist",
    "migration_file_misnamed": "a migration file is not named NNNN_name.sql",
    "migrator_cannot_set_role": "the migration login cannot SET ROLE to the schema owner",
    "applied_migration_missing": "a migration recorded as applied is missing from the folder",
    "applied_migration_changed": "a migration recorded as applied has changed since it was applied",
    "migration_out_of_order": "a pending migration is numbered at or below the highest applied one",
    "migration_left_wrong_role": "a migration left the session as a role other than the schema owner",
    "migration_failed": "a migration failed and was rolled back; the database code beside it names the refusal",
    # job logins
    "selftest_login_privileged": "the isolation self-test login would read past row security",
    "selftest_login_not_in_group": "the isolation self-test login is not a member of its group",
    "lifecycle_login_privileged": "the key-lifecycle login would act beyond the operator console's grants",
    "lifecycle_login_not_in_console": "the key-lifecycle login is not a member of the operator console group",
    "drill_login_privileged": "the restore drill login would act beyond its one grant",
    "drill_login_not_in_group": "the restore drill login is not a member of its group",
    "jobs_login_not_in_group": "the records jobs login is not a member of its group",
    "integrity_mode_unknown": "the integrity job could not tell single from multi-tenant mode",
    "integrity_login_not_in_group": "the integrity job's login is not a member of the integrity group in multi-tenant mode",
    # the Twenty workflow credential
    "twenty_gate_policy_required": "no approved policy is in force, so no Twenty gate credential is issued",
    "twenty_gate_system_disconnected": "the Twenty system is disconnected, so no gate credential is issued",
    "twenty_gate_credential_exists": "the system already has its gate credential; a replacement may be made from day 76 of it",
    # notifications
    "notify_recipient_not_email": "a notification recipient is not a valid email address",
    "notify_variable_looks_like_email": "a notification template variable looks like an email address",
    "notify_variable_looks_like_phone": "a notification template variable looks like a phone number",
    "notify_unknown_template": "a notification names a template that does not exist",
    "notify_unexpected_variable": "a notification passes a variable its template does not take",
    "notify_missing_variable": "a notification leaves out a variable its template needs",
}
