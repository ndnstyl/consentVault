# Security policy

## Reporting a vulnerability

Please do not open a public issue. Open a **private security advisory** on the project's GitHub
repository (Security tab, "Report a vulnerability"). Include what you found, how to reproduce it, and the
version.

You can expect an acknowledgement within a few days. Fixes ship as a patch version and are noted in
`CHANGELOG.md`.

## What counts

Anything that lets someone insert, alter, remove or backdate an event without detection, bypass the
signature check on the API, read data they should not, or make verification report a false pass.

## Handling data

ConsentVault.AI stores personal data (contact points, IP addresses, user agents). Run it on infrastructure you
control, restrict database access, rotate the signing secret, and back up the database. Only a 32-byte
digest is sent to the timestamp authority.

Run the API and the daily jobs as the restricted runtime role, never as the schema owner or a superuser, and
run `consentvault anchor` on a schedule to a sink the database host cannot rewrite. Without both, someone with write
access to the database can delete the newest rows without a trace. See `docs/deployment.md`.

An evidence bundle's `verify.py` needs the timestamp authority's root certificate and at least one anchor taken
from the anchor sink, both from outside the bundle. Keep the verified-grant secret away from the capture edge:
it is what allows a grant to lift a stop.
