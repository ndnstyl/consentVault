# ConsentVault self-host kit (skeleton)

Postgres 16, MinIO with Object Lock (COMPLIANCE default retention), OpenBao with the transit engine,
Keycloak as the OIDC provider, and the vault service built from the repository Dockerfile.
This is a skeleton: OpenBao and Keycloak run in dev mode and are not durable. Replace before real use.

Run every command from the repository root. Copy `selfhost.example.env` in this folder to a
local settings file named `.env` in the same folder and replace every CHANGE_ME. Never commit it.

## Check the file

    docker compose -f deploy/selfhost/docker-compose.yml --env-file deploy/selfhost/.env config

## Start

    docker compose -f deploy/selfhost/docker-compose.yml --env-file deploy/selfhost/.env up -d --build

Run the schema migration (`consentvault migrate`, as the owner role) against the `db` service before first use.

## Stop (data kept)

    docker compose -f deploy/selfhost/docker-compose.yml --env-file deploy/selfhost/.env down

## Teardown (deletes the database and evidence volumes)

    docker compose -f deploy/selfhost/docker-compose.yml --env-file deploy/selfhost/.env down --volumes --remove-orphans

Objects under COMPLIANCE retention cannot be deleted early through MinIO; teardown removes the volume itself.
