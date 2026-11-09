# The open product (the self-host image). The managed service's image is built on top of this one by
# scripts/build_cloud_image.sh from docker/cloud.Dockerfile, which adds the private KMS key provider and the entrypoint
# that writes the injected secrets to /tmp/cv; this file carries nothing private, so any builder can build it.
# The base image is pinned by digest (python:3.12-slim, the multi-architecture index as Docker Hub served it on
# 2026-10-30) and every Python package is installed from a hash-locked file (pip --require-hashes).
FROM python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends openssl \
    && apt-get clean

WORKDIR /app
# requirements-build.lock: the build backend (hatchling) and its dependencies; requirements.lock: the runtime
# dependencies with the cloud extra, exported from uv.lock (tests/test_image_pins.py checks it is current).
COPY requirements-build.lock requirements.lock ./
RUN pip install --no-cache-dir --require-hashes -r requirements-build.lock \
    && pip install --no-cache-dir --require-hashes -r requirements.lock
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY migrations ./migrations
RUN pip install --no-cache-dir --no-deps --no-build-isolation --no-index .

# The cloud migration task runs the trigger guard from the image; the sha256 is pinned here and must equal the pin in
# the cloud setup (tests/test_image_pins.py checks this one; the cloud setup checks its own). The build fails on any
# mismatch.
COPY docker/initdb/20-trigger-guard.sql /app/docker/initdb/20-trigger-guard.sql
# AWS's RDS global CA bundle, which the IAM database sign-in verifies the server against (sslmode=verify-full).
# Fetched once at build, pinned by sha256, verified; a different file fails the build.
RUN set -eu \
    && mkdir -p /etc/consentvault \
    && python -c "import sys, urllib.request; urllib.request.urlretrieve(sys.argv[1], sys.argv[2])" \
         https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem /etc/consentvault/rds-global-bundle.pem \
    && printf '%s\n' \
         "90a6f1a7978a1b1b096dca6c57511ca48d3b8cf052f8e704baf358f34ea2f21b  /etc/consentvault/rds-global-bundle.pem" \
         "995bb344c4fd4506f4201684204ba6b8f79f3a3e4c26c69d5adef13e56b34f8b  /app/docker/initdb/20-trigger-guard.sql" \
         > /tmp/consentvault-pins.sha256 \
    && sha256sum -c /tmp/consentvault-pins.sha256 \
    && rm /tmp/consentvault-pins.sha256 \
    && chmod 0444 /etc/consentvault/rds-global-bundle.pem /app/docker/initdb/20-trigger-guard.sql

ENV CONSENTVAULT_MIGRATIONS=/app/migrations
RUN useradd --system --uid 10001 consentvault
USER consentvault

EXPOSE 8080
CMD ["consentvault", "serve", "--host", "0.0.0.0", "--port", "8080"]

