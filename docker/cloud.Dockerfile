# The managed service's image: the open product image (BASE_IMAGE, built from ../Dockerfile by
# scripts/build_cloud_image.sh and tagged with its own image id, so this layer is built on exactly that image) plus the private KMS key provider, copied from the build
# context named kmsplugin (the ops repository's provider/ folder; never published to an index), and the entrypoint that
# writes the injected secrets to /tmp/cv. Needs BuildKit (named build contexts); the script runs it that way.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
USER root
# The plugin package whole (a hand-kept file list once left a module out), then the test fake and its contract factory
# removed and proved absent. tests/test_image_pins.py checks every module the package imports survives this step.
COPY --from=kmsplugin consentvault_kms/ /usr/local/lib/python3.12/site-packages/consentvault_kms/
COPY docker/cloud-entrypoint.sh /usr/local/bin/cv-entrypoint
RUN chmod 0555 /usr/local/bin/cv-entrypoint \
    && rm -f /usr/local/lib/python3.12/site-packages/consentvault_kms/fake.py /usr/local/lib/python3.12/site-packages/consentvault_kms/contract.py \
    && rm -rf /usr/local/lib/python3.12/site-packages/consentvault_kms/__pycache__ \
    && test ! -e /usr/local/lib/python3.12/site-packages/consentvault_kms/fake.py \
    && test ! -e /usr/local/lib/python3.12/site-packages/consentvault_kms/contract.py \
    && python -c "import consentvault_kms; from consentvault_kms import KmsEvidenceSigner, KmsKeyProvider; from consentvault.notify.cloud import SesMailer, SesNotifier; from consentvault.providers.plugins import load_key_provider"
# The task's root filesystem is read-only and /tmp is a Fargate ephemeral volume. Fargate fills that volume from this image
# only for a path declared with VOLUME (ECS developer guide, "Bind mounts"), keeping owner and mode: /tmp sticky and
# world-writable, and the entrypoint's secret folder owned by the runtime user, mode 700.
RUN mkdir -p /tmp/cv \
    && chown consentvault:consentvault /tmp/cv \
    && chmod 0700 /tmp/cv \
    && chmod 1777 /tmp
VOLUME ["/tmp"]
USER consentvault
ENTRYPOINT ["/usr/local/bin/cv-entrypoint"]
# The managed service runs the multi-tenant cloud entry: the dashboard's routes, the edge sign-in and the metrics ticker.
CMD ["consentvault", "serve-cloud", "--host", "0.0.0.0", "--port", "8080"]
