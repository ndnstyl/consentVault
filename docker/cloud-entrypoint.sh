#!/bin/sh
set -eu
# Cloud image entrypoint. Fargate injects secrets as environment values only and the root filesystem is read-only, so
# every secret the product reads from a file is written under /tmp/cv (the task's scratch volume), mode 600, and removed
# from the environment before the command runs. The pairs below are deploy/cloud-settings.json's secret_file entries
# (tests/test_cloud_settings.py holds the two together):
#   CV_ACCESS_KEY_HEX        -> access-key.hex          (CONSENTVAULT_ACCESS_KEY_FILE)
#   CV_RECEIPT_KEY_HEX       -> receipt-key.hex         (CONSENTVAULT_RECEIPT_KEY_FILE)
#   CV_CURSOR_KEY_HEX        -> cursor-key.hex          (CONSENTVAULT_CURSOR_KEY_FILE)
#   CV_LINK_SECRET_HEX       -> link-secret.hex         (CONSENTVAULT_LINK_SECRET_FILE)
#   CV_TENANT_TOKEN_KEY_HEX  -> tenant-token-key.hex    (CONSENTVAULT_TOKEN_KEY_FILE)
#   CV_EGRESS_SECRET         -> egress-secret           (CONSENTVAULT_EGRESS_SECRET_FILE)
#   CV_STRIPE_SECRET_KEY     -> stripe-secret-key       (CONSENTVAULT_STRIPE_SECRET_KEY_FILE)
#   CV_STRIPE_WEBHOOK_SECRET -> stripe-webhook-secret   (CONSENTVAULT_STRIPE_WEBHOOK_SECRET_FILE)
#   CV_ORG_KEY_POLICY_JSON   -> org-key-policy.json     (CONSENTVAULT_KMS_ORG_KEY_POLICY_FILE)
# Each task is handed only the values it uses, so a value that is not given writes no file; the product then refuses by
# name when it needs the file. A *_HEX value that is not hex stops the task (exit 2) before anything runs.
dir="${CV_FILES_DIR:-/tmp/cv}"
umask 077
mkdir -p "$dir"
hex=""

put() {  # put NAME FILE: write the named variable's value to FILE when the task was given it
    if eval "[ -n \"\${$1+given}\" ]"; then
        case "$1" in
            *_HEX)
                eval "hex=\"\$$1\""
                case "$hex" in
                    ""|*[!0-9a-fA-F]*) echo "cv-entrypoint: $1 is not hex; nothing was started" >&2; exit 2 ;;
                esac ;;
        esac
        eval "printf '%s' \"\$$1\"" > "$dir/$2.tmp"
        mv "$dir/$2.tmp" "$dir/$2"
    fi
}

put CV_ACCESS_KEY_HEX access-key.hex
put CV_RECEIPT_KEY_HEX receipt-key.hex
put CV_CURSOR_KEY_HEX cursor-key.hex
put CV_LINK_SECRET_HEX link-secret.hex
put CV_TENANT_TOKEN_KEY_HEX tenant-token-key.hex
put CV_EGRESS_SECRET egress-secret
put CV_STRIPE_SECRET_KEY stripe-secret-key
put CV_STRIPE_WEBHOOK_SECRET stripe-webhook-secret
put CV_ORG_KEY_POLICY_JSON org-key-policy.json
unset CV_ACCESS_KEY_HEX CV_RECEIPT_KEY_HEX CV_CURSOR_KEY_HEX CV_LINK_SECRET_HEX CV_TENANT_TOKEN_KEY_HEX CV_EGRESS_SECRET CV_STRIPE_SECRET_KEY CV_STRIPE_WEBHOOK_SECRET CV_ORG_KEY_POLICY_JSON
unset hex

exec "$@"
