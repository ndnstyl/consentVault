#!/usr/bin/env bash
# Build the managed service's image: the open product image, then the cloud layer on top of it with the private KMS
# key provider. Never pushes; prints the two image ids.
#   scripts/build_cloud_image.sh [TAG]        (KMS_PLUGIN_DIR defaults to /Users/oxfloors/ConsentVault/operations/provider)
# Exit 2 when the plugin folder is missing; any docker failure stops the build with its own exit code.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
tag=${1:-consentvault:cloud}
plugin=${KMS_PLUGIN_DIR:-/Users/oxfloors/ConsentVault/operations/provider}
if [ ! -d "$plugin/consentvault_kms" ]; then
    echo "build_cloud_image: the private KMS key provider is not at $plugin/consentvault_kms (set KMS_PLUGIN_DIR)" >&2
    exit 2
fi
cd "$root"
iidfile=$(mktemp)
trap 'rm -f "$iidfile"' EXIT
DOCKER_BUILDKIT=1 docker build --iidfile "$iidfile" .
base_id=$(cat "$iidfile")
case "$base_id" in sha256:*) ;; *) echo "build_cloud_image: the open image build gave no image id" >&2; exit 3 ;; esac
# A tag named by the image id itself: the cloud layer is built FROM exactly the open image just built.
docker tag "$base_id" "consentvault-open:${base_id#sha256:}"
DOCKER_BUILDKIT=1 docker build -f docker/cloud.Dockerfile --build-arg "BASE_IMAGE=consentvault-open:${base_id#sha256:}" \
    --build-context "kmsplugin=$plugin" -t "$tag" .
echo "open image $base_id"
echo "cloud image $(docker image inspect --format '{{.Id}}' "$tag") as $tag"
