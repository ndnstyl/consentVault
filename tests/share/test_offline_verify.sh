#!/bin/sh
# T027: the one-record file verifies with Python and openssl on a machine with no network.
#
# Builds the fixture with the suite's own throwaway authority, then runs verify_one.py inside a sandbox with networking
# removed (Linux: unshare -rn; macOS: sandbox-exec with network denied). Before it verifies anything it checks, inside the
# same sandbox, that a connection attempt fails; if networking cannot be removed, or still works, the script exits non-zero
# and says so: a pass is never reported from a machine that could have reached the network.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
py=${PYTHON:-$repo/.venv/bin/python}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/one"
OFFLINE_FIXTURE_DIR="$work/one" "$py" -m pytest "$here/test_record_zip.py::test_it_writes_the_fixture_for_the_offline_script" -q -p no:cacheprovider >"$work/build.log" 2>&1 \
    || { cat "$work/build.log"; echo "offline check: the fixture could not be built" >&2; exit 2; }
[ -f "$work/one/verify_one.py" ] || { cat "$work/build.log"; echo "offline check: no fixture was written" >&2; exit 2; }

probe='import socket,sys
try:
    socket.create_connection(("1.1.1.1", 53), timeout=3)
except OSError:
    sys.exit(0)
sys.exit(1)'

if command -v unshare >/dev/null 2>&1 && unshare -rn true 2>/dev/null; then
    sandbox() { unshare -rn "$@"; }
elif command -v sandbox-exec >/dev/null 2>&1; then
    sandbox() { sandbox-exec -p '(version 1)(allow default)(deny network*)' "$@"; }
else
    echo "offline check: no way to remove networking on this machine (need unshare or sandbox-exec); refusing to report a pass" >&2
    exit 3
fi

sandbox "$py" -c "$probe" || { echo "offline check: the sandbox still reaches the network; refusing to report a pass" >&2; exit 3; }
cd "$work/one"
mkdir "$work/outside"
mv "$work/one/tsa_root.pem" "$work/outside/tsa_root.pem"
sandbox "$py" verify_one.py --cafile "$work/outside/tsa_root.pem" | tee "$work/result.txt"
grep -q "^RESULT PASS" "$work/result.txt" || { echo "offline check: the one-record file did not pass" >&2; exit 1; }
echo "offline check: passed with networking removed"
