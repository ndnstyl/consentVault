"""``python -m consentvault.sync``: the sync worker's start command (the same as ``consentvault sync-worker``)."""

import sys

from ..cli import main

if __name__ == "__main__":
    sys.exit(main(["sync-worker", *sys.argv[1:]]))
