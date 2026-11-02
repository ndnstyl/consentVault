# Self-host suites receipts

`selfhost-suites.json` is written by `tests/selfhost/run_suites.sh` (format and fields in
`tests/selfhost/write_receipt.py`) on every run against the self-host stack, passed or failed. This folder is tracked:
the receipt is committed with the code it proved.

The checkpoint's traceability test accepts the receipt only when it is a clean run of the current code: exit code 0,
every section the runner runs passed, and its product-file digest and security-manifest digest equal to the current
ones. Any change to the product files or the manifest makes it stale; rerun the suites and commit the new receipt.
Until a receipt exists, every requirement proved only by the self-host run reads as pending.

`superseded/` keeps receipts of an earlier format for the record. Traceability never reads them: the format-1 receipt
of 2026-10-30 recorded no digest of the code it ran against, so it cannot be tied to any build.
