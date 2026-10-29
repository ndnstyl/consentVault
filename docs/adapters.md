<p>
  <a href="../README.md"><picture>
    <source media="(prefers-color-scheme: dark)" srcset="../.github/assets/logo-dark.svg">
    <img alt="ConsentVault.AI" src="../.github/assets/logo-light.svg" height="36">
  </picture></a>
</p>

# Adapters

The core knows contact points, channels, purposes and events. Everything vendor-specific lives behind two
small interfaces in `consentvault.adapters`.

## Interfaces

```python
class CrmAdapter(Protocol):
    name: str
    def push_permission_change(self, change: PermissionChange) -> None: ...

class MessagingAdapter(Protocol):
    name: str
    def pull_stop_messages(self, since: datetime | None = None) -> Sequence[StopMessage]: ...
```

- `push_permission_change` delivers one change (`contact_norm`, `contact_kind`, `channel`, `purpose`,
  `allowed`, `reason`, optional `event_id`, `changed_at`) to a system of record. If it was not delivered it
  must raise `AdapterError`. Never return quietly on failure.
- `pull_stop_messages` returns inbound messages that may be stop requests. Feed each `text` to
  `consentvault classify` (or `consentvault.stopwords`); a `stop` becomes a suppress event, `needs_review` goes to a person.
  A failed pull raises `AdapterError`.

## Included

- `NullCrmAdapter` and `NullMessagingAdapter`: do nothing. For installs with no CRM or provider.
- `WebhookCrmAdapter(url, secret)`: POSTs each change as JSON with
  `X-ConsentVault-Timestamp` and `X-ConsentVault-Signature`, where the signature is hex HMAC-SHA256 over
  `timestamp + "." + body`. Any non-2xx answer or network error raises `AdapterError`.

Verifying a webhook on the receiving side:

```python
import hmac, hashlib, time
def verify(secret, timestamp, body, signature, tolerance=300):
    if abs(time.time() - int(timestamp)) > tolerance:
        return False
    expected = hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)
```

## Writing your own

1. Implement the protocol; keep credentials in config or the environment, never in code.
2. Raise `AdapterError` on every failure path. Retrying is the caller's job and must be bounded.
3. Make the push idempotent on `event_id`, so a retry cannot double-apply.
4. Test with an injected transport, as `tests/test_adapters.py` does for the webhook adapter.

---

[Back to the README](../README.md) · [Architecture](../ARCHITECTURE.md)
