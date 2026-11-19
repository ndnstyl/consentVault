# Zapier: update an existing CRM contact from ConsentVault

ConsentVault never creates a contact. This Zap finds the person in your CRM by email or phone and updates them. If nobody matches, it does nothing to the CRM and, for a stop, alerts you.

Not yet run end to end by a person. Zapier's step names can differ by plan; the checks in step 2 tell you if yours differs.

## Before you start
- In ConsentVault, connect the system (Setup, Connect a system) with **Contact sent as: Plain contact point**. A CRM cannot match on Fingerprint only. The choice is recorded in the audit log.
- Pick **HMAC shared secret** as the signature. The secret is 64 hex characters and is shown once. Keep it.

## Steps
1. **Trigger: Webhooks by Zapier, Catch Raw Hook.** Copy the Zap's webhook address into ConsentVault as the endpoint. Use Send a test push. The sample must show the raw body and the header `X-ConsentVault-Signature`. If your sample shows no headers, Zapier cannot verify the signature for you: use the n8n template instead.
2. **Code by Zapier (Python): verify.** Input data: `raw_body` (the raw body), `signature` (the header value), `secret` (your secret), `key` (the Idempotency-Key header). Code:
```python
import hmac, hashlib, json
want = "hmac-sha256=" + hmac.new(bytes.fromhex(input_data["secret"]), input_data["raw_body"].encode("utf-8"), hashlib.sha256).hexdigest()
if not hmac.compare_digest(want, input_data["signature"]):
    raise Exception("ConsentVault signature does not match; stop")
m = json.loads(input_data["raw_body"])
c = (m.get("contact") or "").strip()
digits = "".join(ch for ch in c if ch.isdigit())
if "@" in c:
    kind, value = "email", c.lower()
elif len(digits) >= 7:
    kind, value = "phone", ("+" + digits) if c.startswith("+") else ("+1" + digits if len(digits) == 10 else "+" + digits)
else:
    raise Exception("Contact sent as Fingerprint only; reconnect with Plain contact point")
output = {"kind": kind, "value": value, "state": m["state"], "version": m["version"], "channel": m["channel"], "at": m["at"]}
```
A mismatch stops the Zap, which Zapier shows as an error. ConsentVault's push is not acknowledged, so it is retried and then shown as Undelivered in the portal.
3. **Filter: only continue if the key is new.** Use Storage by Zapier, Get Value with the Idempotency-Key; continue only if it is empty. After step 7, Set Value for that key.
4. **Your CRM: Find Contact(s)** by `kind`/`value`. Turn **off** any "create if not found" option. Zapier returns every match; add a **Looping by Zapier** step so each match is updated.
5. **Filter inside the loop: only continue if your CRM's stored version for this channel is lower than `version`.** A late grant must never lift a newer stop.
6. **Your CRM: Update Contact** in the loop. Write the state and the version into the channel's own field (see the help article, Send sign-ups and stops to your CRM, for the field-per-channel rule).
7. **If Find returned nothing:** add a Path with the rule "found count is 0". On `state = denied` send an email or Slack message titled "Stop for someone not in your CRM; check your dialer and texting tool". On a grant, only log. Never add a Create Contact step.
