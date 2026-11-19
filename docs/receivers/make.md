# Make: update an existing CRM contact from ConsentVault

ConsentVault never creates a contact. This scenario finds the person in your CRM by email or phone and updates them. If nobody matches, it does nothing to the CRM and, for a stop, alerts you.

Not yet run end to end by a person. Make module names can differ by app; the checks below tell you if yours differs.

## Before you start
- In ConsentVault, connect the system with **Contact sent as: Plain contact point**. Fingerprint only cannot match a CRM contact. The choice is recorded in the audit log.
- Choose **HMAC shared secret**. The 64-character secret is shown once.

## Steps
1. **Webhooks, Custom webhook.** Create the webhook, tick **Get request headers** and **JSON pass-through**, copy its address into ConsentVault as the endpoint, and use Send a test push. The signature is over the exact body text, so the raw text must be kept: pass-through keeps it.
2. **Tools, Set multiple variables: verify.** Compute `sha256(<raw body>; <your secret as hex converted to binary>)` as an HMAC and compare it with the header `x-consentvault-signature` after the `hmac-sha256=` prefix. If your Make version cannot take the key as binary, use the n8n template instead.
3. **Filter: stop unless the signature matches.** Add an error handler that returns status 401 to ConsentVault so the push is retried and then shown as Undelivered.
4. **Filter: only continue when `Idempotency-Key` is new.** Use a Data store: search it for the key; continue only if absent; add the key after step 7.
5. **Normalise.** Email: `lower(contact)`. Phone: remove everything except digits and the leading plus; a 10 digit number gets `+1` in front.
6. **Your CRM, Search for contacts** by that email or phone. Search returns every match. Do not add any Create module.
7. **Iterator over the matches, then a filter:** only continue if the CRM's stored version for the channel is lower than the message's `version`. Then **Update contact** with the state and version in the channel's own field.
8. **If the search returned nothing:** a router branch on "number of results = 0". When `state = denied`, send an email or Slack message titled "Stop for someone not in your CRM; check your dialer and texting tool". For a grant, only add a log line.
