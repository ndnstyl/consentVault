# Make: update an existing CRM contact from ConsentVault

ConsentVault never creates a contact. This scenario finds the person in your CRM by email or phone and updates them. If nobody matches, it does nothing to the CRM and, for a stop, alerts you.

Not yet run end to end by a person. Everything below that depends on Make's behaviour is unverified and is marked **(unverified)**; check each one in your own scenario before you rely on it.

## Before you start
- In ConsentVault, connect the system with **Contact sent as: Plain contact point**. Fingerprint only cannot match a CRM contact. The choice is recorded in the audit log.
- Choose **HMAC shared secret**. The 64-character secret is shown once. Nothing is preselected under Contact sent as: you must choose Plain contact point, and you are responsible for how the system you send it to stores and uses it.

## Steps
1. **Webhooks, Custom webhook.** Create the webhook, tick **Get request headers** and **JSON pass-through**, copy its address into ConsentVault as the endpoint, and use Send a test push. The signature is over the exact body text, so the raw text must be kept: pass-through is expected to keep it **(unverified)**.
2. **Tools, Set multiple variables: verify.** Compute `sha256(<raw body>; <your secret as hex converted to binary>)` as an HMAC and compare it with the header `x-consentvault-signature` after the `hmac-sha256=` prefix. Whether Make's HMAC function accepts a binary key is **unverified**. If it cannot, use the n8n template instead.
3. **Filter: stop unless the signature matches.** Add an error handler that answers the webhook with status 401 **(unverified: confirm that Make can set the response status from an error handler)**. A non-2xx answer is retried and then shown as Undelivered in ConsentVault. If your scenario can answer 200 before the checks run, a failed stop would read as delivered: use n8n instead.
4. **Filter: only continue when `Idempotency-Key` is new.** Use a Data store: search it for the key; continue only if absent; add the key after step 7.
5. **Normalise.** Email: `lower(contact)`. Phone: remove everything except digits and the leading plus; a 10 digit number gets `+1` in front.
6. **Your CRM, Search for contacts** by that email or phone. Search returns every match. Do not add any Create module.
7. **Iterator over the matches, then a filter.** Use the message's `channel_state` and `channel_version`, not the per-purpose `state` and `version`. `channel_state` is denied while any purpose on the channel is denied; `channel_version` never decreases. If `channel_state` is `denied`, always continue to the update, whatever version the CRM holds. If it is `permitted`, continue only when the CRM's stored version for the channel is lower than `channel_version`, and, for a contact matched on a phone, only when the contact holds no other phone number than the one matched. Then **Update contact**: write `channel_state` into the channel's own field and the highest `channel_version` seen into its version field. A message with no `channel_state` is refused. That the filter and update behave this way in Make is **(unverified)**; test a late grant against a stopped contact before you rely on it.
8. **If the search returned nothing:** a router branch on "number of results = 0". When `state = denied`, send an optional email or Slack message (yours to keep or remove) titled "Stop for someone not in your CRM; check your dialer and texting tool". For a grant, only add a log line.
