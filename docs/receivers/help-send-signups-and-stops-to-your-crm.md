# Send sign-ups and stops to your CRM

Status: waiting for owner review. Not yet published.

ConsentVault sends one signed message every time a person's permission changes: each new sign-up and each stop. You connect that message to your own automation tool (n8n or Make), and the tool updates the person in your CRM. You do not need any help from ConsentVault.

## Who is responsible for what

ConsentVault delivers each signed message, retries it, and alerts you if your receiver does not accept it. If ConsentVault's own delivery is down, that is ours, and we alert. The receiving system is yours: its data quality, its uptime, and any change made inside it, including someone removing a stop by hand. ConsentVault does not guarantee that your CRM is updated.

<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 900 190" role="img" aria-labelledby="t d" width="100%">
  <title id="t">How a sign-up or stop reaches your CRM</title>
  <desc id="d">The portal sends a signed message to your automation tool, which checks the signature and updates the existing contact in your CRM.</desc>
  <defs><marker id="ar" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0 0L10 5L0 10z" fill="#1b3a5c"/></marker></defs>
  <g font-family="sans-serif" font-size="15" fill="#1b3a5c" text-anchor="middle">
    <rect x="10" y="50" width="170" height="80" rx="10" fill="#e8f0f8" stroke="#1b3a5c" stroke-width="2"/><text x="95" y="85">ConsentVault</text><text x="95" y="107">sign-up or stop</text>
    <rect x="250" y="50" width="170" height="80" rx="10" fill="#e8f0f8" stroke="#1b3a5c" stroke-width="2"/><text x="335" y="85">Signed message</text><text x="335" y="107">one per change</text>
    <rect x="490" y="50" width="190" height="80" rx="10" fill="#e8f0f8" stroke="#1b3a5c" stroke-width="2"/><text x="585" y="78">Your automation</text><text x="585" y="98">checks signature,</text><text x="585" y="118">finds the contact</text>
    <rect x="750" y="50" width="140" height="80" rx="10" fill="#e8f0f8" stroke="#1b3a5c" stroke-width="2"/><text x="820" y="85">Your CRM</text><text x="820" y="107">contact updated</text>
    <line x1="180" y1="90" x2="248" y2="90" stroke="#1b3a5c" stroke-width="2" marker-end="url(#ar)"/>
    <line x1="420" y1="90" x2="488" y2="90" stroke="#1b3a5c" stroke-width="2" marker-end="url(#ar)"/>
    <line x1="680" y1="90" x2="748" y2="90" stroke="#1b3a5c" stroke-width="2" marker-end="url(#ar)"/>
    <text x="585" y="165" font-size="13">No match in your CRM: nothing is created. A stop can raise an alert in your tool.</text>
  </g>
</svg>

## Set it up

1. **Open Setup, Connect a system** (or Connected systems, Connect a system). Give it a name, paste your automation tool's webhook address as the endpoint, and choose the signature. The portal shows the secret (HMAC) or public key (Ed25519) once.
2. **Choose Contact sent as.** Nothing is preselected, and you cannot connect until you choose. **Fingerprint only** sends a scrambled reference, which is the least personal data, but a CRM cannot find a contact from it. **Plain contact point** sends the phone number or email to a system you run, and you are responsible for how that system stores and uses it. To match a CRM contact the system needs Plain contact point. The choice is yours, and it is recorded in the audit log. Nothing else personal is added to the message.
3. **Import the template.** For n8n, import `n8n-update-existing-contact.json`. A self-hosted n8n must allow the crypto module for code steps: set `NODE_FUNCTION_ALLOW_BUILTIN=crypto` before starting it. For Make, follow `make.md`. Paste your secret or public key between the backticks in the code step (the public key is shown in the portal after you connect; paste the whole key, line breaks included), and set your CRM field names. The template is not tested by ConsentVault against your CRM; run the check at the end of this article before you rely on it.
4. **Press Connect and send a test push.** The portal shows whether your tool answered. A test carries no person.

## What the template does, and why

- **Checks the signature** over the exact body. A message that does not match is refused with 401, and ConsentVault shows it as Undelivered.
- **Finds the person by email or phone**, after making the email lowercase and the phone number international format (E.164, for example +14075550123). A phone is searched on both the phone and mobile phone fields. **Every** matching contact is updated, not only the first.
- **Never creates a contact.** If no one matches, nothing in the CRM changes. A **stop** that matches nobody goes to an optional alert step in your own tool (email or Slack, yours to keep, change or remove; it is a convenience, not a ConsentVault duty), titled "Stop for someone not in your CRM; check your dialer and texting tool". A sign-up that matches nobody is only logged, with "not in CRM, add by hand".
- **Keeps order.** Each message carries `channel_state` (denied while any purpose on that channel is denied) and `channel_version` (the sum of that channel's purpose versions, which never decreases). The template writes `channel_state` to the channel's field and stores the highest `channel_version` applied. A denied channel is always applied, whatever the stored version. A sign-up is applied only when its version is newer, so a late or repeated sign-up can never lift a newer stop, and a sign-up for one purpose can never clear a stop on another purpose of the same channel.
- **Ignores repeats.** The same delivery can arrive twice. The template remembers the `Idempotency-Key` header of each delivery it finished and answers a repeat with success without changing anything.
- **Refuses Fingerprint only.** If the system was connected that way, the template answers 422 and says what to change, so nothing is silently lost.

## Map each channel to its own CRM field

A sign-up or stop is for one channel: calls, prerecorded calls, texts or email. Create a separate CRM field for each (for example calls, texts, email), plus a "version" companion field for each, and map each channel to its field in the template. A stop for texts must not block email.

Use **one blanket do-not-contact field only if your CRM has nothing finer**. The template then applies stops only and never lets a sign-up lift it.

## Check it

Send a test push, then change one test person's permission in a demonstration organization. In your CRM, the matching contact's channel field and version change. Change the same contact again with an older version (replay the first delivery): nothing changes.
