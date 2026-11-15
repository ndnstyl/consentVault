# Certificate hidden-field fixtures: sources

Read 2026-11-15. Names below are copied from the issuers' own pages, not from memory.

## TrustedForm (ActiveProspect)

Page: https://developers.activeprospect.com/pages/trustedform/implementing-trustedform-certify.md (read 2026-11-15).

- The Certify web script adds a hidden input and inserts the certificate URL as its value:
  `<input type="hidden" name="xxTrustedFormCertUrl" id="xxTrustedFormCertUrl_0" value="https://cert.trustedform.com/454a35b802f3e7b63ffabb4efedb7c6ebe67886c">`
- The default name is `xxTrustedFormCertUrl`; the integrator may rename it with the script's `field` variable. The id carries a
  `_0`, `_1` ... suffix, one per form on the page.
- The URL shape is `https://cert.trustedform.com/` followed by the certificate id (40 hex characters in the page's example).
- Timing, from the same page: the form must be on the page before the script loads, and the script must be in the same window
  (iframe) as the form. Otherwise the hidden field is never added.
- The page names no second hidden field (no token field). Nothing else is assumed here.
- A cert URL never becomes a request the product makes: the issuer's Validate and Claim APIs are not called (ruling: record
  what was sent, never judge it).

## Jornaya LeadiD (InfutorData by ActiveProspect, formerly Jornaya)

Pages (read 2026-11-15):
- https://help.infutor.com/docs/create-implementation-testing.md
- https://help.infutor.com/docs/getting-started-with-create.md
- https://help.infutor.com/docs/how-to-check-the-authenticity-of-a-leadid-token.md
- https://help.infutor.com/docs/web-form-create-implementation.md

- Example hidden input, from the testing page: `<input id="leadid_token" name="universal_leadid" type="hidden" value="LEADID TOKEN VALUE">`
  (element id `leadid_token`, name `universal_leadid`; the value is filled by the campaign script).
- The token is 36 characters (authenticity page: "All Jornaya LeadiD tokens are 36 characters").
- Timing: the campaign script goes after the closing form tag and before the end of the body; the value is empty until the
  script has fired. A callback function may write the token to a hidden input with another id.

## What the product copies

Widget default names: `xxTrustedFormCertUrl` and `universal_leadid`. Any other name an integrator's script uses is listed in the
widget's `data-passthrough` attribute and is stored whole in the same place; only the two default names get a named reading.
The `data-passthrough` attribute reads the input by its `name`.
