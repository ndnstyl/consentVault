# Role matrix

Three client roles. Contracts today define `admin` and `compliance_viewer` only (contracts/admin.md
`GET/POST /v1/members`; data-model.md `member.role`). **`developer` is proposed by this package** and is listed in
contract-gaps.md; until the contract carries it, the invite dialog offers two roles and every "Developer" cell below is
inactive.

Legend: **W** read and change · **R** read only · **-** hidden from navigation, deep link shows the role-refusal state.
"(gap)" means the role should have it but no read endpoint exists for that role yet.

| Screen or action | Admin | Compliance viewer | Developer (proposed) |
|---|---|---|---|
| 05 Overview | W (all tiles) | R (policy, health; no usage) | R (setup, health) |
| 06 First test event | W | - | W |
| 07 Brands | W | - | R |
| 08 Capture sources | W | - | W |
| 09 Credentials: issue capture or evidence-read | W | - | W (capture only) |
| 09 Credentials: issue gate check | W (after a policy is in force) | - | - (proposed: admin only, because gate checks act on policy) |
| 09 Credentials: revoke | W | - | W (credentials it issued) |
| 10 Wording: list and detail | W | R (gap) | R (gap) |
| 10 Wording: register | W | - | - |
| 11 Policies: read | W | R (gap) | R (gap) |
| 11 Policies: draft and approve with attestation | W | - | - |
| 12 Checklists: read | W | R (gap) | R (gap) |
| 12 Checklists: define and approve | W | - | - |
| 13 Evidence lookup | W | R | - (personal data) |
| 13 Request erasure | W | - | - |
| 14 Evidence packages | W | W (build and download) | - |
| 15 Connected systems: list, detail, deliveries | W | R (gap) | W |
| 15 Connect, test push | W | - | W |
| 15 Redrive undelivered stops | W | - | W (proposed) |
| 16 Retention | W | R (gap) | - |
| 17 Members | W | - | - |
| 18 Audit log | W | - (gap: recommend R) | - |
| 19 Billing | W | - | - |
| 20 Settings: read | W | R | R |
| 20 Request offboarding | W | - | - |
| 21 Rule references | R | R | R |

## Rules the build enforces

1. The server is the authority. Hiding a link is convenience; every endpoint refuses a role that may not call it, and
   the portal shows the refusal state with the role named.
2. A person's role is read from the session after organization selection, not from local storage.
3. The last admin of an organization cannot be removed or demoted (proposed rule, `last_admin` in contract-gaps.md).
4. The developer role never sees a contact point in clear. Delivery lists show fingerprints only.
5. Operator is not a client role and never appears in the portal's role picker.
