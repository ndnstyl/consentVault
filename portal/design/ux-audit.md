# UX audit: ConsentVault Cloud portal (app.consentvault.ai)

Date 2026-10-29. Seat: ui-ux-engineer. Sources read: the cloud specification,
data model, task list and contracts; the open core in this repository (`docs/api.md`,
`src/consentvault/proof.py`); the marketing site's `src/`.

## 1. What exists today

| Surface | State | Evidence |
|---|---|---|
| Portal app | **Does not exist.** No route, no screen, no component. | `ls portal` returned "No such file or directory" before this package was written. tasks.md line 58 (portal build) is unchecked. |
| Core UI | None. The open core is CLI plus HTTP API only. | `src/consentvault/cli.py`, `api.py`; no templates directory. |
| Marketing site | Live, Next.js 14 static, React 18. Holds the brand system the portal must share. | the marketing site's `package.json` (next 14.2.35). |
| Sign-in | Not built. WorkOS AuthKit hosted page is ruled. | contracts/auth.md "Portal sessions"; spec Rulings. |
| Billing pages | Not built. Stripe hosted Checkout and Customer Portal are ruled. | contracts/billing.md. |

There is no old UI to keep, merge or delete. Everything in this package is designed from the spec.

## 2. Reusable from the marketing site (keep, adapt)

| Asset | File and line | Use in portal | Adaptation needed |
|---|---|---|---|
| Color, radius, shadow tokens | `site/src/styles/globals.css` lines 4-35 | Base tokens, light and dark | Add the accessible ink tokens in accessibility.md section 3. |
| Font stacks (Montserrat display, Geist body, Cormorant Garamond serif) | `site/src/pages/_app.tsx` lines 2-17; `globals.css` lines 38-42 | Same three families | Note: the brief names Montserrat and Cormorant; the site's body face is **Geist**. Portal keeps Geist for body and data. Cormorant only for empty-state headings, never for data. |
| Wordmark and mark | `site/src/components/Logo.tsx` lines 2-19 | Top bar, sign-in branding on WorkOS | None. The `Mark` svg is `aria-hidden`; the portal wraps it in a link named "ConsentVault home". |
| Buttons `.btn`, `.btn-gold`, `.btn-line` | `globals.css` lines 75-84 | Primary and secondary actions | Site buttons are 13px uppercase with 16px x 30px padding: too large for dense tables. Add a `size="sm"` (36px tall) variant. |
| Form field `.fld` | `site/src/styles/sections.css` lines 294-297 | Every portal form | Line 296 sets `outline: none` and relies on a gold border plus a 25% gold glow: fails non-text contrast (gold on white is 2.12:1). Replace with the focus ring in accessibility.md. |
| Checkbox pattern `.consent` | `sections.css` lines 299-300, 336 | Attestation and "I stored this secret" boxes | Keep the unchecked-by-default rule. |
| Card `.card` | `globals.css` line 96 | Tiles, panels | None. |
| Chip `.chip` | `sections.css` lines 71-73 | Status chips | 9px text, and colors tuned for the dark hero. Portal needs a light-surface chip at 12px minimum with an icon plus a word, never color alone. |
| Legal table `.legal-table` | `sections.css` line 347 | Base for data tables | Needs the 375px card collapse. |
| Skip link `.skip` | `globals.css` lines 52-53 | First focusable element on every portal page | None. |
| Reduced motion block | `globals.css` lines 105-109 | Same rule in the portal | None. |

## 3. Defects found in the site that must not be copied

| Defect | Evidence | Why it matters in the portal |
|---|---|---|
| Generic error fallback "Something went wrong. Try again." | `site/src/components/ConsentForm.tsx` line 51 | Violates "failure is named". Portal errors always show cause plus next action (copy-rules.md section 4). |
| Focus ring in gold `#C6B25D` on white | `globals.css` line 51 | 2.12:1, below the 3:1 non-text minimum. |
| `--gold-deep #8C7D33` used for small text on white | `globals.css` line 6; used by `.eyebrow` line 64 (11px) | 4.12:1 on white, 3.74:1 on cream. Below 4.5:1 for body-size text. |
| `--text-3 #6B7680` on cream `#F7F4EA` | `globals.css` lines 8-9 | 4.21:1. Passes on white (4.64:1) only. |
| Input border `--border #C8D5DE` | `globals.css` line 10 | 1.5:1. Field edges need 3:1 to be seen. |

## 4. Contract and model inconsistencies found while auditing

Listed in full in `contract-gaps.md`. The ones that change screens:

1. Organization status values differ: data-model.md line 44 lists `active, suspended, offboarding, closed`;
   spec (the organization lifecycle requirement) and contracts/billing.md list `trial, active, past_due, suspended, closed`.
   The portal designs for the union of both.
2. Member roles: data-model.md line 48 and contracts/admin.md allow `admin` and `compliance_viewer` only. The brief asks
   for a `developer` role. Designed as proposed; listed as a gap.
3. Proof: contracts/README.md says `GET /v1/proof`; contracts/proof-export.md says `POST /v1/proof {contact}`. The
   portal uses POST because the contract also says a contact is never put in a URL.
4. Policies and rule sets: admin.md lists both `POST /v1/rule-sets` and `POST /v1/policies`; data-model.md line 280
   says `policy` replaces `rule_set`. The portal shows Policies only.
5. Operator org creation path: admin.md `POST /v1/orgs`, billing.md `POST /v1/admin/orgs`.
6. Almost every admin resource has a write endpoint and no read endpoint (credentials, wording, policies, checklists,
   retention, systems, exports). A portal cannot list what it cannot read.

## 5. Keep, merge, delete

- Keep: tokens, fonts, Logo, button and field patterns, skip link, reduced-motion block.
- Adapt: chip, field focus, table.
- Delete nothing (no portal code exists).
- Do not copy: the site's motion effects (`fx.css`, `Fx.tsx`, `SmoothScroll.tsx`). A records tool gets no
  decorative motion.
