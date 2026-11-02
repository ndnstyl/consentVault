# Accessibility spec (WCAG 2.2 AA)

Target: zero axe-core violations on every built screen, plus the manual checks below. Applies to every state of every
screen, including dialogs and the WorkOS hosted page branding.

## 1. Structure

- One `<h1>` per page, matching the navigation label. Sections use `<h2>`/`<h3>` in order.
- Landmarks: `header` (top bar), `nav aria-label="Portal"`, `main id="main"`, and status banners in a `region` labelled
  "Organization status".
- First focusable element: "Skip to main content" (reuse `.skip`, site `globals.css` lines 52-53).
- `<html lang="en">`. Page `<title>`: "<Screen> | <Organization> | ConsentVault".

## 2. Keyboard and focus

- Every action reachable by Tab in reading order: skip link, wordmark, organization switcher, person menu, side nav,
  banner action, page heading area, primary action, filters, content, pagination.
- Focus moves on purpose: after navigation to the `<h1>` (tabindex -1); after a form error to the error summary,
  whose items link to fields; after a dialog opens to its first field (or the safe button on alert dialogs);
  after a dialog closes back to the button that opened it; after a successful create to the success banner.
- Dialogs: `role="dialog"` or `role="alertdialog"`, `aria-modal="true"`, labelled by their heading, focus trapped,
  Esc closes (except the secret-reveal dialog, where Esc asks to confirm).
- Focus not obscured (2.4.11): the sticky top bar is 56px; `scroll-padding-top: 72px` on `html`.
- Focus ring: 2px `#2A3845` (navy-deep) outline plus 2px white offset ring. 12:1 on white. Replaces the gold ring.

## 3. Color and contrast (computed 2026-10-29)

| Token use | Value | On white | On cream `#F7F4EA` | Verdict |
|---|---|---|---|---|
| Body text `--text` | `#3A4B5B` | 8.98 | | pass |
| Secondary `--text-2` | `#55606B` | 6.42 | | pass |
| Tertiary `--text-3` | `#6B7680` | 4.64 | 4.21 | white only |
| **New** `--text-3-ink` for cream | `#5E6973` | 5.61 | 5.10 | pass |
| `--gold-deep` small text | `#8C7D33` | 4.12 | 3.74 | fails, do not use for text |
| **New** `--gold-ink` | `#776A2A` | 5.41 | 4.92 | pass |
| Gold button text navy-deep on gold | `#2A3845` on `#C6B25D` | 5.67 | | pass |
| Danger text | `#B3412F` | 5.65 | 5.14 | pass |
| Success text `--green-deep` | `#2F6B33` | 6.42 | | pass |
| Field border, **new** `--field-edge` | `#7A8B99` | 3.51 | 3.19 | pass (3:1) |
| Old field border `--border` | `#C8D5DE` | 1.50 | | decorative dividers only |

- Status is never color alone: each chip has an icon and a word (copy-rules.md section 3).
- Dark theme: the site's dark tokens pass for text (`--text-3` dark `#8F9BA6` on `#1B2632` is 5.41).

## 4. Targets (2.5.8)

Minimum 24 x 24 CSS px for every target, 36px tall for buttons, 44px on touch layouts. Table row actions are buttons,
not icon-only links; icon-only buttons carry `aria-label`.

## 5. Forms

- Every input has a visible `<label>`; hints use `aria-describedby`; errors use `aria-invalid="true"` plus
  `aria-describedby` to the message, and an error summary at the top with `role="alert"`.
- Redundant entry (3.3.7): the approver's name on the attestation comes from the session; the organization name typed
  in the offboarding confirmation is the only re-entry and is a deliberate safety check.
- Accessible authentication (3.3.8): sign-in is passkey or federated; no cognitive test. Secrets and keys can be pasted
  and copied; nothing blocks paste.
- Contact input on screen 13: `autocomplete="off"`, `inputmode` switches between `tel` and `email` by first character,
  never written to the URL, cleared on route change.

## 6. Async announcements

- Loading regions carry `aria-busy="true"`; a polite live region announces "Loading <thing>" once, and "Loaded" is not
  announced (the content itself is the signal).
- Export building, first-event waiting, checkout confirming, redrive progress: one `role="status"` region each, updated
  at most every 10 seconds with a sentence, not every poll.
- Errors: `role="alert"` once per failure.
- Toasts stay at least 10 seconds, pause on hover and focus, and are also written to the page (no information only in
  a toast).

## 7. Tables at 375px

Tables with more than 3 columns collapse to one card per row under 760px, each card a `<dl>` of header and value.
Wide technical tables that must stay tabular (policy matrix) scroll inside their own container with `tabindex="0"`,
`role="region"` and a label. No horizontal page scroll at 375px (checked on every wireframe state, 0 overflows).

## 8. Motion

No decorative motion. Spinners are replaced by skeletons. `prefers-reduced-motion: reduce` removes every transition
(reuse site `globals.css` lines 105-109).

## 9. Time limits (2.2.1)

Sessions last 8 hours (contracts/auth.md). Warn 2 minutes before with a dialog offering "Sign in again"; unsaved form
entries are kept in session storage and restored after sign-in. Download links last 15 minutes; the screen shows the
expiry time and offers "Get a new link".

## 10. Test plan

Playwright plus `@axe-core/playwright` on every route, every state reachable by fixture, at 375 and 1440 widths, light
and dark. Manual: keyboard-only pass of flows F1, F4, F5, F6; VoiceOver pass of screens 11, 13, 14.
`@axe-core/playwright` was not available on this machine when the wireframes were checked, so no axe scan has run yet.
