# Contrast table (computed by _build/contrast.py from tokens.css)

WCAG 2.2 AA: 4.5:1 text, 3:1 large text and UI components. Ratios use the WCAG relative-luminance formula. Rows with need 1.0 are informational (decorative borders) and not counted.

Counted pairs: 110 (light + dark). FAIL count: 0.

Lowest ratio relative to its requirement: Field edge (UI 3:1) on --color-surface-sunken in light: 3.05:1 (needs 3.0).

| Use | Tokens | Light colors | Light | Light verdict | Dark colors | Dark | Dark verdict | Need |
|---|---|---|---|---|---|---|---|---|
| Body text | `--color-text` on `--color-surface` | #3A4B5B / #FFFFFF | 8.98 | PASS | #E6ECF1 / #1B2632 | 12.87 | PASS | 4.5 |
| Body text | `--color-text` on `--color-bg` | #3A4B5B / #F2F5F7 | 8.21 | PASS | #E6ECF1 / #131C25 | 14.45 | PASS | 4.5 |
| Body text | `--color-text` on `--color-surface-sunken` | #3A4B5B / #EAF0F4 | 7.82 | PASS | #E6ECF1 / #16202A | 13.84 | PASS | 4.5 |
| Body text | `--color-text` on `--color-surface-cream` | #3A4B5B / #F7F4EA | 8.16 | PASS | #E6ECF1 / #1F2A33 | 12.27 | PASS | 4.5 |
| Strong text | `--color-text-strong` on `--color-surface` | #1B2A37 / #FFFFFF | 14.66 | PASS | #FFFFFF / #1B2632 | 15.33 | PASS | 4.5 |
| Strong text | `--color-text-strong` on `--color-bg` | #1B2A37 / #F2F5F7 | 13.38 | PASS | #FFFFFF / #131C25 | 17.21 | PASS | 4.5 |
| Strong text | `--color-text-strong` on `--color-surface-sunken` | #1B2A37 / #EAF0F4 | 12.75 | PASS | #FFFFFF / #16202A | 16.48 | PASS | 4.5 |
| Strong text | `--color-text-strong` on `--color-surface-cream` | #1B2A37 / #F7F4EA | 13.32 | PASS | #FFFFFF / #1F2A33 | 14.61 | PASS | 4.5 |
| Muted text | `--color-text-muted` on `--color-surface` | #55606B / #FFFFFF | 6.42 | PASS | #B3BEC8 / #1B2632 | 8.11 | PASS | 4.5 |
| Muted text | `--color-text-muted` on `--color-bg` | #55606B / #F2F5F7 | 5.86 | PASS | #B3BEC8 / #131C25 | 9.11 | PASS | 4.5 |
| Muted text | `--color-text-muted` on `--color-surface-sunken` | #55606B / #EAF0F4 | 5.58 | PASS | #B3BEC8 / #16202A | 8.72 | PASS | 4.5 |
| Muted text | `--color-text-muted` on `--color-surface-cream` | #55606B / #F7F4EA | 5.83 | PASS | #B3BEC8 / #1F2A33 | 7.73 | PASS | 4.5 |
| Subtle text | `--color-text-subtle` on `--color-surface` | #5E6973 / #FFFFFF | 5.61 | PASS | #9AA6B1 / #1B2632 | 6.18 | PASS | 4.5 |
| Subtle text | `--color-text-subtle` on `--color-bg` | #5E6973 / #F2F5F7 | 5.12 | PASS | #9AA6B1 / #131C25 | 6.93 | PASS | 4.5 |
| Subtle text | `--color-text-subtle` on `--color-surface-sunken` | #5E6973 / #EAF0F4 | 4.88 | PASS | #9AA6B1 / #16202A | 6.64 | PASS | 4.5 |
| Subtle text | `--color-text-subtle` on `--color-surface-cream` | #5E6973 / #F7F4EA | 5.10 | PASS | #9AA6B1 / #1F2A33 | 5.89 | PASS | 4.5 |
| Link text | `--color-link` on `--color-surface` | #2C5A85 / #FFFFFF | 7.22 | PASS | #9CC3E8 / #1B2632 | 8.31 | PASS | 4.5 |
| Link text | `--color-link` on `--color-bg` | #2C5A85 / #F2F5F7 | 6.59 | PASS | #9CC3E8 / #131C25 | 9.33 | PASS | 4.5 |
| Link text | `--color-link` on `--color-surface-sunken` | #2C5A85 / #EAF0F4 | 6.28 | PASS | #9CC3E8 / #16202A | 8.94 | PASS | 4.5 |
| Link text | `--color-link` on `--color-surface-cream` | #2C5A85 / #F7F4EA | 6.56 | PASS | #9CC3E8 / #1F2A33 | 7.92 | PASS | 4.5 |
| Gold as text | `--color-accent-ink` on `--color-surface` | #776A2A / #FFFFFF | 5.41 | PASS | #D5C47B / #1B2632 | 8.77 | PASS | 4.5 |
| Gold as text | `--color-accent-ink` on `--color-bg` | #776A2A / #F2F5F7 | 4.94 | PASS | #D5C47B / #131C25 | 9.84 | PASS | 4.5 |
| Gold as text | `--color-accent-ink` on `--color-surface-cream` | #776A2A / #F7F4EA | 4.92 | PASS | #D5C47B / #1F2A33 | 8.36 | PASS | 4.5 |
| Gold as text | `--color-accent-ink` on `--color-accent-tint` | #776A2A / #F2EED9 | 4.64 | PASS | #D5C47B / #2A2A1E | 8.29 | PASS | 4.5 |
| Primary button label | `--color-on-accent` on `--color-accent` | #2A3845 / #C6B25D | 5.67 | PASS | #1B2A37 / #C6B25D | 6.93 | PASS | 4.5 |
| Primary button label | `--color-on-accent` on `--color-accent-hover` | #2A3845 / #D5C47B | 6.86 | PASS | #1B2A37 / #D5C47B | 8.38 | PASS | 4.5 |
| Body text on gold tint (nav active) | `--color-text-strong` on `--color-accent-tint` | #1B2A37 / #F2EED9 | 12.57 | PASS | #FFFFFF / #2A2A1E | 14.50 | PASS | 4.5 |
| Success text on its tint | `--color-success` on `--color-success-bg` | #2F6B33 / #E6F1E6 | 5.53 | PASS | #9FD9A2 / #17341B | 8.37 | PASS | 4.5 |
| Success text on surface | `--color-success` on `--color-surface` | #2F6B33 / #FFFFFF | 6.42 | PASS | #9FD9A2 / #1B2632 | 9.43 | PASS | 4.5 |
| Danger text on its tint | `--color-danger` on `--color-danger-bg` | #A63A29 / #FBE9E5 | 5.49 | PASS | #F3A79D / #46211B | 7.25 | PASS | 4.5 |
| Danger text on surface | `--color-danger` on `--color-surface` | #A63A29 / #FFFFFF | 6.44 | PASS | #F3A79D / #1B2632 | 7.90 | PASS | 4.5 |
| Warning text on its tint | `--color-warning` on `--color-warning-bg` | #6F4B00 / #FFF1D6 | 7.01 | PASS | #F0CB7A / #3F2E0A | 8.42 | PASS | 4.5 |
| Warning text on surface | `--color-warning` on `--color-surface` | #6F4B00 / #FFFFFF | 7.83 | PASS | #F0CB7A / #1B2632 | 9.88 | PASS | 4.5 |
| Info text on its tint | `--color-info` on `--color-info-bg` | #2C5A85 / #E4EEF7 | 6.15 | PASS | #A9CBEA / #1C3550 | 7.42 | PASS | 4.5 |
| Info text on surface | `--color-info` on `--color-surface` | #2C5A85 / #FFFFFF | 7.22 | PASS | #A9CBEA / #1B2632 | 9.06 | PASS | 4.5 |
| Evidence found chip | `--ev-found-fg` on `--ev-found-bg` | #1F4E79 / #E1ECF6 | 7.23 | PASS | #A9CBEA / #1C3550 | 7.42 | PASS | 4.5 |
| Evidence found chip on surface (if bg lost) | `--ev-found-fg` on `--color-surface` | #1F4E79 / #FFFFFF | 8.66 | PASS | #A9CBEA / #1B2632 | 9.06 | PASS | 4.5 |
| Evidence stop chip | `--ev-stop-fg` on `--ev-stop-bg` | #7A2E63 / #F6E4F0 | 7.20 | PASS | #EBB8DC / #45213A | 8.11 | PASS | 4.5 |
| Evidence stop chip on surface (if bg lost) | `--ev-stop-fg` on `--color-surface` | #7A2E63 / #FFFFFF | 8.76 | PASS | #EBB8DC / #1B2632 | 9.07 | PASS | 4.5 |
| Evidence none chip | `--ev-none-fg` on `--ev-none-bg` | #4A5560 / #EEF1F3 | 6.71 | PASS | #C2CCD5 / #2A3540 | 7.67 | PASS | 4.5 |
| Evidence none chip on surface (if bg lost) | `--ev-none-fg` on `--color-surface` | #4A5560 / #FFFFFF | 7.61 | PASS | #C2CCD5 / #1B2632 | 9.41 | PASS | 4.5 |
| Evidence incomplete chip | `--ev-incomplete-fg` on `--ev-incomplete-bg` | #0F5F5C / #DDF0EE | 6.32 | PASS | #8FD5CF / #123F3C | 6.98 | PASS | 4.5 |
| Evidence incomplete chip on surface (if bg lost) | `--ev-incomplete-fg` on `--color-surface` | #0F5F5C / #FFFFFF | 7.47 | PASS | #8FD5CF / #1B2632 | 9.19 | PASS | 4.5 |
| Policy proceed chip | `--pol-proceed-fg` on `--color-surface` | #2A3845 / #FFFFFF | 12.00 | PASS | #E6ECF1 / #1B2632 | 12.87 | PASS | 4.5 |
| Policy proceed chip | `--pol-proceed-fg` on `--color-bg` | #2A3845 / #F2F5F7 | 10.96 | PASS | #E6ECF1 / #131C25 | 14.45 | PASS | 4.5 |
| Policy proceed chip | `--pol-proceed-fg` on `--color-surface-sunken` | #2A3845 / #EAF0F4 | 10.44 | PASS | #E6ECF1 / #16202A | 13.84 | PASS | 4.5 |
| Policy hold chip | `--pol-hold-fg` on `--pol-hold-bg` | #FFFFFF / #2A3845 | 12.00 | PASS | #131C25 / #E6ECF1 | 14.45 | PASS | 4.5 |
| Field edge (UI 3:1) | `--color-border-strong` on `--color-surface` | #7A8B99 / #FFFFFF | 3.51 | PASS | #70808F / #1B2632 | 3.78 | PASS | 3.0 |
| Field edge (UI 3:1) | `--color-border-strong` on `--color-bg` | #7A8B99 / #F2F5F7 | 3.21 | PASS | #70808F / #131C25 | 4.24 | PASS | 3.0 |
| Field edge (UI 3:1) | `--color-border-strong` on `--color-surface-sunken` | #7A8B99 / #EAF0F4 | 3.05 | PASS | #70808F / #16202A | 4.06 | PASS | 3.0 |
| Focus ring vs page (UI 3:1) | `--color-focus` on `--color-surface` | #2A3845 / #FFFFFF | 12.00 | PASS | #F2E7A6 / #1B2632 | 12.23 | PASS | 3.0 |
| Focus ring vs page (UI 3:1) | `--color-focus` on `--color-bg` | #2A3845 / #F2F5F7 | 10.96 | PASS | #F2E7A6 / #131C25 | 13.73 | PASS | 3.0 |
| Focus ring vs page (UI 3:1) | `--color-focus` on `--color-surface-sunken` | #2A3845 / #EAF0F4 | 10.44 | PASS | #F2E7A6 / #16202A | 13.15 | PASS | 3.0 |
| Focus ring vs page (UI 3:1) | `--color-focus` on `--color-accent-tint` | #2A3845 / #F2EED9 | 10.29 | PASS | #F2E7A6 / #2A2A1E | 11.57 | PASS | 3.0 |
| Focus ring vs its gap (UI 3:1) | `--color-focus` on `--color-focus-gap` | #2A3845 / #FFFFFF | 12.00 | PASS | #F2E7A6 / #131C25 | 13.73 | PASS | 3.0 |
| Chip border found vs surface (not required, informational) | `--ev-found-border` on `--color-surface` | #7FA6CB / #FFFFFF | 2.55 | PASS | #4A78A5 / #1B2632 | 3.30 | PASS | 1.0 |
| Chip border stop vs surface (not required, informational) | `--ev-stop-border` on `--color-surface` | #BE86AE / #FFFFFF | 2.91 | PASS | #9A5F88 / #1B2632 | 3.19 | PASS | 1.0 |
| Chip border none vs surface (not required, informational) | `--ev-none-border` on `--color-surface` | #8D9AA6 / #FFFFFF | 2.87 | PASS | #6C7B88 / #1B2632 | 3.52 | PASS | 1.0 |
| Chip border incomplete vs surface (not required, informational) | `--ev-incomplete-border` on `--color-surface` | #6BB5AF / #FFFFFF | 2.37 | PASS | #3F8C86 / #1B2632 | 3.87 | PASS | 1.0 |
