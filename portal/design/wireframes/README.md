# Wireframes (Markdown, low fidelity)

The HTML files beside this one carry every state behind a state switcher (they open with all states stacked so
nothing is hidden without scripts). These Markdown frames show the default layout at 1440px, and how it changes at
375px. Grayscale only; the visual layer is web-designer's.

## Shell (every signed-in screen)

```
1440px
+--------------------------------------------------------------------------------+
| [Skip]  CONSENTVAULT                         [Acme Lending v]  [D. Ruiz (Admin) v] |
+-------------------+------------------------------------------------------------+
| START             | [ Organization status banner, when not Active ]            |
|  Overview         | H1 Screen title                                            |
|  First test event | Lede: one sentence on what this page is for                |
| EVIDENCE          | [Primary action]                                           |
|  Evidence lookup  | +--------------------------------------------------------+ |
|  Evidence packages| | content: table, form, timeline                         | |
| CONFIGURATION     | +--------------------------------------------------------+ |
|  ...              |                                                            |
| ORGANIZATION      |                                                            |
|  ...              |                                                            |
+-------------------+------------------------------------------------------------+

375px
+-----------------------------+
| [Menu] CONSENTVAULT [Org v] |
| [ status banner ]           |
| H1                          |
| [Primary action, full width]|
| +-------------------------+ |
| | Card per table row       | |
| |  Label     value         | |
| +-------------------------+ |
+-----------------------------+
```

## 01 Sign in (WorkOS hosted, branded)
```
          CONSENTVAULT
   Sign in to ConsentVault
   Use a passkey, or your work Google or Microsoft account.
   [ Sign in with a passkey      ]
   [ Continue with Google        ]
   [ Continue with Microsoft     ]
   Terms of Service . Privacy Policy
```
States: default, loading, no organization, second factor missing, error, session expired, success.

## 02 Accept an invitation
```
   Join Acme Lending on ConsentVault
   Role ........ Admin
   Invited by .. The Innovative Native (operator)
   Sent to ..... dana@acme.com
   Expires ..... Nov 5, 2026, 10:42 AM ET
   [ Sign in to accept ]
```
States: default, loading, no token, wrong account, expired / used / withdrawn, success.

## 03 Choose an organization
```
   Choose an organization
   | Organization | Your role          | Status   |        |
   | Acme Lending | Admin              | Active   | [Open] |
   | Acme Solar   | Compliance viewer  | Past due | [Open] |
```

## 04 Choose a plan
```
   Choose a plan        (payment on Stripe's page; no card data here)
   +-----------+ +-----------+ +------------+
   | Starter   | | Growth    | | Enterprise |
   | events    | | events    | | events     |
   | checks    | | checks    | | checks     |
   | [Choose]  | | [Choose]  | | [Choose]   |
   +-----------+ +-----------+ +------------+
```
States: default, opening checkout, no plans, payment confirming, checkout failed / cancelled, not an admin, success.

## 05 Overview
```
   Overview                     Acme Lending . Active . Growth
   +----------------+ +----------------+ +----------------+ +----------------+
   | Policy in force| | Unsealed > 1 h | | Undelivered    | | Events this    |
   | Version 3      | | 0              | | stops: 2       | | period 4,812 / |
   | Dana, Oct 30   | | checked 2m ago | | [Review]       | | 10,000         |
   +----------------+ +----------------+ +----------------+ +----------------+
   New org instead shows: Setup checklist 1..5 with Done / To do and the next button.
```

## 06 First test event
```
   Send your first test event
   Use a number you control. Test events are permanent evidence.
   1 Brand [Done]  2 Source [Done]  3 Wording [Done]  4 Credential [Done]
   +--------------------------------------------------+
   | curl -X POST .../v1/events ...                   | [Copy command]
   +--------------------------------------------------+
   ( Waiting for your first event from Website form. Updates every 5 s, 15 min )
```

## 07 Brands, 08 Capture sources (same pattern)
```
   Brands                                     [Add a brand]
   | Brand | Id | Capture sources | Added |
```
```
   Capture sources                            [Add a capture source]
   | Source | Sends as | Brands | Allowed origins | Last event |
```

## 09 Credentials
```
   Credentials    To rotate: issue new, switch, revoke old.   [Issue a credential]
   | Name | Kind | Scope | Source | Created | Status | [Revoke] |

   Issue wizard: 1 Scope and kind -> 2 Key (server only) -> 3 Shown once
   ( ) Gate check  - disabled until a policy is in force [Draft a policy]
   Shown once: [ cvwh_3kq...9Zp ] [Copy]   [x] I stored this secret   [Done]
```

## 10 Wording
```
   Wording                                     [Register wording]
   | Version | Brands | Channels | Purposes | Shown from | Fingerprint | Replaces |
   Detail: fingerprint [Copy] . registered by . replaces . exact text (pre)
           [Register a new version that replaces this one]
```

## 11 Policies
```
   Policies                                    [Draft a new version]
   | Version | Status    | Approved by | Approved |
   | 3       | In force  | Dana Ruiz   | Oct 30   |
   Editor: matrix rows = evidence status, columns = channel, cells = Proceed / Hold
   Approve: matrix (read) + Attestation v1 text + [ ] I accept + Approving as (session) + [Approve]
```

## 12 Documentation checklists
```
   | Checklist | Version | Elements | Approved by | Status |
   Editor: | Element | Text to check for | Regulation text quoted |  [Add element]
```

## 13 Evidence lookup
```
   Evidence lookup
   Phone number or email [______________]  [Look up records]
   Records for (555) 555-0100 in Acme Lending    Chain: Verified to anchor Nov 2
   [Build evidence package] [Request erasure]
   Evidence status now
   | Channel | Purpose | Evidence status | Your policy (v3) |
   notice: Evidence status and the outcome of your organization's approved policy. Not a legal determination.
   Timeline (arrival order)
    <> Grant . Oct 31 10:42 . seq 1 . SMS, voice . wording 2026-10 . Sealed . Checklist 4 of 5
    <> Stop (revoke) . Nov 2 3:10 PM . seq 9 . all purposes . Sealed
   Gate checks for this contact      | Checked | Channel | Evidence status | Policy action | Version |
   Stops sent to connected systems   | System | Sent | State sent | Result |
```

## 14 Evidence packages
```
   Phone number or email [________] [Build evidence package]
   | Contact | Started | Status | Link expires | [Download] |
   How anyone can check this package: verifier, offline, sha256 [Copy]
```

## 15 Connected systems
```
   | System | Kind | Connector | State | Last acknowledged | Undelivered |
   Detail: endpoint . signature . last test push   [Send a test push] [Redrive undelivered]
   Undelivered stops: | Stop recorded | Contact (fingerprint) | Channel | Last answer | Attempts |
```

## 16 Retention, 17 Members, 18 Audit, 19 Billing, 20 Settings, 21 References
```
   Retention: In force 7 years . Platform minimum 5 . [new years] [Save new version] . history table
   Members:   | Name | Email | Role | Status | [Change role] |   [Invite a member]
   Audit:     filters (action, who, from, to) | When | Who | Action | Target | Reason | Request | [Newer] [Older]
   Billing:   Plan . Status . Events used / included . Checks used / included . [Manage billing on Stripe]
   Settings:  Name . Org id . Status . Region . Encryption key . "Leave ConsentVault" steps . [Request offboarding]
   References: banner (citations only, not legal advice) . jurisdiction filter | Jurisdiction | Citation | Source | Reviewed |
```

## 22 Global states
Role refusal, not found, offline, session ending (2 minutes), organization switched in another tab, saved toast.

## 23 Records (added 2026-10-30)
```
   Records    Every phone number and email address the organization holds.
   [Records held 312] [New in last 30 days 71] [With a stop 9 (show only these)]
   New records per day  ||| |||| ||||||  (Show the chart as a table)
   Email  [#########################=-]  found 94% . stop 3% . no record 3%
   Text   [###############=----------]
   Call   [###############-----------]
   Filters: Channel . Evidence status . Purpose . Source . Has a stop . Date (first recorded / last event) . From . To . Test events [Clear]
   Find one exact phone number or email [__________] [Find]
   (o) Show full contact points (audited)                         [Export this list]
   | Contact | Name | Company | First recorded | Source | Email | Text | Call | Stop | Confirmation |  (developer: no Name, no Company)
   Showing 1 to 50 of 312                                   [Newer] [Older]
```
375px: tiles stack, chart keeps its own width with the table alternative, filters wrap, rows become cards.

## 24 Setup walkthrough (added 2026-10-30)
```
   Set up The Innovative Native
   +----------------------------+------------------------------------------+
   | Done  1 Add a brand        | 3. Register your consent wording          |
   | Done  2 Add a source       |  label . exact wording . channels .       |
   | >To do 3 Wording           |  purposes . replaces                      |
   | To do 4 Credential         | [Back] [Register wording]   Leave setup   |
   | To do 5 Test event         |                                          |
   | To do 6 Policy             |                                          |
   | To do 7 System (optional)  |                                          |
   | To do 8 Confirmations (opt)|                                          |
   +----------------------------+------------------------------------------+
```
375px: the rail becomes "Step 3 of 8" with a step picker above the panel.

## 25 Confirmation messages (added 2026-10-30)
```
   [Email account: Connected] [Text account: Connected] [Texting registration: Not marked] [Replies to read: 2]
   | Source               | Email | Text                         | Last sent | Failed 24 h | [Edit] |
   | Early access form    | (On)  | (Off) until registration     | Oct 30    | 0           |
   | Field guide download | (On)  | (Off) until registration     | Oct 30    | 1           |
   Recent activity: | When | Contact | Channel | What happened |
   Edit: on/off . subject . opening line . fixed parts (locked) . options . [Save] [Send a test to my own address]
   Text preview with character and segment count
```
