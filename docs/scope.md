# Scope and responsibilities

ConsentVault is an independent evidence custodian and compliance-support infrastructure provider, run in its managed
form by The Innovative Native LLC. It is not a legal compliance authority and gives no legal advice. It provides
defensible documentation, not guaranteed compliance.

It preserves, retrieves, verifies and organizes the evidence your attorneys may rely on when assessing TCPA, PEWC,
EBR, DNC and state-specific marketing requirements. You and your counsel remain responsible for determining what
constitutes legally sufficient consent, which exemptions apply, and whether a proposed marketing activity is lawful.

| ConsentVault provides | You and your counsel determine |
|---|---|
| Tamper-evident evidence preservation | Whether the underlying consent is legally valid |
| Exact disclosure text and version history | Whether disclosures satisfy applicable law |
| Capture timestamps, metadata and provenance | Whether the evidence establishes the required authorization |
| Documentation completeness checks you define | Whether statutory requirements are satisfied |
| Relationship dates and supporting records | Whether a relationship legally qualifies for an exemption |
| Do-not-call and revocation event history | Whether a particular communication is permissible |
| Informational rule references (citation and link only) | Which laws and interpretations govern your activity |
| Evidence exports that can be checked for changes since sealing | Legal conclusions and litigation strategy |
| Access controls and encryption | Your lawful purpose and retention requirements |

## What the software does and does not do

- The ledger is tamper-evident: a change after the fact is detectable, not impossible for someone with database
  administrator access. Outside timestamps and anchors are what make a change detectable.
- A timestamp shows that a digest existed at a time. It does not show who ticked a box.
- A read reports what the record holds. ConsentVault takes no action in a customer's systems. Anything a customer's own system does after reading a record is that customer's action.
- If the capture surface is compromised before the vault sees the data, the vault records what it was told.
- Which wording to use, how long to keep records and what a court or regulator will accept are your decisions.
  Involving qualified counsel is recommended as best practice; it is your decision.
