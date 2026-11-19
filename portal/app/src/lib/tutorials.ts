// The nine how-to videos shown on the Tutorials screen. The files are copied into public/tutorials by scripts/copy-tutorials.mjs at build time
// (see that script for the source folder and the size checks); the summaries are short readings of each video's script. Every string passes the
// portal copy check (test/tutorials.test.ts).
import type { RouteId } from './roles.ts';

export interface Tutorial {
  id: string;
  number: number;
  title: string;
  tagline: string;
  summary: string;
  file: string;
  voiced: boolean;
  seconds: number;
  /** The screen the video is about, so a viewer can open it after watching. */
  screen: { id: RouteId; href: string; label: string };
}

export const TUTORIALS: Tutorial[] = [
  { id: 'sign-in-and-overview', number: 1, title: 'Sign in and the overview', tagline: 'Your first minute in ConsentVault.', voiced: true, seconds: 64,
    file: 'T1-sign-in-and-overview.mp4', screen: { id: 'overview', href: '/', label: 'Overview' },
    summary: 'Sign in with a passkey, or with your company account if your organization connected one. The Overview opens with a short checklist of setup steps, three counts, including events not yet sealed after one hour, and the menu that holds every other screen.' },
  { id: 'find-a-record-and-read-it', number: 2, title: 'Find a record and read it', tagline: 'From a phone number to the full timeline.', voiced: true, seconds: 73,
    file: 'T2-find-a-record-and-read-it.mp4', screen: { id: 'records', href: '/records', label: 'Records' },
    summary: 'Open Records, type the whole phone number or email address and choose Find. The record shows the evidence status for each channel and purpose, a timeline of every event with the time it was sealed, and a link to the wording version that applied.' },
  { id: 'download-an-evidence-package', number: 3, title: 'Download and verify an evidence package', tagline: 'Build it, download it, check it offline.', voiced: true, seconds: 61,
    file: 'T3-download-and-verify-an-evidence-package.mp4', screen: { id: 'evidence', href: '/evidence', label: 'Evidence lookup' },
    summary: 'Look up a phone number in Evidence lookup, then build one signed package of what is held for that person. The download link works once. Unzip the package and run the public verifier offline, using the authority root, the evidence key and the published anchors from outside the package.' },
  { id: 'connect-a-capture-source', number: 4, title: 'Connect a capture source and its credentials', tagline: 'Where consent records come from.', voiced: true, seconds: 69,
    file: 'T4-connect-a-capture-source-and-its-credentials.mp4', screen: { id: 'sources', href: '/sources', label: 'Capture sources' },
    summary: 'A source is a website form, CRM or other system that sends consent records. Add one, choose how it sends, then issue a credential for it. To rotate a key, issue a new credential, switch your system to it, then revoke the old one.' },
  { id: 'consent-wording-versions', number: 5, title: 'Consent wording versions', tagline: 'The exact text, kept word for word.', voiced: false, seconds: 58,
    file: 'T5-consent-wording-versions-captions-only.mp4', screen: { id: 'wording', href: '/wording', label: 'Wording' },
    summary: 'Wording holds the exact consent text each form shows, one row per version. A version cannot be edited. To change the text, register a new version that replaces it. The fingerprint changes if one character changes.' },
  { id: 'stops-erasures-and-retention', number: 6, title: 'Stops, erasures and retention', tagline: 'What happens when someone says stop.', voiced: false, seconds: 69,
    file: 'T6-stops-erasures-and-retention-captions-only.mp4', screen: { id: 'records', href: '/records', label: 'Records' },
    summary: 'Filter Records to those with a stop on record. An erased record can no longer be read, but its stop is kept. Retention is at least five years, and each record keeps the keep-until date it was given when it was written.' },
  { id: 'members-sign-in-and-audit-log', number: 7, title: 'Members, company sign-in and the audit log', tagline: 'Who can get in, and what they did.', voiced: false, seconds: 60,
    file: 'T7-members-company-sign-in-and-the-audit-log-captions-only.mp4', screen: { id: 'audit', href: '/audit', label: 'Audit log' },
    summary: 'Members lists the people in your organization and what each may do, and suggests a second admin. Company sign-in lets people use a company account. The Audit log is append-only and can be filtered by action.' },
  { id: 'integrity-jobs', number: 8, title: 'Integrity jobs: seal, anchor and verify', tagline: 'The four checks behind every record.', voiced: false, seconds: 47,
    file: 'T8-integrity-jobs-seal-anchor-and-verify-captions-only.mp4', screen: { id: 'references', href: '/references', label: 'Rule references' },
    summary: 'Four jobs check the record on a schedule, and each can be run by hand. Seal adds an outside timestamp, Anchor records the chain position outside ConsentVault, Verify chain checks each event links to the one before, and Verify seals checks each seal still matches its event.' },
  { id: 'send-sign-ups-and-stops-to-your-crm', number: 9, title: 'Send sign-ups and stops to your CRM', tagline: 'Connect a system, then let your automation tool update the CRM.', voiced: false, seconds: 91,
    file: 'T9-send-sign-ups-and-stops-to-your-crm-captions-only.mp4', screen: { id: 'systems', href: '/systems', label: 'Connected systems' },
    summary: 'Connect a system and paste the web address your automation tool gave you, whether n8n, Zapier or Make. Choose Plain contact point so a CRM can find the person, a choice recorded in the audit log. The template checks each signature and updates an existing contact only. A stop for someone not in your CRM raises an alert.' },
];

export const TUTORIALS_COPY = {
  title: 'Tutorials',
  lede: 'Nine short videos, each about one screen. Captions are on screen in every video.',
  silent: 'Captions only. This video has no voice-over yet.',
  voiced: 'Voice-over and captions.',
  open: (label: string) => `Open ${label}`,
  noVideo: 'Your browser cannot play this video.',
  demoNote: 'Every video uses a demonstration organization with made-up people and numbers.',
} as const;

export const tutorialSrc = (t: Tutorial): string => `/tutorials/${t.file}#t=1`;
