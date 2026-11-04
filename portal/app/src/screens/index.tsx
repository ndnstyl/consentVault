import React from 'react';
import type { RouteDef } from '../lib/routes.ts';
import { SignIn, Callback, Invite, ChooseOrg, Plan, BillingReturn } from './auth.tsx';
import { Overview, FirstEvent } from './overview.tsx';
import { Brands, Sources, SourceDetail, Credentials, CredentialNew } from './config.tsx';
import { SourceFieldMaps } from './fieldmaps.tsx';
import { Wording, WordingNew, WordingDetail } from './wording.tsx';
import { Policies, PolicyNew, PolicyDetail, PolicyApprove, Checklists, ChecklistDetail } from './policies.tsx';
import { EvidenceLookup, Exports, ExportDetailScreen } from './evidence.tsx';
import { Systems, SystemNew, SystemDetail } from './systems.tsx';
import { Records } from './records.tsx';
import { Setup } from './setup.tsx';
import { Confirmations, ConfirmationEdit } from './confirmations.tsx';
import { Retention, Members, Audit, BillingScreen, Settings, References, CompanySignIn } from './org.tsx';

export function Screen({ route, params }: { route: RouteDef; params: Record<string, string> }) {
  switch (route.id) {
    case 'sign-in': return <SignIn />;
    case 'callback': return <Callback />;
    case 'invite': return <Invite />;
    case 'choose-org': return <ChooseOrg />;
    case 'plan': return <Plan />;
    case 'billing-return': return <BillingReturn />;
    case 'overview': return <Overview />;
    case 'first-event': return <FirstEvent />;
    case 'brands': return <Brands />;
    case 'sources': return <Sources />;
    case 'source-detail': return <SourceDetail id={params.source_id} />;
    case 'source-field-maps': return <SourceFieldMaps id={params.source_id} />;
    case 'credentials': return <Credentials />;
    case 'credential-new': return <CredentialNew />;
    case 'wording': return <Wording />;
    case 'wording-new': return <WordingNew />;
    case 'wording-detail': return <WordingDetail sha={params.sha256} />;
    case 'policies': return <Policies />;
    case 'policy-new': return <PolicyNew />;
    case 'policy-detail': return <PolicyDetail version={params.version} />;
    case 'policy-approve': return <PolicyApprove version={params.version} />;
    case 'checklists': return <Checklists />;
    case 'checklist-detail': return <ChecklistDetail version={params.version} />;
    case 'evidence': return <EvidenceLookup />;
    case 'exports': return <Exports />;
    case 'export-detail': return <ExportDetailScreen id={params.export_id} />;
    case 'systems': return <Systems />;
    case 'system-new': return <SystemNew />;
    case 'system-detail': return <SystemDetail id={params.system_id} />;
    case 'retention': return <Retention />;
    case 'members': return <Members />;
    case 'sso': return <CompanySignIn />;
    case 'audit': return <Audit />;
    case 'billing': return <BillingScreen />;
    case 'settings': return <Settings />;
    case 'references': return <References />;
    case 'records': return <Records />;
    case 'setup': return <Setup />;
    case 'confirmations': return <Confirmations />;
    case 'confirmation-edit': return <ConfirmationEdit sourceId={params.source_id} channel={params.channel} />;
  }
}
