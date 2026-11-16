import React from 'react';
import { TUTORIALS, TUTORIALS_COPY, tutorialSrc } from '../lib/tutorials.ts';
import { canView } from '../lib/roles.ts';
import { useSession } from '../lib/session.tsx';
import { Link } from '../lib/router.tsx';
import { PageHead } from '../components/ui.tsx';

export function Tutorials() {
  const { role } = useSession();
  return (
    <>
      <PageHead title={TUTORIALS_COPY.title} lede={TUTORIALS_COPY.lede} />
      <ol className="tutorials">
        {TUTORIALS.map((t) => (
          <li key={t.id} className="card tutorial" id={t.id}>
            <h2 id={`${t.id}-h`}>{`${t.number}. ${t.title}`}</h2>
            <p className="muted">{t.tagline}</p>
            <video controls preload="metadata" playsInline aria-labelledby={`${t.id}-h`} src={tutorialSrc(t)}>{TUTORIALS_COPY.noVideo}</video>
            <p className="muted tutorial-kind">{t.voiced ? TUTORIALS_COPY.voiced : TUTORIALS_COPY.silent}</p>
            <p>{t.summary}</p>
            {canView(role, t.screen.id) && <p><Link href={t.screen.href}>{TUTORIALS_COPY.open(t.screen.label)}</Link></p>}
          </li>
        ))}
      </ol>
      <p className="muted">{TUTORIALS_COPY.demoNote}</p>
    </>
  );
}
