import React, { useCallback, useEffect, useId, useRef, useState } from 'react';
import { ApiError } from '../lib/api/client.ts';
import { SYMBOLS, reactAttrs } from '../lib/sprite.ts';
import { DELIVERY_LABEL, DELIVERY_TONE, NA, ORG_STATUS_ICON, ORG_STATUS_LABEL, ORG_STATUS_TONE, causeLine, evidenceLabel } from '../lib/copy.ts';
import { fmtDate, fmtDateTime } from '../lib/format.ts';
import type { OrgStatus } from '../lib/api/types.ts';
import { Link, useRouter } from '../lib/router.tsx';

export const cx = (...a: (string | false | null | undefined)[]) => a.filter(Boolean).join(' ');

// ---------- icons ----------
export function Sprite() {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" width="0" height="0" className="sr-sprite" aria-hidden="true" focusable="false">
      <defs>
        {SYMBOLS.map((s) => <symbol key={s.id} id={s.id} viewBox={s.viewBox}>{s.shapes.map((sh, i) => React.createElement(sh.tag, { key: i, ...reactAttrs(sh.attrs) }))}</symbol>)}
      </defs>
    </svg>
  );
}
export function Icon({ name, className }: { name: string; className?: string }) {
  return <svg className={className} aria-hidden="true" focusable="false"><use href={`#${name}`} /></svg>;
}

// ---------- buttons ----------
type BtnProps = {
  variant?: 'primary' | 'secondary' | 'quiet' | 'danger';
  size?: 'sm';
  busy?: boolean;
  busyLabel?: string;
  icon?: string;
} & Omit<React.ButtonHTMLAttributes<HTMLButtonElement>, 'className'> & { className?: string };

export function Btn({ variant = 'secondary', size, busy, busyLabel, icon, children, className, disabled, type = 'button', ...rest }: BtnProps) {
  return (
    <button type={type} className={cx('btn', `btn-${variant}`, size === 'sm' && 'btn-sm', className)} disabled={disabled || busy} aria-busy={busy || undefined} {...rest}>
      {icon && <Icon name={icon} />}
      {busy ? busyLabel ?? 'Working' : children}
    </button>
  );
}

export function LinkBtn({ href, variant = 'secondary', size, children, className, icon, disabled, ...rest }: { href: string; variant?: 'primary' | 'secondary' | 'quiet' | 'danger'; size?: 'sm'; icon?: string; disabled?: boolean } & Omit<React.AnchorHTMLAttributes<HTMLAnchorElement>, 'href'>) {
  return (
    <Link href={href} className={cx('btn', `btn-${variant}`, size === 'sm' && 'btn-sm', className)} aria-disabled={disabled || undefined} {...rest}>
      {icon && <Icon name={icon} />}{children}
    </Link>
  );
}

// ---------- chips ----------
export function Chip({ tone, icon, children, title }: { tone: string; icon?: string; children: React.ReactNode; title?: string }) {
  return <span className={cx('chip', tone)} title={title}>{icon && <Icon name={icon} />}{children}</span>;
}
export function EvidenceChip({ status }: { status: string }) {
  const l = evidenceLabel(status);
  return <Chip tone={`ev-${l.kind}`} icon={l.icon}>{l.text}</Chip>;
}
export function OrgChip({ status }: { status: OrgStatus | null }) {
  if (!status) return <span className="na">{NA}</span>;
  return <Chip tone={ORG_STATUS_TONE[status]} icon={ORG_STATUS_ICON[status]}>{ORG_STATUS_LABEL[status]}</Chip>;
}
export function DeliveryChip({ status }: { status: string }) {
  return <Chip tone={DELIVERY_TONE[status] ?? 'st-neutral'} icon={status === 'acknowledged' ? 'i-ok' : status === 'dead' ? 'i-err' : status === 'failed' ? 'i-warn' : 'i-info'}>{DELIVERY_LABEL[status] ?? status}</Chip>;
}
export function SealChip({ sealedAt }: { sealedAt: string | null }) {
  return sealedAt
    ? <Chip tone="st-success" icon="i-seal">Sealed <Time iso={sealedAt} /></Chip>
    : <Chip tone="st-warning" icon="i-seal">Seal pending</Chip>;
}
export function StatusWord({ tone, icon, children }: { tone: string; icon: string; children: React.ReactNode }) { return <Chip tone={tone} icon={icon}>{children}</Chip>; }

export function NotAvailable() { return <span className="na">{NA}</span>; }

export function Time({ iso, date }: { iso: string | null | undefined; date?: boolean }) {
  if (!iso) return <NotAvailable />;
  const text = date ? fmtDate(iso) : fmtDateTime(iso);
  return <time dateTime={iso}>{text}</time>;
}

// ---------- page head, banners, states ----------
export function PageHead({ title, lede, meta, actions }: { title: string; lede?: React.ReactNode; meta?: React.ReactNode; actions?: React.ReactNode }) {
  const ref = useRef<HTMLHeadingElement>(null);
  const { navigations } = useRouter();
  useEffect(() => { if (navigations > 0) ref.current?.focus(); // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  return (
    <div className="ph">
      <div>
        <h1 ref={ref} tabIndex={-1}>{title}</h1>
        {lede && <p className="lede">{lede}</p>}
        {meta && <div className="meta">{meta}</div>}
      </div>
      {actions && <div className="btn-row">{actions}</div>}
    </div>
  );
}

type BannerKind = 'info' | 'success' | 'warning' | 'danger';
const BANNER_ICON: Record<BannerKind, string> = { info: 'i-info', success: 'i-ok', warning: 'i-warn', danger: 'i-err' };
export function Banner({ kind, title, children, action, role, id, bannerRef }: { kind: BannerKind; title?: React.ReactNode; children?: React.ReactNode; action?: React.ReactNode; role?: 'status' | 'alert'; id?: string; bannerRef?: React.Ref<HTMLDivElement> }) {
  return (
    <div className={cx('banner', kind)} role={role ?? (kind === 'danger' ? 'alert' : 'status')} id={id} ref={bannerRef} tabIndex={bannerRef ? -1 : undefined}>
      <Icon name={BANNER_ICON[kind]} />
      <div className="bd">
        {title && <b>{title}</b>}
        {children && <p>{children}</p>}
        {action}
      </div>
    </div>
  );
}

/** A success banner that takes focus when it appears (a11y: after a successful create, focus the banner). */
export function SuccessBanner({ children, action, title }: { children: React.ReactNode; action?: React.ReactNode; title?: string }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => { ref.current?.focus(); }, []);
  return <Banner kind="success" bannerRef={ref} title={title} action={action}>{children}</Banner>;
}

export function StateBlock({ kind, title, children, cause, next, actions, icon, headingLevel = 2 }: { kind: 'empty' | 'error'; title: string; children?: React.ReactNode; cause?: React.ReactNode; next?: React.ReactNode; actions?: React.ReactNode; icon?: string; headingLevel?: 2 | 3 }) {
  const H = (`h${headingLevel}`) as 'h2' | 'h3';
  if (kind === 'empty') {
    return (
      <div className="empty">
        <Icon name={icon ?? 'i-vault'} className="big" />
        <H>{title}</H>
        {children && <p>{children}</p>}
        {actions && <div className="btn-row">{actions}</div>}
      </div>
    );
  }
  return (
    <div className="banner danger" role="alert">
      <Icon name="i-err" />
      <div className="bd">
        <H>{title}</H>
        <div className="cause">
          {cause && <p><b>Cause:</b> {cause}</p>}
          {next && <p><b>Next:</b> {next}</p>}
        </div>
        {actions && <div className="btn-row mt4">{actions}</div>}
      </div>
    </div>
  );
}

export const STARTING_RETRY_MS = 15000;
export const STARTING_GIVE_UP_MS = 5 * 60 * 1000;

/** Ask again every 15 seconds; after about five minutes stop and say so through giveUp. Returns the stop function. */
export function startRetryLoop(retry: () => void, giveUp: () => void, everyMs = STARTING_RETRY_MS, maxMs = STARTING_GIVE_UP_MS): () => void {
  let elapsed = 0;
  const t = setInterval(() => {
    elapsed += everyMs;
    if (elapsed >= maxMs) { clearInterval(t); giveUp(); return; }
    retry();
  }, everyMs);
  return () => clearInterval(t);
}

/** The cloud servers are parked and the edge has asked for them: say so and re-run the screen's own load until the vault answers (in place, no page reload, focus untouched). */
export function StartingBlock({ onRetry, onGiveUp, headingLevel = 2 }: { onRetry: () => void; onGiveUp?: () => void; headingLevel?: 2 | 3 }) {
  useEffect(() => startRetryLoop(onRetry, onGiveUp ?? (() => {})), [onRetry, onGiveUp]);
  const H = (`h${headingLevel}`) as 'h2' | 'h3';
  return (
    <div className="empty" role="status" aria-live="polite">
      <Icon name="i-vault" className="big" />
      <H>ConsentVault is starting</H>
      <p>This takes about two minutes. This page refreshes itself and shows your dashboard as soon as it is ready. Capture from your website and systems is not affected.</p>
    </div>
  );
}

export const NOT_SAVED_STARTING = 'Not saved. ConsentVault is starting; try again in about two minutes.';

/** Error formula (copy-rules.md section 4): what did not happen, cause with status and name, one next step.
 *  vault_starting: a LOAD passes onRetry and polls itself (up to about five minutes, then the plain error); anything else (a save, a create, a confirm)
 *  gets a static notice with no timer, so nothing a person typed is ever cleared. */
export function ErrorBlock({ title, err, next, actions, override, headingLevel, onRetry, startingNotice }: { title: string; err: ApiError; next: React.ReactNode; actions?: React.ReactNode; override?: string; headingLevel?: 2 | 3; onRetry?: () => void; startingNotice?: string }) {
  const [gaveUp, setGaveUp] = useState(false);
  if (err.code === 'vault_starting' && !gaveUp) {
    if (onRetry) return <StartingBlock onRetry={onRetry} onGiveUp={() => setGaveUp(true)} headingLevel={headingLevel} />;
    return <Banner kind="warning" title={startingNotice ?? NOT_SAVED_STARTING} />;
  }
  return <StateBlock kind="error" title={title} cause={causeLine(err.status, err.code, override)} next={next} actions={actions} headingLevel={headingLevel} />;
}

export function Skeleton({ what, rows = 3, variant = 'text' }: { what: string; rows?: number; variant?: 'text' | 'table' | 'tiles' }) {
  return (
    <div aria-busy="true" role="status" aria-label={`Loading ${what}`}>
      <p className="loading-msg">Loading {what}</p>
      <div className="skel" aria-hidden="true">
        {variant === 'tiles'
          ? Array.from({ length: rows }).map((_, i) => <i key={i} className="h" />)
          : Array.from({ length: variant === 'table' ? rows + 1 : rows }).map((_, i) => <i key={i} />)}
      </div>
    </div>
  );
}

// ---------- cards and key values ----------
export function Tile({ label, value, sub, href, alert, action, of }: { label: string; value: React.ReactNode | null; sub?: React.ReactNode; href?: string; alert?: boolean; action?: React.ReactNode; of?: React.ReactNode }) {
  return (
    <div className={cx('card stat', alert && 'alert')}>
      <div className="k">{label}</div>
      <div className={cx('v', value === null || typeof value === 'string' && value.length > 12 ? 'small' : '')}>
        {value === null ? <span className="na">{NA}</span> : value}{of ? <> <span className="of">{of}</span></> : null}
      </div>
      {sub && <div className="s">{sub}</div>}
      {href && action ? <LinkBtn href={href} variant="secondary" size="sm">{action}</LinkBtn> : action}
    </div>
  );
}

export function KV({ rows }: { rows: [string, React.ReactNode][] }) {
  return <dl className="kv">{rows.map(([k, v]) => <React.Fragment key={k}><dt>{k}</dt><dd>{v}</dd></React.Fragment>)}</dl>;
}

export function Meter({ label, used, included }: { label: string; used: number | null; included: number | null }) {
  const pct = used !== null && included ? Math.min(100, Math.round((used / included) * 100)) : 0;
  const text = used === null || included === null ? NA : `${used.toLocaleString('en-US')} of ${included.toLocaleString('en-US')}`;
  return (
    <div className="mb5">
      <div className="tile-h"><b>{label}</b><span className="num">{text}</span></div>
      <div className="meter" role="img" aria-label={`${label}: ${text}`}>
        <svg viewBox="0 0 100 8" preserveAspectRatio="none" aria-hidden="true"><rect x="0" y="0" width={pct} height="8" fill="currentColor" /></svg>
      </div>
    </div>
  );
}

// ---------- data table (collapses to cards under 760px) ----------
export interface Col<R> { key: string; header: string; render: (r: R) => React.ReactNode; right?: boolean; primary?: boolean }
export function DataTable<R>({ caption, columns, rows, rowKey, actions }: { caption: string; columns: Col<R>[]; rows: R[]; rowKey: (r: R) => string; actions?: (r: R) => React.ReactNode }) {
  return (
    <div className="tw">
      <div className="tscroll as-table">
        <table>
          <caption>{caption}</caption>
          <thead><tr>{columns.map((c) => <th key={c.key} scope="col" className={c.right ? 'r' : undefined}>{c.header}</th>)}{actions && <th scope="col"><span className="sr">Actions</span></th>}</tr></thead>
          <tbody>{rows.map((r) => (
            <tr key={rowKey(r)}>
              {columns.map((c) => c.primary ? <th scope="row" key={c.key} className={cx('rowhead', c.right && 'r')}>{c.render(r)}</th> : <td key={c.key} className={c.right ? 'r' : undefined}>{c.render(r)}</td>)}
              {actions && <td>{actions(r)}</td>}
            </tr>))}
          </tbody>
        </table>
      </div>
      <div className="cards" role="list" aria-label={caption}>
        {rows.map((r) => (
          <div className="rowcard" role="listitem" key={rowKey(r)}>
            <dl>{columns.map((c) => <React.Fragment key={c.key}><dt>{c.header}</dt><dd>{c.render(r)}</dd></React.Fragment>)}</dl>
            {actions && <div className="actions">{actions(r)}</div>}
          </div>
        ))}
      </div>
    </div>
  );
}

// ---------- forms ----------
export function useFieldIds(name?: string) {
  const id = useId();
  return { id: `${name ?? 'f'}-${id.replace(/:/g, '')}`, hint: `h-${id.replace(/:/g, '')}`, err: `e-${id.replace(/:/g, '')}` };
}

export function Field({ label, hint, error, children, id, errId, hintId }: { label: string; hint?: React.ReactNode; error?: string | null; children: React.ReactNode; id: string; errId: string; hintId: string }) {
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      {hint && <p className="hint" id={hintId}>{hint}</p>}
      {children}
      {error && <p className="field-error" id={errId}><Icon name="i-err" /><span>{error}</span></p>}
    </div>
  );
}

type InputExtra = { label: string; hint?: React.ReactNode; error?: string | null };
export const TextField = React.forwardRef<HTMLInputElement, InputExtra & React.InputHTMLAttributes<HTMLInputElement>>(function TextField({ label, hint, error, className, ...rest }, ref) {
  const ids = useFieldIds(rest.name);
  const describedBy = [hint ? ids.hint : '', error ? ids.err : ''].filter(Boolean).join(' ') || undefined;
  return (
    <Field label={label} hint={hint} error={error} id={ids.id} errId={ids.err} hintId={ids.hint}>
      <input ref={ref} id={ids.id} className={cx('input', className)} aria-invalid={error ? true : undefined} aria-describedby={describedBy} {...rest} />
    </Field>
  );
});
export const TextArea = React.forwardRef<HTMLTextAreaElement, InputExtra & React.TextareaHTMLAttributes<HTMLTextAreaElement>>(function TextArea({ label, hint, error, className, ...rest }, ref) {
  const ids = useFieldIds(rest.name);
  const describedBy = [hint ? ids.hint : '', error ? ids.err : ''].filter(Boolean).join(' ') || undefined;
  return (
    <Field label={label} hint={hint} error={error} id={ids.id} errId={ids.err} hintId={ids.hint}>
      <textarea ref={ref} id={ids.id} className={cx('textarea', className)} aria-invalid={error ? true : undefined} aria-describedby={describedBy} {...rest} />
    </Field>
  );
});
export function SelectField({ label, hint, error, options, ...rest }: InputExtra & { options: { value: string; label: string }[] } & React.SelectHTMLAttributes<HTMLSelectElement>) {
  const ids = useFieldIds(rest.name);
  const describedBy = [hint ? ids.hint : '', error ? ids.err : ''].filter(Boolean).join(' ') || undefined;
  return (
    <Field label={label} hint={hint} error={error} id={ids.id} errId={ids.err} hintId={ids.hint}>
      <select id={ids.id} className="select" aria-invalid={error ? true : undefined} aria-describedby={describedBy} {...rest}>
        {options.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
      </select>
    </Field>
  );
}
export function Check({ label, hint, ...rest }: { label: React.ReactNode; hint?: React.ReactNode } & React.InputHTMLAttributes<HTMLInputElement>) {
  const ids = useFieldIds(rest.name);
  return (
    <div className="check">
      <input id={ids.id} type="checkbox" aria-describedby={hint ? ids.hint : undefined} {...rest} />
      <label htmlFor={ids.id}>{label}{hint && <span className="hint" id={ids.hint}> {hint}</span>}</label>
    </div>
  );
}
export function Radio({ label, hint, ...rest }: { label: React.ReactNode; hint?: React.ReactNode } & React.InputHTMLAttributes<HTMLInputElement>) {
  const ids = useFieldIds(rest.name);
  return (
    <label className="opt" htmlFor={ids.id}>
      <input id={ids.id} type="radio" {...rest} />
      <span><b>{label}</b>{hint && <span>{hint}</span>}</span>
    </label>
  );
}

export function ErrorSummary({ errors, headingRef }: { errors: { id?: string; message: string }[]; headingRef?: React.Ref<HTMLDivElement> }) {
  if (!errors.length) return null;
  return (
    <div className="banner danger errsum" role="alert" ref={headingRef} tabIndex={-1}>
      <Icon name="i-err" />
      <div className="bd"><b>Fix {errors.length === 1 ? 'this' : 'these'} before you continue</b>
        <ul>{errors.map((e, i) => <li key={i}>{e.id ? <a href={`#${e.id}`}>{e.message}</a> : e.message}</li>)}</ul>
      </div>
    </div>
  );
}

// ---------- copy to clipboard ----------
export function CopyButton({ text, label = 'Copy', copiedLabel = 'Copied', size = 'sm', ariaLabel }: { text: string; label?: string; copiedLabel?: string; size?: 'sm'; ariaLabel?: string }) {
  const [done, setDone] = useState(false);
  const copy = useCallback(async () => {
    try { await navigator.clipboard.writeText(text); }
    catch {
      const ta = document.createElement('textarea'); ta.value = text; ta.setAttribute('readonly', ''); ta.className = 'sr-live';
      document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta);
    }
    setDone(true); window.setTimeout(() => setDone(false), 2500);
  }, [text]);
  return (
    <>
      <Btn variant="secondary" size={size} icon="i-copy" onClick={copy} aria-label={ariaLabel}>{done ? copiedLabel : label}</Btn>
      <span className="sr-live" role="status">{done ? copiedLabel : ''}</span>
    </>
  );
}

export function CodeBlock({ code, label }: { code: string; label: string }) {
  return <pre className="code" tabIndex={0} role="region" aria-label={label}>{code}</pre>;
}

// ---------- setup checklist ----------
/** A form screen drawn inside the setup walkthrough: on success it reports back instead of navigating away. */
export interface Embedded { onDone: (notice: string, nextHref?: string) => void }
export interface ChecklistItem { label: string; done: boolean | null; href: string; chip?: { text: string; tone: string; icon: string }; primary?: boolean }
export function SetupChecklist({ items, readOnly }: { items: ChecklistItem[]; readOnly?: boolean }) {
  const firstTodo = items.some((i) => i.primary !== undefined) ? items.findIndex((i) => i.primary) : items.findIndex((i) => i.done === false);
  return (
    <ol className="steps">
      {items.map((it, i) => (
        <li key={it.label} className={cx(it.done && 'done', !readOnly && i === firstTodo && 'next')}>
          <span className="n" aria-hidden="true">{it.done ? <Icon name="i-check" /> : i + 1}</span>
          <span className="t">{it.label}</span>
          {it.chip ? <Chip tone={it.chip.tone} icon={it.chip.icon}>{it.chip.text}</Chip>
            : it.done === null ? <Chip tone="ev-na" icon="i-warn">{NA}</Chip> : <Chip tone={it.done ? 'st-success' : 'st-neutral'} icon={it.done ? 'i-ok' : 'i-dash'}>{it.done ? 'Done' : 'To do'}</Chip>}
          {!readOnly && i === firstTodo && <LinkBtn href={it.href} variant="primary" size="sm">{it.label}</LinkBtn>}
        </li>
      ))}
    </ol>
  );
}

export function Pager({ prev, next, onPrev, onNext }: { prev: boolean; next: boolean; onPrev: () => void; onNext: () => void }) {
  return (
    <nav className="btn-row mt4" aria-label="Pages">
      <Btn size="sm" disabled={!prev} onClick={onPrev}>Newer</Btn>
      <Btn size="sm" disabled={!next} onClick={onNext}>Older</Btn>
    </nav>
  );
}

export function Tabs({ tabs, current, onSelect, label }: { tabs: { id: string; label: string }[]; current: string; onSelect: (id: string) => void; label: string }) {
  return (
    <div className="tabs" role="tablist" aria-label={label}>
      {tabs.map((t) => <button key={t.id} type="button" role="tab" aria-selected={t.id === current} onClick={() => onSelect(t.id)}>{t.label}</button>)}
    </div>
  );
}
