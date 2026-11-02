import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { BOOT_COPY, BOOT_DEADLINE_MS, BOOT_SCRIPT, BOOT_SCRIPT_SLOT, BOOT_STYLE, BOOT_STYLE_SLOT } from '../src/lib/boot-watch.ts';
import { injectBoot, withBootHashes } from '../scripts/csp-hashes.mjs';

const HEADERS = `/*
  Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'
  X-Content-Type-Options: nosniff
`;
const sha = (t: string) => `'sha256-${crypto.createHash('sha256').update(t).digest('base64')}'`;

test('the page gives up waiting after a fixed deadline and says so in a styled, labelled state with a Retry button', () => {
  assert.ok(BOOT_DEADLINE_MS >= 5000 && BOOT_DEADLINE_MS <= 10000);
  assert.match(BOOT_COPY.title, /Can't reach ConsentVault/);
  assert.ok(BOOT_COPY.cause.length > 10 && BOOT_COPY.next.length > 10 && BOOT_COPY.retry === 'Retry');
  assert.match(BOOT_STYLE, /#boot-fail\[hidden\]\s*\{\s*display:\s*none/);
  assert.ok(BOOT_SCRIPT.includes(String(BOOT_DEADLINE_MS)));
  assert.ok(/dataset\.ready/.test(BOOT_SCRIPT) && /location\.reload/.test(BOOT_SCRIPT) && /boot-retry/.test(BOOT_SCRIPT));
});

test('the built pages carry the inline pieces exactly once, put there by the build and not by page code', () => {
  const page = `<html><head><meta name="${BOOT_STYLE_SLOT}" content=""/></head><body><meta name="${BOOT_SCRIPT_SLOT}" content=""/></body></html>`;
  const out = injectBoot(page, BOOT_SCRIPT, BOOT_STYLE);
  assert.ok(out.includes(`<style>${BOOT_STYLE}</style>`) && out.includes(`<script>${BOOT_SCRIPT}</script>`));
  assert.ok(!out.includes(BOOT_STYLE_SLOT) && !out.includes(BOOT_SCRIPT_SLOT));
  assert.throws(() => injectBoot('<html></html>', BOOT_SCRIPT, BOOT_STYLE), /placeholder/);
  assert.throws(() => injectBoot(page + page, BOOT_SCRIPT, BOOT_STYLE), /placeholder/);
});

test('the policy allows exactly these two inline pieces by hash and nothing else inline', () => {
  const out = withBootHashes(HEADERS, BOOT_SCRIPT, BOOT_STYLE);
  assert.ok(out.includes(`script-src 'self' ${sha(BOOT_SCRIPT)};`));
  assert.ok(out.includes(`style-src 'self' ${sha(BOOT_STYLE)};`));
  assert.ok(!out.includes("'unsafe-inline'") && !out.includes("'unsafe-eval'"));
  assert.ok(out.includes("default-src 'self'") && out.includes('X-Content-Type-Options'));
  assert.throws(() => withBootHashes('/*\n  X-Test: 1\n', BOOT_SCRIPT, BOOT_STYLE), /Content-Security-Policy/);
  assert.throws(() => withBootHashes(HEADERS.replace("script-src 'self'; ", ''), BOOT_SCRIPT, BOOT_STYLE), /script-src/);
});
