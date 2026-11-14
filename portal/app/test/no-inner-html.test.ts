import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { SYMBOLS, reactAttrs } from '../src/lib/sprite.ts';

const walk = (d: string): string[] => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(path.join(d, e.name)) : [path.join(d, e.name)]));

test('no source or mock file writes markup into the page', () => {
  const files = [...walk('src'), ...walk('mock')].filter((f) => /\.(tsx?|mjs|js)$/.test(f));
  const bad = files.filter((f) => /innerHTML|outerHTML|insertAdjacentHTML|document\.write/.test(fs.readFileSync(f, 'utf8')));
  assert.deepEqual(bad, []);
});

test('a script tag arriving in data is shown as text, never as an element', () => {
  const evil = '<script>alert(1)</script>';
  const html = renderToStaticMarkup(React.createElement('td', null, evil));
  assert.ok(!html.includes('<script'));
  assert.ok(html.includes('&lt;script&gt;'));
});

test('the icon sprite renders typed shapes with no markup strings', () => {
  const html = renderToStaticMarkup(React.createElement('svg', null, SYMBOLS.map((s) => React.createElement('symbol', { key: s.id, id: s.id }, s.shapes.map((sh, i) => React.createElement(sh.tag, { key: i, ...reactAttrs(sh.attrs) }))))));
  assert.ok(html.includes('stroke-width="1.6"'));
  assert.equal((html.match(/<symbol /g) ?? []).length, SYMBOLS.length);
  assert.ok(SYMBOLS.every((s) => s.shapes.length > 0 && s.shapes.every((sh) => Object.values(sh.attrs).every((v) => !v.includes('<')))));
});
