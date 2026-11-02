import test from 'node:test';
import assert from 'node:assert/strict';
import { safeReturn, sameOriginTarget } from '../src/lib/safe-return.ts';

test('a return address is a path on this site or the home page', () => {
  assert.equal(safeReturn('/evidence?x=1#top'), '/evidence?x=1#top');
  assert.equal(safeReturn(null), '/');
  for (const bad of ['//evil.com', '/\\evil.com', '/\t/evil.com', '/\n/evil.com', '/\r/evil.com', '/ /evil.com', '/\u0000x', 'https://evil.com', 'javascript:alert(1)', 'evil.com', '/a\\b', '/\u007f/x']) {
    assert.equal(safeReturn(bad), '/', JSON.stringify(bad));
  }
  // the browser strips a tab or newline before parsing, so the decoded query value is the dangerous one
  assert.equal(safeReturn(new URLSearchParams('return=/%09/evil.com').get('return')), '/');
});

test('navigation resolves only to this origin; anything else is refused', () => {
  const origin = 'https://app.example.com';
  assert.equal(sameOriginTarget('/ok?x=1', origin), '/ok?x=1');
  assert.equal(sameOriginTarget('https://app.example.com/ok', origin), '/ok');
  for (const bad of ['//evil.com', '/\t/evil.com', 'https://evil.com/x', 'http://app.example.com/x', 'javascript:alert(1)', '/\\evil.com']) {
    assert.equal(sameOriginTarget(bad, origin), null, JSON.stringify(bad));
  }
});
