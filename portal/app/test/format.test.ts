import test from 'node:test';
import assert from 'node:assert/strict';
import { checkContact, maskContact, prettyContact, shortId, orgsBrandsLine } from '../src/lib/format.ts';
import { scanCopy, stripAllowlisted } from '../src/lib/copycheck.ts';
import { GATE_NOTICE, PACKAGE_COVER, evidenceLabel } from '../src/lib/copy.ts';

test('contact check accepts a ten digit phone and a full email, refuses an incomplete entry', () => {
  assert.deepEqual(checkContact('(555) 555-0100'), { ok: true, value: '+15555550100', kind: 'phone' });
  assert.deepEqual(checkContact('dana@acme.com'), { ok: true, value: 'dana@acme.com', kind: 'email' });
  const bad = checkContact('(555) 555-01');
  assert.equal(bad.ok, false);
  assert.equal(bad.ok === false && bad.kind, 'phone');
  const badMail = checkContact('dana@');
  assert.equal(badMail.ok === false && badMail.kind, 'email');
});

test('masked and pretty contact forms never expose a full number', () => {
  assert.equal(maskContact('+15555550100'), '(555) ***-0100');
  assert.equal(maskContact('dana@acme.com'), 'd***@acme.com');
  assert.equal(prettyContact('+15555550100'), '(555) 555-0100');
  assert.equal(shortId('9f2c4d5e6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6ee1'), '9f2c...e1');
});

test('copy check refuses legal conclusions and dashes, and allows only the fixed strings', () => {
  for (const bad of ['This is compliant.', 'valid consent found', 'Proof of consent', 'safe to call', 'it is lawful', 'guaranteed', 'Something went wrong', 'a — b', 'a – b', 'permitted to text', 'the check is satisfied', 'meets TCPA']) {
    assert.ok(scanCopy(bad).length > 0, bad);
  }
  assert.deepEqual(scanCopy(GATE_NOTICE), []);
  assert.deepEqual(scanCopy(PACKAGE_COVER), []);
  assert.deepEqual(scanCopy('Citations and official links only. Not legal advice.'), []);
  assert.deepEqual(scanCopy('It reports documentation completeness and is not a legal test.'), []);
  assert.ok(scanCopy(`${GATE_NOTICE} but also compliant`).length > 0);
  assert.equal(stripAllowlisted(GATE_NOTICE).trim(), '');
});

test('label dictionary words carry no banned phrasing', () => {
  const labels = ['consent_record_found', 'stop_on_record', 'no_record', 'record_incomplete:seller,channels', 'unavailable:key_unavailable', 'unavailable:database_unreachable'].map((s) => evidenceLabel(s).text);
  for (const l of labels) assert.deepEqual(scanCopy(l), [], l);
  assert.equal(evidenceLabel('record_incomplete:seller').text, 'Record incomplete: missing seller');
  assert.equal(evidenceLabel('unavailable:key_unavailable').text, "Not available: your organization's encryption key did not answer");
});

test('the plan card limit line is omitted when the plan carries no limit, never NaN', () => {
  assert.equal(orgsBrandsLine(undefined), null);
  assert.equal(orgsBrandsLine(null), null);
  assert.equal(orgsBrandsLine(NaN), null);
  assert.equal(orgsBrandsLine(5), 'Up to 5 organizations and brands');
});
