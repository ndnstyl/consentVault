// After `next build`: allow the page's two inline boot pieces (src/lib/boot-watch.ts) in the policy by hash, nothing wider.
//   node scripts/csp-hashes.mjs            rewrites out/_headers
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const sha = (t) => `'sha256-${crypto.createHash('sha256').update(t).digest('base64')}'`;

// Puts the inline style and script into one built page at their placeholders; exactly one of each must be there.
export function injectBoot(html, script, style) {
  const slot = (name) => new RegExp(`<meta name="${name}" content=""\\s*/?>`, 'g');
  let out = html;
  for (const [name, tag, text] of [['cv-boot-style', 'style', style], ['cv-boot-script', 'script', script]]) {
    const hits = out.match(slot(name)) ?? [];
    if (hits.length !== 1) throw new Error(`expected exactly one ${name} placeholder in the page, found ${hits.length}`);
    out = out.replace(slot(name), () => `<${tag}>${text}</${tag}>`);
  }
  return out;
}

export function withBootHashes(headers, script, style) {
  if (!/Content-Security-Policy:/.test(headers)) throw new Error('_headers has no Content-Security-Policy line to extend');
  let out = headers;
  for (const [directive, text] of [['script-src', script], ['style-src', style]]) {
    const re = new RegExp(`${directive} 'self'(?=;)`);
    if (!re.test(out)) throw new Error(`the policy has no "${directive} 'self'" to add the boot hash to`);
    out = out.replace(re, `${directive} 'self' ${sha(text)}`);
  }
  return out;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const { BOOT_SCRIPT, BOOT_STYLE } = await import('../src/lib/boot-watch.ts');
  const outDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'out');
  const pages = fs.readdirSync(outDir, { recursive: true }).filter((f) => String(f).endsWith('.html')).map((f) => path.join(outDir, String(f)));
  for (const f of pages) {
    const html = fs.readFileSync(f, 'utf8');
    if (html.includes('cv-boot-style')) fs.writeFileSync(f, injectBoot(html, BOOT_SCRIPT, BOOT_STYLE));
  }
  console.log(`boot pieces added to ${pages.length} pages`);
  const file = path.join(outDir, '_headers');
  fs.writeFileSync(file, withBootHashes(fs.readFileSync(file, 'utf8'), BOOT_SCRIPT, BOOT_STYLE));
  console.log('boot hashes added to out/_headers');
}
