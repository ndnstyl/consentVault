// Copies the eight tutorial videos into public/tutorials before the build, so they ship as static assets of the portal Worker.
// The free plan's static assets cap is 25 MiB a file; a file over it, a missing file or a copy that differs from its source is an error, never a skip.
//   node scripts/copy-tutorials.mjs [source folder]     default: the deliverables folder named below
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const SOURCE = process.argv[2] ?? process.env.CV_TUTORIALS_DIR ?? path.resolve(here, '..', '..', '..', '..', 'tutorials');
const DEST = path.resolve(here, '..', 'public', 'tutorials');
const CAP = 25 * 1024 * 1024;
const files = fs.readFileSync(path.resolve(here, '..', 'src', 'lib', 'tutorials.ts'), 'utf8').match(/file: '([^']+\.mp4)'/g)?.map((m) => m.slice(7, -1)) ?? [];
if (files.length !== 8) { console.error(`copy-tutorials: expected 8 video names in src/lib/tutorials.ts, found ${files.length}`); process.exit(2); }
const sha = (p) => crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
fs.mkdirSync(DEST, { recursive: true });
for (const f of files) {
  const from = path.join(SOURCE, f);
  if (!fs.existsSync(from)) { console.error(`copy-tutorials: ${from} is missing. Set CV_TUTORIALS_DIR to the folder that holds the eight videos.`); process.exit(3); }
  const size = fs.statSync(from).size;
  if (size > CAP) { console.error(`copy-tutorials: ${f} is ${size} bytes, over the 25 MiB per-file limit of the free plan.`); process.exit(4); }
  const to = path.join(DEST, f);
  fs.copyFileSync(from, to);
  if (sha(from) !== sha(to)) { console.error(`copy-tutorials: ${f} differs from its source after the copy.`); process.exit(5); }
  console.log(`copy-tutorials: ${f} ${size} bytes ok`);
}
