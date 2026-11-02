import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { describePortHolder, stopGroup, killGroupSync } from '../e2e/real/workos-smoke-lib.mjs';

const alive = (pid) => { try { process.kill(pid, 0); return true; } catch { return false; } };
const spawnTree = async () => {
  const child = spawn(process.execPath, ['-e', "const c=require('child_process').spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'inherit'});console.log(c.pid);setInterval(()=>{},1000)"], { detached: true, stdio: ['ignore', 'pipe', 'inherit'] });
  const grand = Number(await new Promise((r) => child.stdout.once('data', (d) => r(String(d).trim()))));
  return { child, grand };
};
const gone = async (pid) => { for (let i = 0; i < 40 && alive(pid); i++) await new Promise((r) => setTimeout(r, 50)); return !alive(pid); };

test('stopping a child in its own group takes its grandchildren with it', async () => {
  const { child, grand } = await spawnTree();
  assert.ok(alive(grand));
  await stopGroup(child, 2000);
  assert.ok(await gone(child.pid) && await gone(grand), 'neither the child nor the grandchild survives');
});

test('the synchronous exit-time kill also takes the whole group', async () => {
  const { child, grand } = await spawnTree();
  killGroupSync(child);
  assert.ok(await gone(child.pid) && await gone(grand));
});

test('a taken port is named with the process holding it; a free port is null', async () => {
  const s = http.createServer(); await new Promise((r) => s.listen(0, '127.0.0.1', r));
  const port = s.address().port;
  const h = describePortHolder(port);
  assert.equal(h.pid, process.pid);
  assert.match(h.command, /node/);
  await new Promise((r) => s.close(r));
  assert.equal(describePortHolder(port), null);
});
