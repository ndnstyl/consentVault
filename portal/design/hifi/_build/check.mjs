// node check.mjs : axe + overflow check on every state, both themes, 375 and 1440. Writes ../a11y-report.json
import { createRequire } from 'module';
import fs from 'fs'; import path from 'path'; import { fileURLToPath } from 'url';
// playwright and axe-core are the portal app's pinned dev dependencies (portal/app: npm ci).
const require = createRequire(new URL('../../../app/package.json', import.meta.url));
const { chromium } = require('playwright');
const axeSrc = fs.readFileSync(require.resolve('axe-core/axe.min.js'),'utf8');
const here = path.dirname(fileURLToPath(import.meta.url)); const root = path.resolve(here,'..');
const pages = ['index','sources-credentials','evidence','deliveries','policies','components'];
const exe = process.env.CHROME || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const browser = await chromium.launch({ executablePath: exe });
const out = []; let bad = 0;
for (const w of [375,1440]) for (const theme of ['light','dark']) {
  const ctx = await browser.newContext({ viewport:{width:w,height:900}, colorScheme: theme });
  const pg = await ctx.newPage();
  for (const p of pages) {
    await pg.goto(`file://${root}/${p}.html?theme=${theme}`, {waitUntil:'load'});
    const ids = await pg.$$eval('#stateSel option', o=>o.map(x=>x.value).filter(v=>v!=='__all'));
    const list = ids.length?ids:[''];
    for (const id of list) {
      if (id) { await pg.evaluate(i=>{location.hash=i}, id); await pg.waitForTimeout(30); }
      const over = await pg.evaluate(()=>document.documentElement.scrollWidth - window.innerWidth);
      await pg.evaluate(s=>{ if(!window.axe){ const e=document.createElement('script'); e.textContent=s; document.head.appendChild(e);} }, axeSrc);
      const r = await pg.evaluate(async()=>await window.axe.run(document,{runOnly:{type:'tag',values:['wcag2a','wcag2aa','wcag21a','wcag21aa','wcag22aa','best-practice']}}));
      const v = r.violations.map(x=>({id:x.id,impact:x.impact,n:x.nodes.length,sample:x.nodes[0].html.slice(0,140),why:(x.nodes[0].failureSummary||'').slice(0,200)}));
      if (over>0 || v.length) bad++;
      out.push({page:p,state:id,w,theme,overflow:over,violations:v});
    }
  }
  await ctx.close();
}
fs.writeFileSync(path.join(root,'a11y-report.json'), JSON.stringify(out,null,1));
const summary = {}; for (const o of out){ const k=o.page; summary[k]=summary[k]||{runs:0,overflow:0,viol:0}; summary[k].runs++; if(o.overflow>0)summary[k].overflow++; summary[k].viol+=o.violations.length; }
console.log(JSON.stringify(summary,null,1)); console.log('runs with problems:',bad,'of',out.length);
const seen={}; for (const o of out) for (const v of o.violations){ const k=o.page+'|'+v.id+'|'+v.sample.slice(0,60); if(!seen[k]){seen[k]=1; console.log(o.page,o.state,o.w,o.theme,v.id,v.impact,v.sample,'|',v.why.slice(0,120));}}
for (const o of out) if(o.overflow>0 && !seen['o'+o.page+o.state]) {seen['o'+o.page+o.state]=1; console.log('OVERFLOW',o.page,o.state,o.w,o.overflow);}
await browser.close();
