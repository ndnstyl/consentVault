import { createRequire } from 'module';
// playwright and axe-core are the portal app's pinned dev dependencies (portal/app: npm ci).
const require = createRequire(new URL('../../../app/package.json', import.meta.url));
const { chromium } = require('playwright');
const b = await chromium.launch({ executablePath:'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' });
const p = await b.newPage({viewport:{width:375,height:900}});
await p.goto(new URL('../'+process.argv[2]+'.html#'+(process.argv[3]||''), import.meta.url).href);
console.log(await p.evaluate(()=>{const o=[];document.querySelectorAll('body *').forEach(e=>{const r=e.getBoundingClientRect();if(r.right>376&&r.width>0&&getComputedStyle(e).position!=='fixed')o.push(e.tagName+'.'+e.className+' '+Math.round(r.right))});return o.slice(0,12).join('\n')}));
if(process.argv[4]) await p.screenshot({path:process.argv[4],fullPage:true});
await b.close();
