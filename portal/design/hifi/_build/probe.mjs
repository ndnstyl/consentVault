import { createRequire } from 'module';
const require = createRequire('/Users/oxfloors/brain/projects/ox-floors/training-classroom/package.json');
const { chromium } = require('playwright-core');
const b = await chromium.launch({ executablePath:'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' });
const p = await b.newPage({viewport:{width:375,height:900}});
await p.goto('file:///Users/oxfloors/debwe/portal/design/hifi/'+process.argv[2]+'.html#'+(process.argv[3]||''));
console.log(await p.evaluate(()=>{const o=[];document.querySelectorAll('body *').forEach(e=>{const r=e.getBoundingClientRect();if(r.right>376&&r.width>0&&getComputedStyle(e).position!=='fixed')o.push(e.tagName+'.'+e.className+' '+Math.round(r.right))});return o.slice(0,12).join('\n')}));
if(process.argv[4]) await p.screenshot({path:process.argv[4],fullPage:true});
await b.close();
