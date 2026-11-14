import { createRequire } from 'module';
// playwright and axe-core are the portal app's pinned dev dependencies (portal/app: npm ci).
const require = createRequire(new URL('../../../app/package.json', import.meta.url));
const { chromium } = require('playwright');
const [page,state,w,theme,out]=process.argv.slice(2);
const b = await chromium.launch({ executablePath:'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' });
const p = await b.newPage({viewport:{width:+w,height:900},colorScheme:theme});
await p.goto(new URL(`../${page}.html?theme=${theme}#${state}`, import.meta.url).href);
await p.waitForTimeout(150);
await p.screenshot({path:out,fullPage:process.env.FULL!=='0'});
await b.close();
