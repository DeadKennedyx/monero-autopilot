// Source component with synthetic HTTP responses only. No native host or wallet access.
// No packaged assets, screenshots, recovery phrases, or request bodies are written.
import {chromium,expect} from '@playwright/test';
import {fileURLToPath} from 'node:url';
import {build} from 'vite';

const project=fileURLToPath(new URL('../',import.meta.url));
const entry='/__wallet-setup-pending-entry.js';
const fixture=`
import {createElement} from 'react';
import {createRoot} from 'react-dom/client';
import {WalletSetup} from '/src/WalletSetup.tsx';
const root=createRoot(document.getElementById('root'));
const wallets=[
 {id:'one',name:'First fixture',address:null,restore_height:0,backup_verified:false},
 {id:'two',name:'Second fixture',address:null,restore_height:0,backup_verified:false}
];
window.renderFixture=(active='one')=>root.render(createElement(WalletSetup,{
 network:'mainnet',catalog:{active,wallets},busy:false,phase:'Connected',
 headers:{'Content-Type':'application/json'}
}));
window.renderFixture();
`;
// Bundle in memory and intercept every browser request; no listening server or files.
const bundle=await build({
 configFile:false,root:project,logLevel:'error',
 build:{write:false,minify:false,rollupOptions:{input:entry,output:{inlineDynamicImports:true}}},
 plugins:[{name:'wallet-setup-pending-fixture',resolveId:id=>id===entry?entry:null,load:id=>id===entry?fixture:null}],
});
const script=bundle.output.find(output=>output.type==='chunk'&&output.isEntry)?.code;
if(!script)throw Error('Source fixture did not produce an entry script');
const held=new Map(),actions=[],browserErrors=[],outsideRequests=[];
let browser;
try{
 const origin='http://wallet-setup.fixture';
 browser=await chromium.launch({channel:process.env.PLAYWRIGHT_CHANNEL||(process.platform==='win32'?'msedge':undefined),headless:true});
 const page=await browser.newPage();
 await page.route('**/*',async route=>{
  const url=new URL(route.request().url());
  if(url.origin!==origin){await route.abort();return;}
  if(url.pathname==='/'){await route.fulfill({contentType:'text/html',body:`<html><body><div id="root"></div><script type="module" src="${entry}"></script></body></html>`});return;}
  if(url.pathname===entry){await route.fulfill({contentType:'text/javascript',body:script});return;}
  if(url.pathname==='/api/wallet'){
   const {action}=route.request().postDataJSON();actions.push(action);
   if(action==='hide'){await route.fulfill({json:{}});return;}
   if(held.has(action)){await route.fulfill({status:409,json:{error:'Duplicate fixture request'}});return;}
   held.set(action,route);return;
  }
  await route.fulfill({status:404,body:''});
 });
 page.on('pageerror',error=>browserErrors.push(error.message));
 page.on('request',request=>{if(/^https?:/.test(request.url())&&!request.url().startsWith(origin+'/'))outsideRequests.push(request.url());});
 await page.clock.install({time:new Date('2026-01-01T00:00:00Z')});
 await page.clock.pauseAt(new Date('2026-01-01T00:00:01Z'));
 await page.goto(origin);
 const pending=page.getByTestId('wallet-operation'),slow=page.getByTestId('wallet-operation-wait');
 const release=async(action,value={},status=200)=>{
  await expect.poll(()=>held.has(action)).toBe(true);
  const response=held.get(action);held.delete(action);await response.fulfill({status,json:value});
  await expect(pending).toHaveCount(0);
 };

 await page.getByRole('button',{name:'Create wallet',exact:true}).click();
 await page.getByLabel('Wallet name',{exact:true}).fill('Synthetic create');
 await page.getByRole('button',{name:'Create wallet',exact:true}).click();
 await expect(pending).toHaveText('Creating your wallet. Preparing the connection can take a little while.');
 await expect(page.getByRole('button',{name:'Create wallet',exact:true})).toBeDisabled();
 await expect(slow).toHaveCount(0);
 await page.clock.fastForward(29000);await expect(slow).toHaveCount(0);
 await page.clock.fastForward(1000);await expect(slow).toHaveText('Still working. Keep this window open; you do not need to submit again.');
 // A catalog update can change the visible step while the same request is pending.
 await page.evaluate(()=>window.renderFixture('two'));
 await expect(pending).toContainText('Creating your wallet.');
 await release('create');
 await expect(page.getByRole('status')).toHaveText('Wallet created. Once connected, back it up before receiving funds.');

 await page.getByRole('button',{name:'Restore wallet',exact:true}).click();
 await page.getByLabel('Wallet name',{exact:true}).fill('Synthetic restore');
 await page.getByLabel('25-word English recovery phrase',{exact:true}).fill('invalid fixture input');
 await page.getByRole('button',{name:'Restore wallet',exact:true}).click();
 await expect(pending).toHaveText('Restoring your wallet. Preparing the connection and checking recovery details can take a little while.');
 await expect(slow).toHaveCount(0);
 await expect(page.getByLabel('25-word English recovery phrase',{exact:true})).toHaveValue('');
 await release('restore',{error:'Synthetic restore was refused.'},409);
 await expect(page.getByRole('alert')).toHaveText('Synthetic restore was refused.');
 await page.clock.fastForward(31000);await expect(slow).toHaveCount(0);
 await page.getByRole('button',{name:'Back to wallets',exact:true}).click();

 await page.getByRole('button',{name:'Open',exact:true}).click();
 await expect(pending).toHaveText('Opening your saved wallet. Connecting can take a little while.');
 await expect(slow).toHaveCount(0);await release('open');

 await page.getByRole('button',{name:'Back up wallet',exact:true}).click();
 await page.getByRole('checkbox').check();
 await page.getByRole('button',{name:'Reveal recovery phrase',exact:true}).click();
 await expect(pending).toHaveText('Preparing your recovery phrase. Keep this window private.');
 await expect(page.getByTestId('recovery-phrase')).toHaveCount(0);
 await release('reveal',{phrase:Array.from({length:25},(_,i)=>`fixture${i+1}`).join(' '),challenge:'synthetic',positions:[2,8,19],address:'synthetic',restore_height:0});
 await page.getByRole('button',{name:'I wrote it down — check my backup',exact:true}).click();
 await expect(page.getByTestId('recovery-phrase')).toHaveCount(0);
 for(const position of [2,8,19])await page.getByLabel(`Word ${position}`,{exact:true}).fill('synthetic');
 await page.getByRole('button',{name:'Verify backup',exact:true}).click();
 await expect(pending).toHaveText('Checking your backup words.');
 await release('verify');
 await expect(page.getByRole('status')).toHaveText('Backup words checked. Keep your written recovery phrase somewhere private.');
 await page.clock.fastForward(31000);await expect(slow).toHaveCount(0);
 expect(actions.filter(action=>action!=='hide')).toEqual(['create','restore','open','reveal','verify']);
 expect(browserErrors).toEqual([]);expect(outsideRequests).toEqual([]);
 console.log('PASS Wallet setup: five operation messages, 30-second reassurance, catalog-update stability, request disablement, completion/failure cleanup, and sensitive-field hiding.');
}finally{
 for(const response of held.values())await response.abort().catch(()=>{});
 if(browser)await browser.close();
}
