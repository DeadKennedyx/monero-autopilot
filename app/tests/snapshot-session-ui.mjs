// Real source App with synthetic, intercepted HTTP responses only. No server,
// native host, wallet profile, packaged asset, screenshot, or payment is used.
import {chromium,expect} from '@playwright/test';
import {fileURLToPath} from 'node:url';
import {build} from 'vite';

const project=fileURLToPath(new URL('../',import.meta.url));
const entry='/__snapshot-session-entry.js';
const bundle=await build({
 configFile:false,root:project,logLevel:'error',
 build:{write:false,minify:false,rollupOptions:{input:entry,output:{inlineDynamicImports:true}}},
 plugins:[{name:'snapshot-session-fixture',resolveId:id=>id===entry?entry:null,load:id=>id===entry?`
  import {createElement} from 'react';
  import {createRoot} from 'react-dom/client';
  import {MainnetApp} from '/src/App.tsx';
  createRoot(document.getElementById('root')).render(createElement(MainnetApp));
 `:null}],
});
const script=bundle.output.find(output=>output.type==='chunk'&&output.isEntry)?.code;
if(!script)throw Error('Source fixture did not produce an entry script');
const browser=await chromium.launch({channel:process.env.PLAYWRIGHT_CHANNEL||(process.platform==='win32'?'msedge':undefined),headless:true});
const origin='http://snapshot-session.fixture';
const epoch=Date.parse('2026-01-01T00:00:00Z');
const security=locked=>({configured:true,locked,idle_seconds:300,idle_remaining_seconds:locked?0:300,retry_after_seconds:0,error:null});

async function fixture(){
 const page=await browser.newPage();
 const held=[],requests=[],unexpected=[],errors=[];
 const mode={locked:'locked',unlocked:'hold'};
 let clock=epoch+1000,unlocks=0,preview=false;
 const snapshot=(kind='scanning')=>{
  const now=Math.floor(clock/1000);
  if(kind==='locked')return {network:'mainnet',phase:'Locked',wallet_status:'Locked',security:security(true),events:[]};
  return {
   network:'mainnet',security:security(false),phase:'Connected',busy:false,operation:'',error:null,last_issue:null,
   setup:{active:'fixture',wallets:[{id:'fixture',name:'Synthetic wallet',address:'4'+'a'.repeat(94),restore_height:0,backup_verified:true}]},
   node_height:1000,wallet_height:kind==='ready'?1000:990,wallet_pid:1234,wallet_status:kind==='ready'?'Synchronized':'Scanning',recoveries:0,
   bundled_tor:{state:'ready'},privacy:{operations_allowed:true,recovery:{state:'connected',last_action:'Fixture connected',generation:1},health:{height:1000,network:'mainnet',checked_at:now}},
   receive:{address:'4'+'a'.repeat(94),address_index:0,current:kind==='ready',balance:{confirmed_atomic:'1000000000',spendable_atomic:'1000000000',locked_atomic:'0',sampled_at:now,receipts:[]}},
   send:{blocked:false,error:null,payments:preview?[{id:'synthetic-preview',address:'4'+'b'.repeat(94),amount_atomic:'100000000',fee_atomic:'1000000',total_atomic:'101000000',txid:'c'.repeat(64),created_at:now,expires_at:now+600,status:'Preview',confirmations:0,checked_at:now}]:[]},events:[],
  };
 };
 await page.route('**/*',async route=>{
  const request=route.request(),url=new URL(request.url());
  if(url.origin!==origin){unexpected.push('external request');await route.abort();return;}
  if(url.pathname==='/'){await route.fulfill({contentType:'text/html',body:`<html><head><meta name="lab-token" content="synthetic-fixture"></head><body><div id="root"></div><script type="module" src="${entry}"></script></body></html>`});return;}
  if(url.pathname===entry){await route.fulfill({contentType:'text/javascript',body:script});return;}
  if(url.pathname==='/api/snapshot'){
   const authenticated=!!request.headers()['x-wallet-session'];
   const kind=mode[authenticated?'unlocked':'locked'];
   requests.push({authenticated,kind});
   if(kind==='hold'){held.push({route,authenticated});return;}
   if(kind==='failure'){await route.fulfill({status:503,json:{error:'Synthetic local host unavailable'}});return;}
   await route.fulfill({json:snapshot(kind)});return;
  }
  if(url.pathname==='/api/security'){
   const {action}=request.postDataJSON();
   if(action==='unlock'){await route.fulfill({json:{security:security(false),session:`synthetic-session-${++unlocks}`}});return;}
   if(action==='activity'){await route.fulfill({json:{security:security(false)}});return;}
  }
  unexpected.push(url.pathname);await route.fulfill({status:500,json:{error:'Unexpected fixture request'}});
 });
 page.on('pageerror',error=>errors.push(error.message));
 await page.clock.install({time:new Date(epoch)});
 await page.clock.pauseAt(new Date(clock));
 await page.goto(origin);
 await expect(page.getByRole('heading',{name:'Your wallet is locked.',exact:true})).toBeVisible();
 const advance=async milliseconds=>{clock+=milliseconds;await page.clock.fastForward(milliseconds);};
 const nextPoll=async()=>{
  const count=requests.length;await advance(1600);
  await expect.poll(()=>requests.length).toBeGreaterThan(count);
  // Let the fetch/JSON continuation commit before the next action, including
  // failures while the lock screen hides the connection indicator.
  await page.evaluate(()=>Promise.resolve());
  await advance(1);
 };
 const unlock=async()=>{
  await page.getByLabel('PIN',{exact:true}).fill('123456');
  await page.getByRole('button',{name:'Unlock wallet',exact:true}).click();
  await expect(page.getByTestId('security-screen')).toHaveCount(0);
  await expect.poll(()=>requests.some(request=>request.authenticated)).toBe(true);
 };
 const release=async(authenticated,kind='scanning')=>{
  const index=held.findIndex(request=>request.authenticated===authenticated);
  expect(index).toBeGreaterThanOrEqual(0);
  const [{route}]=held.splice(index,1);
  await route.fulfill(kind==='failure'?{status:503,json:{}}:{json:snapshot(kind)});
 };
 return {page,mode,requests,held,advance,nextPoll,unlock,release,preview:()=>{preview=true;},
  async close(){
   expect(unexpected).toEqual([]);expect(errors).toEqual([]);
   for(const {route} of held)await route.abort().catch(()=>{});
   await page.close();
  },
 };
}

try{
 // A failed poll during PIN verification belongs to the locked session. The
 // next session must start with a loader, without inheriting the offline flag.
 const first=await fixture();
 try{
  const {page}=first,progress=page.getByTestId('wallet-progress');
  first.mode.locked='failure';await first.nextPoll();await first.nextPoll();
  await first.unlock();
  await expect(progress).toHaveAttribute('data-stage','loading');
  await expect(page.getByText('App connection lost',{exact:true})).toHaveCount(0);
  await expect(page.locator('.balance')).toHaveCount(0);
  await page.getByRole('navigation').getByRole('button',{name:'Send',exact:true}).click();
  await expect(page.getByRole('heading',{name:'Choose a wallet first.',exact:true})).toBeVisible();
  await expect(page.getByTestId('confirm-send')).toHaveCount(0);
  first.mode.unlocked='scanning';await first.release(true);
  await page.getByRole('navigation').getByRole('button',{name:'Overview',exact:true}).click();
  await expect(progress).toHaveAttribute('data-stage','scanning');
  console.log('PASS: a locked-session failure cannot survive unlock; startup waits for its own snapshot with no balance or payment authorization.');

  // Establish readiness and fill only synthetic authorization controls. A
  // failure in this same session must disable them on the first failed poll.
  first.preview();first.mode.unlocked='ready';await first.nextPoll();
  await expect(progress).toContainText('Confirming your balance is up to date.');
  await first.advance(10000);await expect(progress).toHaveAttribute('data-stage','ready');
  await page.getByRole('navigation').getByRole('button',{name:'Send',exact:true}).click();
  await page.getByRole('checkbox').check();
  await page.getByLabel('PIN to authorize this payment',{exact:true}).fill('123456');
  await expect(page.getByTestId('confirm-send')).toBeEnabled();
  first.mode.unlocked='failure';await first.nextPoll();
  await expect(page.getByTestId('confirm-send')).toBeDisabled();
  await page.getByRole('navigation').getByRole('button',{name:'Overview',exact:true}).click();
  await expect(progress).toHaveAttribute('data-stage','offline');
  await expect(page.getByRole('button',{name:'Reload app',exact:true})).toBeVisible();
  first.mode.unlocked='ready';await first.nextPoll();
  await expect(progress).toHaveAttribute('data-stage','scanning');
  await expect(progress).toContainText('Confirming your balance is up to date.');
  console.log('PASS: the new session still fails closed immediately on its own failed poll, and fresh evidence restarts readiness settling.');
 }finally{await first.close();}

 // Resolve the locked-session request only after unlock and a fresh response.
 // Aborted old success and failure must neither relock nor mark the app offline.
 for(const lateResult of ['locked','failure']){
  const stale=await fixture();
  try{
   stale.mode.locked='hold';await stale.nextPoll();
   await stale.unlock();
   await expect(stale.page.getByTestId('wallet-progress')).toHaveAttribute('data-stage','loading');
   stale.mode.unlocked='scanning';await stale.release(true);
   await expect(stale.page.getByTestId('wallet-progress')).toHaveAttribute('data-stage','scanning');
   await stale.release(false,lateResult);await stale.advance(1);
   await expect(stale.page.getByTestId('security-screen')).toHaveCount(0);
   await expect(stale.page.getByTestId('wallet-progress')).toHaveAttribute('data-stage','scanning');
  }finally{await stale.close();}
 }
 console.log('PASS: aborted locked-session responses, including a late locked response and failure, cannot overwrite the unlocked session.');

 // Do not convert a genuinely unavailable host into a perpetual friendly
 // loader. Its first authenticated request keeps the six-second deadline.
 const unavailable=await fixture();
 try{
  await unavailable.unlock();
  await expect(unavailable.page.getByTestId('wallet-progress')).toHaveAttribute('data-stage','loading');
  await unavailable.advance(5999);
  await expect(unavailable.page.getByTestId('wallet-progress')).toHaveAttribute('data-stage','loading');
  await unavailable.advance(2);
  await expect(unavailable.page.getByTestId('wallet-progress')).toHaveAttribute('data-stage','offline');
  await expect(unavailable.page.getByRole('button',{name:'Reload app',exact:true})).toBeVisible();
  await expect(unavailable.page.getByTestId('confirm-send')).toHaveCount(0);
  console.log('PASS: a genuinely stalled first request times out at the unchanged deadline and exposes recovery without enabling payments.');
 }finally{await unavailable.close();}
}finally{await browser.close();}
