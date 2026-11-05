// Deterministic startup presentation checks. No native wallet, Tor, or remote
// node is launched; every balance, address, and failure below is a UI fixture.
import {chromium, expect as baseExpect} from '@playwright/test';
import {createServer} from 'node:http';
import {readFileSync, writeFileSync, mkdirSync} from 'node:fs';
import {createHash} from 'node:crypto';

const expect = baseExpect.configure({timeout:20000});
const reportRoot=process.env.MAINNET_UI_REPORT_DIR||'.runtime/tests/startup';
const screenshotRoot = `${reportRoot}/screenshots`;
mkdirSync(screenshotRoot,{recursive:true});
const html = readFileSync(process.env.MAINNET_UI_HTML||'web/index.html','utf8')
  .replaceAll('__LAB_TOKEN__','startup-ui-fixture');
const nodeHeight = 3_799_300;
const address = '4'+'a'.repeat(94);
let mode='tor', clockOffset=0, nodeObservationOffset=0, snapshotOffline=false, served=0, readyServed=0;
const requests=[], errors=[], external=[], results=[];
const now=()=>Math.floor((Date.now()+clockOffset)/1000);
const security=()=>({configured:true,locked:false,idle_seconds:300,idle_remaining_seconds:300,retry_after_seconds:0,error:null});
function snapshot(){
 const route=mode==='opening'||mode==='scanning'||mode==='ready';
 const stopped=mode==='paused'||mode==='attention';
 const hasBalance=['ready','scanning','paused','attention'].includes(mode);
 const state=mode==='tor'?'initializing_transport':mode==='node'?'recovering':mode==='paused'?'disconnected':mode==='attention'?'privacy_blocked':'connected';
 return {
  network:'mainnet',security:security(),
  setup:{active:mode==='empty'?null:'fixture',wallets:mode==='empty'?[]:[{id:'fixture',name:'Everyday wallet',address,restore_height:nodeHeight-100,backup_verified:true}]},
  phase:mode==='opening'?'Recovering':mode==='paused'||mode==='empty'?'Stopped':mode==='attention'?'Needs attention':route?'Connected':'Waiting to retry',
  busy:mode==='opening',operation:mode==='opening'?'Recovery attempt 1 of 3':'',
  error:mode==='node'||mode==='attention'?'The private connection did not respond in time.':null,
  last_issue:mode==='scanning'?'Local RPC operation exceeded its deadline.':null,
  node_pid:null,wallet_pid:mode==='ready'||mode==='scanning'?1234:null,
  node_height:route?nodeHeight:null,node_target:route?nodeHeight:null,node_synced:route,
  wallet_height:mode==='ready'?nodeHeight:mode==='scanning'?nodeHeight-20:null,
  wallet_status:mode==='ready'?'Synchronized':mode==='scanning'?'Wallet RPC busy; waiting':stopped?'Stopped':'Waiting for a permitted connection',
  wallet_id:'fixture',wallet_sample_at:route?now():null,node_sample_at:route?now():null,
  recoveries:0,attempts:mode==='node'?2:1,retry_in_ms:mode==='node'?1000:null,
  bundled_tor:{state:mode==='tor'?'starting':stopped?'stopped':'ready',bootstrap_percent:mode==='tor'?35:100,starts:1,pid:stopped?null:4321,error:null},
  privacy:{profile:'balanced',transport:route?'ready':'checking',route:route?'tor_onion':null,operations_allowed:route,
   recovery:{state,attempts:mode==='node'?2:0,last_error:mode==='node'?'timeout':mode==='attention'?'recovery_exhausted':null,generation:1,last_action:mode==='node'?'Retrying only permitted routes':'Approved connection validated'},
   health:route?{height:nodeHeight,target_height:nodeHeight,network:'mainnet',checked_at:now()+nodeObservationOffset,synchronized:true,latency_ms:2400}:null},
  receive:{address,current:mode==='ready',error:mode==='scanning'?'Local RPC operation exceeded its deadline.':null,
   balance:hasBalance?{confirmed_atomic:'1234567890123',spendable_atomic:'0',sampled_at:now()-(mode==='ready'?0:90),wallet_height:mode==='ready'?nodeHeight:nodeHeight-20}:null},
  events:[{seq:1,time:now(),message:'Fixture: Local RPC operation exceeded its deadline.'}],
 };
}
const server=createServer(async(req,res)=>{
 if(req.url==='/'){res.writeHead(200,{'Content-Type':'text/html'}).end(html);return;}
 res.setHeader('Content-Type','application/json');
 if(req.url==='/api/snapshot'){
  served++;
  if(snapshotOffline){res.writeHead(503).end('{}');return;}
  if(mode==='ready')readyServed++;
  res.end(JSON.stringify(snapshot()));return;
 }
 let bytes='';for await(const chunk of req)bytes+=chunk;
 let body;try{body=JSON.parse(bytes||'{}');}catch{res.writeHead(400).end('{}');return;}
 if(req.url==='/api/privacy'){
  requests.push(body.action);
  if(body.action==='disconnect')mode='paused';
  if(body.action==='connect')mode='node';
  res.end(JSON.stringify({status:snapshot().privacy}));return;
 }
 if(req.url==='/api/security'){res.end(JSON.stringify({security:security()}));return;}
 res.end('{}');
});
await new Promise(r=>server.listen(0,'127.0.0.1',r));
const url=`http://127.0.0.1:${server.address().port}/`;
const browser=await chromium.launch({channel:process.env.PLAYWRIGHT_CHANNEL||(process.platform==='win32'?'msedge':undefined),headless:true});
const report={passed:false,checkedAt:new Date().toISOString(),scope:'UI fixture only; no native wallet, Tor, remote node, real funds, or payment',htmlSha256:createHash('sha256').update(html).digest('hex'),results};
try{
 const page=await browser.newPage({viewport:{width:1360,height:980},reducedMotion:'reduce'});
 page.on('pageerror',e=>errors.push(e.message));
 page.on('request',r=>{if(/^https?:/.test(r.url())&&!r.url().startsWith(url))external.push(r.url());});
 await page.addInitScript(()=>{const realNow=Date.now.bind(Date);window.__startupClockOffset=0;Date.now=()=>realNow()+window.__startupClockOffset;});
 await page.goto(url);
 const progress=page.getByTestId('wallet-progress');
 const nav=page.getByRole('navigation');
 const detail=page.locator('details').filter({has:page.locator('summary').filter({hasText:'Connection details'})});
 const stage=async value=>{mode=value;await expect(progress).toHaveAttribute('data-stage',value);};
 const noConnect=async()=>{for(const button of await page.getByRole('button',{name:'Connect',exact:true}).all())await expect(button).toBeDisabled();};
 await expect(nav.getByRole('button',{name:'Overview',exact:true})).toHaveAttribute('aria-current','page');
 await expect(progress).toHaveAttribute('data-stage','tor');
 await expect(progress.getByRole('status').filter({hasText:'Getting your wallet ready'})).toBeVisible();
 for(const label of ['Private connection','Open wallet','Check balance'])await expect(progress.getByRole('listitem').filter({hasText:label})).toBeVisible();
 await noConnect();
 await expect(page.getByRole('button',{name:'Pause connection',exact:true})).toBeVisible();
 await expect(detail).not.toHaveAttribute('open','');
 expect(await progress.locator('*').evaluateAll(elements=>elements.every(el=>getComputedStyle(el).animationName==='none'))).toBe(true);
 expect(await progress.locator('.progress-icon').evaluate(el=>getComputedStyle(el,'::after').animationName)).toBe('none');
 await page.screenshot({path:`${screenshotRoot}/startup-tor-desktop.png`,fullPage:true});
 results.push('Saved wallet opens on Overview with a three-stage progress view; reduced motion stops animations');

 await stage('node');
 await expect(progress.getByRole('status').filter({hasText:'Getting your wallet ready'})).toBeVisible();
 await expect(page.getByText('The private connection did not respond in time.',{exact:true})).not.toBeVisible();
 await expect(page.getByRole('alert')).toHaveCount(0);
 await noConnect();
 await detail.locator('summary').click();
 await expect(detail).toContainText('The private connection did not respond in time.');
 await detail.locator('summary').click();
 results.push('Retryable timeouts stay in collapsed diagnostics, without red alerts or a restart-inducing Connect button');

 clockOffset=120_000;
 await page.evaluate(offset=>{window.__startupClockOffset=offset;},clockOffset);
 await expect(progress.getByText('This is taking longer than usual.',{exact:true})).toBeVisible();
 await expect(progress).toContainText(/no (extra )?clicks needed|nothing you need to click|no need to click|you don.t need to click/i);
 await nav.getByRole('button',{name:'Connection',exact:true}).click();
 await expect(progress.getByText('This is taking longer than usual.',{exact:true})).toBeVisible();
 await nav.getByRole('button',{name:'Overview',exact:true}).click();
 await expect(progress.getByText('This is taking longer than usual.',{exact:true})).toBeVisible();
 results.push('A long connection attempt remains explicit and elapsed progress survives navigation');

 await stage('opening');
 await expect(progress.getByRole('status').filter({hasText:'Getting your wallet ready'})).toBeVisible();
 await expect(page.getByText('Recovery attempt 1 of 3',{exact:true})).not.toBeVisible();
 await stage('scanning');
 await expect(progress.getByRole('status').filter({hasText:'Getting your wallet ready'})).toBeVisible();
 await expect(page.getByText('Wallet RPC busy; waiting',{exact:true})).not.toBeVisible();
 await expect(page.getByText('Local RPC operation exceeded its deadline.',{exact:true})).not.toBeVisible();
 await expect(page.locator('.balance')).toContainText('1.234567890123');
 await expect(page.getByText(/Last checked .*Waiting for an updated balance/)).toBeVisible();
 await page.setViewportSize({width:390,height:844});
 await page.screenshot({path:`${screenshotRoot}/startup-scanning-mobile.png`,fullPage:true});
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+2)).toBe(true);
 results.push('Opening and scanning use calm progress; a cached balance stays visible and is labeled as last checked');

 // A cached wallet can report current briefly, then start its first network
 // refresh. That early sample must not make the startup UI flash Wallet ready.
 await page.evaluate(()=>{
  window.__earlyReadySeen=false;
  window.__readyObserver=new MutationObserver(()=>{
   if(document.querySelector('[data-testid="wallet-progress"] [role="status"]')?.textContent==='Wallet ready')window.__earlyReadySeen=true;
  });
  window.__readyObserver.observe(document.body,{subtree:true,childList:true,characterData:true});
 });
 const beforeBurst=readyServed;
 mode='ready';
 await expect.poll(()=>readyServed>beforeBurst).toBe(true);
 await expect(progress).toHaveAttribute('data-stage','scanning');
 await page.waitForTimeout(3000);
 await expect(progress).toHaveAttribute('data-stage','scanning');
 expect(await page.evaluate(()=>window.__earlyReadySeen)).toBe(false);
 mode='scanning';
 await expect(progress).toContainText('Checking the latest blocks');
 expect(await page.evaluate(()=>window.__earlyReadySeen)).toBe(false);
 await page.evaluate(()=>window.__readyObserver.disconnect());
 const sustainedStarted=Date.now();
 await stage('ready');
 expect(Date.now()-sustainedStarted).toBeGreaterThanOrEqual(9500);
 results.push('A three-second early current-balance burst never shows Wallet ready; readiness requires ten continuous current seconds after the busy refresh');
 await expect(progress).toContainText('Wallet ready');
 await expect(page.getByText('CONFIRMED BALANCE',{exact:true})).toBeVisible();
 await expect(page.locator('.balance')).toContainText('1.234567890123');
 await noConnect();
 await expect(progress.getByText('This is taking longer than usual.',{exact:true})).toHaveCount(0);
 await page.setViewportSize({width:1360,height:980});
 await page.screenshot({path:`${screenshotRoot}/startup-ready-desktop.png`,fullPage:true});
 results.push('Successful synchronization ends the loader and keeps the confirmed balance visible');

 // A fresh balance must not extend the node's separate health observation.
 // Keep backend flags/current=true to prove that the UI expires its own copy.
 for(const offset of [-61,5]){
  nodeObservationOffset=offset;
  await expect(progress).toHaveAttribute('data-stage','node');
  await expect(progress.getByText('Wallet ready',{exact:true})).toHaveCount(0);
  await expect(page.getByText(/Last checked .*Waiting for an updated balance/)).toBeVisible();
  nodeObservationOffset=0;
  const freshNodeStarted=Date.now();
  await expect(progress).toHaveAttribute('data-stage','scanning');
  await expect(progress).toContainText('Confirming your balance is up to date.');
  await expect(progress).toHaveAttribute('data-stage','ready');
  expect(Date.now()-freshNodeStarted).toBeGreaterThanOrEqual(9500);
 }
 results.push('Expired and future node observations immediately remove Ready despite fresh balances, and each recovery requires a new settling interval');

 await page.getByRole('button',{name:'Pause connection',exact:true}).click();
 await expect(progress).toHaveAttribute('data-stage','paused');
 expect(requests.at(-1)).toBe('disconnect');
 await expect(page.getByRole('button',{name:'Resume connection',exact:true})).toBeEnabled();
 await page.getByRole('button',{name:'Resume connection',exact:true}).click();
 await expect(progress).toHaveAttribute('data-stage','node');
 expect(requests.at(-1)).toBe('connect');
 await expect(progress.getByText('This is taking longer than usual.',{exact:true})).toHaveCount(0);
 results.push('Pause and Resume have distinct controls; resuming starts a fresh elapsed attempt');

 await stage('attention');
 await expect(page.getByRole('button',{name:'Try again',exact:true})).toBeEnabled();
 await expect(page.getByRole('alert')).toBeVisible();
 await page.setViewportSize({width:390,height:844});
 await page.screenshot({path:`${screenshotRoot}/startup-attention-mobile.png`,fullPage:true});
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+2)).toBe(true);
 await page.getByRole('button',{name:'Try again',exact:true}).click();
 await expect(progress).toHaveAttribute('data-stage','node');
 expect(requests.at(-1)).toBe('connect');
 results.push('An exhausted attempt is actionable with a visible explanation and explicit retry');

 await stage('ready');
 snapshotOffline=true;
 await expect(progress).toHaveAttribute('data-stage','offline');
 await expect(progress.getByText('Wallet ready',{exact:true})).toHaveCount(0);
 await expect(page.locator('.balance')).toContainText('1.234567890123');
 await expect(page.getByText(/Last checked .*Waiting for an updated balance/)).toBeVisible();
 snapshotOffline=false;
 await expect(progress).toHaveAttribute('data-stage','ready');
 results.push('A failed local snapshot cannot retain Wallet ready; reconnecting restores the current presentation');

 expect(errors).toEqual([]);expect(external).toEqual([]);
 report.passed=true;report.snapshotReads=served;report.privacyActions=requests;report.browserErrors=errors;report.externalRequests=external.length;
 console.log(JSON.stringify(report,null,2));
}catch(error){report.error=error.message;report.browserErrors=errors;report.externalRequests=external.length;throw error;}
finally{
 report.finishedAt=new Date().toISOString();
 writeFileSync(reportRoot+'/startup-ui-validation.json',JSON.stringify(report,null,2));
 await browser.close();server.closeAllConnections();await new Promise(r=>server.close(r));
}
