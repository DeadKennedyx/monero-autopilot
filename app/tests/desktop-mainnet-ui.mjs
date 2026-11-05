// Actual packaged desktop entrypoint, with isolated HTTP fixtures only.
// No native wallet, real PIN, live node, signing, or funds are accessed.
import {chromium,expect as baseExpect} from '@playwright/test';
import {createServer} from 'node:http';
import {readFileSync,writeFileSync,mkdirSync} from 'node:fs';
import {createHash} from 'node:crypto';
const expect=baseExpect.configure({timeout:15000});
const html=readFileSync('web/index.html','utf8').replaceAll('__LAB_TOKEN__','desktop-ui-fixture');
const screenshots='.runtime/tests/desktop/screenshots';mkdirSync(screenshots,{recursive:true});
let mode='normal',locked=false,reads=0,shutdown='reject',offline=false,changePinPayload=null;
const mutations=[],errors=[],external=[],results=[];
const security=()=>({configured:true,locked,idle_seconds:300,idle_remaining_seconds:300,retry_after_seconds:0,error:null});
const now=()=>Math.floor(Date.now()/1000);
const issue=()=>mode==='duplicate'?{code:'data_directory_in_use',message:'This wallet directory is already open in another AutoPilot window.',next_step:'Use the existing window, or close it before opening AutoPilot again.'}:{code:'network_mismatch',message:'This directory contains stagenet wallets and cannot be opened on mainnet.',next_step:'Choose a separate mainnet wallet directory. Your existing files were not changed.'};
const snapshot=()=>mode!=='normal'?{startup:issue()}:{network:'mainnet',security:security(),setup:{active:'fixture',wallets:[{id:'fixture',name:'Everyday wallet',address:'4'+'a'.repeat(94),restore_height:3799000,backup_verified:true}]},phase:'Connected',busy:false,operation:'',error:null,last_issue:null,wallet_pid:1234,node_height:3799300,wallet_height:3799300,wallet_status:'Synchronized',recoveries:0,bundled_tor:{state:'ready'},privacy:{operations_allowed:true,recovery:{state:'connected',generation:1,last_action:'Validated'},health:{network:'mainnet',height:3799300,checked_at:now()}},receive:{address:'4'+'a'.repeat(94),address_index:0,current:true,balance:{confirmed_atomic:'20000000000',spendable_atomic:'10000000000',locked_atomic:'10000000000',pending_atomic:null,blocks_to_unlock:3,sampled_at:now(),receipts:[]}},send:{payments:[],blocked:false,error:null},events:[]};
const server=createServer(async(req,res)=>{
 if(req.url==='/'){res.writeHead(200,{'Content-Type':'text/html'}).end(html);return;}
 res.setHeader('Content-Type','application/json');
 if(req.url==='/api/snapshot'){reads++;if(offline){res.writeHead(503).end('{}');return;}res.end(JSON.stringify(snapshot()));return;}
 let raw='';for await(const chunk of req)raw+=chunk;const body=JSON.parse(raw||'{}');mutations.push({path:req.url,action:body.action});
 if(req.url==='/api/security'){
  if(body.action==='change_pin'){changePinPayload=body;locked=true;}
  if(body.action==='unlock')locked=false;
  if(body.action==='lock')locked=true;
  res.end(JSON.stringify({security:security(),...(body.action==='unlock'?{session:'fixture-session'}:{})}));return;
 }
 if(req.url==='/api/shutdown'){if(shutdown==='reject'){res.writeHead(409).end('{"error":"Shutdown was not accepted. Please try again."}');return;}res.end('{"stopping":true}');return;}
 res.writeHead(404).end('{}');
});
await new Promise(r=>server.listen(0,'127.0.0.1',r));const url=`http://127.0.0.1:${server.address().port}/`;
const browser=await chromium.launch({channel:process.env.PLAYWRIGHT_CHANNEL||(process.platform==='win32'?'msedge':undefined),headless:true});
const report={passed:false,checkedAt:new Date().toISOString(),scope:'Packaged desktop UI with HTTP fixtures only; no real wallet, PIN, node, signing, or funds',htmlSha256:createHash('sha256').update(html).digest('hex'),results};
try{
 const page=await browser.newPage({viewport:{width:1360,height:1000},reducedMotion:'reduce'});page.on('pageerror',e=>errors.push(e.message));page.on('request',r=>{if(/^https?:/.test(r.url())&&!r.url().startsWith(url))external.push(r.url());});await page.goto(url);
 await expect(page.locator('meta[name="app-mode"]')).toHaveAttribute('content','desktop');await expect(page).toHaveTitle('Monero AutoPilot');await expect(page.getByTestId('wallet-progress')).toBeVisible();await expect(page.locator('body')).not.toContainText(/prototype|STAGENET|sXMR/);expect(await page.evaluate(()=>document.documentElement.dataset.autopilotMode||document.querySelector('style[data-autopilot-theme]')?.dataset.autopilotTheme)).toBe('mainnet');
 const nav=page.getByRole('navigation');for(const name of ['Overview','Receive','Send','Activity','Wallets','Connection','Settings'])await expect(nav.getByRole('button',{name,exact:true})).toBeVisible();results.push('The real desktop entrypoint mounts the mainnet product with seven navigation destinations and no prototype/stagenet labels.');
 await nav.getByRole('button',{name:'Settings',exact:true}).click();await expect(page.getByText('Version 0.9.0 · Mainnet')).toBeVisible();await page.getByRole('button',{name:'Change PIN',exact:true}).click();await page.getByLabel('Current PIN',{exact:true}).fill('074925');await page.getByLabel('New PIN',{exact:true}).fill('648219');await page.getByLabel('Confirm new PIN',{exact:true}).fill('648219');await page.getByRole('button',{name:'Save new PIN',exact:true}).click();await expect(page.getByRole('heading',{name:'Your wallet is locked.',exact:true})).toBeVisible();expect(changePinPayload).toEqual({action:'change_pin',current_pin:'074925',new_pin:'648219',confirm_pin:'648219'});await expect(page.getByLabel('Current PIN',{exact:true})).toHaveCount(0);await page.getByLabel('PIN',{exact:true}).fill('648219');await page.getByRole('button',{name:'Unlock wallet',exact:true}).click();await expect(nav).toBeVisible();results.push('Settings exposes the existing PIN-change flow; the mock change locks the UI and clears sensitive fields before unlock.');
 await nav.getByRole('button',{name:'Settings',exact:true}).click();await page.setViewportSize({width:390,height:844});expect(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth)).toBe(true);await page.screenshot({path:`${screenshots}/settings-mobile.png`,fullPage:true});
 await page.getByRole('button',{name:'Save & quit',exact:true}).first().click();await expect(page.getByRole('heading',{name:'Couldn’t close AutoPilot yet.',exact:true})).toBeVisible();await expect(page.getByRole('alert')).toContainText('Shutdown was not accepted');await expect(page.getByRole('heading',{name:'See you soon.',exact:true})).toHaveCount(0);shutdown='accept';await page.getByRole('button',{name:'Try closing again',exact:true}).click();await expect(page.getByTestId('app-closing')).toBeVisible();await page.waitForTimeout(2000);await expect(page.getByTestId('app-closing')).toBeVisible();offline=true;await expect(page.getByRole('heading',{name:'See you soon.',exact:true})).toBeVisible();results.push('Rejected shutdown is actionable; accepted shutdown shows saving until the host disappears, without claiming immediate completion.');
 for(const fatalMode of ['duplicate','wrong-network']){
  mode=fatalMode;offline=false;reads=0;mutations.length=0;await page.reload();await expect(page.getByTestId('startup-blocked')).toBeVisible();await expect(page.getByRole('alert')).toHaveText(issue().message);await expect(page.getByText(issue().next_step,{exact:true})).toBeVisible();await expect(page.getByTestId('security-screen')).toHaveCount(0);await expect(page.getByRole('button',{name:'Create PIN & continue',exact:true})).toHaveCount(0);await page.waitForTimeout(2000);expect(reads).toBe(1);expect(mutations).toEqual([]);await page.screenshot({path:`${screenshots}/startup-${fatalMode}-mobile.png`,fullPage:true});
 }
 results.push('Lease conflict and wrong-network startup payloads without security render explicit offline instructions and no PIN setup, retry loop, or wallet mutations.');
 await page.getByRole('button',{name:'Close AutoPilot',exact:true}).click();await expect(page.getByTestId('app-closing')).toBeVisible();offline=true;await expect(page.getByRole('heading',{name:'See you soon.',exact:true})).toBeVisible();expect(errors).toEqual([]);expect(external).toEqual([]);report.passed=true;report.browserErrors=errors;report.externalRequests=external;console.log('PASS Desktop mainnet integration: app, Settings/PIN, responsive layout, graceful quit, blocked startup.');
}catch(error){report.error=String(error);throw error;}finally{writeFileSync('.runtime/tests/desktop/ui-integration-validation.json',JSON.stringify(report,null,2));await browser.close();await new Promise(r=>server.close(r));}
