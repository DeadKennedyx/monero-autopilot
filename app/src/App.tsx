import {useEffect,useRef,useState} from 'react';

import {Activity,Check,ShieldCheck,Wallet,LockKeyhole,Power,RefreshCw,Pause,WifiOff,ArrowRight,ArrowUpRight,ArrowDownLeft,History,Settings} from 'lucide-react';
import {WalletSetup} from './WalletSetup';
import {SecurityScreen,SecuritySettings,useWalletSecurity} from './WalletSecurity';
import {amount} from './amount';
import {connectionView,type Snapshot,type ConnectionView} from './status';
import {ActivityPanel,BalanceDetails,ReceivePanel,SendPanel} from './Payments';
import {WalletBuddy} from './WalletBuddy';


const base={'Content-Type':'application/json','x-lab-token':document.querySelector<HTMLMetaElement>('meta[name="lab-token"]')?.content||''};
type Page='Wallets'|'Overview'|'Connection'|'Receive'|'Send'|'Activity'|'Settings';
type Action='connect'|'disconnect';
type StartupIssue={code:string;message:string;next_step:string};
function elapsedLabel(seconds:number){return seconds<60?`${seconds}s`:`${Math.floor(seconds/60)}m ${String(seconds%60).padStart(2,'0')}s`;}

function Progress({view,s,elapsed,pending,onAction,onWallets}:{view:ConnectionView;s:Snapshot|null;elapsed:number;pending:Action|null;onAction:(action:Action)=>void;onWallets:()=>void}) {
  const ready=view.stage==='ready',attention=view.stage==='attention',paused=view.stage==='paused';
  const long=view.working&&elapsed>=90;
  return <section className={`card wallet-progress ${ready?'is-ready':''} ${attention?'needs-attention':''}`} data-testid="wallet-progress" data-stage={view.stage} aria-labelledby="progress-title">
    <div className="progress-top" role={attention?'alert':undefined}>
      <div className={`progress-icon ${view.working?'is-working':''}`} aria-hidden="true">{ready?<Check/>:attention||view.stage==='offline'?<WifiOff/>:paused?<Pause/>:<ShieldCheck/>}</div>
      <div className="progress-copy"><h2 id="progress-title" aria-label={view.title}><span role="status" aria-live="polite">{view.title}</span></h2><p>{view.description}</p></div>
      {view.working&&view.stage!=='loading'&&<span className="elapsed" aria-label={`Connecting for ${elapsedLabel(elapsed)}`}>{elapsedLabel(elapsed)}</span>}
    </div>
    {view.working&&view.step>=0&&<ol className="connection-steps" aria-label="Wallet startup progress">{['Private connection','Open wallet','Check balance'].map((name,index)=><li key={name} className={index<view.step?'complete':index===view.step?'current':''} aria-current={index===view.step?'step':undefined}><span className="step-mark" aria-hidden="true">{index<view.step?<Check size={14}/>:index+1}</span><span>{name}<small>{index<view.step?'Done':index===view.step?'In progress':'Next'}</small></span></li>)}</ol>}
    {view.working&&view.step>=0&&<div className="progress-reassurance">{long&&<strong>This is taking longer than usual.</strong>}<p>{long?'Tor or the node may be slow. AutoPilot is still working automatically. No clicks needed.':'AutoPilot handles each step automatically. No clicks needed.'}</p><p className="progress-timing">A first connection can take several minutes. Later connections often take less time.</p></div>}
    {view.stage==='scanning'&&s?.wallet_height&&s.node_height&&s.wallet_height>1&&s.wallet_height<s.node_height?<p className="scan-progress">{(s.node_height-s.wallet_height).toLocaleString()} blocks left to check · progress is saved automatically</p>:null}
    <div className="progress-actions">
      {view.canPause&&<button className="button secondary small" disabled={!!pending||!!s?.busy} onClick={()=>onAction('disconnect')}><Pause size={15}/>Pause connection</button>}
      {paused&&!pending&&s?.phase!=='Stopping'&&<button className="button" onClick={()=>onAction('connect')} disabled={!!s?.busy}><ArrowRight size={16}/>Resume connection</button>}
      {attention&&<button className="button" disabled={!!pending||!!s?.busy} onClick={()=>onAction('connect')}><RefreshCw size={16}/>{pending?'Trying again…':'Try again'}</button>}
      {view.stage==='offline'&&<button className="button secondary" onClick={()=>window.location.reload()}><RefreshCw size={16}/>Reload app</button>}
      {view.stage==='empty'&&<button className="button" onClick={onWallets}>Set up wallet<ArrowRight size={16}/></button>}
      {pending==='disconnect'&&<span>Saving your progress…</span>}
    </div>
    {s&&<details className="connection-details"><summary>Connection details</summary><p>These details are for troubleshooting. You don’t need to manage the steps yourself.</p><dl><div><dt>Built-in Tor</dt><dd>{s.bundled_tor?.state||'Stopped'}{s.bundled_tor?.state==='starting'&&s.bundled_tor.bootstrap_percent!==undefined?` · ${s.bundled_tor.bootstrap_percent}%`:''}</dd></div><div><dt>Connection</dt><dd>{s.privacy?.recovery.state||'Not connected'}</dd></div><div><dt>Wallet</dt><dd>{s.wallet_status||'Not opened'}</dd></div><div><dt>Wallet height</dt><dd>{s.wallet_height?.toLocaleString()||'—'}</dd></div><div><dt>Node height</dt><dd>{s.node_height?.toLocaleString()||'—'}</dd></div></dl>{[...new Set([s.error,s.last_issue,s.receive?.error,s.privacy?.recovery.last_error].filter(Boolean))].map(message=><p key={message} className="diagnostic-note">{message}</p>)}{s.operation&&<p>{s.operation}</p>}<ul className="events">{s.events?.slice(-5).reverse().map(e=><li key={e.seq}>{e.message}</li>)}</ul></details>}
  </section>;
}

export function MainnetApp(){
  const access=useWalletSecurity(base,true);
  const [snapshot,setS]=useState<Snapshot|null>(null),[page,setPage]=useState<Page>('Overview');
  const [observedRevision,setObservedRevision]=useState<number|null>(null);
  const [offline,setOffline]=useState(false),[actionError,setActionError]=useState(''),[closed,setClosed]=useState(false),[pending,setPending]=useState<Action|null>(null);
  // Unlocking creates a new session. Neither a previous balance nor a failed
  // locked-session poll is evidence about it; await its own first observation.
  const sessionObserved=observedRevision===access.revision.current;
  const s=sessionObserved?snapshot:null;
  const [startupIssue,setStartupIssue]=useState<StartupIssue|null>(null),[closing,setClosing]=useState(false),[quitError,setQuitError]=useState('');
  const quitGuard=useRef(false),quitAccepted=useRef(false);
  const [,setClockTick]=useState(0),[startedAt,setStartedAt]=useState<number|null>(null);
  const [readiness,setReadiness]=useState<{key:string;since:number;settled:boolean}|null>(null);
  const chosenPage=useRef(false),pendingRef=useRef(false),progressWallet=useRef<string|null|undefined>(undefined);
  useEffect(()=>{const timer=setInterval(()=>setClockTick(t=>t+1),1000);return()=>clearInterval(timer);},[]);
  useEffect(()=>{
    if(closed)return;
    let active=true,blocked=false,timer:ReturnType<typeof setTimeout>|undefined;
    const controller=new AbortController();
    async function read(){
      const revision=access.revision.current;
      try{
        const r=await fetch('/api/snapshot',{headers:access.headers(),cache:'no-store',signal:AbortSignal.any([controller.signal,AbortSignal.timeout(6000)])});
        if(!r.ok)throw Error('Snapshot unavailable');
        const data:Snapshot&{startup?:StartupIssue}=await r.json();
        if(active&&revision===access.revision.current){
          setObservedRevision(revision);
          if(data.startup){setStartupIssue(data.startup);setS(null);setOffline(false);blocked=!closing;return;}
          access.acceptStatus(data.security);setS(data);setOffline(false);
          if(data.security&&!data.security.locked&&!chosenPage.current){setPage(data.setup?.active?'Overview':'Wallets');chosenPage.current=true;}
        }
      }catch{if(active&&revision===access.revision.current){if(quitAccepted.current)setClosed(true);else{setObservedRevision(revision);setOffline(true);}}}
      finally{if(active&&!blocked)timer=setTimeout(()=>void read(),1500);}
    }
    void read();return()=>{active=false;controller.abort();clearTimeout(timer);};
  },[access.session,closing,closed]);
  useEffect(()=>{if(access.locked){setS(null);setStartedAt(null);setActionError('');chosenPage.current=false;}},[access.locked]);
  const now=Date.now(),observed=connectionView(s,sessionObserved&&offline,now,pending==='disconnect');
  const readyKey=`${s?.setup?.active}:${s?.wallet_pid}:${s?.privacy?.recovery.generation}`;
  // Opening a cached wallet can briefly answer before its first background
  // refresh begins. Confirm continuous freshness across two refresh intervals
  // before presenting startup as finished; never turn an old sample current.
  useEffect(()=>{
    setReadiness(previous=>{
      if(access.locked||!['ready','scanning'].includes(observed.stage))return null;
      if(observed.stage!=='ready')return previous?.key===readyKey&&previous.settled?previous:null;
      if(previous?.key!==readyKey)return {key:readyKey,since:Date.now(),settled:false};
      if(!previous.settled&&now-previous.since>=10000)return {...previous,settled:true};
      return previous;
    });
  },[observed.stage,readyKey,now,access.locked]);
  const settled=readiness?.key===readyKey&&readiness.settled;
  const view:ConnectionView=observed.stage==='ready'&&!settled
    ?{...observed,stage:'scanning',title:'Getting your wallet ready',description:'Confirming your balance is up to date.',working:true,step:2}
    :observed.stage==='scanning'&&settled
      ?{...observed,title:'Updating your balance',description:'Your wallet is connected and checking for new payments. Your last balance stays visible below.',step:-1}
      :observed;
  useEffect(()=>{
    const changed=progressWallet.current!==s?.setup?.active;
    progressWallet.current=s?.setup?.active;
    if(view.working&&!access.locked)setStartedAt(t=>changed?Date.now():t??Date.now());
    else if(view.stage!=='offline')setStartedAt(null);
  },[view.working,view.stage,access.locked,s?.setup?.active]);
  async function connection(action:Action){
    if(pendingRef.current)return;
    if(action==='connect'&&!['paused','attention'].includes(view.stage))return;
    pendingRef.current=true;setPending(action);setActionError('');
    const revision=access.revision.current;
    try{
      const r=await fetch('/api/privacy',{method:'POST',headers:access.headers(),body:JSON.stringify({action}),signal:AbortSignal.timeout(180000)});
      const data=await r.json();
      if(!r.ok)throw Error(data.error||'Please wait for the current wallet operation to finish.');
      if(revision===access.revision.current){setS(old=>old?{...old,privacy:data.status}:old);if(action==='connect')setStartedAt(Date.now());}
    }catch(e){if(revision===access.revision.current)setActionError(e instanceof Error&&e.name!=='TimeoutError'?e.message:'The app has not confirmed this action yet. Check the connection status before trying again.');}
    finally{pendingRef.current=false;setPending(null);}
  }
  async function quit(){
    if(quitGuard.current)return;
    quitGuard.current=true;setQuitError('');setClosing(true);
    try{
      const response=await fetch('/api/shutdown',{method:'POST',headers:base,signal:AbortSignal.timeout(15000)});
      const data=await response.json();
      if(!response.ok||data.stopping!==true)throw Error(data.error||'The app did not confirm the shutdown request.');
      quitAccepted.current=true;
    }catch(e){quitGuard.current=false;setClosing(false);setQuitError(e instanceof Error&&e.name!=='TimeoutError'?e.message:'The shutdown request timed out. The app may still be running.');}
  }
  if(closed)return <main className="end"><Activity/><h1>See you soon.</h1><p>This window is disconnected from AutoPilot.</p><p>Open Monero AutoPilot to continue.</p></main>;
  if(closing)return <main className="end" data-testid="app-closing"><div className="progress-icon is-working" aria-hidden="true"><ShieldCheck/></div><h1 role="status">Saving your wallet and closing AutoPilot…</h1><p>Please leave the app open while it finishes. This can take a moment.</p></main>;
  if(quitError)return <main className="end"><h1>Couldn’t close AutoPilot yet.</h1><p role="alert">{quitError}</p><div className="wallet-actions"><button className="button" onClick={()=>void quit()}>Try closing again</button><button className="button secondary" onClick={()=>setQuitError('')}>Back to wallet</button></div></main>;
  if(startupIssue)return <main className="mainnet-startup"><div className="startup-logo"><Activity/><strong>Monero AutoPilot</strong><span className="test-pill">MAINNET</span></div><section className="card" data-testid="startup-blocked"><ShieldCheck size={32}/><p className="eyebrow">YOUR WALLET STAYS OFFLINE</p><h1>AutoPilot couldn’t open this wallet.</h1><p role="alert">{startupIssue.message}</p><p>{startupIssue.next_step}</p><button className="button" onClick={()=>void quit()}>Close AutoPilot</button></section></main>;
  if(access.locked)return <SecurityScreen access={access} prototype={false} onQuit={()=>void quit()} network="mainnet" paymentsEnabled/>;
  const current=s?.setup?.wallets.find(w=>w.id===s.setup?.active),ready=view.stage==='ready';
  const elapsed=startedAt===null?0:Math.max(0,Math.floor((now-startedAt)/1000));
  const go=(next:Page)=>{chosenPage.current=true;setPage(next);window.scrollTo({top:0});};
  const progress=<Progress view={view} s={s} elapsed={elapsed} pending={pending} onAction={action=>void connection(action)} onWallets={()=>go('Wallets')}/>;
  const pages:Page[]=['Overview','Receive','Send','Activity','Wallets','Connection','Settings'];
  const titles:Partial<Record<Page,string>>={Wallets:'Your mainnet wallets.',Connection:'A private connection.',Receive:'Receive Monero.',Send:'Send a payment.',Activity:'Your activity.',Settings:'App settings.'};
  const subtitles:Record<Page,string>={Wallets:'Create a wallet, check its backup, or restore one you already own.',Connection:'AutoPilot handles your connection and reconnects when needed.',Overview:'Your connection and balance, in one place.',Receive:'Share your address or QR code to receive Monero on mainnet.',Send:'Choose a recipient, review the exact fee, then authorize with your PIN.',Activity:'Payments received and payments you make with AutoPilot.',Settings:'Protect access to your wallet and authorize each payment.'};
  return <div className="mainnet-shell"><aside><a className="logo" href="#overview" onClick={e=>{e.preventDefault();go('Overview');}}><Activity/><span>monero<strong>AutoPilot</strong></span></a><p className="eyebrow">MONERO MAINNET</p><nav aria-label="Main navigation">{pages.map(item=><button key={item} aria-current={page===item?'page':undefined} onClick={()=>go(item)}>{item==='Wallets'?<Wallet size={19}/>:item==='Connection'?<ShieldCheck size={19}/>:item==='Send'?<ArrowUpRight size={19}/>:item==='Receive'?<ArrowDownLeft size={19}/>:item==='Activity'?<History size={19}/>:item==='Settings'?<Settings size={19}/>:<Activity size={19}/>} {item}</button>)}</nav><div className="aside-note"><ShieldCheck/><strong>Keys stay with you.</strong><p>Your mainnet wallets.<br/>Our node. Built-in Tor.</p></div></aside>
    <div className="content"><header><span className="test-pill">MONERO MAINNET</span><div><button className="button secondary small" onClick={()=>void access.lock()}><LockKeyhole size={16}/>Lock wallet</button><button className="text-button" onClick={()=>void quit()}><Power size={16}/>Save & quit</button><WalletBuddy/></div></header><main>
      <p className="eyebrow">YOUR PRIVATE WALLET</p><h1>{titles[page]||current?.name||'Welcome to AutoPilot.'}</h1><p className="subtitle">{subtitles[page]}</p>
      {actionError&&<div role="alert" className="alert">{actionError}</div>}
      {page==='Wallets'&&<WalletSetup network="mainnet" catalog={s?.setup} busy={!!s?.busy||!!pending} phase={s?.phase||'Stopped'} headers={access.headers()} requiresPin pinRetrySeconds={s?.security.retry_after_seconds}/>}
      {page==='Overview'&&<>{progress}{current&&<><section className="card balance-card-mainnet"><div className="balance-hero"><div className="section-title"><p className="eyebrow">CONFIRMED BALANCE</p><span className={`balance-state ${ready?'current':''}`}>{ready?'Up to date':s?.receive?.balance?'Last checked':'Checking balance'}</span></div><div className="balance">{s?.receive?.balance?amount(s.receive.balance.confirmed_atomic):'—'} <small>XMR</small></div>{s?.receive?.balance?<p className="field-note">{ready?'Checked':'Last checked'} {new Date(s.receive.balance.sampled_at*1000).toLocaleTimeString()}{ready?'':' · Waiting for an updated balance.'}</p>:<p className="field-note">Your balance appears once the wallet has finished checking.</p>}</div>{s&&<BalanceDetails snapshot={s} ready={ready}/>}<div className="wallet-actions"><button className="button" onClick={()=>go('Receive')}><ArrowDownLeft size={17}/>Receive Monero</button><button className="button secondary" onClick={()=>go('Send')}><ArrowUpRight size={17}/>Send a payment</button></div></section><section className="card"><div className="section-title"><h2>Your wallet</h2><Wallet size={20}/></div><p className="field-note">{current.backup_verified?'Backup words checked.':'Check your backup in the Wallets tab.'}</p><details className="address-details"><summary>Primary address</summary><p className="field-note">Use this to verify restoration. The Receive tab provides an address to share for payments.</p><code className="address">{current.address||'Your address appears after wallet creation.'}</code></details></section></>}</>}
      {current&&s&&<><div hidden={page!=='Receive'}><ReceivePanel key={`receive:${current.id}`} snapshot={s} ready={ready&&!pending} headers={access.headers()} now={now}/></div><div hidden={page!=='Send'}><SendPanel key={`send:${current.id}`} snapshot={s} ready={ready&&!pending} headers={access.headers()} now={now} active={page==='Send'}/></div>{page==='Activity'&&<ActivityPanel key={current.id} snapshot={s} ready={ready} headers={access.headers()} now={now}/>}</>}
      {!current&&['Receive','Send','Activity'].includes(page)&&<section className="card"><h2>Choose a wallet first.</h2><p className="field-note">Create or restore a wallet to receive, send, and see your activity.</p><button className="button" onClick={()=>go('Wallets')}>Set up wallet<ArrowRight size={16}/></button></section>}
      {page==='Connection'&&<>{progress}<section className="card owned-node"><ShieldCheck size={24}/><div><h2>AutoPilot owned node</h2><p>Helsinki · Monero mainnet · Restricted RPC over Tor</p><p className="field-note">Your wallet connects privately through the Tor runtime included with AutoPilot. If this route is unavailable, it waits and retries automatically.</p></div></section></>}
      {page==='Settings'&&<><SecuritySettings access={access}/><section className="card"><h2>Monero AutoPilot</h2><p className="field-note">Version 0.9.0 · Mainnet<br/>Your keys and wallet files stay on this device.</p><button className="button secondary" onClick={()=>void quit()}><Power size={16}/>Save & quit</button></section></>}
      <footer><LockKeyhole size={14}/>Locks after 5 minutes idle and on every restart. Wallet data stays on this PC.</footer>
    </main></div></div>;
}
