import {useEffect,useRef,useState} from 'react';
import {ArrowLeft,Check,KeyRound,Plus,ShieldCheck,Wallet} from 'lucide-react';
import './setup.css';
import {PinInput,validPin} from './WalletSecurity';

export type WalletProfile={id:string;name:string;address:string|null;restore_height:number;backup_verified:boolean};
export type WalletCatalog={active:string|null;wallets:WalletProfile[]};
type Props={network?:'stagenet'|'mainnet';catalog?:WalletCatalog;busy:boolean;phase:string;headers:Record<string,string>;requiresPin?:boolean;pinRetrySeconds?:number};
type Backup={phrase:string;challenge:string;positions:number[];address:string;restore_height:number};
type WalletOperation='create'|'restore'|'open'|'reveal'|'verify';
const operationMessages:Record<WalletOperation,string>={
 create:'Creating your wallet. Preparing the connection can take a little while.',
 restore:'Restoring your wallet. Preparing the connection and checking recovery details can take a little while.',
 open:'Opening your saved wallet. Connecting can take a little while.',
 reveal:'Preparing your recovery phrase. Keep this window private.',
 verify:'Checking your backup words.',
};
export function WalletSetup({network='stagenet',catalog,busy,phase,headers,requiresPin=false,pinRetrySeconds=0}:Props){
 const [pin,setPin]=useState('');
 const [step,setStep]=useState<'overview'|'create'|'restore'|'backup'|'phrase'|'verify'>('overview');
 const [pendingOperation,setPendingOperation]=useState<WalletOperation|null>(null),[longWait,setLongWait]=useState(false),pending=pendingOperation!==null;
 const [error,setError]=useState(''),[message,setMessage]=useState(''),[name,setName]=useState(''),[seed,setSeed]=useState(''),[height,setHeight]=useState('0'),[expected,setExpected]=useState(''),[ack,setAck]=useState(false),[backup,setBackup]=useState<Backup|null>(null),[words,setWords]=useState(['','','']);
 const mounted=useRef(true),privacyEpoch=useRef(0),active=catalog?.wallets.find(w=>w.id===catalog.active),disabled=busy||pending;
 const clear=()=>{setPin('');setBackup(null);setSeed('');setWords(['','','']);setAck(false);};
 const invalidate=()=>{void fetch('/api/wallet',{method:'POST',headers,body:JSON.stringify({action:'hide'})}).catch(()=>{});};
 useEffect(()=>{mounted.current=true;return()=>{mounted.current=false;invalidate();};},[]);
 useEffect(()=>{clear();setStep('overview');setError('');},[catalog?.active]);
 useEffect(()=>{
   const hide=()=>{if(document.hidden){privacyEpoch.current++;clear();setStep('overview');invalidate();}};
   const blur=()=>{setPin('');privacyEpoch.current++;setBackup(null);setSeed('');setWords(['','','']);setStep(s=>s==='phrase'||s==='verify'?'overview':s);invalidate();};
   document.addEventListener('visibilitychange',hide);window.addEventListener('blur',blur);
   return()=>{document.removeEventListener('visibilitychange',hide);window.removeEventListener('blur',blur);};
 },[]);
 useEffect(()=>{if(step!=='phrase'&&step!=='verify')return;const timer=setTimeout(()=>{clear();setStep('overview');invalidate();setMessage('Recovery phrase hidden. Reveal it again when you are ready.');},step==='phrase'?60000:120000);return()=>clearTimeout(timer);},[step]);
 useEffect(()=>{if(!pendingOperation)return;const timer=setTimeout(()=>setLongWait(true),30000);return()=>clearTimeout(timer);},[pendingOperation]);
 async function request(body:{action:WalletOperation}&Record<string,unknown>){
   setPendingOperation(body.action);setLongWait(false);setError('');setMessage('');
   try{const r=await fetch('/api/wallet',{method:'POST',headers,body:JSON.stringify(body),signal:AbortSignal.timeout(180000)});const value=await r.json();if(!r.ok)throw Error(value.error||'Wallet operation was refused.');if(!mounted.current)return null;return value;}
   catch(e){if(mounted.current)setError(e instanceof Error&&e.name!=='TimeoutError'?e.message:'The operation may still be finishing. Check your wallet list before trying again.');return null;}
   finally{if(mounted.current)setPendingOperation(null);}
 }
 function go(next:typeof step){clear();invalidate();setError('');setMessage('');setName('');setExpected('');setHeight('0');setStep(next);}
 async function create(){const r=await request({action:'create',name,network});if(r){clear();setStep('overview');setMessage('Wallet created. Once connected, back it up before receiving funds.');}}
 async function restore(){const phrase=seed;setSeed('');const r=await request({action:'restore',name,network,seed:phrase,restore_height:Number(height),expected_address:expected.trim()});if(r){clear();setStep('overview');setMessage('Wallet restored. AutoPilot is scanning the blockchain for your funds.');}}
 async function reveal(){const epoch=privacyEpoch.current;const entered=pin;setPin('');const r=await request({action:'reveal',acknowledged:ack,...(requiresPin?{pin:entered}:{})});if(r&&epoch===privacyEpoch.current&&!document.hidden){setBackup(r);setStep('phrase');}else{invalidate();}}
 async function verify(){const r=await request({action:'verify',challenge:backup?.challenge,words});clear();setStep('overview');if(r)setMessage('Backup words checked. Keep your written recovery phrase somewhere private.');}
 return <section className="card wallet-setup" data-testid="wallet-setup">
  <div className="setup-heading"><span className="icon-circle"><ShieldCheck size={21}/></span><div><p className="eyebrow">YOUR WALLET, YOUR RECOVERY</p><h2>{step==='create'?'Create your wallet':step==='restore'?'Restore a wallet':step==='phrase'?'Write down these 25 words':step==='verify'?'Check your written backup':step==='backup'?'Back up your wallet':'Wallets & backup'}</h2></div></div>
  {error&&<div className="alert" role="alert">{error}</div>}{message&&<div className="notice" role="status">{message}</div>}
  {pendingOperation&&<div className="notice" role="status" data-testid="wallet-operation">{operationMessages[pendingOperation]}{longWait&&<p data-testid="wallet-operation-wait">Still working. Keep this window open; you do not need to submit again.</p>}</div>}
  {step!=='overview'&&<button className="text-button setup-back" disabled={pending} onClick={()=>go('overview')}><ArrowLeft size={15}/>Back to wallets</button>}
  {step==='overview'&&<>
   <p className="setup-intro">{active?'Your wallets stay on this computer. A recovery phrase lets you recover a wallet if you lose access to it.':'Create a wallet, or recover one you already own.'}</p>
   <div className="wallet-list">{catalog?.wallets.map(w=><div className="wallet-item" key={w.id}><Wallet size={19}/><div><strong>{w.name}</strong><span>{w.id===catalog.active?'Current wallet · ':''}{w.backup_verified?'Backup words checked':'Backup needs checking'}</span></div>{w.id===catalog.active?<span className="tag">Selected</span>:<button className="button secondary small" disabled={disabled} onClick={()=>request({action:'open',id:w.id})}>Open</button>}</div>)}</div>
   {active&&<div className="backup-callout"><div><strong>{active.backup_verified?'Your recovery phrase':'Protect your wallet'}</strong><p>{active.backup_verified?'Review your recovery phrase or check your written backup again.':'Write down the phrase, then confirm three words from your copy.'}</p></div><button className="button" disabled={disabled||phase!=='Connected'} onClick={()=>go('backup')}><KeyRound size={16}/>{active.backup_verified?'Review backup':'Back up wallet'}</button></div>}
   <div className="setup-actions"><button className="button secondary" disabled={disabled} onClick={()=>go('create')}><Plus size={16}/>Create wallet</button><button className="button secondary" disabled={disabled} onClick={()=>go('restore')}>Restore wallet</button></div>
   <p className="fine-print">Wallet files are protected for this Windows account. Your recovery phrase restores your funds; local labels and payment history are separate.</p>
  </>}
  {(step==='create'||step==='restore')&&<form onSubmit={e=>{e.preventDefault();void(step==='create'?create():restore());}}>
   <p className="setup-intro">{step==='create'?'Give your wallet a name. AutoPilot will create it and guide you through its backup.':'Enter a recovery phrase for the network shown above. Recovery creates a separate wallet and keeps your existing wallets.'}</p>
   <label htmlFor="wallet-name">Wallet name</label><input id="wallet-name" required maxLength={48} value={name} onChange={e=>setName(e.target.value)} placeholder="e.g. Everyday wallet" autoComplete="off"/>
   {step==='restore'&&<>
    <label htmlFor="recovery-seed">25-word English recovery phrase</label><textarea id="recovery-seed" required rows={4} value={seed} onChange={e=>setSeed(e.target.value)} autoComplete="off" autoCorrect="off" spellCheck={false} maxLength={600} placeholder="Enter your words in their original order"/>
    <div className="soft-note">Use a phrase for the network shown in the header. Recovery words do not identify their network.</div>
    <label htmlFor="restore-height">Restore height</label><input id="restore-height" type="number" min="0" max="999999999" step="1" required value={height} onChange={e=>setHeight(e.target.value)}/><p className="field-note">Use the height written with your backup. If unsure, leave 0 to scan everything. A height later than your first payment can hide older funds.</p>
    <label htmlFor="original-address">Original primary address (optional)</label><textarea id="original-address" rows={2} maxLength={95} value={expected} onChange={e=>setExpected(e.target.value)} spellCheck={false} placeholder="Use the primary address from your backup to check the recovered wallet"/>
   </>}
   <button className="button" disabled={disabled||!name.trim()||(step==='restore'&&!seed.trim())} type="submit">{step==='create'?'Create wallet':'Restore wallet'}</button>
  </form>}
  {step==='backup'&&<><p className="setup-intro">Anyone with these words can control the wallet. Write them on paper in order and keep the copy private.</p><ul className="backup-notes"><li>The phrase will be hidden after 60 seconds or when you leave this window.</li><li>Write down the network, restore height, and primary address shown with it.</li><li>AutoPilot will ask for three words to help you check your copy.</li></ul><label className="confirm-check"><input type="checkbox" checked={ack} onChange={e=>setAck(e.target.checked)}/>I am in a private place and understand that these words control my wallet.</label><>{requiresPin&&<><PinInput id="backup-pin" label="PIN to reveal recovery phrase" value={pin} onChange={setPin} disabled={disabled}/>{pinRetrySeconds>0&&<p className="field-note">Try again in {pinRetrySeconds} seconds.</p>}</>}<button className="button" disabled={disabled||!ack||(requiresPin&&(!validPin(pin)||pinRetrySeconds>0))} onClick={reveal}>Reveal recovery phrase</button></></>}
  {step==='phrase'&&backup&&<><p className="setup-intro">Keep the exact order. Do not share or photograph this screen.</p><ol className="phrase-grid" data-testid="recovery-phrase">{backup.phrase.split(/\s+/).map((word,i)=><li key={i}><span>{i+1}</span><b>{word}</b></li>)}</ol><div className="backup-details"><strong>Restore height: {backup.restore_height}</strong><label>Primary address</label><code className="address">{backup.address}</code></div><button className="button" disabled={pending} onClick={()=>{setBackup({...backup,phrase:''});setStep('verify');}}>I wrote it down — check my backup</button><p className="fine-print">This screen hides automatically after 60 seconds.</p></>}
  {step==='verify'&&backup&&<form onSubmit={e=>{e.preventDefault();void verify();}}><p className="setup-intro">Enter these three words from your written copy. Your phrase is now hidden.</p><div className="word-check">{backup.positions.map((position,i)=><div key={position}><label htmlFor={`backup-word-${i}`}>Word {position}</label><input id={`backup-word-${i}`} type="password" required autoComplete="off" spellCheck={false} value={words[i]} maxLength={40} onChange={e=>setWords(old=>old.map((w,n)=>i===n?e.target.value:w))}/></div>)}</div><button className="button" disabled={disabled||words.some(w=>!w.trim())}><Check size={17}/>Verify backup</button></form>}
 </section>;
}
