import {useEffect,useRef,useState} from 'react';
import {LockKeyhole,ShieldCheck,Power} from 'lucide-react';
import './security.css';
export type SecurityState={configured:boolean;locked:boolean;idle_seconds:number;idle_remaining_seconds:number;retry_after_seconds:number;error:string|null};
type SecurityBody={action:string;pin?:string;confirm_pin?:string;current_pin?:string;new_pin?:string};
export const validPin=(pin:string)=>/^\d{4,6}$/.test(pin);
export function useWalletSecurity(base:Record<string,string>,enabled:boolean){
 const [security,setSecurity]=useState<SecurityState|null>(null),[session,setSession]=useState(''),[error,setError]=useState(''),[pending,setPending]=useState(false);
 const sessionRef=useRef(''),lastInput=useRef(Date.now()),lastPost=useRef(0),revision=useRef(0);
 const headers=()=>({...base,...(sessionRef.current?{'x-wallet-session':sessionRef.current}:{})});
 function clearSession(){revision.current++;sessionRef.current='';setSession('');setSecurity(s=>s?{...s,locked:true}:s);}
 function acceptStatus(next?:SecurityState){
  if(!enabled)return;
  if(!next){clearSession();setSecurity({configured:true,locked:true,idle_seconds:300,idle_remaining_seconds:0,retry_after_seconds:0,error:'PIN protection is unavailable. Restart the app.'});return;}
  setSecurity(next);if(next.locked&&sessionRef.current)clearSession();
 }
 async function request(body:SecurityBody){
  setPending(true);setError('');const version=revision.current;
  try{const r=await fetch('/api/security',{method:'POST',headers:headers(),body:JSON.stringify(body),signal:AbortSignal.timeout(15000)});const result=await r.json();if(!r.ok)throw Error(result.error||'PIN request was refused.');if(version!==revision.current)return false;
   if(result.session){revision.current++;sessionRef.current=result.session;setSession(result.session);lastInput.current=Date.now();}
   acceptStatus(result.security);return true;
  }catch(e){setError(e instanceof Error&&e.name!=='TimeoutError'?e.message:'Connection interrupted. Check the lock screen before trying again.');return false;}finally{setPending(false);}
 }
 async function lock(){const h=headers();clearSession();setError('');try{await fetch('/api/security',{method:'POST',headers:h,body:JSON.stringify({action:'lock'}),signal:AbortSignal.timeout(5000)});}catch{/* The local view stays locked; the backend independently expires the session. */}}
 useEffect(()=>{
  if(!enabled)return;let trailing:ReturnType<typeof setTimeout>|undefined;
  const sendActivity=()=>{if(!sessionRef.current||document.hidden)return;lastPost.current=Date.now();void fetch('/api/security',{method:'POST',headers:headers(),body:JSON.stringify({action:'activity'}),signal:AbortSignal.timeout(5000)}).catch(()=>{});};
  const activity=(event:Event)=>{if(!event.isTrusted||!sessionRef.current||document.hidden)return;if(Date.now()-lastInput.current>=300000){void lock();return;}lastInput.current=Date.now();if(Date.now()-lastPost.current>=10000)sendActivity();clearTimeout(trailing);trailing=setTimeout(sendActivity,1000);};
  const visibility=()=>{if(Date.now()-lastInput.current>=300000&&sessionRef.current)void lock();};
  for(const event of ['pointerdown','pointermove','keydown','scroll'])window.addEventListener(event,activity,{passive:true});
  document.addEventListener('visibilitychange',visibility);
  const timer=setInterval(()=>{if(sessionRef.current&&Date.now()-lastInput.current>=300000)void lock();},1000);
  return()=>{clearInterval(timer);clearTimeout(trailing);for(const event of ['pointerdown','pointermove','keydown','scroll'])window.removeEventListener(event,activity);document.removeEventListener('visibilitychange',visibility);};
 },[enabled]);
 return {security,session,headers,acceptStatus,request,lock,error,pending,locked:enabled&&(!security||security.locked),revision,currentSession:()=>sessionRef.current};
}
export function PinInput({id,label,value,onChange,disabled=false}:{id:string;label:string;value:string;onChange:(s:string)=>void;disabled?:boolean}){
 return <div className="pin-field"><label htmlFor={id}>{label}</label><input id={id} type="password" inputMode="numeric" autoComplete="off" spellCheck={false} pattern="[0-9]{4,6}" minLength={4} maxLength={6} required value={value} onChange={e=>onChange(e.target.value.replace(/\D/g,''))} disabled={disabled} placeholder="4–6 digits"/></div>;
}
type Access=ReturnType<typeof useWalletSecurity>;
export function SecurityScreen({access,prototype,onQuit,network='stagenet',paymentsEnabled=true}:{access:Access;prototype:boolean;onQuit:()=>void;network?:'mainnet'|'stagenet';paymentsEnabled?:boolean}){
 const [pin,setPin]=useState(''),[confirm,setConfirm]=useState(''),[help,setHelp]=useState(false);
 const s=access.security,configure=!!s&&!s.configured;
 useEffect(()=>{const clear=()=>{setPin('');setConfirm('');};window.addEventListener('blur',clear);return()=>window.removeEventListener('blur',clear);},[]);
 useEffect(()=>{setPin('');setConfirm('');},[configure]);
 async function submit(){const entered=pin,repeated=confirm;setPin('');setConfirm('');await access.request(configure?{action:'configure',pin:entered,confirm_pin:repeated}:{action:'unlock',pin:entered});}
 return <div className="lock-screen"><div className="lock-brand"><span className="brand-icon"><LockKeyhole size={25}/></span><span>monero<strong>AutoPilot</strong></span></div><section className="card lock-card" data-testid="security-screen"><span className="test-pill">{network.toUpperCase()}{prototype?' · SECURITY PROTOTYPE':''}</span><div className="lock-symbol"><ShieldCheck size={32}/></div><p className="eyebrow">YOUR WALLET, UNDER YOUR CONTROL</p><h1>{!s?'Starting securely…':configure?'Choose your wallet PIN.':'Your wallet is locked.'}</h1><p className="security-intro">{!paymentsEnabled?'Use your own 4–6 digit PIN to unlock this separate mainnet prototype and protect recovery-phrase access. Six digits are recommended.':configure?'Use 4–6 digits to unlock AutoPilot and authorize each payment. Six digits are recommended.':'Enter your PIN to open your wallets. Each payment also needs your PIN before it is sent.'}</p>
 {prototype&&<div className="notice">Use a disposable test PIN here. The main app will ask you to choose its PIN separately.</div>}
 {(access.error||s?.error)&&<div className="alert" role="alert">{s?.error||access.error}</div>}
 {!!s?.retry_after_seconds&&<div className="notice" role="status">Try again in {s.retry_after_seconds} seconds.</div>}
 {s&&!s.error&&<form onSubmit={e=>{e.preventDefault();void submit();}}><PinInput id="unlock-pin" label={configure?'Choose PIN':'PIN'} value={pin} onChange={setPin} disabled={access.pending}/>{configure&&<PinInput id="confirm-pin" label="Confirm PIN" value={confirm} onChange={setConfirm} disabled={access.pending}/>}<button className="button wide" disabled={access.pending||!validPin(pin)||(configure&&!validPin(confirm))||s.retry_after_seconds>0}>{access.pending?'Checking…':configure?'Create PIN & continue':'Unlock wallet'}</button></form>}
 <div className="lock-policy"><LockKeyhole size={15}/><span>Locks after 5 minutes idle and on every restart.</span></div><p className="fine-print">Your PIN stays on this device. It does not replace your recovery phrase or Windows account security.</p><button className="text-button" onClick={()=>setHelp(!help)}>{configure?'About PIN recovery':'Forgot your PIN?'}</button>{help&&<p className="security-help">Keep your recovery phrase safe before relying on this PIN. There is no PIN-reset shortcut. Your phrase can restore the wallet in a separate installation; keep your current files and payment history.</p>}</section><button className="text-button lock-quit" onClick={onQuit}><Power size={16}/>Save & quit</button></div>;
}
export function SecuritySettings({access}:{access:Access}){
 const [editing,setEditing]=useState(false),[old,setOld]=useState(''),[pin,setPin]=useState(''),[confirm,setConfirm]=useState('');
 useEffect(()=>{const clear=()=>{setOld('');setPin('');setConfirm('');};window.addEventListener('blur',clear);return()=>window.removeEventListener('blur',clear);},[]);
 async function change(){const body={action:'change_pin',current_pin:old,new_pin:pin,confirm_pin:confirm};setOld('');setPin('');setConfirm('');await access.request(body);}
 return <section className="card security-settings"><div className="section-title"><h2>Wallet lock & payments</h2><LockKeyhole size={20}/></div><div className="setting-row"><div><strong>Automatic lock</strong><p>After 5 minutes without activity and whenever the app restarts.</p></div><span className="tag">On</span></div><div className="setting-row"><div><strong>Payment authorization</strong><p>Your PIN is required for each payment and recovery-phrase reveal.</p></div><span className="tag">Required</span></div><div className="setup-actions"><button className="button secondary" onClick={()=>void access.lock()}>Lock now</button><button className="button secondary" onClick={()=>{setEditing(!editing);setOld('');setPin('');setConfirm('');}}>Change PIN</button></div>{editing&&<form onSubmit={e=>{e.preventDefault();void change();}}>{access.error&&<div className="alert" role="alert">{access.error}</div>}<PinInput id="current-pin" label="Current PIN" value={old} onChange={setOld}/><PinInput id="new-pin" label="New PIN" value={pin} onChange={setPin}/><PinInput id="repeat-new-pin" label="Confirm new PIN" value={confirm} onChange={setConfirm}/><p className="field-note">Changing your PIN locks the app. Unlock again with your new PIN.</p><button className="button" disabled={access.pending||!validPin(old)||!validPin(pin)||!validPin(confirm)||!!access.security?.retry_after_seconds}>Save new PIN</button></form>}</section>;
}
