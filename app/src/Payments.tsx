import {useEffect,useRef,useState} from 'react';
import {ArrowDownLeft,ArrowUpRight,ArrowLeft,Check,Copy,LockKeyhole,Plus,RefreshCw,ShieldCheck,Wallet} from 'lucide-react';
import QRCode from 'qrcode';
import {PinInput,validPin} from './WalletSecurity';
import {amount} from './amount';
import type {FeePriority,Payment,Snapshot} from './status';

type Props={snapshot:Snapshot;ready:boolean;headers:Record<string,string>;now:number;active?:boolean};
const date=(timestamp:number)=>new Date(timestamp*1000).toLocaleString();
const short=(value:string)=>`${value.slice(0,12)}…${value.slice(-8)}`;
const paymentTitle=(payment:Payment)=>payment.status==='Confirmed'?'Payment confirmed':payment.status==='Pending'?'Payment submitted':payment.status;
// The native wallet validates network bytes and checksum before preparing.
// This inexpensive input check catches wrong-network pastes immediately.
function inputError(address:string,value:string){
 if(!/^[48][1-9A-HJ-NP-Za-km-z]{94}$/.test(address))return 'Enter a Monero mainnet standard address or subaddress (95 characters, beginning with 4 or 8).';
 if(!/^(0|[1-9][0-9]*)(\.[0-9]{1,12})?$/.test(value))return 'Enter a positive XMR amount with up to 12 decimal places.';
 const [whole,fraction='']=value.split('.'),atomic=BigInt(whole)*1_000_000_000_000n+BigInt(fraction.padEnd(12,'0'));
 if(atomic<=0n)return 'Enter an amount greater than zero.';
 if(atomic>10_000_000_000n)return 'The payment limit is 0.01 XMR.';
 return '';
}
function useCopy(scope?:string|null){
 const [copied,setCopied]=useState<{key:string;value:string}|null>(null),[error,setError]=useState('');
 const sequence=useRef(0),queue=useRef(Promise.resolve()),mounted=useRef(true);
 useEffect(()=>{mounted.current=true;return()=>{mounted.current=false;sequence.current++;};},[]);
 useEffect(()=>{sequence.current++;setCopied(null);setError('');},[scope]);
 async function copy(value:string,key:string){
  const request=++sequence.current;setCopied(null);setError('');
  // Serialize clipboard writes so a slow older request cannot overwrite a
  // newer address after its button has already reported success.
  const write=queue.current.then(async()=>{if(mounted.current)await navigator.clipboard.writeText(value);});
  queue.current=write.catch(()=>{});
  try{await write;if(mounted.current&&request===sequence.current)setCopied({key,value});}
  catch{if(mounted.current&&request===sequence.current)setError('Copy was unavailable. Select the full address or transaction ID to copy it manually.');}
 }
 return {isCopied:(key:string,value:string|null|undefined)=>copied?.key===key&&copied.value===value,error,copy};
}
export function BalanceDetails({snapshot,ready}:{snapshot:Snapshot;ready:boolean}){
 const b=snapshot.receive?.balance;
 const pendingPayment=snapshot.send?.payments.find(payment=>payment.status==='Pending');
 return <><dl className="balance-breakdown" aria-label="Balance details">
  <div><dt>Available to send</dt><dd data-testid="available-balance">{amount(b?.spendable_atomic)} <small>XMR</small></dd></div>
  <div><dt>Locked or unavailable</dt><dd data-testid="locked-balance">{amount(b?.locked_atomic)} <small>XMR</small></dd></div>
  {b?.pending_atomic!=null&&<div><dt>Incoming pending</dt><dd data-testid="pending-balance">{amount(b.pending_atomic)} XMR</dd></div>}
 </dl>{!!b?.blocks_to_unlock&&<p className="field-note unlock-note">Locked funds need about {b.blocks_to_unlock} more {b.blocks_to_unlock===1?'block':'blocks'} before they can be spent{ready?'.':' (last checked).'} The wait depends on new blocks arriving.</p>}
 {pendingPayment&&<div className="payment-wait" data-testid="pending-payment-notice" role="status"><strong>Payment submitted.</strong><p>Waiting for network confirmation. Funds used by this payment cannot be sent again yet; your balance will update as the wallet confirms it.</p>{pendingPayment.self_transfer&&<p>This is a transfer within your wallet; only the network fee leaves your wallet.</p>}</div>}
 <p className="field-note" data-testid={b?.pending_atomic==null?'pending-balance':undefined}>Incoming payments appear after confirmation.</p></>;
}
export function ReceivePanel({snapshot:s,ready,headers}:Props){
 const address=s.receive?.address,[qr,setQr]=useState(''),[pending,setPending]=useState(false),[error,setError]=useState('');
 const guard=useRef(false),previousAddress=useRef<string|null|undefined>(null),previousEvent=useRef(0),copy=useCopy(address);
 useEffect(()=>{let active=true;setQr('');if(address)void QRCode.toDataURL(`monero:${address}`,{width:240,margin:2,color:{dark:'#17181b',light:'#ffffff'}}).then(url=>{if(active)setQr(url);}).catch(()=>{if(active)setError('The QR code could not be drawn. You can still copy your receiving address.');});return()=>{active=false;};},[address]);
 useEffect(()=>{if(pending&&address!==previousAddress.current){setPending(false);guard.current=false;}},[address,pending]);
 useEffect(()=>{if(pending&&!s.busy){const issue=s.receive?.error||s.error;if(issue&&s.events?.some(e=>e.seq>previousEvent.current&&e.message===issue)){setError(issue);setPending(false);guard.current=false;}}},[s,pending]);
 async function newAddress(){
  if(guard.current||!ready||s.busy)return;guard.current=true;previousAddress.current=address;previousEvent.current=s.events?.at(-1)?.seq||0;setPending(true);setError('');
  try{const r=await fetch('/api/command',{method:'POST',headers,body:JSON.stringify({action:'new_address'}),signal:AbortSignal.timeout(15000)});const data=await r.json();if(!r.ok){guard.current=false;setPending(false);throw Error(data.error||'A new address could not be created.');}}
  catch(e){setError(e instanceof Error&&e.name!=='TimeoutError'?e.message:'Waiting to confirm the new address. Your existing addresses still work.');}
 }
 return <div className="receive-layout"><section className="card receive-main"><div className="section-title"><h2>Your receiving address</h2><span className="muted">Address {s.receive?.address_index??'—'}</span></div>
  {(error||copy.error)&&<div role="alert" className="alert">{error||copy.error}</div>}<div className="qr-area">{qr?<img src={qr} width={240} height={240} alt="Monero mainnet receiving address QR code" data-testid="receive-qr"/>:<div className="qr-placeholder"><Wallet size={36}/><span>Your address appears when the wallet opens.</span></div>}</div>
  <label>MONERO MAINNET ADDRESS</label><code className="address" data-testid="receive-address">{address||'Waiting for your saved address…'}</code><button className="button wide" disabled={!address} onClick={()=>void copy.copy(address!,'address')}>{copy.isCopied('address',address)?<Check size={17}/>:<Copy size={17}/>} {copy.isCopied('address',address)?'Address copied':'Copy address'}</button>
  <button className="text-button new-address" disabled={!ready||s.busy||pending} onClick={()=>void newAddress()}><Plus size={16}/>{pending?'Creating your address…':'Create a new receiving address'}</button>
 </section><section className="card helpful"><span className="icon-circle"><ArrowDownLeft size={22}/></span><h2>A fresh address. The same wallet.</h2><p>Share this address or QR code to receive Monero on mainnet. A new address helps keep separate payments separate.</p><ol><li>Payments appear here after a block confirms them.</li><li>Confirmed funds can remain locked for several blocks.</li><li>Unlocked funds become available to send.</li></ol><div className="soft-note"><ShieldCheck size={18}/><span>Previous receiving addresses continue to work. You never need to share your recovery words.</span></div></section></div>;
}
type Waiting={action:string;id?:string;baseline:Snapshot;since:number};
export function SendPanel({snapshot:s,ready,headers,now,active=true}:Props){
 const [address,setAddress]=useState(''),[value,setValue]=useState(''),[pin,setPin]=useState(''),[approved,setApproved]=useState(false),[error,setError]=useState('');
 const [priority,setPriority]=useState<FeePriority>('automatic');
 const [waiting,setWaiting]=useState<Waiting|null>(null),[uncertain,setUncertain]=useState(false);
 const [notice,setNotice]=useState(''),previousPreview=useRef<Payment|null>(null),noticeRef=useRef<HTMLParagraphElement>(null);
 const guard=useRef(false),alive=useRef(true);
 const errorRef=useRef<HTMLDivElement>(null),displayError=error||s.send?.error;
 useEffect(()=>{if(active&&displayError){errorRef.current?.focus({preventScroll:true});errorRef.current?.scrollIntoView?.({block:'nearest'});}},[active,displayError]);
 const payments=s.send?.payments||[],preview=payments.find(p=>p.status==='Preview'),latest=payments.find(p=>!['Preview','Cancelled'].includes(p.status));
 useEffect(()=>{
  const previous=previousPreview.current;
  if(previous&&!preview&&waiting?.action!=='cancel'&&now/1000>=previous.expires_at&&payments.some(p=>p.id===previous.id&&p.status==='Cancelled')){
   setAddress(previous.address);setValue(amount(previous.amount_atomic));setPriority(previous.priority||'automatic');
   setNotice('This preview expired. Nothing was sent. Review the payment again when you are ready.');
  }
  previousPreview.current=preview||null;
 },[preview,payments,now,waiting?.action]);
 useEffect(()=>{if(active&&notice){noticeRef.current?.focus({preventScroll:true});noticeRef.current?.scrollIntoView?.({block:'nearest'});}},[active,notice]);
 useEffect(()=>{alive.current=true;return()=>{alive.current=false;};},[]);
 useEffect(()=>{setPin('');setApproved(false);},[preview?.id]);
 useEffect(()=>{if(!active){setPin('');setApproved(false);}},[active]);
 useEffect(()=>{const clear=()=>{setPin('');setApproved(false);};window.addEventListener('blur',clear);return()=>window.removeEventListener('blur',clear);},[]);
 useEffect(()=>{
  if(!waiting||s===waiting.baseline||s.busy)return;
  const completed=waiting.action==='prepare'?!!preview&&preview.id!==waiting.baseline.send?.payments.find(p=>p.status==='Preview')?.id:waiting.action==='confirm'?payments.some(p=>p.id===waiting.id&&p.status!=='Preview'):waiting.action==='cancel'?!payments.some(p=>p.id===waiting.id&&p.status==='Preview'):true;
  const lastEvent=waiting.baseline.events?.at(-1)?.seq||0;
  const rejected=!!s.send?.error&&(s.send.error!==waiting.baseline.send?.error||s.events?.some(e=>e.seq>lastEvent&&e.message===s.send?.error));
  if(completed||rejected){setWaiting(null);guard.current=false;if(completed)setUncertain(false);}
 },[s,waiting,preview,payments]);
 async function send(body:{action:string;address?:string;amount?:string;id?:string;pin?:string;priority?:FeePriority}){
  if(guard.current||!ready||s.busy)return;
  if(body.action==='prepare'){setNotice('');const issue=inputError(body.address!,body.amount!);if(issue){setError(issue);return;}}
  guard.current=true;setError('');setWaiting({action:body.action,id:body.id,baseline:s,since:Date.now()});
  try{
   const r=await fetch('/api/send',{method:'POST',headers,body:JSON.stringify(body),signal:AbortSignal.timeout(15000)}),data=await r.json();
   if(!alive.current)return;
   if(!r.ok){guard.current=false;setWaiting(null);setError(data.error||'This action was not accepted. Check the payment details and try again.');}
  }catch{if(alive.current){setUncertain(true);setError('The app has not confirmed the result yet. We are checking the original payment. Do not create the same payment again.');}}
 }
 const busy=!!waiting||s.busy,expired=!!preview&&now/1000>=preview.expires_at;
 const invalidPreview=!!preview&&(!/^[0-9]+$/.test(preview.fee_atomic)||BigInt(preview.fee_atomic)>100_000_000n);
 return <div className="send-layout"><section className="card send-main">
  <div className="steps"><span className={!preview?'selected':''}>1 <b>Payment details</b></span><i/><span className={preview?'selected':''}>2 <b>Review & confirm</b></span></div>
  {(displayError||s.send?.rejected_fee)&&<div className="alert" role="alert" ref={errorRef} tabIndex={-1}>{displayError}{s.send?.rejected_fee&&<p data-testid="rejected-fee">Returned network fee: <strong>{amount(s.send.rejected_fee.fee_atomic)} XMR</strong>. Maximum allowed: <strong>{amount(s.send.rejected_fee.maximum_fee_atomic)} XMR</strong>. This attempt did not send a payment.</p>}</div>}
  {notice&&<p className="payment-wait" role="status" ref={noticeRef} tabIndex={-1} data-testid="preview-expiry-notice">{notice}</p>}
  {!ready&&!waiting&&<p className="payment-wait" role="status">Waiting for an up-to-date balance. AutoPilot will enable payments when your wallet is ready.</p>}
  {waiting&&<p className="payment-wait" role="status">{waiting.action==='confirm'?'Submitting your payment once. Checking its status…':waiting.action==='prepare'?'Checking your balance and preparing the exact fee…':waiting.action==='cancel'?'Discarding this preview…':'Checking the original payment…'}{now-waiting.since>=60000?' This is taking longer than usual. No clicks needed.':''}</p>}
  {preview?<><button className="text-button" disabled={busy||!ready||uncertain} onClick={()=>{setAddress(preview.address);setValue(amount(preview.amount_atomic));setPriority(preview.priority||'automatic');void send({action:'cancel',id:preview.id});}}><ArrowLeft size={15}/>Edit payment</button><h2>Review your payment</h2><p className="muted">{waiting?.action==='confirm'?'Your authorization was submitted. Wait for its result below.':'Nothing has been broadcast. Check the complete address below.'}</p>
   {preview.self_transfer&&<p className="payment-wait">Self-transfer · This address belongs to your wallet. Only the network fee leaves your wallet; selected funds will temporarily lock.</p>}
   <label>RECIPIENT</label><code className="address" data-testid="preview-address">{preview.address}</code>
   <div className="review-values"><div><span>Recipient receives</span><strong data-testid="preview-amount">{amount(preview.amount_atomic)} XMR</strong></div><div><span>Network fee</span><strong data-testid="preview-fee">{amount(preview.fee_atomic)} XMR</strong></div><div className="total"><span>{preview.self_transfer?'Transfer amount + fee':'Total from your wallet'}</span><strong data-testid="preview-total">{amount(preview.total_atomic)} XMR</strong></div></div>
   <p className="field-note" data-testid="preview-priority">Fee preference: {preview.priority==='economy'?'Economy · May take longer to confirm.':'Automatic.'} Choose Edit payment to change it and review a new fee.</p>
   {invalidPreview&&<div role="alert" className="alert">This fee exceeds the 0.0001 XMR safety limit. This payment cannot be confirmed.</div>}
   <label className="confirm-check"><input type="checkbox" checked={approved} disabled={busy||expired} onChange={e=>setApproved(e.target.checked)}/>I checked the recipient and amount.</label>
   <PinInput id="send-pin" label="PIN to authorize this payment" value={pin} onChange={setPin} disabled={busy||expired}/><p className="send-pin-note">{s.security.retry_after_seconds?`Try again in ${s.security.retry_after_seconds} seconds.`:'Your PIN authorizes only this recipient, amount, and fee.'}</p>
   <button className="button wide" data-testid="confirm-send" disabled={!ready||busy||uncertain||!approved||!validPin(pin)||expired||invalidPreview||!!s.security.retry_after_seconds} onClick={()=>{const entered=pin;setPin('');setApproved(false);void send({action:'confirm',id:preview.id,pin:entered});}}><ArrowUpRight size={18}/>Confirm & send {amount(preview.amount_atomic)} XMR</button>
   <p className="fine-print">{expired?'This preview expired. Choose Edit payment to prepare a new one.':`Preview expires in ${Math.max(0,preview.expires_at-Math.floor(now/1000))}s.`} Confirmed payments cannot be reversed.</p>
  </>:<form onSubmit={e=>{e.preventDefault();void send({action:'prepare',address:address.trim(),amount:value.trim(),priority});}}><h2>Where should it go?</h2><label htmlFor="recipient">Recipient address</label><textarea id="recipient" rows={3} autoComplete="off" spellCheck={false} placeholder="Paste a Monero mainnet address" value={address} onChange={e=>setAddress(e.target.value)} maxLength={110} disabled={busy}/><label htmlFor="amount">Amount</label><div className="amount-input"><input id="amount" type="text" inputMode="decimal" autoComplete="off" placeholder="0.00" value={value} onChange={e=>setValue(e.target.value)} maxLength={30} disabled={busy}/><span>XMR</span></div>
   <div className="available"><span>Available: {amount(s.receive?.balance?.spendable_atomic)} XMR</span><span>{ready?'Current balance':'Last checked balance'}</span></div><p className="field-note">Payment limit: 0.01 XMR. The exact network fee is shown next (maximum 0.0001 XMR).</p>
   <label htmlFor="fee-priority">Network fee preference</label><select id="fee-priority" value={priority} disabled={busy||!!s.send?.blocked||uncertain} onChange={e=>setPriority(e.target.value as FeePriority)}><option value="automatic">Automatic</option><option value="economy">Economy</option></select><p className="field-note">Economy requests a lower fee and may take longer to confirm. Both choices keep the same maximum fee. You review the exact fee before sending.</p>
   <button className="button wide" disabled={!ready||busy||uncertain||!address.trim()||!value||!!s.send?.blocked}>Review payment<ArrowUpRight size={17}/></button>
   {s.send?.blocked&&<p className="field-note">Your previous payment must be resolved before another can be prepared. Check its status below or in Activity.</p>}
  </form>}
 </section><div><section className="card helpful"><span className="icon-circle"><ShieldCheck size={23}/></span><h2>You confirm every payment.</h2><p>Review the address, amount, and exact network fee. Your PIN is required each time you send. Reconnecting never sends a new payment automatically.</p><div className="soft-note"><LockKeyhole size={18}/><span>Your keys and prepared payment stay on this device.</span></div></section>
  {latest&&<section className="card payment-status" aria-live="polite"><p className="eyebrow">LATEST PAYMENT</p><h2 data-testid="payment-status">{paymentTitle(latest)}</h2>{latest.self_transfer&&<p>Self-transfer · Only the network fee leaves your wallet.</p>}<strong className="status-amount">{amount(latest.amount_atomic)} <small>XMR</small></strong>{latest.status==='Confirmed'&&latest.checked_at===null&&<p className="payment-wait">Saved confirmation · Waiting for a fresh status check.</p>}<p>{['Checking outcome','Needs review'].includes(latest.status)?'The outcome is not yet confirmed. Do not send the same payment again.':`${latest.confirmations} confirmations · ${date(latest.created_at)}`}</p><code className="transaction-id">{latest.txid||'Transaction ID not available yet'}</code><button className="text-button" disabled={!ready||busy} onClick={()=>void send({action:'check'})}><RefreshCw size={15}/>Check status</button></section>}
 </div></div>;
}
export function ActivityPanel({snapshot:s}:Props){
 const [filter,setFilter]=useState('All'),copy=useCopy();
 const entries=[...(s.receive?.balance?.receipts||[]).map(r=>({key:`received:${r.txid}:${r.address_index}`,direction:'Received',title:'Received',status:r.status,atomic:r.amount_atomic,txid:r.txid,timestamp:r.timestamp,confirmations:r.confirmations,fee:null as string|null})),...(s.send?.payments||[]).filter(p=>!['Preview','Cancelled'].includes(p.status)).map(p=>({key:`sent:${p.id}`,direction:'Sent',title:p.self_transfer?'Self-transfer':'Sent',status:p.status==='Confirmed'&&p.checked_at===null?'Confirmed (last known)':p.status,atomic:p.amount_atomic,txid:p.txid,timestamp:p.created_at,confirmations:p.confirmations,fee:p.fee_atomic}))].sort((a,b)=>b.timestamp-a.timestamp).filter(t=>filter==='All'||t.direction===filter);
 return <section className="card payment-activity"><div className="section-title"><h2>Payment activity</h2><div className="tabs" aria-label="Filter activity">{['All','Received','Sent'].map(item=><button key={item} aria-pressed={filter===item} className={filter===item?'active':''} onClick={()=>setFilter(item)}>{item}</button>)}</div></div>{copy.error&&<p role="alert">{copy.error}</p>}
  {entries.length?entries.map(t=><article className="transaction" key={t.key} data-testid="activity-row"><span className={`transaction-icon ${t.direction==='Sent'?'out':''}`}>{t.direction==='Sent'?<ArrowUpRight size={18}/>:<ArrowDownLeft size={18}/>}</span><div className="tx-name"><strong>{t.title}</strong><span>{t.status} · {t.confirmations} confirmations</span><span>{date(t.timestamp)}</span>{t.title==='Self-transfer'&&<span>Net cost: {amount(t.fee)} XMR fee</span>}<details><summary>Transaction ID</summary><code className="transaction-id">{t.txid||'Not available yet'}</code>{t.txid&&<button className="text-button" onClick={()=>void copy.copy(t.txid,t.key)}><Copy size={12}/>{copy.isCopied(t.key,t.txid)?'Copied':'Copy transaction ID'}</button>}</details></div><div className="tx-value"><strong>{amount(t.atomic)} <small>XMR</small></strong><span>{t.txid?short(t.txid):'Awaiting transaction ID'}</span></div></article>):<div className="empty"><Wallet size={28}/><h3>No {filter==='All'?'payment':filter.toLowerCase()} activity yet.</h3><p>Incoming payments appear after confirmation.</p></div>}
  <p className="fine-print">Incoming payments and payments created in AutoPilot. Self-transfers may appear only once because Monero does not report a separate incoming payment to the same account.</p>
 </section>;
}
