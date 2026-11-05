import type {WalletCatalog} from './WalletSetup';
import type {SecurityState} from './WalletSecurity';

export type Receipt={txid:string;address_index:number;amount_atomic:string;confirmations:number;timestamp:number;status:string};
export type FeePriority='automatic'|'economy';
export type Payment={id:string;address:string;amount_atomic:string;fee_atomic:string;total_atomic:string;txid:string;created_at:number;expires_at:number;status:string;confirmations:number;checked_at:number|null;self_transfer?:boolean;priority?:FeePriority};
export type Snapshot = {
  network:string; phase:string; busy:boolean; operation:string; error:string|null;
  last_issue:string|null; security:SecurityState; setup?:WalletCatalog;
  node_height:number|null; wallet_height:number|null; wallet_pid?:number|null;
  wallet_status:string; recoveries:number;
  receive?:{address:string|null;address_index?:number|null;current:boolean;error?:string|null;balance:{confirmed_atomic:string;spendable_atomic:string;locked_atomic?:string;pending_atomic?:string|null;blocks_to_unlock?:number;sampled_at:number;receipts?:Receipt[]}|null};
  send?:{payments:Payment[];blocked:boolean;error:string|null;rejected_fee?:{fee_atomic:string;maximum_fee_atomic:string}|null};
  bundled_tor?:{state:string;bootstrap_percent?:number};
  privacy?:{operations_allowed:boolean;recovery:{state:string;last_action:string;last_error?:string|null;generation?:number};health?:{height:number;network:string;checked_at?:number}|null};
  events:{seq:number;message:string}[];
};
export type Stage = 'loading'|'empty'|'tor'|'node'|'opening'|'scanning'|'ready'|'paused'|'attention'|'offline';
export type ConnectionView = {stage:Stage; title:string; description:string; working:boolean; step:number; canPause:boolean};
export function connectionView(s:Snapshot|null, offline:boolean, now:number, pausing=false):ConnectionView {
  const view=(stage:Stage,title:string,description:string,working=false,step=-1,canPause=false)=>({stage,title,description,working,step,canPause});
  if(offline)return view('offline','App connection lost','We’re trying to reach the app on this PC. If you closed it, reopen AutoPilot.');
  if(!s)return view('loading','Loading your wallet','Checking your saved wallet on this device.',true);
  const route=s.privacy?.recovery.state;
  if(pausing||s.phase==='Stopping')return view('paused','Pausing your connection','Saving your progress and closing the connection.');
  if(s.phase==='Needs attention'||route==='privacy_blocked'||s.bundled_tor?.state==='failed') {
    const walletProblem=s.phase==='Needs attention'&&route!=='privacy_blocked';
    return view('attention',walletProblem?'Your wallet needs attention':'Couldn’t connect yet',walletProblem?'Automatic retries have stopped. Review the connection details before trying again.':'Automatic retries have stopped. Check your internet connection, then try again.');
  }
  const active=!!s.setup?.active;
  const paused=route==='disconnected'&&!s.busy&&s.phase==='Stopped';
  if(paused&&active)return view('paused','Connection paused','Your wallet is saved. Resume whenever you’re ready.');
  const balance=s.receive?.balance;
  const recent=balance&&now/1000>=balance.sampled_at&&now/1000-balance.sampled_at<=15;
  // Snapshots can age while a later poll is pending. Match the backend's
  // independent node lease rather than extending it with fresh balance data.
  const checkedAt=s.privacy?.health?.checked_at;
  const nodeRecent=typeof checkedAt==='number'&&Number.isFinite(checkedAt)&&now/1000>=checkedAt&&now/1000-checkedAt<=60;
  const routeReady=route==='connected'&&!!s.privacy?.operations_allowed&&nodeRecent;
  if(active&&s.receive?.current&&recent&&routeReady) {
    return view('ready','Wallet ready','Your confirmed balance is up to date.',false,3,true);
  }
  if(!active&&!s.busy)return view('empty','Make yourself at home','Create a wallet or restore one from your backup to get started.');
  if(!routeReady) {
    const torReady=s.bundled_tor?.state==='ready';
    return view(torReady?'node':'tor','Getting your wallet ready',torReady?'Connecting privately to our node. Slow connections are retried automatically.':'Building your private connection with Tor. This can take a little while when you first open the app.',true,0,true);
  }
  if(!s.wallet_pid)return view('opening','Getting your wallet ready','Opening your saved wallet securely on this device.',true,1,true);
  return view('scanning','Getting your wallet ready','Checking the latest blocks for your payments and balance. Your saved progress is reused.',true,2,true);
}
