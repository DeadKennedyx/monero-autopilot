import {writeFileSync,existsSync} from 'node:fs';
import {join} from 'node:path';
import {randomUUID} from 'node:crypto';
import {readRun,readJson} from './files.mjs';
const [id,action,fee]=process.argv.slice(2),{root}=readRun(id);
if(action==='status'){
  console.log(JSON.stringify(readJson(join(root,'proxy-state.json')),null,2));
}else{
  if(!['read-only','overfee','drop-next'].includes(action))throw Error('Use status, read-only, overfee <atomic-per-weight>, or drop-next.');
  const feePerWeight=fee===undefined?undefined:Number(fee);
  if(action==='overfee'&&(!/^\d+$/.test(fee||'')||!Number.isSafeInteger(feePerWeight)||feePerWeight<1||feePerWeight>1_000_000_000))throw Error('Fee must be an integer from 1 through 1000000000 atomic units per weight.');
  const command={id:randomUUID(),action,...(action==='overfee'?{feePerWeight}:{})};
  writeFileSync(join(root,'command.json'),JSON.stringify(command),{flag:'wx'});
  const deadline=Date.now()+5000;
  let result;
  while(Date.now()<deadline){
    const path=join(root,'command-result.json');
    if(existsSync(path)){try{const value=readJson(path);if(value.id===command.id){result=value;break;}}catch{}}
    await new Promise(resolve=>setTimeout(resolve,100));
  }
  if(!result)throw Error('Command is pending. Start/check the proxy, then inspect status; do not queue another command.');
  console.log(JSON.stringify({outcome:result.outcome}));
  if(result.outcome!=='applied')process.exitCode=1;
}
