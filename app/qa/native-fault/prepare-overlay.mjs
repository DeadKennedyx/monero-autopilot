import {execFileSync} from 'node:child_process';
import {readFileSync,writeFileSync,mkdirSync,existsSync,symlinkSync} from 'node:fs';
import {resolve,join,dirname} from 'node:path';
import {createHash} from 'node:crypto';
import {appRoot,readRun,atomicJson,checkedEndpoint,ownedEndpoint,contained} from './files.mjs';

const {root}=readRun(process.argv[2]);
const local=process.argv[3]==='--local';
if(process.argv[3]&&!local)throw Error('Unknown overlay option.');
const endpoint=local?ownedEndpoint().href.replace(/\/$/,''):
  checkedEndpoint(`http://${readFileSync(join(root,'tor-service/hostname'),'utf8').trim()}:18089`).href.replace(/\/$/,'');
if(!local&&endpoint===ownedEndpoint().href.replace(/\/$/,''))throw Error('QA service must differ from the production owned endpoint.');
const destination=join(root,'source');
if(existsSync(destination))throw Error('Overlay already exists. Use a new run ID to preserve the reviewed snapshot.');
const repository=resolve(appRoot,'..');
const tracked=execFileSync('git',['-C',repository,'ls-files','-z','--','app'],{encoding:'utf8'}).split('\0').filter(Boolean);
const excluded=path=>/^app\/(?:qa|\.runtime|\.tools|node_modules|dist|web)\//.test(path)||/\/(?:target|gen|resources)\//.test(path);
const untracked=execFileSync('git',['-C',repository,'ls-files','--others','--exclude-standard','-z','--','app'],{encoding:'utf8'}).split('\0').filter(Boolean)
  .filter(path=>!excluded(path)&&!/^app\/crates\/[^/]+\/Cargo.lock$/.test(path));
if(untracked.length)throw Error('Untracked app source exists. Stage intended source files before preparing an overlay; no commit is required.');
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const files=new Map();
for(const path of tracked.filter(path=>!excluded(path))){
  if(!path.startsWith('app/')||path.includes('..')||!contained(repository,join(repository,path)))throw Error('Unexpected source path.');
  files.set(path,readFileSync(join(repository,path)));
}
files.set('LICENSE',readFileSync(join(repository,'LICENSE')));
const originalHashes=Object.fromEntries([...files].map(([path,bytes])=>[path,hash(bytes)]));
function replaceOne(path,pattern,replacement){
  const content=files.get(path)?.toString('utf8');
  if(content===undefined||[...content.matchAll(new RegExp(pattern.source,'g'))].length!==1)throw Error(`Expected one patch location: ${path}`);
  files.set(path,Buffer.from(content.replace(pattern,replacement)));
}
if(local){
  const path='app/crates/autopilot-privacy/src/transport.rs';
  replaceOne(path,/        let url = format!\(/,'        let qa_drop = qa_fault_before(path)?;\n        let url = format!(');
  replaceOne(path,/        Ok\(data\)/,'        qa_fault_after(qa_drop, &data)?;\n        Ok(data)');
  const template=readFileSync(join(appRoot,'qa/native-fault/local-fault.rs'),'utf8');
  files.set(path,Buffer.concat([files.get(path),Buffer.from('\n'+template.replace('__QA_ROOT__',root.replaceAll('\\','/')))]));
}else{
  replaceOne('app/crates/wallet-runtime/src/mainnet.rs',/pub const OWNED_NODE: &str\s*=\s*"[^"]+";/,`pub const OWNED_NODE: &str = "${endpoint}";`);
}
replaceOne('app/src-tauri/src/main.rs',/\.title\("Monero AutoPilot"\)/,'.title("MONERO AUTOPILOT — QA FAULT TEST — CONTROLLED WALLET ONLY")');
const configPath='app/src-tauri/tauri.conf.json';
const tauri=JSON.parse(files.get(configPath));
tauri.productName='Monero AutoPilot QA Fault Test';
tauri.identifier='com.moneroautopilot.qa.faulttest';
files.set(configPath,Buffer.from(JSON.stringify(tauri,null,2)+'\n'));
// Abort if another editor changed any input while the snapshot was being made.
for(const [path,expected] of Object.entries(originalHashes))if(hash(readFileSync(join(repository,path)))!==expected)throw Error('Source changed during snapshot. Wait for edits to finish and retry.');
for(const [path,bytes] of files){const output=join(destination,path);mkdirSync(dirname(output),{recursive:true});writeFileSync(output,bytes,{flag:'wx'});}
// Reuse only build dependencies and verified public runtimes, never .runtime or profiles.
for(const name of ['node_modules','.tools']){
  const source=join(appRoot,name);
  if(!existsSync(source))throw Error(`Prepare the production app's ${name} first. Overlay was left for inspection.`);
  symlinkSync(source,join(destination,'app',name),'junction');
}
const changed=[...files].filter(([path,bytes])=>hash(bytes)!==originalHashes[path]).map(([path,bytes])=>({path,original:originalHashes[path],overlay:hash(bytes)}));
if(changed.length!==3)throw Error('Unexpected overlay change count.');
atomicJson(join(root,'overlay.json'),{schema:1,sourceCommit:execFileSync('git',['-C',repository,'rev-parse','HEAD'],{encoding:'utf8'}).trim(),
  source:destination,createdAt:new Date().toISOString(),mode:local?'local-accepted-reply-loss':'tor-proxy',endpoint,files:files.size,changed,sourceHashes:originalHashes,
  overlayHashes:Object.fromEntries([...files].map(([path,bytes])=>[path,hash(bytes)]))});
console.log(JSON.stringify({outcome:'overlay_prepared_not_built',changed:changed.map(item=>item.path),files:files.size}));
