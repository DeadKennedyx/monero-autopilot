import {readFileSync,writeFileSync,openSync,fsyncSync,closeSync,renameSync,mkdirSync,existsSync} from 'node:fs';
import {resolve,join,relative,isAbsolute} from 'node:path';
export const appRoot=resolve(import.meta.dirname,'../..');
export function runPath(id){
  if(typeof id!=='string'||!/^[a-z0-9][a-z0-9_-]{0,39}$/.test(id))throw Error('Use a run ID of 1–40 lowercase letters, digits, hyphens or underscores.');
  return join(appRoot,'.runtime','native-fault',id);
}
export function contained(root,path){const rel=relative(root,resolve(path));return !!rel&&!rel.startsWith('..')&&!isAbsolute(rel);}
export function readJson(path){return JSON.parse(readFileSync(path,'utf8'));}
export function atomicJson(path,value){
  const temporary=path+'.tmp';
  const fd=openSync(temporary,'w');
  try{writeFileSync(fd,JSON.stringify(value,null,2)+'\n');fsyncSync(fd);}finally{closeSync(fd);}
  renameSync(temporary,path);
}
export function readRun(id){
  const root=runPath(id),config=readJson(join(root,'run.json'));
  if(config.schema!==1||config.id!==id||config.root!==root||!Number.isInteger(config.socksPort)||!Number.isInteger(config.proxyPort)
    ||config.socksPort<1024||config.socksPort>65535||config.proxyPort<1024||config.proxyPort>65535||config.socksPort===config.proxyPort)throw Error('Invalid QA run configuration.');
  return {root,config};
}
export function ownedEndpoint(){
  const source=readFileSync(join(appRoot,'crates/wallet-runtime/src/mainnet.rs'),'utf8');
  const value=source.match(/pub const OWNED_NODE: &str\s*=\s*"([^"]+)";/)?.[1];
  if(!value)throw Error('Cannot identify the production owned-node constant.');
  return checkedEndpoint(value);
}
export function checkedEndpoint(value){
  const url=new URL(value);
  if(url.protocol!=='http:'||!/^([a-z2-7]{56})\.onion$/.test(url.hostname)||!url.port||url.pathname!=='/'||url.search||url.hash||url.username||url.password)throw Error('Only an explicit v3 onion HTTP endpoint is accepted.');
  return url;
}
export function createRun(id,socksPort,proxyPort){
  const root=runPath(id);
  if(existsSync(root))throw Error('Run already exists. Use another run ID; existing evidence is preserved.');
  if(![socksPort,proxyPort].every(n=>Number.isInteger(n)&&n>=1024&&n<=65535)||socksPort===proxyPort)throw Error('Choose distinct local ports between 1024 and 65535.');
  mkdirSync(root,{recursive:true});
  const config={schema:1,id,root,socksPort,proxyPort};
  atomicJson(join(root,'run.json'),config);
  return {root,config};
}
