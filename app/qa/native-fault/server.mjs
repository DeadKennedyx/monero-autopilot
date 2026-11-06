// Explicitly run this file to start the QA listener. Importing policy/tests does not start it.
import http from 'node:http';
import {readFileSync,writeFileSync,existsSync,unlinkSync} from 'node:fs';
import {join} from 'node:path';
import {FaultController,initialState,REQUEST_LIMIT} from './core.mjs';
import {readRun,readJson,atomicJson,ownedEndpoint} from './files.mjs';
import {torUpstream} from './transport.mjs';

const log=entry=>process.stdout.write(JSON.stringify({at:new Date().toISOString(),...entry})+'\n');
process.on('uncaughtException',()=>{log({outcome:'proxy_failed'});process.exit(1);});
process.on('unhandledRejection',()=>{log({outcome:'proxy_failed'});process.exit(1);});
const {root,config}=readRun(process.argv[2]);
const lock=join(root,'proxy.pid');
if(existsSync(lock)){
  const owner=Number(readFileSync(lock,'utf8'));
  if(!Number.isInteger(owner)||owner<1)throw Error('Invalid QA proxy lock. Inspect the run manually.');
  let alive=true;try{process.kill(owner,0);}catch(error){if(error.code==='ESRCH')alive=false;}
  if(alive)throw Error('This QA proxy run is already active.');
  unlinkSync(lock);
}
writeFileSync(lock,String(process.pid),{flag:'wx'});
const stateFile=join(root,'proxy-state.json');
const controller=new FaultController({state:existsSync(stateFile)?readJson(stateFile):initialState(),persist:state=>atomicJson(stateFile,state),log});
atomicJson(stateFile,controller.snapshot());
const upstream=torUpstream(ownedEndpoint().href,config.socksPort);
let active=0;
const server=http.createServer(async(request,response)=>{
  response.setHeader('Cache-Control','no-store');
  response.setHeader('X-Content-Type-Options','nosniff');
  if(request.socket.remoteAddress!=='127.0.0.1'||active>=8){response.writeHead(503).end();return;}
  active++;
  try{
    const chunks=[];let length=0;
    const declared=request.headers['content-length'];
    if(declared!==undefined&&(!/^\d+$/.test(declared)||Number(declared)>REQUEST_LIMIT)){response.writeHead(413).end();return;}
    for await(const chunk of request){length+=chunk.length;if(length>REQUEST_LIMIT){response.writeHead(413).end();request.destroy();return;}chunks.push(chunk);}
    const result=await controller.handle({method:request.method,path:request.url,body:Buffer.concat(chunks),
      hasCredentials:!!(request.headers.authorization||request.headers.cookie||request.headers['proxy-authorization'])},upstream);
    if(result.drop){request.socket.destroy();return;}
    response.writeHead(result.status,{'Content-Type':result.contentType,'Content-Length':result.body.length}).end(result.body);
  }catch{if(!response.headersSent)response.writeHead(502);response.end();}
  finally{active--;}
});
server.requestTimeout=20_000;
server.headersTimeout=10_000;
server.maxConnections=16;
// Keep idle connections past the product client's pooling lifetime. The only
// intentional socket loss in this fixture is the accepted-broadcast fault.
server.keepAliveTimeout=120_000;
server.on('clientError',(_error,socket)=>socket.destroy());
server.on('error',()=>{log({outcome:'listener_failed'});process.exitCode=1;shutdown();});
const commands=setInterval(()=>{
  const path=join(root,'command.json');
  if(!existsSync(path))return;
  let command;
  try{command=readJson(path);}catch{return;}
  let outcome;
  try{
    if(typeof command.id!=='string'||!/^[a-f0-9-]{36}$/.test(command.id))throw Error('command_denied');
    controller.command(command.action,command.feePerWeight);
    outcome='applied';
  }catch(error){outcome=['broadcast_budget_spent_create_another_run','command_denied','fee_invalid','state_unavailable'].includes(error.message)?error.message:'command_denied';}
  atomicJson(join(root,'command-result.json'),{id:typeof command.id==='string'&&/^[a-f0-9-]{36}$/.test(command.id)?command.id:null,outcome});
  unlinkSync(path);
},100);
let stopping=false;
function shutdown(){if(stopping)return;stopping=true;clearInterval(commands);server.close(()=>{if(existsSync(lock)&&readFileSync(lock,'utf8')===String(process.pid))unlinkSync(lock);});server.closeIdleConnections();}
process.once('SIGINT',shutdown);process.once('SIGTERM',shutdown);
process.once('exit',()=>{if(existsSync(lock)&&readFileSync(lock,'utf8')===String(process.pid))unlinkSync(lock);});
server.listen(config.proxyPort,'127.0.0.1',()=>log({outcome:'listener_ready',broadcasts:controller.snapshot().broadcasts}));
