// One request = one SOCKS5h tunnel. No redirects, retry, OS DNS or direct fallback.
import net from 'node:net';
import http from 'node:http';
import {REQUEST_LIMIT,RESPONSE_LIMIT,upstreamDeadlineMs} from './core.mjs';
import {checkedEndpoint} from './files.mjs';

async function exact(socket,count,signal){
  return await new Promise((resolve,reject)=>{
    const cleanup=()=>{socket.off('readable',read);socket.off('error',fail);socket.off('end',fail);socket.off('close',fail);signal.removeEventListener('abort',fail);};
    const fail=()=>{cleanup();reject(Error('socks_failed'));};
    const read=()=>{const data=socket.read(count);if(data!==null){cleanup();resolve(data);}};
    socket.on('readable',read);socket.once('error',fail);socket.once('end',fail);socket.once('close',fail);signal.addEventListener('abort',fail,{once:true});
    if(signal.aborted||socket.destroyed)fail();else read();
  });
}
async function connectSocks(port,target,signal){
  const socket=net.createConnection({host:'127.0.0.1',port});
  socket.on('error',()=>{}); // Individual handshake/HTTP operations report fixed, redacted errors.
  const abort=()=>socket.destroy();
  signal.addEventListener('abort',abort,{once:true});
  socket.once('close',()=>signal.removeEventListener('abort',abort));
  try{
    await new Promise((resolve,reject)=>{const fail=()=>{socket.off('connect',ready);socket.off('error',fail);socket.off('close',fail);reject(Error('socks_unavailable'));};const ready=()=>{socket.off('error',fail);socket.off('close',fail);resolve();};socket.once('connect',ready);socket.once('error',fail);socket.once('close',fail);});
    socket.write(Buffer.from([5,1,0]));
    const greeting=await exact(socket,2,signal);
    if(greeting[0]!==5||greeting[1]!==0)throw Error('socks_auth_refused');
    const host=Buffer.from(target.hostname,'ascii'),destination=Number(target.port);
    socket.write(Buffer.concat([Buffer.from([5,1,0,3,host.length]),host,Buffer.from([destination>>8,destination&255])]));
    const reply=await exact(socket,4,signal);
    if(reply[0]!==5||reply[1]!==0||reply[2]!==0)throw Error('socks_connect_refused');
    if(reply[3]===1)await exact(socket,4,signal);
    else if(reply[3]===4)await exact(socket,16,signal);
    else if(reply[3]===3)await exact(socket,(await exact(socket,1,signal))[0],signal);
    else throw Error('socks_reply_invalid');
    await exact(socket,2,signal);
    return socket;
  }catch{socket.destroy();throw Error('socks_failed');}
}
export function torUpstream(endpoint,socksPort){
  const target=checkedEndpoint(endpoint);
  if(!Number.isInteger(socksPort)||socksPort<1024||socksPort>65535)throw Error('socks_port_invalid');
  return async(path,body)=>{
    if(!Buffer.isBuffer(body)||body.length>REQUEST_LIMIT)throw Error('request_too_large');
    const signal=AbortSignal.timeout(upstreamDeadlineMs(path,body));
    const agent=new http.Agent({keepAlive:false,maxSockets:1});
    agent.createConnection=(_options,callback)=>{void connectSocks(socksPort,target,signal).then(socket=>callback(null,socket),()=>callback(Error('socks_failed')));};
    try{
      return await new Promise((resolve,reject)=>{
        const request=http.request({hostname:target.hostname,port:Number(target.port),method:'POST',path,agent,signal,
          headers:{'Content-Type':path.endsWith('.bin')?'application/octet-stream':'application/json','Content-Length':body.length,'Accept-Encoding':'identity','Connection':'close'}},response=>{
          const chunks=[];let size=0;
          response.on('data',chunk=>{size+=chunk.length;if(size>RESPONSE_LIMIT){response.destroy();request.destroy();reject(Error('response_too_large'));}else chunks.push(chunk);});
          response.once('error',()=>reject(Error('upstream_failed')));
          response.once('aborted',()=>reject(Error('upstream_failed')));
          response.once('end',()=>resolve({status:response.statusCode,body:Buffer.concat(chunks),contentType:path.endsWith('.bin')?'application/octet-stream':'application/json'}));
        });
        request.once('error',()=>reject(Error('upstream_failed')));
        request.end(body);
      });
    }finally{agent.destroy();}
  };
}
