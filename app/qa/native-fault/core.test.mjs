// In-memory tests only. No listeners, Tor, wallet files, real transactions or external requests.
import test from 'node:test';
import assert from 'node:assert/strict';
import {FaultController,initialState,validateState,operation,REQUEST_LIMIT,RESPONSE_LIMIT,upstreamDeadlineMs} from './core.mjs';
const request=(path,body)=>({method:'POST',path,body:Buffer.from(JSON.stringify(body))});
// Monero 0.18.5.4 serializes rpc_access_request_base.client even when empty.
const broadcast=()=>request('/sendrawtransaction',{client:'',tx_as_hex:'deadbeef',do_not_relay:false,do_sanity_checks:true});
const feeRequest=()=>request('/json_rpc',{jsonrpc:'2.0',id:'fixture',method:'get_fee_estimate',params:{}});
const reply=(body,status=200)=>({status,body:Buffer.from(JSON.stringify(body)),contentType:'application/json'});

test('closed path/method/body boundary rejects unknown operations and credentials',()=>{
  for(const path of ['/stop_daemon','/set_log_level','http://elsewhere.invalid/','/json_rpc?query=1','/../json_rpc'])assert.throws(()=>operation('POST',path,Buffer.from('{}')));
  for(const method of ['transfer','relay_tx','query_key','stop_daemon'])assert.throws(()=>operation('POST','/json_rpc',Buffer.from(JSON.stringify({jsonrpc:'2.0',method}))));
  assert.throws(()=>operation('GET','/get_info',Buffer.from('{}')));
  assert.throws(()=>operation('POST','/get_info',Buffer.from('[]')));
  assert.throws(()=>operation('POST','/get_info',Buffer.alloc(REQUEST_LIMIT+1)));
  assert.throws(()=>operation('POST','/get_info',Buffer.from('{}'),true));
  assert.throws(()=>operation('POST','/send_raw_transaction',Buffer.from('{"tx_as_hex":"bad hex"}')));
  assert.throws(()=>operation('POST','/send_raw_transaction',Buffer.from('{"tx_as_hex":"deadbeef","extra":true}')));
  for(const client of [null,42,{},'x'.repeat(1025)])assert.throws(()=>operation('POST','/sendrawtransaction',request('/sendrawtransaction',{client,tx_as_hex:'deadbeef'}).body));
  assert.equal(operation('POST','/sendrawtransaction',broadcast().body).broadcast,true);
  assert.equal(operation('POST','/getblocks.bin',Buffer.from([1,2])).broadcast,false);
});

test('unarmed and overfee modes never forward a broadcast',async()=>{
  const controller=new FaultController();let calls=0;
  const upstream=async()=>{calls++;return reply({status:'OK'});};
  assert.equal((await controller.handle(broadcast(),upstream)).status,403);
  controller.command('overfee',100000);
  assert.equal((await controller.handle(broadcast(),upstream)).status,403);
  assert.equal(calls,0);assert.equal(controller.snapshot().broadcasts,0);
});

test('overfee changes only supported fee fields and never mutates a signed transaction',async()=>{
  const controller=new FaultController();controller.command('overfee',100000);
  const original={jsonrpc:'2.0',id:'fixture',result:{status:'OK',fee:4,fees:[4,8,12,16],quantization_mask:10000,height:123}};
  const result=await controller.handle(feeRequest(),async()=>reply(original));
  assert.deepEqual(JSON.parse(result.body),{...original,result:{...original.result,fee:100000,fees:[100000,100000,100000,100000]}});
  assert.equal(original.result.fee,4);
  const ordinary=request('/json_rpc',{jsonrpc:'2.0',id:1,method:'get_info'}),bytes=Buffer.from('{"unmodified":true}');
  const forwarded=await controller.handle(ordinary,async()=>({status:200,body:bytes}));
  assert.equal(forwarded.body,bytes);
  assert.equal((await controller.handle(feeRequest(),async()=>reply({result:{unexpected:1}}))).status,502);
});

test('acceptance is awaited, permission is persisted before forwarding, concurrent sends are denied',async()=>{
  const saved=[],logs=[];
  const controller=new FaultController({persist:state=>saved.push(structuredClone(state)),log:entry=>logs.push(entry)});
  controller.command('drop-next');let release,calls=0;
  const upstream=async()=>{calls++;assert.equal(saved.at(-1).claimed,true);assert.equal(saved.at(-1).broadcasts,1);return await new Promise(resolve=>{release=resolve;});};
  let completed=false;
  const first=controller.handle(broadcast(),upstream).then(value=>{completed=true;return value;});
  assert.equal(controller.snapshot().mode,'spent');assert.equal(completed,false);assert.equal(controller.snapshot().dropped,0);
  assert.equal((await controller.handle(broadcast(),upstream)).status,403);assert.equal(calls,1);
  release(reply({status:'OK',not_relayed:false}));
  assert.deepEqual(await first,{drop:true});assert.equal(controller.snapshot().accepted,1);assert.equal(controller.snapshot().dropped,1);
  assert.throws(()=>controller.command('drop-next'),/budget_spent/);
  assert.equal(JSON.stringify(logs).includes('deadbeef'),false);
  for(const entry of logs)assert.deepEqual(Object.keys(entry).sort(),['broadcasts','method','outcome']);
});

test('restart after claim never replays a broadcast, even without its upstream outcome',async()=>{
  let persisted;const controller=new FaultController({persist:state=>{persisted=structuredClone(state);}});
  controller.command('drop-next');let release;
  const first=controller.handle(broadcast(),async()=>await new Promise(resolve=>{release=resolve;}));
  const restarted=new FaultController({state:persisted});let repeated=0;
  assert.equal((await restarted.handle(broadcast(),async()=>{repeated++;return reply({status:'OK'});})).status,403);
  assert.throws(()=>restarted.command('read-only'),/budget_spent/);assert.equal(repeated,0);
  release(reply({status:'BUSY'},503));assert.equal((await first).status,503);
});

test('upstream failure consumes the one-shot permission and never retries',async()=>{
  const controller=new FaultController();controller.command('drop-next');let calls=0;
  const result=await controller.handle(broadcast(),async()=>{calls++;throw Error('secret remote details');});
  assert.equal(result.status,502);assert.equal(calls,1);assert.equal(controller.snapshot().accepted,0);assert.equal(controller.snapshot().dropped,0);
  assert.equal(result.body.includes('secret'),false);assert.throws(()=>controller.command('drop-next'),/budget_spent/);
});

test('only a successful accepted response triggers the injected drop',async()=>{
  for(const response of [reply({status:'BUSY'}),reply({status:'OK',not_relayed:true}),reply({status:'OK',not_relayed:'true'}),reply({status:'OK',double_spend:true}),reply({status:'OK',error:'refused'}),reply({status:'OK'},500),{status:200,body:Buffer.from('invalid')}]){
    const controller=new FaultController();controller.command('drop-next');const result=await controller.handle(broadcast(),async()=>response);
    assert.equal(result.drop,undefined);assert.equal(controller.snapshot().dropped,0);assert.equal(controller.snapshot().claimed,true);
  }
});

test('state persistence failure before the attempt prevents all network forwarding',async()=>{
  let writes=0,calls=0;const controller=new FaultController({persist:()=>{if(++writes===2)throw Error('disk failure');}});
  controller.command('drop-next');
  const result=await controller.handle(broadcast(),async()=>{calls++;return reply({status:'OK'});});
  assert.equal(result.status,503);assert.equal(calls,0);assert.throws(()=>controller.command('drop-next'),/unavailable/);
});

test('persistence failure after acceptance cannot recreate permission or forward a successful reply',async()=>{
  let writes=0,persisted,calls=0;
  const controller=new FaultController({persist:state=>{if(++writes===3)throw Error('disk failure');persisted=structuredClone(state);}});
  controller.command('drop-next');
  assert.deepEqual(await controller.handle(broadcast(),async()=>{calls++;return reply({status:'OK'});}),{drop:true});
  const reopened=new FaultController({state:persisted});
  assert.equal((await reopened.handle(broadcast(),async()=>{calls++;return reply({status:'OK'});})).status,403);
  assert.equal(calls,1);assert.equal(reopened.snapshot().claimed,true);
});

test('unexpected state, oversized upstream bodies and redirects fail closed',async()=>{
  for(const value of [{...initialState(),extra:'secret'},{...initialState(),lastOutcome:'arbitrary log text'},{...initialState(),broadcasts:1},{...initialState(),claimed:true},{...initialState(),mode:'overfee',feePerWeight:0}])assert.throws(()=>validateState(value));
  const controller=new FaultController();let calls=0;
  for(const response of [{status:302,body:Buffer.from('')},{status:200,body:Buffer.alloc(RESPONSE_LIMIT+1)}]){
    assert.equal((await controller.handle(feeRequest(),async()=>{calls++;return response;})).status,502);
  }
  assert.equal(calls,2);assert.equal(controller.snapshot().broadcasts,0);
});

test('bounded block requests stay unchanged and use the product bulk deadline',async()=>{
  const controller=new FaultController();
  for(const path of ['/getblocks.bin','/get_blocks.bin','/gethashes.bin','/get_hashes.bin','/getblocks_by_height.bin','/get_blocks_by_height.bin','/get_output_distribution.bin']){
    const body=Buffer.from([1,17,1,1,1,1,2,1,0,0,7,0]),response=Buffer.from([8,4,2,0]);
    const result=await controller.handle({method:'POST',path,body},async(p,b)=>{assert.equal(p,path);assert.equal(b,body);return {status:200,body:response};});
    assert.equal(result.body,response);assert.equal(upstreamDeadlineMs(path,body),180_000);
  }
  assert.equal(upstreamDeadlineMs('/json_rpc',Buffer.from('{"method":"get_output_distribution"}')),180_000);
  assert.equal(upstreamDeadlineMs('/json_rpc',feeRequest().body),25_000);
  assert.equal(upstreamDeadlineMs('/send_raw_transaction',broadcast().body),25_000);
});
