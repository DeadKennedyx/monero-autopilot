// QA-only fault policy. This module never opens a socket or reads wallet data.
export const REQUEST_LIMIT = 1024 * 1024;
export const RESPONSE_LIMIT = 32 * 1024 * 1024;
const bulkPaths = new Set(['/getblocks.bin','/get_blocks.bin','/gethashes.bin','/get_hashes.bin',
  '/getblocks_by_height.bin','/get_blocks_by_height.bin','/gettransactions','/get_transactions','/get_output_distribution.bin']);
export function upstreamDeadlineMs(path,body){
  if(bulkPaths.has(path))return 180_000;
  if(path==='/json_rpc'&&Buffer.isBuffer(body)&&body.length<=REQUEST_LIMIT){
    try{if(JSON.parse(body).method==='get_output_distribution')return 180_000;}catch{}
  }
  return 25_000;
}
const paths = new Set([
  '/json_rpc', '/get_height', '/getheight', '/get_info', '/getblocks.bin',
  '/get_blocks.bin', '/gethashes.bin', '/get_hashes.bin', '/get_o_indexes.bin',
  '/get_outs.bin', '/get_outs', '/get_transactions', '/gettransactions',
  '/get_output_distribution.bin', '/get_transaction_pool_hashes.bin',
  '/get_transaction_pool_hashes', '/get_transaction_pool', '/get_txpool_backlog',
  '/is_key_image_spent', '/sendrawtransaction', '/send_raw_transaction',
  '/getblocks_by_height.bin', '/get_blocks_by_height.bin',
]);
const methods = new Set([
  'get_info', 'get_version', 'get_block_header_by_height', 'getblockheaderbyheight',
  'get_last_block_header', 'getlastblockheader', 'get_block_headers_range',
  'getblockheadersrange', 'hard_fork_info', 'get_fee_estimate',
  'get_output_histogram', 'get_output_distribution', 'get_txpool_backlog',
]);
function object(value) { return value !== null && typeof value === 'object' && !Array.isArray(value); }
const outcomes = new Set(['created','configured','broadcast_denied','forwarding','upstream_failed_no_retry',
  'accepted_response_dropped','upstream_did_not_confirm_acceptance','fee_estimate_overridden','forwarded','fee_schema_unrecognized']);
export function operation(method, path, body, hasCredentials = false) {
  if (method !== 'POST' || !paths.has(path) || !Buffer.isBuffer(body)
      || body.length > REQUEST_LIMIT || hasCredentials) throw Error('request_denied');
  let value;
  if (!path.endsWith('.bin')) {
    try { value = JSON.parse(body); } catch { throw Error('request_denied'); }
    if (!object(value)) throw Error('request_denied');
  }
  if (path === '/json_rpc' && (value.jsonrpc !== '2.0' || !methods.has(value.method))) {
    throw Error('request_denied');
  }
  const broadcast = path === '/sendrawtransaction' || path === '/send_raw_transaction';
  if (broadcast && (typeof value.tx_as_hex !== 'string' || !/^[a-fA-F0-9]+$/.test(value.tx_as_hex)
      || value.tx_as_hex.length % 2 || value.do_not_relay === true
      || Object.keys(value).some(key=>!['tx_as_hex','do_not_relay','do_sanity_checks','client'].includes(key))
      || (value.client!==undefined&&(typeof value.client!=='string'||value.client.length>1024))
      || ['do_not_relay','do_sanity_checks'].some(key=>value[key]!==undefined&&typeof value[key]!=='boolean'))) throw Error('request_denied');
  return { name: path === '/json_rpc' ? value.method : path.slice(1), broadcast };
}
export function initialState() {
  return { schema: 1, mode: 'read-only', feePerWeight: null, claimed: false,
    requests: 0, forwarded: 0, broadcasts: 0, accepted: 0, dropped: 0,
    lastMethod: null, lastOutcome: 'created' };
}
export function validateState(value) {
  if (!object(value) || value.schema !== 1 || !['read-only', 'overfee', 'drop-next', 'spent'].includes(value.mode)
      || Object.keys(value).sort().join(',')!==Object.keys(initialState()).sort().join(',')
      || !outcomes.has(value.lastOutcome)
      || typeof value.claimed !== 'boolean' || !['requests', 'forwarded', 'broadcasts', 'accepted', 'dropped'].every(k => Number.isSafeInteger(value[k]) && value[k] >= 0)
      || value.broadcasts > 1 || value.accepted > value.broadcasts || value.dropped > value.accepted
      || (value.claimed !== (value.broadcasts === 1)) || (value.claimed && value.mode !== 'spent')
      || (value.mode === 'overfee' && !validFee(value.feePerWeight))
      || (value.mode !== 'overfee' && value.feePerWeight !== null)
      || (value.lastMethod !== null && !methods.has(value.lastMethod) && !paths.has('/' + value.lastMethod))) {
    throw Error('state_invalid');
  }
  return structuredClone(value);
}
function validFee(value) { return Number.isSafeInteger(value) && value > 0 && value <= 1_000_000_000; }
function accepted(reply) {
  if (reply.status < 200 || reply.status >= 300) return false;
  try {
    const value = JSON.parse(reply.body);
    return object(value) && value.status === 'OK'
      && (value.not_relayed === undefined || value.not_relayed === false)
      && (value.double_spend === undefined || value.double_spend === false) && value.error === undefined;
  } catch { return false; }
}
function response(status, outcome) {
  return { status, body: Buffer.from(JSON.stringify({ status: 'FAILED', reason: outcome })), contentType: 'application/json' };
}
export class FaultController {
  constructor({ state = initialState(), persist = () => {}, log = () => {} } = {}) {
    this.state = validateState(state);
    this.persist = persist;
    this.log = log;
    this.faulted = false;
  }
  commit(next) {
    if (this.faulted) throw Error('state_unavailable');
    try { this.persist(next); } catch { this.faulted = true; throw Error('state_unavailable'); }
    this.state = next;
  }
  command(action, feePerWeight) {
    if (this.state.claimed) throw Error('broadcast_budget_spent_create_another_run');
    if (!['read-only', 'overfee', 'drop-next'].includes(action)) throw Error('command_denied');
    if (action === 'overfee' && !validFee(feePerWeight)) throw Error('fee_invalid');
    this.commit({ ...this.state, mode: action, feePerWeight: action === 'overfee' ? feePerWeight : null,
      lastOutcome: 'configured' });
    return this.snapshot();
  }
  snapshot() { return structuredClone(this.state); }
  async handle(request, upstream) {
    let op;
    try { op = operation(request.method, request.path, request.body, request.hasCredentials); }
    catch { return response(403, 'request_denied'); }
    if (this.faulted) return response(503, 'state_unavailable');
    const feeOverride = this.state.mode === 'overfee' ? this.state.feePerWeight : null;
    const denyBroadcast = op.broadcast && (this.state.mode !== 'drop-next' || this.state.claimed);
    const next = { ...this.state, requests: this.state.requests + 1, lastMethod: op.name,
      lastOutcome: denyBroadcast ? 'broadcast_denied' : 'forwarding' };
    if (!denyBroadcast) next.forwarded++;
    if (op.broadcast && !denyBroadcast) {
      // Persist BEFORE I/O. A failure, restart, or duplicate connection cannot
      // recreate this run's single broadcast permission.
      next.claimed = true;
      next.broadcasts = 1;
      next.mode = 'spent';
      next.feePerWeight = null;
    }
    try { this.commit(next); } catch { return response(503, 'state_unavailable'); }
    if (denyBroadcast) { this.log({ method: op.name, outcome: 'broadcast_denied', broadcasts: next.broadcasts }); return response(403, 'broadcast_denied'); }
    let reply;
    try {
      reply = await upstream(request.path, request.body);
      if (!Number.isInteger(reply.status) || !Buffer.isBuffer(reply.body) || reply.body.length > RESPONSE_LIMIT
          || (reply.status >= 300 && reply.status < 400)) throw Error('upstream_invalid');
    } catch {
      try { this.commit({ ...this.state, lastMethod: op.name, lastOutcome: 'upstream_failed_no_retry' }); } catch {}
      this.log({ method: op.name, outcome: 'upstream_failed_no_retry', broadcasts: this.state.broadcasts });
      return response(502, 'upstream_failed_no_retry');
    }
    if (op.broadcast && accepted(reply)) {
      // Fault injection happens only AFTER the upstream says it accepted.
      try { this.commit({ ...this.state, accepted: 1, dropped: 1, lastMethod: op.name, lastOutcome: 'accepted_response_dropped' }); }
      catch { this.log({ method: op.name, outcome: 'accepted_response_dropped_state_unavailable', broadcasts: 1 }); return { drop: true }; }
      this.log({ method: op.name, outcome: 'accepted_response_dropped', broadcasts: 1 });
      return { drop: true };
    }
    if (op.name === 'get_fee_estimate' && feeOverride !== null && reply.status >= 200 && reply.status < 300) {
      try {
        const value = JSON.parse(reply.body);
        if (!object(value.result) || value.error !== undefined) throw Error();
        let changed = false;
        if (Number.isSafeInteger(value.result.fee) && value.result.fee >= 0) { value.result.fee = feeOverride; changed = true; }
        if (Array.isArray(value.result.fees) && value.result.fees.length > 0
            && value.result.fees.every(n => Number.isSafeInteger(n) && n >= 0)) {
          value.result.fees = value.result.fees.map(() => feeOverride); changed = true;
        }
        if (!changed) throw Error();
        reply = { ...reply, body: Buffer.from(JSON.stringify(value)), contentType: 'application/json' };
      } catch {
        try { this.commit({ ...this.state, lastMethod:op.name, lastOutcome:'fee_schema_unrecognized' }); } catch {}
        this.log({method:op.name,outcome:'fee_schema_unrecognized',broadcasts:this.state.broadcasts});
        return response(502, 'fee_schema_unrecognized');
      }
    }
    const outcome = op.broadcast ? 'upstream_did_not_confirm_acceptance' : feeOverride !== null && op.name === 'get_fee_estimate' ? 'fee_estimate_overridden' : 'forwarded';
    try { this.commit({ ...this.state, lastMethod: op.name, lastOutcome: outcome }); } catch { return response(503, 'state_unavailable'); }
    this.log({ method: op.name, outcome, broadcasts: this.state.broadcasts });
    return reply;
  }
}
