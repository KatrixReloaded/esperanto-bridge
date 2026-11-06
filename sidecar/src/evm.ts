import { Transaction, getAddress, keccak256 } from 'ethers';
import { rpcJson } from './rpc.ts';

export const CHAIN_ID = '11155111';
export const RPC_TRUST = 'explicitly_trusted_rpc';
export const MAX_EVM_BODY = 512 * 1024;
export class EvmError extends Error {
  readonly code: string;
  readonly status: number;
  constructor(code: string, status = 400) { super(code); this.code = code; this.status = status; }
}
type ObjectValue = Record<string, any>;
export type RpcCall = (method: string, params: unknown[], timeoutMs?: number) => Promise<unknown>;
function bad(code = 'invalid_evm_request'): never { throw new EvmError(code); }
function object(value: unknown): ObjectValue {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return bad();
  return value as ObjectValue;
}
function fields(value: ObjectValue, required: string[], optional: string[] = []) {
  if (required.some(k => !Object.hasOwn(value, k)) || Object.keys(value).some(k => ![...required, ...optional].includes(k))) bad();
}
function hash(value: unknown): string {
  if (typeof value !== 'string' || !/^0x[\da-fA-F]{64}$/.test(value)) return bad();
  return value.toLowerCase();
}
function address(value: unknown): string {
  if (typeof value !== 'string' || !/^0x[\da-fA-F]{40}$/.test(value)) return bad();
  try { return getAddress(value).toLowerCase(); } catch { return bad(); }
}
function bytes(value: unknown, maximum = 128 * 1024): string {
  if (typeof value !== 'string' || !/^0x(?:[\da-fA-F]{2})*$/.test(value) || value.length > 2 + maximum * 2) return bad();
  return value.toLowerCase();
}
function quantity(value: unknown, maximum = (1n << 64n) - 1n): bigint {
  if (typeof value !== 'string' || !/^0x(?:0|[1-9a-fA-F][\da-fA-F]*)$/.test(value) || value.length > 66 || BigInt(value) > maximum) return bad();
  return BigInt(value);
}
function anchor(value: unknown): { blockHash: string; requireCanonical: true } {
  const a = object(value); fields(a, ['blockHash', 'requireCanonical']);
  if (a.requireCanonical !== true) return bad();
  return { blockHash: hash(a.blockHash), requireCanonical: true };
}
function transaction(value: unknown): ObjectValue {
  const tx = object(value); fields(tx, ['to', 'data'], ['from', 'value', 'gas']);
  address(tx.to); bytes(tx.data);
  if (tx.from !== undefined) address(tx.from);
  if (tx.value !== undefined) quantity(tx.value, (1n << 256n) - 1n);
  if (tx.gas !== undefined) quantity(tx.gas);
  return tx;
}
function filter(value: unknown): ObjectValue {
  const f = object(value); fields(f, ['address', 'topics'], ['blockHash', 'fromBlock', 'toBlock']);
  const addresses = Array.isArray(f.address) ? f.address : [f.address];
  if (!addresses.length || addresses.length > 16) return bad();
  addresses.forEach(address);
  if (!Array.isArray(f.topics) || f.topics.length > 4) return bad();
  for (const topic of f.topics) {
    if (topic === null) continue;
    const alternatives = Array.isArray(topic) ? topic : [topic];
    if (!alternatives.length || alternatives.length > 16) return bad();
    alternatives.forEach(hash);
  }
  if (f.blockHash !== undefined) {
    hash(f.blockHash); if (f.fromBlock !== undefined || f.toBlock !== undefined) return bad();
  } else {
    const first = quantity(f.fromBlock), last = quantity(f.toBlock);
    if (last < first || last - first >= 256n) return bad('log_range_too_large');
  }
  return f;
}
function readParams(method: string, params: unknown): unknown[] {
  if (!Array.isArray(params)) return bad();
  switch (method) {
    case 'eth_call': case 'eth_estimateGas':
      if (params.length !== 2) return bad(); transaction(params[0]); anchor(params[1]); break;
    case 'eth_getCode':
      if (params.length !== 2) return bad(); address(params[0]); anchor(params[1]); break;
    case 'eth_getLogs':
      if (params.length !== 1) return bad(); filter(params[0]); break;
    case 'eth_getBlockByHash':
      if (params.length !== 2 || params[1] !== false) return bad(); hash(params[0]); break;
    case 'eth_getBlockByNumber':
      if (params.length !== 2 || params[1] !== false) return bad();
      if (!['latest', 'safe', 'finalized'].includes(params[0])) quantity(params[0]); break;
    case 'eth_getTransactionCount':
      if (params.length !== 2) return bad(); address(params[0]);
      if (params[1] !== 'pending') anchor(params[1]); break;
    case 'eth_gasPrice': case 'eth_maxPriorityFeePerGas':
      if (params.length !== 0) return bad(); break;
    default: return bad('rpc_method_forbidden');
  }
  return params;
}
function block(value: unknown): { hash: string; number: string; parentHash: string; timestamp: string } {
  const b = object(value);
  const h = hash(b.hash), parentHash = hash(b.parentHash);
  quantity(b.number); quantity(b.timestamp);
  return { hash: h, number: b.number, parentHash, timestamp: b.timestamp };
}
function log(value: unknown): ObjectValue {
  const l = object(value);
  if (l.removed !== false || !Array.isArray(l.topics) || l.topics.length > 4) return bad('invalid_rpc_log');
  quantity(l.blockNumber); quantity(l.transactionIndex); quantity(l.logIndex);
  return { address: address(l.address), topics: l.topics.map(hash), data: bytes(l.data), blockHash: hash(l.blockHash),
    blockNumber: l.blockNumber, transactionHash: hash(l.transactionHash), transactionIndex: l.transactionIndex, logIndex: l.logIndex, removed: false };
}
function logs(value: unknown): ObjectValue[] {
  if (!Array.isArray(value) || value.length > 1024) return bad('invalid_rpc_logs');
  const result = value.map(log), seen = new Set();
  for (const l of result) {
    const key = `${l.blockHash}:${quantity(l.logIndex)}`;
    if (seen.has(key)) return bad('duplicate_rpc_log');
    seen.add(key);
  }
  return result;
}
function readResult(method: string, params: unknown[], value: unknown): unknown {
  switch (method) {
    case 'eth_call': case 'eth_getCode': return bytes(value);
    case 'eth_getLogs': {
      const f = filter(params[0]), result = logs(value);
      const addresses = (Array.isArray(f.address) ? f.address : [f.address]).map(address);
      for (const l of result) {
        if (!addresses.includes(l.address) || (f.blockHash !== undefined && hash(f.blockHash) !== l.blockHash) ||
          (f.blockHash === undefined && (quantity(l.blockNumber) < quantity(f.fromBlock) || quantity(l.blockNumber) > quantity(f.toBlock)))) return bad('rpc_log_scope_mismatch');
        for (let i = 0; i < f.topics.length; i++) {
          const topic = f.topics[i];
          if (topic !== null && !(Array.isArray(topic) ? topic : [topic]).map(hash).includes(l.topics[i])) return bad('rpc_log_scope_mismatch');
        }
      }
      return result;
    }
    case 'eth_getBlockByHash': case 'eth_getBlockByNumber': {
      if (value === null) return null;
      const b = block(value);
      if ((method === 'eth_getBlockByHash' && b.hash !== hash(params[0])) ||
        (method === 'eth_getBlockByNumber' && typeof params[0] === 'string' && params[0].startsWith('0x') && quantity(params[0]) !== quantity(b.number))) return bad('rpc_block_scope_mismatch');
      return b;
    }
    default: quantity(value, (1n << 256n) - 1n); return value;
  }
}
export function nymRpc(rpcUrl: string, options: { proxyPort?: number; timeoutMs?: number } = {}): RpcCall {
  let nextId = 0;
  return async (method, params, timeoutMs) => {
    const id = ++nextId;
    const response = object(await rpcJson(rpcUrl, { jsonrpc: '2.0', id, method, params }, { ...options, timeoutMs: Math.min(timeoutMs ?? 120_000, options.timeoutMs ?? 120_000) }));
    if (response.jsonrpc !== '2.0' || response.id !== id || !Object.hasOwn(response, 'result') || Object.hasOwn(response, 'error')) throw new EvmError('rpc_response_rejected', 502);
    return response.result;
  };
}

/** Transport observations only. The operator explicitly trusts this Sepolia RPC's chain and finality. */
export class EvmClient {
  private readonly rpc: RpcCall;
  private readonly timeout: number;
  constructor(rpc: RpcCall, timeoutMs = 120_000) {
    if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120_000) throw new Error('invalid_evm_timeout');
    this.rpc = rpc; this.timeout = timeoutMs;
  }
  private async call(method: string, params: unknown[], deadline: number): Promise<unknown> {
    const remaining = deadline - Date.now();
    if (remaining <= 0) throw new EvmError('rpc_timeout', 504);
    let timer: ReturnType<typeof setTimeout> | undefined;
    try { return await Promise.race([this.rpc(method, params, remaining), new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new EvmError('rpc_timeout', 504)), remaining);
    })]); } finally { clearTimeout(timer); }
  }
  private async checkChain(deadline: number) {
    if (await this.call('eth_chainId', [], deadline) !== '0xaa36a7') throw new EvmError('chain_mismatch', 409);
  }
  async handle(route: string, body: ObjectValue): Promise<unknown> {
    const deadline = Date.now() + this.timeout;
    if (body.chainId !== CHAIN_ID) throw new EvmError('chain_mismatch', 409);
    if (route === '/evm/read') {
      fields(body, ['chainId', 'method', 'params']);
      const params = readParams(body.method, body.params);
      await this.checkChain(deadline);
      return { chainId: CHAIN_ID, trust: RPC_TRUST, result: readResult(body.method, params, await this.call(body.method, params, deadline)) };
    }
    if (route === '/evm/send') {
      fields(body, ['chainId', 'rawTransaction', 'expectedHash']);
      const raw = bytes(body.rawTransaction), expected = hash(body.expectedHash);
      let tx: Transaction;
      try { tx = Transaction.from(raw); if (!tx.from) return bad('invalid_signed_transaction'); } catch { return bad('invalid_signed_transaction'); }
      if (!tx.signature || tx.chainId !== BigInt(CHAIN_ID) || tx.hash?.toLowerCase() !== expected || keccak256(raw) !== expected || ![0, 1, 2].includes(tx.type ?? -1)) return bad('invalid_signed_transaction');
      await this.checkChain(deadline); // Everything before send is known not to submit a transaction.
      try {
        const actual = await this.call('eth_sendRawTransaction', [raw], deadline);
        if (typeof actual !== 'string' || actual.toLowerCase() !== expected) return { chainId: CHAIN_ID, hash: expected, outcome: 'ambiguous', reason: 'hash_mismatch' };
        return { chainId: CHAIN_ID, hash: expected, outcome: 'accepted' };
      } catch { return { chainId: CHAIN_ID, hash: expected, outcome: 'ambiguous', reason: 'submission_unknown' }; }
    }
    if (route === '/evm/receipt') {
      fields(body, ['chainId', 'hash']);
      const expected = hash(body.hash);
      await this.checkChain(deadline);
      const value = await this.call('eth_getTransactionReceipt', [expected], deadline);
      if (value === null) return { chainId: CHAIN_ID, trust: RPC_TRUST, receipt: null, finality: 'not_found', finalizedHead: null };
      const r = object(value);
      if (hash(r.transactionHash) !== expected || !['0x0', '0x1'].includes(r.status)) return bad('rpc_receipt_scope_mismatch');
      quantity(r.blockNumber); quantity(r.transactionIndex); quantity(r.gasUsed);
      const h = hash(r.blockHash), receiptLogs = logs(r.logs);
      if (receiptLogs.some(l => l.transactionHash !== expected || l.blockHash !== h || quantity(l.blockNumber) !== quantity(r.blockNumber) || quantity(l.transactionIndex) !== quantity(r.transactionIndex))) return bad('rpc_receipt_scope_mismatch');
      const head = block(await this.call('eth_getBlockByNumber', ['finalized', false], deadline));
      const canonical = block(await this.call('eth_getBlockByNumber', [r.blockNumber, false], deadline));
      if (canonical.hash !== h || quantity(canonical.number) !== quantity(r.blockNumber) || (quantity(head.number) === quantity(r.blockNumber) && head.hash !== h)) return bad('rpc_receipt_not_canonical');
      const receipt = { transactionHash: expected, blockHash: h, blockNumber: r.blockNumber, transactionIndex: r.transactionIndex, status: r.status, gasUsed: r.gasUsed, logs: receiptLogs };
      return { chainId: CHAIN_ID, trust: RPC_TRUST, receipt, finality: quantity(head.number) >= quantity(r.blockNumber) ? 'finalized' : 'included', finalizedHead: head };
    }
    return bad('rpc_method_forbidden');
  }
}
