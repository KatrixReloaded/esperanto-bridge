import { test } from 'node:test';
import assert from 'node:assert/strict';
import { request } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createServer } from '../src/http.ts';
import { EvmClient, CHAIN_ID } from '../src/evm.ts';
import { SdkError, type SdkAdapter, type PreparedPermit } from '../src/sdk.ts';

const contract = '0x1111111111111111111111111111111111111111';
const user = '0x2222222222222222222222222222222222222222';
const handle: `0x${string}` = `0x${'33'.repeat(32)}`;
const signature = `0x${'44'.repeat(65)}`;
const scope = { contract, user, handle, width: 'uint64' };
function fake() {
  const calls = { encrypt: 0, prepare: 0, decrypt: 0, dispose: 0, values: [] as bigint[] };
  const sdk = {
    prepareEncryption: async () => {},
    publicBoolean: async (h: string) => ({ handle: h, value: true, abiEncodedClearValues: '0x' + '0'.repeat(63) + '1', decryptionProof: '0x1234' }),
    encrypt: async (_contract: string, _user: string, value: bigint) => {
      calls.encrypt++; calls.values.push(value); return { handle, inputProof: '0x1234' };
    },
    encryptRedemption: async (_contract: string, _user: string, _amount: bigint, _destination: readonly [bigint, bigint, bigint]) => ({ handles: [handle, handle, handle, handle], inputProof: '0x1234' }),
    prepare: async () => {
      calls.prepare++;
      return { keypair: { publicKey: 'public', privateKey: 'SECRET' }, publicKey: 'public', startTimestamp: '1', digest: handle,
        eip712: { domain: {}, types: {}, message: {} } } as unknown as PreparedPermit;
    },
    decrypt: async () => { calls.decrypt++; return 18446744073709551615n; },
    dispose: () => { calls.dispose++; },
  };
  return { calls, sdk: sdk as SdkAdapter };
}
async function service(options: Parameters<typeof createServer>[1] = {}, supplied = fake()) {
  const server = createServer(supplied.sdk, options);
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as AddressInfo).port;
  async function post(path: string, body: unknown, headers: Record<string, string> = {}, raw = false) {
    return new Promise<{ status: number; body: any; raw: string }>((resolve, reject) => {
      const req = request({ hostname: '127.0.0.1', port, path, method: 'POST', headers: { 'content-type': 'application/json', ...headers } }, res => {
        const chunks: Buffer[] = [];
        res.on('data', chunk => chunks.push(chunk));
        res.on('end', () => { const text = Buffer.concat(chunks).toString(); resolve({ status: res.statusCode!, body: JSON.parse(text), raw: text }); });
      });
      req.on('error', reject);
      req.end(raw ? body : JSON.stringify(body));
    });
  }
  return { ...supplied, server, post, close: () => new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve())) };
}
const decryptBody = (sessionId: string) => ({ sessionId, ...scope, signature });

test('encrypt preserves uint64 zero/MAX and rejects noncanonical or numeric amounts', async () => {
  const s = await service();
  try {
    for (const value of ['0', '18446744073709551615']) assert.equal((await s.post('/encrypt', { contract, user, value })).status, 200);
    for (const value of ['18446744073709551616', '01', '-1', '+1', '1.0', '1e2', '', ' 1', 0, 1, null]) {
      assert.equal((await s.post('/encrypt', { contract, user, value })).body.error.code, 'invalid_uint64');
    }
    assert.deepEqual(s.calls.values, [0n, 18446744073709551615n]);
  } finally { await s.close(); }
});

test('strict input, JSON, size, host and origin boundaries', async () => {
  const s = await service();
  try {
    for (const body of [{ contract, user, value: '1', privateKey: 'bad' }, { contract, value: '1' }, [], null]) {
      assert.equal((await s.post('/encrypt', body)).status, 400);
    }
    for (const bad of ['0x' + '00'.repeat(20), 'x', 1]) assert.equal((await s.post('/encrypt', { contract: bad, user, value: '1' })).body.error.code, 'invalid_address');
    assert.equal((await s.post('/encrypt', {}, { origin: 'null' })).status, 403);
    assert.equal((await s.post('/encrypt', {}, { host: 'localhost' })).status, 403);
    assert.equal((await s.post('/encrypt', {}, { host: '127.0.0.1.attacker.test' })).status, 403);
    assert.equal((await s.post('/encrypt', {}, { 'content-type': 'text/plain' })).status, 415);
    assert.equal((await s.post('/encrypt', '{', {}, true)).body.error.code, 'invalid_json');
    assert.equal((await s.post('/encrypt', ' '.repeat(16 * 1024 + 1), {}, true)).status, 413);
    assert.equal((await s.post('/encrypt', ' '.repeat(16 * 1024 + 1), { 'transfer-encoding': 'chunked' }, true)).status, 413);
    assert.equal((await s.post('/decrypt-request', { ...scope, handle: '0x' + '00'.repeat(32) })).body.error.code, 'invalid_handle');
    assert.equal((await s.post('/decrypt-request', { ...scope, user: contract })).body.error.code, 'invalid_user');
    assert.equal(s.calls.encrypt + s.calls.prepare, 0);
  } finally { await s.close(); }
});

test('permit public fields, single use, scope binding, capacity and failure consumption', async () => {
  const s = await service({ maxSessions: 1 });
  try {
    const prepared = await s.post('/decrypt-request', scope);
    assert.equal(prepared.status, 200);
    assert.match(prepared.body.sessionId, /^[0-9a-f]{64}$/);
    assert.deepEqual(Object.keys(prepared.body).sort(), ['sessionId', 'contract', 'user', 'handle', 'expiresAt', 'publicKey', 'startTimestamp', 'typedData', 'digest', 'width'].sort());
    assert.ok(!prepared.raw.includes('SECRET'));
    assert.equal((await s.post('/decrypt-request', scope)).body.error.code, 'session_capacity');
    assert.equal(s.calls.prepare, 1);
    assert.equal((await s.post('/decrypt', decryptBody(prepared.body.sessionId))).body.value, '18446744073709551615');
    assert.equal((await s.post('/decrypt', decryptBody(prepared.body.sessionId))).body.error.code, 'session_unavailable');
    for (const mutation of [{ user: contract }, { handle: '0x' + '55'.repeat(32) }, { signature: 'bad' }, { width: 'uint256' }, { extra: 'bad' }]) {
      const permit = await s.post('/decrypt-request', scope);
      assert.ok((await s.post('/decrypt', { ...decryptBody(permit.body.sessionId), ...mutation })).status >= 400);
      assert.equal((await s.post('/decrypt', decryptBody(permit.body.sessionId))).status, 410);
    }
    assert.equal(s.calls.decrypt, 1);
    assert.equal((await s.post('/decrypt', decryptBody('A'.repeat(64)))).body.error.code, 'invalid_session');
    assert.equal((await s.post('/decrypt', decryptBody('a'.repeat(64)))).status, 410);
  } finally { await s.close(); }
});

test('expired and restarted sessions are unavailable', async () => {
  const s = await service({ sessionTtlMs: 15 });
  const permit = await s.post('/decrypt-request', scope);
  await new Promise(resolve => setTimeout(resolve, 30));
  assert.equal((await s.post('/decrypt', decryptBody(permit.body.sessionId))).body.error.code, 'session_unavailable');
  await s.close();
  const restarted = await service();
  try { assert.equal((await restarted.post('/decrypt', decryptBody(permit.body.sessionId))).status, 410); }
  finally { await restarted.close(); }
});

test('only explicit SDK errors escape; ACL denial differs from invalid signatures', async () => {
  const f = fake();
  let error: unknown;
  f.sdk.decrypt = async () => { throw error; };
  const s = await service({}, f);
  try {
    for (const [failure, code, status] of [
      [new SdkError('sdk_acl_denied'), 'sdk_acl_denied', 403],
      [new SdkError('invalid_signature'), 'invalid_signature', 400],
      [new SdkError('signature_user_mismatch'), 'signature_user_mismatch', 403],
      [new SdkError('decrypt_failed'), 'decrypt_failed', 502],
      [new Error('SECRET plaintext URL'), 'sdk_failed', 502],
      [{ code: 'sdk_acl_denied', message: 'SECRET' }, 'sdk_failed', 502],
      [new SdkError('SECRET'), 'sdk_failed', 502],
    ] as const) {
      error = failure;
      const prepared = await s.post('/decrypt-request', scope);
      const result = await s.post('/decrypt', decryptBody(prepared.body.sessionId));
      assert.equal(result.status, status);
      assert.deepEqual(result.body, { error: { code } });
      assert.equal((await s.post('/decrypt', decryptBody(prepared.body.sessionId))).status, 410);
    }
  } finally { await s.close(); }
});

test('busy does not consume a session; timeout retires SDK and invalidates sessions', async () => {
  const f = fake();
  let entered!: () => void;
  const started = new Promise<void>(resolve => { entered = resolve; });
  let release!: () => void;
  f.sdk.encrypt = async () => { entered(); await new Promise<void>(resolve => { release = resolve; }); return { handle, inputProof: '0x1234' }; };
  const s = await service({ operationTimeoutMs: 50 }, f);
  const retirements: string[] = [];
  s.server.on('sdkTimeout', (route: string) => { retirements.push(route); });
  try {
    const permit = await s.post('/decrypt-request', scope);
    const pending = s.post('/encrypt', { contract, user, value: '1' });
    await started;
    assert.equal((await s.post('/decrypt', decryptBody(permit.body.sessionId))).body.error.code, 'busy');
    release();
    assert.equal((await pending).status, 200);
    assert.equal((await s.post('/decrypt', decryptBody(permit.body.sessionId))).status, 200);
    const next = await s.post('/decrypt-request', scope);
    assert.ok(next.body.sessionId);
    f.sdk.encrypt = async () => new Promise(() => {});
    const timed = await s.post('/encrypt', { contract, user, value: '1' });
    assert.deepEqual(timed.body, { error: { code: 'operation_timeout' } });
    assert.equal(timed.status, 504);
    assert.equal(f.calls.dispose, 1);
    assert.deepEqual(retirements, ['/encrypt']);
    assert.equal((await s.post('/decrypt', decryptBody(next.body.sessionId))).body.error.code, 'sdk_unavailable');
    assert.equal((await s.post('/encrypt', { contract, user, value: '1' })).status, 503);
  } finally { await s.close(); }
});

test('server options enforce configured upper/lower bounds', () => {
  for (const options of [{ maxSessions: 65 }, { sessionTtlMs: 300001 }, { operationTimeoutMs: 120001 }, { maxSessions: 0 }, { maxSessions: 1.5 }]) {
    assert.throws(() => createServer(fake().sdk, options), /invalid_server_option/);
  }
});

test('redemption encryption bounds three uint256 words', async () => {
 const s = await service();
 try {
  const max = ((1n << 256n) - 1n).toString();
  assert.equal((await s.post('/encrypt-redemption', {contract, user, amount:'1', destination:['0', max, '9']})).status, 200);
  for (const destination of [['0','1'], ['0','1',(1n << 256n).toString()], ['0','01','2']])
   assert.equal((await s.post('/encrypt-redemption', {contract,user,amount:'1',destination})).body.error.code, 'invalid_uint256');
 } finally { await s.close(); }
});
test('decrypt width is bound to session and response', async () => {
 const f = fake(); f.sdk.decrypt = async input => input.width === 'uint256' ? (1n << 256n) - 1n : 1n;
 const s = await service({}, f);
 try {
  const wide = {...scope, width:'uint256'};
  const p = await s.post('/decrypt-request', wide);
  assert.equal(p.body.width, 'uint256');
  const result = await s.post('/decrypt', {sessionId:p.body.sessionId, ...wide, signature});
  assert.equal(result.body.value, ((1n << 256n) - 1n).toString());
  assert.equal(result.body.width, 'uint256');
  const p2 = await s.post('/decrypt-request', wide);
  assert.equal((await s.post('/decrypt', {sessionId:p2.body.sessionId, ...scope, signature})).body.error.code, 'session_scope_mismatch');
 } finally { await s.close(); }
});


test('EVM routes keep loopback checks, separate size bounds and sanitized chain errors', async () => {
  const calls: string[] = [];
  const evm = new EvmClient(async method => { calls.push(method); return method === 'eth_chainId' ? '0xaa36a7' : '0x1234'; });
  const s = await service({ evm });
  const body = {chainId:CHAIN_ID,method:'eth_call',params:[{to:contract,data:'0x'+'ab'.repeat(12000)},{blockHash:handle,requireCanonical:true}]};
  try {
    assert.equal((await s.post('/evm/read',body)).status,200);
    assert.deepEqual(calls,['eth_chainId','eth_call']);
    assert.equal((await s.post('/evm/read',{...body,chainId:'1'})).body.error.code,'chain_mismatch');
    assert.equal((await s.post('/evm/read',body,{origin:'null'})).status,403);
    assert.equal((await s.post('/evm/read',' '.repeat(512*1024+1),{},true)).status,413);
    assert.equal(s.calls.encrypt+s.calls.prepare+s.calls.decrypt,0);
  } finally { await s.close(); }
  const noEvm=await service();
  try { assert.equal((await noEvm.post('/evm/read',body)).status,404); } finally { await noEvm.close(); }
});

test('public boolean proof route rejects amount handles and wrong chains', async () => {
  const s = await service();
  try {
    const h = '0x' + 'ab'.repeat(22) + '0000000000aa36a7' + '0000';
    const r = await s.post('/public-boolean', { handle: h });
    assert.equal(r.status, 200); assert.equal(r.body.value, true); assert.equal(r.body.decryptionProof, '0x1234');
    assert.equal((await s.post('/public-boolean', { handle: h.slice(0, 62) + '0500' })).status, 400);
    assert.equal((await s.post('/public-boolean', { handle: h.slice(0, 46) + '00000000000000010000' })).status, 400);
  } finally { await s.close(); }
});
