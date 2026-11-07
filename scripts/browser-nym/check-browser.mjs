// Read-only live check: fresh Chromium profile, real finalized RPC, pinned TLS over Nym.
import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
const browser = process.env.CWXMR_BROWSER;
if (!browser) throw Error('Set CWXMR_BROWSER to a Chromium-compatible executable');
const origin = process.argv[2] ?? 'http://127.0.0.1:5188';
if (!['127.0.0.1', 'localhost'].includes(new URL(origin).hostname)) throw Error('Use the local frontend development server');
const profile = await mkdtemp(join(tmpdir(), 'cwxmr-nym-check-'));
const child = spawn(browser, ['--headless', '--disable-gpu', '--remote-debugging-port=0', `--user-data-dir=${profile}`, 'about:blank'], { stdio: ['ignore', 'ignore', 'pipe'] });
let socket;
try {
  const endpoint = await new Promise((resolve, reject) => {
    let output = '';
    child.stderr.on('data', data => { output += data; const match = output.match(/DevTools listening on (ws:\/\/[^\s]+)/); if (match) resolve(match[1]); });
    child.on('error', reject); child.on('exit', () => reject(Error('Browser exited before CDP was ready')));
  });
  socket = new WebSocket(endpoint);
  await new Promise((resolve, reject) => { socket.onopen = resolve; socket.onerror = reject; });
  let id = 0; const pending = new Map();
  socket.onmessage = event => {
    const message = JSON.parse(event.data);
    if (message.id) { const request = pending.get(message.id); if (request) { pending.delete(message.id); message.error ? request.reject(Error(message.error.message)) : request.resolve(message.result); } }
    if (message.method === 'Runtime.consoleAPICalled') {
      const text = message.params.args.map(a => a.value ?? a.description ?? '').join(' ');
      if (text.startsWith('CWXMR_CHECK:')) console.log(text);
    }
  };
  const call = (method, params = {}, sessionId) => new Promise((resolve, reject) => { const request = ++id; pending.set(request, { resolve, reject }); socket.send(JSON.stringify({ id: request, method, params, sessionId })); });
  const { targetId } = await call('Target.createTarget', { url: `${origin}/` });
  const { sessionId } = await call('Target.attachToTarget', { targetId, flatten: true });
  await call('Runtime.enable', {}, sessionId);
  await call('Page.enable', {}, sessionId);
  const expression = `(async () => {
    const { nym } = await import('/src/api/nym.ts');
    const { readAttestedPeer } = await import('/src/wallet/attestation.ts');
    const { metamask } = await import('/src/wallet/metamask.ts');
    const { liveApi } = await import('/src/api/live.ts');
    const provider = { on() {}, removeListener() {}, async request({method, params=[]}) {
      if (!['eth_chainId','eth_getBlockByNumber','eth_getBlockByHash','eth_getCode','eth_call','eth_getLogs'].includes(method)) throw Error('Read-only RPC only');
      const response = await fetch('https://ethereum-sepolia-rpc.publicnode.com', {method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method,params})});
      const data=await response.json(); if(data.error) throw Error(data.error.message); return data.result;
    }};
    nym.subscribe(() => console.log('CWXMR_CHECK:', JSON.stringify(nym.getSnapshot())));
    await new Promise(resolve => setTimeout(resolve, 500));
    if(nym.getSnapshot().phase==='idle') throw Error('Actual App did not start Nym without a wallet');
    console.log('CWXMR_CHECK: actual App started Nym without a wallet');
    // Inject real read-only RPC at the wallet boundary; no account/signature/balance fabrication.
    metamask.provider = () => provider;
    console.log('CWXMR_CHECK: running complete liveApi.getInfo');
    const info = await liveApi.getInfo(AbortSignal.timeout(120000));
    if(!info.scanner_ready) throw Error(info.readiness_reason || 'Complete bridge info did not enable deposits');
    const peer = await readAttestedPeer(provider);
    return {bridgeInfo:{scanner_ready:info.scanner_ready,withdrawals_ready:info.withdrawals_ready,terms_configured:info.terms_configured,token_contract:info.token_contract,eligibleVaultCount:info.eligible_vaults.length},origin:peer.origin,spki:peer.spkiSha256,block:peer.blockHash};
  })()`;
  const result = await Promise.race([call('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true }, sessionId), new Promise((_, reject) => setTimeout(() => reject(Error('Browser Nym check exceeded 4 minutes')), 240000))]);
  if (result.exceptionDetails) throw Error(result.exceptionDetails.exception?.description ?? result.exceptionDetails.text);
  console.log(JSON.stringify(result.result.value, null, 2));
} finally {
  socket?.close();
  child.kill('SIGTERM');
  await new Promise(resolve => { child.once('exit', resolve); setTimeout(resolve, 2000).unref(); });
  await rm(profile, { recursive: true, force: true });
}
process.exit(0);
