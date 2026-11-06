#!/usr/bin/env node
// Authenticate a live TLS key using a directory record established by a successful Automata-proven mint.
// This proves key possession and current directory policy, not fresh attestation of the running image.
// The configured RPC + finalized block must be independently trusted: this is not an Ethereum light client.
import { createRequire } from 'node:module';
import { createHash, X509Certificate } from 'node:crypto';
import tls from 'node:tls';
import { isIP } from 'node:net';
import { pathToFileURL } from 'node:url';
const require = createRequire(new URL('../../sidecar/package.json', import.meta.url));
const { Interface, keccak256 } = require('ethers');

export function connectPinned(endpoint, expectedSpki, path = '/health') {
  const url = new URL(endpoint);
  if (url.protocol !== 'https:' || url.username || url.password || url.pathname !== '/' || url.search || url.hash) throw Error('expected HTTPS origin');
  if (!/^(0x)?[a-fA-F0-9]{64}$/.test(expectedSpki)) throw Error('invalid SPKI pin');
  if (!/^\/[a-z?=0-9A-Fa-f-]*$/.test(path)) throw Error('invalid public path');
  const pin = expectedSpki.replace(/^0x/, '').toLowerCase();
  return new Promise((resolve, reject) => {
    const socket = tls.connect({ host: url.hostname, port: Number(url.port || 443), servername: isIP(url.hostname) ? undefined : url.hostname,
      minVersion: 'TLSv1.3', rejectUnauthorized: false });
    let bytes = Buffer.alloc(0);
    const fail = error => { socket.destroy(); reject(error); };
    socket.setTimeout(5000, () => fail(Error('TLS peer deadline')));
    socket.on('error', reject);
    socket.on('secureConnect', () => {
      try {
        const certificate = new X509Certificate(socket.getPeerCertificate().raw);
        const spki = certificate.publicKey.export({ type: 'spki', format: 'der' });
        if (createHash('sha256').update(spki).digest('hex') !== pin) throw Error('TLS key differs from authorized registry key');
        // Send requests only after the actual connection proves possession of the attested private key.
        socket.write(`GET ${path} HTTP/1.1\r\nHost: ${url.host}\r\nConnection: close\r\n\r\n`);
      } catch (error) { fail(error); }
    });
    socket.on('data', chunk => {
      bytes = Buffer.concat([bytes, chunk]);
      if (bytes.length > 65536) fail(Error('peer response bound exceeded'));
    });
    socket.on('end', () => {
      try {
        const text = bytes.toString('utf8');
        if (!text.startsWith('HTTP/1.1 200 OK\r\n')) throw Error('peer request rejected');
        resolve(JSON.parse(text.split('\r\n\r\n').slice(1).join('\r\n\r\n')));
      } catch (error) { reject(error); }
    });
  });
}
async function main() {
  const [rpc, chain, registry, codeHash, vaultId, blockHash, endpoint] = process.argv.slice(2);
  if (!endpoint) throw Error('usage: verify-peer.mjs HTTPS_RPC CHAIN_ID REGISTRY REGISTRY_CODEHASH VAULT_ID TRUSTED_FINALIZED_BLOCK_HASH HTTPS_ENDPOINT');
  if (new URL(rpc).protocol !== 'https:' || !/^0x[\da-fA-F]{64}$/.test(blockHash)) throw Error('HTTPS RPC and trusted finalized block hash required');
  let id = 0;
  async function call(method, params) {
    const response = await fetch(rpc, { method:'POST', headers:{'content-type':'application/json'},
      body:JSON.stringify({jsonrpc:'2.0',id:++id,method,params}), signal:AbortSignal.timeout(10000) });
    if (!response.ok) throw Error('registry RPC unavailable');
    const text = await response.text(); if (text.length > 262144) throw Error('RPC response bound exceeded');
    const value = JSON.parse(text); if (value.error || value.result === undefined) throw Error('registry RPC rejected pinned read');
    return value.result;
  }
  if (BigInt(await call('eth_chainId', [])) !== BigInt(chain)) throw Error('wrong registry chain');
  const block = await call('eth_getBlockByHash', [blockHash, false]);
  const now = BigInt(Math.floor(Date.now()/1000));
  if (!block || block.hash.toLowerCase() !== blockHash.toLowerCase() || now-BigInt(block.timestamp)>1200n || BigInt(block.timestamp)>now+30n) throw Error('stale or incorrect trusted block');
  const at = { blockHash, requireCanonical:true };
  if (keccak256(await call('eth_getCode', [registry, at])).toLowerCase() !== codeHash.toLowerCase()) throw Error('registry bytecode pin mismatch');
  const abi = new Interface(['function authorized(bytes32,bool) view returns (bool)',
    'function vaults(bytes32) view returns (address signingKey,address decryptKey,bytes32 tlsKeyHash,bytes32 authKeyHash,bytes32 pcrTuple,uint64 policyVersion,uint8 status)']);
  async function read(name, values) { return abi.decodeFunctionResult(name, await call('eth_call',[{to:registry,data:abi.encodeFunctionData(name,values)},at])); }
  if (!(await read('authorized',[vaultId,false]))[0]) throw Error('vault is not currently authorized');
  const record = await read('vaults',[vaultId]);
  if (record.status !== 1n) throw Error('vault inactive');
  const health = await connectPinned(endpoint, record.tlsKeyHash);
  console.log(JSON.stringify({authenticated_tls_key:true,vault_id:vaultId,registry_block:blockHash,health},null,2));
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(() => { console.error('Attested registry/TLS verification failed'); process.exitCode=1; });
}
