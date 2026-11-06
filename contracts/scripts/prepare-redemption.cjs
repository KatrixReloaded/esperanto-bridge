#!/usr/bin/env node
// Local file preparation only. No wallet access, network transport or transaction submission.
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { Interface, getAddress, parseUnits, keccak256, toUtf8Bytes } = require('ethers');
const iface = new Interface(require('../abi/Bridge.json'));
const MODE = 'UNSAFE_TEST_NO_NITRO';
const HASH = /^0x[0-9a-fA-F]{64}$/;
const fail = () => { throw new Error('Invalid local redemption input or response'); };
const hash = v => typeof v === 'string' && HASH.test(v) && BigInt(v) !== 0n ? v.toLowerCase() : fail();
function amountAtomic(value) {
  if (typeof value !== 'string' || !/^(0|[1-9]\d*)(\.\d{1,12})?$/.test(value) || value.length > 32) fail();
  const n = parseUnits(value, 12);
  if (n <= 0n || n > (1n << 64n) - 1n) fail();
  return n.toString();
}
function terms(input) {
  if (input.mode !== MODE || input.chainId !== 11155111) fail();
  const user = getAddress(input.user);
  if (BigInt(user) === 0n) fail();
  const pins = {};
  for (const name of ['bridge','registry','adapter','verifier']) {
    pins[name] = getAddress(input.pins[name]);
    if (BigInt(pins[name]) === 0n) fail();
    pins[`${name}_code_hash`] = hash(input.pins[`${name}_code_hash`]);
  }
  if (new Set(['bridge','registry','adapter','verifier'].map(k => pins[k])).size !== 4) fail();
  if (!Array.isArray(input.vaultIds) || input.vaultIds.length < 1 || input.vaultIds.length > 16) fail();
  const vaultIds = input.vaultIds.map(hash).sort((a,b) => BigInt(a) < BigInt(b) ? -1 : 1);
  if (new Set(vaultIds).size !== vaultIds.length) fail();
  return { mode: MODE, chainId: 11155111, user, pins, feeTermsHash: hash(input.feeTermsHash), vaultIds };
}
function words(encoded) {
  if (typeof encoded !== 'string' || !/^0x[0-9a-f]{192}$/.test(encoded)) fail();
  const bytes = Buffer.from(encoded.slice(2), 'hex');
  if (bytes[0] !== 1 || bytes[1] !== 2 || bytes[2] > 1 || bytes.subarray(71).some(b => b !== 0)) fail();
  return [0,32,64].map(i => BigInt(`0x${bytes.subarray(i,i+32).toString('hex')}`).toString());
}
function prepare(input, encode) {
  const scope = terms(input);
  if (typeof input.destination !== 'string' || input.destination.length > 256) fail();
  const encryptionRequest = { contract: scope.pins.bridge, user: scope.user, amount: amountAtomic(input.amount), destination: words(encode(input.destination)) };
  return { ...scope, encryptionRequest, requestHash: keccak256(toUtf8Bytes(JSON.stringify(encryptionRequest))) };
}
function finish(context, response) {
  const scope = terms(context), request = context.encryptionRequest;
  if (getAddress(request.contract) !== scope.pins.bridge || getAddress(request.user) !== scope.user ||
      typeof request.amount !== 'string' || !/^[1-9]\d{0,19}$/.test(request.amount) || BigInt(request.amount) > (1n<<64n)-1n ||
      !Array.isArray(request.destination) || request.destination.length !== 3 || request.destination.some(w => typeof w !== 'string' || !/^(0|[1-9]\d{0,77})$/.test(w) || BigInt(w) >= (1n<<256n)) ||
      context.requestHash !== keccak256(toUtf8Bytes(JSON.stringify(request)))) fail();
  words('0x'+request.destination.map(w => BigInt(w).toString(16).padStart(64,'0')).join(''));
  // The pinned SDK's current ciphertext version is 0. Byte30 is FHE type, bytes22..29 chain ID.
  if (!Array.isArray(response.handles) || response.handles.length !== 4 || Object.keys(response).sort().join(',') !== 'handles,inputProof') fail();
  const handles = response.handles.map((value,i) => {
    const h = hash(value), bytes = Buffer.from(h.slice(2),'hex');
    if (bytes[31] !== 0 || bytes[30] !== (i === 0 ? 5 : 8) || bytes.readBigUInt64BE(22) !== 11155111n) fail();
    return h;
  });
  if (new Set(handles).size !== 4 || typeof response.inputProof !== 'string' || !/^0x(?:[0-9a-fA-F]{2})+$/.test(response.inputProof) || response.inputProof.length > 2*1024*1024) fail();
  // Proof authenticity and its contract/user binding are checked by Bridge/FHE at execution.
  const data = iface.encodeFunctionData('requestRedemption', [handles[0], handles.slice(1), response.inputProof, scope.feeTermsHash, scope.vaultIds]);
  return { chainId: 11155111, from: scope.user, to: scope.pins.bridge, value: '0x0', data };
}
function read(file) {
  if (fs.statSync(file).size > 3*1024*1024) fail();
  return JSON.parse(fs.readFileSync(file,'utf8'));
}
function writePrivate(file, value) {
  const fd = fs.openSync(file, 'wx', 0o600);
  try { fs.writeFileSync(fd, JSON.stringify(value,null,2)+'\n'); fs.fsyncSync(fd); }
  finally { fs.closeSync(fd); }
}
function main(args) {
  if (args[0] === 'prepare' && (args.length === 3 || args.length === 4)) {
    const encoder = args[3] ?? path.resolve(__dirname,'../../service/target/debug/cwxmr-destination');
    const context = prepare(read(args[1]), destination => {
      const result = spawnSync(encoder, [], { input: destination+'\n', encoding:'utf8', timeout:10000, maxBuffer:4096 });
      if (result.status !== 0 || result.error) fail();
      return result.stdout.trim();
    });
    writePrivate(args[2]+'.context.json', context);
    writePrivate(args[2]+'.encrypt.json', context.encryptionRequest);
    console.log('Prepared private files. Pass .encrypt.json to local /encrypt-redemption; then run finish. Nothing submitted.');
  } else if (args[0] === 'finish' && args.length === 4) {
    const tx = finish(read(args[1]), read(args[2]));
    writePrivate(args[3], tx);
    console.log('Unsigned Bridge request saved (0600). Review before user approval; proof not verified locally.');
    console.log('User execution only (replace UNSIGNED_JSON with the saved file path):');
    console.log('cast send --account personal --from '+tx.from+' --chain 11155111 --rpc-url "$SEPOLIA_RPC_URL" "$(jq -r .to UNSIGNED_JSON)" --data "$(jq -r .data UNSIGNED_JSON)"');
  } else throw new Error('Usage: prepare-redemption.cjs prepare INPUT_JSON OUTPUT_PREFIX [ENCODER] | finish CONTEXT_JSON RESPONSE_JSON UNSIGNED_JSON');
}
module.exports = { amountAtomic, terms, words, prepare, finish, writePrivate };
if (require.main === module) { try { main(process.argv.slice(2)); } catch { console.error('Local redemption preparation failed; validate input, permissions, encoder and sidecar response. No transaction submitted.'); process.exitCode=1; } }
