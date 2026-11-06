// Operator-side spending journal. No Ethereum RPC and no access to enclave secrets.
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { lstat, mkdir, open, readFile } from 'node:fs/promises';
import { dirname, isAbsolute, join } from 'node:path';
import { promisify } from 'node:util';

const run=promisify(execFile);
function check(ok,message) { if(!ok) throw Error(message); }
export function validateNetwork(config) {
  const n=config.network;
  check(n && Object.keys(n).sort().join()==='maxRequests,stateDirectory,walletFile','Explicit bounded network configuration required');
  check(isAbsolute(n.walletFile) && isAbsolute(n.stateDirectory),'Absolute wallet/state paths required');
  check(Number.isInteger(n.maxRequests) && n.maxRequests>=1 && n.maxRequests<=10,'Network budget must be 1..10 requests, each capped at 1 PROVE');
  check(config.sp1RpcUrl===null,'Bounded network prover uses pinned Succinct Mainnet');
}
async function durable(file,bytes) {
  const handle=await open(file,'wx',0o600);
  try { await handle.writeFile(bytes); await handle.sync(); } finally { await handle.close(); }
  const parent=await open(dirname(file),'r');
  try { await parent.sync(); } finally { await parent.close(); }
}
// Atomic slots cap attempts even across concurrent service processes. Failed/ambiguous attempts
// retain their slots; deleting state is an explicit operator budget reset, never an automatic retry.
export async function reserveAttempt(directory,key,maxRequests) {
  check(/^[a-f0-9]{64}$/.test(key),'Invalid request key');
  check(Number.isInteger(maxRequests) && maxRequests>=1 && maxRequests<=10,'Invalid request budget');
  await mkdir(directory,{recursive:true,mode:0o700});
  const info=await lstat(directory);
  check(info.isDirectory() && (info.mode&0o077)===0,'Private regular network state directory required');
  const job=join(directory,key);
  await mkdir(job,{mode:0o700}); // Existing jobs never submit again, even with a new NSM timestamp.
  for(let slot=0;slot<maxRequests;slot++) {
    try { await durable(join(directory,`attempt-${slot}.json`),JSON.stringify({key,capAtomicProve:'1000000000000000000'})); return job; }
    catch(error) { if(error.code!=='EEXIST') throw error; }
  }
  throw Error('Paid proof attempt budget exhausted');
}
export async function networkProof(config,request,report,{signal}={}) {
  validateNetwork(config);
  check(process.env.CWXMR_ALLOW_PAID_PROVING==='1','Explicit paid proving opt-in required');
  const binary=await lstat(config.cli.binary);
  check(binary.isFile() && binary.size<=512*1024*1024,'Invalid network prover binary');
  const hash='0x'+createHash('sha256').update(await readFile(config.cli.binary)).digest('hex');
  check(hash.toLowerCase()===config.cli.sha256.toLowerCase(),'Network prover checksum mismatch');
  signal?.throwIfAborted();
  const a=request.authorization;
  const key=createHash('sha256').update(JSON.stringify([request.domain.chainId,
    request.domain.verifyingContract.toLowerCase(),a.vaultId.toLowerCase(),a.depositId.toLowerCase(),a.nonce])).digest('hex');
  const job=await reserveAttempt(config.network.stateDirectory,key,config.network.maxRequests);
  await durable(join(job,'attestation.report'),report);
  await durable(join(job,'mint-request.json'),JSON.stringify(request));
  const env={PATH:process.env.PATH,HOME:process.env.HOME,RUST_LOG:'warn'};
  for(const name of ['SSL_CERT_FILE','SSL_CERT_DIR','TMPDIR']) if(process.env[name]) env[name]=process.env[name];
  // The binary reads the wallet file internally. No private key appears in argv or child output.
  await run(config.cli.binary,['submit',join(job,'attestation.report'),job,config.network.walletFile],
    {env,signal,timeout:config.timeoutSeconds*1000,killSignal:'SIGKILL',maxBuffer:512*1024});
  const file=join(job,'verified-proof.json');
  check((await lstat(file)).size<=512*1024,'Network proof result too large');
  return JSON.parse(await readFile(file,'utf8'));
}
