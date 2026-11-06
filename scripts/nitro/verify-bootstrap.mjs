#!/usr/bin/env node
// Operator-only first-contact authentication. Fetch public data provisionally, then execute
// the pinned Nitro verifier locally and bind the verified report to the live TLS key.
import { createRequire } from 'node:module';
import { createHash, randomBytes, X509Certificate } from 'node:crypto';
import { execFile } from 'node:child_process';
import { mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { join, resolve } from 'node:path';
import tls from 'node:tls';
import { promisify } from 'node:util';
import { pathToFileURL } from 'node:url';
import { connectPinned } from './verify-peer.mjs';
import { JOURNAL } from './prove-mint.mjs';
const require=createRequire(new URL('../../contracts/package.json',import.meta.url));
const E=require('ethers'), coder=E.AbiCoder.defaultAbiCoder();
const run=promisify(execFile);
const TYPE='CWXMRNitroIdentityBinding(uint256 chainId,address registry,address bridge,bytes32 vaultId,address signingKey,address decryptKey,bytes32 tlsKeyHash,bytes32 authKeyHash,uint64 policyVersion,bytes32 nonce)';
function check(ok,message) { if(!ok) throw Error(message); }
function same(a,b,label) { check(String(a).toLowerCase()===String(b).toLowerCase(),`${label} mismatch`); }
function hex(value,length) { const v=value?.startsWith('0x')?value:`0x${value}`; check(E.isHexString(v,length),'Invalid identity field'); return v; }
export function validateIdentity(journal,identity,nonce,config,spki,now=Date.now()) {
  check(identity && Object.keys(identity).sort().join()==='auth_key_hash,decrypt_key,public_key,signing_key,tls_key_hash,vault_id','Unexpected identity fields');
  const pub=hex(identity.public_key,64),vault=hex(identity.vault_id,32),signer=hex(identity.signing_key,20);
  same(E.keccak256(pub),vault,'vault ID'); same(E.computeAddress('0x04'+pub.slice(2)),signer,'signing key');
  same(hex(identity.tls_key_hash,32),spki,'TLS SPKI');
  if(config.expectedVaultId!==null) same(vault,config.expectedVaultId,'expected restored vault');
  const d=config.domain;
  check(d.chain_id===11155111 && Number.isSafeInteger(d.policy_version) && d.policy_version>0,'Unsupported discovery domain');
  const binding=E.keccak256(coder.encode(['bytes32','uint256','address','address','bytes32','address','address','bytes32','bytes32','uint64','bytes32'],
    [E.id(TYPE),d.chain_id,d.registry,d.bridge,vault,signer,hex(identity.decrypt_key,20),hex(identity.tls_key_hash,32),hex(identity.auth_key_hash,32),d.policy_version,nonce]));
  check(journal.result===0n && journal.certs.length>0 && journal.trustedCertsPrefixLen>0n && journal.trustedCertsPrefixLen<=journal.certs.length,'Unsuccessful NSM verification');
  same(journal.certs[0],config.rootCert,'AWS root');
  same(journal.publicKey,pub,'attested signing key'); same(journal.nonce,nonce,'challenge'); same(journal.userData,binding,'discovery binding');
  check(journal.timestamp<=BigInt(now) && journal.timestamp+600000n>=BigInt(now),'Stale/future attestation');
  const pcrs=new Map();
  for(const p of journal.pcrs) {
    if(p.index>2n) continue;
    check(p.index>=0n && !pcrs.has(p.index),'Duplicate PCR');
    const value=E.concat([p.value.first,p.value.second]);
    check(!/^0x0+$/.test(value),'Debug PCR'); pcrs.set(p.index,value);
  }
  check(pcrs.size===3,'Missing PCR');
  same(E.keccak256(E.concat([0n,1n,2n].map(i=>pcrs.get(i)))),config.pcrTuple,'approved image');
  return {vaultId:vault,signingKey:signer,tlsSpki:spki,attestationTimestamp:String(journal.timestamp)};
}
function provisionalSpki(endpoint) {
  const u=new URL(endpoint);
  check(u.protocol==='https:' && !u.username && !u.password && u.pathname==='/' && !u.search && !u.hash,'HTTPS origin required');
  return new Promise((resolve,reject)=>{
    const socket=tls.connect({host:u.hostname,port:Number(u.port||443),servername:isIP(u.hostname)?undefined:u.hostname,minVersion:'TLSv1.3',rejectUnauthorized:false});
    socket.setTimeout(5000,()=>socket.destroy(Error('TLS discovery timeout')));
    socket.on('error',reject);
    socket.on('secureConnect',()=>{
      try {
        const key=new X509Certificate(socket.getPeerCertificate().raw).publicKey.export({type:'spki',format:'der'});
        resolve('0x'+createHash('sha256').update(key).digest('hex'));
      } catch(error) { reject(error); }
      finally { socket.destroy(); }
    });
  });
}
async function main() {
  const [path,out]=process.argv.slice(2);
  check(process.argv.length===4,'Usage: verify-bootstrap.mjs PUBLIC_CONFIG NEW_OUTPUT_DIRECTORY');
  check((await stat(path)).size<=65536,'Config too large');
  const config=JSON.parse(await readFile(path));
  check(config.schema==='cwxmr-bootstrap-v1','Invalid bootstrap configuration');
  for(const name of ['rootCert','programId','pcrTuple']) check(E.isHexString(config[name],32) && config[name]!==E.ZeroHash,`Invalid ${name}`);
  check((await stat(config.cli.binary)).size<=512*1024*1024,'Prover binary too large');
  same('0x'+createHash('sha256').update(await readFile(config.cli.binary)).digest('hex'),config.cli.sha256,'pinned verifier binary');
  await mkdir(out,{mode:0o700});
  const spki=await provisionalSpki(config.endpoint);
  const identity=await connectPinned(config.endpoint,spki,'/identity');
  const nonce=E.hexlify(randomBytes(32));
  const attestation=await connectPinned(config.endpoint,spki,`/attestation?nonce=${nonce}`);
  check(attestation.purpose==='identity-discovery-only','Wrong attestation purpose');
  check(JSON.stringify(attestation.identity)===JSON.stringify(identity),'Identity changed during discovery');
  const report=Buffer.from(attestation.document,'base64');
  check(report.length>0 && report.length<=65536 && report.toString('base64')===attestation.document,'Invalid NSM document');
  const reportPath=join(resolve(out),'attestation.report');
  await writeFile(reportPath,report,{flag:'wx',mode:0o600});
  // inspect never reads a wallet, contacts the prover network or submits a paid proof.
  await run(config.cli.binary,['inspect',reportPath,resolve(out),'unused'],{timeout:60000,maxBuffer:65536});
  const execution=JSON.parse(await readFile(join(out,'execution.json')));
  check(execution.schema==='cwxmr-nsm-execution-v1' && execution.proof_submitted===false,'Unexpected verification result');
  same(execution.report_hash,E.keccak256(report),'executed NSM document'); same(execution.program,config.programId,'pinned guest program');
  const [journal]=coder.decode([JOURNAL],execution.output);
  same(coder.encode([JOURNAL],[journal]),execution.output,'canonical journal');
  const verified=validateIdentity(journal,identity,nonce,config,spki);
  const health=await connectPinned(config.endpoint,spki,'/health');
  const result={schema:'cwxmr-verified-bootstrap-v1',...verified,identity,nonce,health,verifiedAt:new Date().toISOString(),paidProof:false};
  await writeFile(join(out,'verified-identity.json'),JSON.stringify(result,null,2)+'\n',{flag:'wx',mode:0o600});
  console.log(JSON.stringify(result,null,2));
}
if(process.argv[1] && import.meta.url===pathToFileURL(resolve(process.argv[1])).href) main().catch(e=>{console.error(e.message);process.exitCode=1;});
