#!/usr/bin/env node
// Operator verification uses explicit HTTPS RPC. Candidate-only mode never contacts Ethereum;
// the enclave must verify its exact calldata over Nym before signing or broadcasting.
import { createRequire } from 'node:module';
import { readFile, writeFile, mkdtemp, rm, stat } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { tmpdir } from 'node:os';
import { join, resolve, dirname, parse } from 'node:path';
import { pathToFileURL } from 'node:url';
import { validateNetwork, networkProof } from './network-prover.mjs';
const require = createRequire(new URL('../../contracts/package.json', import.meta.url));
const E = require('ethers'), cbor = require('cbor');
const run = promisify(execFile), coder = E.AbiCoder.defaultAbiCoder();
export const REVISION = '65c4a4233029ea3bbe16110a80731fcfd47cf300';
export const JOURNAL = 'tuple(uint8 result,uint8 trustedCertsPrefixLen,uint64 timestamp,bytes32[] certs,bytes userData,bytes nonce,bytes publicKey,tuple(uint64 index,tuple(bytes32 first,bytes16 second) value)[] pcrs,string moduleId)';
export const MINT = {Mint:[['vaultId','bytes32'],['depositId','bytes32'],['recipient','address'],['amountHandle','bytes32'],['inputProofHash','bytes32'],['nonce','uint256'],['deadline','uint64']].map(([name,type])=>({name,type}))};
const TYPE = 'CWXMRNitroMintBinding(uint256 chainId,address registry,address bridge,bytes32 vaultId,address signingKey,address decryptKey,bytes32 tlsKeyHash,bytes32 authKeyHash,uint64 policyVersion,bytes32 mintDigest)';
const bridgeAbi = require('./abi/Bridge.json');
const registryAbi = require('./abi/VaultRegistry.json');
const adapterAbi = require('./abi/NitroVerifierAdapter.json');
const MAX_JSON = 32 * 1024 * 1024, MAX_DOCUMENT = 65536;
function check(value, message) { if (!value) throw Error(message); }
function hex(value, bytes, label) { check(E.isHexString(value, bytes ?? true) && value.length > 2, `Invalid ${label}`); return value.toLowerCase(); }
function address(value) { const a=E.getAddress(value); check(a !== E.ZeroAddress,'Zero address'); return a; }
function uint(value, bits) { check(typeof value==='string' && /^(0|[1-9][0-9]*)$/.test(value),'Expected canonical decimal string'); const n=BigInt(value); check(n < 1n<<BigInt(bits),'Integer overflow'); return n; }
function same(a,b,label) { check(String(a).toLowerCase()===String(b).toLowerCase(),`${label} mismatch`); }
function exact(object, keys) { check(object && typeof object==='object' && !Array.isArray(object) && Object.keys(object).sort().join()===keys.split(',').sort().join(),'Unexpected object fields'); }
function https(url) { const u=new URL(url); check(u.protocol==='https:' && !u.username && !u.password && !u.hash,'Expected HTTPS URL without userinfo'); return u.href; }
export function validateConfig(config,{candidate=false}={}) {
  exact(config,'schema,automataRevision,cli,sourceDirectory,prover,rpcUrl,sp1RpcUrl,timeoutSeconds,pins'+(config.prover==='network'?',network':''));
  check(config.schema==='cwxmr-nitro-prover-v1' && config.automataRevision===REVISION,'Unsupported prover schema/revision');
  exact(config.cli,'binary,sha256'); hex(config.cli.sha256,32,'CLI SHA256');
  check(parse(config.cli.binary).root && parse(config.sourceDirectory).root,'Absolute CLI/source paths required');
  check(['cpu','network'].includes(config.prover),'Expected explicit cpu or network prover');
  if(config.prover==='network') validateNetwork(config);
  if(candidate) check(config.rpcUrl===null && config.sp1RpcUrl===null,'Candidate service requires null RPC URLs');
  else { https(config.rpcUrl); if(config.sp1RpcUrl!==null) https(config.sp1RpcUrl); }
  check(Number.isInteger(config.timeoutSeconds) && config.timeoutSeconds>0 && config.timeoutSeconds<=540,'Prover timeout must be 1..540 seconds');
  const p=config.pins;
  exact(p,'chainId,bridge,bridgeCodeHash,registry,registryCodeHash,adapter,adapterCodeHash,verifier,verifierCodeHash,zkVerifier,zkVerifierCodeHash,coprocessor,programId,rootCert,proofSelector,policyVersion,pcrTuple');
  check(Number.isSafeInteger(p.chainId) && p.chainId>0 && p.coprocessor===2,'Only pinned SP1 is supported by this tool');
  for(const name of ['bridge','registry','adapter','verifier','zkVerifier']) { address(p[name]); hex(p[`${name}CodeHash`],32,`${name} code hash`); }
  for(const name of ['programId','rootCert','pcrTuple']) { hex(p[name],32,name); check(p[name]!==E.ZeroHash,`Zero ${name}`); }
  hex(p.proofSelector,4,'proof selector'); check(uint(p.policyVersion,64)>0n,'Zero policy version');
  return p;
}
export function validateRequest(request,pins,nowMs=Date.now()) {
  exact(request,'schema,domain,registry,authorization,keys,policyVersion,publicKey,inputProof,signature');
  check(request.schema==='cwxmr-mint-proof-request-v1','Unsupported request schema');
  exact(request.domain,'name,version,chainId,verifyingContract');
  check(request.domain.name==='CWXMRBridge' && request.domain.version==='1','Incorrect EIP712 domain');
  same(request.domain.chainId,pins.chainId,'chain'); same(address(request.domain.verifyingContract),address(pins.bridge),'Bridge');
  same(address(request.registry),address(pins.registry),'registry'); same(request.policyVersion,pins.policyVersion,'policy');
  exact(request.authorization,'vaultId,depositId,recipient,amountHandle,inputProofHash,nonce,deadline');
  const a=request.authorization; for(const n of ['vaultId','depositId','amountHandle','inputProofHash']) hex(a[n],32,n);
  check(a.depositId!==E.ZeroHash && a.amountHandle!==E.ZeroHash,'Zero deposit/handle'); address(a.recipient);
  uint(a.nonce,256); check(uint(a.deadline,64)*1000n>=BigInt(nowMs),'Mint authorization expired');
  hex(request.publicKey,64,'raw64 public key'); hex(request.inputProof,undefined,'input proof'); hex(request.signature,65,'signature');
  same(E.Signature.from(request.signature).serialized,request.signature,'canonical ECDSA signature');
  same(E.keccak256(request.publicKey),a.vaultId,'public key/vault'); same(E.keccak256(request.inputProof),a.inputProofHash,'input proof');
  const signer=E.computeAddress(E.concat(['0x04',request.publicKey]));
  same(E.verifyTypedData(request.domain,MINT,a,request.signature),signer,'signature');
  exact(request.keys,'decryptKey,tlsKeyHash,authKeyHash');
  check(address(request.keys.decryptKey)!==signer,'Separate decrypt key required');
  for(const n of ['tlsKeyHash','authKeyHash']) { hex(request.keys[n],32,n); check(request.keys[n]!==E.ZeroHash,`Zero ${n}`); }
  const mintDigest=E.TypedDataEncoder.hash(request.domain,MINT,a);
  const userData=E.keccak256(coder.encode(['bytes32','uint256','address','address','bytes32','address','address','bytes32','bytes32','uint64','bytes32'],
    [E.id(TYPE),pins.chainId,pins.registry,pins.bridge,a.vaultId,signer,request.keys.decryptKey,request.keys.tlsKeyHash,request.keys.authKeyHash,request.policyVersion,mintDigest]));
  return {mintDigest,userData,nonce:E.toBeHex(a.nonce,32),publicKey:request.publicKey};
}
function decodeCbor(bytes) { return cbor.decodeFirstSync(bytes,{preferMap:true,preventDuplicateKeys:true,max_depth:16}); }
function buffer(value,label) { check(Buffer.isBuffer(value),`Expected ${label} bytes`); return E.hexlify(value); }
function fresh(timestamp,nowMs) { const t=BigInt(timestamp); check(t>0n && t<=BigInt(nowMs) && t+600000n>=BigInt(nowMs),'Stale/future Nitro document'); }
function pcrTuple(pcrs) {
  const selected=new Map();
  for(const [index,value] of pcrs) {
    const i=BigInt(index); if(i>2n) continue;
    check(i>=0n && !selected.has(i),'Duplicate PCR'); hex(value,48,'PCR'); check(!/^0x0+$/.test(value),'Debug PCR'); selected.set(i,value);
  }
  check(selected.size===3,'Missing PCR'); return E.keccak256(E.concat([0n,1n,2n].map(i=>selected.get(i))));
}
// Public-field preflight only. Authenticity is established by the genuine adapter eth_call below.
export function inspectDocument(bytes,expected,pins,nowMs=Date.now()) {
  check(bytes.length>0 && bytes.length<=MAX_DOCUMENT,'NSM document size');
  let sign1=decodeCbor(bytes); if(sign1 instanceof cbor.Tagged) { check(sign1.tag===18,'Wrong COSE tag'); sign1=sign1.value; }
  check(Array.isArray(sign1) && sign1.length===4,'Expected COSE_Sign1');
  const protectedHeaders=decodeCbor(sign1[0]);
  check(protectedHeaders instanceof Map && protectedHeaders.get(1)===-35 && sign1[1] instanceof Map,'Expected ES384 COSE headers');
  check(Buffer.isBuffer(sign1[3]) && sign1[3].length===96,'Invalid COSE signature size');
  const d=decodeCbor(sign1[2]); check(d instanceof Map && d.get('digest')==='SHA384','Invalid Nitro payload');
  for(const [field,exp] of [['public_key',expected.publicKey],['user_data',expected.userData],['nonce',expected.nonce]]) same(buffer(d.get(field),field),exp,field);
  const timestamp=d.get('timestamp'); check((typeof timestamp==='bigint'||Number.isSafeInteger(timestamp)),'Invalid Nitro timestamp'); fresh(timestamp,nowMs);
  check(d.get('pcrs') instanceof Map,'Invalid PCR map');
  const tuple=pcrTuple([...d.get('pcrs')].map(([i,v])=>[i,buffer(v,'PCR')])); same(tuple,pins.pcrTuple,'PCR policy');
  check(typeof d.get('module_id')==='string' && d.get('module_id').length>0,'Missing module ID');
  const certs=d.get('cabundle'); check(Array.isArray(certs) && certs.length>0 && certs.every(Buffer.isBuffer) && Buffer.isBuffer(d.get('certificate')),'Missing certificate chain');
  return {timestamp:BigInt(timestamp).toString(),moduleId:d.get('module_id'),pcrTuple:tuple,reportKeccak256:E.keccak256(bytes),reportSha256:'0x'+createHash('sha256').update(bytes).digest('hex')};
}
export function validateProof(proof,request,expected,document,pins,nowMs=Date.now()) {
  if(proof.schema==='cwxmr-network-proof-v1') {
    exact(proof,'schema,request_id,program,report_hash,locally_verified,seconds,output,proof');
    same(proof.program,pins.programId,'program ID');
    check(proof.locally_verified===true,'Unverified network proof');
    hex(proof.request_id,32,'network request'); same(proof.report_hash,document.reportKeccak256,'report hash');
    // Share all binding/PCR/freshness checks with the upstream format; aggregation metadata is
    // unused for a single-report proof and deliberately not asserted by the bounded driver.
    proof={zktype:'Succinct',zkvm_version:'6.1.0',proof_type:'Verifier',
      program_id:{verifier_id:proof.program,verifier_proof_id:E.ZeroHash,aggregator_id:E.ZeroHash},
      raw_proof:{encoded_proof:proof.proof,journal:proof.output},onchain_proof:proof.proof};
  }
  exact(proof,'zktype,zkvm_version,program_id,raw_proof,onchain_proof,proof_type');
  exact(proof.program_id,'verifier_id,verifier_proof_id,aggregator_id');
  exact(proof.raw_proof,'encoded_proof,journal');
  for(const value of Object.values(proof.program_id)) hex(value,32,'program identifier');
  hex(proof.raw_proof.encoded_proof,undefined,'serialized proof');
  check(typeof proof.zkvm_version==='string' && proof.zkvm_version.length>0 && proof.zkvm_version.length<=64,'Missing zkVM version');
  check(proof.zktype==='Succinct' && proof.proof_type==='Verifier','Expected single-report SP1 proof');
  same(proof.program_id?.verifier_id,pins.programId,'program ID');
  hex(proof.onchain_proof,undefined,'onchain proof'); check(proof.onchain_proof.length>10,'Empty/non-EVM proof'); same(proof.onchain_proof.slice(0,10),pins.proofSelector,'proof selector');
  const output=hex(proof.raw_proof?.journal,undefined,'journal');
  const [j]=coder.decode([JOURNAL],output); same(coder.encode([JOURNAL],[j]),output,'canonical journal');
  check(j.result===0n && j.certs.length>0 && j.trustedCertsPrefixLen>0n && j.trustedCertsPrefixLen<=j.certs.length,'Unsuccessful journal'); same(j.certs[0],pins.rootCert,'root certificate');
  for(const field of ['publicKey','userData','nonce']) same(j[field],expected[field],field);
  fresh(j.timestamp,nowMs); same(j.timestamp,document.timestamp,'document timestamp'); same(j.moduleId,document.moduleId,'module ID');
  same(pcrTuple(j.pcrs.map(p=>[p.index,E.concat([p.value.first,p.value.second])])),pins.pcrTuple,'PCR policy');
  validateRequest(request,pins,nowMs);
  return {keys:request.keys,policyVersion:request.policyVersion,output,proof:proof.onchain_proof};
}
async function readBounded(file,max=MAX_JSON) { check((await stat(file)).size<=max,'Input file too large'); const b=await readFile(file); check(b.length<=max,'Input file too large'); return b; }
async function json(file) { return JSON.parse(await readBounded(file)); }

// Returned runner is operator-only. Runtime/backend callers must use the separately reviewed Nym transport.
export async function checkChain(config,request) {
  const p=validateConfig(config), rpc=new E.FetchRequest(https(config.rpcUrl)); rpc.timeout=10000;
  const provider=new E.JsonRpcProvider(rpc);
  try {
    same((await provider.getNetwork()).chainId,p.chainId,'RPC chain');
    const block=await provider.getBlock('latest'); check(block && Date.now()-block.timestamp*1000<=120000 && block.timestamp*1000<=Date.now()+30000,'Stale/future RPC block');
    const at={blockTag:block.number};
    for(const name of ['bridge','registry','adapter','verifier','zkVerifier']) same(E.keccak256(await provider.getCode(p[name],block.number)),p[`${name}CodeHash`],`${name} code`);
    const adapter=new E.Contract(p.adapter,adapterAbi,provider),registry=new E.Contract(p.registry,registryAbi,provider),bridge=new E.Contract(p.bridge,bridgeAbi,provider);
    same(await bridge.registry(at),p.registry,'Bridge registry'); same(await registry.bridge(at),p.bridge,'registry Bridge'); same(await registry.adapter(at),p.adapter,'registry adapter');
    for(const field of ['verifier','verifierCodeHash','zkVerifier','zkVerifierCodeHash','rootCert','programId','proofSelector','coprocessor']) same(await adapter[field](at),p[field],`adapter ${field}`);
    check(await adapter.configurationValid(at),'Invalid live verifier configuration');
    check(await registry.approvedPcrTuples(p.policyVersion,p.pcrTuple,at),'PCR policy not approved');
    const a=request.authorization;
    check(!await bridge.consumedDeposits(a.depositId,at) && !await bridge.usedMintNonces(a.vaultId,a.nonce,at),'Mint replay');
    const record=await registry.vaults(a.vaultId,at);
    check(record.status===0n || record.status===1n,'Vault lifecycle blocks mint');
    if(record.status===1n) for(const key of ['decryptKey','tlsKeyHash','authKeyHash']) same(record[key],request.keys[key],`directory ${key}`);
    return {provider,adapter,block};
  } catch(e) { provider.destroy(); throw e; }
}
export function proverEnvironment(env,mode) {
  check(['cpu','network'].includes(mode),'Unknown prover mode');
  for(const name of ['DEV_MODE','RISC0_DEV_MODE','PICO_DEV_MODE']) check(!env[name] || ['0','false'].includes(env[name]),'Mock proving forbidden');
  check(!env.SP1_PROVER || env.SP1_PROVER===mode,'Environment prover differs from explicit mode');
  if(mode==='network') {
    check(env.CWXMR_ALLOW_PAID_PROVING==='1','Paid proving requires explicit CWXMR_ALLOW_PAID_PROVING=1');
    check(/^0x[0-9a-fA-F]{64}$/.test(env.SP1_PRIVATE_KEY??''),'SP1_PRIVATE_KEY required');
  }
  // Whitelist avoids implicit CONTRACT/.env, mock selectors and unrelated host credentials.
  const out={PATH:env.PATH,HOME:env.HOME,DEV_MODE:'false',SP1_PROVER:mode,RUST_LOG:'warn'};
  if(mode==='network') { out.SP1_PRIVATE_KEY=env.SP1_PRIVATE_KEY; out.NETWORK_PRIVATE_KEY=env.SP1_PRIVATE_KEY; }
  for(const name of ['SSL_CERT_FILE','SSL_CERT_DIR','TMPDIR']) if(env[name]) out[name]=env[name];
  return out;
}
async function prove(config,report,signal,request) {
  if(config.prover==='network') return networkProof(config,request,report,{signal});
  const source=resolve(config.sourceDirectory);
  same((await run('git',['-C',source,'rev-parse','HEAD'],{signal})).stdout.trim(),REVISION,'source revision');
  const patch=await readFile(new URL('./automata-host-prover.patch',import.meta.url),'utf8');
  check((await run('git',['-C',source,'diff','--binary','HEAD'],{signal,maxBuffer:1024*1024})).stdout===patch,'Prover source must contain exactly the reviewed host-only patch');
  const binary=resolve(config.cli.binary);
  same('0x'+createHash('sha256').update(await readBounded(binary,512*1024*1024)).digest('hex'),config.cli.sha256,'CLI checksum');
  const env=proverEnvironment(process.env,config.prover);
  if(config.prover==='cpu') {
    // This pinned SP1 build wraps Groth16 with Docker; fail before expensive CPU work.
    try { await run('docker',['info'],{signal,env,timeout:10000,maxBuffer:1024*1024}); }
    catch { throw Error('CPU Groth16 proving requires a running Docker daemon; docker info failed'); }
  }
  const dir=await mkdtemp(join(tmpdir(),'cwxmr-proof-'));
  try {
    // Upstream loads .env from CWD/parents. Refuse any parent .env; never load deployment secrets.
    for(let at=dir;;at=dirname(at)) { try { await stat(join(at,'.env')); throw Error('Prover working-directory ancestor contains .env'); } catch(e) { if(e.code!=='ENOENT') throw e; } if(dirname(at)===at) break; }
    const reportPath=join(dir,'attestation.report'),out=join(dir,'proof.json');
    await writeFile(reportPath,report,{flag:'wx',mode:0o600});
    const args=['prove','--report',reportPath,'--sp1','--prover',config.prover,'--out',out];
    if(config.prover==='network' && config.sp1RpcUrl!==null) args.push('--sp1-rpc-url',config.sp1RpcUrl);
    signal?.throwIfAborted();
    const processTask=run(binary,args,{cwd:dir,env,detached:true,maxBuffer:MAX_JSON});
    const stop=()=>{ if(Number.isInteger(processTask.child.pid)) { try { process.kill(-processTask.child.pid,'SIGKILL'); } catch {} } };
    const timer=setTimeout(stop,config.timeoutSeconds*1000);
    signal?.addEventListener('abort',stop,{once:true});
    if(signal?.aborted) stop();
    try { await processTask; }
    catch { throw Error(config.prover==='network'
      ? 'Pinned prover failed/timed out; inspect account before retrying (a paid request may remain active)'
      : 'CPU prover failed/timed out; inspect local prover and Docker resources before retrying'); }
    finally { clearTimeout(timer); signal?.removeEventListener('abort',stop); stop(); }
    return await json(out);
  } finally { await rm(dir,{recursive:true,force:true}); }
}
// Shape and binding checks only. The untrusted host cannot certify a valid proof or mint.
export function assembleCandidate(config,request,report,proof,nowMs=Date.now()) {
  const p=validateConfig(config,{candidate:true}),expected=validateRequest(request,p,nowMs);
  const document=inspectDocument(report,expected,p,nowMs);
  const evidence=validateProof(proof,request,expected,document,p,nowMs);
  const data=new E.Interface(bridgeAbi).encodeFunctionData('confidentialMint',[request.authorization,request.inputProof,request.signature,evidence]);
  return {schema:'cwxmr-mint-proof-candidate-v1',verification:'candidate_unverified',transaction:{to:p.bridge,data,value:'0'}};
}
export async function proveCandidate(config,request,report,{signal}={}) {
  const p=validateConfig(config,{candidate:true}),expected=validateRequest(request,p);
  inspectDocument(report,expected,p);
  const proof=await prove(config,report,signal,request);
  return assembleCandidate(config,request,report,proof);
}
export async function assemble(config,request,report,proof) {
  const p=validateConfig(config),expected=validateRequest(request,p),document=inspectDocument(report,expected,p);
  const evidence=validateProof(proof,request,expected,document,p);
  const {provider,adapter,block}=await checkChain(config,request);
  try {
    // eth_call executes genuine verification, including upstream certificate-cache writes, without persisting them.
    const verified=await adapter.verify.staticCall(evidence.output,evidence.proof,{blockTag:block.number});
    same(coder.encode([JOURNAL],[verified]),evidence.output,'adapter journal');
    fresh(verified.timestamp,block.timestamp*1000);
    same((await provider.getBlock(block.number)).hash,block.hash,'validation block hash');
    check(BigInt(request.authorization.deadline)>=BigInt(block.timestamp),'Expired at validation block');
    const data=new E.Interface(bridgeAbi).encodeFunctionData('confidentialMint',[request.authorization,request.inputProof,request.signature,evidence]);
    return {schema:'cwxmr-mint-proof-result-v1',request,evidence,reportSha256:document.reportSha256,
      adapterVerifiedAt:{blockHash:block.hash,blockNumber:block.number},transaction:{to:p.bridge,data,value:'0'},broadcast:false};
  } finally { provider.destroy(); }
}
async function main() {
  const argv=process.argv.slice(2), modeIndex=argv.indexOf('--prover');
  let selected;
  if(modeIndex>=0) { selected=argv[modeIndex+1]; check(['cpu','network'].includes(selected),'Expected --prover cpu|network'); argv.splice(modeIndex,2); }
  const [command,configFile,requestFile,reportFile,...rest]=argv;
  check(['inspect','prove','assemble'].includes(command),'Usage: prove-mint.mjs inspect CONFIG REQUEST REPORT | prove CONFIG REQUEST REPORT OUTPUT | assemble CONFIG REQUEST REPORT PROOF OUTPUT');
  check(rest.length===(command==='inspect'?0:command==='prove'?1:2),'Wrong command arguments');
  const config=await json(configFile),request=await json(requestFile),report=await readBounded(reportFile,MAX_DOCUMENT);
  if(selected) config.prover=selected;
  const p=validateConfig(config),expected=validateRequest(request,p),document=inspectDocument(report,expected,p);
  if(command==='inspect') { console.log(JSON.stringify({schemaValidated:true,cryptographicallyVerified:false,...expected,...document},null,2)); return; }
  const outputFile=rest.at(-1);
  const rawOutput=outputFile+'.automata.json';
  for(const file of command==='prove'?[outputFile,rawOutput]:[outputFile]) {
    try { await stat(file); throw Error('Output already exists'); } catch(e) { if(e.code!=='ENOENT') throw e; }
  }
  let proof;
  if(command==='prove') {
    // Validate all cheap request, document, environment and onchain policy checks before requesting paid work.
    if(config.prover==='cpu') proverEnvironment(process.env,config.prover);
    else check(process.env.CWXMR_ALLOW_PAID_PROVING==='1','Explicit paid proving opt-in required');
    const chain=await checkChain(config,request); chain.provider.destroy();
    proof=await prove(config,report,undefined,request);
    await writeFile(rawOutput,JSON.stringify(proof,null,2)+'\n',{flag:'wx',mode:0o600});
  } else proof=await json(rest[0]);
  const result=await assemble(config,request,report,proof);
  await writeFile(outputFile,JSON.stringify(result,null,2)+'\n',{flag:'wx',mode:0o600});
  console.log('Verified adapter evidence written; transaction not broadcast. Revalidate before submission.');
}
if(process.argv[1] && import.meta.url===pathToFileURL(resolve(process.argv[1])).href) main().catch(e=>{console.error(e.message);process.exitCode=1;});
