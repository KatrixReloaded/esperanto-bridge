// Synthetic public fields/proof bytes test protocol rejection only, never genuine Nitro/ZK verification.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { readFile } from 'node:fs/promises';
import { validateConfig,validateRequest,inspectDocument,validateProof,proverEnvironment,assembleCandidate,REVISION,JOURNAL,MINT } from './prove-mint.mjs';
import { createProverServer } from './prover-server.mjs';
const require=createRequire(new URL('../../contracts/package.json',import.meta.url));
const E=require('ethers'),cbor=require('cbor'),coder=E.AbiCoder.defaultAbiCoder();
const vector=JSON.parse(await readFile(new URL('../../contracts/test/fixtures/mint-binding-v1.json',import.meta.url)));
const now=100000;
async function fixture() {
 const wallet=new E.Wallet('0x'+'00'.repeat(31)+'01');
 const pcrs=[0,1,2].map(i=>[i,Buffer.alloc(48,i+1)]),tuple=E.keccak256(E.concat(pcrs.map(x=>x[1])));
 const pins={chainId:11155111,bridge:vector.domain.verifyingContract,registry:vector.bindingDomain.registry,
  adapter:'0x'+'99'.repeat(20),verifier:'0x'+'aa'.repeat(20),zkVerifier:'0x'+'bb'.repeat(20),coprocessor:2,programId:E.id('program'),rootCert:E.id('root'),proofSelector:'0x12345678',policyVersion:'1',pcrTuple:tuple};
 for(const n of ['bridge','registry','adapter','verifier','zkVerifier']) pins[n+'CodeHash']=E.id(n);
 const config={schema:'cwxmr-nitro-prover-v1',automataRevision:REVISION,cli:{binary:'/tmp/nitro-attest-cli',sha256:E.id('binary')},sourceDirectory:'/tmp/source',prover:'cpu',rpcUrl:'https://operator.invalid',sp1RpcUrl:null,timeoutSeconds:540,pins};
 const authorization={...vector.mint,deadline:String(vector.mint.deadline)};
 const request={schema:'cwxmr-mint-proof-request-v1',domain:vector.domain,registry:pins.registry,authorization,
  keys:{decryptKey:vector.identity.decrypt_key,tlsKeyHash:vector.identity.tls_key_hash,authKeyHash:vector.identity.auth_key_hash},policyVersion:'1',publicKey:vector.identity.public_key,inputProof:vector.inputProof,
  signature:await wallet.signTypedData(vector.domain,MINT,authorization)};
 const expected=validateRequest(request,pins,now);
 const payload=new Map([['module_id','SYNTHETIC TEST ONLY'],['timestamp',now],['digest','SHA384'],['pcrs',new Map(pcrs)],['certificate',Buffer.from('not a certificate')],['cabundle',[Buffer.from('not a certificate')]],
  ['public_key',Buffer.from(E.getBytes(expected.publicKey))],['user_data',Buffer.from(E.getBytes(expected.userData))],['nonce',Buffer.from(E.getBytes(expected.nonce))]]);
 const encode=(d=payload)=>cbor.encode([cbor.encode(new Map([[1,-35]])),new Map(),cbor.encode(d),Buffer.alloc(96)]);
 const report=encode(),document=inspectDocument(report,expected,pins,now);
 const journal={result:0,trustedCertsPrefixLen:1,timestamp:now,certs:[pins.rootCert],userData:expected.userData,nonce:expected.nonce,publicKey:expected.publicKey,
  pcrs:pcrs.map(([index,value])=>({index,value:{first:E.hexlify(value.subarray(0,32)),second:E.hexlify(value.subarray(32))}})),moduleId:'SYNTHETIC TEST ONLY'};
 const proof={zktype:'Succinct',zkvm_version:'fixture',program_id:{verifier_id:pins.programId,verifier_proof_id:E.id('vk'),aggregator_id:E.id('aggregate')},proof_type:'Verifier',raw_proof:{encoded_proof:'0xaabb',journal:coder.encode([JOURNAL],[journal])},onchain_proof:'0x12345678aabb'};
 return {wallet,pins,config,request,expected,payload,encode,report,document,journal,proof};
}
test('canonical request and binary COSE fields match shared Rust vector; evidence encodes exact contract call',async()=>{
 const f=await fixture(); validateConfig(f.config);
 assert.equal(f.expected.mintDigest,vector.mintDigest);assert.equal(f.expected.userData,vector.userData);
 const evidence=validateProof(f.proof,f.request,f.expected,f.document,f.pins,now);
 const abi=require('./abi/Bridge.json'),iface=new E.Interface(abi);
 const call=iface.encodeFunctionData('confidentialMint',[f.request.authorization,f.request.inputProof,f.request.signature,evidence]);
 const decoded=iface.decodeFunctionData('confidentialMint',call);
 assert.equal(decoded.evidence.output,f.proof.raw_proof.journal);assert.equal(decoded.evidence.proof,f.proof.onchain_proof);
 assert.equal(inspectDocument(cbor.encode(new cbor.Tagged(18,cbor.decodeFirstSync(f.report))),f.expected,f.pins,now).timestamp,String(now));
});
test('request rejects altered authorization/domain/key/input/signature and unsafe numbers',async()=>{
 const f=await fixture();
 for(const mutate of [r=>r.authorization.recipient=E.ZeroAddress,r=>r.authorization.nonce=7,r=>r.authorization.nonce='07',r=>r.authorization.deadline='1',r=>r.inputProof='0x04',r=>r.publicKey='0x'+'11'.repeat(64),r=>r.signature=r.signature.slice(0,-2)+'00',r=>r.domain.chainId=1,r=>r.registry=E.ZeroAddress,r=>r.keys.decryptKey=f.wallet.address,r=>r.extra='untrusted']) {
  const r=structuredClone(f.request);mutate(r);assert.throws(()=>validateRequest(r,f.pins,now));
 }
 const changed=structuredClone(f.request);changed.authorization.recipient='0x'+'22'.repeat(20);changed.signature=await f.wallet.signTypedData(changed.domain,MINT,changed.authorization);
 const next=validateRequest(changed,f.pins,now);assert.notEqual(next.userData,f.expected.userData);
 assert.throws(()=>inspectDocument(f.report,next,f.pins,now),/user_data/);
});
test('NSM parser rejects unbound/stale/debug/missing PCR, discovery, CBOR duplication/trailing input',async()=>{
 const f=await fixture();
 for(const [name,value] of [['timestamp',now+1],['timestamp',now-700000],['public_key',Buffer.alloc(64)],['nonce',Buffer.alloc(32)],['user_data',Buffer.alloc(32)],['digest','SHA256'],['pcrs',new Map([[0,Buffer.alloc(48)]])]]) {
  const payload=new Map(f.payload);payload.set(name,value);assert.throws(()=>inspectDocument(f.encode(payload),f.expected,f.pins,now));
 }
 assert.throws(()=>inspectDocument(Buffer.concat([f.report,Buffer.from([0])]),f.expected,f.pins,now));
 assert.throws(()=>inspectDocument(Buffer.from('a2616101616102','hex'),f.expected,f.pins,now),/Duplicate/);
 assert.throws(()=>inspectDocument(cbor.encode(new cbor.Tagged(19,[])),f.expected,f.pins,now),/COSE tag/);
});
test('proof rejects wrong backend/program/selector/root, unsuccessful or noncanonical journal, and report substitutions',async()=>{
 const f=await fixture();
 for(const change of [{zktype:'Pico'},{proof_type:'Aggregator'},{onchain_proof:'0x'},{onchain_proof:'0x87654321aabb'},{program_id:{verifier_id:E.ZeroHash}}]) assert.throws(()=>validateProof({...f.proof,...change},f.request,f.expected,f.document,f.pins,now));
 for(const change of [{result:1},{certs:[E.ZeroHash]},{nonce:E.ZeroHash},{timestamp:now-1},{moduleId:'different report'},{pcrs:[]},{trustedCertsPrefixLen:0}]) {
  const proof={...f.proof,raw_proof:{encoded_proof:'0xaabb',journal:coder.encode([JOURNAL],[{...f.journal,...change}])}};
  assert.throws(()=>validateProof(proof,f.request,f.expected,f.document,f.pins,now));
 }
 assert.throws(()=>validateProof({...f.proof,raw_proof:{...f.proof.raw_proof,journal:f.proof.raw_proof.journal+'00'}},f.request,f.expected,f.document,f.pins,now),/canonical/);
});
test('CPU default forwards no proving wallet; network requires explicit paid opt-in; mock/env overrides fail',async()=>{
 const env={PATH:'/bin',HOME:'/tmp',SP1_PRIVATE_KEY:'0x'+'11'.repeat(32),UNRELATED_SECRET:'never forward'};
 const cpu=proverEnvironment(env,'cpu');assert.equal(cpu.SP1_PROVER,'cpu');assert.equal(cpu.SP1_PRIVATE_KEY,undefined);assert.equal(cpu.UNRELATED_SECRET,undefined);
 assert.throws(()=>proverEnvironment(env,'network'),/Paid proving/);
 const network=proverEnvironment({...env,CWXMR_ALLOW_PAID_PROVING:'1'},'network');assert.equal(network.SP1_PROVER,'network');
 for(const field of ['DEV_MODE','RISC0_DEV_MODE','PICO_DEV_MODE']) assert.throws(()=>proverEnvironment({...env,[field]:'1'},'cpu'),/Mock/);
 assert.throws(()=>proverEnvironment({...env,SP1_PROVER:'mock'},'cpu'));
});
test('config rejects unsupported revision/backend, missing pins, credentials in URLs and wrong mode',async()=>{
 const f=await fixture();
 for(const mutate of [c=>c.automataRevision='unreviewed',c=>c.pins.programId=null,c=>c.pins.coprocessor=1,c=>c.prover='mock',c=>c.rpcUrl='http://insecure',c=>c.rpcUrl='https://user:secret@example.org',c=>c.timeoutSeconds=601]) {
  const config=structuredClone(f.config);mutate(config);assert.throws(()=>validateConfig(config));
 }
});

test('real upstream historical NSM encoding parses but cannot authorize a bridge mint',async()=>{
 const f=await fixture();
 const report=await readFile(new URL('../../contracts/test/fixtures/automata-attestation-1.report',import.meta.url));
 assert.throws(()=>inspectDocument(report,f.expected,f.pins,now),/public_key mismatch/);
});

test('candidate assembly is offline, explicitly unverified and requires CPU without RPC URLs',async()=>{
 const f=await fixture(),config={...f.config,rpcUrl:null};
 const result=assembleCandidate(config,f.request,f.report,f.proof,now);
 assert.equal(result.verification,'candidate_unverified');
 assert.equal(result.schema,'cwxmr-mint-proof-candidate-v1');
 assert.equal(result.transaction.to,config.pins.bridge);
 assert.equal(result.transaction.value,'0');
 const decoded=new E.Interface(require('./abi/Bridge.json')).decodeFunctionData('confidentialMint',result.transaction.data);
 assert.equal(decoded.evidence.proof,f.proof.onchain_proof);
 assert.throws(()=>assembleCandidate({...config,rpcUrl:'https://rpc.invalid'},f.request,f.report,f.proof,now),/null RPC/);
 assert.throws(()=>assembleCandidate({...config,prover:'network'},f.request,f.report,f.proof,now),/requires CPU/);
 assert.throws(()=>assembleCandidate(config,f.request,f.report,{...f.proof,onchain_proof:'0xdeadbeef1234'},now),/selector/);
 await serve(config,{prover:async(c,r,d)=>assembleCandidate(c,r,d,f.proof,now)},async url=>{
  const response=await fetch(url,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({request:f.request,document:f.report.toString('base64')})});
  assert.equal(response.status,200);assert.deepEqual(await response.json(),result);
 });
});

async function serve(config,options,fn) {
 const server=createProverServer(config,options);
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 try { await fn(`http://127.0.0.1:${server.address().port}/prove`); }
 finally { server.closeAllConnections(); await new Promise(resolve=>server.close(resolve)); }
}
test('loopback service bounds input, rejects malformed documents and sanitizes failures',async()=>{
 const f=await fixture(),config={...f.config,rpcUrl:null};let calls=0;
 const prover=async()=>{calls++;throw Error('private process stderr must not escape');};
 await serve(config,{prover},async url=>{
  const post=body=>fetch(url,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});
  for(const body of [{request:f.request,document:'@@@'},{request:f.request,document:'AA=='+' '.repeat(512*1024)},{request:f.request,document:Buffer.alloc(65537).toString('base64')}]) {
   const response=await post(body);assert.equal(response.status,400);
  }
  assert.equal(calls,0);
  const response=await post({request:f.request,document:f.report.toString('base64')});
  assert.equal(response.status,502);assert.deepEqual(await response.json(),{error:'prover_failed'});assert.equal(calls,1);
 });
});
test('loopback service allows one job and aborts it before its bounded total deadline',async()=>{
 const f=await fixture(),config={...f.config,rpcUrl:null};let started,aborted=false;
 const running=new Promise(resolve=>{started=resolve;});
 const prover=async(_c,_r,_d,{signal})=>{started();await new Promise((resolve,reject)=>signal.addEventListener('abort',()=>{aborted=true;reject(Error('aborted'));},{once:true}));};
 await serve(config,{prover,deadlineMs:100},async url=>{
  const post=()=>fetch(url,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({request:f.request,document:f.report.toString('base64')})});
  const first=post();await running;
  const busy=await post();assert.equal(busy.status,503);assert.deepEqual(await busy.json(),{error:'prover_busy'});
  const timeout=await first;assert.equal(timeout.status,504);assert.deepEqual(await timeout.json(),{error:'prover_timeout'});assert.equal(aborted,true);
 });
});
