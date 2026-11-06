const {assert,E,receipt,rejects,jump,fixture,evidence,register,enroll}=require('./helpers.cjs');
describe('Nitro admission and lifecycle',function(){
 it('registers exact authenticated fields, consumes challenge, refreshes only same active bundle',async()=>{
  const f=await fixture(),v=await enroll(f);
  assert.equal(await f.registry.authorized(v.vaultId,false),true);
  await rejects(()=>register(f,v),'InvalidEvidence');
  const fresh=await evidence(f,f.readerA,v); await receipt(register(f,fresh));
  await receipt(f.registry.setStatus(v.vaultId,3));
  const blocked=await evidence(f,f.readerA,v); await rejects(()=>register(f,blocked),'InvalidLifecycle');
  assert.equal(await f.registry.authorized(v.vaultId,true),false);
 });
 it('rejects wrong key/userdata/nonce, stale/future evidence and missing/debug/duplicate PCRs',async()=>{
  const f=await fixture(),v=await evidence(f);
  const bads=[{publicKey:'0x'+'44'.repeat(64)},{userData:E.id('wrong')},{nonce:E.id('wrong')},
   {timestamp:v.journal.timestamp-1000},{timestamp:v.journal.timestamp+100000},
   {pcrs:f.pcrs.slice(1)},{pcrs:[...f.pcrs,f.pcrs[0]]},
   {pcrs:[{index:0,value:{first:E.ZeroHash,second:'0x'+'00'.repeat(16)}},...f.pcrs.slice(1)]},
   {pcrs:[{...f.pcrs[0],value:{first:E.id('wrong'),second:'0x'+'ab'.repeat(16)}},...f.pcrs.slice(1)]},
   {result:1}];
  for(const bad of bads) await rejects(()=>register(f,v,bad));
  await jump(601); await rejects(()=>register(f,v),'InvalidEvidence');
 });
 it('gates every action on policy, expiry and upstream pins; revocation cannot refresh',async()=>{
  const f=await fixture(),v=await enroll(f);
  await receipt(f.registry.setPcrPolicy(1,f.tuple,false)); assert.equal(await f.registry.authorized(v.vaultId,false),false);
  await receipt(f.registry.setPcrPolicy(1,f.tuple,true));
  await receipt(f.mock.setRoot(E.id('new-root'))); assert.equal(await f.registry.authorized(v.vaultId,false),false);
  await receipt(f.mock.setRoot(E.id('test-root')));
  await jump(86401); assert.equal(await f.registry.authorized(v.vaultId,false),false);
  const fresh=await evidence(f,f.readerA,v); await receipt(register(f,fresh));
  await receipt(f.registry.setStatus(v.vaultId,4));
  const revoked=await evidence(f,f.readerA,v);
  await rejects(()=>register(f,revoked),'InvalidLifecycle');
  await rejects(()=>f.registry.setStatus(v.vaultId,1),'InvalidLifecycle');
 });
 it('rejects cross-deployment binding and non-proof output tampering',async()=>{
  const f=await fixture(),v=await evidence(f);
  const other=await fixture();
  const wrong=await other.registry.bindingDigest(v.vaultId,v.wallet.address,v.keys,1,v.challenge);
  await rejects(()=>register(f,v,{userData:wrong}),'InvalidEvidence');
  await rejects(()=>f.registry.attest(v.vaultId,v.keys,1,v.challenge,'0x','0x12345678'),'BAD_PROOF');
 });
});

describe('Registration key and caller isolation',function(){
 it('rejects key substitution on refresh and disallows owner bypass',async()=>{
  const f=await fixture(),v=await enroll(f);
  const fresh=await evidence(f,f.readerA,v);
  fresh.keys={...fresh.keys,decryptKey:f.outsider.address};
  fresh.journal.userData=await f.registry.bindingDigest(v.vaultId,v.wallet.address,fresh.keys,1,fresh.challenge);
  await rejects(()=>register(f,fresh),'InvalidEvidence');
  await rejects(()=>f.registry.connect(f.outsider).setPcrPolicy(1,f.tuple,true));
  await rejects(()=>f.registry.setStatus(v.vaultId,1),'InvalidLifecycle');
  await receipt(f.mock.setEnabled(false));
  assert.equal(await f.registry.authorized(v.vaultId,false),false);
 });
 it('rejects a submitter other than the challenge requester and malformed proof route',async()=>{
  const f=await fixture(),v=await evidence(f);
  const {coder,JOURNAL}=require('./helpers.cjs');
  const output=coder.encode([JOURNAL],[v.journal]),proof=E.concat(['0x12345678',E.keccak256(output)]);
  await rejects(()=>f.registry.connect(f.outsider).attest(v.vaultId,v.keys,1,v.challenge,output,proof),'InvalidEvidence');
  await rejects(()=>f.registry.attest(v.vaultId,v.keys,1,v.challenge,output,E.concat(['0x87654321',E.keccak256(output)])),'InvalidConfiguration');
  await receipt(register(f,v));
 });
});
