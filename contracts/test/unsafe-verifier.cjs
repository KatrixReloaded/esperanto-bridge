const {assert,E,coder,JOURNAL,fixture,identity,mintAuth,receipt,rejects,balance,request,claimArgs,settleArgs}=require('./helpers.cjs');

describe('Explicit unsafe attestation test deployment',function(){
 it('accepts fabricated evidence through the real adapter and preserves mint/burn/claim/settle',async()=>{
  const f=await fixture({unsafeVerifier:true}),v=await identity(f),m=await mintAuth(f,v,100n);
  assert.equal(await f.mock.unsafeTestOnly(),true);
  // No NSM or cryptographic proof: this four-byte marker is sufficient in this test lane.
  m.evidence.proof=await f.mock.proofSelector();
  m.evidence.output=coder.encode([JOURNAL],[{...m.journal,result:3}]);
  assert.equal((await f.adapter.verify.staticCall(m.evidence.output,m.evidence.proof)).result,0n);
  await receipt(f.bridge.connect(f.relayer).confidentialMint(m.a,m.enc.inputProof,m.signature,m.evidence));
  assert.equal(await balance(f),100n);
  await rejects(()=>f.bridge.connect(f.relayer).confidentialMint(m.a,m.enc.inputProof,m.signature,m.evidence),'AlreadyConsumed');
  const redemption=await request(f,40n,[v]);
  await receipt(f.bridge.claim(...await claimArgs(f,v,redemption.requestId)));
  await receipt(f.bridge.settle(...await settleArgs(f,v,redemption.requestId)));
  assert.equal(await balance(f),60n);
  assert.equal((await f.bridge.redemptions(redemption.requestId)).status,3n);
 });
 it('still enforces request binding, signature, PCR policy and FHE sender',async()=>{
  const f=await fixture({unsafeVerifier:true}),v=await identity(f),m=await mintAuth(f,v,10n);
  m.evidence.proof=await f.mock.proofSelector();
  await rejects(()=>f.bridge.connect(f.relayer).confidentialMint({...m.a,recipient:f.outsider.address},m.enc.inputProof,m.signature,m.evidence),'Unauthorized');
  const output=coder.encode([JOURNAL],[{...m.journal,userData:E.ZeroHash}]);
  await rejects(()=>f.bridge.connect(f.relayer).confidentialMint(m.a,m.enc.inputProof,m.signature,{...m.evidence,output}),'InvalidEvidence');
  await rejects(()=>f.bridge.connect(f.user).confidentialMint(m.a,m.enc.inputProof,m.signature,m.evidence));
  await receipt(f.registry.setPcrPolicy(1,f.tuple,false));
  await rejects(()=>f.bridge.connect(f.relayer).confidentialMint(m.a,m.enc.inputProof,m.signature,m.evidence),'InvalidEvidence');
 });
});
