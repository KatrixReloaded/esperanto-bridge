const {assert,E,coder,JOURNAL,MINT,receipt,rejects,jump,time,fixture,identity,encodeEvidence,discover,mintAuth,mint,request,claimArgs,settleArgs,balance}=require('./helpers.cjs');
function submit(f,m,e=m.evidence,a=m.a,sig=m.signature) { return f.bridge.connect(f.relayer).confidentialMint(a,m.enc.inputProof,sig,e); }
describe('Per-mint Nitro verification and directory lifecycle',function(){
 it('requires one pinned verifier call for each mint, discovers on first mint, and has no enrollment bypass',async()=>{
  const f=await fixture(),v=await identity(f);
  assert.equal(await f.registry.authorized(v.vaultId,false),false);
  assert.equal(f.registry.interface.hasFunction('attest'),false);
  assert.equal(f.registry.interface.hasFunction('issueChallenge'),false);
  assert.equal(f.bridge.interface.hasFunction('mint'),false);
  await mint(f,v,10n); assert.equal(await f.mock.verificationCalls(),1n);
  await mint(f,v,20n); assert.equal(await f.mock.verificationCalls(),2n);
  const m=await mintAuth(f,v,1n);
  await rejects(()=>f.registry.verifyMint(v.vaultId,E.TypedDataEncoder.hash(f.domain,MINT,m.a),m.a.nonce,m.evidence),'Unauthorized');
  await receipt(f.mock.setEnabled(false));
  await rejects(()=>submit(f,m),'InvalidConfiguration');
  assert.equal(await balance(f),30n);
 });
 it('rejects unbound fields, stale/future documents, missing/debug/duplicate PCRs and invalid proofs atomically',async()=>{
  const f=await fixture(),v=await identity(f),m=await mintAuth(f,v,10n);
  const bads=[{publicKey:'0x'+'44'.repeat(64)},{userData:E.id('wrong')},{nonce:E.id('wrong')},
   {timestamp:m.journal.timestamp-601000},{timestamp:m.journal.timestamp+100000},
   {pcrs:f.pcrs.slice(1)},{pcrs:[...f.pcrs,f.pcrs[0]]},
   {pcrs:[{index:0,value:{first:E.ZeroHash,second:'0x'+'00'.repeat(16)}},...f.pcrs.slice(1)]},
   {pcrs:[{...f.pcrs[0],value:{first:E.id('wrong'),second:'0x'+'ab'.repeat(16)}},...f.pcrs.slice(1)]},{result:1}];
  for(const bad of bads) await rejects(()=>submit(f,m,encodeEvidence(v,m.journal,bad)));
  await rejects(()=>submit(f,m,{...m.evidence,proof:'0x12345678'}),'BAD_PROOF');
  await rejects(()=>submit(f,m,{...m.evidence,proof:E.concat(['0x87654321',E.keccak256(m.evidence.output)])}),'InvalidConfiguration');
  assert.equal(await f.mock.verificationCalls(),0n);
  assert.equal(await f.bridge.consumedDeposits(m.a.depositId),false);
  assert.equal(await f.bridge.usedMintNonces(v.vaultId,m.a.nonce),false);
  assert.equal((await f.registry.vaults(v.vaultId)).status,0n);
  // A valid Nitro proof cannot leave keys/replay markers behind if FHE sender validation fails.
  await rejects(()=>f.bridge.connect(f.user).confidentialMint(m.a,m.enc.inputProof,m.signature,m.evidence));
  assert.equal((await f.registry.vaults(v.vaultId)).status,0n);
  assert.equal(await f.bridge.consumedDeposits(m.a.depositId),false);
  assert.equal(await f.bridge.usedMintNonces(v.vaultId,m.a.nonce),false);
  await receipt(submit(f,m)); assert.equal(await balance(f),10n);
 });
 it('binds every canonical authorization field even with a valid new enclave signature',async()=>{
  const f=await fixture(),v=await identity(f),m=await mintAuth(f,v,10n);
  for(const change of [{vaultId:E.toBeHex(BigInt(v.vaultId) ^ (1n<<255n),32)},{recipient:f.outsider.address},{amountHandle:E.id('other')},{depositId:E.id('other')},{nonce:m.a.nonce+1n},{deadline:m.a.deadline+1}]) {
   const a={...m.a,...change},sig=await v.wallet.signTypedData(f.domain,MINT,a);
   await rejects(()=>submit(f,m,m.evidence,a,sig),'InvalidEvidence');
  }
  const a={...m.a,inputProofHash:E.keccak256('0x12')},sig=await v.wallet.signTypedData(f.domain,MINT,a);
  await rejects(()=>f.bridge.connect(f.relayer).confidentialMint(a,'0x12',sig,m.evidence),'InvalidEvidence');
  const wrongDomain={...f.domain,chainId:1};
  const wrongBinding=await f.registry.bindingDigest(v.vaultId,v.wallet.address,v.keys,1,E.TypedDataEncoder.hash(wrongDomain,MINT,m.a));
  await rejects(()=>submit(f,m,encodeEvidence(v,m.journal,{userData:wrongBinding})),'InvalidEvidence');
  const other=await fixture();
  const otherBinding=await other.registry.bindingDigest(v.vaultId,v.wallet.address,v.keys,1,E.TypedDataEncoder.hash(other.domain,MINT,m.a));
  await rejects(()=>submit(f,m,encodeEvidence(v,m.journal,{userData:otherBinding})),'InvalidEvidence');
  await receipt(submit(f,m)); await rejects(()=>submit(f,m),'AlreadyConsumed');
  const next=await mintAuth(f,v,1n); await rejects(()=>submit(f,next,m.evidence),'InvalidEvidence');
 });
 it('never rebinds keys or revives revoked/suspended identities; permits approved image upgrades',async()=>{
  const f=await fixture(),v=await discover(f),m=await mintAuth(f,v,1n);
  for(const change of [{decryptKey:f.outsider.address},{tlsKeyHash:E.id('substitute')},{authKeyHash:E.id('substitute')}]) {
   const keys={...v.keys,...change},binding=await f.registry.bindingDigest(v.vaultId,v.wallet.address,keys,1,await f.bridge.mintDigest(m.a));
   await rejects(()=>submit(f,m,encodeEvidence({...v,keys},m.journal,{userData:binding})),'InvalidEvidence');
  }
  await receipt(f.registry.setPcrPolicy(2,f.tuple,true));
  const binding=await f.registry.bindingDigest(v.vaultId,v.wallet.address,v.keys,2,await f.bridge.mintDigest(m.a));
  await receipt(submit(f,m,{...encodeEvidence(v,m.journal,{userData:binding}),policyVersion:2}));
  assert.equal((await f.registry.vaults(v.vaultId)).policyVersion,2n);
  await receipt(f.registry.setStatus(v.vaultId,4));
  const next=await mintAuth(f,v,1n); await rejects(()=>submit(f,next),'InvalidLifecycle');
  await rejects(()=>f.registry.setStatus(v.vaultId,1),'InvalidLifecycle');
  await rejects(()=>f.registry.connect(f.outsider).setPcrPolicy(1,f.tuple,true));
 });
 it('withdrawal authorization needs no renewal; policy and verifier changes still fail closed',async()=>{
  const f=await fixture(),v=await identity(f); await mint(f,v,10n);
  await jump(86401); assert.equal(await f.registry.authorized(v.vaultId,false),true);
  const r=await request(f,5n,[v]); await receipt(f.bridge.claim(...await claimArgs(f,v,r.requestId)));
  await receipt(f.registry.setPcrPolicy(1,f.tuple,false)); assert.equal(await f.registry.authorized(v.vaultId,true),false);
  await receipt(f.registry.setPcrPolicy(1,f.tuple,true));
  await receipt(f.mock.setRoot(E.id('new-root'))); assert.equal(await f.registry.authorized(v.vaultId,true),false);
  await receipt(f.mock.setRoot(E.id('test-root')));
  await receipt(f.bridge.settle(...await settleArgs(f,v,r.requestId)));
  assert.equal((await f.bridge.redemptions(r.requestId)).status,3n);
 });
});
