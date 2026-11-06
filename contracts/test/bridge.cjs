const {assert,hre,E,FhevmType,MINT,receipt,rejects,jump,fixture,discover,mintAuth,mint,request,claimArgs,settleArgs,decrypt,balance}=require('./helpers.cjs');
describe('Confidential bridge actual-result accounting',function(){
 it('mints only enclave-signed deposits, blocks duplicate IDs and binds recipient/proof/domain',async()=>{
  const f=await fixture(),v=await discover(f),m=await mint(f,v,100n,'deposit');
  assert.equal(await balance(f),100n); assert.equal(await decrypt(f,m.event.actualAmount),100n);
  await assert.rejects(()=>decrypt(f,m.event.actualAmount,f.relayer));
  await assert.rejects(()=>decrypt(f,m.a.amountHandle,f.relayer));
  await rejects(()=>f.bridge.connect(f.relayer).confidentialMint(m.a,m.enc.inputProof,m.signature,m.evidence),'AlreadyConsumed');
  const next=await mintAuth(f,v,10n);
  await rejects(()=>f.bridge.connect(f.relayer).confidentialMint({...next.a,recipient:f.outsider.address},next.enc.inputProof,next.signature,next.evidence),'Unauthorized');
  await rejects(()=>f.bridge.connect(f.user).confidentialMint(next.a,next.enc.inputProof,next.signature,next.evidence));
  const badsig=await v.wallet.signTypedData({...f.domain,chainId:1},MINT,next.a);
  await rejects(()=>f.bridge.connect(f.relayer).confidentialMint(next.a,next.enc.inputProof,badsig,next.evidence),'Unauthorized');
  await rejects(()=>f.token.bridgeMint(f.user.address,m.event.actualAmount),'Unauthorized');
  assert.equal(await f.token.decimals(),12n);
 });
 it('grants exact amount and all destination words only to snapshot readers',async()=>{
  const f=await fixture(),a=await discover(f),b=await discover(f,f.readerB);
  await mint(f,a,100n); const r=await request(f,40n,[a,b]);
  assert.equal(await balance(f),60n);
  for(const reader of [f.user,f.readerA,f.readerB]) {
   assert.equal(await decrypt(f,r.actualAmount,reader),40n);
   for(let i=0;i<3;i++) assert.equal(await decrypt(f,r.destination[i],reader,FhevmType.euint256),BigInt((i+1)*11));
  }
  await assert.rejects(()=>decrypt(f,r.actualAmount,f.outsider));
  await assert.rejects(()=>decrypt(f,r.destination[0],f.outsider,FhevmType.euint256));
  await assert.rejects(()=>hre.fhevm.publicDecrypt([r.actualAmount]));
 });
 it('makes first valid claim final and accepts settlement only from assignee',async()=>{
  const f=await fixture(),a=await discover(f),b=await discover(f,f.readerB);
  await mint(f,a,100n); const r=await request(f,40n,[a,b]);
  const ca=await claimArgs(f,a,r.requestId),cb=await claimArgs(f,b,r.requestId);
  await receipt(f.bridge.claim(...ca));
  await rejects(()=>f.bridge.claim(...cb),'InvalidState');
  await jump(3601); await rejects(()=>f.bridge.connect(f.user).cancel(r.requestId),'InvalidState');
  const wrong=await settleArgs(f,b,r.requestId); await rejects(()=>f.bridge.settle(...wrong),'InvalidState');
  const correct=await settleArgs(f,a,r.requestId); await receipt(f.bridge.settle(...correct));
  await rejects(()=>f.bridge.settle(...correct),'InvalidState');
  assert.equal((await f.bridge.redemptions(r.requestId)).status,3n);
 });
 it('rejects zero/insufficient actual burns at claim and permits exact one-time zero refund',async()=>{
  const f=await fixture(),a=await discover(f); await mint(f,a,10n);
  for(const amount of [0n,11n]) {
   const r=await request(f,amount,[a]); assert.equal(await decrypt(f,r.actualAmount),0n);
   const args=await claimArgs(f,a,r.requestId); await rejects(()=>f.bridge.claim(...args));
   await jump(3601); await receipt(f.bridge.connect(f.user).cancel(r.requestId));
   await rejects(()=>f.bridge.connect(f.user).cancel(r.requestId),'InvalidState');
  }
  assert.equal(await balance(f),10n);
 });
 it('reserves pending burn capacity across max supply and refunds exactly once',async()=>{
  const f=await fixture(),a=await discover(f),max=(1n<<64n)-1n;
  await mint(f,a,max); const r=await request(f,100n,[a]);
  const overflow=await mint(f,a,1n); assert.equal(await decrypt(f,overflow.event.actualAmount),0n);
  await rejects(()=>f.bridge.connect(f.user).cancel(r.requestId),'InvalidState');
  await jump(3601); await receipt(f.bridge.connect(f.user).cancel(r.requestId));
  assert.equal(await balance(f),max);
  await rejects(()=>f.bridge.connect(f.user).cancel(r.requestId),'InvalidState');
  const again=await mint(f,a,1n); assert.equal(await decrypt(f,again.event.actualAmount),0n);
 });
 it('releases capacity only on settlement, and lifecycle rejects new claims',async()=>{
  const f=await fixture(),a=await discover(f),max=(1n<<64n)-1n;
  await mint(f,a,max); const r=await request(f,100n,[a]);
  await receipt(f.bridge.claim(...await claimArgs(f,a,r.requestId)));
  await receipt(f.bridge.settle(...await settleArgs(f,a,r.requestId)));
  const m=await mint(f,a,100n); assert.equal(await decrypt(f,m.event.actualAmount),100n);
  const pending=await request(f,1n,[a]); const args=await claimArgs(f,a,pending.requestId);
  await receipt(f.registry.setStatus(a.vaultId,3)); await rejects(()=>f.bridge.claim(...args),'Unauthorized');
 });
});

describe('Adversarial bridge authorization',function(){
 it('rejects globally duplicate deposits across vaults and per-vault nonce reuse',async()=>{
  const f=await fixture(),a=await discover(f),b=await discover(f,f.readerB);
  const first=await mint(f,a,10n,'shared-deposit');
  const duplicate=await mintAuth(f,b,20n,'shared-deposit');
  await rejects(()=>f.bridge.connect(f.relayer).confidentialMint(duplicate.a,duplicate.enc.inputProof,duplicate.signature,duplicate.evidence),'AlreadyConsumed');
  const nonce=await mintAuth(f,a,10n,'new-deposit',first.a.nonce);
  await rejects(()=>f.bridge.connect(f.relayer).confidentialMint(nonce.a,nonce.enc.inputProof,nonce.signature,nonce.evidence),'AlreadyConsumed');
  const mismatch=await mintAuth(f,a,1n);
  await rejects(()=>f.bridge.connect(f.relayer).confidentialMint(mismatch.a,'0x',mismatch.signature,mismatch.evidence),'InvalidInput');
 });
 it('rejects non-snapshot claimant, wrong positivity proof and stale signatures',async()=>{
  const f=await fixture(),a=await discover(f),b=await discover(f,f.readerB);
  await mint(f,a,100n);const r=await request(f,10n,[a]),r2=await request(f,10n,[a]);
  const outsider=await claimArgs(f,b,r.requestId);await rejects(()=>f.bridge.claim(...outsider),'InvalidState');
  const good=await claimArgs(f,a,r.requestId),other=await claimArgs(f,a,r2.requestId);
  await rejects(()=>f.bridge.claim(...good.slice(0,4),other[4]));
  await jump(601);await rejects(()=>f.bridge.claim(...good),'Unauthorized');
 });
 it('draining vault can complete assignment but cannot mint or win new claims',async()=>{
  const f=await fixture(),a=await discover(f);await mint(f,a,100n);
  const r=await request(f,10n,[a]),other=await request(f,10n,[a]);
  await receipt(f.bridge.claim(...await claimArgs(f,a,r.requestId)));
  await receipt(f.owner.sendTransaction({to:a.wallet.address,value:E.parseEther('1')}));
  await receipt(f.registry.connect(a.wallet.connect(E.provider)).setStatus(a.vaultId,2));
  assert.equal(await f.registry.authorized(a.vaultId,false),false);
  assert.equal(await f.registry.authorized(a.vaultId,true),true);
  await rejects(()=>f.registry.setStatus(a.vaultId,5),'InvalidLifecycle');
  const m=await mintAuth(f,a,1n);await rejects(()=>f.bridge.connect(f.relayer).confidentialMint(m.a,m.enc.inputProof,m.signature,m.evidence),'InvalidLifecycle');
  const claim=await claimArgs(f,a,other.requestId);await rejects(()=>f.bridge.claim(...claim),'Unauthorized');
  await receipt(f.bridge.settle(...await settleArgs(f,a,r.requestId)));
  await receipt(f.registry.setStatus(a.vaultId,5));
  assert.equal(await f.registry.authorized(a.vaultId,true),false);
 });
});
