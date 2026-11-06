const {setup,swap,assert,hre,rejects,receipt,event,jump,claimArgs,settleArgs,decrypt,FhevmType}=require('./swap-helpers.cjs');
const E=hre.ethers;
const words=[11n,22n,33n];
async function destination(b,who,values=words) {
 const e=hre.fhevm.createEncryptedInput(b.target,who.address);
 for(const value of values)e.add256(value);
 return e.encrypt();
}
async function redemption(f,amount=500000000000n,who=f.service,target=f.balancer.target) {
 const e=await hre.fhevm.createEncryptedInput(target,who.address).add64(amount).encrypt();
 return [E.id('operation'),e.handles[0],e.inputProof,E.id('fees'),[f.vault.vaultId]];
}
async function inventory(f) {
 const h=await f.token.confidentialBalanceOf(f.balancer.target);
 return h===E.ZeroHash?0n:hre.fhevm.debugger.decryptEuint(FhevmType.euint64,h);
}
async function fresh(f) { return (await E.getContractFactory('CWXMRBalancer')).deploy(f.bridge.target,f.service.address); }
describe('XMR inventory redemption with a pinned encrypted destination',function(){
 it('reuses persistent destination handles with fresh amounts, claims and settles through the actual Bridge',async function(){
  const f=await setup();await swap(f);
  const pinned=await Promise.all(words.map((_,i)=>f.balancer.destination(i)));
  for(const [label,amount] of [['first',300000000000n],['second',200000000000n]]) {
   const args=await redemption(f,amount);args[0]=E.id(label);
   const r=await receipt(f.balancer.connect(f.service).redeem(...args));
   const id=event(f.balancer,r,'RedemptionRequested').redeemId;
   const rec=await f.bridge.redemptions(id);
   assert.equal(rec.user,f.balancer.target);assert.deepEqual(Array.from(rec.destination),pinned);
   assert.equal(await decrypt(f,rec.amount),amount);
   for(let i=0;i<3;i++)assert.equal(await decrypt(f,rec.destination[i],f.readerA,FhevmType.euint256),words[i]);
   await assert.rejects(()=>decrypt(f,rec.destination[0],f.outsider,FhevmType.euint256));
   await receipt(f.bridge.claim(...await claimArgs(f,f.vault,id)));
   await rejects(()=>f.balancer.connect(f.service).cancel(args[0]),'InvalidState');
   await receipt(f.bridge.settle(...await settleArgs(f,f.vault,id)));
   assert.equal((await f.bridge.redemptions(id)).status,3n);
  }
  assert.equal(await inventory(f),500000000000n);
 });
 it('binds retries to complete terms and cancels an unassigned burn back into inventory exactly once',async function(){
  const f=await setup();await swap(f);const args=await redemption(f);
  const r=await receipt(f.balancer.connect(f.service).redeem(...args));
  const id=event(f.balancer,r,'RedemptionRequested').redeemId;
  const next=await f.bridge.nextRequestId();
  assert.equal(await f.balancer.connect(f.service).redeem.staticCall(...args),id);
  await receipt(f.balancer.connect(f.service).redeem(...args));assert.equal(await f.bridge.nextRequestId(),next);
  for(const changed of [[...args.slice(0,3),E.id('other fees'),args[4]],[...args.slice(0,4),[]]])
   await rejects(()=>f.balancer.connect(f.service).redeem(...changed),'OperationConflict');
  const other=await redemption(f,1n);await rejects(()=>f.balancer.connect(f.service).redeem(...other),'OperationConflict');
  await rejects(()=>f.balancer.cancel(args[0]),'Unauthorized');
  await rejects(()=>f.balancer.connect(f.service).cancel(E.id('missing')),'UnknownOperation');
  await rejects(()=>f.balancer.connect(f.service).cancel(args[0]),'InvalidState');
  await jump(3601);await receipt(f.balancer.connect(f.service).cancel(args[0]));
  assert.equal(await inventory(f),1000000000000n);
  await rejects(()=>f.balancer.connect(f.service).cancel(args[0]),'InvalidState');
  await receipt(f.balancer.connect(f.service).redeem(...args));assert.equal(await inventory(f),1000000000000n);
  assert.equal(await f.bridge.nextRequestId(),next);
 });
 it('uses the actual burn for insufficient inventory and leaves failed requests retryable',async function(){
  const f=await setup();await swap(f);const args=await redemption(f,1000000000001n);
  await rejects(()=>f.balancer.connect(f.service).redeem(...args.slice(0,4),[]),'InvalidInput');
  assert.equal((await f.balancer.operations(args[0])).redeemId,0n);
  const r=await receipt(f.balancer.connect(f.service).redeem(...args));
  const id=event(f.balancer,r,'RedemptionRequested').redeemId;
  assert.equal(await decrypt(f,(await f.bridge.redemptions(id)).amount),0n);
  await rejects(async()=>f.bridge.claim(...await claimArgs(f,f.vault,id)));
  await jump(3601);await receipt(f.balancer.connect(f.service).cancel(args[0]));
  assert.equal(await inventory(f),1000000000000n);
 });
 it('requires one-time deployer setup and rejects malformed, empty and wrong-caller destination proofs',async function(){
  const f=await setup(),b=await fresh(f);const good=await destination(b,f.owner);
  await rejects(()=>b.connect(f.service).initializeDestination(good.handles,good.inputProof),'Unauthorized');
  await rejects(()=>b.initializeDestination(good.handles,'0x'),'InvalidConfiguration');
  await rejects(()=>b.initializeDestination(good.handles,'0x1234'));
  const wrong=await destination(b,f.service);await rejects(()=>b.initializeDestination(wrong.handles,wrong.inputProof));
  assert.equal(await b.initialized(),false);
  await receipt(b.initializeDestination(good.handles,good.inputProof));
  const replacement=await destination(b,f.owner,[44n,55n,66n]);
  await rejects(()=>b.initializeDestination(replacement.handles,replacement.inputProof),'AlreadyInitialized');
  assert.deepEqual(await Promise.all(words.map((_,i)=>b.destination(i))),good.handles.map(E.hexlify));
 });
 it('blocks inventory callbacks and redemption before setup, then permits the initialized receiver',async function(){
  const f=await setup(),b=await fresh(f);
  const e=await hre.fhevm.createEncryptedInput(f.token.target,f.user.address).add64(1n).encrypt();
  const transfer=()=>f.token.connect(f.user)['confidentialTransferAndCall(address,bytes32,bytes,bytes)'](b.target,e.handles[0],e.inputProof,'0x');
  await rejects(transfer);
  const args=await redemption(f,1n,f.service,b.target);await rejects(()=>b.connect(f.service).redeem(...args),'NotInitialized');
  const d=await destination(b,f.owner);await receipt(b.initializeDestination(d.handles,d.inputProof));
  await receipt(transfer());
  assert.equal(await hre.fhevm.debugger.decryptEuint(FhevmType.euint64,await f.token.confidentialBalanceOf(b.target)),1n);
  await rejects(()=>b.onConfidentialTransferReceived(f.addr,f.user.address,E.ZeroHash,'0x'),'Unauthorized');
  for(const name of ['withdraw','release','setDestination'])assert.equal(b.interface.getFunction(name),null);
 });
 it('requires service authorization and fresh uint64 proofs scoped to the balancer/service',async function(){
  const f=await setup();await swap(f);const args=await redemption(f);
  await rejects(()=>f.balancer.redeem(...args),'Unauthorized');
  await rejects(()=>f.balancer.connect(f.service).redeem(args[0],args[1],'0x',args[3],args[4]),'InvalidConfiguration');
  for(const [who,target] of [[f.owner,f.balancer.target],[f.service,f.bridge.target]]) {
   const bad=await redemption(f,1n,who,target);await rejects(()=>f.balancer.connect(f.service).redeem(...bad));
  }
  const wide=await hre.fhevm.createEncryptedInput(f.balancer.target,f.service.address).add256(1n).encrypt();
  await rejects(()=>f.balancer.connect(f.service).redeem(args[0],wide.handles[0],wide.inputProof,args[3],args[4]));
  assert.equal(await inventory(f),1000000000000n);
 });
 it('rejects empty-proof reuse by an account lacking permission to the fixed destination',async function(){
  const f=await setup();const pinned=await Promise.all(words.map((_,i)=>f.balancer.destination(i)));
  await rejects(()=>f.bridge.connect(f.service).requestRedemption(E.ZeroHash,pinned,'0x',E.id('fees'),[f.vault.vaultId]));
 });
 it('requires both the amount and destination ACL grants to Bridge on the empty-proof path',async function(){
  const f=await setup();const probe=await(await E.getContractFactory('InventoryAclProbe')).deploy();
  const e=await hre.fhevm.createEncryptedInput(probe.target,f.owner.address).add64(0n).add256(11n).add256(22n).add256(33n).encrypt();
  const args=[f.bridge.target,e.handles[0],e.handles.slice(1),e.inputProof,f.vault.vaultId];
  for(const flags of [[false,true],[true,false]])await rejects(()=>probe.forward(...args,...flags));
  await receipt(probe.forward(...args,true,true));
 });
 it('rejects invalid bridge or service configuration',async function(){
  const f=await setup(),factory=await E.getContractFactory('CWXMRBalancer');
  await rejects(()=>factory.deploy(f.owner.address,f.service.address),'InvalidConfiguration');
  await rejects(()=>factory.deploy(f.bridge.target,E.ZeroAddress),'InvalidConfiguration');
 });
});
