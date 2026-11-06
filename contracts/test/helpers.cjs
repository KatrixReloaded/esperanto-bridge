const assert = require('node:assert/strict');
const hre = require('hardhat');
const { FhevmType } = require('@fhevm/hardhat-plugin');
const E = hre.ethers;
const coder = E.AbiCoder.defaultAbiCoder();
const JOURNAL = 'tuple(uint8 result,uint8 trustedCertsPrefixLen,uint64 timestamp,bytes32[] certs,bytes userData,bytes nonce,bytes publicKey,tuple(uint64 index,tuple(bytes32 first,bytes16 second) value)[] pcrs,string moduleId)';
const MINT = {Mint:[['vaultId','bytes32'],['depositId','bytes32'],['recipient','address'],['amountHandle','bytes32'],['inputProofHash','bytes32'],['nonce','uint256'],['deadline','uint64']].map(([name,type])=>({name,type}))};
const CLAIM = {Claim:[['requestId','uint256'],['vaultId','bytes32'],['deadline','uint64']].map(([name,type])=>({name,type}))};
const SETTLE = {Settle:[['requestId','uint256'],['vaultId','bytes32'],['paymentCommitment','bytes32'],['deadline','uint64']].map(([name,type])=>({name,type}))};
async function receipt(tx) { return (await tx).wait(); }
function event(c,r,n) { return r.logs.map(x=>{try{return c.interface.parseLog(x);}catch{return null;}}).find(x=>x?.name===n).args; }
async function rejects(fn, match) {
 let caught; try { await receipt(fn()); } catch(e) { caught=e; }
 assert.ok(caught,'expected rejection');
 if(match) assert.ok(String(caught.message).includes(match) || String(caught.data ?? '').startsWith(E.id(match+'()').slice(0,10)), `expected ${match}, got ${caught.message}`);
}
async function time() { return Number((await E.provider.getBlock('latest')).timestamp); }
async function jump(seconds) { await hre.network.provider.send('evm_increaseTime',[seconds]); await hre.network.provider.send('evm_mine'); }
async function fixture({unsafeVerifier=false}={}) {
 assert.equal(hre.network.name,'hardhat'); assert.ok(hre.fhevm.isMock);
 const [owner,user,relayer,readerA,readerB,outsider] = await E.getSigners();
 const mock = await (await E.getContractFactory(unsafeVerifier?'UnsafeTestNitroVerifier':'MockNitroVerifier')).deploy();
 const addr=await mock.getAddress(), hash=E.keccak256(await E.provider.getCode(addr));
 const selector=unsafeVerifier?await mock.proofSelector():'0x12345678';
 const adapter=await(await E.getContractFactory('NitroVerifierAdapter')).deploy(addr,hash,await mock.rootCert(),await mock.program(),2,selector,addr,hash);
 const bridge=await(await E.getContractFactory('Bridge')).deploy(owner.address,await adapter.getAddress());
 const registry=await E.getContractAt('VaultRegistry',await bridge.registry());
 const token=await E.getContractAt('CWXMR',await bridge.token());
 const domain={name:'CWXMRBridge',version:'1',chainId:31337,verifyingContract:await bridge.getAddress()};
 const pcrs=[0,1,2].map(i=>({index:i,value:{first:E.id('pcr'+i),second:'0x'+'ab'.repeat(16)}}));
 const tuple=E.keccak256(E.concat(pcrs.map(x=>E.concat([x.value.first,x.value.second]))));
 await receipt(registry.setPcrPolicy(1,tuple,true));
 return {owner,user,relayer,readerA,readerB,outsider,mock,adapter,bridge,registry,token,domain,pcrs,tuple};
}
async function identity(f, reader=f.readerA) {
 const wallet=E.Wallet.createRandom();
 const publicKey='0x'+wallet.signingKey.publicKey.slice(4), vaultId=E.keccak256(publicKey);
 const keys={decryptKey:reader.address,tlsKeyHash:E.id('tls'),authKeyHash:E.id('auth')};
 return {wallet,publicKey,vaultId,keys};
}
function encodeEvidence(v, journal, changes={}) {
 const output=coder.encode([JOURNAL],[{...journal,...changes}]);
 return {keys:v.keys,policyVersion:1,output,proof:E.concat(['0x12345678',E.keccak256(output)])};
}
async function discover(f,reader=f.readerA) {
 const v=await identity(f,reader);
 // Local fixture establishes directory membership via a real deposit-mint entrypoint only.
 await mint(f,v,0n); return v;
}
async function mintAuth(f,v,amount,label=E.hexlify(E.randomBytes(8)),nonce=BigInt(E.hexlify(E.randomBytes(8)))) {
 const enc=await hre.fhevm.createEncryptedInput(await f.bridge.getAddress(),f.relayer.address).add64(amount).encrypt();
 const a={vaultId:v.vaultId,depositId:E.id(label),recipient:f.user.address,amountHandle:E.hexlify(enc.handles[0]),inputProofHash:E.keccak256(enc.inputProof),nonce,deadline:(await time())+600};
 const digest=E.TypedDataEncoder.hash(f.domain,MINT,a);
 assert.equal(await f.bridge.mintDigest(a),digest);
 const binding=await f.registry.bindingDigest(v.vaultId,v.wallet.address,v.keys,1,digest);
 const journal={result:0,trustedCertsPrefixLen:1,timestamp:(await time())*1000,certs:[await f.mock.rootCert()],userData:binding,nonce:E.toBeHex(a.nonce,32),publicKey:v.publicKey,pcrs:f.pcrs,moduleId:'TEST ONLY'};
 return {a,enc,journal,evidence:encodeEvidence(v,journal),signature:await v.wallet.signTypedData(f.domain,MINT,a)};
}
async function mint(f,v,amount,label) { const m=await mintAuth(f,v,amount,label); const r=await receipt(f.bridge.connect(f.relayer).confidentialMint(m.a,m.enc.inputProof,m.signature,m.evidence)); return {...m,event:event(f.bridge,r,'DepositMinted')}; }
async function request(f,amount,vs) {
 const enc=await hre.fhevm.createEncryptedInput(await f.bridge.getAddress(),f.user.address).add64(amount).add256(11n).add256(22n).add256(33n).encrypt();
 const r=await receipt(f.bridge.connect(f.user).requestRedemption(enc.handles[0],enc.handles.slice(1),enc.inputProof,E.id('fees'),vs.map(v=>v.vaultId).sort()));
 return event(f.bridge,r,'RedemptionRequested');
}
async function claimArgs(f,v,id) {
 const deadline=(await time())+600;
 const signature=await v.wallet.signTypedData(f.domain,CLAIM,{requestId:id,vaultId:v.vaultId,deadline});
 const rec=await f.bridge.redemptions(id);
 const proof=await hre.fhevm.publicDecrypt([rec.nonzero]);
 return [id,v.vaultId,deadline,signature,proof.decryptionProof];
}
async function settleArgs(f,v,id) {
 const deadline=(await time())+600, paymentCommitment=E.id('payment:'+id);
 return [id,v.vaultId,paymentCommitment,deadline,await v.wallet.signTypedData(f.domain,SETTLE,{requestId:id,vaultId:v.vaultId,paymentCommitment,deadline})];
}
async function decrypt(f,handle,reader=f.readerA,type=FhevmType.euint64) { return hre.fhevm.userDecryptEuint(type,handle,await f.bridge.getAddress(),reader); }
async function balance(f) { return hre.fhevm.userDecryptEuint(FhevmType.euint64,await f.token.confidentialBalanceOf(f.user.address),await f.token.getAddress(),f.user); }
module.exports={assert,hre,E,FhevmType,coder,JOURNAL,MINT,CLAIM,SETTLE,receipt,event,rejects,time,jump,fixture,identity,encodeEvidence,discover,mintAuth,mint,request,claimArgs,settleArgs,decrypt,balance};
