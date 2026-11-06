const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { Interface } = require('ethers');
const { amountAtomic, prepare, finish, words, writePrivate } = require('./prepare-redemption.cjs');
const USER = '0x9999999999999999999999999999999999999999';
const hash = b => '0x'+b.repeat(32);
const address = b => '0x'+b.repeat(20);
const input = () => ({ mode:'UNSAFE_TEST_NO_NITRO', chainId:11155111, user:USER, pins:Object.fromEntries(['bridge','registry','adapter','verifier'].flatMap((name,i) => [[name,address(`0${i+1}`)],[name+'_code_hash',hash('ab')]])), feeTermsHash:hash('34'), vaultIds:[hash('22'),hash('11')], amount:'0.123456789012', destination:'checked-by-rust' });
const encoded = () => { const b=Buffer.alloc(96); b[0]=1; b[1]=2; for(let i=3;i<71;i++)b[i]=i; return '0x'+b.toString('hex'); };
const handle = (i,type=i===0?5:8,chain=11155111n,version=0) => {const b=Buffer.alloc(32,i+1);b.writeBigUInt64BE(chain,22);b[30]=type;b[31]=version;return '0x'+b.toString('hex');};
const response = () => ({handles:[0,1,2,3].map(i=>handle(i)),inputProof:'0x112233'});
test('12-decimal exact uint64 amount bounds',()=>{
  assert.equal(amountAtomic('0.000000000001'),'1');
  assert.equal(amountAtomic('18446744.073709551615'), '18446744073709551615');
  for(const s of ['0','-1','1e3','01','1.0000000000001','18446744.073709551616'])assert.throws(()=>amountAtomic(s));
});
test('big-endian three-word packing retains exact96 bytes',()=>{
  const result=words(encoded());
  assert.equal('0x'+result.map(w=>BigInt(w).toString(16).padStart(64,'0')).join(''),encoded());
  const b=Buffer.from(encoded().slice(2),'hex'); b[95]=1; assert.throws(()=>words('0x'+b.toString('hex')));
});
test('prepare binds Bridge/user and sorts unique eligible vaults',()=>{
  const c=prepare(input(),encoded);
  assert.equal(c.encryptionRequest.contract,input().pins.bridge);
  assert.equal(c.encryptionRequest.user,USER);
  assert.equal(c.encryptionRequest.amount,'123456789012');
  const other=prepare({...input(),user:address('88')},encoded);
  assert.equal(other.user,address('88'));
  assert.equal(finish(other,response()).from,address('88'));
  assert.throws(()=>prepare({...input(),user:'0x52908400098527886E0F7030069857D2E4169ee7'},encoded));
  assert.deepEqual(c.vaultIds,[hash('11'),hash('22')]);
  const bad=input();bad.vaultIds=[hash('11'),hash('11')];assert.throws(()=>prepare(bad,encoded));
  for(const update of [{chainId:1},{user:address('00')},{mode:'production'}])assert.throws(()=>prepare({...input(),...update},encoded));
});
test('finish emits current Bridge ABI with zero native value and correct terms',()=>{
  const c=prepare(input(),encoded),r=response(),tx=finish(c,r);
  const abi=new Interface(require('../abi/Bridge.json'));
  const decoded=abi.decodeFunctionData('requestRedemption',tx.data);
  assert.equal(tx.to,c.pins.bridge);assert.equal(tx.from,USER);assert.equal(tx.chainId,11155111);assert.equal(tx.value,'0x0');
  assert.equal(decoded[0],r.handles[0]);assert.deepEqual(Array.from(decoded[1]),r.handles.slice(1));
  assert.equal(decoded[2],r.inputProof);assert.equal(decoded[3],c.feeTermsHash);assert.deepEqual(Array.from(decoded[4]),c.vaultIds);
});
test('finish rejects wrong chain, ciphertext type/version, empty proof and modified scope',()=>{
  for(const bad of [handle(0,8),handle(0,5,1n),handle(0,5,11155111n,1)]){const r=response();r.handles[0]=bad;assert.throws(()=>finish(prepare(input(),encoded),r));}
  for(const proof of ['0x','0xz1','0x1'])assert.throws(()=>finish(prepare(input(),encoded),{...response(),inputProof:proof}));
  const c=prepare(input(),encoded);c.encryptionRequest.contract=address('99');assert.throws(()=>finish(c,response()));
  assert.throws(()=>finish(prepare(input(),encoded),{...response(),handles:[handle(0)]}));
});
test('private output is0600 and never overwrites existing files',()=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'cwxmr-redemption-'));
  try { const file=path.join(dir,'request.json');writePrivate(file,{data:'0x1234'});assert.equal(fs.statSync(file).mode&0o777,0o600);assert.throws(()=>writePrivate(file,{})); }
  finally {fs.rmSync(dir,{recursive:true});}
});
