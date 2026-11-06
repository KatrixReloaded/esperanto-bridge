import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Wallet, keccak256 } from 'ethers';
import { EvmClient, CHAIN_ID, RPC_TRUST, type RpcCall } from '../src/evm.ts';
const hash = (n: number) => '0x' + n.toString(16).padStart(2, '0').repeat(32);
const account = '0x' + '22'.repeat(20);
const header = (number = '0xa', h = hash(1)) => ({ number, hash: h, parentHash: hash(2), timestamp: '0x65555555' });
async function signed(chainId = 11155111) {
  const rawTransaction = await new Wallet('0x' + '11'.repeat(32)).signTransaction({ chainId, type: 2, nonce: 7,
    to: account, value: 0n, gasLimit: 21000n, maxFeePerGas: 1000000000n, maxPriorityFeePerGas: 100000000n });
  return { chainId: CHAIN_ID, rawTransaction, expectedHash: keccak256(rawTransaction) };
}
function mock(result: (method: string, params: unknown[]) => unknown | Promise<unknown>, chain = '0xaa36a7') {
  const calls: {method:string;params:unknown[]}[] = [];
  const rpc: RpcCall = async (method, params) => {
    calls.push({method,params}); return method === 'eth_chainId' ? chain : result(method,params);
  };
  return { calls, client: new EvmClient(rpc), rpc };
}

test('hash-pinned reads check Sepolia and exclude mutation methods/unbounded filters', async () => {
  const m=mock(()=> '0x1234');
  assert.deepEqual(await m.client.handle('/evm/read',{chainId:CHAIN_ID,method:'eth_call',params:[{to:account,data:'0x'},{blockHash:hash(1),requireCanonical:true}]}),
    {chainId:CHAIN_ID,trust:RPC_TRUST,result:'0x1234'});
  for(const [method,params] of [['eth_sendTransaction',[{}]], ['eth_call',[{to:account,data:'0x'},'latest']],
    ['eth_getLogs',[{address:account,topics:[],fromBlock:'0x0',toBlock:'0x100'}]],
    ['eth_getLogs',[{address:account,topics:[],blockHash:hash(1),fromBlock:'0x0'}]]]) {
    const before=m.calls.length;
    await assert.rejects(()=>m.client.handle('/evm/read',{chainId:CHAIN_ID,method,params}));
    assert.equal(m.calls.length,before);
  }
  const wrong=mock(()=>{throw Error('must not read');},'0x1');
  await assert.rejects(()=>wrong.client.handle('/evm/read',{chainId:CHAIN_ID,method:'eth_gasPrice',params:[]}),/chain_mismatch/);
  assert.equal(wrong.calls.length,1);
});

test('submits identical journal bytes once and treats ack as hash only', async () => {
  const tx=await signed(),m=mock((_method,params)=>{assert.deepEqual(params,[tx.rawTransaction]);return tx.expectedHash;});
  assert.deepEqual(await m.client.handle('/evm/send',tx),{chainId:CHAIN_ID,hash:tx.expectedHash,outcome:'accepted'});
  assert.equal(m.calls.filter(c=>c.method==='eth_sendRawTransaction').length,1);
  assert.deepEqual(m.calls.map(c=>c.method),['eth_chainId','eth_sendRawTransaction']);
});

test('wrong chain, wrong signed hash, unsigned/noncanonical envelopes never reach send', async () => {
  const m=mock(()=>{throw Error('unexpected send');}),tx=await signed();
  for(const body of [{...tx,chainId:'1'},{...tx,expectedHash:hash(3)},await signed(1),{...tx,rawTransaction:'0x'}, {...tx,rawTransaction:tx.rawTransaction+'00'}])
    await assert.rejects(()=>m.client.handle('/evm/send',body));
  assert.equal(m.calls.length,0);
  const wrong=mock(()=>{throw Error('must not send');},'0x1');
  await assert.rejects(()=>wrong.client.handle('/evm/send',tx),/chain_mismatch/);
  assert.equal(wrong.calls.length,1);
});

test('timeout, node error, and hash mismatch stay ambiguous without resend or replacement', async () => {
  const tx=await signed();
  for(const result of [()=>{throw Error('private RPC diagnostic');},()=>hash(4),()=>new Promise(()=>{})]) {
    const m=mock(result),client=new EvmClient(m.rpc,25);
    const response=await client.handle('/evm/send',tx) as any;
    assert.equal(response.outcome,'ambiguous');assert.equal(response.hash,tx.expectedHash);
    assert.equal(m.calls.filter(c=>c.method==='eth_sendRawTransaction').length,1);
    assert.ok(!JSON.stringify(response).includes('private'));
  }
});

function receipt(txHash: string) {
  return { transactionHash:txHash,blockHash:hash(1),blockNumber:'0xa',transactionIndex:'0x0',status:'0x1',gasUsed:'0x5208',logs:[{
    address:account,topics:[hash(5)],data:'0x1234',blockHash:hash(1),blockNumber:'0xa',transactionHash:txHash,transactionIndex:'0x0',logIndex:'0x0',removed:false }] };
}
test('receipt finality is explicitly trusted RPC and checks canonical block/hash/log scope',async()=>{
  const txHash=hash(8),r=receipt(txHash);
  for(const [head,finality] of [[header('0x9',hash(6)),'included'],[header(),'finalized']] as const){
    const m=mock((method,params)=>method==='eth_getTransactionReceipt'?r:params[0]==='finalized'?head:header());
    const observed=await m.client.handle('/evm/receipt',{chainId:CHAIN_ID,hash:txHash}) as any;
    assert.equal(observed.trust,RPC_TRUST);assert.equal(observed.finality,finality);
  }
  const missing=mock(()=>null);
  assert.deepEqual(await missing.client.handle('/evm/receipt',{chainId:CHAIN_ID,hash:txHash}),
    {chainId:CHAIN_ID,trust:RPC_TRUST,receipt:null,finality:'not_found',finalizedHead:null});
  for(const bad of [{...r,transactionHash:hash(7)},{...r,logs:[{...r.logs[0],blockHash:hash(7)}]},
    {...r,logs:[r.logs[0],r.logs[0]]},{...r,status:'0x2'}]) {
    const m=mock(method=>method==='eth_getTransactionReceipt'?bad:header());
    await assert.rejects(()=>m.client.handle('/evm/receipt',{chainId:CHAIN_ID,hash:txHash}));
  }
  const fork=mock(method=>method==='eth_getTransactionReceipt'?r:header('0xa',hash(9)));
  await assert.rejects(()=>fork.client.handle('/evm/receipt',{chainId:CHAIN_ID,hash:txHash}),/rpc_receipt_not_canonical/);
});

test('logs are bounded and match requested addresses/topics/block range',async()=>{
  const l=receipt(hash(8)).logs[0];
  const body={chainId:CHAIN_ID,method:'eth_getLogs',params:[{address:account,topics:[hash(5)],fromBlock:'0xa',toBlock:'0xa'}]};
  assert.equal(((await mock(()=>[l]).client.handle('/evm/read',body)) as any).result.length,1);
  for(const invalid of [[{...l,address:'0x'+'33'.repeat(20)}],[{...l,topics:[hash(7)]}],[{...l,blockNumber:'0xb'}],[{...l,removed:true}],[l,l]])
    await assert.rejects(()=>mock(()=>invalid).client.handle('/evm/read',body));
});
