import assert from 'node:assert/strict';
import { createServer } from 'node:net';
import { test } from 'node:test';
import { rpcRequest, retryableHttpStatus } from '../src/rpc.ts';

test('HTTP retry classification limits 404 to the observed 1rpc endpoint', () => {
  const exact=new URL('https://1rpc.io/sepolia');
  assert.equal(retryableHttpStatus(exact,404),true);
  for(const url of ['https://1rpc.io/sepolia?other=1','https://1rpc.io/other','https://example.org/sepolia'])
    assert.equal(retryableHttpStatus(new URL(url),404),false);
  for(const status of [429,502,503,504])assert.equal(retryableHttpStatus(new URL('https://example.org'),status),true);
  for(const status of [200,400,401,403,500])assert.equal(retryableHttpStatus(exact,status),false);
});

test('RPC sends the destination hostname to SOCKS and fails if the tunnel fails', async () => {
  let destination = '';
  const proxy = createServer(socket => {
    let state = 0;
    let pending = Buffer.alloc(0);
    socket.on('data', data => {
      pending = Buffer.concat([pending, data]);
      if (state === 0 && pending.length >= 3) {
        pending = pending.subarray(3);
        state = 1;
        socket.write(Buffer.from([5, 0]));
      }
      if (state === 1 && pending.length >= 5 && pending.length >= 7 + pending[4]) {
        assert.equal(pending[3], 3); // SOCKS domain address, not a locally resolved IP.
        destination = pending.subarray(5, 5 + pending[4]).toString();
        socket.end(Buffer.from([5, 1, 0, 1, 0, 0, 0, 0, 0, 0]));
        state = 2;
      }
    });
  });
  await new Promise<void>(resolve => proxy.listen(0, '127.0.0.1', resolve));
  try {
    const address = proxy.address();
    assert.ok(address && typeof address !== 'string');
    const request = rpcRequest('https://rpc.example.invalid', address.port);
    await assert.rejects(request.send());
    assert.equal(destination, 'rpc.example.invalid');
  } finally {
    await new Promise<void>(resolve => proxy.close(() => resolve()));
  }
});

test('bounded RPC JSON transport uses Nym remote DNS and never falls back or retries', async () => {
  const { rpcJson } = await import('../src/rpc.ts');
  let connections=0,destination='';
  const proxy=createServer(socket=>{
    connections++;let pending=Buffer.alloc(0),stage=0;
    socket.on('data',chunk=>{
      pending=Buffer.concat([pending,chunk]);
      if(stage===0&&pending.length>=3){pending=pending.subarray(3);stage=1;socket.write(Buffer.from([5,0]));}
      if(stage===1&&pending.length>=5&&pending.length>=7+pending[4]){
        assert.equal(pending[3],3);destination=pending.subarray(5,5+pending[4]).toString();stage=2;
        socket.end(Buffer.from([5,1,0,1,0,0,0,0,0,0]));
      }
    });
  });
  await new Promise<void>(r=>proxy.listen(0,'127.0.0.1',r));
  try {
    const at=proxy.address();assert.ok(at&&typeof at!=='string');
    await assert.rejects(()=>rpcJson('https://rpc.example.invalid',{jsonrpc:'2.0',id:1,method:'eth_chainId',params:[]},{proxyPort:at.port,timeoutMs:500}));
    assert.equal(connections,1);assert.equal(destination,'rpc.example.invalid');
    await assert.rejects(()=>rpcJson('http://rpc.example.invalid',{}));
    await assert.rejects(()=>rpcJson('https://rpc.example.invalid','x'.repeat(512*1024+1)));
    assert.equal(connections,1);
  }finally{await new Promise<void>(r=>proxy.close(()=>r()));}
});
