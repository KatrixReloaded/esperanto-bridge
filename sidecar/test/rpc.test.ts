import assert from 'node:assert/strict';
import { createServer } from 'node:net';
import { test } from 'node:test';
import { rpcRequest } from '../src/rpc.ts';

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
