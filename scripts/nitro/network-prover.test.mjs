import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, readdir, chmod } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { reserveAttempt, validateNetwork } from './network-prover.mjs';

test('concurrent jobs cannot exceed the persistent paid-attempt budget; retries stay blocked',async()=>{
  const state=await mkdtemp(join(tmpdir(),'cwxmr-budget-test-'));
  try {
    const attempts=await Promise.allSettled(Array.from({length:8},(_,i)=>reserveAttempt(state,i.toString(16).padStart(64,'0'),2)));
    assert.equal(attempts.filter(r=>r.status==='fulfilled').length,2);
    assert.equal((await readdir(state)).filter(n=>n.startsWith('attempt-')).length,2);
    await assert.rejects(reserveAttempt(state,'0'.repeat(64),2));
    await assert.rejects(reserveAttempt(state,'f'.repeat(64),2),/budget exhausted/);
    await assert.rejects(reserveAttempt(state,'../escape',2),/request key/);
    await chmod(state,0o755);
    await assert.rejects(reserveAttempt(state,'e'.repeat(64),2),/Private/);
  } finally { await rm(state,{recursive:true,force:true}); }
});
test('network budget is explicit, bounded and fixed to the supported endpoint',()=>{
  const config={sp1RpcUrl:null,network:{walletFile:'/private/wallet',stateDirectory:'/private/jobs',maxRequests:1}};
  validateNetwork(config);
  for(const maxRequests of [0,11,1.5]) assert.throws(()=>validateNetwork({...config,network:{...config.network,maxRequests}}));
  assert.throws(()=>validateNetwork({...config,sp1RpcUrl:'https://unexpected.example'}));
  assert.throws(()=>validateNetwork({...config,network:{...config.network,walletFile:'relative'}}));
});
