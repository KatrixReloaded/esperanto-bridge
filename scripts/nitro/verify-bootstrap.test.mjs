import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { validateIdentity } from './verify-bootstrap.mjs';
const require=createRequire(new URL('../../contracts/package.json',import.meta.url));
const E=require('ethers');
const coder=E.AbiCoder.defaultAbiCoder();
const TYPE='CWXMRNitroIdentityBinding(uint256 chainId,address registry,address bridge,bytes32 vaultId,address signingKey,address decryptKey,bytes32 tlsKeyHash,bytes32 authKeyHash,uint64 policyVersion,bytes32 nonce)';
function fixture() {
  const pub=E.SigningKey.computePublicKey('0x'+'11'.repeat(32),false).slice(4);
  const identity={public_key:pub,vault_id:E.keccak256('0x'+pub).slice(2),signing_key:E.computeAddress('0x04'+pub).slice(2),
    decrypt_key:'22'.repeat(20),tls_key_hash:'33'.repeat(32),auth_key_hash:'44'.repeat(32)};
  const nonce=E.id('fresh challenge'),spki='0x'+identity.tls_key_hash,now=1700000000000;
  const pcrs=[0n,1n,2n].map((index)=>({index,value:{first:'0x'+'55'.repeat(32),second:'0x'+'66'.repeat(16)}}));
  const config={domain:{chain_id:11155111,registry:'0x'+'77'.repeat(20),bridge:'0x'+'88'.repeat(20),policy_version:1},
    rootCert:E.id('root'),pcrTuple:E.keccak256(E.concat(pcrs.map(p=>E.concat([p.value.first,p.value.second])))),expectedVaultId:null};
  const userData=E.keccak256(coder.encode(['bytes32','uint256','address','address','bytes32','address','address','bytes32','bytes32','uint64','bytes32'],
    [E.id(TYPE),config.domain.chain_id,config.domain.registry,config.domain.bridge,'0x'+identity.vault_id,'0x'+identity.signing_key,'0x'+identity.decrypt_key,spki,'0x'+identity.auth_key_hash,1,nonce]));
  const journal={result:0n,certs:[config.rootCert],trustedCertsPrefixLen:1n,timestamp:BigInt(now),publicKey:'0x'+pub,nonce,userData,pcrs};
  return {journal,identity,nonce,config,spki,now};
}
test('first-contact identity binds live TLS, key bundle, challenge, deployment and measured image',()=>{
  const f=fixture(),verify=v=>validateIdentity(v.journal,v.identity,v.nonce,v.config,v.spki,v.now);
  assert.equal(verify(f).vaultId,'0x'+f.identity.vault_id);
  for(const mutate of [
    v=>v.spki=E.id('other TLS'),v=>v.nonce=E.id('replay'),v=>v.journal.userData=E.id('mint domain'),
    v=>v.config.domain.bridge='0x'+'99'.repeat(20),v=>v.config.rootCert=E.id('other root'),
    v=>v.config.expectedVaultId=E.id('other restored vault'),v=>v.identity.auth_key_hash='aa'.repeat(32),
    v=>v.journal.timestamp-=600001n,v=>v.journal.timestamp+=1n,
    v=>v.journal.pcrs[0].value={first:E.ZeroHash,second:'0x'+'00'.repeat(16)},
    v=>v.journal.pcrs.push(v.journal.pcrs[0]),v=>v.journal.pcrs.pop(),
  ]) { const v=structuredClone(f); mutate(v); assert.throws(()=>verify(v)); }
});
