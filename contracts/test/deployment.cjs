const {assert,E,coder,JOURNAL,MINT,fixture}=require('./helpers.cjs');
const {validateManifest}=require('../scripts/check-deployment.cjs');
const template=require('../deployment.example.json');
describe('Deployment and upstream schema boundaries',function(){
 it('matches the shared Rust EIP-712 and NSM binding vectors',async()=>{
  const v=require('./fixtures/mint-binding-v1.json'),f=await fixture();
  assert.equal(E.TypedDataEncoder.hash(v.domain,MINT,v.mint),v.mintDigest);
  assert.equal(E.keccak256(coder.encode(
   ['bytes32','uint256','address','address','bytes32','address','address','bytes32','bytes32','uint64','bytes32'],
   [await f.registry.BINDING_TYPEHASH(),v.bindingDomain.chain_id,v.bindingDomain.registry,v.bindingDomain.bridge,
    v.identity.vault_id,v.identity.signing_key,v.identity.decrypt_key,v.identity.tls_key_hash,v.identity.auth_key_hash,v.bindingDomain.policy_version,v.mintDigest])),v.userData);
 });
 it('rejects shared-network mocks/bypass and unreviewed real deployment',function(){
  for(const flag of ['allowMocks','bypassAttestation','devMode'])
   assert.throws(()=>validateManifest({...template,[flag]:true},{releases:[]}),/forbidden/);
  assert.throws(()=>validateManifest(template,{releases:[]}),/Shared deployment disabled/);
  assert.throws(()=>validateManifest({...template,chainId:31337},{releases:[]}),/Missing pin/);
 });
 it('decodes the genuine upstream historical journal; does not treat it as a mint proof',function(){
  const fixture=require('./fixtures/automata-pico-journal.json');
  const [j]=coder.decode([JOURNAL],fixture.publicValues);
  assert.equal(j.result,0n); assert.ok(j.timestamp > 1000000000000n);
  assert.ok(j.certs.length>0); assert.equal(j.trustedCertsPrefixLen,1n);
  // This old Pico fixture has no bridge keys/mint commitment and cannot authorize this application.
  assert.notEqual(j.publicKey.length,130);
 });
});
