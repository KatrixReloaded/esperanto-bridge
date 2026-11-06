const {assert,coder,JOURNAL}=require('./helpers.cjs');
const {validateManifest}=require('../scripts/check-deployment.cjs');
const template=require('../deployment.example.json');
describe('Deployment and upstream schema boundaries',function(){
 it('rejects shared-network mocks/bypass and unreviewed real deployment',function(){
  for(const flag of ['allowMocks','bypassAttestation','devMode'])
   assert.throws(()=>validateManifest({...template,[flag]:true},{releases:[]}),/forbidden/);
  assert.throws(()=>validateManifest(template,{releases:[]}),/Shared deployment disabled/);
  assert.throws(()=>validateManifest({...template,chainId:31337},{releases:[]}),/Missing pin/);
 });
 it('decodes the genuine upstream historical journal; does not treat it as bridge enrollment',function(){
  const fixture=require('./fixtures/automata-pico-journal.json');
  const [j]=coder.decode([JOURNAL],fixture.publicValues);
  assert.equal(j.result,0n); assert.ok(j.timestamp > 1000000000000n);
  assert.ok(j.certs.length>0); assert.equal(j.trustedCertsPrefixLen,1n);
  // This old Pico fixture has no bridge keys/challenge and cannot authorize this application.
  assert.notEqual(j.publicKey.length,130);
 });
});
