// Read-only validation. This script never signs or broadcasts a transaction.
const fs = require('node:fs');
const path = require('node:path');
const { JsonRpcProvider, Contract, keccak256, isHexString, getAddress } = require('ethers');
const AUTOMATA_REVISION = '65c4a4233029ea3bbe16110a80731fcfd47cf300';
function fail(message) { throw new Error(message); }
function validateManifest(m, releasePolicy) {
  if (!Number.isSafeInteger(m.chainId) || m.chainId <= 0) fail('Invalid chain ID');
  if (m.automataRevision !== AUTOMATA_REVISION) fail('Unreviewed Automata revision');
  const local = m.chainId === 31337;
  if (!local) {
    if (m.allowMocks || m.bypassAttestation || m.devMode) fail('Mocks and attestation bypass are forbidden on shared networks');
    // Shared release must be reviewed and committed, not activated by an environment flag.
    const release = releasePolicy.releases.find(r => r.chainId === m.chainId && r.manifestHash === keccak256(Buffer.from(JSON.stringify(m))));
    if (!release || !release.realNitroRoundTripEvidence || !release.productionZamaRoundTripEvidence || !release.reviewCommit)
      fail('Shared deployment disabled: no reviewed release with real Nitro and production Zama evidence');
  }
  for (const field of ['verifierCodeHash','zkVerifierCodeHash','programId','rootCert'])
    if (!isHexString(m[field],32) || /^0x0+$/.test(m[field])) fail(`Missing pin: ${field}`);
  for (const field of ['verifier','zkVerifier']) if (getAddress(m[field]) === '0x0000000000000000000000000000000000000000') fail(`Missing address: ${field}`);
  if (![1,2].includes(m.coprocessor) || !isHexString(m.proofSelector,4)) fail('Unsupported proof backend/selector');
  return local;
}
async function checkRpc(m, rpcUrl) {
  if (m.chainId === 31337 && !['localhost','127.0.0.1','[::1]'].includes(new URL(rpcUrl).hostname))
    fail('Local test configuration requires a loopback RPC');
  const provider = new JsonRpcProvider(rpcUrl);
  if ((await provider.getNetwork()).chainId !== BigInt(m.chainId)) fail('RPC chain ID mismatch');
  const block = await provider.getBlockNumber();
  for (const [addressField, hashField] of [['verifier','verifierCodeHash'], ['zkVerifier','zkVerifierCodeHash']]) {
    const code = await provider.getCode(m[addressField], block);
    if (code === '0x' || keccak256(code) !== m[hashField]) fail(`Runtime code mismatch: ${addressField}`);
    // Explicit rejection of the repository's test mock even if a manifest supplies its hash.
    const mockPath = path.resolve(__dirname,'../artifacts/contracts/test/MockNitroVerifier.sol/MockNitroVerifier.json');
    if (fs.existsSync(mockPath) && code === JSON.parse(fs.readFileSync(mockPath)).deployedBytecode && m.chainId !== 31337)
      fail('Test verifier forbidden on shared network');
  }
  const v = new Contract(m.verifier,[
    'function rootCert() view returns(bytes32)',
    'function isVerifierIdSupported(uint8,bytes32) view returns(bool)',
    'function getZkVerifier(uint8,bytes4) view returns(address)'
  ],provider);
  if (await v.rootCert({blockTag:block}) !== m.rootCert || !await v.isVerifierIdSupported(m.coprocessor,m.programId,{blockTag:block}) ||
      getAddress(await v.getZkVerifier(m.coprocessor,m.proofSelector,{blockTag:block})) !== getAddress(m.zkVerifier))
    fail('Live verifier configuration differs from pins');
  console.log(`Read-only configuration checks passed at block ${block}; deployment was not performed.`);
  provider.destroy();
}
if (require.main === module) {
  (async()=>{
    if (!process.argv[2]) fail('Usage: node scripts/check-deployment.cjs manifest.json [RPC_URL]');
    const m=JSON.parse(fs.readFileSync(process.argv[2]));
    const policy=JSON.parse(fs.readFileSync(path.resolve(__dirname,'../shared-network-policy.json')));
    validateManifest(m,policy);
    if (process.argv[3]) await checkRpc(m,process.argv[3]);
    else console.log('Manifest shape validated; RPC and runtime verification not performed.');
  })().catch(e=>{console.error(e.message);process.exitCode=1;});
}
module.exports={validateManifest,checkRpc};
