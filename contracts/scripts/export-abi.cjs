const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
for (const name of ['Bridge', 'CWXMR', 'VaultRegistry', 'NitroVerifierAdapter']) {
  const artifact = JSON.parse(fs.readFileSync(path.join(root, 'artifacts/contracts', `${name}.sol`, `${name}.json`)));
  const abi = JSON.stringify(artifact.abi, null, 2) + '\n';
  fs.writeFileSync(path.join(root, 'abi', `${name}.json`), abi);
  if (name === 'Bridge') fs.writeFileSync(path.join(root, '../service/crates/zama/abi/Bridge.json'), abi);
}
