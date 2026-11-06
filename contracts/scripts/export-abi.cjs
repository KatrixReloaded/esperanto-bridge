const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
for (const name of ['Bridge', 'CWXMR', 'VaultRegistry', 'NitroVerifierAdapter']) {
  const artifact = JSON.parse(fs.readFileSync(path.join(root, 'artifacts/contracts', `${name}.sol`, `${name}.json`)));
  fs.writeFileSync(path.join(root, 'abi', `${name}.json`), JSON.stringify(artifact.abi, null, 2) + '\n');
}
