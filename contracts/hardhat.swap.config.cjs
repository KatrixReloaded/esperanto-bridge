// Signature verification only, on an in-process Sepolia-ID chain. No FHE plugin,
// RPC, funded exchange, or external network. Compile first with hardhat.pool.config.cjs.
require('@nomicfoundation/hardhat-ethers');
module.exports = { solidity: '0.8.28', networks: { hardhat: { chainId: 11155111 } }, paths: { artifacts: './artifacts/pool', cache: './cache/pool' } };
