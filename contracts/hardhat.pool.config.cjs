// Keep pool validation separate from existing Foundry and deployed bridge artifacts.
const base = require('./hardhat.config.cjs');
module.exports = { ...base, paths: { ...base.paths, artifacts: './artifacts/pool', cache: './cache/pool' } };
