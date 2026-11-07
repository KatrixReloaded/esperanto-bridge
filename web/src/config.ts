/** Explicit simulation only. Unset mode is live and never falls back to fabricated success. */
export const DEMO = import.meta.env.VITE_BRIDGE_MODE === 'demo'
export const API_BASE = (import.meta.env.VITE_API_BASE ?? '').replace(/\/$/, '')
export const BRIDGE_ADDRESS = import.meta.env.VITE_BRIDGE_ADDRESS ?? ''
export const REGISTRY_ADDRESS = import.meta.env.VITE_REGISTRY_ADDRESS ?? ''
export const REGISTRY_CODE_HASH = import.meta.env.VITE_REGISTRY_CODE_HASH ?? ''
export const VAULT_ID = import.meta.env.VITE_VAULT_ID ?? ''
export const DEPLOYMENT_BLOCK = import.meta.env.VITE_DEPLOYMENT_BLOCK ?? ''
export const FEE_TERMS_HASH = import.meta.env.VITE_FEE_TERMS_HASH ?? ''
export const FIXED_FEE_ATOMIC = import.meta.env.VITE_FIXED_FEE_ATOMIC ?? ''
export const MIN_REDEEM_ATOMIC = import.meta.env.VITE_MIN_REDEEM_ATOMIC ?? ''
export const LIVE_BLOCKER = 'Waiting for an authorized enclave connection through Nym.'
export const POLL_MS = DEMO ? 1000 : 5000
export const DEFAULT_CHAIN_ID = '11155111'
export const explorerTx = (hash: string) => `https://sepolia.etherscan.io/tx/${hash}`
export const explorerAddress = (address: string) => `https://sepolia.etherscan.io/address/${address}`
