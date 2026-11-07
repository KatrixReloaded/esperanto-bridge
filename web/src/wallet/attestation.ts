import { decodeFunctionResult, encodeFunctionData, getAddress, keccak256, parseAbi, type Hex } from 'viem'
import { API_BASE, BRIDGE_ADDRESS, REGISTRY_ADDRESS, REGISTRY_CODE_HASH, VAULT_ID } from '../config'
import { walletRead } from './readError'
import { finalizedHead } from './contracts'
import { metamask, type Eip1193Provider } from './metamask'

const hex32 = /^0x[0-9a-fA-F]{64}$/
const abi = parseAbi([
  'function registry() view returns (address)',
  'function authorized(bytes32,bool) view returns (bool)',
  'function vaults(bytes32) view returns (address signingKey,address decryptKey,bytes32 tlsKeyHash,bytes32 authKeyHash,bytes32 pcrTuple,uint64 policyVersion,uint8 status)',
])
export interface AttestedPeer { origin: string; spkiSha256: string; vaultId: string; blockHash: string }

/** Authority is the finalized on-chain directory, not the HTTP server or a configuration boolean. */
export async function readAttestedPeer(p: Eip1193Provider = metamask.provider()): Promise<AttestedPeer> {
  const origin = new URL(API_BASE)
  if (origin.protocol !== 'https:' || origin.username || origin.password || origin.pathname !== '/' || origin.search || origin.hash || !hex32.test(REGISTRY_CODE_HASH) || !hex32.test(VAULT_ID)) throw new Error('Enclave verification is not configured')
  const registry = getAddress(REGISTRY_ADDRESS)
  const head = await finalizedHead(p)
  const block = await walletRead('authority timestamp (eth_getBlockByHash)', () => p.request({ method: 'eth_getBlockByHash', params: [head.hash, false] })) as { hash?: string; timestamp?: string } | null
  if (!block || block.hash?.toLowerCase() !== head.hash.toLowerCase() || !/^0x[0-9a-f]+$/i.test(block.timestamp ?? '')) throw new Error('Invalid finalized block')
  const age = BigInt(Math.floor(Date.now() / 1000)) - BigInt(block.timestamp!)
  if (age < -30n || age > 1200n) throw new Error('Finalized authority is stale')
  const at = { blockHash: head.hash, requireCanonical: true }
  const code = await walletRead('registry bytecode (eth_getCode, canonical block hash)', () => p.request({ method: 'eth_getCode', params: [registry, at] })) as Hex
  if (!/^0x(?:[0-9a-fA-F]{2})+$/.test(code) || keccak256(code).toLowerCase() !== REGISTRY_CODE_HASH.toLowerCase()) throw new Error('Registry code differs from its pin')
  async function read(to: string, name: 'registry' | 'authorized' | 'vaults', args?: readonly unknown[]): Promise<unknown> {
    const data = encodeFunctionData({ abi, functionName: name, args } as Parameters<typeof encodeFunctionData>[0])
    const result = await walletRead(`authority ${name} (eth_call, canonical block hash)`, () => p.request({ method: 'eth_call', params: [{ to, data }, at] })) as Hex
    return decodeFunctionResult({ abi, functionName: name, data: result })
  }
  if (getAddress(String(await read(getAddress(BRIDGE_ADDRESS), 'registry'))) !== registry) throw new Error('Bridge registry mismatch')
  // authorized checks lifecycle, the current PCR policy, and the live Automata adapter configuration.
  if (await read(registry, 'authorized', [VAULT_ID, false]) !== true) throw new Error('Vault is not authorized')
  const record = await read(registry, 'vaults', [VAULT_ID]) as readonly [string, string, string, string, string, bigint, number]
  const pin = record[2]
  if (record[6] !== 1 || !hex32.test(pin) || /^0x0{64}$/.test(pin)) throw new Error('Vault TLS identity is unavailable')
  return { origin: origin.origin, spkiSha256: pin.slice(2).toLowerCase(), vaultId: VAULT_ID.toLowerCase(), blockHash: head.hash }
}
