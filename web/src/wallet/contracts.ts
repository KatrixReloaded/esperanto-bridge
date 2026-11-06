import { decodeFunctionResult, encodeFunctionData, getAddress, parseAbi, toEventSelector, type Hex } from 'viem'
import { BRIDGE_ADDRESS, DEPLOYMENT_BLOCK, FEE_TERMS_HASH, FIXED_FEE_ATOMIC, MIN_REDEEM_ATOMIC, LIVE_BLOCKER } from '../config'
import type { BridgeInfo, RedeemRecord } from '../api/types'
import { toAtomic } from '../lib/amount'
import { isRedeemId } from '../lib/validate'
import { metamask, type Eip1193Provider } from './metamask'

export const READ_ABI = parseAbi([
  'function token() view returns (address)', 'function registry() view returns (address)',
  'function decimals() view returns (uint8)', 'function authorized(bytes32 vaultId, bool completion) view returns (bool)',
  'function redemptions(uint256 id) view returns ((address user,bytes32 amount,bytes32[3] destination,bytes32 nonzero,bytes32 feeTermsHash,uint64 cancelAfter,uint8 status,bytes32 assignee,bytes32 paymentCommitment))',
])
const HEX32 = /^0x[0-9a-fA-F]{64}$/
const quantity = (n: bigint) => `0x${n.toString(16)}`
export async function finalizedHead(p: Eip1193Provider) {
  if (await p.request({ method: 'eth_chainId' }) !== '0xaa36a7') throw new Error('Sepolia wallet required')
  const head = await p.request({ method: 'eth_getBlockByNumber', params: ['finalized', false] }) as { hash?: string; number?: string } | null
  if (!head || !HEX32.test(head.hash ?? '') || !/^0x[0-9a-f]+$/i.test(head.number ?? '')) throw new Error('Finalized RPC head unavailable')
  return { hash: head.hash as Hex, number: BigInt(head.number!) }
}
async function read(p: Eip1193Provider, at: Hex, to: string, functionName: 'token' | 'registry' | 'decimals' | 'authorized' | 'redemptions', args?: readonly unknown[]): Promise<unknown> {
  const data = encodeFunctionData({ abi: READ_ABI, functionName, args } as Parameters<typeof encodeFunctionData>[0])
  const value = await p.request({ method: 'eth_call', params: [{ to, data }, { blockHash: at, requireCanonical: true }] }) as Hex
  return decodeFunctionResult({ abi: READ_ABI, functionName, data: value })
}
/** Reads are explicit observations of the user's trusted wallet RPC, not consensus verification. */
export async function readBridge(p = metamask.provider()): Promise<BridgeInfo> {
  const contract = getAddress(BRIDGE_ADDRESS)
  if (!/^(0|[1-9]\d*)$/.test(DEPLOYMENT_BLOCK)) throw new Error('Deployment block not configured')
  const head = await finalizedHead(p)
  const token = String(await read(p, head.hash, contract, 'token'))
  const registry = String(await read(p, head.hash, contract, 'registry'))
  if (await read(p, head.hash, token, 'decimals') !== 12) throw new Error('Unexpected token precision')
  const start = BigInt(DEPLOYMENT_BLOCK)
  // Explicit cap: fresh one-vault deployment discovery; never silently truncate eligible vaults.
  if (start > head.number || head.number - start > 16_384n) throw new Error('Vault discovery range exceeds local PoC limit')
  const ids = new Set<Hex>()
  for (let from = start; from <= head.number; from += 256n) {
    const to = from + 255n < head.number ? from + 255n : head.number
    const logs = await p.request({ method: 'eth_getLogs', params: [{ address: registry, fromBlock: quantity(from), toBlock: quantity(to), topics: [toEventSelector('VaultDiscovered(bytes32,address,address,uint64)')] }] }) as { address: string; topics: string[]; removed?: boolean }[]
    if (!Array.isArray(logs) || logs.length > 256) throw new Error('Invalid discovery response')
    for (const log of logs) {
      if (log.removed || log.address.toLowerCase() !== registry.toLowerCase() || !HEX32.test(log.topics?.[1] ?? '')) throw new Error('Invalid discovery log')
      ids.add(log.topics[1].toLowerCase() as Hex)
    }
    if (ids.size > 256) throw new Error('Too many discovered vaults')
  }
  const eligible: string[] = []
  for (const id of [...ids].sort()) if (await read(p, head.hash, registry, 'authorized', [id, false]) === true) eligible.push(id)
  // All active vaults in this bounded discovery scope must fit the on-chain ACL cap.
  const configured = HEX32.test(FEE_TERMS_HASH) && toAtomic(FIXED_FEE_ATOMIC) !== null && toAtomic(MIN_REDEEM_ATOMIC) !== null && BigInt(MIN_REDEEM_ATOMIC) > BigInt(FIXED_FEE_ATOMIC) && eligible.length > 0 && eligible.length <= 16
  return { network: 'stagenet', contract, token_contract: token, registry_contract: registry, chain_id: '11155111', fixed_fee_atomic: FIXED_FEE_ATOMIC, minimum_redeem_atomic: MIN_REDEEM_ATOMIC, fee_terms_hash: FEE_TERMS_HASH, eligible_vaults: eligible, scanner_ready: false, readiness_reason: configured ? LIVE_BLOCKER : 'Fee terms or eligible vaults are not configured.', persisted: { halted: false } }
}
export async function readRedemption(id: string, p = metamask.provider(), contract = BRIDGE_ADDRESS): Promise<RedeemRecord> {
  if (!isRedeemId(id)) throw new Error('Invalid request ID')
  const head = await finalizedHead(p)
  const r = await read(p, head.hash, getAddress(contract), 'redemptions', [BigInt(id)]) as { user: string; status: number; assignee: string; paymentCommitment: string; cancelAfter: bigint }
  if (r.status === 0) throw new Error('Request not observed at finalized RPC head')
  const status = ['absent', 'open', 'assigned', 'paid', 'refunded'][r.status] ?? 'unknown'
  return { id, status, user: r.user, assignee: /^0x0{64}$/.test(r.assignee) ? null : r.assignee, paymentCommitment: /^0x0{64}$/.test(r.paymentCommitment) ? null : r.paymentCommitment, actualPositive: r.status === 2 || r.status === 3 ? true : null, cancelAfter: r.cancelAfter.toString(), observedBlock: head.number.toString(), trust: 'wallet_rpc_observation' }
}
