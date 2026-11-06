import { encodeFunctionData, type Hex } from 'viem'
import { BROWSER_ATTESTATION_READY, LIVE_BLOCKER } from '../config'
import { decodeDestination } from '../lib/monero'
import { CWXMR_ABI } from '../lib/redeemTx'
import { MAX_ATOMIC } from '../lib/amount'
import { readBridge, readRedemption } from '../wallet/contracts'
import { metamask } from '../wallet/metamask'
import { getJson, postJson } from './http'
import type { BridgeApi, DepositIntent, Health, PrepareRequest } from './types'
const hex32 = /^0x[0-9a-fA-F]{64}$/
export function validateIntent(value: unknown, expected?: { recipient?: string; intentId?: string }): DepositIntent {
  const v = value as DepositIntent
  if (!v || !hex32.test(v.intentId) || !hex32.test(v.vaultId) || !/^0x[0-9a-fA-F]{40}$/.test(v.recipient) || v.network !== 'stagenet' || typeof v.status !== 'string' || v.status.length > 64 || (expected?.recipient && v.recipient.toLowerCase() !== expected.recipient.toLowerCase()) || (expected?.intentId && v.intentId.toLowerCase() !== expected.intentId.toLowerCase())) throw new Error('Invalid deposit intent response')
  decodeDestination(v.depositAddress)
  return v
}
export async function requireLiveActions() {
  // This is deliberately not an environment toggle: browser attested TLS is not implemented.
  if (!BROWSER_ATTESTATION_READY) throw new Error(LIVE_BLOCKER)
  const h = await getJson<Health>('/health')
  if (h.native_development !== false || h.bridge_actions_enabled !== true) throw new Error('Bridge actions unavailable')
}
/** SDK encryption happens in this browser; there is no server prepare/redeem route. */
export async function prepareLocally(req: PrepareRequest) {
  if (req.chain_id !== '11155111' || !/^[1-9]\d*$/.test(req.amount) || BigInt(req.amount) > MAX_ATOMIC || !hex32.test(req.fee_terms_hash)) throw new Error('Invalid redemption terms')
  if (req.eligible_vaults.length < 1 || req.eligible_vaults.length > 16 || req.eligible_vaults.some((v, i, a) => !hex32.test(v) || (i > 0 && BigInt(v) <= BigInt(a[i - 1])))) throw new Error('Invalid eligible vaults')
  const destination = decodeDestination(req.monero_address)
  const { encryptRedemption } = await import('../wallet/fhe')
  const encrypted = await encryptRedemption(metamask.provider(), req.user, req.contract, BigInt(req.amount), destination.words)
  const data = encodeFunctionData({ abi: CWXMR_ABI, functionName: 'requestRedemption', args: [encrypted.handles[0] as Hex, encrypted.handles.slice(1) as [Hex, Hex, Hex], encrypted.proof, req.fee_terms_hash as Hex, req.eligible_vaults as Hex[]] })
  return { operation_id: req.operation_id, already_submitted: false, transaction: { from: req.user, to: req.contract, chainId: '0xaa36a7', value: '0x0', data } }
}
export const liveApi: BridgeApi = {
  async getInfo(signal) {
    const info = await readBridge()
    try {
      const h = await getJson<Health>('/health', signal)
      if (h.bridge_actions_enabled !== true) info.readiness_reason = `Backend is not ready. ${LIVE_BLOCKER}`
    } catch { info.readiness_reason = `Backend health unavailable. ${LIVE_BLOCKER}` }
    return info
  },
  async createDepositIntent(recipient, nonce, signal) {
    if (!/^0x[0-9a-fA-F]{40}$/.test(recipient) || !hex32.test(nonce)) throw new Error('Invalid intent inputs')
    await requireLiveActions()
    return validateIntent(await postJson('/v1/deposit-intents', { recipient, nonce }, signal), { recipient })
  },
  async getDepositIntent(intentId, signal) {
    if (!hex32.test(intentId)) throw new Error('Invalid intent ID')
    // Recipient mapping is private bearer data; never fetch it over unverified enclave TLS.
    await requireLiveActions()
    return validateIntent(await getJson(`/v1/deposit-intents/${intentId}`, signal), { intentId })
  },
  getRedeem: id => readRedemption(id),
  async prepareRedeem(req) { await requireLiveActions(); return prepareLocally(req) },
}
