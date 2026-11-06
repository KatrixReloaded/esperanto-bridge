// Explicit demo mode only. No money moves; all lifecycle observations are simulated.
import { encodeFunctionData, keccak256, stringToHex, type Hex } from 'viem'
import type { BridgeApi, BridgeInfo, DepositIntent, RedeemRecord } from './types'
import { CWXMR_ABI } from '../lib/redeemTx'
export const DEMO_USER = '0x12ab34cd56ef7890a1b2c3d4e5f60718293a4b5c'
export const DEMO_ADDRESS = '51sMKEsmA5v1Ajszg3RAw21Ajszg3RAw21Ajszg3RAw21Ajszg3RAw21Ajszg3RAw21Ajszg3RAw21Ajszg3RAw21CQ7nfY'
export const DEMO_VAULT = ('0x' + '11'.repeat(32)) as Hex
export const DEMO_FEE = ('0x' + '22'.repeat(32)) as Hex
export const INFO: BridgeInfo = { network: 'stagenet', contract: '0x1111111111111111111111111111111111111111', token_contract: '0x2222222222222222222222222222222222222222', registry_contract: '0x3333333333333333333333333333333333333333', chain_id: '11155111', fixed_fee_atomic: '100000000', minimum_redeem_atomic: '100000001', fee_terms_hash: DEMO_FEE, eligible_vaults: [DEMO_VAULT], scanner_ready: true, readiness_reason: '', persisted: { halted: false } }
const intents = new Map<string, { value: DepositIntent; at: number }>()
const redemptions = new Map<string, { user: string; positive: boolean; at: number }>()
const preparedAmounts = new Map<string, bigint>()
export const demoBalance = () => 12_500_000_000_000n
export const demoHandle = (type = '05') => ('0x' + 'ab'.repeat(22) + '0000000000aa36a7' + type + '00') as Hex
export function demoRedeemSubmitted(id: string, user: string, data: string) {
  if (!redemptions.has(id)) redemptions.set(id, { user, positive: (preparedAmounts.get(data) ?? 0n) > 0n && (preparedAmounts.get(data) ?? 0n) <= demoBalance(), at: Date.now() })
}
export const mockApi: BridgeApi = {
  async getInfo() { return INFO },
  async createDepositIntent(recipient, nonce) {
    const intentId = keccak256(stringToHex(recipient.toLowerCase() + nonce))
    const value: DepositIntent = { intentId, vaultId: DEMO_VAULT, recipient, depositAddress: DEMO_ADDRESS, network: 'stagenet', status: 'awaiting_deposit' }
    if (!intents.has(intentId)) intents.set(intentId, { value, at: Date.now() })
    return intents.get(intentId)!.value
  },
  async getDepositIntent(id) {
    const v = intents.get(id)
    if (!v) throw new Error('Unknown demo intent')
    const status = ['awaiting_deposit', 'confirming', 'proving', 'minting', 'minted'][Math.min(4, Math.floor((Date.now() - v.at) / 4000))]
    return { ...v.value, status }
  },
  async prepareRedeem(req) {
    const data = encodeFunctionData({ abi: CWXMR_ABI, functionName: 'requestRedemption', args: [demoHandle(), [demoHandle('08'), demoHandle('08'), demoHandle('08')], stringToHex(req.operation_id), req.fee_terms_hash as Hex, req.eligible_vaults as Hex[]] })
    preparedAmounts.set(data, BigInt(req.amount))
    return { operation_id: req.operation_id, already_submitted: false, transaction: { from: req.user, to: req.contract, chainId: '0xaa36a7', value: '0x0', data }, fixed_fee_atomic: INFO.fixed_fee_atomic, minimum_redeem_atomic: INFO.minimum_redeem_atomic }
  },
  async getRedeem(id): Promise<RedeemRecord> {
    const r = redemptions.get(id)
    if (!r) throw new Error('Unknown demo request')
    const status = !r.positive ? 'completed_zero' : Date.now() - r.at > 8000 ? 'paid' : Date.now() - r.at > 4000 ? 'assigned' : 'open'
    return { id, status, user: r.user, actualPositive: r.positive, assignee: status === 'assigned' || status === 'paid' ? DEMO_VAULT : null, paymentCommitment: status === 'paid' ? DEMO_FEE : null, cancelAfter: String(Math.floor(r.at / 1000) + 3600), observedBlock: '0', trust: 'demo' }
  },
}
