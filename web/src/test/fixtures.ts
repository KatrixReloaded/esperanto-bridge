import type { DepositIntent, RedeemRecord } from '../api/types'
import { INFO, DEMO_ADDRESS, DEMO_VAULT, DEMO_USER } from '../api/mock'
export const info = INFO
export const deposit = (over: Partial<DepositIntent> = {}): DepositIntent => ({ intentId: DEMO_VAULT, vaultId: DEMO_VAULT, recipient: DEMO_USER, depositAddress: DEMO_ADDRESS, network: 'stagenet', status: 'awaiting_deposit', ...over })
export const redeem = (over: Partial<RedeemRecord> = {}): RedeemRecord => ({ id: '1', status: 'open', user: DEMO_USER, actualPositive: null, assignee: null, paymentCommitment: null, cancelAfter: '100', observedBlock: '100', trust: 'wallet_rpc_observation', ...over })
