export type Unsubscribe = () => void
export interface BridgeInfo {
  network: 'stagenet'; contract: string; token_contract: string; registry_contract: string; chain_id: string
  fixed_fee_atomic: string; minimum_redeem_atomic: string; fee_terms_hash: string; eligible_vaults: string[]
  scanner_ready: boolean; readiness_reason: string; persisted: { halted: boolean }
}
export interface Health { runtime: string; native_development: boolean; bridge_actions_enabled: boolean; required_gates: string[] }
export type DepositStatus = 'awaiting_deposit' | 'confirming' | 'proving' | 'minting' | 'minted' | 'failed' | 'quarantined' | (string & {})
export interface DepositIntent {
  intentId: string; vaultId: string; recipient: string; depositAddress: string; network: 'stagenet'; status: DepositStatus
}
export type RedeemStatus = 'open' | 'assigned' | 'paid' | 'refunded' | 'completed_zero' | (string & {})
export interface RedeemRecord {
  id: string; status: RedeemStatus; user: string; assignee: string | null; paymentCommitment: string | null
  actualPositive: boolean | null; cancelAfter: string; observedBlock: string; trust: 'wallet_rpc_observation' | 'demo'
}
export interface PrepareRequest {
  operation_id: string; user: string; amount: string; monero_address: string; chain_id: string; contract: string
  fee_terms_hash: string; eligible_vaults: string[]
}
export interface PreparedTransaction { from: string; to: string; chainId: string; value: string; data: string }
/** Locally prepared ciphertext, revalidated before any wallet prompt. No server prepare route exists. */
export interface PrepareResponse {
  operation_id: string; already_submitted: boolean; transaction?: PreparedTransaction; transaction_hash?: string
  fixed_fee_atomic?: string; minimum_redeem_atomic?: string
}
export interface BridgeApi {
  getInfo(signal?: AbortSignal): Promise<BridgeInfo>
  createDepositIntent(recipient: string, nonce: string, signal?: AbortSignal): Promise<DepositIntent>
  getDepositIntent(intentId: string, signal?: AbortSignal): Promise<DepositIntent>
  getRedeem(id: string, signal?: AbortSignal): Promise<RedeemRecord | null>
  prepareRedeem(request: PrepareRequest, signal?: AbortSignal): Promise<PrepareResponse>
}
