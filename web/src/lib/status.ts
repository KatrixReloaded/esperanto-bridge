import { WalletReadError } from '../wallet/readError'
import { TunnelError } from '../api/nym'
import type { BridgeInfo, DepositIntent, RedeemRecord } from '../api/types'
export type PanelKind = 'alert' | 'info' | 'check'
export type Stage = { kind: 'progress'; step: number; detail: string } | { kind: 'panel'; panel: PanelKind; title: string; detail: string } | { kind: 'done' }
const panel = (title: string, detail: string, kind: PanelKind = 'info'): Stage => ({ kind: 'panel', panel: kind, title, detail })
export const DEPOSIT_STEPS = ['Awaiting deposit', 'Confirming', 'Proving', 'Minting', 'Minted']
export const REDEEM_STEPS = ['Requested', 'Assigned', 'Settled']
export function depositStage(d: DepositIntent): Stage {
  const step = ['awaiting_deposit', 'confirming', 'proving', 'minting'].indexOf(d.status)
  if (step >= 0) return { kind: 'progress', step, detail: [
    'Send stagenet XMR to your deposit address.',
    'Waiting for confirmations.',
    'Preparing mint.',
    'Confirming mint.',
  ][step] }
  if (d.status === 'minted') return { kind: 'done' }
  if (d.status === 'failed') return panel('Mint did not succeed', 'Keep your intent ID.', 'alert')
  if (d.status === 'quarantined') return panel('Deposit requires review', 'Keep your intent ID.', 'alert')
  return panel('Unknown status', 'Status unavailable.')
}
export function redeemStage(r: RedeemRecord): Stage {
  if (r.status === 'completed_zero' || r.actualPositive === false) return panel('Nothing redeemed', 'No XMR payout.')
  if (r.status === 'paid') return { kind: 'done' }
  if (r.status === 'refunded') return panel('Refund recorded', 'Reveal your balance to check the refund.', 'check')
  if (r.status === 'assigned') return { kind: 'progress', step: 1, detail: 'Processing XMR payout.' }
  if (r.status === 'open') return { kind: 'progress', step: 0, detail: 'Waiting for a vault.' }
  return panel('Unknown status', 'Status unavailable.')
}
export type InfoBanner = 'nym' | 'unavail' | 'paused' | 'notready'
export function infoBanner(info: BridgeInfo | undefined, error: unknown): InfoBanner | null {
  if (error instanceof TunnelError) return 'nym'
  if (error) return 'unavail'
  if (!info) return null
  if (info.persisted.halted) return 'paused'
  return info.scanner_ready ? null : 'notready'
}

/** Never display arbitrary provider errors, which can contain RPC payloads or URLs. */
export function bridgeErrorMessage(error: unknown): string | undefined {
  if (!error) return undefined
  if (error instanceof WalletReadError) return `Wallet RPC failed at ${error.stage}${error.rpcCodes.length ? ` (RPC code ${error.rpcCodes.join(', ')})` : ' (no RPC code)'}. Check MetaMask’s RPC connection.`
  const message = error instanceof Error ? error.message : ''
  if (message === 'MetaMask is not installed') return 'Enable MetaMask and connect on Sepolia.'
  if (message === 'Sepolia wallet required') return 'Switch MetaMask to Sepolia.'
  if (message === 'Deployment block not configured' || message === 'Vault discovery range exceeds local PoC limit') return 'Bridge configuration needs updating.'
  if (message === 'Unexpected token precision') return 'Token configuration mismatch.'
  if (error instanceof TunnelError) return 'Nym could not start. Reload to reconnect.'
  return 'Check MetaMask’s Sepolia network and RPC connection.'
}
