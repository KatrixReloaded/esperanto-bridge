import { TunnelError } from '../api/nym'
import type { BridgeInfo, DepositIntent, RedeemRecord } from '../api/types'
export type PanelKind = 'alert' | 'info' | 'check'
export type Stage = { kind: 'progress'; step: number; detail: string } | { kind: 'panel'; panel: PanelKind; title: string; detail: string } | { kind: 'done' }
const panel = (title: string, detail: string, kind: PanelKind = 'info'): Stage => ({ kind: 'panel', panel: kind, title, detail })
export const DEPOSIT_STEPS = ['Awaiting deposit', 'Confirming', 'Proving', 'Minting', 'Minted']
export const REDEEM_STEPS = ['Requested', 'Assigned', 'Settled']
export function depositStage(d: DepositIntent): Stage {
  const step = ['awaiting_deposit', 'confirming', 'proving', 'minting'].indexOf(d.status)
  if (step >= 0) return { kind: 'progress', step, detail: step === 0 ? 'Only send stagenet XMR to this issued address.' : 'Waiting for the bridge. Do not create a duplicate deposit.' }
  if (d.status === 'minted') return { kind: 'done' }
  if (d.status === 'failed') return panel('Mint did not succeed', 'The actual encrypted mint result was zero. Contact the operator with your private intent ID.', 'alert')
  if (d.status === 'quarantined') return panel('Deposit requires review', 'Automatic processing stopped. Keep your private intent ID.', 'alert')
  return panel('Unknown status', 'No completion is inferred from this response.')
}
export function redeemStage(r: RedeemRecord): Stage {
  if (r.status === 'completed_zero' || r.actualPositive === false) return panel('Nothing redeemed', 'The actual encrypted burn was zero. No XMR payout is owed.')
  if (r.status === 'paid') return { kind: 'done' }
  if (r.status === 'refunded') return panel('Refund recorded', 'The actual burned amount was credited once. Reveal your balance to check it.', 'check')
  if (r.status === 'assigned') return { kind: 'progress', step: 1, detail: 'A vault has claimed this request. Only that vault may settle it; cancellation is unavailable.' }
  if (r.status === 'open') return { kind: 'progress', step: 0, detail: 'Actual burn amount remains encrypted. This receipt alone does not establish a positive payout. Only an unassigned request may be cancelled after its deadline.' }
  return panel('Unknown status', 'No settlement is inferred.')
}
export type InfoBanner = 'nym' | 'unavail' | 'paused' | 'notready'
export function infoBanner(info: BridgeInfo | undefined, error: unknown): InfoBanner | null {
  if (error instanceof TunnelError) return 'nym'
  if (error) return 'unavail'
  if (!info) return null
  if (info.persisted.halted) return 'paused'
  return info.scanner_ready ? null : 'notready'
}
