import { useEffect, useRef, useState } from 'react'
import { api, type DepositIntent } from '../api'
import { DEMO, LIVE_BLOCKER } from '../config'
import { usePoll } from './usePoll'
import type { Wallet } from './useWallet'
import type { BridgeInfoState } from './useBridgeInfo'
/** A nonce is reused on retry. Private intent IDs are never put in URLs, logs, or storage. */
export function useDeposit(wallet: Wallet, bridge: BridgeInfoState) {
  const [issued, setIssued] = useState<DepositIntent | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const current = useRef({ recipient: wallet.address, generation: 0, nonce: '' })
  if (current.current.recipient !== wallet.address) current.current = { recipient: wallet.address, generation: current.current.generation + 1, nonce: '' }
  useEffect(() => { setIssued(null); setError(''); setBusy(false) }, [wallet.address])
  const own = issued?.recipient.toLowerCase() === wallet.address?.toLowerCase() ? issued : null
  const status = usePoll(own?.intentId ?? null, async (id, signal) => {
    const result = await api.getDepositIntent(id, signal)
    if (result.recipient.toLowerCase() !== own?.recipient.toLowerCase()) throw new Error('Recipient changed')
    return result
  })
  const blockReason = !DEMO ? LIVE_BLOCKER : !bridge.info?.scanner_ready ? 'Bridge unavailable.' : !wallet.connected ? 'Connect a Sepolia wallet.' : ''
  return { issued: own, status, busy, error, blockReason,
    async create() {
      if (busy || blockReason || !wallet.address) return
      const state = current.current, generation = state.generation
      state.nonce ||= '0x' + Array.from(crypto.getRandomValues(new Uint8Array(32)), n => n.toString(16).padStart(2, '0')).join('')
      setBusy(true); setError('')
      try { const intent = await api.createDepositIntent(wallet.address, state.nonce); if (current.current.generation === generation) setIssued(intent) }
      catch { if (current.current.generation === generation) setError('Could not issue an address. Retry keeps the same recipient and nonce.') }
      finally { if (current.current.generation === generation) setBusy(false) }
    },
  }
}
export type Deposit = ReturnType<typeof useDeposit>
