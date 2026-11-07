import { useEffect, useRef, useState } from 'react'
import { api, type DepositIntent } from '../api'
import { usePoll } from './usePoll'
import type { Wallet } from './useWallet'
import type { BridgeInfoState } from './useBridgeInfo'
/** A nonce is reused on retry. Private intent IDs are never put in URLs, logs, or storage. */
export function useDeposit(wallet: Wallet, bridge: BridgeInfoState) {
  const [issued, setIssued] = useState<DepositIntent | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [savedIntentId, setSavedIntentId] = useState('')
  const current = useRef({ recipient: wallet.address, generation: 0, nonce: '' })
  if (current.current.recipient !== wallet.address) current.current = { recipient: wallet.address, generation: current.current.generation + 1, nonce: '' }
  useEffect(() => { setIssued(null); setError(''); setBusy(false); setSavedIntentId('') }, [wallet.address])
  const own = issued?.recipient.toLowerCase() === wallet.address?.toLowerCase() ? issued : null
  const status = usePoll(own?.intentId ?? null, async (id, signal) => {
    const result = await api.getDepositIntent(id, signal)
    if (result.recipient.toLowerCase() !== own?.recipient.toLowerCase()) throw new Error('Recipient changed')
    return result
  })
  const blockReason = !wallet.connected ? 'Connect a Sepolia wallet.' : bridge.error || !bridge.info?.scanner_ready ? bridge.errorDetail || bridge.info?.readiness_reason || 'Bridge unavailable.' : ''
  return { issued: own, status, busy, error, blockReason, savedIntentId,
    editSavedIntentId: (value: string) => { setSavedIntentId(value.trim()); setError('') },
    async resume() {
      if (busy || blockReason || !wallet.address) return
      if (!/^0x[0-9a-fA-F]{64}$/.test(savedIntentId)) {
        setError('Enter your private deposit intent ID (0x followed by 64 hexadecimal characters).')
        return
      }
      const { generation } = current.current
      const recipient = wallet.address
      setBusy(true); setError('')
      try {
        const intent = await api.getDepositIntent(savedIntentId)
        if (intent.recipient.toLowerCase() !== recipient.toLowerCase()) throw new Error('Recipient mismatch')
        if (current.current.generation === generation) { setIssued(intent); setSavedIntentId('') }
      } catch {
        if (current.current.generation === generation) setError('Could not restore this deposit. Check the intent ID and connect its recipient wallet.')
      } finally {
        if (current.current.generation === generation) setBusy(false)
      }
    },
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
