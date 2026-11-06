import { api } from '../api'
import { toAtomic } from '../lib/amount'
import { infoBanner } from '../lib/status'
import { usePoll } from './usePoll'

export function useBridgeInfo() {
  const poll = usePoll('info', (_, signal) => api.getInfo(signal))
  const info = poll.data
  return {
    ...poll,
    info,
    banner: infoBanner(info, poll.error),
    feeAtomic: toAtomic(info?.fixed_fee_atomic),
    minAtomic: toAtomic(info?.minimum_redeem_atomic),
    halted: !!info?.persisted?.halted,
  }
}

export type BridgeInfoState = ReturnType<typeof useBridgeInfo>
