import { expect, it } from 'vitest'
import { deposit, redeem, info } from '../test/fixtures'
import { depositStage, redeemStage, infoBanner } from './status'
it('only minted is successful; failed zero-result and unknown states fail closed', () => {
  expect(depositStage(deposit({ status: 'minted' })).kind).toBe('done')
  for (const status of ['failed', 'quarantined', 'unexpected']) expect(depositStage(deposit({ status })).kind).toBe('panel')
})
it('a successful burn receipt alone cannot establish positive entitlement', () => {
  expect(redeemStage(redeem()).kind).toBe('progress')
  expect(redeemStage(redeem({ actualPositive: false })).kind).toBe('panel')
  expect(redeemStage(redeem({ status: 'paid', actualPositive: true })).kind).toBe('done')
  expect(redeemStage(redeem({ status: 'refunded' })).kind).toBe('panel')
})
it('readiness and errors suppress stale ready state', () => {
  expect(infoBanner(info, new Error())).toBe('unavail')
  expect(infoBanner({ ...info, scanner_ready: false }, null)).toBe('notready')
})
