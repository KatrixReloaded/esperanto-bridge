import { expect, it } from 'vitest'
import { formatAtomic, MAX_ATOMIC, parseXmr, toAtomic } from './amount'
import { amountError } from './validate'
it('uses exact twelve decimal atomic units and u64 capacity', () => {
  expect(parseXmr('1.5')).toBe(1_500_000_000_000n)
  expect(parseXmr('.000000000001')).toBe(1n)
  expect(formatAtomic(1n)).toBe('0.000000000001')
  expect(formatAtomic(MAX_ATOMIC)).toBe('18446744.073709551615')
  expect(parseXmr(formatAtomic(MAX_ATOMIC))).toBe(MAX_ATOMIC)
  expect(parseXmr('18446744.073709551616')).toBeNull()
  for (const v of ['', '.', '1e5', '-1', '0.0000000000001']) expect(parseXmr(v)).toBeNull()
  for (const v of [undefined, null, '', '1.5', '-1', 10001, (MAX_ATOMIC + 1n).toString()]) expect(toAtomic(v)).toBeNull()
  expect(amountError('2', 1n, 1_500_000_000_000n)).toBe('More than your balance.')
})
