import { formatAtomic, parseXmr } from './amount'
import { decodeDestination } from './monero'
export function amountError(value: string, min: bigint | null, balance: bigint | null) {
  value = value.trim()
  if (!value) return ''
  if (!/^\d*\.?\d*$/.test(value) || value === '.') return 'Enter an amount.'
  if ((value.split('.')[1] || '').length > 12) return 'Use up to 12 decimal places.'
  const n = parseXmr(value)
  if (n === null) return 'Amount exceeds the cwXMR uint64 capacity.'
  if (n === 0n) return 'Enter an amount greater than 0.'
  if (min !== null && n < min) return `Minimum is ${formatAtomic(min)} cwXMR.`
  if (balance !== null && n > balance) return 'More than your balance.'
  return ''
}
export function destinationError(value: string) {
  if (!value.trim()) return ''
  try { decodeDestination(value.trim()); return '' } catch (error) { return (error as Error).message }
}
export const isRedeemId = (value: string) => /^(0|[1-9]\d{0,77})$/.test(value) && BigInt(value) < (1n << 256n)
