export const ATOMIC_UNITS = 1_000_000_000_000n
export const MAX_ATOMIC = (1n << 64n) - 1n
/** Exact XMR atomic units, 12 decimals and no floating point. */
export function formatAtomic(value: bigint | string) {
  const n = BigInt(value), a = n < 0n ? -n : n
  const frac = (a % ATOMIC_UNITS).toString().padStart(12, '0').replace(/0+$/, '')
  return `${n < 0n ? '-' : ''}${a / ATOMIC_UNITS}.${frac || '0'}`
}
export function parseXmr(value: string): bigint | null {
  const m = /^(\d*)(?:\.(\d*))?$/.exec(value.trim())
  if (!m || (!m[1] && !m[2]) || (m[2] ?? '').length > 12) return null
  const n = BigInt(m[1] || '0') * ATOMIC_UNITS + BigInt((m[2] ?? '').padEnd(12, '0'))
  return n <= MAX_ATOMIC ? n : null
}
export const toAtomic = (value: unknown) => typeof value === 'string' && /^(0|[1-9]\d*)$/.test(value) && BigInt(value) <= MAX_ATOMIC ? BigInt(value) : null
