/** Public operation labels only; never retain provider messages, calldata or URLs. */
export class WalletReadError extends Error {
  constructor(readonly stage: string, readonly rpcCodes: number[]) {
    super(`Wallet read failed: ${stage}`)
  }
}
export async function walletRead<T>(stage: string, operation: () => Promise<T>): Promise<T> {
  try { return await operation() } catch (error) {
    const codes = new Set<number>()
    const inspect = (value: unknown, depth: number) => {
      if (!value || typeof value !== 'object' || depth > 3) return
      const v = value as Record<string, unknown>
      if (typeof v.code === 'number' && Number.isSafeInteger(v.code)) codes.add(v.code)
      for (const key of ['cause', 'data', 'originalError']) inspect(v[key], depth + 1)
    }
    inspect(error, 0)
    throw new WalletReadError(stage, [...codes].slice(0, 3))
  }
}
