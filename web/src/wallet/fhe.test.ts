import { getAddress } from 'viem'
import { afterEach, describe, expect, it, vi } from 'vitest'

// The real SDK needs a browser, WASM and the relayer; here only the call sequence is checked.
const sdk = {
  createToken: vi.fn(),
  encrypt: vi.fn(),
  permits: { grantPermit: vi.fn() },
  decryption: { decryptValues: vi.fn() },
  terminate: vi.fn(),
}
const config = vi.fn((c: unknown) => c)
vi.mock('@zama-fhe/sdk', () => ({
  ZamaSDK: vi.fn(function () { return sdk }),
  MemoryStorage: class MemoryStorage {},
  isEncryptedValueZero: (h: string) => /^0x0{64}$/.test(h),
  sepolia: { id: 11155111, relayerUrl: 'https://relayer.testnet.zama.org' },
}))
vi.mock('@zama-fhe/sdk/viem', () => ({ createConfig: config }))
vi.mock('@zama-fhe/sdk/web', () => ({ web: (o: unknown) => ({ web: o }) }))
vi.mock('./metamask', () => ({}))

const { revealBalance, encryptRedemption } = await import('./fhe')
const wallet = { request: vi.fn(), on: vi.fn(), removeListener: vi.fn() }
const scope = { account: '0x12ab34cd56ef7890a1b2c3d4e5f60718293a4b5c', contract: '0x91cac58cea711bd9487721824ea38e2b5742253f', chainId: '11155111' }
const H = '0x' + 'ab'.repeat(32)
const C = getAddress(scope.contract)

afterEach(() => vi.clearAllMocks())

describe('revealBalance (browser SDK)', () => {
  it('reads the handle, asks for one permit, decrypts and always terminates', async () => {
    sdk.createToken.mockReturnValue({ confidentialBalanceOf: vi.fn().mockResolvedValue(H) })
    sdk.decryption.decryptValues.mockResolvedValue({ [H]: 1_250_000_000n })
    const phases: string[] = []
    expect(await revealBalance(wallet, scope, (p) => phases.push(p))).toBe(1_250_000_000n)
    expect(phases).toEqual(['signing', 'decrypting'])
    expect(sdk.permits.grantPermit).toHaveBeenCalledWith([C])
    expect(sdk.decryption.decryptValues).toHaveBeenCalledWith([{ encryptedValue: H, contractAddress: C }])
    expect(sdk.terminate).toHaveBeenCalledTimes(1)
    // Keys and permits stay in memory; chain reads go through the user's wallet.
    const c = config.mock.calls[0][0] as { storage: object; chains: { network: unknown }[]; telemetry: boolean }
    expect(c.storage.constructor.name).toBe('MemoryStorage')
    expect(c.chains[0].network).toBe(wallet)
    expect(c.telemetry).toBe(false)
  })

  it('returns 0 for the zero handle without asking for a signature', async () => {
    sdk.createToken.mockReturnValue({ confidentialBalanceOf: vi.fn().mockResolvedValue('0x' + '00'.repeat(32)) })
    expect(await revealBalance(wallet, scope, () => {})).toBe(0n)
    expect(sdk.permits.grantPermit).not.toHaveBeenCalled()
    expect(sdk.terminate).toHaveBeenCalledTimes(1)
  })

  it('propagates a declined permit or decryption failure and still terminates', async () => {
    sdk.createToken.mockReturnValue({ confidentialBalanceOf: vi.fn().mockResolvedValue(H) })
    sdk.permits.grantPermit.mockRejectedValueOnce(Object.assign(new Error('rejected'), { name: 'SigningRejectedError' }))
    await expect(revealBalance(wallet, scope, () => {})).rejects.toMatchObject({ name: 'SigningRejectedError' })
    sdk.decryption.decryptValues.mockResolvedValueOnce({})
    await expect(revealBalance(wallet, scope, () => {})).rejects.toThrow('unexpected decryption result')
    expect(sdk.terminate).toHaveBeenCalledTimes(2)
  })

  it('refuses chains the SDK preset is not for', async () => {
    await expect(revealBalance(wallet, { ...scope, chainId: '1' }, () => {})).rejects.toThrow('unsupported chain')
  })
})

it('encrypts the amount and all three destination words in one Bridge/user-bound SDK proof', async () => {
  sdk.encrypt.mockResolvedValueOnce({ encryptedValues: [H, H, H, H], inputProof: '0x1234' })
  const result = await encryptRedemption(wallet, scope.account, scope.contract, 12n, [1n, 2n, 3n])
  expect(sdk.encrypt).toHaveBeenCalledWith({ contractAddress: C, userAddress: getAddress(scope.account), values: [
    { type: 'euint64', value: 12n }, { type: 'euint256', value: 1n }, { type: 'euint256', value: 2n }, { type: 'euint256', value: 3n },
  ] })
  expect(result.proof).toBe('0x1234')
  expect(sdk.terminate).toHaveBeenCalledTimes(1)
})
it('rejects partial encryption output and terminates its in-memory SDK', async () => {
  sdk.encrypt.mockResolvedValueOnce({ encryptedValues: [H], inputProof: '0x1234' })
  await expect(encryptRedemption(wallet, scope.account, scope.contract, 12n, [1n, 2n, 3n])).rejects.toThrow('Invalid encryption result')
  expect(sdk.terminate).toHaveBeenCalledTimes(1)
})
