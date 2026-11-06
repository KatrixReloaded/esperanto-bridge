import { MemoryStorage, ZamaSDK, isEncryptedValueZero, sepolia as fheSepolia } from '@zama-fhe/sdk'
import { createConfig } from '@zama-fhe/sdk/viem'
import { web } from '@zama-fhe/sdk/web'
import { createPublicClient, createWalletClient, custom, getAddress, type EIP1193Provider } from 'viem'
import { sepolia } from 'viem/chains'
import type { RevealPhase, RevealScope } from './chain'
import type { Eip1193Provider } from './metamask'

/**
 * Wallet-authorized user decryption of the connected account's cwXMR balance.
 * Each reveal uses a fresh SDK with in-memory storage: the transport key pair and the signed
 * permit never touch disk and are dropped when the SDK is terminated.
 */
export async function revealBalance(wallet: Eip1193Provider, scope: RevealScope, onPhase: (p: RevealPhase) => void): Promise<bigint> {
  if (BigInt(scope.chainId) !== BigInt(fheSepolia.id)) throw new Error('unsupported chain')
  const account = getAddress(scope.account), contract = getAddress(scope.contract)
  const sdk = makeSdk(wallet, scope.account)
  try {
    const handle = await sdk.createToken(contract).confidentialBalanceOf(account)
    // An account that never held cwXMR has the zero handle: balance 0, nothing to sign.
    if (isEncryptedValueZero(handle)) return 0n
    onPhase('signing')
    await sdk.permits.grantPermit([contract])
    onPhase('decrypting')
    const value = (await sdk.decryption.decryptValues([{ encryptedValue: handle, contractAddress: contract }]))[handle]
    if (typeof value !== 'bigint') throw new Error('unexpected decryption result')
    return value
  } finally {
    sdk.terminate()
  }
}

export function makeSdk(wallet: Eip1193Provider, user: string) {
  const provider = wallet as unknown as EIP1193Provider
  const transport = custom(provider)
  const account = getAddress(user)
  return new ZamaSDK(
    createConfig({
      // Chain reads (ACL, KMS context) go through the user's wallet, not a third-party RPC.
      chains: [{ ...fheSepolia, network: provider }],
      publicClient: createPublicClient({ chain: sepolia, transport }),
      walletClient: createWalletClient({ account, chain: sepolia, transport }),
      ethereum: provider,
      relayers: { [fheSepolia.id]: web({ offloadEncrypt: false }) },
      storage: new MemoryStorage(),
      transportKeyPairTTL: 86_400,
      permitTTL: 1,
      telemetry: false,
    }),
  )
}

export async function encryptRedemption(wallet: Eip1193Provider, user: string, contract: string, amount: bigint, destination: readonly [bigint, bigint, bigint]) {
  const sdk = makeSdk(wallet, user)
  try {
    const result = await sdk.encrypt({ contractAddress: getAddress(contract), userAddress: getAddress(user), values: [
      { type: 'euint64', value: amount }, ...destination.map(value => ({ type: 'euint256' as const, value })),
    ] })
    if (result.encryptedValues.length !== 4 || !/^0x(?:[0-9a-fA-F]{2})+$/.test(result.inputProof)) throw new Error('Invalid encryption result')
    return { handles: result.encryptedValues, proof: result.inputProof }
  } finally { sdk.terminate() }
}
