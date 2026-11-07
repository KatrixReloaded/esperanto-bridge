import { beforeEach, expect, it, vi } from 'vitest'
import { decodeFunctionData, encodeFunctionResult, keccak256, parseAbi, type Hex } from 'viem'
import type { Eip1193Provider } from './metamask'
const cfg = vi.hoisted(() => ({ API_BASE: 'https://vault.example', BRIDGE_ADDRESS: '0x1111111111111111111111111111111111111111', REGISTRY_ADDRESS: '0x2222222222222222222222222222222222222222', REGISTRY_CODE_HASH: '', VAULT_ID: '0x' + '33'.repeat(32) }))
vi.mock('../config', () => cfg)
vi.mock('./metamask', () => ({ metamask: { provider: vi.fn() } }))
import { readAttestedPeer } from './attestation'
const hash = ('0x' + 'ab'.repeat(32)) as Hex
const pin = ('0x' + 'cd'.repeat(32)) as Hex
const abi = parseAbi(['function registry() view returns(address)', 'function authorized(bytes32,bool) view returns(bool)', 'function vaults(bytes32) view returns(address,address,bytes32,bytes32,bytes32,uint64,uint8)'])
function wallet(over: { age?: number; authorized?: boolean; status?: number; pin?: Hex; chain?: string; code?: string; registry?: Hex } = {}) {
  const request = vi.fn(async ({ method, params }: { method: string; params?: unknown[] }) => {
    if (method === 'eth_chainId') return over.chain ?? '0xaa36a7'
    if (method === 'eth_getBlockByNumber') return { hash, number: '0x123' }
    if (method === 'eth_getBlockByHash') return { hash, timestamp: '0x' + (Math.floor(Date.now() / 1000) - (over.age ?? 800)).toString(16) }
    if (method === 'eth_getCode') return over.code ?? '0x6000'
    if (method === 'eth_call') {
      const call = decodeFunctionData({ abi, data: (params![0] as {data:Hex}).data })
      if (call.functionName === 'registry') return encodeFunctionResult({ abi, functionName: 'registry', result: over.registry ?? cfg.REGISTRY_ADDRESS as Hex })
      if (call.functionName === 'authorized') return encodeFunctionResult({ abi, functionName: 'authorized', result: over.authorized ?? true })
      return encodeFunctionResult({ abi, functionName: 'vaults', result: [cfg.BRIDGE_ADDRESS as Hex, cfg.BRIDGE_ADDRESS as Hex, over.pin ?? pin, pin, pin, 1n, over.status ?? 1] })
    }
    throw Error('Unexpected RPC')
  })
  return { request, on() {}, removeListener() {} } as Eip1193Provider & { request: typeof request }
}
beforeEach(() => { cfg.REGISTRY_CODE_HASH = keccak256('0x6000') })
it('binds every authority read to one finalized canonical block and returns the registered SPKI', async () => {
  const p = wallet()
  await expect(readAttestedPeer(p)).resolves.toEqual({ origin: cfg.API_BASE, spkiSha256: pin.slice(2), vaultId: cfg.VAULT_ID, blockHash: hash })
  for (const [r] of p.request.mock.calls) if (r.method === 'eth_call' || r.method === 'eth_getCode') expect(r.params![1]).toEqual({ blockHash: hash, requireCanonical: true })
})
it.each([
  [{chain:'0x1'}, 'Sepolia'], [{age:1201}, 'stale'], [{age:-31}, 'stale'],
  [{authorized:false}, 'not authorized'], [{status:2}, 'unavailable'],
  [{code:'0x6001'}, 'code differs'], [{pin:('0x'+'00'.repeat(32)) as Hex}, 'unavailable'],
  [{registry:('0x'+'44'.repeat(20)) as Hex}, 'mismatch'],
])('fails closed for invalid authority %j', async (over, error) => {
  await expect(readAttestedPeer(wallet(over))).rejects.toThrow(error)
})
