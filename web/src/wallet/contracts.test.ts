import { expect, it, vi } from 'vitest'
import { decodeFunctionData, encodeFunctionResult, parseAbi, type Hex } from 'viem'
vi.mock('./metamask', () => ({ metamask: { provider: vi.fn() } }))
vi.mock('../config', () => ({ BRIDGE_ADDRESS: '0x1111111111111111111111111111111111111111', DEPLOYMENT_BLOCK: '10', FEE_TERMS_HASH: '0x' + '22'.repeat(32), FIXED_FEE_ATOMIC: '10', MIN_REDEEM_ATOMIC: '11', LIVE_BLOCKER: 'unverified' }))
import { finalizedHead, readBridge, readRedemption, READ_ABI } from './contracts'
import type { Eip1193Provider } from './metamask'
import BridgeAbi from '../abi/Bridge.json'
import RegistryAbi from '../abi/VaultRegistry.json'
import { CWXMR_ABI } from '../lib/redeemTx'
const hash = ('0x' + 'ab'.repeat(32)) as Hex
const id = ('0x' + '11'.repeat(32)) as Hex
const address = '0x1111111111111111111111111111111111111111'
function wallet() {
  const calls: unknown[] = []
  return { calls, on() {}, removeListener() {}, request: vi.fn(async ({ method, params }: { method: string; params?: unknown[] }) => {
    if (method === 'eth_chainId') return '0xaa36a7'
    if (method === 'eth_getBlockByNumber') return { hash, number: '0xb' }
    if (method === 'eth_getLogs') return [{ address, topics: [hash, id] }]
    if (method === 'eth_call') {
      calls.push(params)
      const d = decodeFunctionData({ abi: READ_ABI, data: (params![0] as { data: Hex }).data })
      if (d.functionName === 'token' || d.functionName === 'registry') return encodeFunctionResult({ abi: READ_ABI, functionName: d.functionName, result: address })
      if (d.functionName === 'decimals') return '0x' + '0'.repeat(63) + 'c'
      if (d.functionName === 'authorized') return '0x' + '0'.repeat(63) + '1'
      const abi = parseAbi(['function redemptions(uint256) view returns ((address user,bytes32 amount,bytes32[3] destination,bytes32 nonzero,bytes32 feeTermsHash,uint64 cancelAfter,uint8 status,bytes32 assignee,bytes32 paymentCommitment))'])
      return encodeFunctionResult({ abi, functionName: 'redemptions', result: { user: address, amount: id, destination: [id, id, id], nonzero: id, feeTermsHash: id, cancelAfter: 12n, status: 1, assignee: id, paymentCommitment: id } })
    }
    throw new Error('unexpected')
  }) } as Eip1193Provider & { calls: unknown[]; request: ReturnType<typeof vi.fn> }
}
it('uses Sepolia and canonical hash-pinned calls, sorted eligibility, keeps writes unavailable', async () => {
  const p = wallet(), result = await readBridge(p)
  expect(result.eligible_vaults).toEqual([id])
  expect(result.scanner_ready).toBe(false)
  for (const call of p.calls) expect((call as unknown[])[1]).toEqual({ blockHash: hash, requireCanonical: true })
})
it('rejects wrong chain and never calls contracts', async () => {
  const p = wallet(); p.request.mockResolvedValue('0x1')
  await expect(finalizedHead(p)).rejects.toThrow('Sepolia')
  expect(p.request).toHaveBeenCalledTimes(1)
})
it('does not infer positive burn from open status at RPC finalized block', async () => {
  const r = await readRedemption('3', wallet(), address)
  expect(r).toMatchObject({ status: 'open', actualPositive: null, trust: 'wallet_rpc_observation', observedBlock: '11' })
})
it('UI function and event inputs match exported current contract ABIs', () => {
  for (const name of ['requestRedemption', 'RedemptionRequested']) {
    const ui = CWXMR_ABI.find(a => 'name' in a && a.name === name) as { inputs: readonly { type: string; indexed?: boolean }[] }
    const actual = BridgeAbi.find(a => 'name' in a && a.name === name)!
    expect(ui.inputs.map(x => [x.type, !!x.indexed])).toEqual(actual.inputs!.map(x => [x.type, 'indexed' in x ? !!x.indexed : false]))
  }
  expect(RegistryAbi.some(a => a.name === 'VaultDiscovered')).toBe(true)
})
