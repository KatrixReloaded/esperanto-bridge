// Demo mode only: no transaction is sent and nothing is signed.
import { encodeAbiParameters, encodeEventTopics, type Hex } from 'viem'
import { demoBalance, demoRedeemSubmitted, demoHandle, DEMO_FEE, DEMO_VAULT } from '../api/mock'
import { CWXMR_ABI, type Receipt } from '../lib/redeemTx'
import type { ChainClient } from './chain'

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms))
const sent = new Map<string, { at: number; from: Hex; to: Hex; id: string; data: string }>()
let nextId = 100
const hex32 = (n: number) => ('0x' + n.toString(16).padStart(64, '0')) as Hex

export const mockChain: ChainClient = {
  async sendTransaction(tx) {
    await wait(1800)
    const id = String(nextId++)
    const hash = hex32(Date.now())
    sent.set(hash, { at: Date.now(), from: tx.from, to: tx.to, id, data: tx.data })
    return hash
  },
  async getReceipt(hash): Promise<Receipt | null> {
    const s = sent.get(hash)
    if (!s || Date.now() - s.at < 2000) return null
    demoRedeemSubmitted(s.id, s.from, s.data)
    const topics = encodeEventTopics({ abi: CWXMR_ABI, eventName: 'RedemptionRequested', args: { requestId: BigInt(s.id), user: s.from } }) as Hex[]
    const data = encodeAbiParameters([{ type: 'bytes32' }, { type: 'bytes32[3]' }, { type: 'bytes32' }, { type: 'bytes32' }, { type: 'uint64' }, { type: 'bytes32[]' }], [demoHandle(), [demoHandle('08'), demoHandle('08'), demoHandle('08')], demoHandle('00'), DEMO_FEE, 0n, [DEMO_VAULT]])
    return { transactionHash: hash, status: '0x1', from: s.from, logs: [{ address: s.to, topics, data }] }
  },
  async revealBalance(_scope, onPhase) {
    onPhase('signing')
    await wait(1400)
    onPhase('decrypting')
    await wait(900)
    return demoBalance()
  },
}
