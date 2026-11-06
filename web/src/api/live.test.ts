import { expect, it, vi } from 'vitest'
vi.mock('../wallet/metamask', () => ({ metamask: { provider: vi.fn() } }))
import { liveApi, validateIntent } from './live'
import { deposit } from '../test/fixtures'
import { terms } from '../test/redeem'
import { prepareBody } from '../lib/redeemTx'
it('live writes fail closed even with syntactically valid inputs', async () => {
  const d = deposit()
  await expect(liveApi.createDepositIntent(d.recipient, d.intentId)).rejects.toThrow('verify the enclave identity')
  await expect(liveApi.getDepositIntent(d.intentId)).rejects.toThrow('verify the enclave identity')
  await expect(liveApi.prepareRedeem(prepareBody(terms))).rejects.toThrow('verify the enclave identity')
})
it('validates recipient binding, private IDs, network and Monero checksum', () => {
  const d = deposit()
  expect(validateIntent(d, { recipient: d.recipient, intentId: d.intentId })).toEqual(d)
  expect(() => validateIntent(d, { recipient: '0x' + 'ff'.repeat(20) })).toThrow()
  expect(() => validateIntent({ ...d, network: 'mainnet' })).toThrow()
  expect(() => validateIntent({ ...d, depositAddress: d.depositAddress.slice(0, -1) + '1' })).toThrow()
  expect(validateIntent({ ...d, status: 'failed' }).status).toBe('failed')
})
