import { beforeEach, expect, it, vi } from 'vitest'
vi.mock('../wallet/metamask', () => ({ metamask: { provider: vi.fn() } }))
import { liveApi, validateIntent } from './live'
import { deposit } from '../test/fixtures'
import { terms } from '../test/redeem'
import { prepareBody } from '../lib/redeemTx'
const transport = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn() }))
vi.mock('./http', () => ({ getJson: transport.get, postJson: transport.post }))
vi.mock('../config', async original => ({ ...await original<object>(), VAULT_ID: '0x' + '11'.repeat(32) }))
beforeEach(() => { transport.get.mockReset(); transport.post.mockReset() })
it('live writes fail closed when authenticated health does not enable them', async () => {
  transport.get.mockResolvedValue({ runtime: 'ready', native_development: false, bridge_actions_enabled: false, withdrawals_enabled: false })
  const d = deposit()
  await expect(liveApi.createDepositIntent(d.recipient, d.intentId)).rejects.toThrow('unavailable')
  await expect(liveApi.getDepositIntent(d.intentId)).rejects.toThrow('unavailable')
  await expect(liveApi.prepareRedeem(prepareBody(terms))).rejects.toThrow('unavailable')
  expect(transport.post).not.toHaveBeenCalled()
})
it('requires withdrawal readiness even when deposits are enabled', async () => {
  transport.get.mockResolvedValue({ runtime: 'ready', native_development: false, bridge_actions_enabled: true, withdrawals_enabled: false })
  await expect(liveApi.prepareRedeem(prepareBody(terms))).rejects.toThrow('unavailable')
})
it('rejects a response naming a different vault', async () => {
  transport.get.mockResolvedValue({ runtime: 'ready', native_development: false, bridge_actions_enabled: true })
  const d = deposit({ vaultId: '0x' + 'ff'.repeat(32) })
  transport.post.mockResolvedValue(d)
  await expect(liveApi.createDepositIntent(d.recipient, d.intentId)).rejects.toThrow('Unexpected deposit vault')
})
it('validates recipient binding, private IDs, network and Monero checksum', () => {
  const d = deposit()
  expect(validateIntent(d, { recipient: d.recipient, intentId: d.intentId })).toEqual(d)
  expect(() => validateIntent(d, { recipient: '0x' + 'ff'.repeat(20) })).toThrow()
  expect(() => validateIntent({ ...d, network: 'mainnet' })).toThrow()
  expect(() => validateIntent({ ...d, depositAddress: d.depositAddress.slice(0, -1) + '1' })).toThrow()
  expect(validateIntent({ ...d, status: 'failed' }).status).toBe('failed')
})
