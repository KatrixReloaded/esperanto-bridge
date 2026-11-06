import { describe, expect, it } from 'vitest'
import { CONTRACT, HASH, USER, calldata, handle, prepared, receipt, terms } from '../test/redeem'
import { encodeFunctionData } from 'viem'
import { CWXMR_ABI, PreparedMismatch, readRedeemReceipt, verifyPrepared } from './redeemTx'

describe('verifyPrepared', () => {
  it('accepts the expected requestRedemption call and sends our own from/to/value', () => {
    const v = verifyPrepared(prepared({}, { from: USER.toUpperCase().replace('0X', '0x'), to: CONTRACT }), terms)
    expect(v).toEqual({ kind: 'send', tx: { from: USER, to: CONTRACT, chainId: '0xaa36a7', value: '0x0', data: calldata() } })
  })

  it('returns the stored hash when the backend already has a submitted transaction', () => {
    expect(verifyPrepared({ operation_id: 'web-1', already_submitted: true, transaction_hash: HASH.toUpperCase().replace('0X', '0x') }, terms)).toEqual({ kind: 'hash', hash: HASH })
    expect(() => verifyPrepared({ operation_id: 'web-1', already_submitted: true, transaction_hash: '0x12' }, terms)).toThrow(PreparedMismatch)
  })

  it.each([
    ['another operation', prepared({ operation_id: 'web-2' })],
    ['another sender', prepared({}, { from: '0x' + '11'.repeat(20) })],
    ['another contract', prepared({}, { to: '0x' + '22'.repeat(20) })],
    ['another chain', prepared({}, { chainId: '0x1' })],
    ['nonzero value', prepared({}, { value: '0x1' })],
    ['malformed value', prepared({}, { value: 'free' })],
    ['another method', prepared({}, { data: '0xa9059cbb' + '00'.repeat(64) })],
    ['trailing bytes', prepared({}, { data: calldata() + '00' })],
    ['handle for another chain', prepared({}, { data: calldata(handle(1n)) })],
    ['handle of another type', prepared({}, { data: calldata(handle(11155111n, '04')) })],
    ['amount under the minimum', prepared({ minimum_redeem_atomic: '200000000' })],
    ['missing transaction', prepared({ transaction: undefined })],
  ])('rejects %s', (_, res) => {
    expect(() => verifyPrepared(res, terms)).toThrow(PreparedMismatch)
  })
})

describe('readRedeemReceipt', () => {
  it('extracts the redemption ID from RedemptionRequested', () => {
    expect(readRedeemReceipt(receipt({}, { id: 42n }), HASH, terms)).toEqual({ status: 'ok', redeemId: '42' })
  })
  it('reports a reverted burn', () => {
    expect(readRedeemReceipt(receipt({ status: '0x0', logs: [] }), HASH, terms)).toEqual({ status: 'reverted' })
  })
  it.each([
    ['a different transaction', receipt({ transactionHash: '0x' + '00'.repeat(32) })],
    ['a different sender', receipt({ from: '0x' + '11'.repeat(20) })],
    ['an event for another user', receipt({}, { user: ('0x' + '11'.repeat(20)) as `0x${string}` })],
    ['an event from another contract', receipt({}, { address: '0x' + '22'.repeat(20) })],
    ['no event', receipt({ logs: [] })],
    ['two events', (() => { const r = receipt(); return { ...r, logs: [...r.logs, ...r.logs] } })()],
  ])('rejects %s', (_, r) => {
    expect(() => readRedeemReceipt(r, HASH, terms)).toThrow()
  })
})

it('rejects altered fee commitment, unsorted or duplicate vault ACL and destination types', () => {
  const ids = ['0x' + '22'.repeat(32), '0x' + '11'.repeat(32)] as `0x${string}`[]
  const make = (vaults = terms.eligibleVaults, fee = terms.feeTermsHash, dest = handle(11155111n, '08')) => prepared({}, { data: encodeFunctionData({ abi: CWXMR_ABI, functionName: 'requestRedemption', args: [handle(), [dest, dest, dest], '0x1234', fee, vaults] }) })
  expect(() => verifyPrepared(make(undefined, ids[1]), terms)).toThrow(PreparedMismatch)
  expect(() => verifyPrepared(make(ids), { ...terms, eligibleVaults: ids })).toThrow(PreparedMismatch)
  expect(() => verifyPrepared(make([ids[0], ids[0]]), { ...terms, eligibleVaults: [ids[0], ids[0]] })).toThrow(PreparedMismatch)
  expect(() => verifyPrepared(make([], undefined), { ...terms, eligibleVaults: [] })).toThrow(PreparedMismatch)
  expect(() => verifyPrepared(make(undefined, undefined, handle()), terms)).toThrow(PreparedMismatch)
})
