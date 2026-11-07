import { expect, it } from 'vitest'
import { walletRead, WalletReadError } from './readError'
import { bridgeErrorMessage } from '../lib/status'
it('reports the precise public stage and nested numeric RPC codes without provider payloads', async () => {
  const error = await walletRead('token getter (eth_call, canonical block hash)', async () => {
    throw { code: -32603, message: 'secret URL', data: { originalError: { code: -32602, message: 'private calldata' } } }
  }).catch(error => error)
  expect(error).toBeInstanceOf(WalletReadError)
  expect(error.rpcCodes).toEqual([-32603, -32602])
  const message = bridgeErrorMessage(error)
  expect(message).toContain('token getter')
  expect(message).toContain('-32602')
  expect(JSON.stringify(error)).not.toContain('secret')
  expect(message).not.toContain('calldata')
})
it('does not echo string error codes supplied by a provider', async () => {
  const error = await walletRead('vault discovery', async () => { throw { code: 'secret' } }).catch(error => error)
  expect(error.rpcCodes).toEqual([])
  expect(bridgeErrorMessage(error)).toContain('no RPC code')
})
