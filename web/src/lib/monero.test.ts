import { expect, it } from 'vitest'
import { bytesToHex, hexToBytes, keccak256 } from 'viem'
import { DEMO_ADDRESS } from '../api/mock'
import { decodeDestination } from './monero'
function encode(prefix: number) {
  const payload = new Uint8Array([prefix, ...new Uint8Array(64).fill(1)])
  const raw = new Uint8Array([...payload, ...hexToBytes(keccak256(payload)).slice(0, 4)])
  const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
  let address = ''
  for (let i = 0; i < raw.length; i += 8) {
    const block = raw.slice(i, i + 8); let value = BigInt(bytesToHex(block)), out = ''
    while (value) { out = alphabet[Number(value % 58n)] + out; value /= 58n }
    address += out.padStart(block.length === 8 ? 11 : 7, '1')
  }
  return { address, checksum: bytesToHex(raw.slice(65)).slice(2) }
}
it('encodes exact version/network/kind/key/checksum and zero padding into three big-endian uint256s', () => {
  for (const prefix of [24, 36]) {
    const { address, checksum } = encode(prefix)
    const result = decodeDestination(address)
    const bytes = result.words.map(w => w.toString(16).padStart(64, '0')).join('')
    expect(bytes).toBe(`0102${prefix === 24 ? '00' : '01'}${'01'.repeat(64)}${checksum}${'00'.repeat(25)}`)
    expect(result.kind).toBe(prefix === 24 ? 'standard' : 'subaddress')
  }
  expect(encode(24).address).toBe(DEMO_ADDRESS)
})
it('rejects wrong network, integrated, checksum, invalid alphabet and base58 overflow', () => {
  for (const prefix of [18, 42, 53, 63, 25]) expect(() => decodeDestination(encode(prefix).address)).toThrow()
  for (const address of [DEMO_ADDRESS.slice(0, -1) + '1', 'z'.repeat(95), '0'.repeat(95), DEMO_ADDRESS + '1'.repeat(11)]) expect(() => decodeDestination(address)).toThrow()
})
