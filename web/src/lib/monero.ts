import { bytesToHex, keccak256 } from 'viem'
const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
/** Standard and subaddresses only. Authoritative spend-key/destination validation remains in the enclave. */
export function decodeDestination(address: string): { kind: 'standard' | 'subaddress'; words: [bigint, bigint, bigint] } {
  if (address.length !== 95) throw new Error('Use a 95-character Monero stagenet standard address or subaddress.')
  const raw = new Uint8Array(69)
  for (let offset = 0, out = 0; offset < address.length; offset += 11, out += 8) {
    const block = address.slice(offset, offset + 11), size = block.length === 11 ? 8 : 5
    if (block.length !== 11 && block.length !== 7) throw new Error('Invalid Monero address encoding.')
    let value = 0n
    for (const char of block) {
      const digit = ALPHABET.indexOf(char)
      if (digit < 0) throw new Error('Invalid Monero address character.')
      value = value * 58n + BigInt(digit)
    }
    if (value >= 1n << BigInt(size * 8)) throw new Error('Invalid Monero address encoding.')
    for (let i = size - 1; i >= 0; i--) { raw[out + i] = Number(value & 255n); value >>= 8n }
  }
  if (raw[0] !== 24 && raw[0] !== 36) throw new Error('Use a Monero stagenet standard address or subaddress.')
  if (keccak256(raw.slice(0, 65)).slice(2, 10) !== bytesToHex(raw.slice(65)).slice(2)) throw new Error('Monero address checksum does not match.')
  const encoded = new Uint8Array(96)
  encoded.set([1, 2, raw[0] === 24 ? 0 : 1]); encoded.set(raw.slice(1, 65), 3); encoded.set(raw.slice(65), 67)
  return { kind: raw[0] === 24 ? 'standard' : 'subaddress', words: [0, 32, 64].map(i => BigInt(bytesToHex(encoded.slice(i, i + 32)))) as [bigint, bigint, bigint] }
}
