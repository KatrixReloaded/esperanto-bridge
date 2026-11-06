# cwXMR stagenet / Sepolia web

Reuses the `zz-bridge/web` React layout, wallet adapter, in-memory balance reveal, transaction journal and Nym tunnel. Unsupported swap functionality and legacy Zcash routes are removed.

```
npm ci
npm test
npm run build
VITE_BRIDGE_MODE=demo npm run dev
```

Unset mode is live, with no fabricated success. `demo` explicitly simulates deposits, encryption, receipts and payouts. Never send funds to the displayed demo address. A MetaMask connection selects the demo recipient, but demo transaction/reveal operations do not sign or send.

Live configuration (no secrets):

| Variable | Meaning |
| --- | --- |
| `VITE_API_BASE` | Public HTTPS backend origin, reached only through Nym |
| `VITE_BRIDGE_ADDRESS` | Current Sepolia Bridge deployment |
| `VITE_DEPLOYMENT_BLOCK` | Registry discovery start block; at most 16,384 blocks to the finalized head |
| `VITE_FEE_TERMS_HASH` | Reviewed fee policy commitment (bytes32) |
| `VITE_FIXED_FEE_ATOMIC` | Configured fee in 12-decimal atomic units |
| `VITE_MIN_REDEEM_ATOMIC` | Configured minimum, greater than the fee |

The current live build **cannot create deposits or submit redemptions**. Browser verification of the Nitro identity and its TLS key is not implemented. `BROWSER_ATTESTATION_READY` is deliberately false and has no environment override. The runtime's self-signed certificate cannot be safely bootstrapped by disabling browser TLS checks. Backend `bridge_actions_enabled:true` alone is insufficient. This is an explicit integration blocker, not successful live acceptance.

Read-only wallet RPC discovers Bridge.token/registry, verifies 12 token decimals, discovers VaultDiscovered IDs and queries Registry.authorized(id,false) at a canonical hash-pinned finalized head. Eligible IDs are unique, sorted, bounded to16; discovery is capped and fails rather than silently truncating. Calls rely on the wallet's trusted Sepolia node. A finalized RPC response is not independent consensus verification. Balance reveal targets the token contract, uses Zama SDK3.7.1 and wallet permits, and stores keys/permits only in memory.

The backend interface is POST `/v1/deposit-intents` with `{recipient,nonce}` and GET `/v1/deposit-intents/{intentId}`. Responses contain `{intentId,vaultId,recipient,depositAddress,network:'stagenet',status}`. The browser validates recipient/ID binding and the address checksum/network. `failed` (actual zero mint) and `quarantined` are not success. Nonces are reused within a page on retry; recipient changes ignore late responses. Private bearer intent IDs stay in page memory and can be copied for recovery; reload loses automatic tracking. No amounts, addresses or bearer IDs are written to logs or local storage. No memo, shared deposit address, server prepare, server redemption status or swap endpoint exists.

Redemption preparation uses the actual SDK locally: euint64 amount plus three euint256 destination words, one proof and the exact `Bridge.requestRedemption(bytes32,bytes32[3],bytes,bytes32,bytes32[])` ABI. Destination encoding is 96 bytes: version1, stagenet2, kind0/1, raw spend32, view32, original checksum4, zero25; words are big-endian. Standard/subaddresses are checked for prefix/checksum; authoritative key-point validation remains in the enclave. Integrated addresses are rejected. Amounts use integer arithmetic and the u64 limit.

All eligible vaults can decrypt the actual burn and destination. Calldata checks bind fee commitment, vault set, chain, sender, target, zero ETH, handle types and canonical encoding. A receipt supplies the request ID only; it cannot establish positive entitlement. Open requests show actual burn as unknown. Assignment/settlement status is read at the wallet RPC finalized head; only the assigned vault may settle. Cancellation submission is outside this minimal UI. Unknown wallet submission never triggers automatic replacement. The journal stores only operation/hash/request IDs, scoped by account, chain and Bridge; old bridge journals are not reused.

Backend requests retain pinned Nym mix-fetch3.0.1, no native-fetch fallback, bounded outstanding requests and no redirects. Wallet RPC, wallet extension traffic, SDK relayers/encryption-key downloads, page hosting and fonts are outside this tunnel. The copied CSP must be validated against the actual hosting and SDK endpoints before deployment. No deployment, genuine browser attestation, funded transaction, Nym ingress acceptance or live balance reveal was performed for this adaptation. Tests use synthetic addresses, mocked SDKs and trusted RPC fixtures.

Local validation: 85 unit tests, TypeScript and production build pass. The unconfigured live build was rendered with headless Chromium at desktop1440×1000 and mobile390×844; no address or successful transaction is fabricated. These checks do not exercise a real wallet, enclave or public bridge ingress.
