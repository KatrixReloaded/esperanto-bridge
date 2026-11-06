# cwXMR contract interface v1

Local implementation, not a deployed bridge. ABI JSON is exported by `npm run export-abi` after compilation.

## Pinned dependencies and Nitro journal

Automata revision `65c4a4233029ea3bbe16110a80731fcfd47cf300` (2026-11-06 inspected): https://github.com/automata-network/aws-nitro-enclave-attestation/tree/65c4a4233029ea3bbe16110a80731fcfd47cf300
Vendored Apache-2.0 interface is unchanged. Single-report `verifyWithProgramId(bytes output,uint8 backend,bytes32 programId,bytes proof)` returns `VerifierJournal`: result enum, trusted prefix length, timestamp **milliseconds**, certificate hashes, userData, nonce, publicKey, PCR entries (index + bytes32/bytes16), module ID. These are verified outputs, never caller-authorized substitutions. Adapter pins contract code, backend 1 RISC0 or 2 SP1, explicit program, root, proof selector and actual proof verifier code/address. No fees in this ABI. Shared deployment requires independently verified pins; repository addresses alone are insufficient.

## Attestation binding

Enclave mint public key: exactly 64 bytes secp256k1 uncompressed x||y (no 04 prefix). `vaultId=keccak256(publicKey)`; signing EVM address is its low 20 bytes. Keys struct `(address decryptKey,bytes32 tlsKeyHash,bytes32 authKeyHash)` uses a dedicated enclave EVM decryption identity, SHA-256 of RA-TLS SPKI DER, and SHA-256 of authentication public key canonical encoding (Ed25519 raw32 for MVP). No private key is included.

Every `Bridge.confidentialMint` invokes the pinned adapter through Bridge-only `VaultRegistry.verifyMint`. `MintEvidence` contains `(Keys keys,uint64 policyVersion,bytes output,bytes proof)`. There is no registration, challenge transaction, renewal, or reusable mint authority. Authenticated NSM fields are exactly: public_key=raw64 mint key; nonce=uint256 mint nonce encoded as raw32 big-endian; user_data=raw32 `bindingDigest(...)`.

Digest = keccak256(abi.encode(TYPEHASH, chainId, registry, bridge, vaultId, signingKey, decryptKey, tlsKeyHash, authKeyHash, policyVersion, mintDigest)). TYPEHASH hashes this exact ASCII string:
`CWXMRNitroMintBinding(uint256 chainId,address registry,address bridge,bytes32 vaultId,address signingKey,address decryptKey,bytes32 tlsKeyHash,bytes32 authKeyHash,uint64 policyVersion,bytes32 mintDigest)`.
`mintDigest` is the complete EIP-712 digest below, including recipient, depositId, amountHandle, inputProofHash, vaultId, nonce, deadline and chain/Bridge domain. `Bridge.mintDigest` exposes the canonical computation. The shared Rust/ethers vector is `test/fixtures/mint-binding-v1.json`.

Document timestamp must be nonzero, <= current block timestamp *1000 and at most 600 seconds old. PCR tuple = keccak256(PCR0 raw48 || PCR1 raw48 || PCR2 raw48). All three required, distinct indexes, individually nonzero. Policy keyed by uint64 version and tuple. Dedicated decryption address must differ from mint signing address. Signature must recover the signing address authenticated by the raw64 public key. Evidence for another request, deployment, key bundle or policy cannot authorize a mint. Any failed check, including later FHE validation, reverts directory insertion, replay consumption and mint together.

The first successfully verified mint transaction inserts the key bundle into the directory; insertion does not prove positive issuance or Monero liquidity because the actual encrypted mint result can be zero. Future mints require Active status and exactly the same signing/decryption/TLS/authentication keys. A fresh valid per-mint proof can update the recorded approved PCR tuple/policy version without changing those keys. No evidence can reactivate Suspended/Revoked/Retired identities. Active permits new redemption eligibility and claims; Active or Draining permits assigned settlement. These operations use signatures, directory lifecycle, approved recorded policy and current verifier pins, with no authorization expiry or renewal dependency. Policy removal fails closed immediately for that recorded policy; a later valid mint under another approved policy can update an Active record. Draining cannot mint or claim; retirement requires Draining and zero assigned requests, which does not establish reserve sufficiency.

Before the first mint, discovery uses independently validated fresh Nitro identity evidence with the separate type string `CWXMRNitroIdentityBinding(uint256 chainId,address registry,address bridge,bytes32 vaultId,address signingKey,address decryptKey,bytes32 tlsKeyHash,bytes32 authKeyHash,uint64 policyVersion,bytes32 nonce)`. Its final word and NSM nonce are a fresh client-selected raw32 nonce. This discovery digest is never accepted for minting. The public runtime route only emits discovery evidence; mint NSM generation is internal, requires the enclave's matching authorization signature, and remains unwired until verified-deposit processing is implemented. The pre-first-mint discovery verifier/client remains a release gate.

## Bridge signatures and calls

EIP-712 domain name `CWXMRBridge`, version `1`, chainId and verifyingContract=Bridge. Exact typed structs:

- `Mint(bytes32 vaultId,bytes32 depositId,address recipient,bytes32 amountHandle,bytes32 inputProofHash,uint256 nonce,uint64 deadline)`
- `Claim(uint256 requestId,bytes32 vaultId,uint64 deadline)`
- `Settle(uint256 requestId,bytes32 vaultId,bytes32 paymentCommitment,uint64 deadline)`

Deadlines are inclusive Unix seconds. `confidentialMint(MintAuthorization,bytes inputProof,bytes signature,MintEvidence evidence)` binds proof hash and encrypted handle. Deposit IDs globally single-use, mint nonce single-use per vault, including actual-zero results. Mint result is persisted as `mintedAmounts(depositId)` and emitted; receipt success alone does not certify positive issuance. Relayers must reconcile actual amount.

`requestRedemption(bytes32 amount,bytes32[3] destination,bytes inputProof,bytes32 feeTermsHash,bytes32[] vaultIds)` returns ID. FHE external handles use input proof scoped to **Bridge + submitting msg.sender**, for mint too; choose relayer before preparing mint ciphertext. Bridge validates external proofs and grants token transient handle permission, token grants actual-result permission back. User must initiate redemption. Eligible snapshot is user's selected sorted unique subset of 1..16 currently active vault IDs. Both actual amount and all destination words receive persistent ACL for their enclave decryptKey, requester and Bridge; other vaults receive none.

`claim(uint256 id,bytes32 vaultId,uint64 deadline,bytes signature,bytes nonzeroProof)` accepts **Zama KMS** public-decryption proof for the stored nonzero ebool handle and `abi.encode(true)`. This discloses only whether actual burn >0; zero actual result cannot claim. No amount is publicly decryptable. This is unrelated to AWS KMS. First valid claim wins. `settle(uint256 id,bytes32 vaultId,bytes32 paymentCommitment,uint64 deadline,bytes signature)` is assignee-only under current completion authorization. Settlement is enclave testimony, not a Monero light-client proof. `cancel(uint256 id)` only requester, OPEN, after 3600 seconds; exact actual burn restored once. This refund restores reserved previously burned tokens; it is not a new Monero-backed deposit mint and does not request fresh Nitro evidence. ASSIGNED never automatically refunded/reassigned.

## Destination encoding

Three big-endian uint256 words concatenate to 96 bytes: offset0 version=1; offset1 network 0 mainnet/1 testnet/2 stagenet; offset2 kind 0 standard/1 subaddress; offsets3..34 public spend key raw32; offsets35..66 public view key raw32; offsets67..70 original Monero checksum raw4; offsets71..95 zero padding. Original address checksum is first4 Keccak-256(original Monero network/type prefix byte || spend key || view key). Reject integrated/unknown formats and noncanonical padding in enclave before claiming. These are encrypted as externalEuint256[3], supported by @fhevm/solidity 0.11.1; contract cannot inspect private destination bytes.

## Accounting and events

Token decimals=12, euint64 maximum 18446744073709551615 atomic units (18,446,744.073709551615 XMR). Committed supply=circulating+pending actual burns, so pending refunds reserve capacity. Overflow mints and insufficient-balance burns produce actual-zero without changing entitlement. Token has immutable sole Bridge authority, no roles/admin mint path. Bridge constructs token and registry, preventing circular address configuration.

Events: PcrPolicyUpdated, VaultDiscovered, VaultStatusChanged, DepositMinted, RedemptionRequested (amount, three destination handles, nonzero handle, fee terms, cancel time, eligible IDs), RedemptionAssigned, RedemptionPaid, RedemptionRefunded. Exact field order/types in exported ABIs. Status: None=0/Open=1/Assigned=2/Paid=3/Refunded=4.

## Trust and deployment limitations

Current upstream `revokeCert` removes a cached trusted certificate; it is not a permanent certificate denylist (shorter trusted-prefix proofs can recache certificates). Bridge lifecycle revocation is terminal and independent. Directory identity authorization persists until policy removal or lifecycle suspension/revocation; it does not attest continuous enclave liveness. Upstream certificate-cache changes alone do not invalidate a directory record. Every new deposit mint nevertheless requires a new request-bound successful proof verification. Upstream mutable proof-verifier internals/proxies require independent deployment inspection beyond extcodehash. No genuine proof for this bridge-bound mint request exists without an approved live enclave; mocks are test-only. Shared networks must stay disabled until release pins, actual attestation proof, image measurements, infrastructure/finality and production ciphertext/decryption round trip are validated.
