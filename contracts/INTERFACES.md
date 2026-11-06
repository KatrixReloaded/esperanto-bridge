# cwXMR contract interface v1

Local implementation, not a deployed bridge. ABI JSON is exported by `npm run export-abi` after compilation.

## Pinned dependencies and Nitro journal

Automata revision `65c4a4233029ea3bbe16110a80731fcfd47cf300` (2026-11-06 inspected): https://github.com/automata-network/aws-nitro-enclave-attestation/tree/65c4a4233029ea3bbe16110a80731fcfd47cf300
Vendored Apache-2.0 interface is unchanged. Single-report `verifyWithProgramId(bytes output,uint8 backend,bytes32 programId,bytes proof)` returns `VerifierJournal`: result enum, trusted prefix length, timestamp **milliseconds**, certificate hashes, userData, nonce, publicKey, PCR entries (index + bytes32/bytes16), module ID. These are verified outputs, never caller-authorized substitutions. Adapter pins contract code, backend 1 RISC0 or 2 SP1, explicit program, root, proof selector and actual proof verifier code/address. No fees in this ABI. Shared deployment requires independently verified pins; repository addresses alone are insufficient.

## Attestation binding

Enclave mint public key: exactly 64 bytes secp256k1 uncompressed x||y (no 04 prefix). `vaultId=keccak256(publicKey)`; signing EVM address is its low 20 bytes. Keys struct `(address decryptKey,bytes32 tlsKeyHash,bytes32 authKeyHash)` uses a dedicated enclave EVM decryption identity, SHA-256 of RA-TLS SPKI DER, and SHA-256 of authentication public key canonical encoding (Ed25519 raw32 for MVP). No private key is included.

`issueChallenge(bytes32 vaultId,bytes32 salt)` emits a unique challenge bound to caller. The same caller submits `attest(bytes32 vaultId,Keys keys,uint64 version,bytes32 challenge,bytes output,bytes proof)`. Authenticated NSM fields are exactly: public_key=raw64 mint key; nonce=challenge raw32; user_data=raw32 `bindingDigest(...)`.

Digest = keccak256(abi.encode(TYPEHASH, chainId, registry, bridge, vaultId, signingKey, decryptKey, tlsKeyHash, authKeyHash, policyVersion, challenge)). TYPEHASH hashes this exact ASCII string:
`CWXMRNitroBinding(uint256 chainId,address registry,address bridge,bytes32 vaultId,address signingKey,address decryptKey,bytes32 tlsKeyHash,bytes32 authKeyHash,uint64 policyVersion,bytes32 challenge)`.

Challenge lives 600 seconds, is consumed once, and document timestamp must be >= challenge issue (seconds *1000), <= current block timestamp *1000 and at most 600 seconds old. Authority expires 86400 seconds after document timestamp. PCR tuple = keccak256(PCR0 raw48 || PCR1 raw48 || PCR2 raw48). All three required, distinct indexes, individually nonzero. Policy keyed by uint64 version and tuple; removal immediately disables actions. Refresh requires same key bundle and does not reactivate suspended/revoked/retired vaults. Active permits mint/claim; active or draining permits settlement; all actions require current evidence and policy. No draining mint path. Retirement requires draining status and zero outstanding assigned requests; this does not establish offchain reserve sufficiency. Dedicated decryption address must differ from mint signing address.

## Bridge signatures and calls

EIP-712 domain name `CWXMRBridge`, version `1`, chainId and verifyingContract=Bridge. Exact typed structs:

- `Mint(bytes32 vaultId,bytes32 depositId,address recipient,bytes32 amountHandle,bytes32 inputProofHash,uint256 nonce,uint64 deadline)`
- `Claim(uint256 requestId,bytes32 vaultId,uint64 deadline)`
- `Settle(uint256 requestId,bytes32 vaultId,bytes32 paymentCommitment,uint64 deadline)`

Deadlines are inclusive Unix seconds. `mint(MintAuthorization,bytes inputProof,bytes signature)` binds proof hash and encrypted handle. Deposit IDs globally single-use, mint nonce single-use per vault, including actual-zero results. Mint result is persisted as `mintedAmounts(depositId)` and emitted; receipt success alone does not certify positive issuance. Relayers must reconcile actual amount.

`requestRedemption(bytes32 amount,bytes32[3] destination,bytes inputProof,bytes32 feeTermsHash,bytes32[] vaultIds)` returns ID. FHE external handles use input proof scoped to **Bridge + submitting msg.sender**, for mint too; choose relayer before preparing mint ciphertext. Bridge validates external proofs and grants token transient handle permission, token grants actual-result permission back. User must initiate redemption. Eligible snapshot is user's selected sorted unique subset of 1..16 currently active vault IDs. Both actual amount and all destination words receive persistent ACL for their enclave decryptKey, requester and Bridge; other vaults receive none.

`claim(uint256 id,bytes32 vaultId,uint64 deadline,bytes signature,bytes nonzeroProof)` accepts **Zama KMS** public-decryption proof for the stored nonzero ebool handle and `abi.encode(true)`. This discloses only whether actual burn >0; zero actual result cannot claim. No amount is publicly decryptable. This is unrelated to AWS KMS. First valid claim wins. `settle(uint256 id,bytes32 vaultId,bytes32 paymentCommitment,uint64 deadline,bytes signature)` is assignee-only under current completion authorization. Settlement is enclave testimony, not a Monero light-client proof. `cancel(uint256 id)` only requester, OPEN, after 3600 seconds; exact actual burn restored once. ASSIGNED never automatically refunded/reassigned.

## Destination encoding

Three big-endian uint256 words concatenate to 96 bytes: offset0 version=1; offset1 network 0 mainnet/1 testnet/2 stagenet; offset2 kind 0 standard/1 subaddress; offsets3..34 public spend key raw32; offsets35..66 public view key raw32; offsets67..70 original Monero checksum raw4; offsets71..95 zero padding. Original address checksum is first4 Keccak-256(original Monero network/type prefix byte || spend key || view key). Reject integrated/unknown formats and noncanonical padding in enclave before claiming. These are encrypted as externalEuint256[3], supported by @fhevm/solidity 0.11.1; contract cannot inspect private destination bytes.

## Accounting and events

Token decimals=12, euint64 maximum 18446744073709551615 atomic units (18,446,744.073709551615 XMR). Committed supply=circulating+pending actual burns, so pending refunds reserve capacity. Overflow mints and insufficient-balance burns produce actual-zero without changing entitlement. Token has immutable sole Bridge authority, no roles/admin mint path. Bridge constructs token and registry, preventing circular address configuration.

Events: ChallengeIssued, PcrPolicyUpdated, VaultAttested, VaultStatusChanged, DepositMinted, RedemptionRequested (amount, three destination handles, nonzero handle, fee terms, cancel time, eligible IDs), RedemptionAssigned, RedemptionPaid, RedemptionRefunded. Exact field order/types in exported ABIs. Status: None=0/Open=1/Assigned=2/Paid=3/Refunded=4.

## Trust and deployment limitations

Current upstream `revokeCert` removes a cached trusted certificate; it is not a permanent certificate denylist (shorter trusted-prefix proofs can recache certificates). Bridge lifecycle revocation is terminal and independent. Existing registration remains valid until expiry/policy removal or vault suspension/revocation; upstream certificate-cache changes alone do not invalidate it. Upstream mutable proof-verifier internals/proxies require independent deployment inspection beyond extcodehash. No genuine proof for bridge-generated nonce exists without an approved live enclave; mocks are test-only. Shared networks must stay disabled until release pins, actual attestation proof, image measurements, infrastructure/finality and production ciphertext/decryption round trip are validated.
