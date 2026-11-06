# cwXMR: Private-to-Private Monero ↔ Ethereum Bridge

Status: architecture and implementation plan; no implementation or deployment claimed.
Date: 2026-11-06.

## 1. Objective and agreed design

Build a bidirectional, private-to-private bridge between native Monero (XMR) and cwXMR, a Zama-backed confidential ERC-7984 token on Ethereum.

- **Monero → Ethereum:** a user deposits XMR into a recipient-bound subaddress belonging to an enclave-controlled vault. The enclave verifies the deposit and authorizes confidential cwXMR minting directly to the designated Ethereum recipient.
- **Ethereum → Monero:** a user burns cwXMR and supplies an encrypted Monero destination. Eligible vault enclaves decrypt the redemption details, check their available funds, and compete to claim the request. The first valid claim accepted on Ethereum assigns the payout to one vault.
- Each vault owns an independent Monero wallet. There is no shared master spend key or threshold custody in the initial version.
- Multiple instances of the approved enclave build may operate independently.
- **The initial release targets AWS Nitro Enclaves only**, using approved enclave image PCR measurements. AWS account activation is currently unresolved; implementation starts locally and real Nitro validation will use an authorized AWS account when available. Trial credits and instance eligibility must be checked in that account. SGX, TDX, and SEV-SNP support are outside the MVP.
- **An enclave must be validated through Automata's Nitro verifier contract before its signing key receives any cwXMR minting authority.** This replaces the earlier DCAP requirement: the existing Intel DCAP adapter cannot verify Nitro evidence. Peer attestation or an operator's assertion cannot substitute for onchain verification.
- The Rust backend consists of four crates: Monero, Zama, core, and watcher. All four must support execution in the selected TEE environment. The watcher provides RA-TLS communication.
- Reuse the existing zz-bridge service and web application as foundations, adapting their Zcash and single-operator assumptions as described in sections 14–15.

This design replaces the initially considered shared-key threshold committee with independent custody vaults. Threshold custody remains a possible future redesign, not a hidden dependency of the MVP.

## 2. Meaning of private-to-private

Monero provides the source/destination asset's native privacy properties. On Ethereum, cwXMR uses Zama confidential computation for amounts and balances, and redemption destinations remain encrypted in contract inputs and storage.

The intended privacy boundary is:

| Information | Intended visibility |
| --- | --- |
| cwXMR amounts and balances | Authorized Zama participants under contract ACL policy |
| Deposit amount and recipient mapping | Receiving enclave and the depositing user; necessary token recipients obtain their authorized token data |
| Redemption amount and XMR destination | Requesting user and eligible vault enclaves granted access |
| Monero spend/view keys | Their owning vault enclave |
| Ethereum accounts, contract calls, vault identity, request status and timing | Generally public |
| Host traffic patterns, uptime and transaction timing | Potentially observable |

“Private-to-private” does not promise anonymous Ethereum accounts, hidden participation, or immunity to timing correlation. Eligible enclaves deliberately learn redemption details to decide whether to claim. The host operator must not obtain this plaintext through application APIs, logs, or decryption endpoints.

ERC-7984 defines a confidential-token interface, not a complete bridge, anonymity system, or mint authorization scheme. [ERC-7984](https://eips.ethereum.org/EIPS/eip-7984)

## 3. System components and trust boundaries

### On Ethereum

1. **VaultRegistry:** verified enclave identities, signing keys, vault lifecycle, attestation policy versions, expiry, and revocation.
2. **Bridge:** deposit replay protection, mint authorization, redemption creation, eligibility snapshots, assignment, and settlement records.
3. **cwXMR:** confidential balances, supply accounting, minting, and burning using Zama's Solidity FHE library.
4. **Automata Nitro verifier:** verifies proofs of AWS Nitro attestation documents through the configured deployed verifier contract.
5. **Zama infrastructure:** confidential computation and permissioned decryption.

Recommended contract structure: cwXMR gives its mint role only to Bridge. Bridge accepts mint authorizations only from currently authorized, Automata-verified enclave keys. Thus every active vault can initiate minting, while every mint passes through one consistent authorization and replay check. There is no alternate administrator or operator mint path in the planned production interface.

### Inside each TEE

The backend owns wallet keys, enclave identity keys, decryption keys, deposit mappings, wallet scanning/transaction construction, request validation, liquidity reservations, and payout state. RA-TLS terminates inside the TEE.

Package all four backend crates and any secret-processing Zama SDK component in one Nitro enclave image file (EIF). The parent EC2 instance runs the enclave launcher and untrusted forwarding/storage helpers. A regular Nitro-based EC2 VM alone is not the enclave boundary.

### Outside the TEE

Host processes may transport ciphertext, relay signed transactions, provide encrypted storage, and supply blockchain data. Their data and acknowledgements are untrusted. External Ethereum, Monero, Zama, and Automata infrastructure are dependencies, not backend components that become trusted merely by being contacted from an enclave.

Nitro enclaves have no external network interface or persistent storage. Use vsock forwarding through the parent for outbound RPC and inbound client/peer traffic; authenticate remote services and terminate sensitive TLS sessions inside the enclave. Store only authenticated encrypted wallet/state records on parent storage or an external store. AWS KMS supplies attestation-restricted key recovery as specified in section 7. [AWS Nitro architecture](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html)

Operators may use independent AWS accounts, but all MVP vaults share AWS Nitro's infrastructure and attestation root of trust. Independent operators do not provide cloud-provider diversity. Parent operators can withhold network, storage, or KMS access; confidentiality does not guarantee availability.

An untrusted host can stop or delay execution. Enclaves must fail closed when chain state, identity, or payment state cannot be established.

## 4. Mandatory Automata Nitro mint gate

### Enrollment

1. Start an approved production enclave build.
2. Generate the vault's Monero wallet and separate enclave authentication, mint-signing, RA-TLS, and decryption keys inside the enclave.
3. Request an AWS Nitro attestation document through the enclave's Nitro Secure Module (NSM), binding a domain-separated digest of the enclave-generated identity/key bundle, bridge deployment, Ethereum chain ID, policy version, and fresh registration challenge into its authenticated public_key/user_data/nonce fields under a versioned encoding.
4. Generate an Automata-supported SP1 or RISC Zero proof of the document's verification, then submit that proof, authenticated outputs and registration data through VaultRegistry. Proof generation may run outside the enclave on the public attestation document; no wallet key or bridge plaintext is needed by the prover.
5. VaultRegistry invokes the configured Automata Nitro verifier and consumes its authenticated verification result. Pin the prover program identity, output schema and verifier contracts; do not accept caller-supplied PCRs or key bindings without matching verified outputs.
6. Enforce bridge-specific policy: approved PCR0/PCR1/PCR2 tuple, valid AWS attestation certificate chain under the verifier's policy, non-debug measurements, document freshness, challenge freshness and single use, expected domain, and exact binding to the submitted keys. Check that all policy fields are authenticated and exposed by the pinned verifier integration before enabling registration.
7. Activate the identity only if all required verification and admission checks succeed.

Automata verification is mandatory, but document validity alone is not sufficient: the document must attest the exact build and keys this bridge intends to trust. The measured code must generate and retain those keys internally; attestation alone does not prove key provenance if the code accepts arbitrary host keys. Automata provides Nitro attestation proof generation and verification; the bridge provides application policy. Its repository lists a Sepolia verifier deployment, whose address, code, proof backend and ABI must be verified and pinned during implementation. [Automata Nitro SDK and contracts](https://github.com/automata-network/aws-nitro-enclave-attestation)

PCR0 measures the enclave image, PCR1 the kernel/bootstrap and PCR2 the application. Do not require a single global PCR3 (parent IAM role) or PCR4 (parent instance), which would prevent independent-account deployment. Those values may be used in a particular operator's recovery policy. PCR8 signer identity is optional and must not silently permit arbitrary replacement images. Reject debug/attached-console enclaves with zero measurements. [AWS Nitro measurements](https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html)

### Every mint

Bridge verifies:

- A valid signature by the registered enclave mint-signing key.
- Successful prior Automata enrollment and current mint-authorized status.
- Current attestation validity/policy and no suspension or revocation.
- Correct bridge, chain, vault identity, recipient, confidential amount handles/input proof binding, and authorization nonce.
- A globally unused deposit identifier.

The contract consumes the identifier and performs the mint atomically. Any relayer may submit the authorization; its Ethereum account does not receive mint authority.

Re-attestation is required before the configured authorization expires. Expiry blocks new actions under the defined policy. Draining vaults need an explicit, limited path for processing previously issued deposit addresses and pending work; they do not retain general mint authority indefinitely.

The same approved PCR tuple does not demonstrate independent ownership or prevent one operator from running many instances. Admission limits and economic protections are separate decisions. No particular centralized operator approval process is assumed by this plan.

## 5. Monero → Ethereum flow

### Deposit address issuance

1. The client selects an active vault and connects to its attested endpoint.
2. It supplies the Ethereum recipient, deployment/network context, and a deposit-intent nonce.
3. Inside the enclave, associate that recipient-bound intent with a valid Monero subaddress index in the vault wallet.
4. Persist the mapping before returning an authenticated deposit instruction.
5. Return the subaddress, vault identity, intent identifier, network, fee terms, and address-validity policy.

Use standard Monero subaddress derivation. Do not invent an address by hashing an Ethereum address. A deterministic intent-to-index mapping requires collision handling and durable allocation state; a stored allocation keyed by the recipient and nonce is the simpler baseline. Repeating the same intent returns the same address; a fresh intent can allocate another address.

Subaddress allocation and its recipient binding remain inside the enclave. Wallet-seed recovery alone must not be assumed to restore these application mappings. [Monero subaddresses](https://docs.getmonero.org/public-address/subaddress/)

### Observation and mint

1. Watch for outputs belonging to issued subaddresses.
2. Verify ownership, amount, transaction/block inclusion, canonical chain position, and the configured confirmation/unlock policy.
3. Derive a stable opaque deposit identifier per received output. Bind it to the bridge deployment and vault; do not expose raw XMR transaction identifiers as the default Ethereum mint metadata.
4. Compute the mint amount using exact atomic-unit arithmetic and the disclosed fee policy.
5. Produce a Zama-compatible encrypted input and its required proof without exposing the amount to the host.
6. Sign the complete mint authorization.
7. Relay it to Bridge, which applies the mandatory Automata-backed authorization gate and mints directly to the recipient.
8. Mark the deposit finalized only after observing the finalized Ethereum mint.

A repeated observation, restart, relayer retry, or duplicate event must produce the same deposit identity and cannot mint twice. One transaction may contain multiple relevant outputs; output identity must distinguish them.

Plaintext calldata followed by an onchain conversion to an encrypted type is not confidential input. The mint path must preserve secrecy from input creation onward.

The Monero verification approach is an implementation gate: specify whether validated node logic runs inside the trusted environment or what independently verified chain data the enclave consumes. An external wallet RPC response saying “received” is insufficient evidence by itself.

## 6. Ethereum → Monero flow

### Request creation and confidentiality

The user submits an encrypted amount, required input proofs, encrypted Monero destination, and accepted fee terms. Bridge burns cwXMR and records the actual burned amount as the source of redemption entitlement.

Do not create entitlement from a user-supplied amount independently of the burn. Failed, insufficient-balance, or zero-result confidential operations must not produce a positive claimable redemption.

For the MVP, capture a bounded snapshot of eligible active vaults at request creation and grant those enclave identities access to both amount and destination. This follows the agreed “decrypt, validate, then compete” design. It avoids assigning a vault before it can discover an invalid destination.

Zama ACL permissions are granted in the contract; decryption happens offchain. The authorization key and final recipient decryption key must both be enclave-controlled. The contract also needs the appropriate permissions for ciphertexts it retains and operates on. [Zama user decryption](https://docs.zama.org/protocol/examples/basic/decryption/fhe-user-decrypt-single-value)

Use the term “Monero destination” in interfaces. For the MVP, support standard addresses and subaddresses on the configured network; reject unsupported formats explicitly. A Monero destination is not an Ethereum eaddress. Specify a versioned fixed-size encoding across supported encrypted types, including address kind, network and payload, with deterministic validation. Do not assume arbitrary encrypted byte arrays are available in the pinned library. [Zama supported types](https://docs.zama.org/protocol/solidity-guides/smart-contract/types)

### Claiming

1. Eligible enclaves observe the finalized request.
2. Decrypt and validate the destination, actual redemption amount, network, fee terms, and minimum payout.
3. Check spendable unlocked XMR after existing reservations and fee headroom.
4. Reserve funds durably before signing a claim.
5. Sign the request ID, vault ID, bridge/chain domain, and claim validity context.
6. A relayer submits the claim.
7. Bridge atomically verifies eligibility, current action authorization, signature, and OPEN status, then sets ASSIGNED(vaultId).

The first valid transaction accepted by Ethereum wins. This is transaction-order priority, not guaranteed fairness or arrival-time ordering. Subsequent claims fail. Losing enclaves release reservations after verifying finalized assignment elsewhere.

Snapshot membership determines data access and initial eligibility; current registry status still gates whether a vault can act. New vaults do not automatically gain access to old requests. A later-access mechanism, if added, must explicitly authorize and grant access.

### Payout and settlement

1. The winner waits for finalized assignment.
2. Construct and sign the XMR transaction inside the enclave.
3. Persist its exact signed bytes and request binding before broadcasting.
4. Broadcast and verify inclusion/confirmation under the configured Monero policy.
5. Submit an enclave-signed settlement receipt bound to the assigned request and payment commitment.
6. Bridge accepts it only from the authorized assignee under the settlement policy and marks PAID.

Settlement relies on the attested enclave's Monero verification; this plan does not claim an Ethereum-verifiable Monero payment proof. A host acknowledgement or arbitrary transaction hash is not sufficient.

Public state: OPEN → ASSIGNED → PAID.
Internal payout stages: reserved → transaction prepared → broadcast → confirmed.

One vault pays each redemption in full. A request stays queued if no vault has sufficient liquidity. Splitting payments across vaults is deferred.

## 7. Retries, restarts, rollback and recovery

A host may crash an enclave, replay old storage, duplicate requests, or run competing instances. Encrypted storage and attestation-restricted key recovery provide confidentiality/integrity but do not by themselves prove freshness.

### Nitro persistence and key recovery

Nitro has no persistent enclave disk. Generate wallet and identity secrets inside the enclave, encrypt durable state with an enclave-held data key, and persist both ciphertext and a KMS-wrapped copy of that data key outside the enclave. Back up subaddress mappings, reservations and exact signed transaction records as well as wallet keys.

For the MVP, each operator provisions a KMS key in their own account. The key policy permits recovery only through the approved attested recipient flow and image measurements. Recovery uses a fresh enclave-held recipient key and attestation; KMS returns the data key encrypted to that recipient, so the parent only relays ciphertext. Restrict direct decryption, grant creation and alternative policy paths; a host-callable plaintext decrypt path defeats this design. Include recovery policy inspection in operator setup. [AWS KMS enclave integration](https://docs.aws.amazon.com/enclaves/latest/user/connect-enclave-kms.html)

KMS policy administrators and image-policy changes form part of the recovery trust boundary. Operators can delete or disable their KMS keys and backups; the MVP does not promise recovery from a vanished or malicious account owner. Do not treat per-operator KMS as threshold custody or as protection against arbitrary recovery-policy changes by its administrators.

Restoring the same secrets into multiple enclaves is possible unless separately fenced. KMS and encrypted backups do not provide exclusive execution, prevent snapshot rollback, or prove the latest payout state. The spending gate below is required before recovered instances resume payouts. Test ordinary restart, replacement-parent recovery, simultaneous restores and stale-backup recovery.

### Payment safety

Required behavior:

- Replayed mint authorizations are rejected by the contract.
- Reservations and payment records survive ordinary process restarts.
- A retried payout rebroadcasts the same signed transaction, rather than constructing another payment.
- Assignment is checked against verified finalized Ethereum state before spending.
- An assigned withdrawal is never automatically reopened merely because a timer expires.
- Cancellation/refund is initially restricted to unassigned requests through an atomic contract transition; it restores only the actual burned entitlement once.
- Assigned requests require explicit recovery when payment status is uncertain.

Rollback-resistant single-writer execution remains a required design gate. A local journal alone is insufficient if the host restores a snapshot from before transaction preparation. Select a concrete freshness/fencing mechanism before enabling payouts. One candidate is an immutable finalized payment commitment plus recoverable encrypted signed-transaction storage, combined with enclave rules that prohibit a second transaction for the same request. Its storage availability and concurrent-instance behavior must be validated.

Without reliable evidence that a prior payment cannot execute, do not refund or reassign an assigned request. The MVP may deliberately leave such a request pending for recovery.

Invalid destinations can remain unassigned and be cancelled. The claim-versus-cancel race is resolved atomically by Ethereum state.

## 8. Liquidity, backing and fees

cwXMR is fungible across vaults. Vault B may redeem tokens originally minted by vault A. The user does not need to return to the originating vault.

Conceptual solvency condition:

spendable/recoverable reserves, net of fees and other obligations
≥ circulating cwXMR + burned but unpaid redemption liabilities.

Burning reduces token supply but creates a pending payout obligation until payment or authorized refund. Internal reserve transfers must not count as new user deposits or mint new cwXMR.

All accounting uses integer amounts with an explicit conversion between Monero atomic units and token units. Select the token amount width/decimals, maximum supply, rounding policy, and overflow checks together; do not assume every chosen confidential integer width can represent the desired XMR supply at atomic-unit precision.

Choose a fee policy before implementation. Baseline proposal: deposit fees are disclosed before funding; redemption pays the burned amount minus the agreed fee, and the vault covers the actual transaction fee from that fee budget/reserve. Define fee limits and who bears overruns. Fees must not silently consume backing owed to other holders.

Independent custody limits a stolen spend key to that vault's funds, but unrestricted malicious minting can undermine all cwXMR. Consider bounded per-vault issuance exposure and admission controls. These are additional protections, not substitutes for Automata verification, and their confidential accounting must be designed rather than assumed.

## 9. Vault lifecycle

Lifecycle: REGISTERING → ACTIVE → DRAINING → RETIRED, with SUSPENDED available for incident handling.

- **Join:** create keys inside the enclave, pass mandatory onchain Automata verification and bridge policy, then activate. No key resharing is needed.
- **Operate:** issue deposit subaddresses, mint verified deposits, and claim/payout eligible redemptions.
- **Drain:** stop issuing new deposit instructions and taking new claims. Complete assignments, account for late deposits, and transfer remaining reserves to another verified vault when appropriate.
- **Retire:** remove action authority after outstanding obligations and reserve transfers are reconciled.
- **Suspend:** block configured new actions immediately; explicitly define whether narrowly scoped completion of existing payouts remains permitted.

Reserve transfers use attested peer coordination and authenticated accounting. The recipient recognizes them as internal liquidity transfers and cannot mint against them.

Old subaddresses remain valid Monero destinations even after retirement. Publish the expiry/late-deposit policy and retain an operational handling path. Removing a registry entry does not invalidate a Monero key or recover inaccessible funds.

No automatic recovery is assumed if an operator disappears with the only usable wallet backup or KMS authorization. Per-operator Nitro/KMS recovery covers authorized restart and replacement, not independent recovery from an unavailable account owner. Loss of a vault can impair backing.

Persistent Zama ACL grants must be treated as lasting access to existing ciphertexts. Removing a vault prevents future grants/actions but cannot erase previously learned data or be assumed to revoke old ciphertext permissions. [Zama ACL overview](https://docs.zama.org/protocol/solidity-guides/getting-started)

## 10. Rust crate architecture

Suggested package names are prefixed to avoid collision with Rust's core crate and upstream libraries.

| Crate | Responsibilities |
| --- | --- |
| zz-monero | Wallet key operations; standard subaddress derivation; scanning and output identification; chain-evidence validation; transaction construction/signing; payment observation; atomic-unit arithmetic |
| zz-zama | Ethereum contract bindings; encrypted input/proof integration; enclave-controlled user decryption; ciphertext/ACL handling; mint, claim and settlement payloads; chain/finality verification integration |
| zz-core | Domain types and invariants; lifecycle/state machines; deposit mapping; redemption eligibility; reservations; fee/accounting policy; idempotency; storage and transport interfaces |
| zz-watcher | Runtime orchestration; chain subscriptions and reconciliation; durable cursors; retries; transaction relay scheduling; RA-TLS endpoints and peer sessions; attestation/runtime integration |

Dependency direction:

- zz-core defines shared types and interfaces without depending on concrete chain adapters.
- zz-monero and zz-zama implement the relevant interfaces.
- zz-watcher composes core and adapters into the runnable service.
- Keep the workspace dependency graph acyclic. Solidity contracts remain a separate contracts package.

The Zama Rust crate is a bridge adapter, not an assertion that an official Rust client provides every required API. Prove encrypted input generation, proof handling and user decryption within the chosen TEE runtime early. FFI or a supported embedded component is acceptable only if secret processing stays inside the enclave. Do not move plaintext processing to a host-side JavaScript service to satisfy SDK compatibility.

Watcher subscriptions are hints. Reconciliation from persisted cursors, canonical chain checks, finalized state and deduplication determine authoritative behavior.

## 11. RA-TLS and TEE compatibility

RA-TLS binds a TLS session to an attested enclave-held TLS key. Peer verification checks the AWS-signed Nitro document, approved PCR measurements, freshness, non-debug policy and TLS key binding. Bridge peers additionally verify the identity's applicable registry status.

RA-TLS protects client/vault and vault/vault communication. It does not grant mint rights, establish Monero chain truth, or override Ethereum withdrawal assignment. Mint rights require the separate Automata contract gate.

Peer messages may include liquidity availability, drain requests, reserve-transfer coordination and health signals. They never independently authorize an XMR payout. Avoid unnecessary exact balance disclosure.

If browser clients cannot perform custom RA-TLS certificate verification, choose a supported client/verifier or an application-level attested encryption protocol before claiming end-to-enclave protection. A conventional TLS proxy that decrypts user requests outside the enclave is not equivalent.

Use an explicit Nitro attestation-to-TLS binding: an enclave-held TLS key is bound into the authenticated attestation payload, and peers verify both the evidence and possession of that key. Forward encrypted sessions over vsock without terminating them on the parent. This is an implementation requirement, not a claim that Nitro supplies a ready-made RA-TLS endpoint.

Nitro replaces the earlier SGX runtime choice. Build a pinned Linux userspace into an EIF, using Rust std/Tokio where supported and NSM for attestation. Prefer one x86_64 build target for the MVP; additional architectures require their own reproducible builds and approved measurements. SGX/DCAP, TDX and SEV-SNP adapters are deferred. The hardware attestation change does not inherently change Zama's encrypted-input proof formats.

All four crates must:

- Build and run under the selected production TEE runtime.
- Use enclave-supported cryptography, secure randomness and attestation interfaces.
- Keep keys and sensitive plaintext inside the trusted boundary.
- Treat host clocks, filesystem contents, RPC data and scheduling as adversarial inputs.
- Persist authenticated encrypted state with a separate freshness design.
- Avoid sensitive logging, plaintext dumps and host-readable temporary secrets.
- Bound work, buffers and request sizes for hostile inputs.
- Support deterministic replay/reconciliation where safe.
- Separate production attestation from test mocks; production contracts reject mock identities.

TEE compatibility does not require no_std here. Validate the Linux image, system calls, native dependencies, randomness, async runtime, vsock transport and Zama SDK integration in the actual enclave. A successful local container run does not establish Nitro compatibility.

Measurement allowlisting also requires a controlled upgrade path. A new enclave build generally needs new authorization and a verified state/key migration procedure.

## 12. Implementation sequence and acceptance gates

### Phase 1: Contracts first, locally

Start in xmr-bridge/contracts with the reusable CWZEC accounting and registry patterns. Pin the Solidity/OpenZeppelin/Zama toolchain and Automata Nitro repository revision. Inspect the actual Nitro contract ABI, proof outputs and verification semantics before defining the bridge adapter; do not invent an interface based on the old DCAP return type.

Implement in this order:

1. **CWXMR token:** name/symbol, 12-decimal representation and explicit euint64 capacity bounds; preserve actual-result accounting, pending-burn capacity reservations and exactly-once recredit behavior. Establish Bridge as the sole mint authority with no admin mint bypass.
2. **Nitro attestation adapter and VaultRegistry:** consume authenticated Automata outputs, enforce approved PCR tuples, key/domain binding, fresh challenges, expiry, refresh, revocation and lifecycle. Keep mock verification exclusively in local test fixtures and separate deployment scripts.
3. **Bridge mint path:** domain-separated enclave signatures, recipient/ciphertext binding, registry authorization and globally consumed deposit IDs.
4. **Bridge redemption path:** actual burned entitlement, bounded eligible-vault ACL snapshot, encrypted destination encoding, first-valid-claim assignment, assignee-only settlement and cancellation only while unassigned. Validate Zama caller/contract/input-proof domains across the Bridge/token boundary.
5. **Deployment and bindings:** deterministic configuration, ABI exports and scripts that check chain ID, verifier code/configuration, token permissions and registry policy. Production/testnet scripts must reject mock verifiers and bypass roles.

Acceptance: unregistered/revoked/expired keys cannot mint; invalid, stale, replayed, zero-PCR or incorrectly bound attestations cannot register; duplicate deposits cannot mint twice; racing claims/cancellation choose one state transition; settlement requires the assignee; zero/insufficient burns cannot create excess entitlement; confidential supply limits and refunds preserve accounting.

Local contract tests may use Zama's supported local testing environment and a mock at the attestation adapter boundary. Add upstream genuine proof fixtures if available and compatible, including negative cases. Mock success is not end-to-end attestation validation. Keep real Sepolia deployment and real proof verification as explicit gates in phase 2.

### Phase 2: Nitro runtime and operator setup

Scaffold zz-core, zz-monero, zz-zama and zz-watcher; extract reusable journal/domain interfaces. Build one pinned enclave image containing the backend and any secret-processing Zama sidecar. Add NSM attestation, vsock forwarding, enclave-terminated TLS and KMS-wrapped encrypted persistence. Keep the host launcher/proxies outside the secret-processing backend.

Local work can include crate compilation, state-machine tests, a dev container, deterministic payload encoding, transport abstractions, image build scripts, infrastructure templates and operator documentation. Dev mode must use separate contracts/configuration and never masquerade as a registered Nitro vault.

When authorized AWS access is available, prove: production EIF boot → enclave-generated identity → bound attestation → Automata proof → Sepolia registry activation → enclave-authorized mint using a test fixture → restart and safe identity recovery. Also prove encrypted input generation and enclave-only Zama decryption over the actual network forwarding path. These checks precede an integrated bridge demonstration.

Provide an operator package with:

- A pinned release/image digest, reproducible build instructions and expected PCR measurements; build provenance and upgrade policy.
- Infrastructure scripts for a supported EC2 instance, enclave allocator, least-privilege IAM, per-operator KMS key/policy, encrypted backup location and network forwarding.
- Prerequisite checks for instance support, account quota, enclave memory/CPU, NSM, chain endpoints, proof-generation access and KMS recovery permissions.
- Commands/runbooks to configure, launch, attest/register, inspect health, back up, restore, drain and stop; clear resource cleanup and billing guidance.
- Documentation for an independent AWS account. Use delegated IAM access or an assumed role when using another person's account, rather than shared root credentials. Account-specific role/instance PCRs must not become a global registry requirement.

Acceptance: wrong-image/debug evidence cannot register or recover secrets; the normal host principal cannot obtain plaintext data keys; TLS/plaintext processing remains in the enclave; restarting restores the same vault safely; a second operator can follow the instructions without maintainer-held secrets. Validate simultaneous and stale restores before enabling payout execution.

### Phase 3: Deposit path

Implement recipient-bound subaddress allocation, scanning, chain validation, confirmation policy, encrypted mint inputs and relayed mint authorization.

Acceptance: repeat observations and restarts are idempotent; a reorg before eligibility does not mint; an attacker cannot replace the recipient or amount ciphertext.

### Phase 4: Redemption path

Implement encrypted destination encoding, ACL snapshot grants, liquidity reservations, finalized claims, XMR payout and settlement.

Acceptance: competing vaults produce one authorized payout; a vault cannot over-reserve; unsupported/invalid destinations are rejected before claim; an untrusted host cannot initiate claims or decrypt destination data.

Alongside phases 3–4, carry over web/ and adapt its deposit, redemption, balance and tracking flows as described in section 15. Validate against the new backend and contract interfaces rather than relying only on renamed mock fixtures.

### Phase 5: Recovery and lifecycle

Implement rollback protection, safe transaction rebroadcast, cancellation of unassigned requests, draining, internal reserve transfers, late-deposit handling and the chosen backup policy.

Acceptance: crash injection around each payout stage does not cause a second payment; restored snapshots cannot create another payment; internal transfers never mint; retirement preserves accounted obligations.

### Phase 6: Multi-vault demonstration

Run Monero stagenet and Ethereum Sepolia with at least two real attested Nitro vault instances, including an independently operated AWS account. Deposit to A, mint cwXMR, then redeem through B. Exercise an empty vault, concurrent claims, delayed relayers, node restarts and one draining node.

Acceptance: verify backing and unpaid liabilities across the entire scenario, encrypted-data access boundaries, Automata authorization at every mint path, and real TEE execution of all four crates.

## 13. Decisions still required

These are unresolved engineering choices, not completed guarantees:

1. Pinned Nitro Linux/EIF build, instance sizing, reproducible PCR process and upgrade authorization.
2. Automata Nitro revision/address and proof backend, authenticated output schema, certificate/root policy, proof cost, attestation lifetime and refresh rules.
3. Authenticated Ethereum finality/freshness and Monero chain-verification strategy.
4. Zama Rust/FFI integration, amount representation, destination encoding and proof/ACL compatibility.
5. Rollback-resistant payout fencing and recoverable transaction storage.
6. Fee schedule, confirmation depths, maximum request size and minimum economical payout.
7. Vault admission/exposure limits, request snapshot size and handling of queued requests after membership changes.
8. Per-operator KMS policy/administration and backup availability; lost-account recovery limits, incident authority, draining deadlines and late deposits.
9. Confidential reserve/liability accounting and any externally verifiable reporting.

The initial implementation remains intentionally narrow: independent attested vaults, confidential mint/burn, first-valid-claim withdrawals, one vault per payment, and RA-TLS communication. It does not include threshold custody, automatic ambiguous-payment reassignment, or split-vault payouts.

## 14. Backend and contract reuse assessment

Source review: 2026-11-06. These are reuse candidates identified by reading the existing implementation, not claims that it has passed migration tests, a security audit, or Nitro execution checks. The source projects were not modified during the assessment.

### Crate migration map

| Target | Existing source in zz-bridge | Reuse and remodeling |
| --- | --- | --- |
| zz-monero | service/crates/zcash | Retain separation between wallet, signer, scanner and RPC interfaces. Implement Monero key/view-key handling, subaddresses, output/key-image tracking, transaction construction, fees and chain validation anew; Zcash cryptography and note/witness structures do not port directly. |
| zz-zama | service/crates/zama | Reuse Alloy transaction encoding, signing/journal identities, permit validation, hash-pinned contract reads and deployment-verification patterns. Regenerate bindings and replace CWZEC, Sepolia-only and single-service assumptions. Move secret SDK processing inside the trusted boundary. |
| zz-core | service/crates/app/src/core and domain logic in store | Extract deposit/redemption states, actual-result reconciliation, accounting, input reservations and recovery invariants behind storage/chain/signer interfaces. Replace concrete Zcash types and single-wallet accounting. |
| zz-watcher | service/crates/zama/src/watcher and app/src/bin/bridge-auto.rs | Reuse bounded polling, log deduplication, receipt/header consistency checks, durable cursors, retries, reconciliation-before-action and graceful shutdown. Add Monero events, registry/claim observation, enclave runtime integration and RA-TLS. |

Keep token-specific encoding in zz-zama and orchestration in zz-watcher; do not create cyclic dependencies while extracting the existing app.

### Preserve these mechanisms

- [EVM watcher](/Users/katrixrldd/Desktop/Learning/projects/zz-bridge/service/crates/zama/src/watcher/mod.rs:32): bounded scans, deduplication, receipt/header cross-checks and anchor rereads.
- [Checkpoint reads](/Users/katrixrldd/Desktop/Learning/projects/zz-bridge/service/crates/zama/src/contract/checkpoint.rs:37): contract reads pinned to an explicit block hash, without fallback to latest.
- [Mint orchestration](/Users/katrixrldd/Desktop/Learning/projects/zz-bridge/service/crates/app/src/core/bridge_mint.rs:36): recover signed work before new work; reconcile actual minted amounts instead of treating transaction success as proof of full issuance.
- [Payout journaling](/Users/katrixrldd/Desktop/Learning/projects/zz-bridge/service/crates/app/src/core/payout.rs:104): persist signed bytes before broadcast and retry those exact bytes after ambiguous failures.
- Preserve tests covering duplicate deposits, zero/overflow actual results, wrong FHE input domains, nonce exclusion, crash/restart recovery, reservation races and reorg-triggered halts. Rewrite chain-specific fixtures and assertions.

RPC consistency checks remain useful but do not authenticate Ethereum finality or Monero consensus against a dishonest data provider. The existing two-EVM/three-Zcash confirmation assumptions are not the new bridge's finality policy.

### CWZEC → cwXMR

[CWZEC.sol](/Users/katrixrldd/Desktop/Learning/projects/zz-bridge/contracts/contracts/CWZEC.sol:11) contains both token and bridge logic. Reuse ERC-7984 behavior, encrypted mint/burn accounting, consumed deposit IDs, actual-result storage, pending-redemption supply reservations, and one-time fulfillment/recredit transitions.

Rename the token and symbol. Target 12 decimals to match XMR atomic units, subject to explicit capacity validation: retaining euint64 limits committed supply to 18,446,744.073709551615 XMR, including capacity reserved for unpaid burns. Replace Zcash amount ceilings and validate database representations across the full chosen range; changing display decimals does not widen integers.

Additional required changes:

1. Replace unrestricted admin-granted mint authority with the mandatory Automata-backed authorization path. If Bridge alone holds the token mint role, no alternate role grant may bypass registry checks.
2. Replace the immutable single service reader with the agreed vault eligibility/ACL model. Decide whether a separate supply auditor remains necessary and who controls it.
3. Add OPEN/ASSIGNED settlement semantics, assignee identity and current action authorization. Merely granting multiple accounts MINTER_ROLE would let any of them settle another vault's redemption.
4. Replace opaque service-encrypted destination bytes with the agreed Zama-protected encoding and permissions.
5. Rename Zcash-specific fields and use the planned opaque payment commitment where appropriate instead of automatically exposing a raw XMR transaction ID.
6. Regenerate ABI bindings, events and tests. Bind FHE inputs to the actual caller/contract in the new Bridge/token call path; relayed authorization does not automatically preserve the old proof domain.

### Automata adapter → VaultRegistry integration

The existing [AutomataDcapVerifierAdapter.sol](/Users/katrixrldd/Desktop/Work/CatalogRepos/new-evm-arch/evm-htlc-temp/src/AutomataDcapVerifierAdapter.sol:52) is an SGX reference only. Do not carry its IDcapVerifier interface, packed quote offsets, MRENCLAVE interpretation or TCB-status mapping into the Nitro implementation. Preserve it unchanged in its source project.

Build a Nitro-specific adapter against the pinned [Automata Nitro contracts](https://github.com/automata-network/aws-nitro-enclave-attestation). Map only authenticated outputs into the registry's application policy. Verify PCR values, timestamp units, key/user-data/nonce exposure, prover program identity, certificate-validation semantics, revocation behavior, proof fees and deployment configuration from that revision. If required binding/freshness fields are absent, resolve that integration gap before granting authority; do not substitute unverified calldata. The onchain attestation-proof verifier is separate from Zama's FHE input-proof validation.

Remodel [AttestedAllocatorRegistry.sol](/Users/katrixrldd/Desktop/Work/CatalogRepos/new-evm-arch/evm-htlc-temp/src/AttestedAllocatorRegistry.sol:86):

- Remove ownerRegister(), which deliberately creates an active identity without attestation.
- Extend the current public-key-hash report binding with bridge/chain domain, policy and fresh challenge. Update Nitro document generation, proof output decoding and registry validation together.
- Add expiry and refresh without letting refresh undo an explicit suspension or revocation.
- Recheck current measurement policy when authorizing actions; the current isActive() only returns a stored boolean, and removing an allowed measurement leaves existing records active.
- Add active/draining/retired lifecycle and action-specific completion rules.
- Enforce approved nonzero PCR measurements and reject debug evidence in the verified path. Replace the old SGX measurement/report-data/TCB return structure with the authenticated Nitro output schema.

### Replace trusted-host assumptions

The [FHE client](/Users/katrixrldd/Desktop/Learning/projects/zz-bridge/service/crates/zama/src/fhe/mod.rs:81) sends plaintext amounts to a loopback HTTP sidecar and receives plaintext decryption results. Keep bounded requests, scope validation and error handling, but place secret SDK processing inside the Nitro EIF trusted boundary. A separate enclave service is an alternative only with attestation, RA-TLS and an explicit authorization policy. An ordinary host-side sidecar is not compatible with the stated threat model.

The [signer loader](/Users/katrixrldd/Desktop/Learning/projects/zz-bridge/service/crates/zama/src/contract/signer.rs:6) reads a filesystem private key. Replace this provisioning path with enclave-generated keys and the attestation-restricted KMS and encrypted-backup recovery mechanism in section 7. The existing PostgreSQL store holds plaintext wallet details, amounts, destinations and signed transactions. Move sensitive state to authenticated encrypted records or a protected database design; retain transaction/journal semantics without trusting host-editable rows as authorization.

The PostgreSQL coordinator advisory lock and in-process mutexes coordinate cooperative processes. They do not prevent hostile host rollback or cloned execution. Implement the freshness/fencing requirement in section 7 separately.

The current [destination encryption](/Users/katrixrldd/Desktop/Learning/projects/zz-bridge/service/crates/app/src/core/destination.rs:21) uses one local XChaCha20-Poly1305 key and Zcash address validation. It cannot provide per-vault Zama ACL access as written. Preserve domain separation and input bounds when replacing it.

### Rebuild chain and multi-vault policy

- Replace Zcash memo-to-recipient routing and rho/rseed deposit tags with persistent recipient-bound Monero subaddress intents and stable private output identifiers.
- The current accounting compares one wallet with global token supply and expects every mint to match local deposit data. Split it into per-vault obligations/reservations and aggregate backing reconciliation; another vault's mint must not be mistaken for unsupported issuance merely because it is absent from this wallet.
- Replace singleton coordinator/nonce assumptions where they cross vault boundaries. Each vault has its own signer and reservations; Ethereum determines global withdrawal assignment.
- Rebuild payout-death evidence. Existing recovery depends on Zcash expiry heights and history validation. Keep uncertain payouts reserved until Monero-specific evidence supports recovery; do not port expiration-based recredit decisions mechanically.
- Add authenticated internal reserve-transfer classification, membership lifecycle and late-deposit handling. Internal transfers must never trigger user-deposit minting.

## 15. Web application reuse

Carry over the existing zz-bridge web/ application as the frontend foundation. Preserve its layout, shared components, wallet connection, navigation, copy/status controls, polling, confidential balance reveal and durable redemption-intent tracking. Adapt the existing flows instead of building a replacement UI from scratch.

### Required changes

| Area | Existing source | Adaptation |
| --- | --- | --- |
| Branding and network context | Header.tsx, BalanceRow.tsx, views/, styles/ | Replace ZEC/cWZEC, Zcash, wallet instructions, network labels and explorer links with the selected Monero/Ethereum deployment. Use cwXMR consistently. |
| Amounts and fees | lib/amount.ts, lib/validate.ts, hooks/useBridgeInfo.ts | Replace zatoshi naming and fixed 8-decimal arithmetic with XMR atomic units and 12-decimal parsing/formatting if that token representation is selected. Preserve bigint/string arithmetic and test rounding, bounds and minimum payouts. |
| Deposits | views/DepositView.tsx, hooks/useDeposit.ts, api/live.ts | Replace the shared vault address plus generated memo with recipient-bound subaddress issuance from an eligible vault. Display the issued address and intent status; remove the requirement to copy a Zcash memo. Bind returned instructions to the requested recipient, vault, network and intent. |
| Redemption destination | lib/validate.ts, lib/redeemTx.ts, hooks/useRedeem.ts | Replace the utest1-oriented validator and zcash_address API field with proper Monero network/address validation. Produce the agreed encrypted destination and amount inputs locally, or through a verified enclave channel whose plaintext exposure is explicitly controlled. |
| Transaction preparation | lib/redeemTx.ts, lib/redeemFlow.ts, wallet/chain.ts | Retain account/chain/contract/value/calldata checks, receipt parsing and duplicate-submission protection. Update ABI, proof handling and deployment config. Existing validation checks response structure, not the plaintext contents of ciphertext supplied by a server. |
| Progress and recovery | lib/status.ts, views/RedeemView.tsx | Add awaiting-liquidity, assigned-vault, payout-confirming and recovery-pending states. Never imply a timed-out assigned withdrawal can automatically be retried through another vault or refunded. |
| API and mocks | api/types.ts, api/live.ts, api/mock.ts, test/ | Replace old field names, single-address info, confirmation settings and fixed fees. Model registry eligibility, deposit intents, claims and authentic settlement status in fixtures. |

The existing [balance reveal](/Users/katrixrldd/Desktop/Learning/projects/zz-bridge/web/src/wallet/fhe.ts:10) keeps user permits and transport keys in memory and uses the connected wallet for chain reads. Retain this behavior while updating network/token configuration and SDK compatibility.

The existing [Nym transport](/Users/katrixrldd/Desktop/Learning/projects/zz-bridge/web/src/api/nym.ts:27) can also be carried over, with its bounded requests and failure handling. Nym routing does not validate an enclave or replace RA-TLS/application-level attested encryption. Resolve browser-compatible enclave authentication before sending sensitive plaintext to backend preparation endpoints.

The existing swap view and swap modules contain hardcoded cwZEC addresses, an 8-decimal conversion and a CWZECSwap signing domain. Preserve them as reusable frontend code, but do not expose a working cwXMR swap until a compatible pool, deployment, quote source, decimals and authorization domain have been configured and validated. A name change alone does not establish a cwXMR market.

### Frontend acceptance checks

- Deposit instructions match the intended Ethereum recipient and selected vault without any Zcash memo dependency.
- XMR formatting and parsing preserve exact atomic units, including 12-decimal boundary cases.
- Wrong-network or unsupported Monero destinations are rejected before submission; authoritative enclave validation remains required.
- Wallet account/chain switches, delayed responses and page reloads do not create a second redemption.
- A successful burn with zero actual amount never displays a positive XMR payout entitlement.
- Assignment and payout status come from authenticated/canonical evidence under the backend trust model; a host-only success response is not settlement proof.
- Updated tests cover confidentiality, ciphertext binding, one-time intent submission, liquidity waiting, claim races and recovery messaging alongside the existing UI/polling tests.
