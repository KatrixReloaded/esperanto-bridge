# Nitro operator runbook

Sepolia contracts are deployed. The separate unsafe development runner has minted against a real stagenet deposit; a real Nitro/SP1 mint has now finalized and its decrypted positive result was recorded by the enclave. The Nitro withdrawal leg remains unverified. On 2026-11-07 IST, the actual bridge bootstrap image ran on the Mumbai `m6i.xlarge` with pinned Nitro CLI 1.5.2 and `Flags: NONE`. Fresh NSM verification authenticated its exact image, identity and live TLS key. After termination and relaunch, KMS recipient recovery restored the same vault/signing/TLS keys and authenticated PostgreSQL state. Bootstrap minting remains disabled. Evidence is under `artifacts/nitro/bootstrap/{verified,restored}/`. The stagenet PoC explicitly trusts configured chain nodes and one operator without database rollback; mainnet and malicious-operator custody remain out of scope.

On the same date, a separate non-debug diagnostic enclave produced a genuine NSM report that was proved through Succinct Mainnet and verified by the deployed Automata adapter using Sepolia `eth_call`. Proof generation and local verification took 82 seconds; the adapter accepted the report at age 115 seconds and rejected a one-bit-corrupted proof. The network balance decreased by 0.31510638574 PROVE. This validates the standalone attestation proof path only: the diagnostic uses public dummy binding fields, its PCRs are not bridge-approved, and it performed no mint or custody action. Evidence and the isolated single-request spending guard are under `artifacts/nitro/cost-probe/paid-diagnostic-1/` and its parent directory. The runtime proof service now has bounded network support. Bootstrap hardware validation passed; the final mint-enabled image and its real mint still require validation.

The restored mint image has also built and booted without debug mode, with `initialize:false`, the expected vault ID and real deployment hashes measured into its config. Fresh verification under `artifacts/nitro/mint/verified/` confirmed the same identity/TLS keys under its new PCR tuple. KMS now authorizes only that final tuple. The Mac proof service listens on loopback port 18789 and reaches parent loopback 8789 through SSH; the requester wallet stays on the Mac. The owner approved that image and funded its signing address with 0.05 Sepolia ETH. After restart, pinned TLS health reports `bridge_actions_enabled:true`, `monero_sync:running`, and `withdrawals_enabled:false`; evidence is in `artifacts/nitro/mint/approved-verified/` and `approved-health.json`. The resumable owner command is `artifacts/nitro/mint/owner-actions.sh`. Setup has submitted no additional paid proof and does not establish a successful mint or withdrawal.

The first real mint attempt produced a locally verified Succinct proof in 62.52 seconds; its complete mint calldata also passed a real Sepolia `eth_call`. No mint transaction was sent. A 60-second idle deadline on both PostgreSQL relay hops closed the connection during proving and released the cooperative lease, so the runner stopped. Both database relays now use 600 seconds, exceeding the proof client's 560-second deadline. The corrected image was rebuilt, approved on-chain and in KMS, and booted without debug mode. Fresh verification under `artifacts/nitro/mint-retry/verified/` confirms the original vault/TLS identity; the superseded on-chain PCR policy was revoked. The deposited XMR remains in the same vault. The retry proof verified in 46.29 seconds and the database lease survived, but mint transaction `0x8c3a87af437108d6b89fc7f1f1a55bf6d090a247ed2b7f09d3ecae09bd0b775c` reverted. The preflight omitted the configured gas limit: historical replay fails at 3 million gas and succeeds at 5 million, while estimation returns 3,441,667. No cwXMR was minted. Both paid-attempt slots are retained, and the enclave is stopped pending recovery.

For explicit recovery, measured `minting.retry_expired_mint` selects one `{deposit_id, expired_deadline}`. Only an expired, eligible, non-quarantined authorization with no journaled transaction and unused on-chain deposit/nonce can receive a new deadline/signature. Recipient, amount ciphertext, input proof and nonce remain unchanged. The expected old deadline prevents applying that selection twice. Ordinary restarts never renew authorizations automatically. Reconcile and archive the old proof job separately while preserving the global paid-attempt slots; do not reset the spending budget or roll back the database.

Measured `minting.retry_reverted_mint` instead selects one `{deposit_id, transaction_hash}`. The enclave requires a matched, canonical, finalized status-zero receipt with no logs; expired authorization; fresh source eligibility; and unused bridge deposit/nonce. It preserves the failed signed bytes, original authorization and receipt inclusion in `reverted_mints`, retains the consumed Ethereum nonce, and renews only the deadline/signature. No absent, pending, ambiguous, successful or quarantined transaction qualifies. Ordinary restart still reconciles the original transaction. The next attempt simulates the signed EIP-1559 envelope with its exact gas limit and fees before journaling/broadcast. The repair uses 5 million gas, 5 gwei max fee and 1 gwei priority fee; historical replay with those exact limits succeeds. Evidence is under `artifacts/nitro/mint-recovery/`. The repaired image built and booted with `Flags: NONE`; fresh verification under `artifacts/nitro/mint-recovery/verified/` confirms the original vault, signing, decryption and TLS identities. KMS now permits only its new PCRs. The owner action is `artifacts/nitro/mint-recovery/owner-actions.sh`; the owner approved the new tuple and revoked the previous tuple. After explicit authorization for one further proof, the completed second proof job was archived with its finalized failed receipt, both paid-attempt slots were retained, and the total cap increased to three (1 PROVE for the new request). The third proof verified in 60.81 seconds. Mint transaction `0x895719a0b84db3ea38b1599a65b8d2de3e83d601f564c8445a614c601b9c5e12` succeeded in Sepolia block 12,080,236 using 3,403,354 gas. At 2026-11-07 01:12:45 UTC, the finalized head was 12,080,259 and the authenticated enclave endpoint reported `minted`, establishing a positive decrypted result within the deposit backing. The public endpoint does not expose the exact plaintext result. The paid prover is stopped with all three attempt slots retained. This validates the real stagenet-to-cwXMR leg; Nitro withdrawals and authenticated browser ingress still prevent full frontend E2E.

For a fresh Amazon Linux 2023 parent, [infra/nitro-demo-bootstrap.sh](../infra/nitro-demo-bootstrap.sh) installs host packages and sets a persistent shutdown deadline 15 hours after first boot. Set EC2 shutdown behavior to **Stop**. The package repository currently installs Nitro CLI 1.5.0; install the pinned 1.5.2 CLI and matching blobs before running project preflight. The timer does not delete billed disks or KMS keys. The demo uses a 60 GiB gp3 root disk and reserves 2 vCPUs/8192 MiB for enclaves. AWS's allocator parser requires the `---` YAML marker. After allocation, `nproc` counts only the remaining parent CPUs; preflight checks total configured CPUs.

## Boundary and keys

The one EIF contains `zz-monero`, `zz-zama`, `zz-core`, `zz-watcher` and the real `@zama-fhe/sdk` sidecar. It creates the Monero spend key and separate secp256k1 mint/decryption, Ed25519 authentication and P-256 TLS keys internally. The sidecar listens only on enclave loopback `127.0.0.1:8788`. Do not forward that port. The parent only forwards public TLS bytes, outbound HTTPS/CONNECT bytes and encrypted storage. It can deny service, replay old ciphertext, clone restored instances and manipulate unauthenticated chain responses.

Per-mint Nitro attestation uses raw64 secp256k1 `public_key`, the mint nonce as raw32 big-endian `nonce`, and a raw32 digest committing to the entire mint request and key bundle as `user_data`. `tlsKeyHash` is SHA256 of the TLS SPKI DER; authentication hash is SHA256 of raw32 Ed25519 public key. The exact ABI encoding is in [contracts/INTERFACES.md](../contracts/INTERFACES.md). Native mode returns no NSM evidence and cannot produce mint evidence.

KMS recovery uses a **separate fresh RSA-2048 SPKI DER recipient** NSM document. `GenerateDataKey`/`Decrypt` run over authenticated KMS TLS, signed with the parent's temporary IAM credentials, inside the enclave. KMS CMS `CiphertextForRecipient` is unwrapped only inside the enclave. The parent never receives the data key or private key. Runtime uses KMS `GenerateDataKey(Recipient)`, never a host-generated key plus `Encrypt`.

Identity DER keys are encrypted with AES-256-GCM under the recovered 32-byte data key; core state uses `zz_core::storage::Cipher` (XChaCha20-Poly1305). Canonical recovery domain is `cwxmr/recovery/v1` ASCII || chainId uint64 big endian || registry raw20 || bridge raw20. Its SHA256 hex is KMS EncryptionContext `cwxmr-domain`; its raw bytes are identity-backup AAD. Mutable policy versions, address case and `0x` spelling do not change recovery. Envelope bytes and wrapped keys are host-visible. Current runtime backup covers generated identity/wallet keys only; application mappings, reservations and signed payouts need the core PostgreSQL encrypted state backup once orchestration is integrated. Seed-only recovery is insufficient.

KMS policy administrators, account owners able to change those administrators, and approved image/policy upgrades are recovery trust boundaries. They can change policy to recover or forge secrets. Encryption and KMS do not establish storage freshness, exclusive execution or resistance to rollback. Cooperative PostgreSQL locks do not fence hostile clones. Payout broadcasting remains blocked in core.

## Configure and build (Linux x86_64)

Review [infra/operator.yaml](../infra/operator.yaml). It creates a new parent: do not deploy the whole template when using an existing EC2 instance. For the manually launched demo, its IAM/KMS resources were extracted into `artifacts/nitro/recovery-stack.yaml` and the resulting instance profile attached to the existing parent. The default `m6i.xlarge` has 4 vCPUs/16 GiB and supports Nitro Enclaves; `m6i.large` does not. The optional `m6i.2xlarge` has 8 vCPUs/32 GiB. Allocate 2 vCPU/8192 MiB to the enclave initially; SDK/Nym peak memory remains unmeasured. The Mumbai account checked on 2026-11-06 had a 5-vCPU Standard On-Demand quota, so the larger option exceeds it. Free-plan eligibility is separate from quotas and instance support.

Verify regional AMI, price, quota and credits before launching. The template requires IMDSv2 and an existing subnet/security group, allows an existing SSH `KeyName`, and provisions an encrypted 100 GiB gp3 volume. KMS recovery defaults disabled: initially leave PCR parameters empty, obtain the key ARN with no recipient access, then build the configured EIF. Enabling recovery requires all three reviewed nonzero PCRs; template rules reject missing values. Use the specified policy-administration role so KMS lockout-safety checks remain satisfied. No root IAM-delegation wildcard is included.

Install and independently verify AWS `nitro-cli 1.5.2` (source revision `1c496ed730d2dc41ec5bff6df89b4f3185e18840`), Docker, Python3, jq and sha256sum on the Linux builder. Record package/kernel/bootstrap artifacts. Configure the parent allocator using [infra/allocator.yaml](../infra/allocator.yaml), then restart its allocator service. No debug/console launch is supported.

```sh
cp enclave/config/runtime.example.json enclave/config/runtime.json
cp enclave/config/sidecar.example.json enclave/config/sidecar.json
# Set chain, actual registry/Bridge, policy version, KMS ARN/region and HTTPS RPC.
# Set the stagenet birth height and TLS-verified local PostgreSQL identity/CA.
# initialize=true only during a new identity bootstrap; restore uses false.
scripts/nitro/build.sh
scripts/nitro/reproduce.sh
```

The image pins Rust 1.96.0 and Node24.11.1 manifests by digest, Linux amd64, Debian package snapshot 2026-11-01, Cargo.lock and npm lockfile. It builds the actual four-crate backend and copies the actual SDK. No private `.env`, PEM/key, node_modules or target files enter the Docker context. The actual bootstrap EIF has built and run on EC2 from a hashed public source manifest. Independent matching Linux builds remain a shared-network release requirement; this single-builder stagenet demo does not establish reproducibility. Changes to public baked config, compiler, SDK, app or bootstrap alter measurements and require policy review.

The measured runtime config contains the public PostgreSQL CA PEM and DNS name, database and restricted role. Configure PostgreSQL on parent loopback port 5432 with TLS and a certificate valid for that name; configure the dedicated local connection role without a baked password. The enclave connects to local port 8446, forwards bytes over vsock and verifies that exact CA and hostname inside the enclave. The parent may corrupt, withhold or replay ciphertext; TLS does not provide rollback protection. Set the stagenet birth height explicitly to the earliest block that must be scanned. A new encrypted vault row is created only when this boot actually creates the identity; a restored identity requires its existing encrypted database state, so back it up alongside the identity envelope. `initialize=true` alone does not recreate a missing restored database.

Build output is under `artifacts/nitro/`: EIF, build/describe JSON, measurements JSON, SHA256 and source/tool/lock/config hashes. `describe-eif` is a local build measurement, not live attestation. Never blindly approve its output. Review the source/config and an independent build before allowing that tuple onchain or in KMS. Zero/missing PCRs fail local checks; onchain registry and KMS must independently reject debug PCRs.

## KMS policy inspection

Parent role may perform only recipient-restricted `GenerateDataKey` and `Decrypt` for the approved exact PCR tuple. Deny un-attested/plaintext requests. Explicitly deny parent `Encrypt`, `ReEncrypt*`, grant creation, policy edits and alternate key-generation paths. Otherwise a parent could wrap a known data key, forge an identity backup with host-known private keys, restore it and obtain apparently valid attestation. Check **all** grants, root/IAM delegation, alternate roles and account administrators; a narrowly written Allow alone is insufficient.

After future provisioning, retrieve the actual key policy and grants and inspect them (requires operator-authorized AWS access):

```sh
aws kms get-key-policy --key-id "$KEY_ARN" --policy-name default > actual-key-policy.json
aws kms list-grants --key-id "$KEY_ARN" > actual-key-grants.json
python3 scripts/nitro/inspect-kms-policy.py actual-key-policy.json "$PARENT_ROLE_ARN" approved-measurements.json
```

The inspector is a conservative structural aid, not a full AWS authorization evaluator. It rejects root/wildcard delegation and unsupported negative policy selectors by default. After explicitly reviewing an administrator, `--reviewed-administrator EXACT_IAM_ARN` permits only an exact list of administrative actions for that principal; cryptographic use, grants and wildcard actions still fail. The demo uses the account root principal for this restricted administration, which also delegates those administrative actions through IAM. Policy administrators and principals able to obtain those permissions remain trusted. See [AWS key-policy delegation](https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html). Require an empty reviewed grant list and review administrators/role assumption paths separately. Test parent plaintext Decrypt/GDK and chosen-key Encrypt/ReEncrypt rejection on real AWS. Successful attested recipient unwrap, replacement-parent recovery and policy-denial tests remain pending.

## Launch and connectivity

Review exact outbound hostnames needed by the Nym bootstrap and entry gateway, Zama gateway/relayer/KMS network. [infra/outbound.example.json](../infra/outbound.example.json) is a starting list, **not validated SDK endpoint discovery**. In a local test on 2026-11-06, the testnet relayer returned public key and CRS URLs on the exact S3 hostname listed there; other deployments or later key rotations may require different reviewed hosts. Missing hostnames fail startup/requests. Enclave DNS is unnecessary for Node built-in HTTP/fetch paths because Node24 proxy support sends CONNECT hostnames to the parent. Custom SDK agent paths and native dependencies still require a real-enclave compatibility test; setting proxy variables alone is not evidence that all traffic works. Remote TLS certificate validation stays enabled inside Rust/Node.

The sidecar's Ethereum RPC uses the enclave-local Nym SOCKS5 client with remote DNS and HTTPS; it has no direct RPC fallback. This is native Nym, not Ethereum Foundation anon-rpc. Set `nym.provider` to a separately verified Nym Network Requester recipient, `nym.gateway` to the selected entry gateway's identity key, and `nym.api` to a reviewed HTTPS Nym API in the measured sidecar config. The selected gateway must support WSS and anonymous replies must work with the requester. Add the API hostname and the gateway's advertised exact `hostname:port` to the parent allowlist; bare hostnames allow port 443. The parent resolves and connects to the gateway but sees only its TLS traffic. The requester resolves the Ethereum RPC hostname; HTTPS terminates at the RPC provider. Nym client keys and reply state are ephemeral inside the enclave, so each restart re-registers; no Nym state is exported. Nym keeps sending cover traffic while idle, and startup can take minutes. Neither the real Nym route nor these settings have been validated on Nitro or a live mixnet; a listening SOCKS port alone does not prove connectivity or anonymity.

```sh
# Terminal A: untrusted transport only; path contains ciphertext, no wallet plaintext.
scripts/nitro/run-host.sh /var/lib/cwxmr/identity.encrypted.json outbound-reviewed.json
# Terminal B: compares reviewed PCRs and launches without debug or console.
scripts/nitro/launch.sh approved-measurements.json
nitro-cli describe-enclaves
```

Traffic map: parent TCP8443 → enclave vsock8443 → TLS127.0.0.1:8443; enclave local8444 → parent vsock8444 → ciphertext store/IMDS helper; local8445 → parent vsock8445 → regional KMS443; local8446 → parent vsock8446 → PostgreSQL loopback 5432; local8447 → parent vsock8447 → local public-proof service 8789; local8888 → parent vsock8888 → allowlisted CONNECT proxy. The proof and database forwarders allow 600 seconds of idle time for the proof service's 550-second deadline; only public proof inputs may cross that path. Inbound parent TCP8443 listens on loopback; any external load balancer must pass TLS bytes unchanged. No host HTTPS termination for sensitive enclave requests.

A new bootstrap must persist/read back the encrypted envelope before publishing the identity. Once bootstrap succeeds, record its vaultId independently. Set `initialize=false` before any funded release and rebuild/reapprove the resulting measured config; include both approved images in a deliberate KMS migration window if needed. Otherwise a malicious parent returning 404 can trigger a different fresh identity. It cannot recreate the old key or satisfy an existing client's old TLS pin, but it can confuse an unpinned operator. The mint-enabled config requires the independently recorded expected vault ID; mismatches stop startup.

## Per-mint proof and TLS discovery

The public runtime routes are `/identity`, `/health`, and `/attestation?nonce=HEX32`. They perform no deposit, mint, decryption, claim or payout action. The attestation route emits **identity-discovery-only** evidence with `CWXMRNitroIdentityBinding`, using a fresh client-generated nonce and the enclave's own key bundle. Its digest is incompatible with `CWXMRNitroMintBinding` and cannot authorize issuance. `/health` reports disabled gates explicitly. A self-signed certificate or successful HTTPS request alone is not RA-TLS.

For first discovery, [verify-bootstrap.mjs](../scripts/nitro/verify-bootstrap.mjs) provisionally fetches public identity data, then executes the pinned Automata guest locally using the hash-pinned network driver's `inspect` command. It checks the fresh AWS-signed document, exact discovery domain/nonce/key bundle, reviewed nonzero PCRs, timestamp and live TLS SPKI possession. This uses no wallet and buys no proof. Supply `expectedVaultId` when verifying a restored vault. The directory-based client below cannot bootstrap a brand-new vault; browser integration is still pending. Do not treat an unverified endpoint's claimed TLS hash as a trust anchor.

```sh
# Public config: endpoint/domain/rootCert/programId/pcrTuple, expectedVaultId, cli binary/SHA256.
node scripts/nitro/verify-bootstrap.mjs PUBLIC_CONFIG.json NEW_EVIDENCE_DIRECTORY
```

The mint runner checks Monero deposit eligibility under the explicit trusted-node stagenet policy, authorizes the exact canonical mint request, then internally requests its mint-bound NSM document. There is no public mint-attestation or signing oracle. Prove that exact document with pinned Automata revision `65c4a4233029ea3bbe16110a80731fcfd47cf300` using the approved SP1/RISC0 deployment pins. Submit authorization, input proof, signature and Nitro evidence in one `Bridge.confidentialMint` transaction. Each call verifies the proof before issuing tokens. The first successful transaction also inserts immutable directory keys; no enrollment or renewal transaction exists. The [operator proof tool](nitro-proving.md) now validates and packages per-mint evidence using a pinned CPU/network SP1 CLI. The standalone diagnostic NSM proof passed. The runtime now wires the existing mint driver behind the explicit configuration below; its first real hardware mint remains pending. Reconcile actual encrypted issuance: directory membership or receipt success does not prove positive issuance or liquidity.

For a peer already discovered by a proven mint, the client reads current authorization at an independently trusted finalized block, checks pinned registry bytecode and live TLS SPKI before sending its request:

```sh
npm ci --prefix sidecar --ignore-scripts
node scripts/nitro/verify-peer.mjs "$HTTPS_RPC" "$CHAIN_ID" "$REGISTRY" "$REGISTRY_CODEHASH" "$VAULT_ID" "$TRUSTED_FINALIZED_BLOCK_HASH" https://127.0.0.1:8443
```

This checks possession of the immutable TLS key first bound by Automata, current lifecycle/policy and verifier pins, not fresh enclave liveness. Directory authority has no time-based expiry. Wrong keys, inactive/policy-disabled records, wrong chain/code hash and stale state fail closed. Configured RPC and finalized block are trust inputs; consistency is not Ethereum consensus authentication. Runtime/browser peer authentication and fresh on-demand document verification remain integration work.

Restores preserve the same key bundle. A new approved image/policy can be recorded through a fresh mint proof from an Active identity; keys remain immutable for snapshot ACL safety. Draining can settle existing assignments without renewal, but cannot mint or claim. Suspended, Revoked and Retired identities cannot reactivate through a proof. No CLI exports or accepts a production authority private key.

## Explicit stagenet mint runner

`runtime.json` defaults to `"minting":null`. Bootstrap with `initialize:true` and minting disabled, persist the encrypted identity, then stop and rebuild with `initialize:false`. Configure `minting` with `assumption:"trusted-stagenet-single-operator-no-rollback"`, the independently recorded `expected_vault_id`, exact `bridge_code_hash`, `registry_code_hash`, `adapter`, `adapter_code_hash`, and bounded `gas_limit`, `max_fee_per_gas`, `max_priority_fee_per_gas`. Set `confirmations:10`; optional `demo_mint_confirmations:3` changes mint eligibility only, never XMR spendability. Optional `demo_evm_mint_confirmations:2` accepts a successful Sepolia mint after two block confirmations (inclusion counts as one), then verifies its scoped confidential result and rechecks the canonical receipt. Omit this field to require Ethereum finality. The demo setting accepts reorg risk; it does not relax withdrawal finality or finalized-revert recovery.

Approve the final measured image in both KMS and the registry before enabling its runner. It verifies its own locked, nonzero PCR0/1/2 through NSM and checks registry approval, so no self-referential PCR value is baked into the image. A new/mismatched identity, bootstrap mode, missing deployment pins or missing explicit trust assumption cannot mint. One cooperative PostgreSQL lease serializes mint authority; all source scans, proof generation and transaction nonce allocation share one worker. Requests can receive `bridge_busy` while that worker proves. Proof, persistence, pin or transaction errors stop it for reconciliation; restart does not buy another proof automatically. Health reports whether mint actions are currently available. Withdrawals remain disabled in this runtime.

For the parent database, `sudo bash scripts/nitro/setup-postgres.sh` creates a pinned PostgreSQL 16 container with loopback-only TLS and a public CA for the measured config. It refuses to overwrite existing state. Local database authentication trusts the explicitly trusted parent operator; vault records remain authenticated ciphertext. The database and KMS recovery do not establish rollback resistance.

## Backup, restore, drain and cleanup

```sh
scripts/nitro/backup.sh /var/lib/cwxmr/identity.encrypted.json /secure-backups/vault-01
# Optional DATABASE_URL causes backup.sh to include encrypted_vault_state rows only.
scripts/nitro/restore.sh /secure-backups/vault-01 /var/lib/cwxmr-restored/identity.encrypted.json
```

Keep envelope + KMS key + immutable recovery domain + encrypted application state + source/config/measurement metadata. Backup SHA256 only detects accidental changes; enclave AEAD authenticates secrets. Restore refuses to overwrite an existing envelope. Configure `initialize=false`, the same canonical recovery deployment and KMS key, then start parent helpers/approved enclave on the replacement machine. KMS recipient recovery occurs inside the enclave. Confirm original public identity/TLS key and authenticated state before any action. The provided restore stages identity ciphertext only; restoring SQL state must preserve its transaction journal and be reviewed separately. Ordinary restart, simultaneous restores, old snapshots and exact transaction rebroadcast must be tested before payouts can be enabled.

Draining is an onchain lifecycle transition (`setStatus(vaultId, Draining=2)`) signed by the vault signing key while active. The enclave does not yet implement that signer/transaction command; do not substitute host private-key access or an administrator mint bypass. Current registry permits draining completion, blocks new mint/claim, and retires only a draining vault with zero assigned requests through owner policy. Late deposits, full obligation reconciliation and internal reserve migration are not integrated; no automated retirement claim is made.

For an unfunded local test, stop forwarding processes and terminate only the recorded enclave ID:

```sh
nitro-cli terminate-enclave --enclave-id "$ENCLAVE_ID"
```

After any future funded operation, drain/reconcile obligations before stopping. The template retains KMS keys; preserve recovery artifacts before any parent/cloud cleanup. No resource-deletion automation runs here. Deleting/disabling KMS or losing its account can make backups unrecoverable.

## Verification and hardware release gates

Local checks cover real native TLS key possession/pin rejection, no native attestation, exact binding/domain changes, authenticated key-backup roundtrip/tamper rejection, core Cipher key integration, transport byte preservation/half-close, measured-PCR rejection and template syntax. After installing sidecar dependencies with Node 22 or 24, run from the repository root:

```sh
cargo build --manifest-path service/Cargo.toml -p zz-watcher
cargo test --manifest-path service/Cargo.toml -p zz-watcher
python3 scripts/nitro/test-local.py
```

Set `NODE_BIN` if Node is not on PATH, and `WATCHER_BIN` if using a custom Cargo target directory. These tests start a temporary native TLS server with bridge actions disabled. Local tests do not provide Nitro evidence.

Hardware evidence now covers the actual bootstrap amd64 image, non-debug NSM identity/TLS verification, KMS recipient initialization and same-host restart recovery, authenticated encrypted database restore, and parent plaintext Decrypt/GenerateDataKey/chosen-key Encrypt denials. The standalone genuine proof also passed the real adapter. Remaining PoC evidence includes the final restored mint-enabled image, its request-bound proof and confidential mint, and withdrawal runtime integration. Shared-network release additionally needs independent matching builds, replacement-host and adverse recovery tests, browser authentication, consensus verification and rollback/clone-resistant payout coordination. Full round-trip operation remains unverified.

Primary references: [AWS enclave architecture](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html), [AWS measurements](https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html), [KMS attested calls](https://docs.aws.amazon.com/kms/latest/developerguide/attested-calls.html), [KMS Decrypt recipient API](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html), [NSM API](https://github.com/aws/aws-nitro-enclaves-nsm-api), [Node proxy support](https://nodejs.org/learn/http/enterprise-network-configuration).
