# Nitro operator runbook

Sepolia contracts are deployed; the backend is not yet a usable bridge. Read-only AWS profile, quota and instance capability checks were performed; no AWS resources were provisioned. The operator has postponed EC2 rental until local work is complete. The runtime deliberately reports `bridge_actions_enabled:false`: chain integration, deposit/payout orchestration, payout fencing and live FHE/proof integration remain gates. The stagenet PoC may explicitly trust configured chain nodes; mainnet and malicious-operator custody remain out of scope. Never fund these vaults yet.

## Boundary and keys

The one EIF contains `zz-monero`, `zz-zama`, `zz-core`, `zz-watcher` and the real `@zama-fhe/sdk` sidecar. It creates the Monero spend key and separate secp256k1 mint/decryption, Ed25519 authentication and P-256 TLS keys internally. The sidecar listens only on enclave loopback `127.0.0.1:8788`. Do not forward that port. The parent only forwards public TLS bytes, outbound HTTPS/CONNECT bytes and encrypted storage. It can deny service, replay old ciphertext, clone restored instances and manipulate unauthenticated chain responses.

Per-mint Nitro attestation uses raw64 secp256k1 `public_key`, the mint nonce as raw32 big-endian `nonce`, and a raw32 digest committing to the entire mint request and key bundle as `user_data`. `tlsKeyHash` is SHA256 of the TLS SPKI DER; authentication hash is SHA256 of raw32 Ed25519 public key. The exact ABI encoding is in [contracts/INTERFACES.md](../contracts/INTERFACES.md). Native mode returns no NSM evidence and cannot produce mint evidence.

KMS recovery uses a **separate fresh RSA-2048 SPKI DER recipient** NSM document. `GenerateDataKey`/`Decrypt` run over authenticated KMS TLS, signed with the parent's temporary IAM credentials, inside the enclave. KMS CMS `CiphertextForRecipient` is unwrapped only inside the enclave. The parent never receives the data key or private key. Runtime uses KMS `GenerateDataKey(Recipient)`, never a host-generated key plus `Encrypt`.

Identity DER keys are encrypted with AES-256-GCM under the recovered 32-byte data key; core state uses `zz_core::storage::Cipher` (XChaCha20-Poly1305). Canonical recovery domain is `cwxmr/recovery/v1` ASCII || chainId uint64 big endian || registry raw20 || bridge raw20. Its SHA256 hex is KMS EncryptionContext `cwxmr-domain`; its raw bytes are identity-backup AAD. Mutable policy versions, address case and `0x` spelling do not change recovery. Envelope bytes and wrapped keys are host-visible. Current runtime backup covers generated identity/wallet keys only; application mappings, reservations and signed payouts need the core PostgreSQL encrypted state backup once orchestration is integrated. Seed-only recovery is insufficient.

KMS policy administrators, account owners able to change those administrators, and approved image/policy upgrades are recovery trust boundaries. They can change policy to recover or forge secrets. Encryption and KMS do not establish storage freshness, exclusive execution or resistance to rollback. Cooperative PostgreSQL locks do not fence hostile clones. Payout broadcasting remains blocked in core.

## Configure and build (Linux x86_64)

Review [infra/operator.yaml](../infra/operator.yaml); do not provision until local checks are complete. The default `m6i.xlarge` has 4 vCPUs/16 GiB and supports Nitro Enclaves; `m6i.large` does not. The optional `m6i.2xlarge` has 8 vCPUs/32 GiB. Allocate 2 vCPU/8192 MiB to the enclave initially; SDK/Nym peak memory remains unmeasured. The Mumbai account checked on 2026-11-06 had a 5-vCPU Standard On-Demand quota, so the larger option exceeds it. Free-plan eligibility is separate from quotas and instance support.

Verify regional AMI, price, quota and credits before launching. The template requires IMDSv2 and an existing subnet/security group, allows an existing SSH `KeyName`, and provisions an encrypted 100 GiB gp3 volume. KMS recovery defaults disabled: initially leave PCR parameters empty, obtain the key ARN with no recipient access, then build the configured EIF. Enabling recovery requires all three reviewed nonzero PCRs; template rules reject missing values. Use the specified policy-administration role so KMS lockout-safety checks remain satisfied. No root IAM-delegation wildcard is included.

Install and independently verify AWS `nitro-cli 1.5.2` (source revision `1c496ed730d2dc41ec5bff6df89b4f3185e18840`), Docker, Python3, jq and sha256sum on the Linux builder. Record package/kernel/bootstrap artifacts. Configure the parent allocator using [infra/allocator.yaml](../infra/allocator.yaml), then restart its allocator service. No debug/console launch is supported.

```sh
cp enclave/config/runtime.example.json enclave/config/runtime.json
cp enclave/config/sidecar.example.json enclave/config/sidecar.json
# Set chain, actual registry/Bridge, policy version, KMS ARN/region and HTTPS RPC.
# initialize=true only during a new identity bootstrap; restore uses false.
scripts/nitro/build.sh
scripts/nitro/reproduce.sh
```

The image pins Rust 1.96.0 and Node24.11.1 manifests by digest, Linux amd64, Debian package snapshot 2026-11-01, Cargo.lock and npm lockfile. It builds the actual four-crate backend and copies the actual SDK. No private `.env`, PEM/key, node_modules or target files enter the Docker context. Two no-cache builds compare EIF hashes and PCR tuples. These scripts have **not** run locally: the current machine is macOS and Docker daemon/Nitro devices are absent. There is no claimed EIF hash/PCR or reproducibility result. Independent matching Linux builds remain required. Changes to public baked config, compiler, SDK, app or bootstrap alter measurements and require policy review.

Build output is under `artifacts/nitro/`: EIF, build/describe JSON, measurements JSON, SHA256 and source/tool/lock/config hashes. `describe-eif` is a local build measurement, not live attestation. Never blindly approve its output. Review the source/config and an independent build before allowing that tuple onchain or in KMS. Zero/missing PCRs fail local checks; onchain registry and KMS must independently reject debug PCRs.

## KMS policy inspection

Parent role may perform only recipient-restricted `GenerateDataKey` and `Decrypt` for the approved exact PCR tuple. Deny un-attested/plaintext requests. Explicitly deny parent `Encrypt`, `ReEncrypt*`, grant creation, policy edits and alternate key-generation paths. Otherwise a parent could wrap a known data key, forge an identity backup with host-known private keys, restore it and obtain apparently valid attestation. Check **all** grants, root/IAM delegation, alternate roles and account administrators; a narrowly written Allow alone is insufficient.

After future provisioning, retrieve the actual key policy and grants and inspect them (requires operator-authorized AWS access):

```sh
aws kms get-key-policy --key-id "$KEY_ARN" --policy-name default > actual-key-policy.json
aws kms list-grants --key-id "$KEY_ARN" > actual-key-grants.json
python3 scripts/nitro/inspect-kms-policy.py actual-key-policy.json "$PARENT_ROLE_ARN" approved-measurements.json
```

The inspector is a conservative structural aid, not a full AWS authorization evaluator. It intentionally rejects root/wildcard delegation and unsupported negative policy selectors. Require an empty reviewed grant list and review administrators/role assumption paths separately. Test parent plaintext Decrypt/GDK and chosen-key Encrypt/ReEncrypt rejection on real AWS. Successful attested recipient unwrap, replacement-parent recovery and policy-denial tests remain pending.

## Launch and connectivity

Review exact outbound hostnames needed by the Nym bootstrap and entry gateway, Zama gateway/relayer/KMS network. [infra/outbound.example.json](../infra/outbound.example.json) is a starting list, **not validated SDK endpoint discovery**. Missing hostnames fail startup/requests. Enclave DNS is unnecessary for Node built-in HTTP/fetch paths because Node24 proxy support sends CONNECT hostnames to the parent. Custom SDK agent paths and native dependencies still require a real-enclave compatibility test; setting proxy variables alone is not evidence that all traffic works. Remote TLS certificate validation stays enabled inside Rust/Node.

The sidecar's Ethereum RPC uses the enclave-local Nym SOCKS5 client with remote DNS and HTTPS; it has no direct RPC fallback. This is native Nym, not Ethereum Foundation anon-rpc. Set `nym.provider` to a separately verified Nym Network Requester recipient, `nym.gateway` to the selected entry gateway's identity key, and `nym.api` to a reviewed HTTPS Nym API in the measured sidecar config. The selected gateway must support WSS and anonymous replies must work with the requester. Add the API hostname and the gateway's advertised exact `hostname:port` to the parent allowlist; bare hostnames allow port 443. The parent resolves and connects to the gateway but sees only its TLS traffic. The requester resolves the Ethereum RPC hostname; HTTPS terminates at the RPC provider. Nym client keys and reply state are ephemeral inside the enclave, so each restart re-registers; no Nym state is exported. Nym keeps sending cover traffic while idle, and startup can take minutes. Neither the real Nym route nor these settings have been validated on Nitro or a live mixnet; a listening SOCKS port alone does not prove connectivity or anonymity.

```sh
# Terminal A: untrusted transport only; path contains ciphertext, no wallet plaintext.
scripts/nitro/run-host.sh /var/lib/cwxmr/identity.encrypted.json outbound-reviewed.json
# Terminal B: compares reviewed PCRs and launches without debug or console.
scripts/nitro/launch.sh approved-measurements.json
nitro-cli describe-enclaves
```

Traffic map: parent TCP8443 → enclave vsock8443 → TLS127.0.0.1:8443; enclave local8444 → parent vsock8444 → ciphertext store/IMDS helper; local8445 → parent vsock8445 → regional KMS443; local8888 → parent vsock8888 → allowlisted CONNECT proxy. Outbound wallet/chain adapters are not yet integrated. Inbound parent TCP8443 listens on loopback; any external load balancer must pass TLS bytes unchanged. No host HTTPS termination for sensitive enclave requests.

A new bootstrap must persist/read back the encrypted envelope before publishing the identity. Once bootstrap succeeds, record its vaultId independently. Set `initialize=false` before any funded release and rebuild/reapprove the resulting measured config; include both approved images in a deliberate KMS migration window if needed. Otherwise a malicious parent returning 404 can trigger a different fresh identity. It cannot recreate the old key or satisfy an existing client's old TLS pin, but it can confuse an unpinned operator. Expected-vault identity fencing is still a release gate.

## Per-mint proof and TLS discovery

The public runtime routes are `/identity`, `/health`, and `/attestation?nonce=HEX32`. They perform no deposit, mint, decryption, claim or payout action. The attestation route emits **identity-discovery-only** evidence with `CWXMRNitroIdentityBinding`, using a fresh client-generated nonce and the enclave's own key bundle. Its digest is incompatible with `CWXMRNitroMintBinding` and cannot authorize issuance. `/health` reports disabled gates explicitly. A self-signed certificate or successful HTTPS request alone is not RA-TLS.

For first discovery, provisionally fetch the public identity without sending secrets; compare independent recovery/identity records. An independent verifier must validate the fresh AWS-signed Nitro document, exact discovery domain/nonce/key bundle, allowed nonzero PCRs, timestamp and live TLS SPKI possession. The integrated bootstrap verifier/client is still missing; the directory-based client below cannot bootstrap a brand-new vault. Do not treat the unverified endpoint's claimed TLS hash as a trust anchor.

After authenticated Monero deposit eligibility is implemented, the enclave will authorize the exact canonical mint request, then internally request its mint-bound NSM document. There is no public mint-attestation or signing oracle. Prove that exact document with pinned Automata revision `65c4a4233029ea3bbe16110a80731fcfd47cf300` using the approved SP1/RISC0 deployment pins. Submit authorization, input proof, signature and Nitro evidence in one `Bridge.confidentialMint` transaction. Each call verifies the proof before issuing tokens. The first successful transaction also inserts immutable directory keys; no enrollment or renewal transaction exists. Prover packaging, real NSM proof roundtrip and transaction orchestration remain pending. Reconcile actual encrypted issuance: directory membership or receipt success does not prove positive issuance or liquidity.

For a peer already discovered by a proven mint, the client reads current authorization at an independently trusted finalized block, checks pinned registry bytecode and live TLS SPKI before sending its request:

```sh
npm ci --prefix sidecar --ignore-scripts
node scripts/nitro/verify-peer.mjs "$HTTPS_RPC" "$CHAIN_ID" "$REGISTRY" "$REGISTRY_CODEHASH" "$VAULT_ID" "$TRUSTED_FINALIZED_BLOCK_HASH" https://127.0.0.1:8443
```

This checks possession of the immutable TLS key first bound by Automata, current lifecycle/policy and verifier pins, not fresh enclave liveness. Directory authority has no time-based expiry. Wrong keys, inactive/policy-disabled records, wrong chain/code hash and stale state fail closed. Configured RPC and finalized block are trust inputs; consistency is not Ethereum consensus authentication. Runtime/browser peer authentication and fresh on-demand document verification remain integration work.

Restores preserve the same key bundle. A new approved image/policy can be recorded through a fresh mint proof from an Active identity; keys remain immutable for snapshot ACL safety. Draining can settle existing assignments without renewal, but cannot mint or claim. Suspended, Revoked and Retired identities cannot reactivate through a proof. No CLI exports or accepts a production authority private key.

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

Remaining hardware work: actual amd64 container/EIF builds and independent matching hashes/PCRs; allocator/CPU/RAM viability; real NSM and non-debug policy; IAM/KMS recipient roundtrip/denial tests; encrypted restart/restore; SDK proxy/native-library compatibility; real request-bound Automata proof + atomic first mint; browser/peer client integration; independently authenticated Ethereum/Monero chain data; durable orchestration and rollback-resistant payout fencing. Full bridge workflows remain disabled until those gates pass.

Primary references: [AWS enclave architecture](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html), [AWS measurements](https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html), [KMS attested calls](https://docs.aws.amazon.com/kms/latest/developerguide/attested-calls.html), [KMS Decrypt recipient API](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html), [NSM API](https://github.com/aws/aws-nitro-enclaves-nsm-api), [Node proxy support](https://nodejs.org/learn/http/enterprise-network-configuration).
