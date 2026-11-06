# Nitro operator runbook

This is a locally tested foundation, not a deployed or usable bridge. AWS account activation is pending. No AWS resources were provisioned. The runtime deliberately reports `bridge_actions_enabled:false`: authenticated chain verification, deposit/payout orchestration, independent payout fencing and live FHE/proof integration are release gates. Never fund these vaults yet.

## Boundary and keys

The one EIF contains `zz-monero`, `zz-zama`, `zz-core`, `zz-watcher` and the real `@zama-fhe/sdk` sidecar. It creates the Monero spend key and separate secp256k1 mint/decryption, Ed25519 authentication and P-256 TLS keys internally. The sidecar listens only on enclave loopback `127.0.0.1:8788`. Do not forward that port. The parent only forwards public TLS bytes, outbound HTTPS/CONNECT bytes and encrypted storage. It can deny service, replay old ciphertext, clone restored instances and manipulate unauthenticated chain responses.

Registry attestation uses raw64 secp256k1 `public_key`, challenge raw32 `nonce`, and raw32 application binding digest `user_data`. `tlsKeyHash` is SHA256 of the TLS SPKI DER; authentication hash is SHA256 of raw32 Ed25519 public key. The exact ABI encoding is in [contracts/INTERFACES.md](../contracts/INTERFACES.md). Native mode returns no NSM evidence and cannot register.

KMS recovery uses a **separate fresh RSA-2048 SPKI DER recipient** NSM document. `GenerateDataKey`/`Decrypt` run over authenticated KMS TLS, signed with the parent's temporary IAM credentials, inside the enclave. KMS CMS `CiphertextForRecipient` is unwrapped only inside the enclave. The parent never receives the data key or private key. Runtime uses KMS `GenerateDataKey(Recipient)`, never a host-generated key plus `Encrypt`.

Identity DER keys are encrypted with AES-256-GCM under the recovered 32-byte data key; core state uses `zz_core::storage::Cipher` (XChaCha20-Poly1305). Canonical recovery domain is `cwxmr/recovery/v1` ASCII || chainId uint64 big endian || registry raw20 || bridge raw20. Its SHA256 hex is KMS EncryptionContext `cwxmr-domain`; its raw bytes are identity-backup AAD. Mutable policy versions, address case and `0x` spelling do not change recovery. Envelope bytes and wrapped keys are host-visible. Current runtime backup covers generated identity/wallet keys only; application mappings, reservations and signed payouts need the core PostgreSQL encrypted state backup once orchestration is integrated. Seed-only recovery is insufficient.

KMS policy administrators, account owners able to change those administrators, and approved image/policy upgrades are recovery trust boundaries. They can change policy to recover or forge secrets. Encryption and KMS do not establish storage freshness, exclusive execution or resistance to rollback. Cooperative PostgreSQL locks do not fence hostile clones. Payout broadcasting remains blocked in core.

## Configure and build (Linux x86_64)

Review [infra/operator.yaml](../infra/operator.yaml); it is a template, not an instruction to provision now. `m6i.2xlarge` is a paid initial sizing candidate (8 vCPU/32 GiB), with enclave allocator 2 vCPU/8192 MiB. SDK peak memory is unmeasured. Operator must verify regional AMI, supported Nitro instance, price/quota/credits and installation procedures before authorizing any resources. The template requires IMDSv2 and an existing subnet/security group. KMS recovery defaults disabled: first obtain the key ARN with no recipient access, build the configured EIF, then enable only its reviewed nonzero PCR0/PCR1/PCR2. Deploy using the specified policy-administration role so KMS's lockout-safety checks remain satisfied. No root IAM-delegation wildcard is included.

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

Review exact outbound HTTPS hostnames needed by the configured Ethereum provider, Zama gateway/relayer/KMS network. [infra/outbound.example.json](../infra/outbound.example.json) is a starting list, **not validated SDK endpoint discovery**. Missing hostnames fail startup/requests. Enclave DNS is unnecessary for Node built-in HTTP/fetch paths because Node24 proxy support sends CONNECT hostnames to the parent. Custom SDK agent paths and native dependencies still require a real-enclave compatibility test; setting proxy variables alone is not evidence that all traffic works. Remote TLS certificate validation stays enabled inside Rust/Node.

```sh
# Terminal A: untrusted transport only; path contains ciphertext, no wallet plaintext.
scripts/nitro/run-host.sh /var/lib/cwxmr/identity.encrypted.json outbound-reviewed.json
# Terminal B: compares reviewed PCRs and launches without debug or console.
scripts/nitro/launch.sh approved-measurements.json
nitro-cli describe-enclaves
```

Traffic map: parent TCP8443 → enclave vsock8443 → TLS127.0.0.1:8443; enclave local8444 → parent vsock8444 → ciphertext store/IMDS helper; local8445 → parent vsock8445 → regional KMS443; local8888 → parent vsock8888 → allowlisted CONNECT proxy. Outbound wallet/chain adapters are not yet integrated. Inbound parent TCP8443 listens on loopback; any external load balancer must pass TLS bytes unchanged. No host HTTPS termination for sensitive enclave requests.

A new bootstrap must persist/read back the encrypted envelope before publishing the identity. Once bootstrap succeeds, record its vaultId independently. Set `initialize=false` before any funded release and rebuild/reapprove the resulting measured config; include both approved images in a deliberate KMS migration window if needed. Otherwise a malicious parent returning 404 can trigger a different fresh identity. It cannot recreate the old key or satisfy an existing client's old TLS pin, but it can confuse an unpinned operator. Expected-vault identity fencing is still a release gate.

## Attest, register and authenticate the TLS peer

Before enrollment the only public routes are `/identity`, `/health`, and `/attestation?challenge=HEX32`. They perform no deposit, mint, decryption, claim or payout action. `/health` reports the disabled gates explicitly. A self-signed certificate or successful HTTPS request alone is **not RA-TLS**.

1. Fetch public identity provisionally. Compare expected identity/recovery records; do not send secrets.
2. On VaultRegistry call `issueChallenge(vaultId,salt)` with the account that will submit `attest`; read `ChallengeIssued`. Challenges expire after 600 seconds.
3. Fetch `/attestation?challenge=<exact onchain raw32 challenge>` through TLS. The initial document fetch may use an untrusted self-signed connection because it contains only public evidence; treat all fields as unverified until the next step.
4. Use the pinned Automata revision `65c4a4233029ea3bbe16110a80731fcfd47cf300` prover (SP1/RISC0 selected and independently pinned by deployment) to prove that exact NSM document. Configure the actual proof verifier/program/root/prefix policy and submit authenticated output/proof to `VaultRegistry.attest` with the exact key bundle/version/challenge. Existing interface pins are documented in contracts; automatic prover packaging/submission and a live document/proof roundtrip are **pending**, not simulated by an operator registration path.
5. Verify finalized registration/current authorization, PCR policy and expiry. For a registered peer, the provided client reads current authorization at an independently trusted finalized block, validates pinned registry bytecode and compares the live TLS SPKI before sending its HTTP request:

```sh
npm ci --prefix sidecar --ignore-scripts
node scripts/nitro/verify-peer.mjs "$HTTPS_RPC" "$CHAIN_ID" "$REGISTRY" "$REGISTRY_CODEHASH" "$VAULT_ID" "$TRUSTED_FINALIZED_BLOCK_HASH" https://127.0.0.1:8443
```

This client authenticates possession of the TLS private key enrolled by Automata; it fails on changed keys, inactive/expired registry entries, wrong chain/code hash or stale block time. It trusts configured RPC state and the supplied finalized block; RPC/header consistency is not Ethereum consensus authentication. Runtime/browser peer authentication and fresh on-demand COSE verification are still integration work. Never obtain a TLS pin solely from the same untrusted endpoint and call that remote attestation.

Renew attestation before the registry's 86400-second expiry using a fresh registry challenge. Rebuild/policy updates must preserve the same recovered key bundle if refreshing a vault. Refresh cannot reactivate a suspended/revoked/retired vault. No CLI exports or accepts a production authority private key.

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

Local checks cover real native TLS key possession/pin rejection, no native attestation, exact binding/domain changes, authenticated key-backup roundtrip/tamper rejection, core Cipher key integration, transport byte preservation/half-close, measured-PCR rejection and template syntax. See test commands in `scripts/nitro/test-local.py` and the Rust watcher tests. Local tests do not provide Nitro evidence.

Remaining hardware work: actual amd64 container/EIF builds and independent matching hashes/PCRs; allocator/CPU/RAM viability; real NSM and non-debug policy; IAM/KMS recipient roundtrip/denial tests; encrypted restart/restore; SDK proxy/native-library compatibility; real Automata proof + registry enrollment; browser/peer client integration; independently authenticated Ethereum/Monero chain data; durable orchestration and rollback-resistant payout fencing. Full bridge workflows remain disabled until those gates pass.

Primary references: [AWS enclave architecture](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html), [AWS measurements](https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html), [KMS attested calls](https://docs.aws.amazon.com/kms/latest/developerguide/attested-calls.html), [KMS Decrypt recipient API](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html), [NSM API](https://github.com/aws/aws-nitro-enclaves-nsm-api), [Node proxy support](https://nodejs.org/learn/http/enterprise-network-configuration).
