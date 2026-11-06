# Linux-only stagenet round-trip test

This explicitly unsafe lane replaces Nitro proof verification for a separate Ethereum Sepolia deployment. It can exercise real Monero stagenet transfers and real Zama ciphertexts without an NSM device or a prover. It does **not** test enclave isolation, attestation, KMS recovery or proof-backed custody. Anyone can fabricate evidence and mint this deployment's token; never use real XMR or treat these tokens as backed assets.

The contract interface returns a `VerifierJournal`, not a boolean. `UnsafeTestNitroVerifier` decodes caller-supplied output, ignores the proof and reports `Success`. The existing `NitroVerifierAdapter`, `VaultRegistry`, `Bridge` and token remain unchanged: signatures, request binding, replay protection, PCR-policy lookup, FHE input proofs, burn accounting, claim proofs and settlement checks still execute. The unsafe verifier constructor permits only Sepolia (11155111) and the local test chain (31337).

Deploy **new** verifier, adapter and Bridge instances. The new Bridge creates a new token and registry. Existing verified deployments are immutable and are not modified. The regular release checker continues to reject unsafe deployments.

## Deployment commands

These are operator commands; running them spends Sepolia ETH. Use your existing `personal` keystore. Each assignment retains the address in your current terminal. Run each block separately and stop if a command fails. Node 22 or 24 is recommended for project dependencies.

```bash
cd /Users/katrixrldd/Desktop/Learning/projects/xmr-bridge/contracts
set -o pipefail
TEST_RPC_URL="https://ethereum-sepolia-rpc.publicnode.com"
TEST_OWNER=$(cast wallet address --account personal)
test "$(cast chain-id --rpc-url "$TEST_RPC_URL")" = "11155111"
npm ci

TEST_FORGE_ARGS=(--root "$PWD" --hardhat --out out --cache-path cache/forge
  --use 0.8.28 --evm-version cancun
  --optimize --optimizer-runs 200
  --remappings '@openzeppelin/=node_modules/@openzeppelin/'
  --remappings '@fhevm/=node_modules/@fhevm/')
forge build "${TEST_FORGE_ARGS[@]}"
```

```bash
TEST_VERIFIER_ADDRESS=$(
  forge create "${TEST_FORGE_ARGS[@]}" \
    contracts/test/UnsafeTestNitroVerifier.sol:UnsafeTestNitroVerifier \
    --rpc-url "$TEST_RPC_URL" --account personal --broadcast --json \
  | jq -er '.deployedTo'
)
TEST_VERIFIER_CODE=$(cast code "$TEST_VERIFIER_ADDRESS" --rpc-url "$TEST_RPC_URL")
test "$TEST_VERIFIER_CODE" != "0x"
TEST_VERIFIER_CODE_HASH=$(cast keccak "$TEST_VERIFIER_CODE")
TEST_ROOT=$(cast call "$TEST_VERIFIER_ADDRESS" 'rootCert()(bytes32)' --rpc-url "$TEST_RPC_URL")
TEST_PROGRAM=$(cast call "$TEST_VERIFIER_ADDRESS" 'program()(bytes32)' --rpc-url "$TEST_RPC_URL")
test "$(cast call "$TEST_VERIFIER_ADDRESS" 'unsafeTestOnly()(bool)' --rpc-url "$TEST_RPC_URL")" = "true"
```

```bash
TEST_ADAPTER_ADDRESS=$(
  forge create "${TEST_FORGE_ARGS[@]}" \
    contracts/NitroVerifierAdapter.sol:NitroVerifierAdapter \
    --rpc-url "$TEST_RPC_URL" --account personal --broadcast --json \
    --constructor-args "$TEST_VERIFIER_ADDRESS" "$TEST_VERIFIER_CODE_HASH" \
      "$TEST_ROOT" "$TEST_PROGRAM" 2 0x54535431 \
      "$TEST_VERIFIER_ADDRESS" "$TEST_VERIFIER_CODE_HASH" \
  | jq -er '.deployedTo'
)
test "$(cast call "$TEST_ADAPTER_ADDRESS" 'configurationValid()(bool)' --rpc-url "$TEST_RPC_URL")" = "true"
```

```bash
TEST_BRIDGE_ADDRESS=$(
  forge create "${TEST_FORGE_ARGS[@]}" contracts/Bridge.sol:Bridge \
    --rpc-url "$TEST_RPC_URL" --account personal --broadcast --json \
    --constructor-args "$TEST_OWNER" "$TEST_ADAPTER_ADDRESS" \
  | jq -er '.deployedTo'
)
TEST_CWXMR_ADDRESS=$(cast call "$TEST_BRIDGE_ADDRESS" 'token()(address)' --rpc-url "$TEST_RPC_URL")
TEST_REGISTRY_ADDRESS=$(cast call "$TEST_BRIDGE_ADDRESS" 'registry()(address)' --rpc-url "$TEST_RPC_URL")

# Synthetic test measurements: PCR0=48 bytes of 0x11, PCR1=0x22, PCR2=0x33.
# This is keccak256(PCR0 || PCR1 || PCR2), not a Nitro image measurement.
TEST_PCR_TUPLE=0x8763f7b4ff8be9260da66b94bf5e8fab677768a66074d4f2bf62e85ba173cef4
cast send "$TEST_REGISTRY_ADDRESS" 'setPcrPolicy(uint64,bytes32,bool)' \
  1 "$TEST_PCR_TUPLE" true --rpc-url "$TEST_RPC_URL" --account personal
```

Save public runtime pins for the development runner (this contains no private keys):

```bash
TEST_BRIDGE_CODE=$(cast code "$TEST_BRIDGE_ADDRESS" --rpc-url "$TEST_RPC_URL")
TEST_REGISTRY_CODE=$(cast code "$TEST_REGISTRY_ADDRESS" --rpc-url "$TEST_RPC_URL")
TEST_ADAPTER_CODE=$(cast code "$TEST_ADAPTER_ADDRESS" --rpc-url "$TEST_RPC_URL")
TEST_BRIDGE_CODE_HASH=$(cast keccak "$TEST_BRIDGE_CODE")
TEST_REGISTRY_CODE_HASH=$(cast keccak "$TEST_REGISTRY_CODE")
TEST_ADAPTER_CODE_HASH=$(cast keccak "$TEST_ADAPTER_CODE")
mkdir -p artifacts
jq -n \
  --arg bridge "$TEST_BRIDGE_ADDRESS" --arg bridge_hash "$TEST_BRIDGE_CODE_HASH" \
  --arg registry "$TEST_REGISTRY_ADDRESS" --arg registry_hash "$TEST_REGISTRY_CODE_HASH" \
  --arg adapter "$TEST_ADAPTER_ADDRESS" --arg adapter_hash "$TEST_ADAPTER_CODE_HASH" \
  --arg verifier "$TEST_VERIFIER_ADDRESS" --arg verifier_hash "$TEST_VERIFIER_CODE_HASH" \
  '{bridge:$bridge,bridge_code_hash:$bridge_hash,
    registry:$registry,registry_code_hash:$registry_hash,
    adapter:$adapter,adapter_code_hash:$adapter_hash,
    verifier:$verifier,verifier_code_hash:$verifier_hash}' \
  > artifacts/unsafe-test-pins.json
```

PublicNode is used here only by operator deployment commands. Backend chain RPC continues through Nym; the tested Nym exit required the explicitly configured `https://1rpc.io/sepolia` instead of PublicNode.

## Runtime and validation boundary

The separate `unsafe-test` backend feature and development runner are under implementation. They must use their own persistent development identity/database, explicit trusted-node and single-operator assumptions, synthetic journal generation and these new contract pins. No fake NSM response or automatic fallback belongs in the Nitro runtime. The ordinary `serve-dev` command does not currently run this bridge flow.

Before funding, finish the Linux runtime integration and pin the local development endpoint. Then create a stagenet user wallet, obtain faucet funds, fund the development vault's Sepolia signing address, issue an XMR deposit intent, wait for the real confidential mint, request withdrawal and confirm the real stagenet payout and Ethereum settlement. A passed local contract test uses FHEVM mocks and does not establish this live round trip.
