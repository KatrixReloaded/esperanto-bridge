# Local unsigned stagenet redemption

This tool prepares a user-approved redemption against the **new unsafe Bridge**. It reads no wallet or enclave bundle and sends no transaction. Wait for a confirmed nonzero mint before choosing the amount. The requested burn includes the configured payout fee; the worker enforces its fee commitment and limits.

Build the existing Monero address parser/encoder and use Node 22 (ethers is already in contracts dependencies):

```sh
cargo build --manifest-path service/Cargo.toml -p zz-monero --bin cwxmr-destination
umask 077
mkdir -p dev-state
```

Create a private `dev-state/redemption-input.json` with these fields:

```json
{
  "mode": "UNSAFE_TEST_NO_NITRO",
  "chainId": 11155111,
  "user": "0xUSER_SUBMITTING_ETHEREUM_ADDRESS",
  "pins": { "bridge": "COPY_ALL_EIGHT_FIELDS_FROM_UNSAFE_TEST_PINS_JSON" },
  "feeTermsHash": "0xREVIEWED_WORKER_FEE_COMMITMENT",
  "vaultIds": ["0xCURRENT_ELIGIBLE_VAULT_ID"],
  "amount": "USER_CHOSEN_XMR_DECIMAL_AMOUNT",
  "destination": "USER_STAGENET_STANDARD_OR_SUBADDRESS"
}
```

Replace `pins` with the entire eight-field object from the reviewed deployment artifact. This offline tool validates configuration shape, not live code or current vault eligibility. It validates and checksum-normalizes the nonzero submitting address, preserves it as the ciphertext scope and transaction sender, fixes chain 11155111, sorts unique vault IDs, enforces positive uint64 amounts with at most 12 decimal places, and validates Monero network/checksum/key points through the existing Rust library. Integrated addresses are rejected. The exact 96-byte encoding becomes three big-endian uint256 words.

```sh
node contracts/scripts/prepare-redemption.cjs prepare dev-state/redemption-input.json dev-state/redemption
```

This creates `.context.json` and `.encrypt.json` with mode 0600, refusing existing output files. Both contain private amount/destination information. Keep them out of public logs.

To encrypt, run this **only when the local real SDK sidecar is ready**, with `DEV_CONTAINER` set to its container name. The SDK keeps its existing Nym transport; this command only reaches its loopback API. Do not expose a host port:

```sh
(umask 077; set -C
 docker exec -i "$DEV_CONTAINER" node --input-type=module -e '
   const chunks=[]; for await (const c of process.stdin) chunks.push(c);
   const body=Buffer.concat(chunks); if(body.length>4096)process.exit(1);
   const r=await fetch("http://127.0.0.1:8788/encrypt-redemption", {
     method:"POST",headers:{"content-type":"application/json"},body,
     signal:AbortSignal.timeout(180000)
   });
   if(!r.ok)process.exit(1);
   process.stdout.write(await r.text());
 ' < dev-state/redemption.encrypt.json > dev-state/redemption.encrypted.json
)
```

The response must be `{ "handles": ["0x...", "0x...", "0x...", "0x..."], "inputProof": "0x..." }`. Use only the response for this exact input; the response has no independent scope echo. Local checks validate four handle widths/types, Sepolia chain, current ciphertext version 0 and a nonempty byte proof. **They do not cryptographically verify the input proof or prove its plaintext/contract/user binding. Bridge/FHE performs that verification on execution.**

```sh
node contracts/scripts/prepare-redemption.cjs finish dev-state/redemption.context.json dev-state/redemption.encrypted.json dev-state/redemption.unsigned.json
```

The final mode 0600 JSON contains `from`, Bridge `to`, chain 11155111, zero native value and the current `Bridge.requestRedemption` calldata. Review it locally. The tool prints an explicit `cast send --account personal` command for the user to approve and execute; it never executes that command. Replace its `UNSIGNED_JSON` placeholder with the saved file path, and set the intended Sepolia RPC URL. No token contract call or token approval is used.

Tests (local fixtures only):

```sh
node --test contracts/scripts/prepare-redemption.test.cjs
cargo test --manifest-path service/Cargo.toml -p zz-monero --bin cwxmr-destination
```
