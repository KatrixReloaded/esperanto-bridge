# Stagenet user wallet in Docker

The official Linux Monero CLI 0.18.5.4 runs on native arm64 or amd64. The build checks the archive against the SHA-256 published in Monero's official release list. This is a user wallet, separate from the bridge vault. It connects directly to Nodely's HTTPS stagenet node; it does not inherit the backend's Nym transport.

Build from the repository root:

```sh
docker build -t cwxmr-wallet:0.18.5.4 scripts/monero-wallet
docker run --rm cwxmr-wallet:0.18.5.4 --version
```

Create a wallet interactively; its seed and password stay in your terminal:

```sh
mkdir -p "$HOME/cwxmr-stagenet"
docker run --rm -it --cap-drop ALL --security-opt no-new-privileges \
  --mount "type=bind,source=$HOME/cwxmr-stagenet,target=/wallet" \
  cwxmr-wallet:0.18.5.4 --generate-new-wallet /wallet/user
```

Choose a password and save the recovery seed privately. At the wallet prompt, run `address`, use that address at https://faucet-stagenet.xmr.nodely.dev/, then run `refresh` and `balance`. Wait for an unlocked balance before transferring.

Reopen the same wallet:

```sh
docker run --rm -it --cap-drop ALL --security-opt no-new-privileges \
  --mount "type=bind,source=$HOME/cwxmr-stagenet,target=/wallet" \
  cwxmr-wallet:0.18.5.4 --wallet-file /wallet/user
```

`--rm` removes the stopped container, not the mounted wallet directory. Back up that directory and the recovery seed; never commit them. No host ports, Docker socket or other host directories are mounted. On a managed device, Docker remains subject to its administrator's policies.
