FROM debian:bookworm-slim AS download
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl bzip2 \
    && rm -rf /var/lib/apt/lists/*
# Official release hashes: https://www.getmonero.org/downloads/hashes.txt
RUN set -eu; \
    case "$TARGETARCH" in \
      arm64) archive=monero-linux-armv8-v0.18.5.4.tar.bz2; digest=d20d71e6522b41eb8e549c3425f7f4622c9c9a448fc7147525393fd0a6b59703 ;; \
      amd64) archive=monero-linux-x64-v0.18.5.4.tar.bz2; digest=ba2928962c101b609434bf8c1b43ad59ebe96c5525977284ca599d8bf0f02d10 ;; \
      *) exit 1 ;; \
    esac; \
    curl --fail --location --retry 3 --max-time 300 "https://downloads.getmonero.org/cli/$archive" -o /tmp/monero.tar.bz2; \
    printf '%s  /tmp/monero.tar.bz2\n' "$digest" | sha256sum --check -; \
    mkdir /opt/monero; \
    tar -xjf /tmp/monero.tar.bz2 -C /opt/monero --strip-components=1

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libstdc++6 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=download /opt/monero/monero-wallet-cli /usr/local/bin/monero-wallet-cli
WORKDIR /wallet
ENTRYPOINT ["monero-wallet-cli", "--stagenet", "--daemon-address", "https://xmr.nodely.dev:38089", "--untrusted-daemon", "--log-file", "/wallet/wallet.log", "--shared-ringdb-dir", "/wallet/ringdb"]
