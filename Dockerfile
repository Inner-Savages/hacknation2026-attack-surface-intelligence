# syntax=docker/dockerfile:1
#
#   docker build --target sensor  -t ghcr.io/inner-savages/silence-on-the-wire/sensor   .
#   docker build --target traffic -t ghcr.io/inner-savages/silence-on-the-wire/traffic .
#   docker build --target scanner -t ghcr.io/inner-savages/silence-on-the-wire/scanner .
#   docker build --target trigger -t ghcr.io/inner-savages/silence-on-the-wire/trigger .
#   docker build --target console -t ghcr.io/inner-savages/silence-on-the-wire/console .

FROM golang:1.26 AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends libpcap-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
# The sensor links libpcap (cgo); everything else is static.
RUN CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o /out/sensor ./cmd/sensor \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/traffic ./cmd/traffic \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/scanner ./cmd/scanner \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/trigger ./cmd/trigger \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/console ./cmd/console

# Passive sensor. Runs as an unprivileged user; the binary carries only the
# CAP_NET_RAW file capability (the container must allow it: cap_add NET_RAW).
FROM debian:trixie-slim AS sensor
RUN apt-get update \
 && apt-get install -y --no-install-recommends libpcap0.8t64 libcap2-bin \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/sensor /usr/local/bin/sensor
RUN setcap cap_net_raw+ep /usr/local/bin/sensor \
 && apt-get purge -y libcap2-bin && apt-get autoremove -y \
 && mkdir /data && chown 65532:65532 /data
USER 65532:65532
VOLUME /data
ENTRYPOINT ["sensor", "-state", "/data/sensor-state.json"]

# Background traffic generator for labs. Static binary, nothing else.
FROM scratch AS traffic
COPY --from=build /out/traffic /traffic
USER 65532:65532
ENTRYPOINT ["/traffic"]

# Active scanner: nmap (-sT connect scan by default, which needs no
# privileges) plus our HTTP prober and signatures. Runs unprivileged and
# writes results to /data. For -sS run with --user 0 --cap-add NET_RAW.
FROM debian:trixie-slim AS scanner
RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir /data && chown 65532:65532 /data
COPY --from=build /out/scanner /usr/local/bin/scanner
USER 65532:65532
WORKDIR /data
VOLUME /data
ENTRYPOINT ["scanner"]

# Trigger: receives sensor events and runs targeted scans with the same
# pipeline as the scanner, so it reuses that image (nmap, unprivileged).
FROM scanner AS trigger
COPY --from=build /out/trigger /usr/local/bin/trigger
ENTRYPOINT ["trigger", "-state", "/data"]

# Operator console (web UI + intake API). The UI is embedded in the binary
# (cmd/console/static), so the image is the binary plus CA certificates for
# the Shodan/Censys/NVD/LLM clients. Listens on 0.0.0.0:18081 by default here
# because it is meant to sit behind a proxy/tunnel on a private network;
# state (encrypted at rest when ASI_DATA_KEY[_FILE] is set) goes to /data.
FROM debian:trixie-slim AS console
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir /data && chown 65532:65532 /data
COPY --from=build /out/console /usr/local/bin/console
USER 65532:65532
WORKDIR /data
VOLUME /data
EXPOSE 18081
ENTRYPOINT ["console", "-listen", "0.0.0.0:18081", "-data-dir", "/data"]
