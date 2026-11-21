# syntax=docker/dockerfile:1
#
#   docker build --target sensor  -t ghcr.io/inner-savages/silence-on-the-wire/sensor   .
#   docker build --target traffic -t ghcr.io/inner-savages/silence-on-the-wire/traffic .

FROM golang:1.26 AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends libpcap-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
# The sensor links libpcap (cgo); the traffic generator is fully static.
RUN CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o /out/sensor ./cmd/sensor \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/traffic ./cmd/traffic

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
