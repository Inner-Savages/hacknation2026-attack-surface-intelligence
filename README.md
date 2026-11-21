# Silence on the Wire

[![CI](https://github.com/Inner-Savages/silence-on-the-wire/actions/workflows/images.yml/badge.svg?branch=main)](https://github.com/Inner-Savages/silence-on-the-wire/actions/workflows/images.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Inner-Savages/silence-on-the-wire/badges/coverage.json)](https://github.com/Inner-Savages/silence-on-the-wire/actions/workflows/images.yml)
[![Go version](https://img.shields.io/github/go-mod/go-version/Inner-Savages/silence-on-the-wire)](go.mod)
[![Go Report Card](https://goreportcard.com/badge/github.com/Inner-Savages/silence-on-the-wire)](https://goreportcard.com/report/github.com/Inner-Savages/silence-on-the-wire)
[![Images](https://img.shields.io/badge/ghcr.io-sensor%20%7C%20traffic-2496ED?logo=docker&logoColor=white)](https://github.com/orgs/Inner-Savages/packages?repo_name=silence-on-the-wire)
[![Platforms](https://img.shields.io/badge/platform-linux%2Famd64%20%7C%20linux%2Farm64-lightgrey)](Dockerfile)
[![HackNation 2026](https://img.shields.io/badge/HackNation-2026-red)](https://hacknation.pl)

A passive network sensor that notices changes in your network and (soon) wakes up an
active scanner to take a closer look. Named after Michał Zalewski's book on passive
reconnaissance.

Built during [HackNation 2026](https://hacknation.pl) for the *Attack Surface
Intelligence* challenge set by the Information Security Center of AGH University of
Krakow (CBI AGH). Work in progress.

## Why

Large networks are scanned periodically, because nobody wants a scanner hammering every
service all the time. Between scans the security team is blind. A passive sensor sees
traffic continuously: when a new host or service shows up, a banner changes, or a
service goes quiet, it emits an event that can trigger a targeted active scan instead of
waiting for the next full sweep.

```
network traffic ──► [ passive sensor ] ── change events ──► [ active scanner ]
                     baseline: host,                         nmap + HTTP prober
                     port, banner                             (in progress)
```

## What works today

- **Sensor** (`cmd/sensor`): captures with libpcap on one or more interfaces (or replays
  a pcap) with a kernel BPF filter that keeps only ARP, SYN/RST and HTTP response heads.
  It builds a baseline of hosts, services and stable HTTP banner fingerprints, persists
  it across restarts, and prints JSON-lines events:

  | Event | Meaning |
  |---|---|
  | `host_new`, `service_new` | not in the baseline before |
  | `service_changed` | HTTP banner fingerprint changed (`Server`, `X-Powered-By`, cookie names, ...) |
  | `service_closed` | a SYN was answered with RST: the host is up, the port is closed |
  | `host_silent`, `service_silent` | no traffic for `-silent-after`: maybe gone, maybe just quiet |
  | `host_back`, `service_back` | seen again after closed/silent |

- **Traffic generator** (`cmd/traffic`): gentle background traffic for labs (HTTP GETs,
  TCP connects with banner reads), so a passive sensor has something to observe. No
  logins, no exploits.
- **Lab overlay for the CBI AGH templates** (`lab/agh/`): adds traffic, an unstable
  host and the sensor to their `custom-network` stack without modifying their files
  (included in `lab/agh/upstream/`).

## Quick start

### Sensor on the host

Needs Go 1.26+ and `libpcap-dev`.

```bash
make sensor-caps        # builds bin/sensor and grants it only CAP_NET_RAW
./bin/sensor -i eth0 -learn 30s > events.jsonl
```

Useful flags: `-i br-a,br-b` (several interfaces), `-net` (prefixes to watch; default
`auto` = subnets of the capture interfaces), `-silent-after`, `-learn`, `-state`
(baseline file), `-r capture.pcap` (replay), `-f` (BPF filter, `""` = everything).

### Docker images

```bash
docker run --rm --network host --cap-drop ALL --cap-add NET_RAW \
  -v sotw-data:/data ghcr.io/inner-savages/silence-on-the-wire/sensor -i eth0
docker run --rm ghcr.io/inner-savages/silence-on-the-wire/traffic \
  -targets "http://example.internal/ tcp://example.internal:22"
```

Images are built by GitHub Actions for `linux/amd64` and `linux/arm64`. The sensor runs
as an unprivileged user and needs only `CAP_NET_RAW`. `make images` builds them locally
under the same names.

### On the CBI AGH lab templates

The organizers' templates are included unchanged in `lab/agh/upstream/` (with their
permission). The overlay adds traffic, a flapping host and the sensor:

```bash
docker compose -f lab/agh/upstream/docker-compose-custom-network.yml \
               -f lab/agh/traffic-custom-network.yml up -d
docker compose -f lab/agh/upstream/docker-compose-custom-network.yml \
               -f lab/agh/traffic-custom-network.yml logs -f sensor
```

`lab/agh/scenario.sh` runs a scripted scenario (banner change, service stop/start, new
host, flapping service) and prints which event to expect after each step. See
`lab/agh/README.md`.

### Own minimal lab

`lab/` contains a small Docker lab (named bridge `br-asilab`, `172.28.0.0/24`) with a
plain nginx, a fake WordPress, a staging host, a flapping host and a traffic client.

```bash
make lab-up
lab/scripts/sensor-live-test.sh out/    # ~2 min live test of the sensor
make lab-down
```

## Development

```bash
make test     # go vet + go test (needs libpcap-dev)
```

Layout: `cmd/` (binaries), `internal/sensor` (decoder, BPF filter, tracker, baseline),
`internal/traffic` (probes), `lab/` (test environments), `Dockerfile` (targets `sensor`
and `traffic`).

## Blog

The build process is documented (Polish and English) on
[q84fh.net](https://q84fh.net/posts/2026-11-21-hacknation-asi-01-lab/).
