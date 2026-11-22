# Silence on the Wire

[![CI](https://github.com/Inner-Savages/silence-on-the-wire/actions/workflows/images.yml/badge.svg?branch=main)](https://github.com/Inner-Savages/silence-on-the-wire/actions/workflows/images.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Inner-Savages/silence-on-the-wire/badges/coverage.json)](https://github.com/Inner-Savages/silence-on-the-wire/actions/workflows/images.yml)
[![Go version](https://img.shields.io/github/go-mod/go-version/Inner-Savages/silence-on-the-wire)](go.mod)
[![Images](https://img.shields.io/badge/ghcr.io-sensor%20%7C%20scanner%20%7C%20trigger%20%7C%20traffic-2496ED?logo=docker&logoColor=white)](https://github.com/orgs/Inner-Savages/packages?repo_name=silence-on-the-wire)
[![Platforms](https://img.shields.io/badge/platform-linux%2Famd64%20%7C%20linux%2Farm64-lightgrey)](Dockerfile)
[![HackNation 2026](https://img.shields.io/badge/HackNation-2026-red)](https://hacknation.pl)

A passive network sensor that notices changes in your network and wakes up an active
scanner to take a closer look. Named after Michał Zalewski's book on passive
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
network traffic ──► [ passive sensor ] ── webhook ──► [ trigger ] ──► [ scan pipeline ]
                     baseline: host,                   debounce,       nmap + HTTP prober
                     port, banner                      cooldown,       + signatures
                                                       quiet window          │
                                         findings.jsonl ◄── verdict + diff ◄─┘
```

## What works today

- **Sensor** (`cmd/sensor`): captures with libpcap on one or more interfaces (or replays
  a pcap) with a kernel BPF filter that keeps only ARP, SYN/RST and HTTP response heads.
  It builds a baseline of hosts, services and stable HTTP banner fingerprints, persists
  it across restarts, and prints JSON-lines events:

  | Event | Meaning |
  |---|---|
  | `host_new`, `service_new` | not in the baseline before |
  | `service_changed` | HTTP banner fingerprint changed (`Server`, `X-Powered-By`, `X-Env`, ...) |
  | `service_closed` | a SYN was answered with RST: the host is up, the port is closed |
  | `host_silent`, `service_silent` | no traffic for `-silent-after`: maybe gone, maybe just quiet |
  | `host_back`, `service_back` | seen again after closed/silent |

- **Scanner** (`cmd/scanner`): safe discovery scan of IPs, CIDRs (up to /12) and
  hostnames, split into chunks scanned by parallel nmap processes (`-sT` connect scan by
  default, `-sV`, rate limit, no NSE scripts or OS detection), with chunk and total
  durations. Web services are then probed with GET only: status, title, headers, cookie
  names and flags, same-host redirects, TLS certificate, favicon (Shodan-compatible mmh3
  hash). YAML signatures recognize technologies with a confidence score (WordPress,
  phpMyAdmin, Adminer, DVWA, Gitea, RabbitMQ, Traefik, nginx, PHP, databases, SSH, a few
  IoT devices, plus staging environments, admin panels, setup and default pages).
  `scanner diff` compares two results: new, gone and changed hosts and services.

  *Why the favicon?* Most web apps ship with a default icon, and almost nobody replaces
  it: an admin may hide the `Server` header, the version and the page title, but Gitea,
  phpMyAdmin or a router panel still serves its stock `favicon.ico`. A hash of that file
  therefore identifies the product even when nothing else in the response does. The hash
  is computed exactly like Shodan's `http.favicon.hash` (mmh3 of the base64-encoded icon),
  so it can be matched against public hash lists or searched on Shodan
  (`http.favicon.hash:<n>`) to find other instances. A changed hash between two scans
  means a different application, or version, now answers on that address.

  *Why our own signature format?* There is no single standard, only de facto ones, each
  covering part of the job: Wappalyzer/webappanalyzer (JSON, the largest web technology
  base, but passive: one response, no paths, no favicon hashes, no nmap data), nuclei
  templates (YAML with favicon hashes, but a whole engine that sends its own requests,
  many of them beyond a safe GET), nmap-service-probes (TCP level, used here through
  `-sV`), Recog and WhatWeb. Our format is small (one kind of evidence per matcher) and
  combines nmap results, the HTTP response, the favicon and safe GET-only paths, with
  weights that add up to a confidence score. It also has rules those bases lack, such as
  "staging" or "admin panel". The cost is that we don't get thousands of signatures for
  free. The natural next step is an importer that translates Wappalyzer technologies and
  nuclei favicon hashes into this format, without adopting their engines.
- **Trigger** (`cmd/trigger`): receives sensor events (`sensor -webhook`) and runs
  targeted scans through the same pipeline: new or changed services and hosts are
  scanned, silent or closed ones verified. Each scan becomes a finding with a verdict
  (`scanned`, `still-open`, `gone-confirmed`, `still-up`, `down-confirmed`, `error`),
  services, technologies and the diff against the previous scan of that target. Only
  allow-listed addresses are scanned; events about the scanner's own addresses are
  ignored; bursts are debounced; a quiet window drops events caused by the scan itself;
  per-target cooldowns, a 30-minute pause on re-verifying targets found alive, a global
  rate limit and a pending-job cap keep the active side bounded.
- **Export** (`scanner export`): CSV (one row per open service, or per trigger finding),
  JSON, nmap XML, and DefectDojo. Selected observations (admin panels, unfinished
  installations, default pages, staging, self-signed or expired certificates, outdated
  components) become informational findings with their evidence, linked to their
  endpoint. A stable `unique_id_from_tool` keeps later runs from creating duplicates:
  they refresh the evidence and leave analysts' decisions, severities and tags alone.
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

Useful flags: `-i br-a,br-b` or `-i 'br-*'` (several interfaces, globs), `-net` (prefixes to watch; default
`auto` = subnets of the capture interfaces), `-silent-after`, `-learn`, `-state`
(baseline file), `-r capture.pcap` (replay), `-f` (BPF filter, `""` = everything).

### Scanner

```bash
make build
./bin/scanner -t 10.0.0.0/24 -p 22,80,443,8000-8100 -o scan1.json
./bin/scanner -t 10.0.0.0/24 -p 22,80,443,8000-8100 -o scan2.json
./bin/scanner diff scan1.json scan2.json          # -json, -exit-code
```

Useful flags: `-f targets.txt`, `-allow 10.0.0.0/16` (refuse targets outside), `-Pn`,
`-sS` (needs `CAP_NET_RAW`), `-max-rate`, `-chunk` and `-parallel` (chunking),
`-signatures extra.yaml` (custom signatures, see `internal/fingerprint/signatures/`),
`-probe=false`, `-fingerprint-paths=false` (no extra GETs such as `/wp-login.php`).

### Export to CSV and DefectDojo

```bash
./bin/scanner export -o scan.csv scan.json
./bin/scanner export -findings trigger-state/findings.jsonl -o findings.csv
./bin/scanner export -format defectdojo -dry-run scan.json       # what would be sent
export DEFECTDOJO_TOKEN=...                                      # or -token-file
./bin/scanner export -format defectdojo -url https://dojo.example.org scan.json
```

`-select` picks observations (`default,category:database,tech:Gitea,tag:login`, or single
rules such as `admin-panel,cert-expired`), `-min-confidence` drops weak ones, `-findings`
adds what the sensor and the trigger noticed as evidence, `-previous old.json` supplies
first-seen dates, `-nmap` also feeds DefectDojo's own "Nmap Scan" importer. `-product`,
`-engagement` and `-test` name the place in DefectDojo, created if missing. Findings are
matched within the test, so give networks with overlapping addresses separate tests. All
scans on the command line count as current; findings missing from them are not closed. The
token needs permission to create findings there (and products, if they are missing).
`lab/defectdojo/` runs a local instance for trying it out.

### Sensor + trigger

```bash
./bin/trigger -allow 10.0.0.0/16 -state trigger-state      # listens on 127.0.0.1:8099
./bin/sensor -i eth0 -webhook http://127.0.0.1:8099/events
tail -f trigger-state/findings.jsonl
```

Set the same `SOTW_WEBHOOK_TOKEN` for both to require a bearer token. `GET /healthz`
shows pending and running scans and why events were dropped. Policy flags: `-debounce`,
`-quiet`, `-cooldown`, `-closed-cooldown`, `-max-per-minute`, `-top-ports`.

### Docker images

```bash
docker run --rm --network host --cap-drop ALL --cap-add NET_RAW \
  -v sotw-data:/data ghcr.io/inner-savages/silence-on-the-wire/sensor -i eth0
docker run --rm --network host --user $(id -u):$(id -g) -v "$PWD:/data" \
  ghcr.io/inner-savages/silence-on-the-wire/scanner -t 127.0.0.1 -Pn -o scan.json
docker run --rm ghcr.io/inner-savages/silence-on-the-wire/traffic \
  -targets "http://example.internal/ tcp://example.internal:22"
```

Images are built by GitHub Actions for `linux/amd64` and `linux/arm64`. All of them run
as an unprivileged user; the sensor needs only `CAP_NET_RAW`, the scanner and the trigger
none (connect scan). `--user $(id -u):$(id -g)` makes result files belong to you (they are created
with mode 0600). `make images` builds them locally under the same names.

### On the CBI AGH lab templates

The organizers' templates are included unchanged in `lab/agh/upstream/`. The overlay
adds traffic, a flapping host, the sensor and the trigger:

```bash
docker compose -f lab/agh/upstream/docker-compose-custom-network.yml \
               -f lab/agh/traffic-custom-network.yml up -d
docker compose -f lab/agh/upstream/docker-compose-custom-network.yml \
               -f lab/agh/traffic-custom-network.yml logs -f sensor trigger
```

`lab/agh/scenario.sh` runs a scripted scenario (banner change, service stop/start, new
host, flapping service) and prints which event to expect after each step. See
`lab/agh/README.md`. Their own demo works with the scanner too:

```bash
P=2223,3001,5673,8787,8888,15432,15673
./bin/scanner -t 127.0.0.1 -p $P -Pn -o scan1.json
(cd lab/agh/upstream && ./quickstart.sh change)     # stops the service on 8787
./bin/scanner -t 127.0.0.1 -p $P -Pn -o scan2.json
./bin/scanner diff scan1.json scan2.json           # - 8787/tcp http nginx ...
```

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
`internal/scan` (targets, chunks, nmap), `internal/probe` (HTTP/TLS), `internal/fingerprint`
(signatures), `internal/pipeline` (scan + probe + fingerprint), `internal/diff`, `internal/export` (CSV, DefectDojo),
`internal/trigger` (policy, service), `internal/result` (shared model), `internal/traffic`,
`lab/` (test environments), `Dockerfile` (targets `sensor`, `scanner`, `trigger`, `traffic`).

## Blog

The build process is documented (Polish and English) on
[q84fh.net](https://q84fh.net/tags/hacknation2026/).
