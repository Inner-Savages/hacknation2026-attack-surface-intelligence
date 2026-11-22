# Silence on the Wire

[![CI](https://github.com/Inner-Savages/silence-on-the-wire/actions/workflows/images.yml/badge.svg?branch=main)](https://github.com/Inner-Savages/silence-on-the-wire/actions/workflows/images.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Inner-Savages/silence-on-the-wire/badges/coverage.json)](https://github.com/Inner-Savages/silence-on-the-wire/actions/workflows/images.yml)
[![Go version](https://img.shields.io/github/go-mod/go-version/Inner-Savages/silence-on-the-wire)](go.mod)
[![Images](https://img.shields.io/badge/ghcr.io-sensor%20%7C%20scanner%20%7C%20trigger%20%7C%20traffic%20%7C%20console-2496ED?logo=docker&logoColor=white)](https://github.com/orgs/Inner-Savages/packages?repo_name=silence-on-the-wire)
[![Platforms](https://img.shields.io/badge/platform-linux%2Famd64%20%7C%20linux%2Farm64-lightgrey)](Dockerfile)
[![HackNation 2026](https://img.shields.io/badge/HackNation-2026-red)](https://hacknation.pl)

A passive network sensor that notices changes in your network and wakes up an active
scanner to take a closer look. Named after Michał Zalewski's book on passive
reconnaissance.

Built during [HackNation 2026](https://hacknation.pl) for the *Attack Surface
Intelligence* challenge set by the Information Security Center of AGH University of
Krakow (CBI AGH).

| Attack-surface map with a time slider | Per-host risk ranking |
|---|---|
| ![Map: lab hosts and the event timeline](docs/slides/img/mapa.jpg) | ![Risk: hosts ranked 0-100 with their main factors](docs/slides/img/ryzyko.jpg) |

## Dla jury

Narzędzie do ciągłego discovery dużych sieci: bezpieczny skaner (nmap + HTTP + sygnatury), pasywny
sensor, który budzi skan tam, gdzie coś się zmieniło, i konsola operatora z rolami, edycją i szyfrowaniem.

| Co | Gdzie |
|---|---|
| **Demo** | Publiczne demo działało na czas oceny i zostało wyłączone 2026-11-22. Lokalnie: [docs/DEMO.md, część B](docs/DEMO.md#b-lokalnie-z-terminala); własna instancja: [deploy/demo](deploy/demo/README.md) |
| **Prezentacja** (10 slajdów) | [PDF](docs/slides/silence-on-the-wire.pdf) |
| **Scenariusz demo** (co kliknąć, czego się spodziewać) | [docs/DEMO.md](docs/DEMO.md) |
| **Dokumentacja techniczna**, odpowiedzi na trzy pytania z zadania | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [sekcja 6](docs/ARCHITECTURE.md#6-odpowiedzi-na-pytania-z-zadania) |
| **Zgodność z zadaniem**, wymaganie po wymaganiu, z lukami | [docs/COMPLIANCE.md](docs/COMPLIANCE.md) |

Kryteria testowe (sekcja 6 zadania) i miejsce, w którym je sprawdzić:

| Kryterium | Jak sprawdzić |
|---|---|
| Aktywne hosty, usługi, fingerprinting, CMS, nagłówki i ciasteczka | `scanner -t … -o scan.json`, [DEMO, kroki 2–3](docs/DEMO.md#krok-2-skan-odniesienia) |
| Własne sygnatury | `-signatures plik.yaml`, przykłady w [`internal/fingerprint/signatures/`](internal/fingerprint/signatures/) |
| Porównanie skanów | `scanner diff`, [DEMO, krok 4](docs/DEMO.md#krok-4-zmiana-między-przebiegami-diff) |
| Hosty niestabilne | trigger i werdykty, [ARCHITECTURE 6.3](docs/ARCHITECTURE.md#63-po-jakim-czasie-braku-odpowiedzi-raportować-host-jako-nieaktywny) |
| Bezpieczeństwo skanera | [ARCHITECTURE 5.1](docs/ARCHITECTURE.md#51-skaner): tylko GET, bez NSE, allowlista, limity tempa |
| Dashboard, import i eksport, edycja, role | konsola, [DEMO, część A](docs/DEMO.md#a-publiczne-demo-co-klika-jury); eksport: `scanner export` |

The rest of this README is in English.

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

- **Scanner** (`cmd/scanner`): safe discovery scan of IPs, CIDRs (up to /12) and
  hostnames, split into chunks scanned by parallel nmap processes (`-sT` connect scan by
  default, `-sV`, rate limit, no NSE scripts or OS detection), with chunk and total
  durations. Web services are then probed with GET only: status, title, headers, cookie
  names and flags, same-host redirects, TLS certificate, favicon (Shodan-compatible mmh3
  hash). YAML signatures recognize technologies with a confidence score (WordPress,
  phpMyAdmin, Adminer, DVWA, Gitea, RabbitMQ, Traefik, nginx, PHP, databases, SSH, a few
  IoT devices, plus staging environments, admin panels, setup and default pages).
  `scanner diff` compares two results: new, gone and changed hosts and services.

  <details><summary><b>Why the favicon?</b></summary>

  Most web apps ship with a default icon, and almost nobody replaces
  it: an admin may hide the `Server` header, the version and the page title, but Gitea,
  phpMyAdmin or a router panel still serves its stock `favicon.ico`. A hash of that file
  therefore identifies the product even when nothing else in the response does. The hash
  is computed exactly like Shodan's `http.favicon.hash` (mmh3 of the base64-encoded icon),
  so it can be matched against public hash lists or searched on Shodan
  (`http.favicon.hash:<n>`) to find other instances. A changed hash between two scans
  means a different application, or version, now answers on that address.

  </details>

  <details><summary><b>Why our own signature format?</b> (and how to import Wappalyzer and nuclei)</summary>

  There is no single standard, only de facto ones, each
  covering part of the job: Wappalyzer/webappanalyzer (JSON, the largest web technology
  base, but passive: one response, no paths, no favicon hashes, no nmap data), nuclei
  templates (YAML with favicon hashes, but a whole engine that sends its own requests,
  many of them beyond a safe GET), nmap-service-probes (TCP level, used here through
  `-sV`), Recog and WhatWeb. Our format is small (one kind of evidence per matcher) and
  combines nmap results, the HTTP response, the favicon and safe GET-only paths, with
  weights that add up to a confidence score. It also has rules those bases lack, such as
  "staging" or "admin panel". The cost — not getting thousands of signatures for free —
  is covered by the importer (`cmd/sigimport`), which translates Wappalyzer technologies
  and nuclei detection templates (including the favicon mmh3 hashes and the bulk
  WordPress plugin/theme lists) into this format, without adopting their engines:

  ```bash
  git clone --depth 1 https://github.com/enthec/webappanalyzer
  git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates
  go run ./cmd/sigimport \
      -wappalyzer webappanalyzer/src/technologies \
      -nuclei nuclei-templates/http/technologies \
      -o signatures-imported.yaml
  ./bin/scanner -t 10.0.0.0/24 -signatures signatures-imported.yaml ...
  ```

  The importer converts only evidence our passive model can honour (headers, cookies,
  HTML/meta/script patterns, fixed paths, favicon hashes) and reports the rest as
  skipped: Wappalyzer `js`/`dom`/`dns`/`xhr` need a browser or resolver, and nuclei
  requests whose `and`-condition depends on an untranslatable matcher are dropped
  whole, because keeping half of a conjunction would create false positives. On the
  current sources this yields about 60,000 signatures (roughly 6,000 Wappalyzer and
  54,000 nuclei, most of them individual WordPress plugins and themes); the engine
  loads them in under a second. The generated file is data, not code — re-run the
  importer against newer sources instead of editing it by hand.

  </details>

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

- **Trigger** (`cmd/trigger`): receives sensor events (`sensor -webhook`) and runs
  targeted scans through the same pipeline: new or changed services and hosts are
  scanned, silent or closed ones verified. Each scan becomes a finding with a verdict
  (`scanned`, `still-open`, `gone-confirmed`, `still-up`, `down-confirmed`, `error`),
  services, technologies and the diff against the previous scan of that target. Only
  allow-listed addresses are scanned; events about the scanner's own addresses are
  ignored; bursts are debounced; a quiet window drops events caused by the scan itself;
  per-target cooldowns, a 30-minute pause on re-verifying targets found alive, a global
  rate limit and a pending-job cap keep the active side bounded.

- **Operator console** (`cmd/console`, `go run ./cmd/console -demo`): the web UI and API on top of
  everything above. Cases from sensor events and trigger findings (`POST /logs`,
  `/events`, `/findings`, bearer token `ASI_CENTRAL_TOKEN`), an attack-surface map with a time
  slider, external exposure (Shodan/Censys, needs keys), TLS certificate monitor, asset
  inventory with passive device classes, per-host risk ranking, and **Targets and import**: a
  manual form plus TXT/CSV/JSON import of target lists and of scan results (JSON or the CSV from
  `scanner export`), with a diff against the previous scan. User edits (title, technology, tags,
  note, status) are kept separately and survive re-imports. **RBAC**: 22 permissions, built-in
  roles `admin`, `editor`, `analyst`, `viewer` plus custom roles, audit trail. **Encryption at
  rest**: AES-256-GCM (`ASIE` header) for the console's accounts, roles, settings, cases,
  inventory, TLS state and audit log. The console does not scan the targets typed into the form itself
  (use `scanner`, `scanner schedule` or the trigger, then import the result); a case's "scan"
  action can ask the trigger for a targeted scan when `ASI_TRIGGER_URL` is set. Walkthrough: [`docs/DEMO.md`](docs/DEMO.md).

- **Export** (`scanner export`): CSV (one row per open service, or per trigger finding),
  JSON, nmap XML, and DefectDojo. Selected observations (admin panels, unfinished
  installations, default pages, staging, self-signed or expired certificates, outdated
  components) become informational findings with their evidence, linked to their
  endpoint. A stable `unique_id_from_tool` keeps later runs from creating duplicates:
  they refresh the evidence and leave analysts' decisions, severities and tags alone.

- **AI edge gate** (`cmd/edgegate`, optional): a calibrated Tree+GNB →
  Basal+Laya+Kev cascade that can sit between the sensor and the trigger
  (`edgegate serve`): it scores events, forwards the interesting ones with a
  `score`, and always passes events about services that went silent or closed.
  Without it the sensor talks to the trigger directly. Weights (~2.5 GB) are
  downloaded and SHA256-verified from pinned upstream revisions, not committed.
  The 50% target is calibrated on synthetic data and is not a hard quota.
  See [setup, smoke test and sensor integration](deploy/cascade50/README.md).

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

Leaving out your own infrastructure (model containers, the console, the scanner host):

```bash
./bin/sensor -i 'br-*,!br-edge*,!docker0'                 # do not capture there at all
./bin/sensor -i 'br-*' -exclude-net 172.18.0.0/16,10.0.0.5 # capture, but report nothing about these
./bin/trigger -allow 172.16.0.0/12 -ignore-net 172.18.0.0/16  # never scan these, whoever reports them
```

- In `-i`, `!name` and `!glob` are applied after everything else, in any order, and may
  match nothing. They beat an explicitly listed name.
- `-exclude-net` produces no events about those addresses and adds nothing to the baseline.
  Services that answer an excluded client are still reported: they are not the excluded
  side. Entries already in a baseline from before are kept unchanged, never reported
  silent, and count again when the exclusion is removed. The same holds for networks that
  are no longer captured or not in `-net`.
- Both `-exclude-net` and `-ignore-net` default to `$SOTW_EXCLUDE_NET`. An exclusion that
  leaves nothing to watch or scan is an error at startup.
- The sensor does not ask Docker which networks are yours (that would need access to the
  Docker socket). Give your own compose network a fixed bridge name instead
  (`driver_opts: {com.docker.network.bridge.name: br-edge0}`) and exclude it by glob.

### Scanner

```bash
make build
./bin/scanner -t 10.0.0.0/24 -p 22,80,443,8000-8100 -o scan1.json
./bin/scanner -t 10.0.0.0/24 -p 22,80,443,8000-8100 -o scan2.json
./bin/scanner diff scan1.json scan2.json          # -json, -exit-code
```

Useful flags:

| Flag | Meaning |
|---|---|
| `-f targets.txt`, `-allow 10.0.0.0/16` | targets from a file; refuse targets outside the range |
| `-Pn`, `-sS` | skip host discovery; SYN scan (needs `CAP_NET_RAW`) |
| `-max-rate`, `-parallel` | packets per second per nmap process (300), number of processes (4) |
| `-chunk-time 1m` / `-chunk N` | size chunks by the measured speed to take about this long / fix the size |
| `-version-mode` | `balanced`: short `-sV` waits, then ports left unidentified again with nmap's own; `fast`: no second pass; `full`: plain nmap |
| `-signatures extra.yaml` | custom signatures (format: `internal/fingerprint/signatures/`), also bases imported with `cmd/sigimport` |
| `-probe=false`, `-fingerprint-paths=false` | no HTTP probing; no extra GETs such as `/wp-login.php` |
| `-cve`, `-cve-cache` | map detected product versions to CVEs (below); cache directory, default `var/cve-cache` |

### CVE enrichment (NVD + EPSS)

With `-cve` the scanner turns every detected product *and version* into a CPE
(`internal/vuln`), queries NVD for the matching CVEs and ranks them by **EPSS**
exploitation probability from FIRST, flagging anything on the **CISA KEV** list
of actively exploited vulnerabilities. Each technology in the result then carries
up to five entries like `CVE-2021-42013 — CVSS 9.8, EPSS 0.97, KEV`, so a diff
stops being a list of changes and becomes a ranked risk picture. Lookups are
fail-soft (no network, no enrichment) and cached on disk (NVD 7 days, EPSS/KEV
24 h); `NVD_API_KEY` raises the anonymous NVD quota ~10x. Products and versions
come from the fingerprint detections and from service banners (OpenSSH, Apache,
nginx, IIS, MySQL/MariaDB, Redis, PostgreSQL, …); a detection without a version
is deliberately skipped — a versionless lookup is noise, not intelligence.

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

### Scheduled scans

```bash
mkdir -p results
./bin/scanner schedule -window 22:00-05:00 -tz Europe/Warsaw -every daily@22:00 \
  -checkpoint state.jsonl -out results -f targets.txt -allow 10.0.0.0/16
```

Scans only inside the windows (`mon-fri 22:00-05:00,sat+sun 00:00-24:00`) and as often as
`-every` says (`once`, `24h`, `daily@22:00`, `mon+thu@22:00`). When a window closes, running
nmap processes are stopped and the next window continues with the targets that are left:
each finished chunk, probed and fingerprinted, is already in the checkpoint. Restarting
the same command resumes too. Chunks are sized to finish before the window closes, and the
log shows when the whole run is expected to end. Each completed run becomes
`results/scan-<start>.json` with its sessions, chunk durations and the reason for each
chunk size. All flags of a plain scan apply except `-cve`; changing the targets or what is scanned
starts over, changing speed limits does not.

### Sensor + trigger

```bash
./bin/trigger -allow 10.0.0.0/16 -state trigger-state      # listens on 127.0.0.1:8099
./bin/sensor -i eth0 -webhook http://127.0.0.1:8099/events
tail -f trigger-state/findings.jsonl
```

Set the same `SOTW_WEBHOOK_TOKEN` for both to require a bearer token. `GET /healthz`
shows pending and running scans and why events were dropped. Policy flags: `-debounce`,
`-ignore-net`, `-quiet`, `-cooldown`, `-closed-cooldown`, `-max-per-minute`, `-top-ports`,
`-parallel` (default 2). `-findings-url http://console:18081/findings` also ships every finding to the
operator console (token: `-findings-token` or `$ASI_CENTRAL_TOKEN`).

### Operator console

```bash
make console
ASI_ADMIN_LOGIN=admin ASI_ADMIN_PASSWORD=<password> ASI_CENTRAL_TOKEN=<token> \
  ./bin/console -demo -listen 127.0.0.1:18081 -data-dir var/console
```

`-demo` seeds a synthetic fleet (137 sensors, 217 cases) so every tab has something to show;
without it the console starts empty. Sensors, the trigger and the edge gate deliver to
`POST /logs`, `/findings` and `/events` with `Authorization: Bearer $ASI_CENTRAL_TOKEN` (401
without it). The first account comes from `ASI_ADMIN_LOGIN`/`ASI_ADMIN_PASSWORD`; add a read-only
account with `ASI_VIEWER_LOGIN`/`ASI_VIEWER_PASSWORD` and close self-registration with
`ASI_ALLOW_REGISTRATION=false`. The data key comes from `ASI_DATA_KEY` or `ASI_DATA_KEY_FILE`, or is
generated in `<data-dir>/data.key` (0600) on first start; losing it makes the data unreadable.

### Docker images

```bash
docker run --rm --network host --cap-drop ALL --cap-add NET_RAW \
  -v sotw-data:/data ghcr.io/inner-savages/silence-on-the-wire/sensor -i eth0
docker run --rm --network host --user $(id -u):$(id -g) -v "$PWD:/data" \
  ghcr.io/inner-savages/silence-on-the-wire/scanner -t 127.0.0.1 -Pn -o scan.json
docker run --rm ghcr.io/inner-savages/silence-on-the-wire/traffic \
  -targets "http://example.internal/ tcp://example.internal:22"
```

Images (`sensor`, `scanner`, `trigger`, `traffic` and `console`) are built by GitHub Actions for
`linux/amd64` and `linux/arm64`. All of them run
as an unprivileged user; the sensor needs only `CAP_NET_RAW`, the scanner and the trigger
none (connect scan). `--user $(id -u):$(id -g)` makes result files belong to you (they are created
with mode 0600). `make images` builds the first four locally under the same names; the `console`
image (Dockerfile target `console`) comes from CI and is used by `deploy/demo/`.

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
[`lab/agh/README.md`](lab/agh/README.md). Their own demo works with the scanner too:

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

## Blog

The build process is documented (Polish and English) on
[q84fh.net](https://q84fh.net/tags/hacknation2026/).

## License

[MIT](LICENSE), except third-party material: [`models/`](models/README.md) (Apache-2.0)
and [`lab/agh/upstream/`](lab/agh/README.md) (lab templates by CBI AGH, all rights remain
with their authors).
