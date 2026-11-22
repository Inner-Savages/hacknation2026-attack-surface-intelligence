# ASI edge cascade, 50% calibration target

This package adds a Go edge gate alongside the existing sensor. It includes the
calibrated Decision Tree and Gaussian Naive Bayes, the three real neural model
checkpoints, tokenizers, runtime dependency locks, Docker builds, the operator
web console, and a durable integration inbox. The sensor and scanner remain
independent programs.

```text
sensor -> append-only JSONL -> Go Tree + GNB rank mean
                                   | escalate immediately
                                   | otherwise
                              Basal + Laya + Kev over HTTP
                                   | rank maximum
                              durable outbox -> operator console
                              (fleet view, case workflow, actions)
```

The default pipeline delivers escalations to the **operator console**
(`cmd/console`), where a human verifies cases from the whole sensor fleet. The
included `receive` command remains available as a minimal integration inbox for
external analytics endpoints — it is not a central analytical AI model. Any
service implementing the same HTTP acknowledgement contract can take the
console's place.

## Start from a clean checkout

Install Docker with Compose v2. Reserve about 12 GB of Docker memory
and 15 GB of free disk for the weights, images, and build cache. CPU inference is
the default; the smoke run was tested on Linux ARM64 via Docker Desktop.

```sh
git clone https://github.com/Inner-Savages/silence-on-the-wire.git
cd silence-on-the-wire
make cascade50-up
make cascade50-smoke
```

The weights (about 2.5 GB) are not in the repository. `up` first runs
`fetch-models`, which downloads every artifact listed in `models/manifest.json`
from its pinned Hugging Face revision, checks its size and SHA256, and skips
files that already match; then it verifies everything again before starting the
model servers. `make cascade50-models` does only the download.
The first build needs internet access for base images and pinned packages. Model
loading uses local read-only files with Hugging Face offline mode enabled.

`up` starts Basal, Laya, Kev and the operator console, then tests actual
`/v1/systemone` responses and calibrated model identities, and waits for the
console's health endpoint. `smoke` runs ten synthetic events through real
inference and checks that every escalation was durably acknowledged by the
console. Decisions are saved to `var/cascade50/smoke-decisions.jsonl`.
Model APIs are published only on loopback: Basal 18000, Laya 18001, Kev 18008;
the console is at `http://127.0.0.1:18081` (intake `POST /events`).

For the full system in one command — models, the gate following the sensor
output, and escalations landing in the console — run:

```sh
make cascade50-demo   # then watch http://127.0.0.1:18081
```

```sh
docker compose -f deploy/cascade50/compose.yaml logs --tail=100
make cascade50-down
```

Stopping the stack preserves all named volumes, including pending escalations,
accepted envelopes and console cases. Do not remove the volumes until their
contents have been processed or archived.

## Between the sensor and the trigger (optional stage)

`edgegate serve` puts the cascade in the event path of the main project without
changing either side:

```text
sensor --webhook--> edgegate serve :8098 --POST /events--> trigger :8099 --> scan
sensor --webhook----------------------------------------> trigger :8099      (no AI, default)
```

Both hops use the sensor's event format (`POST /events` with a JSON array, bearer
token from `$SOTW_WEBHOOK_TOKEN`), so switching is configuration only: point the
sensor's `-webhook` at `http://127.0.0.1:8098/events` to use the gate, or at the
trigger to skip it.

- Events are scored in arrival order (the feature extractor keeps per-host state).
- **Bounded memory at fleet scale.** The extractor's per-host state is kept on a
  TTL (`-host-ttl`, default 24h in `serve`): a host silent for longer than the
  window — measured in stream time, so replays stay deterministic — is evicted
  and relearned from scratch when it returns. A sensor watching 10k+ IPs stays
  flat instead of growing without limit. Per-host port sets are capped too.
  `/healthz` reports `hosts_tracked` and `hosts_evicted`.
- **Restarts keep the baseline.** The host table is checkpointed to
  `-state-file` every `-state-save-interval` (default 5 min) and once more on
  shutdown, then restored on boot (atomically, via tmp+rename; a corrupt file
  is ignored, never fatal). Hosts already stale at save time are skipped on
  load, exactly as the TTL sweep would have dropped them.
- Escalations are forwarded as the original event plus `score`, `reason` and
  `event_id`; they pass through the durable outbox and are deleted only after
  the trigger answers 2xx, so a trigger restart loses nothing.
- `host_silent`, `service_silent` and `service_closed` are always forwarded
  (`reason: verification_passthrough`): a model must not hide a service that
  disappeared.
- A full queue answers 503 for the whole batch; the sensor retries it.

```sh
make cascade50-up      # models + Basal, Laya, Kev
make cascade50-serve   # gate on 127.0.0.1:8098 -> trigger on 127.0.0.1:8099
sensor -i 'br-*' -webhook http://127.0.0.1:8098/events
```

## Run the decisions inbox on an external host

If the central analytics endpoint cannot host the inbox itself, run the
bundled receiver as a standalone container anywhere reachable and point the
gate at it. The receiver is the same hardened `edgegate` image; it keeps
escalations durable on its own volume until an analytics service consumes
them, and it needs no model weights.

```sh
docker build -f deploy/cascade50/Dockerfile.edgegate -t asi-edgegate:cascade50 .
docker run -d --name asi-inbox --read-only --tmpfs /tmp \
  -e ASI_CENTRAL_TOKEN=choose-a-long-random-token \
  -v asi-inbox-data:/data \
  asi-edgegate:cascade50 receive -listen 0.0.0.0:8080 -inbox-dir /data/inbox
```

The receiver speaks plain HTTP, which is fine for the local Compose network.
Before exposing it beyond loopback, put it behind a TLS proxy (Caddy, nginx,
a cloud load balancer). The gate refuses a non-HTTPS remote central URL on
purpose, so the proxy is not optional on a real network. Any gate can then
deliver decisions to it:

```sh
export ASI_CENTRAL_TOKEN=choose-a-long-random-token
./bin/edgegate gate -sensor-id site-a \
  -policy deploy/cascade50/policy.json \
  -input var/cascade50/events.jsonl -follow \
  -outbox-dir var/cascade50/outbox \
  -central-url https://inbox.example.org/events
```

The acknowledgement contract is intentionally tiny — `POST /events` with a
bearer token, `202` only after a durable write, deduplication by `event_id` —
so a later operator console or analytics platform can replace the bundled
receiver without touching the gate.

## Connect the unchanged sensor and lab

Run live capture on a Linux machine that can see the monitored interfaces. Docker
Desktop's VM cannot capture the macOS host's physical interfaces. Use the existing
[lab instructions](../../lab/README.md) or [AGH lab](../../lab/agh/README.md).
For the repository's default lab:

```sh
make lab-up
make sensor-caps
mkdir -p var/cascade50
./bin/sensor -i br-asilab -net 172.28.0.0/24 -learn 30s \
  -state var/cascade50/sensor-state.json \
  >>var/cascade50/events.jsonl 2>>var/cascade50/sensor.log
```

In another terminal, after `make cascade50-up`:

```sh
./deploy/cascade50/run.sh gate >var/cascade50/decisions.jsonl
```

The sensor writes its own file, so an unavailable model or slow inference cannot
block capture through a shell pipe. The gate follows complete lines from the
beginning. It processes all events to retain causal host history. It rejects file
rotation/truncation when detected at EOF; keep the input append-only for a run.
There is currently no persistent input cursor: restarting replays history and can
repeat HTTP inference and delivery. Large backlogs must be monitored operationally.

Build only the host Go gate, without libpcap, with `make edgegate`. Example:

```sh
./bin/edgegate verify-models
./bin/edgegate gate -sensor-id site-a \
  -policy deploy/cascade50/policy.json \
  -input var/cascade50/events.jsonl -follow \
  -outbox-dir var/cascade50/outbox \
  -central-url http://127.0.0.1:18080/events
./bin/edgegate replay -outbox-dir var/cascade50/outbox \
  -central-url http://127.0.0.1:18080/events
```

The scanner remains available through `make build` and its existing README/CLI.
This gate does not automatically launch active scans.

## Delivery and safety behavior

- Early Tree+GNB escalation cannot be vetoed by a later model. Otherwise all three
  HTTP models run concurrently, with a six-second timeout each by default.
- Missing/invalid scores, HTTP errors, wrong model identities, Laya routing
  changes, truncation, abstention, or review requests force escalation with
  `unresolved:true`. Invalid input is retained as `raw_event` and escalated too.
- 50% is a **soft validation target**, never a hard admission quota. Failures may
  forward 100% of events. No queue entry is dropped to preserve a quota.
- Forwarded envelopes are fsynced to a per-event file before stdout or HTTP.
  Only a central 2xx removes the pending file. A failed delivery stays pending;
  run `replay` after recovery (or schedule it externally). There is no background
  retry daemon in this version.
- Delivery is at least once. The central service must persist before returning
  2xx and deduplicate by `event_id`. IDs hash the sensor ID and exact input line;
  byte-identical repeated lines share an ID. Use a unique stable ID per sensor.
- HTTPS is required for a remote central endpoint. Plain HTTP is allowed only
  on loopback and the local Compose service `central`. Optional bearer tokens:
  `ASI_CENTRAL_TOKEN`, `ASI_BASAL_TOKEN`, `ASI_LAYA_TOKEN`, `ASI_KEV_TOKEN`.
  Pass tokens explicitly into containers when using authenticated services.
- The calibrated risk baseline is frozen. It does not learn from repetition,
  predictions, or test labels. It is separate from the sensor's inventory
  baseline. Future updates require approved external feedback and recalibration.
- `host_silent` describes lack of observed traffic; it does not establish that a
  host is inactive or compromised.

## Operator console for the escalation fleet

`cmd/console` is the human verification layer above the inbox: a durable case
store plus a web UI where an operator triages escalations from the whole
sensor fleet. It accepts the same delivery contract as the bundled receiver
(`POST /events`, bearer token, `202` after durable write, deduplication by
`event_id`), so the gate can deliver to it directly.

```sh
make console-up                 # demo fleet of 137 sensors on 127.0.0.1:18081
# or point a real gate at it:
./bin/edgegate gate -sensor-id site-a ... -central-url http://127.0.0.1:18081/events
```

The console is designed for **hundreds of edge sensors**: a fleet view with
online/offline health, per-sensor alert counts and last contact, plus search
and pagination; the alerts view filters by sensor, status, event type and
free text. Sensor liveness comes from incoming escalations (a sensor silent
longer than `-offline-ttl` is marked offline); the demo mode simulates
heartbeats so the fleet stays realistically mixed.

The operator workflow mirrors the escalation envelope:

- **Verification**: set a status (do weryfikacji / potwierdzony / fałszywy
  alarm / zamknięty), assign an owner, add case notes; every change lands in
  an append-only audit log and in the case history.
- **Evidence**: the full `cascadeEnvelope` — event, 28 features, per-model
  scores with latencies, model errors, baseline anomaly, policy digest. The
  UI states plainly that scores are a verification hint, not a verdict.
- **Actions**: reinforce observation, order an active scan, rerun model
  analysis, and isolate the host. Isolation is **two-step and always
  human-confirmed**; a cut-off host can be restored to the network with the
  single-step, audited *przywróć do sieci* action. In demo mode actions are
  recorded in the audit trail but never touch traffic, exactly as the
  banner says.

The UI ships light and dark themes (light is the default) and is embedded in
the binary — no build step, no JavaScript dependencies. Run it in Docker as
the `console` service (port `127.0.0.1:18081`) with its own `console-data`
volume; like the inbox, put it behind a TLS proxy and set `ASI_CENTRAL_TOKEN`
before exposing it beyond loopback.

### Live feed and AI-assisted triage

The dashboard's **Logi live** tab streams everything the console sees:

- raw sensor log lines, shipped to `POST /logs` in the passive sensor's own
  NDJSON shape (`{"time","type","ip","port","proto","source"}`; one object, a
  JSON array or NDJSON, bearer token, sensor id via `X-Sensor-Id`, `?sensor=`
  or the `source` field). A sensor that ships logs is marked alive in the
  fleet view;
- console events mirrored from the audit log — new alerts, status changes,
  assignments, notes, operator actions and AI analyses.

The UI polls `GET /api/logs?since=<seq>` and renders the tail; the feed
itself is a bounded in-memory ring (1000 entries), so it costs nothing when
nobody watches.

For triage support the console can ask an LLM to read the escalation
envelope and the recent logs of the affected sensor. It speaks the
**OpenAI-compatible chat-completions API**, so the provider is a deployment
choice, not code: set `ASI_AI_API_KEY` (OpenAI by default) or point
`ASI_AI_BASE_URL` at any compatible endpoint — including a local model
served by Ollama, llama.cpp, vLLM or LM Studio, with no API key needed.
`ASI_AI_MODEL` picks the model (default `gpt-4o-mini`). As AI moves on, a
newer, smaller or more energy-efficient model is a configuration change,
exactly like the `/v1/systemone` backends.

Analyses run on demand (`POST /api/alerts/{id}/analysis`, the "Analiza AI"
button in the case view) and automatically for every new escalation when a
provider is configured (`-ai-auto`, on by default). Each analysis is stored
as a case note and a history entry under the actor `AI · <model>` — advisory
only; every executable decision stays with the human operator.

### Accounts, configuration and the AI operator mode

The console has its own operator accounts: the first registered account
becomes the administrator, passwords are stored locally as
PBKDF2-HMAC-SHA256 (no external identity dependency), and sessions are
HttpOnly cookies. All operator APIs require a session; the machine intake
(`POST /events`, `POST /logs`) keeps its bearer-token contract.

The **Ustawienia** tab (admin) persists runtime configuration in
`settings.json` and mirrors every change into the live feed:

- **Demo/live switch** — turns the synthetic demo feed off; from then on the
  dashboard shows only real events captured by the edge sensors. The banner
  flips to "LIVE · tylko edge".
- **AI provider** — base URL, model and API key are editable from the UI
  (the key is write-only and never returned to the browser), so a local
  model is a two-field change: address `http://<host>:11434/v1`, no key.
- **AI operator mode** (`-ai-operator` / `ASI_AI_OPERATOR` or the toggle):
  the configured LLM orchestrates the platform as an autonomous operator.
  For every escalation it returns a structured verdict (threat level,
  confidence, status, justification, action) and the console executes it
  through the *same* audited mutations a human uses — statuses, notes,
  observation, active scans and re-analysis all land in the case history,
  the audit log and the live feed under the actor `AI · <model> (operator)`.
  The one exception is host isolation: the AI may only **arm** it. A human
  must confirm, so the most destructive action always keeps a person in the
  loop.

### Rule mode: deterministic triage without the model stack

When the decision models digest too slowly (the Bayesian stage, the decision
tree, the basal/laya/kev backends or the LLM operator all stall behind rate
limits or heavy hardware), the console can drop to **hard rules** from the
**Reguły** tab. With rule mode enabled every new escalation is triaged
instantly against an ordered rule list — offline, with no model calls at
all:

- Rules are edited in the dashboard (admin) and persisted in `rules.json`.
  Conditions: event types, ports, source host or CIDR, sensor, escalation
  reasons, minimum score, unresolved flag. Empty conditions match
  everything; the first matching rule wins.
- Outcomes: set status, assign, attach a justification note, and run a
  non-destructive action (observe, scan, re-analyze). Isolation follows the
  same rule as everywhere else in the console — a rule may only **arm** it;
  a human confirms.
- Every rule decision is recorded through the same audited mutation as a
  human or the AI operator, under the actor `silnik reguł · <nazwa>`, and
  lands in the case history and the live feed (kind `REGUŁA`).
- Switching rule mode on immediately re-triages the open backlog
  (synchronously — the engine needs no provider round-trips), and the
  **Zastosuj do otwartych spraw** button re-runs the rules on demand, e.g.
  right after editing the list. Switching it off returns triage to the
  model stack.

### Ground truth: periodic control scans of silent hosts

A host that stops speaking is indistinguishable from a host that is off —
the passive feed alone cannot resolve the `silent_stealth` scenario, so
without active ground truth that observability gap stays invisible. The
console therefore keeps a durable **registry of passive observations** per
host (`hosts.json`: services seen, last event, when the silence began) and
runs **control scans** of the longest-silent hosts:

- The scan is gentle and bounded: TCP connects to the host's known ports
  plus a small common set (22, 80, 443, 445, 3306, 3389, 5432, 6379, 8080,
  8443, 9200), a short banner read, nothing sent. Full-coverage port scans
  remain the scanner's job; control scans only verify what the passive view
  cannot.
- The first scan of a host establishes the **ground-truth baseline** (open
  ports and banners). Every later scan diffs against it: a new service, a
  changed banner or a vanished one while the host is passively silent
  escalates as a `ground_truth_change` case — an ordinary case, so the rule
  engine and the AI operator triage it like any other alert. A verified
  quiet host and an unreachable one are recorded as feed notes. Each drift
  escalates once and then becomes the new baseline.
- The policy lives in **Ustawienia → Skany kontrolne** (admin): enable/disable,
  interval (default 6 h), the silence threshold that qualifies a host
  (default 1 h) and the sample size per run (default 50 longest-silent
  hosts). **Uruchom teraz** triggers a scan on demand; every run, verdict
  and policy change is mirrored to the live feed, and the registry persists
  across restarts. `GET /api/groundtruth` reports the policy, registry size
  and the last run's summary.
- **CVE enrichment**: banners captured by the control scan already name
  products and versions (OpenSSH, Apache, nginx, MySQL, Redis, …), so each
  escalation is looked up in NVD and ranked by EPSS, with CISA KEV flagged —
  the case says *"this instance has CVE-2021-42013 with EPSS 0.97, actively
  exploited"* instead of just *"something changed"*. The toggle lives in
  **Ustawienia → Skany kontrolne** (default on), results are cached on disk,
  and `NVD_API_KEY` raises the query quota. Lookup failures degrade to a
  plain case, never to a failed scan.

### Attack-surface map (topology + timeline)

The alert list answers "what happened"; the **Mapa** tab answers "what does
my network look like and how is it drifting". The same passive registry
that feeds ground truth now also keeps a durable **topology journal**: every
state transition the sensor reports (host appeared, host went silent, host
came back, service appeared, service went quiet) plus every control-scan
verdict is appended with the sensor's own timestamp and persisted in
`hosts.json` (bounded: 5000 events / 30 days, oldest first out).

- The graph groups hosts by `/24` and draws services as port chips on each
  host; colors carry the state at the selected moment — active, passively
  silent, changed under silence (control-scan finding), unreachable.
- The **timeline scrubber** replays the journal: dragging it (or pressing
  *Odtwórz*) rebuilds the network state at any moment, so a drift becomes
  visible as it happened — what appeared, what changed, what vanished.
  *Na żywo* jumps back to the live edge.
- Clicking a host shows its state at the selected moment, sensor, first
  and last contact, the latest scan verdict and its own event history.
- `GET /api/map` returns the current per-host records plus the journal,
  with optional `from`/`to` (RFC3339) bounds on the timeline.

### Inside/outside correlation (Shodan/Censys)

The sensor sees the network from within; internet-wide scanners see what of
it faces the world. Neither view alone answers "is anything exposed that
should not be" — the **Ekspozycja** tab diffs the two, which is where
shadow IT and accidental exposures live:

- The engine pulls the outside view of the public IP (Shodan, or Censys v2;
  the IP is auto-detected or pinned in settings) on a schedule (default
  6 h) and on demand, and diffs it against the passive registry. The first
  run establishes the external baseline; escalations start with the first
  diff, so enabling the feature does not flood the backlog.
- Findings: **unmatched_external** (the internet sees a service no
  internal host reports — shadow-IT candidate, score 0.9),
  **exposed_internal** (`service_new` inside that is simultaneously
  visible from the internet — the sharpest alert, 0.95), **new_external**
  (appeared on the public IP since the last check, 0.85) and
  **gone_external** (good news, reported not escalated). Escalations are
  ordinary cases, and new exposures also land on the map's topology
  timeline.
- **Favicon cross-match**: Shodan reports favicon hashes as mmh3 — the
  exact format the internal scanner computes (`internal/probe/mmh3.go`) —
  so for every external HTTP service the engine asks "where else is this
  favicon visible" and flags the same app exposed on other public IPs.
- Configuration in **Ustawienia → Ekspozycja** (admin): provider, API key
  (write-only; `SHODAN_API_KEY` or `CENSYS_API_ID` + `CENSYS_API_SECRET`
  work as env fallbacks), optional public-IP override, interval. Default
  OFF — the feature queries an external API, so it is opt-in. `GET
  /api/exposure` reports the view and findings; `POST /api/exposure/run`
  triggers a check. Everything is fail-soft: no key or no network is a
  feed note, never a failed run.

### TLS certificate monitoring

The control scans already touch TLS ports, so they now also complete a
plain handshake and record the peer certificate (subject, issuer, SANs,
validity, fingerprint, negotiated version and cipher — with
`InsecureSkipVerify` on purpose: a verifying handshake would refuse
expired and self-signed certs before they could be seen). The **TLS** tab
ages those records into findings — the cheapest high-quality alert in
attack-surface management:

- **Expiring certificates** at 30/14/7-day thresholds (warn/high/critical)
  and **expired** ones. Escalation tightens 30 → 14 → 7: each threshold
  crossing raises one case; a renewed certificate has a new fingerprint
  and starts its own lifecycle.
- **Self-signed certificates** — fine for a NAS, worth a look on anything
  claiming to be a production service.
- **CA changes**: the issuer is compared against the previous observation
  for the same host:port — a silent CA swap is a classic
  interception/misconfiguration signal.
- **Weak cryptography**: TLS older than 1.2, RC4, 3DES, CBC suites, RSA
  key exchange without forward secrecy, NULL ciphers.

Findings land in the inventory (`tls.json`, durable), escalate as ordinary
cases (type `tls`, deduplicated per host/port/cert/kind), and appear on
the map's topology timeline. `GET /api/tls` reports the inventory, `POST
/api/tls/run` triggers a pass; the toggle and interval live in
**Ustawienia → Skany kontrolne** (default ON — pure arithmetic over data
the console already holds, no external calls). The rules themselves live
in `internal/tlspolicy`, so the scanner can evaluate the same policy over
its own probe results.


On first run the engine seeds a starter list so it is useful out of the
box. It ports the heuristics the edge bakes into its feature extractor
(`internal/edge/aiml/model.go` — the `risky_port` and `management_port`
classifications) and covers the gate's fail-open escalation path:

1. **Fail-open — niekompletny sygnał modeli** (unresolved escalations →
   status *do weryfikacji* + wzmocniona obserwacja).
2. **C2/backdoor — porty 4444, 1337, 6667** (uzbraja odcięcie — potwierdza
   człowiek).
3. **Zarządzanie wystawione — Telnet/RDP/VNC/WinRM/Docker** (23, 3389,
   5900, 5985, 2375 → skan + weryfikacja).
4. **Wysoka ocena modeli ≥ 0.9** (skan + priorytetowa weryfikacja).
5. **Porty ryzykowne przy ocenie ≥ 0.6 — FTP/SSH/SMB/proxy** (21, 22, 445,
   8080, 8443, 8888 → weryfikacja).
6. **Nowy host w sieci** (wzmocniona obserwacja).

The seeded list is persisted like any operator edit and is never
re-seeded over your changes.

Rule mode and the AI operator are complementary: rules are the guaranteed,
instant fallback path; the models add judgement when latency allows it.

## Model interchange and the System One standard

All three neural backends speak one vendor-neutral wire protocol,
`POST /v1/systemone`. The gate sends a structured state (event, extracted
features, baseline anomaly) plus a yes/no question with explicit criteria,
and expects a probability (`answers.attack.noul` in `[0,1]`), the serving
model's identity and no truncated questions. The sensor, gate and comparator
never link against any model runtime: a backend can be a Python server, a
llama.cpp container or a future vendor appliance, as long as it honours the
contract.

This is what keeps the stack replaceable as AI moves on. Newer, smaller or
more energy- and compute-efficient models can be swapped in per stage:

1. Serve the new weights behind the same `/v1/systemone` contract — a thin
   adapter container is usually enough.
2. Update the expected model identity in `deploy/cascade50/policy.json`. The
   gate pins and verifies the reported identity on every response, so a
   silent model or routing change fails closed into escalation instead of
   changing behaviour unnoticed.
3. Recalibrate and re-evaluate the thresholds — probabilities from different
   models are not assumed to be interchangeable — then pin the new artifact
   hashes in [models/manifest.json](../../models/manifest.json).

The same applies to the fast Go stage: the Tree/GNB pair is exported
parameters, not embedded code, so a refreshed calibration ships as policy
data. There is no model-vendor lock-in anywhere in the decision path.

## Calibration and reproducibility

The bundled policy contains Go model parameters, five weighted validation ECDFs,
a frozen benign-training baseline, exact thresholds, and source/data digests.
The fast threshold is `0.5152814464395828`; the residual rank-max threshold is
`0.8998301933678775`. Probabilities from different models are not assumed to be
interchangeable. Runtime package versions are locked; model revisions and hashes
are listed in [models/manifest.json](../../models/manifest.json).

The original experiment used 280,000 synthetic events, with real model inference
on 1,670 selected observations. There were zero false negatives in that selected
cohort, including its synthetic shift split. Weighted escalation was 49.97% on
validation, 46.16% on test, and 45.67% on shift. These are screening results,
**not evidence of effectiveness on real attacks**, and the 50% target is not
guaranteed on another distribution. The expensive stage still processed about
71% of weighted events. No latency or accuracy guarantee is implied.

`go test ./cmd/edgegate ./internal/edge/...` runs fault, durability, API and
recorded-inference parity tests without weights or external services. The small
fixture contains complete histories for two hosts and the exact recorded model
requests/responses. Labels are absent from runtime and portable fixtures.
An optional larger parity test uses the separately retained original experiment:

```sh
ASI_CASCADE_EXPERIMENT=/path/to/asi-go-ml/experiments/real-models-20261121 \
  go test -run TestCascadeFullStreamParityWithRecordedInference -v ./cmd/edgegate
```

This optional test requires the original sibling `data` directory. It reconstructs
120,000 source events, checks 1,670 cohort decisions and 2,943 recorded HTTP calls.
It does not perform fresh inference. The runtime does not require that dataset,
benchmark cache, Python on the host, or any path from the original developer's
machine. Source digests in the policy identify the original calibration code;
the port is verified through parity tests. Changing features, prompts, weights or
model variants requires a new calibration and evaluation.
