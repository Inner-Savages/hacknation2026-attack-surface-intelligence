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
- Escalations are forwarded as the original event plus `score`, `reason` and
  `event_id`; they pass through the durable outbox and are deleted only after the
  trigger answers 2xx, so a trigger restart loses nothing.
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
