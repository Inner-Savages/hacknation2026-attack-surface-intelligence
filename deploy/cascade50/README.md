# ASI edge cascade, 50% calibration target

This package adds a Go edge gate alongside the existing sensor. It includes the
calibrated Decision Tree and Gaussian Naive Bayes, the three real neural model
checkpoints, tokenizers, runtime dependency locks, Docker builds, and a durable
integration inbox. The sensor and scanner remain independent programs.

```text
sensor -> append-only JSONL -> Go Tree + GNB rank mean
                                   | escalate immediately
                                   | otherwise
                              Basal + Laya + Kev over HTTP
                                   | rank maximum
                              durable outbox -> central HTTP endpoint
```

The included `receive` command stores escalations for inspection. **It is an
integration inbox, not a central analytical AI model.** An analytical service can
consume this inbox or implement the same HTTP acknowledgement contract.

## Start from a clean checkout

Install Docker with Compose v2 and Git LFS. Reserve about 12 GB of Docker memory
and 15 GB of free disk for the weights, images, and build cache. CPU inference is
the default; the smoke run was tested on Linux ARM64 via Docker Desktop.

```sh
git lfs install
git clone https://github.com/Inner-Savages/silence-on-the-wire.git
cd silence-on-the-wire
# Until merged, check out the PR branch before pulling its weights:
git switch codex/cascade50-edge-gate
git lfs pull
make cascade50-up
make cascade50-smoke
```

The weights are actual Git LFS objects attached to this branch, about 2.49 GB in
total. Downloading a source ZIP without LFS objects is insufficient. `up` builds
the Go container and verifies every artifact's size and SHA256 before starting
the model servers; a missing file or LFS pointer produces an actionable error.
The first build needs internet access for base images and pinned packages. Model
loading uses local read-only files with Hugging Face offline mode enabled.

`up` starts Basal, Laya, Kev and the integration inbox, then tests actual
`/v1/systemone` responses and calibrated model identities. `smoke` runs ten
synthetic events through real inference and checks that every escalation was
acknowledged. Decisions are saved to `var/cascade50/smoke-decisions.jsonl`.
Model APIs are published only on loopback: Basal 18000, Laya 18001, Kev 18008;
the inbox is at `http://127.0.0.1:18080/events`.

```sh
docker compose -f deploy/cascade50/compose.yaml logs --tail=100
docker compose -f deploy/cascade50/compose.yaml exec central sh -c 'ls /data/inbox'
make cascade50-down
```

Stopping the stack preserves both named volumes, including pending escalations
and accepted envelopes. Do not remove the volumes until their contents have been
processed or archived.

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
