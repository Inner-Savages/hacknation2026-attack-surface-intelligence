#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."
dc() { docker compose -f deploy/cascade50/compose.yaml "$@"; }
mkdir -p var/cascade50
touch var/cascade50/events.jsonl
case "${1:-}" in
  models)
    dc build central
    dc run --rm --no-deps -T --user "$(id -u):$(id -g)" models
    ;;
  up)
    dc build central
    dc run --rm --no-deps -T --user "$(id -u):$(id -g)" models
    dc run --rm --no-deps -T gate verify-models
    dc up -d --build basal laya kev central
    attempt=0
    until dc run --rm --no-deps -T gate check-models \
      -basal-url http://basal:8000/v1/systemone \
      -laya-url http://laya:8000/v1/systemone \
      -kev-url http://kev:8000/v1/systemone \
      -model-timeout 30s >var/cascade50/readiness.log 2>&1; do
      attempt=$((attempt + 1))
      if [ "$attempt" -ge 30 ]; then cat var/cascade50/readiness.log >&2; exit 1; fi
      sleep 2
    done
    cat var/cascade50/readiness.log
    ;;
  smoke)
    dc run --rm --no-deps -T gate gate -sensor-id cascade50-smoke \
      -input deploy/cascade50/smoke.jsonl -outbox-dir /data/smoke-outbox \
      -central-url http://central:8080/events \
      -basal-url http://basal:8000/v1/systemone \
      -laya-url http://laya:8000/v1/systemone \
      -kev-url http://kev:8000/v1/systemone >var/cascade50/smoke-decisions.jsonl
    test "$(wc -l <var/cascade50/smoke-decisions.jsonl | tr -d ' ')" = 10
    if grep -q '"unresolved":true' var/cascade50/smoke-decisions.jsonl; then
      echo 'Model failures occurred; inspect var/cascade50/smoke-decisions.jsonl' >&2; exit 1
    fi
    # Fail the smoke run if central did not durably acknowledge every item.
    dc run --rm --no-deps -T --entrypoint sh gate -c 'test -z "$(ls /data/smoke-outbox/*.json 2>/dev/null)"'
    echo 'PASS: 10 events, real model inference, no unresolved decisions, all escalations acknowledged.'
    ;;
  gate)
    dc run --rm --no-deps -T gate
    ;;
  serve)
    dc --profile serve up -d --build serve
    echo 'gate listening on 127.0.0.1:8098; point the sensor webhook there (it forwards to the trigger on 8099)'
    ;;
  replay)
    dc run --rm --no-deps -T gate replay -outbox-dir /data/outbox -central-url http://central:8080/events
    ;;
  *) echo "usage: $0 {models|up|smoke|serve|gate|replay}" >&2; exit 2 ;;
esac
