#!/bin/bash
# Test sensora pasywnego na żywo w labie, z powtarzalnym harmonogramem.
#
#   make sensor-caps                       # raz: build + CAP_NET_RAW
#   lab/scripts/sensor-live-test.sh out/   # ok. 2 minuty
#
# Wynik w <outdir>: events.jsonl (zdarzenia), sensor.log, actions.log (co i kiedy
# zrobił skrypt), state.json (baseline). Na koniec flapper wraca do 300 s.
set -euo pipefail

OUT=$(realpath "${1:?użycie: $0 <outdir>}")
cd "$(dirname "$0")/../.."
mkdir -p "$OUT"
COMPOSE="docker compose -f lab/docker-compose.yml"
A=$OUT/actions.log
: > "$A"
act() { echo "$(date +%T) $*" | tee -a "$A"; }

rm -f "$OUT/state.json"
act "prep: świeży web-plain, flapper 35 s up / 35 s down"
$COMPOSE up -d --force-recreate web-plain >/dev/null 2>&1
FLAP_UP=35 FLAP_DOWN=35 $COMPOSE up -d flapper >/dev/null 2>&1
sleep 3

act "terminal 1: start sensora (nauka 15 s, cisza po 30 s)"
timeout -s INT 105 ./bin/sensor -i br-asilab -state "$OUT/state.json" \
  -learn 15s -silent-after 30s -sweep 5s > "$OUT/events.jsonl" 2> "$OUT/sensor.log" &
SENSOR=$!
sleep 19

act "krok 1: nowy host 172.28.0.30"
docker run -d --rm --name asi-newhost --network asi-lab_lab --ip 172.28.0.30 nginx:alpine >/dev/null
sleep 3

act "krok 2: curl http://172.28.0.30/"
curl -s -o /dev/null http://172.28.0.30/
sleep 5

act "krok 3: web-plain przestaje podawać wersję nginxa"
docker exec asi-lab-web-plain-1 sh -c \
  "echo 'server_tokens off;' > /etc/nginx/conf.d/tokens.conf && nginx -s reload" 2>/dev/null
sleep 12

act "krok 4: docker stop asi-newhost"
docker stop asi-newhost >/dev/null

wait "$SENSOR" || true
act "sensor zatrzymany"
$COMPOSE up -d flapper >/dev/null 2>&1
