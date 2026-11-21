#!/bin/bash
# Scenariusz dla sensora pasywnego na stacku custom-network z szablonów CBI AGH.
# Rozszerza ich quickstart (usługa znika i wraca) o nowy host, zmianę bannera
# i niestabilny host, a przy każdym kroku wypisuje, jakiego zdarzenia się
# spodziewać.
#
#   lab/agh/scenario.sh <AGH>/docker-compose-custom-network.yml
#
# Obrazy silence-on-the-wire/{sensor,traffic} muszą być dostępne (rejestr albo `make images`).
# Na koniec stack zostaje uruchomiony; zatrzymanie:
#   docker compose -f <AGH>/docker-compose-custom-network.yml -f lab/agh/traffic-custom-network.yml down
set -euo pipefail

AGH=$(realpath "${1:?użycie: $0 <AGH>/docker-compose-custom-network.yml}")
OVERLAY=$(realpath "$(dirname "$0")/traffic-custom-network.yml")
C=(docker compose -f "$AGH" -f "$OVERLAY")
NET=hacknation-custom-network_backend
TRAFFIC_IMAGE="${SOTW_IMAGE_PREFIX:-ghcr.io/inner-savages/silence-on-the-wire}/traffic:${SOTW_TAG:-latest}"

LEARN_WAIT=${LEARN_WAIT:-45}    # sensor uczy się 30 s (SENSOR_LEARN), plus zapas na start usług
SILENT_WAIT=${SILENT_WAIT:-80}  # silent-after 60 s (SENSOR_SILENT_AFTER) + przegląd co 10 s
STEP_WAIT=${STEP_WAIT:-20}

step()   { printf '\n%s === %s\n' "$(date +%T)" "$*"; }
expect() { printf '           oczekiwane: %s\n' "$*"; }

step "0. start stacku AGH z nakładką; sensor uczy się przez ${LEARN_WAIT}s"
"${C[@]}" up -d --quiet-pull
expect "brak zdarzeń: wszystko, co działa teraz, trafia do baseline'u po cichu"
sleep "$LEARN_WAIT"

step "1. zmiana bannera: flask-app przestaje podawać wersję nginxa"
"${C[@]}" exec -T flask-app sh -c "echo 'server_tokens off;' > /etc/nginx/conf.d/tokens.conf && nginx -s reload" 2>/dev/null
expect "service_changed dla flask-app:80 (server=nginx/X -> server=nginx), przy najbliższym GET z traffic"
sleep "$STEP_WAIT"

step "2. usługa znika: docker compose stop flask-app (jak 'quickstart.sh change')"
"${C[@]}" stop flask-app
expect "po ok. ${SILENT_WAIT}s: host_silent i service_silent dla flask-app (oba jego adresy)."
expect "Nie service_closed: zatrzymany kontener znika z sieci, więc nikt nie odpowiada RST."
sleep "$SILENT_WAIT"

step "3. usługa wraca: docker compose start flask-app"
"${C[@]}" start flask-app
expect "host_back i service_back dla flask-app"
sleep "$STEP_WAIT"

step "4. nowy host w sieci backend, którego nie było w baseline"
docker run -d --rm --name asi-intruder --network "$NET" nginx:alpine >/dev/null
sleep 5
docker run --rm --network "$NET" "$TRAFFIC_IMAGE" -once -targets "http://asi-intruder/" 2>&1 | tail -1
expect "host_new (już przy starcie kontenera, z ARP), potem service_new dla asi-intruder:80"
sleep "$STEP_WAIT"
docker rm -f asi-intruder >/dev/null

step "5. przez cały czas: flapper (host niestabilny) co FLAP_UP/FLAP_DOWN"
expect "service_closed (RST: kontener żyje, port zamknięty) i service_back na zmianę"

step "zdarzenia sensora od startu"
"${C[@]}" logs --no-log-prefix sensor 2>/dev/null | grep '"type"' || true
