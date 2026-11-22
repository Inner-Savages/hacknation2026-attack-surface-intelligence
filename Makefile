.PHONY: build test sensor-caps lab-up lab-down sensor images

IMAGE_PREFIX ?= ghcr.io/inner-savages/silence-on-the-wire

# Obrazy sensora, generatora ruchu i skanera, otagowane tak jak w rejestrze, więc
# nakładki compose używają ich lokalnie bez pobierania.
images:
	docker build --target sensor  -t $(IMAGE_PREFIX)/sensor:latest .
	docker build --target traffic -t $(IMAGE_PREFIX)/traffic:latest .
	docker build --target scanner -t $(IMAGE_PREFIX)/scanner:latest .

build:
	go build -o bin/sensor ./cmd/sensor
	go build -o bin/scanner ./cmd/scanner
	CGO_ENABLED=0 go build -o bin/traffic ./cmd/traffic
	CGO_ENABLED=0 go build -o bin/edgegate ./cmd/edgegate

.PHONY: edgegate cascade50-models cascade50-up cascade50-down cascade50-smoke cascade50-serve
edgegate:
	CGO_ENABLED=0 go build -o bin/edgegate ./cmd/edgegate

cascade50-models:
	./deploy/cascade50/run.sh models

cascade50-up:
	./deploy/cascade50/run.sh up

cascade50-smoke:
	./deploy/cascade50/run.sh smoke

cascade50-serve:
	./deploy/cascade50/run.sh serve

cascade50-down:
	docker compose -f deploy/cascade50/compose.yaml down

test:
	go vet ./...
	go test ./...

# Nadaje binarce tylko CAP_NET_RAW, żeby nie uruchamiać sensora jako root.
sensor-caps: build
	sudo setcap cap_net_raw+ep bin/sensor

sensor: sensor-caps
	./bin/sensor -i br-asilab -net 172.28.0.0/24 -learn 30s

lab-up:
	docker compose -f lab/docker-compose.yml up -d

lab-down:
	docker compose -f lab/docker-compose.yml down
